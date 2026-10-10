//! Записи, соединения, байты потоков и кадры (контракт v0.1.0).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::rejection::QueryRejection;
use axum::extract::{DefaultBodyLimit, FromRequest, Multipart, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::routing::get;
use axum::{Json, Router};
use pl_app::SourceData;
use pl_capture::{Checksum, DiagCode, Severity, decode, frame_bytes, tcp_flags};
use pl_core::ProblemKind;
use pl_reassembly::{Bytes, Close, Connection, Flag, PieceKind, Stream};
use serde::{Deserialize, Serialize};

use crate::encode::{base64, rfc3339};
use crate::{ApiError, AppState};

const DEFAULT_LIMIT: u64 = 50;
const MAX_LIMIT: u64 = 500;
const DEFAULT_LEN: u64 = 4096;
/// Предел `len` у байтов потока (контракт).
const MAX_LEN: u64 = 1 << 20;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/sources",
            // Размер тела проверяет сам обработчик: JSON — 8 МиБ, загрузка — предел размера записи.
            get(list_sources)
                .post(import_source)
                .layer(DefaultBodyLimit::disable()),
        )
        .route("/sources/{sha256}/diagnostics", get(diagnostics))
        .route("/connections", get(list_connections))
        .route("/streams/{stream}/bytes", get(stream_bytes))
        .route("/frames/{source}/{frame_no}", get(frame))
}

fn bad_request(detail: impl Into<String>) -> ApiError {
    ApiError::new(ProblemKind::BadRequest, detail)
}

fn not_found(detail: impl Into<String>) -> ApiError {
    ApiError::new(ProblemKind::NotFound, detail)
}

fn query<T>(q: Result<Query<T>, QueryRejection>) -> Result<T, ApiError> {
    q.map(|Query(v)| v)
        .map_err(|e| bad_request(format!("Некорректные параметры запроса: {}", e.body_text())))
}

#[derive(Deserialize)]
struct PageQuery {
    limit: Option<u64>,
    offset: Option<u64>,
}

fn page(limit: Option<u64>, offset: Option<u64>) -> Result<(u64, u64), ApiError> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(bad_request(format!("limit — от 1 до {MAX_LIMIT}.")));
    }
    Ok((limit, offset.unwrap_or(0)))
}

#[derive(Serialize)]
struct Page<T> {
    items: Vec<T>,
    total: u64,
    limit: u64,
    offset: u64,
}

fn paginate<T>(all: Vec<T>, limit: u64, offset: u64) -> Page<T> {
    let total = all.len() as u64;
    let items = all
        .into_iter()
        .skip(usize::try_from(offset).unwrap_or(usize::MAX))
        .take(limit as usize)
        .collect();
    Page {
        items,
        total,
        limit,
        offset,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceDto {
    sha256: String,
    import_id: String,
    name: String,
    format: &'static str,
    size_bytes: u64,
    status: &'static str,
    frame_count: u64,
    connection_count: u64,
}

fn source_dto(s: &SourceData) -> SourceDto {
    SourceDto {
        sha256: s.sha256.clone(),
        import_id: s.import_id.clone(),
        name: s.name.clone(),
        format: s.format().name(),
        size_bytes: s.file.len() as u64,
        status: "ready",
        frame_count: s.index.frames.len() as u64,
        connection_count: s.connections.len() as u64,
    }
}

async fn list_sources(
    State(state): State<AppState>,
    q: Result<Query<PageQuery>, QueryRejection>,
) -> Result<Json<Page<SourceDto>>, ApiError> {
    let q = query(q)?;
    let (limit, offset) = page(q.limit, q.offset)?;
    let all = state.sources.list().iter().map(|s| source_dto(s)).collect();
    Ok(Json(paginate(all, limit, offset)))
}

#[derive(Deserialize)]
struct ImportByPath {
    path: PathBuf,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JobAccepted {
    job_id: String,
}

async fn import_source(
    State(state): State<AppState>,
    request: Request,
) -> Result<(StatusCode, HeaderMap, Json<JobAccepted>), ApiError> {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let job_id = if content_type.starts_with("application/json") {
        let bytes = axum::body::to_bytes(request.into_body(), crate::MAX_JSON_BODY)
            .await
            .map_err(|_| {
                ApiError::new(ProblemKind::LimitExceeded, "Тело запроса слишком большое.")
            })?;
        let req: ImportByPath = serde_json::from_slice(&bytes).map_err(|_| {
            bad_request("Ожидается JSON {\"path\": \"...\"} с путём к файлу записи.")
        })?;
        pl_app::import_path(&state.jobs, &state.sources, &state.session, req.path, None)?
    } else if content_type.starts_with("multipart/form-data") {
        // Проект проверяем до чтения тела: гигабайты загрузки без проекта не нужны.
        if state.session.read().is_none() {
            return Err(ApiError(pl_app::Session::no_project()));
        }
        let multipart = Multipart::from_request(request, &state)
            .await
            .map_err(|_| bad_request("Тело запроса не похоже на multipart/form-data."))?;
        let upload = crate::upload::save(&state, multipart).await?;
        match pl_app::import_path(
            &state.jobs,
            &state.sources,
            &state.session,
            upload.file,
            Some(upload.dir.clone()),
        ) {
            Ok(id) => id,
            Err(problem) => {
                let _ = tokio::fs::remove_dir_all(&upload.dir).await;
                return Err(problem.into());
            }
        }
    } else {
        return Err(ApiError::new(
            ProblemKind::UnsupportedMedia,
            "Ожидается application/json или multipart/form-data.",
        ));
    };
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&format!("/api/jobs/{job_id}")) {
        headers.insert(header::LOCATION, v);
    }
    Ok((StatusCode::ACCEPTED, headers, Json(JobAccepted { job_id })))
}

fn source(state: &AppState, sha256: &str) -> Result<Arc<SourceData>, ApiError> {
    state
        .sources
        .get(sha256)
        .ok_or_else(|| not_found("Такой записи в проекте нет."))
}

fn severity(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticDto {
    code: &'static str,
    severity: &'static str,
    title: &'static str,
    detail: String,
    count: u64,
    frame_numbers: Vec<u32>,
}

#[derive(Serialize)]
struct FrameCounts {
    total: u64,
    parsed: u64,
    skipped: u64,
}

#[derive(Serialize)]
struct SourceDiagnostics {
    sha256: String,
    frames: FrameCounts,
    items: Vec<DiagnosticDto>,
}

async fn diagnostics(
    State(state): State<AppState>,
    Path(sha256): Path<String>,
) -> Result<Json<SourceDiagnostics>, ApiError> {
    let s = source(&state, &sha256)?;
    let checksums = pl_reassembly::checksum_report(&s.index);
    let items = s
        .index
        .diagnostics
        .groups
        .iter()
        .map(|(code, g)| DiagnosticDto {
            code: code.code(),
            severity: severity(code.severity()),
            title: code.title(),
            detail: match (code, checksums.offloading_host) {
                (DiagCode::BadChecksum, Some(host)) => format!(
                    "Неверные суммы только у кадров от {host}, у остальных узлов суммы верны: похоже на offloading при захвате на этом узле. Байты учтены по политике проекта."
                ),
                (DiagCode::BadChecksum, None) => format!(
                    "Неверные суммы у кадров от {} узл. и не у всех кадров узла: похоже на повреждение по пути, а не на offloading. Поведение определяет политика проекта (игнорировать, предупреждать, отбрасывать).",
                    checksums.bad_hosts.len()
                ),
                _ => code.detail().to_owned(),
            },
            count: g.count,
            frame_numbers: g.frames.clone(),
        })
        .collect();
    Ok(Json(SourceDiagnostics {
        sha256: s.sha256.clone(),
        frames: FrameCounts {
            total: s.index.frames.len() as u64,
            parsed: s.index.parsed(),
            skipped: s.index.skipped(),
        },
        items,
    }))
}

#[derive(Serialize)]
struct EndpointDto {
    address: String,
    port: u16,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StreamSummary {
    id: String,
    direction: &'static str,
    length: u64,
    data_bytes: u64,
    gap_bytes: u64,
    ambiguous_bytes: u64,
    start_available: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionDto {
    id: String,
    source: String,
    a: EndpointDto,
    b: EndpointDto,
    roles_known: bool,
    first_frame_time: String,
    last_frame_time: String,
    frame_count: u32,
    close: &'static str,
    flags: Vec<&'static str>,
    flag_counts: BTreeMap<&'static str, u64>,
    streams: Vec<StreamSummary>,
}

const DIRECTIONS: [(&str, &str); 2] = [("ab", "a_to_b"), ("ba", "b_to_a")];

fn connection_dto(s: &SourceData, c: &Connection) -> ConnectionDto {
    let id = c.id(&s.sha256);
    let endpoint = |e: std::net::SocketAddrV4| EndpointDto {
        address: e.ip().to_string(),
        port: e.port(),
    };
    ConnectionDto {
        source: s.sha256.clone(),
        a: endpoint(c.a),
        b: endpoint(c.b),
        roles_known: c.roles_known,
        first_frame_time: rfc3339(c.first_ts_ns),
        last_frame_time: rfc3339(c.last_ts_ns),
        frame_count: c.frame_count,
        close: match c.close {
            Close::Fin => "fin",
            Close::Rst => "rst",
            Close::Open => "open",
        },
        flags: c.flags.iter().map(|f| f.code()).collect(),
        flag_counts: c.flag_counts.iter().map(|(f, n)| (f.code(), *n)).collect(),
        streams: c
            .streams
            .iter()
            .zip(DIRECTIONS)
            .map(|(st, (suffix, direction))| StreamSummary {
                id: format!("{id}:{suffix}"),
                direction,
                length: st.length,
                data_bytes: st.data_bytes(),
                gap_bytes: st.gap_bytes(),
                ambiguous_bytes: st.ambiguous_bytes(),
                start_available: st.start_available,
            })
            .collect(),
        id,
    }
}

#[derive(Deserialize)]
struct ConnectionQuery {
    limit: Option<u64>,
    offset: Option<u64>,
    source: Option<String>,
    port: Option<u16>,
    address: Option<String>,
    flag: Option<String>,
}

const FLAGS: [Flag; 7] = [
    Flag::Retransmissions,
    Flag::Gaps,
    Flag::Ambiguous,
    Flag::NoSyn,
    Flag::BadChecksum,
    Flag::Truncated,
    Flag::ReusedPorts,
];

async fn list_connections(
    State(state): State<AppState>,
    q: Result<Query<ConnectionQuery>, QueryRejection>,
) -> Result<Json<Page<ConnectionDto>>, ApiError> {
    let q = query(q)?;
    let (limit, offset) = page(q.limit, q.offset)?;
    let flag = match q.flag.as_deref() {
        None => None,
        Some(code) => Some(
            FLAGS
                .into_iter()
                .find(|f| f.code() == code)
                .ok_or_else(|| bad_request(format!("Неизвестный признак «{code}».")))?,
        ),
    };
    let mut all = Vec::new();
    for s in state.sources.list() {
        if q.source.as_ref().is_some_and(|sha| *sha != s.sha256) {
            continue;
        }
        for c in &s.connections {
            let ends = [c.a, c.b];
            if q.port.is_some_and(|p| ends.iter().all(|e| e.port() != p))
                || q.address
                    .as_ref()
                    .is_some_and(|a| ends.iter().all(|e| e.ip().to_string() != *a))
                || flag.is_some_and(|f| !c.flags.contains(&f))
            {
                continue;
            }
            all.push(connection_dto(&s, c));
        }
    }
    Ok(Json(paginate(all, limit, offset)))
}

/// `<8 hex>:cNNNN:ab|ba` → запись, соединение, направление (0 — a→b).
pub(crate) fn resolve_stream(
    state: &AppState,
    id: &str,
) -> Result<(Arc<SourceData>, usize, usize), ApiError> {
    let missing = || not_found(format!("Потока {id} нет."));
    let mut parts = id.split(':');
    let (Some(prefix), Some(conn), Some(dir), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(missing());
    };
    let number: usize = conn
        .strip_prefix('c')
        .and_then(|n| n.parse().ok())
        .ok_or_else(missing)?;
    let dir = DIRECTIONS
        .iter()
        .position(|(suffix, _)| *suffix == dir)
        .ok_or_else(missing)?;
    let s = state.sources.by_prefix(prefix).ok_or_else(missing)?;
    let index = number
        .checked_sub(1)
        .filter(|i| *i < s.connections.len())
        .ok_or_else(missing)?;
    Ok((s, index, dir))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FrameRefDto {
    source: String,
    frame_no: u32,
    duplicate: bool,
}

#[derive(Serialize)]
struct VariantDto {
    data: String,
    frames: Vec<FrameRefDto>,
}

#[derive(Serialize)]
struct SegmentDto {
    start: u64,
    end: u64,
    status: &'static str,
    data: Option<String>,
    frames: Vec<FrameRefDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    variants: Option<Vec<VariantDto>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StreamBytesDto {
    stream: String,
    from: u64,
    length: u64,
    stream_length: u64,
    segments: Vec<SegmentDto>,
}

#[derive(Deserialize)]
struct BytesQuery {
    from: Option<u64>,
    len: Option<u64>,
}

fn file_slice(file: &[u8], at: u64, len: u64) -> &[u8] {
    usize::try_from(at)
        .ok()
        .zip(usize::try_from(len).ok())
        .and_then(|(at, len)| file.get(at..at.checked_add(len)?))
        .unwrap_or_default()
}

fn frame_refs(sha256: &str, b: &Bytes) -> Vec<FrameRefDto> {
    b.frames
        .iter()
        .map(|f| FrameRefDto {
            source: sha256.to_owned(),
            frame_no: f.frame,
            duplicate: f.duplicate,
        })
        .collect()
}

fn segments(s: &SourceData, st: &Stream, from: u64, to: u64) -> Vec<SegmentDto> {
    st.pieces_in(from, to)
        .iter()
        .map(|p| {
            let (start, end) = (p.start.max(from), p.end.min(to));
            let bytes = |b: &Bytes| {
                base64(file_slice(
                    &s.file,
                    b.file_offset + (start - p.start),
                    end - start,
                ))
            };
            match &p.kind {
                PieceKind::Data(b) => SegmentDto {
                    start,
                    end,
                    status: "data",
                    data: Some(bytes(b)),
                    frames: frame_refs(&s.sha256, b),
                    variants: None,
                },
                PieceKind::Gap => SegmentDto {
                    start,
                    end,
                    status: "gap",
                    data: None,
                    frames: Vec::new(),
                    variants: None,
                },
                PieceKind::Ambiguous { chosen, variants } => SegmentDto {
                    start,
                    end,
                    status: "ambiguous",
                    data: chosen.and_then(|c| variants.get(c)).map(bytes),
                    frames: variants
                        .iter()
                        .flat_map(|v| frame_refs(&s.sha256, v))
                        .collect(),
                    variants: Some(
                        variants
                            .iter()
                            .map(|v| VariantDto {
                                data: bytes(v),
                                frames: frame_refs(&s.sha256, v),
                            })
                            .collect(),
                    ),
                },
            }
        })
        .collect()
}

async fn stream_bytes(
    State(state): State<AppState>,
    Path(id): Path<String>,
    q: Result<Query<BytesQuery>, QueryRejection>,
) -> Result<Json<StreamBytesDto>, ApiError> {
    let q = query(q)?;
    let from = q.from.unwrap_or(0);
    let len = q.len.unwrap_or(DEFAULT_LEN);
    if !(1..=MAX_LEN).contains(&len) {
        return Err(bad_request(format!("len — от 1 до {MAX_LEN} байт.")));
    }
    let (s, conn, dir) = resolve_stream(&state, &id)?;
    let Some(st) = s.connections.get(conn).and_then(|c| c.streams.get(dir)) else {
        return Err(not_found(format!("Потока {id} нет.")));
    };
    let to = from.saturating_add(len).min(st.length);
    let from = from.min(to);
    Ok(Json(StreamBytesDto {
        segments: segments(&s, st, from, to),
        stream: id,
        from,
        length: to - from,
        stream_length: st.length,
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EthernetDto {
    src: String,
    dst: String,
    ether_type: u16,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Ipv4Dto {
    src: String,
    dst: String,
    ttl: u8,
    protocol: u8,
    header_length: u8,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TcpDto {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: Vec<&'static str>,
    window: u16,
    header_length: u8,
    checksum: &'static str,
}

#[derive(Serialize)]
struct PayloadDto {
    offset: u64,
    length: u64,
}

#[derive(Serialize)]
struct StreamRangeDto {
    stream: String,
    start: u64,
    end: u64,
    duplicate: bool,
}

#[derive(Serialize)]
struct FrameDiagnostic {
    code: &'static str,
    severity: &'static str,
    title: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FrameDto {
    source: String,
    frame_no: u32,
    time: String,
    file_offset: u64,
    captured_length: u32,
    original_length: u32,
    data: String,
    ethernet: Option<EthernetDto>,
    ipv4: Option<Ipv4Dto>,
    tcp: Option<TcpDto>,
    payload: Option<PayloadDto>,
    stream_range: Option<StreamRangeDto>,
    diagnostics: Vec<FrameDiagnostic>,
}

fn mac(m: [u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

const TCP_FLAG_NAMES: [(u8, &str); 8] = [
    (tcp_flags::FIN, "fin"),
    (tcp_flags::SYN, "syn"),
    (tcp_flags::RST, "rst"),
    (tcp_flags::PSH, "psh"),
    (tcp_flags::ACK, "ack"),
    (tcp_flags::URG, "urg"),
    (tcp_flags::ECE, "ece"),
    (tcp_flags::CWR, "cwr"),
];

fn stream_range(s: &SourceData, frame_no: u32) -> Option<StreamRangeDto> {
    for c in &s.connections {
        if frame_no < c.first_frame || frame_no > c.last_frame {
            continue;
        }
        for (st, (suffix, _)) in c.streams.iter().zip(DIRECTIONS) {
            let Ok(at) = st.frames.binary_search_by_key(&frame_no, |f| f.frame) else {
                continue;
            };
            let Some(span) = st.frames.get(at) else {
                continue;
            };
            return Some(StreamRangeDto {
                stream: format!("{}:{suffix}", c.id(&s.sha256)),
                start: span.start,
                end: span.end,
                duplicate: span.duplicate,
            });
        }
    }
    None
}

async fn frame(
    State(state): State<AppState>,
    Path((sha256, frame_no)): Path<(String, String)>,
) -> Result<Json<FrameDto>, ApiError> {
    let s = source(&state, &sha256)?;
    let missing = || not_found(format!("Кадра {frame_no} в записи нет."));
    let no: u32 = frame_no.parse().map_err(|_| missing())?;
    let rec = s.index.frame(no).ok_or_else(missing)?;
    let data = frame_bytes(&s.file, rec).unwrap_or_default();
    let d = decode(data, rec.original_len, rec.linktype);
    let payload = d.tcp.map(|_| PayloadDto {
        offset: d.payload_offset as u64,
        length: u64::from(d.captured_payload_len),
    });
    Ok(Json(FrameDto {
        source: s.sha256.clone(),
        frame_no: no,
        time: rfc3339(rec.ts_ns),
        file_offset: rec.file_offset,
        captured_length: rec.captured_len,
        original_length: rec.original_len,
        data: base64(data),
        ethernet: d.ethernet.map(|e| EthernetDto {
            src: mac(e.src),
            dst: mac(e.dst),
            ether_type: e.ether_type,
        }),
        ipv4: d.ipv4.map(|ip| Ipv4Dto {
            src: ip.src.to_string(),
            dst: ip.dst.to_string(),
            ttl: ip.ttl,
            protocol: ip.protocol,
            header_length: ip.header_len,
        }),
        tcp: d.tcp.map(|t| TcpDto {
            src_port: t.src_port,
            dst_port: t.dst_port,
            seq: t.seq,
            ack: t.ack,
            flags: TCP_FLAG_NAMES
                .iter()
                .filter(|(bit, _)| t.flags & bit != 0)
                .map(|(_, name)| *name)
                .collect(),
            window: t.window,
            header_length: t.header_len,
            checksum: match t.checksum {
                Checksum::Ok => "ok",
                Checksum::Bad => "bad",
                Checksum::Unknown => "unknown",
            },
        }),
        payload,
        stream_range: if d.payload_len > 0 {
            stream_range(&s, no)
        } else {
            None
        },
        diagnostics: d
            .issues
            .iter()
            .map(|c: &DiagCode| FrameDiagnostic {
                code: c.code(),
                severity: severity(c.severity()),
                title: c.title(),
            })
            .collect(),
    }))
}
