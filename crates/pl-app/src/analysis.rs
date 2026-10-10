//! Подсказки исследователю поверх собранных потоков: границы, изменчивость, пары запрос→ответ.

use pl_analysis::{
    DataRun, Exchange, ExchangeStats, FramingHints, Msg, StreamSample, Variability,
    VariabilityOptions, find_framing, pair_exchanges, variability,
};
use pl_core::{Problem, ProblemKind};
use pl_interp::schema::Framing;
use pl_interp::{Interpretation, Read, RegionKind, StreamInput};
use pl_reassembly::Stream;
use serde::Serialize;

use crate::{
    Session, SourceData, SourceStore, current_interpretation, resolve_stream, stream_input,
};

/// Сколько потоков принимает один запрос подсказок.
pub const MAX_REQUEST_STREAMS: usize = pl_analysis::MAX_STREAMS;

const SUFFIX: [&str; 2] = ["ab", "ba"];

fn bad(detail: impl Into<String>) -> Problem {
    Problem::new(ProblemKind::BadRequest, detail)
}

fn not_found(id: &str) -> Problem {
    Problem::new(ProblemKind::NotFound, format!("Потока {id} нет в проекте."))
}

/// Непрерывные участки известных байтов потока и начала TCP-сегментов внутри них.
fn runs_of(input: &StreamInput<'_>, stream: &Stream) -> Vec<DataRun> {
    let mut runs: Vec<(u64, DataRun)> = Vec::new();
    let mut last_end: Option<u64> = None;
    for region in &input.regions {
        let RegionKind::Data(bytes) = &region.kind else {
            last_end = None;
            continue;
        };
        match (runs.last_mut(), last_end) {
            (Some((_, run)), Some(end)) if end == region.start => {
                run.data.extend_from_slice(bytes);
            }
            _ => runs.push((
                region.start,
                DataRun {
                    data: bytes.to_vec(),
                    segment_starts: Vec::new(),
                    starts_at_boundary: region.start == 0 && stream.start_available,
                },
            )),
        }
        last_end = Some(region.end);
    }
    for (start, run) in &mut runs {
        let end = *start + run.data.len() as u64;
        run.segment_starts = stream
            .frames
            .iter()
            .filter(|f| !f.duplicate && f.start >= *start && f.start < end)
            .filter_map(|f| usize::try_from(f.start - *start).ok())
            .collect();
    }
    runs.into_iter().map(|(_, r)| r).collect()
}

fn resolve_all(
    store: &SourceStore,
    ids: &[String],
) -> Result<Vec<(String, StreamSample)>, Problem> {
    if ids.is_empty() {
        return Err(bad("Нужен хотя бы один поток в streams."));
    }
    if ids.len() > MAX_REQUEST_STREAMS {
        return Err(bad(format!(
            "В одном запросе не больше {MAX_REQUEST_STREAMS} потоков."
        )));
    }
    let mut out = Vec::new();
    for id in ids {
        let (data, conn, dir) = resolve_stream(store, id).ok_or_else(|| not_found(id))?;
        let (Some(connection), true) = (data.connections.get(conn), dir < 2) else {
            return Err(not_found(id));
        };
        let Some(stream) = connection.streams.get(dir) else {
            return Err(not_found(id));
        };
        let input = stream_input(&data.file, connection, stream, dir);
        out.push((
            id.clone(),
            StreamSample {
                id: id.clone(),
                runs: runs_of(&input, stream),
            },
        ));
    }
    Ok(out)
}

/// Подсказки по границам сообщений в указанных направленных потоках.
pub fn framing_hints(
    store: &SourceStore,
    streams: &[String],
    cancelled: &dyn Fn() -> bool,
) -> Result<FramingHints, Problem> {
    let samples: Vec<StreamSample> = resolve_all(store, streams)?
        .into_iter()
        .map(|(_, s)| s)
        .collect();
    Ok(find_framing(&samples, cancelled))
}

/// Интерпретация только из фрейминга: типы сообщений не описаны, границы — по ней.
fn framing_only(framing: &Framing) -> Result<Interpretation, Problem> {
    let doc = serde_json::json!({
        "format": "protoledger/interpretation@1",
        "framing": framing,
        "messages": [],
    });
    Interpretation::parse(&doc.to_string()).map_err(|e| {
        Problem::new(
            ProblemKind::Unprocessable,
            format!("Фрейминг не принят: {e}."),
        )
    })
}

/// Какая интерпретация даёт границы: заданный фрейминг (поверх текущей интерпретации, если она есть)
/// либо сохранённая интерпретация.
fn effective(
    session: &Session,
    framing: Option<&Framing>,
    need_types: bool,
) -> Result<Interpretation, Problem> {
    match (framing, current_interpretation(session)) {
        (Some(f), Some(mut it)) => {
            it.framing = f.clone();
            Ok(it)
        }
        (Some(f), None) if !need_types => framing_only(f),
        (None, Some(it)) => Ok(it),
        _ => Err(Problem::new(
            ProblemKind::Conflict,
            if need_types {
                "Для фильтра по типу нужна сохранённая интерпретация: сохраните её через PUT /api/interpretation."
            } else {
                "Нужен фрейминг: передайте framing или сохраните интерпретацию через PUT /api/interpretation."
            },
        )),
    }
}

/// Сообщение потока: границы, тип по интерпретации и время кадров.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageRef {
    pub stream: String,
    pub start: u64,
    pub end: u64,
    pub message_id: Option<String>,
    pub first_ts_ns: u64,
    pub last_ts_ns: u64,
}

struct Framed {
    refs: Vec<MessageRef>,
    from_initiator: Vec<bool>,
}

fn frame_connection(
    data: &SourceData,
    connection: &pl_reassembly::Connection,
    it: &Interpretation,
    cancelled: &dyn Fn() -> bool,
) -> Result<Framed, Problem> {
    let id = connection.id(&data.sha256);
    let mut out = Framed {
        refs: Vec::new(),
        from_initiator: Vec::new(),
    };
    for (i, stream) in connection.streams.iter().enumerate() {
        let stream_id = format!("{id}:{}", SUFFIX.get(i).copied().unwrap_or("ab"));
        let input = stream_input(&data.file, connection, stream, i);
        let result = pl_interp::apply(it, &input, cancelled).map_err(|e| {
            Problem::new(
                ProblemKind::Unprocessable,
                format!("Поток {stream_id}: {e}."),
            )
        })?;
        for m in result.messages {
            let times: Vec<u64> = stream
                .frames
                .iter()
                .filter(|f| f.start < m.end && f.end > m.start)
                .map(|f| data.index.frame(f.frame).map_or(0, |fr| fr.ts_ns))
                .collect();
            let (Some(first), Some(last)) = (times.iter().min(), times.iter().max()) else {
                continue;
            };
            out.refs.push(MessageRef {
                stream: stream_id.clone(),
                start: m.start,
                end: m.end,
                message_id: m.message_id,
                first_ts_ns: *first,
                last_ts_ns: *last,
            });
            out.from_initiator.push(i == 0);
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Default)]
pub struct VariabilityRequest {
    pub streams: Vec<String>,
    pub framing: Option<Framing>,
    /// Только сообщения этого типа (нужна интерпретация).
    pub message_id: Option<String>,
    pub length: Option<usize>,
}

/// Изменчивость байтов сообщений указанных потоков.
pub fn message_variability(
    session: &Session,
    store: &SourceStore,
    request: &VariabilityRequest,
    cancelled: &dyn Fn() -> bool,
) -> Result<Variability, Problem> {
    if request.streams.is_empty() || request.streams.len() > MAX_REQUEST_STREAMS {
        return Err(bad(format!(
            "streams — от 1 до {MAX_REQUEST_STREAMS} потоков."
        )));
    }
    let it = effective(
        session,
        request.framing.as_ref(),
        request.message_id.is_some(),
    )?;
    let mut messages: Vec<Vec<u8>> = Vec::new();
    for id in &request.streams {
        let (data, conn, dir) = resolve_stream(store, id).ok_or_else(|| not_found(id))?;
        let (Some(connection), Some(stream)) = (
            data.connections.get(conn),
            data.connections.get(conn).and_then(|c| c.streams.get(dir)),
        ) else {
            return Err(not_found(id));
        };
        let input = stream_input(&data.file, connection, stream, dir);
        let result = pl_interp::apply(&it, &input, cancelled)
            .map_err(|e| Problem::new(ProblemKind::Unprocessable, format!("Поток {id}: {e}.")))?;
        for m in result.messages {
            if let Some(want) = &request.message_id
                && m.message_id.as_ref() != Some(want)
            {
                continue;
            }
            if messages.len() >= pl_analysis::MAX_MESSAGES {
                break;
            }
            if let Read::Bytes(bytes) = input.read(m.start, m.end - m.start) {
                messages.push(bytes.into_owned());
            }
        }
    }
    let refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
    Ok(variability(
        &refs,
        &VariabilityOptions {
            length: request.length,
        },
    ))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeView {
    pub requests: Vec<MessageRef>,
    pub responses: Vec<MessageRef>,
    pub delay_ns: Option<u64>,
    pub certainty: pl_analysis::Certainty,
}

/// Пары запрос→ответ в соединении `<src8>:cNNNN`.
pub fn connection_exchanges(
    session: &Session,
    store: &SourceStore,
    connection_id: &str,
    framing: Option<&Framing>,
    cancelled: &dyn Fn() -> bool,
) -> Result<(Vec<ExchangeView>, ExchangeStats), Problem> {
    let (data, conn) = find_connection(store, connection_id).ok_or_else(|| {
        Problem::new(
            ProblemKind::NotFound,
            format!("Соединения {connection_id} нет."),
        )
    })?;
    let Some(connection) = data.connections.get(conn) else {
        return Err(Problem::new(
            ProblemKind::NotFound,
            format!("Соединения {connection_id} нет."),
        ));
    };
    // Пары строятся по обоим направлениям: область применимости интерпретации не сужает соединение.
    let mut it = effective(session, framing, false)?;
    it.scope = pl_interp::schema::Scope::default();
    let framed = frame_connection(&data, connection, &it, cancelled)?;
    let msgs: Vec<Msg> = framed
        .refs
        .iter()
        .zip(&framed.from_initiator)
        .enumerate()
        .map(|(id, (r, from_initiator))| Msg {
            id,
            from_initiator: *from_initiator,
            first_ts_ns: r.first_ts_ns,
            last_ts_ns: r.last_ts_ns,
        })
        .collect();
    let (pairs, stats) = pair_exchanges(&msgs);
    let pick = |ids: &[usize]| -> Vec<MessageRef> {
        ids.iter()
            .filter_map(|i| framed.refs.get(*i).cloned())
            .collect()
    };
    let views = pairs
        .iter()
        .map(|e: &Exchange| ExchangeView {
            requests: pick(&e.requests),
            responses: pick(&e.responses),
            delay_ns: e.delay_ns,
            certainty: e.certainty,
        })
        .collect();
    Ok((views, stats))
}

fn find_connection(store: &SourceStore, id: &str) -> Option<(std::sync::Arc<SourceData>, usize)> {
    let mut parts = id.split(':');
    let (prefix, conn, None) = (parts.next()?, parts.next()?, parts.next()) else {
        return None;
    };
    let number: usize = conn.strip_prefix('c')?.parse().ok()?;
    let data = store.by_prefix(prefix)?;
    let index = number
        .checked_sub(1)
        .filter(|i| *i < data.connections.len())?;
    Some((data, index))
}
