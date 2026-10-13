//! Подсказки исследователю поверх собранных потоков: границы, изменчивость, пары запрос→ответ.

use pl_analysis::{
    ChecksumAlt, ChecksumFn, ConstBytes, CorrSample, Correlations, DataRun, Exchange,
    ExchangeStats, FieldAlt, FieldKind, FieldSample, FramingHints, KeyHint, KeyValue, Msg,
    StreamSample, TypeKey, TypeOptions, TypeSample, Variability, VariabilityOptions, correlate,
    find_framing, pair_exchanges, variability,
};
use pl_core::{Problem, ProblemKind};
use pl_interp::schema::Framing;
use pl_interp::{Category, Interpretation, Read, RegionKind, StreamInput};
use pl_reassembly::Stream;
use serde::Serialize;

use crate::{
    ActionLogStore, Session, SourceData, SourceStore, current_interpretation, resolve_stream,
    stream_input,
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

/// Число потоков проверяется раньше всего остального: пустой запрос — ошибка запроса, а не проекта.
fn check_streams(streams: &[String]) -> Result<(), Problem> {
    if streams.is_empty() || streams.len() > MAX_REQUEST_STREAMS {
        return Err(bad(format!(
            "streams — от 1 до {MAX_REQUEST_STREAMS} потоков."
        )));
    }
    Ok(())
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

#[derive(Debug, Clone)]
pub struct ChecksumRequest {
    pub streams: Vec<String>,
    pub framing: Option<Framing>,
    /// Только сообщения этого типа (нужна интерпретация).
    pub message_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumCounterView {
    pub stream: String,
    pub start: u64,
    pub end: u64,
    pub got: u64,
    pub expected: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumHintView {
    pub algorithm: String,
    pub title: String,
    pub at: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub from: u32,
    pub to: String,
    pub expr: String,
    pub matches: u64,
    pub samples: u64,
    pub share_permille: u32,
    pub distinct: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_counterexample: Option<ChecksumCounterView>,
    pub equivalent: Vec<ChecksumAlt>,
}

/// Функция, которая проверялась: имя в выражениях и название.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumAlgorithm {
    pub name: String,
    pub title: String,
    pub width: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumView {
    pub messages: u64,
    pub truncated: bool,
    pub skipped_long: u64,
    pub incomplete: bool,
    pub hints: Vec<ChecksumHintView>,
    /// Что проверялось: пустой список подсказок значит «ни одна из этих функций не подошла».
    pub checked: Vec<ChecksumAlgorithm>,
}

/// Поиск контрольной суммы в сообщениях указанных потоков.
pub fn message_checksums(
    session: &Session,
    store: &SourceStore,
    request: &ChecksumRequest,
    cancelled: &dyn Fn() -> bool,
) -> Result<ChecksumView, Problem> {
    check_streams(&request.streams)?;
    let it = effective(
        session,
        request.framing.as_ref(),
        request.message_id.is_some(),
    )?;
    checksums_on(&it, store, request, cancelled)
}

/// То же на заданном описании: оно может быть ещё не сохранено в проекте.
pub(crate) fn checksums_on(
    it: &Interpretation,
    store: &SourceStore,
    request: &ChecksumRequest,
    cancelled: &dyn Fn() -> bool,
) -> Result<ChecksumView, Problem> {
    if request.streams.is_empty() || request.streams.len() > MAX_REQUEST_STREAMS {
        return Err(bad(format!(
            "streams — от 1 до {MAX_REQUEST_STREAMS} потоков."
        )));
    }
    let mut messages: Vec<Vec<u8>> = Vec::new();
    let mut places: Vec<(&str, u64, u64)> = Vec::new();
    // Запас сверх предела поиска нужен только для признака «не всё вошло».
    let room = pl_analysis::MAX_CHECKSUM_MESSAGES + 1;
    for id in &request.streams {
        let (data, conn, dir) = resolve_stream(store, id).ok_or_else(|| not_found(id))?;
        let (Some(connection), Some(stream)) = (
            data.connections.get(conn),
            data.connections.get(conn).and_then(|c| c.streams.get(dir)),
        ) else {
            return Err(not_found(id));
        };
        let input = stream_input(&data.file, connection, stream, dir);
        let result = pl_interp::apply(it, &input, cancelled)
            .map_err(|e| Problem::new(ProblemKind::Unprocessable, format!("Поток {id}: {e}.")))?;
        for m in result.messages {
            if messages.len() >= room {
                break;
            }
            if let Some(want) = &request.message_id
                && m.message_id.as_ref() != Some(want)
            {
                continue;
            }
            // Оборванное или неоднозначное сообщение дало бы ложный контрпример.
            if matches!(m.category, Category::Incomplete | Category::Ambiguous) {
                continue;
            }
            if let Read::Bytes(bytes) = input.read(m.start, m.end - m.start) {
                messages.push(bytes.into_owned());
                places.push((id.as_str(), m.start, m.end));
            }
        }
    }

    let algorithms = &pl_interp::checksum::ALGORITHMS;
    type Compute = Box<dyn Fn(&[u8]) -> u64>;
    let computes: Vec<Compute> = algorithms
        .iter()
        .map(|a| Box::new(move |data: &[u8]| a.compute(data)) as Compute)
        .collect();
    let functions: Vec<ChecksumFn<'_>> = algorithms
        .iter()
        .zip(&computes)
        .map(|(a, compute)| ChecksumFn {
            name: a.name,
            title: a.title,
            width: a.width,
            compute: compute.as_ref(),
        })
        .collect();
    let refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
    let found = pl_analysis::find_checksums(&refs, &functions, cancelled);

    let hints = found
        .hints
        .into_iter()
        .map(|h| ChecksumHintView {
            first_counterexample: h.first_counterexample.and_then(|c| {
                let (stream, start, end) = usize::try_from(c.index)
                    .ok()
                    .and_then(|i| places.get(i))
                    .copied()?;
                Some(ChecksumCounterView {
                    stream: stream.to_owned(),
                    start,
                    end,
                    got: c.got,
                    expected: c.expected,
                })
            }),
            algorithm: h.algorithm,
            title: h.title,
            at: h.at,
            ty: h.ty,
            from: h.from,
            to: h.to,
            expr: h.expr,
            matches: h.matches,
            samples: h.samples,
            share_permille: h.share_permille,
            distinct: h.distinct,
            equivalent: h.equivalent,
        })
        .collect();
    Ok(ChecksumView {
        messages: found.messages,
        truncated: found.truncated,
        skipped_long: found.skipped_long,
        incomplete: found.incomplete,
        hints,
        checked: algorithms
            .iter()
            .map(|a| ChecksumAlgorithm {
                name: a.name.to_owned(),
                title: a.title.to_owned(),
                width: a.width,
            })
            .collect(),
    })
}

#[derive(Debug, Clone)]
pub struct TypesRequest {
    pub streams: Vec<String>,
    pub framing: Option<Framing>,
}

/// Поле-различитель для описания: объявляется в каждом сообщении, на него ссылается `when`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeField {
    pub name: String,
    pub at: u32,
    #[serde(rename = "type")]
    pub ty: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagePlace {
    pub stream: String,
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeGroupView {
    /// Предлагаемый идентификатор сообщения.
    pub id: String,
    /// Условие для описания.
    pub when: String,
    pub key: Vec<KeyValue>,
    pub count: u64,
    pub share_permille: u32,
    pub min_len: u64,
    pub max_len: u64,
    pub lengths: u32,
    pub constant: Vec<ConstBytes>,
    pub example: Option<MessagePlace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length_outlier: Option<MessagePlace>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TypesView {
    pub messages: u64,
    pub truncated: bool,
    pub incomplete: bool,
    pub keys: Vec<KeyHint>,
    pub fields: Vec<TypeField>,
    pub types: Vec<TypeGroupView>,
    pub rare: u64,
}

/// Типы сообщений указанных потоков: различители и условие `when` для каждого типа.
pub fn message_types(
    session: &Session,
    store: &SourceStore,
    request: &TypesRequest,
    cancelled: &dyn Fn() -> bool,
) -> Result<TypesView, Problem> {
    check_streams(&request.streams)?;
    let it = effective(session, request.framing.as_ref(), false)?;
    types_on(&it, store, request, cancelled)
}

/// То же на заданном описании: оно может быть ещё не сохранено в проекте.
pub(crate) fn types_on(
    it: &Interpretation,
    store: &SourceStore,
    request: &TypesRequest,
    cancelled: &dyn Fn() -> bool,
) -> Result<TypesView, Problem> {
    if request.streams.is_empty() || request.streams.len() > MAX_REQUEST_STREAMS {
        return Err(bad(format!(
            "streams — от 1 до {MAX_REQUEST_STREAMS} потоков."
        )));
    }
    let mut messages: Vec<(Vec<u8>, u8, u32)> = Vec::new();
    let mut places: Vec<(&str, u64, u64)> = Vec::new();
    // Порт принимающей стороны: если он один на все потоки, сторону можно записать условием на порт.
    let mut ports: std::collections::BTreeSet<u16> = std::collections::BTreeSet::new();
    let room = pl_analysis::MAX_TYPE_MESSAGES + 1;
    for (number, id) in request.streams.iter().enumerate() {
        let (data, conn, dir) = resolve_stream(store, id).ok_or_else(|| not_found(id))?;
        let (Some(connection), Some(stream)) = (
            data.connections.get(conn),
            data.connections.get(conn).and_then(|c| c.streams.get(dir)),
        ) else {
            return Err(not_found(id));
        };
        let input = stream_input(&data.file, connection, stream, dir);
        ports.insert(if dir == 0 {
            input.meta.dst_port
        } else {
            input.meta.src_port
        });
        let result = pl_interp::apply(it, &input, cancelled)
            .map_err(|e| Problem::new(ProblemKind::Unprocessable, format!("Поток {id}: {e}.")))?;
        for m in result.messages {
            if messages.len() >= room {
                break;
            }
            // Оборванное сообщение короче настоящего и исказило бы длины типа.
            if matches!(m.category, Category::Incomplete | Category::Ambiguous) {
                continue;
            }
            if let Read::Bytes(bytes) = input.read(m.start, m.end - m.start) {
                messages.push((bytes.into_owned(), u8::from(dir != 0), number as u32));
                places.push((id.as_str(), m.start, m.end));
            }
        }
    }
    let port = match (ports.len(), ports.first()) {
        (1, Some(p)) => Some(*p),
        _ => None,
    };
    let exclude = it
        .framing
        .length
        .as_ref()
        .map(|l| {
            let size = l.ty.int().map_or(4, |t| t.size() as u32);
            (l.at..l.at.saturating_add(size)).collect()
        })
        .unwrap_or_default();
    let samples: Vec<TypeSample<'_>> = messages
        .iter()
        .map(|(data, side, stream)| TypeSample {
            data,
            side: *side,
            stream: *stream,
        })
        .collect();
    let found = pl_analysis::find_types(
        &samples,
        &TypeOptions {
            exclude,
            without_side: port.is_none(),
        },
        cancelled,
    );

    let place = |index: u64| {
        usize::try_from(index)
            .ok()
            .and_then(|i| places.get(i))
            .map(|(stream, start, end)| MessagePlace {
                stream: (*stream).to_owned(),
                start: *start,
                end: *end,
            })
    };
    let types = found
        .types
        .into_iter()
        .map(|t| {
            let mut id = "msg".to_owned();
            let mut terms: Vec<String> = Vec::new();
            for kv in &t.key {
                match (kv.key, port) {
                    (TypeKey::Byte { at }, _) => {
                        id.push_str(&format!("_{:02x}", kv.value));
                        terms.push(format!("b{at} == 0x{:02x}", kv.value));
                    }
                    (TypeKey::Side, Some(p)) if kv.value == 0 => {
                        id.push_str("_req");
                        terms.push(format!("dst_port == {p}"));
                    }
                    (TypeKey::Side, Some(p)) => {
                        id.push_str("_resp");
                        terms.push(format!("src_port == {p}"));
                    }
                    // Без общего порта на стороны не делим: сюда не попадаем.
                    (TypeKey::Side, None) => {}
                }
            }
            TypeGroupView {
                id,
                when: terms.join(" && "),
                key: t.key,
                count: t.count,
                share_permille: t.share_permille,
                min_len: t.min_len,
                max_len: t.max_len,
                lengths: t.lengths,
                constant: t.constant,
                example: place(t.first),
                length_outlier: t.length_outlier.and_then(place),
            }
        })
        .collect();
    Ok(TypesView {
        messages: found.messages,
        truncated: found.truncated,
        incomplete: found.incomplete,
        fields: found
            .keys
            .iter()
            .filter_map(|k| match k.key {
                TypeKey::Byte { at } => Some(TypeField {
                    name: format!("b{at}"),
                    at,
                    ty: "u8",
                }),
                TypeKey::Side => None,
            })
            .collect(),
        keys: found.keys,
        types,
        rare: found.rare,
    })
}

/// Отбор сообщений по значению байта: так выбирается один тип до того, как он описан.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteMatch {
    pub at: u32,
    pub value: u8,
}

#[derive(Debug, Clone)]
pub struct FieldsRequest {
    pub streams: Vec<String>,
    pub framing: Option<Framing>,
    /// Только сообщения этого типа (нужна интерпретация).
    pub message_id: Option<String>,
    /// Только сообщения с этими значениями байтов.
    pub matching: Vec<ByteMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldHintView {
    pub kind: FieldKind,
    pub at: u32,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_end: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<u32>,
    /// Что это значит, одной фразой.
    pub summary: String,
    pub matches: u64,
    pub samples: u64,
    pub share_permille: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_counterexample: Option<MessagePlace>,
    pub equivalent: Vec<FieldAlt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldsView {
    pub messages: u64,
    pub truncated: bool,
    pub incomplete: bool,
    pub hints: Vec<FieldHintView>,
}

fn field_summary(h: &pl_analysis::FieldHint) -> String {
    match h.kind {
        FieldKind::Counter => "растёт на единицу с каждым сообщением потока".to_owned(),
        FieldKind::Time => {
            let unit = match h.unit {
                Some("s") => "секундах",
                Some("ms") => "миллисекундах",
                _ => "микросекундах",
            };
            if h.epoch == Some(true) {
                format!("время в {unit} от эпохи Unix: совпадает с часами записи")
            } else {
                format!("растёт вместе со временем записи, в {unit}; отсчёт не от эпохи Unix")
            }
        }
        FieldKind::String => {
            let tail = if h.to_end == Some(true) {
                ", до конца сообщения"
            } else {
                ""
            };
            format!("длина и сразу за ней текст этой длины{tail}")
        }
        FieldKind::Text => "печатный текст на постоянном месте".to_owned(),
        FieldKind::Tlv => format!(
            "записи «метка, длина, значение» до конца сообщения; разных меток: {}",
            h.tags.unwrap_or(0)
        ),
    }
}

/// Подсказки полей по поведению значений в сообщениях указанных потоков.
pub fn message_fields(
    session: &Session,
    store: &SourceStore,
    request: &FieldsRequest,
    cancelled: &dyn Fn() -> bool,
) -> Result<FieldsView, Problem> {
    check_streams(&request.streams)?;
    let it = effective(
        session,
        request.framing.as_ref(),
        request.message_id.is_some(),
    )?;
    fields_on(&it, store, request, cancelled)
}

/// То же на заданном описании: оно может быть ещё не сохранено в проекте.
pub(crate) fn fields_on(
    it: &Interpretation,
    store: &SourceStore,
    request: &FieldsRequest,
    cancelled: &dyn Fn() -> bool,
) -> Result<FieldsView, Problem> {
    if request.streams.is_empty() || request.streams.len() > MAX_REQUEST_STREAMS {
        return Err(bad(format!(
            "streams — от 1 до {MAX_REQUEST_STREAMS} потоков."
        )));
    }
    if request.matching.len() > 8 {
        return Err(bad("match — не больше 8 условий."));
    }
    // Все сообщения потоков и признак «выбрано фильтром»: счётчик — свойство потока целиком,
    // среди сообщений одного типа он идёт с пропусками.
    struct Row<'a> {
        data: Vec<u8>,
        stream: u32,
        ts_ns: u64,
        place: (&'a str, u64, u64),
        selected: bool,
    }
    let mut rows: Vec<Row<'_>> = Vec::new();
    let room = pl_analysis::MAX_FIELD_MESSAGES + 1;
    for (number, id) in request.streams.iter().enumerate() {
        let (data, conn, dir) = resolve_stream(store, id).ok_or_else(|| not_found(id))?;
        let (Some(connection), Some(stream)) = (
            data.connections.get(conn),
            data.connections.get(conn).and_then(|c| c.streams.get(dir)),
        ) else {
            return Err(not_found(id));
        };
        let input = stream_input(&data.file, connection, stream, dir);
        let times = crate::hypothesis::Times::new(&data, stream);
        let result = pl_interp::apply(it, &input, cancelled)
            .map_err(|e| Problem::new(ProblemKind::Unprocessable, format!("Поток {id}: {e}.")))?;
        for m in result.messages {
            if rows.len() >= room {
                break;
            }
            // Оборванное сообщение нарушило бы и счётчик, и длины строк.
            if matches!(m.category, Category::Incomplete | Category::Ambiguous) {
                continue;
            }
            let Read::Bytes(bytes) = input.read(m.start, m.end - m.start) else {
                continue;
            };
            let of_type = request
                .message_id
                .as_ref()
                .is_none_or(|want| m.message_id.as_ref() == Some(want));
            let matched = request
                .matching
                .iter()
                .all(|c| bytes.get(c.at as usize) == Some(&c.value));
            rows.push(Row {
                ts_ns: times.first_ts(m.start, m.end).unwrap_or(0),
                data: bytes.into_owned(),
                stream: number as u32,
                place: (id.as_str(), m.start, m.end),
                selected: of_type && matched,
            });
        }
    }
    let sample = |r: &'_ Row<'_>| MessagePlace {
        stream: r.place.0.to_owned(),
        start: r.place.1,
        end: r.place.2,
    };
    let view = |h: pl_analysis::FieldHint, rows: &[&Row<'_>]| FieldHintView {
        summary: field_summary(&h),
        first_counterexample: h
            .first_counterexample
            .and_then(|i| usize::try_from(i).ok())
            .and_then(|i| rows.get(i))
            .map(|r| sample(r)),
        kind: h.kind,
        at: h.at,
        ty: h.ty,
        size: h.size,
        unit: h.unit,
        epoch: h.epoch,
        to_end: h.to_end,
        example: h.example,
        tags: h.tags,
        matches: h.matches,
        samples: h.samples,
        share_permille: h.share_permille,
        equivalent: h.equivalent,
    };
    let search = |rows: &[&Row<'_>]| {
        let samples: Vec<FieldSample<'_>> = rows
            .iter()
            .map(|r| FieldSample {
                data: &r.data,
                stream: r.stream,
                ts_ns: r.ts_ns,
            })
            .collect();
        pl_analysis::find_fields(&samples, cancelled)
    };

    let all: Vec<&Row<'_>> = rows.iter().collect();
    let selected: Vec<&Row<'_>> = rows.iter().filter(|r| r.selected).collect();
    let filtered = selected.len() != all.len();
    let found = search(&selected);
    let mut incomplete = found.incomplete;
    let mut hints: Vec<FieldHintView> = found
        .hints
        .into_iter()
        .filter(|h| !(filtered && h.kind == FieldKind::Counter))
        .map(|h| view(h, &selected))
        .collect();
    if filtered {
        let whole = search(&all);
        incomplete |= whole.incomplete;
        hints.extend(
            whole
                .hints
                .into_iter()
                .filter(|h| h.kind == FieldKind::Counter)
                .map(|h| view(h, &all)),
        );
        hints.sort_by_key(|h| (h.at, h.kind as u8));
    }
    Ok(FieldsView {
        messages: found.messages,
        truncated: found.truncated,
        incomplete,
        hints,
    })
}

/// Карта энтропии одного потока.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamEntropy {
    pub stream: String,
    /// Длина потока в байтах.
    pub length: u64,
    #[serde(flatten)]
    pub map: pl_analysis::EntropyMap,
    /// Что это значит, одной фразой.
    pub summary: String,
}

/// Где в потоках данные похожи на сжатые или зашифрованные, на текст и на заполнение.
pub fn stream_entropy(
    store: &SourceStore,
    streams: &[String],
) -> Result<Vec<StreamEntropy>, Problem> {
    check_streams(streams)?;
    let mut out = Vec::new();
    for id in streams {
        let (data, conn, dir) = resolve_stream(store, id).ok_or_else(|| not_found(id))?;
        let (Some(connection), Some(stream)) = (
            data.connections.get(conn),
            data.connections.get(conn).and_then(|c| c.streams.get(dir)),
        ) else {
            return Err(not_found(id));
        };
        let input = stream_input(&data.file, connection, stream, dir);
        // Подряд идущие известные участки склеиваются: окно не должно рваться на границе сегмента.
        let mut pieces: Vec<(u64, Vec<u8>)> = Vec::new();
        for region in &input.regions {
            let RegionKind::Data(bytes) = &region.kind else {
                continue;
            };
            match pieces.last_mut() {
                Some((start, joined)) if *start + joined.len() as u64 == region.start => {
                    joined.extend_from_slice(bytes);
                }
                _ => pieces.push((region.start, bytes.to_vec())),
            }
        }
        let refs: Vec<(u64, &[u8])> = pieces.iter().map(|(s, b)| (*s, b.as_slice())).collect();
        let map = pl_analysis::entropy_map(&refs);
        let share = |part: u64| part.saturating_mul(100).checked_div(map.bytes).unwrap_or(0);
        let summary = if map.bytes == 0 {
            format!(
                "Данных меньше окна в {} байт: об энтропии судить рано.",
                pl_analysis::ENTROPY_WINDOW
            )
        } else if map.high_bytes > 0 {
            format!(
                "{} % просмотренных байтов похожи на сжатые или зашифрованные: полей в них не найти.",
                share(map.high_bytes)
            )
        } else if map.text_bytes * 2 > map.bytes {
            format!(
                "{} % просмотренных байтов — печатный текст.",
                share(map.text_bytes)
            )
        } else {
            "Участков, похожих на сжатие или шифрование, нет.".to_owned()
        };
        out.push(StreamEntropy {
            stream: id.clone(),
            length: stream.length,
            map,
            summary,
        });
    }
    Ok(out)
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

#[derive(Debug, Clone, Default)]
pub struct CorrelationRequest {
    pub streams: Vec<String>,
    pub framing: Option<Framing>,
    pub message_id: Option<String>,
    /// Журнал действий; без значения — все журналы проекта.
    pub log_id: Option<String>,
    pub window_ms: Option<u64>,
}

/// Связи байтов сообщений с параметрами и именем действий из журнала.
pub fn message_correlations(
    session: &Session,
    store: &SourceStore,
    logs: &ActionLogStore,
    request: &CorrelationRequest,
    cancelled: &dyn Fn() -> bool,
) -> Result<Correlations, Problem> {
    check_streams(&request.streams)?;
    let it = effective(
        session,
        request.framing.as_ref(),
        request.message_id.is_some(),
    )?;
    correlations_on(&it, store, logs, request, cancelled)
}

/// То же на заданном описании: оно может быть ещё не сохранено в проекте.
pub(crate) fn correlations_on(
    it: &Interpretation,
    store: &SourceStore,
    logs: &ActionLogStore,
    request: &CorrelationRequest,
    cancelled: &dyn Fn() -> bool,
) -> Result<Correlations, Problem> {
    if request.streams.is_empty() || request.streams.len() > MAX_REQUEST_STREAMS {
        return Err(bad(format!(
            "streams — от 1 до {MAX_REQUEST_STREAMS} потоков."
        )));
    }
    if request.window_ms.is_some_and(|w| w > 600_000) {
        return Err(bad("windowMs — не больше 600000."));
    }
    let loaded = match &request.log_id {
        Some(id) => vec![logs.get(id).ok_or_else(|| {
            Problem::new(ProblemKind::NotFound, format!("Журнала действий {id} нет."))
        })?],
        None => logs.list(),
    };
    if loaded.is_empty() {
        return Err(Problem::new(
            ProblemKind::Conflict,
            "В проекте нет журнала действий: импортируйте его через POST /api/action-logs.",
        ));
    }
    let mut actions: Vec<&pl_actions::Action> =
        loaded.iter().flat_map(|l| l.actions.iter()).collect();
    actions.sort_by_key(|a| (a.ts_ns, a.line));
    let window_ns = request
        .window_ms
        .unwrap_or(crate::DEFAULT_WINDOW_MS)
        .saturating_mul(1_000_000);

    let mut samples: Vec<CorrSample> = Vec::new();
    for id in &request.streams {
        let (data, conn, dir) = resolve_stream(store, id).ok_or_else(|| not_found(id))?;
        let (Some(connection), Some(stream)) = (
            data.connections.get(conn),
            data.connections.get(conn).and_then(|c| c.streams.get(dir)),
        ) else {
            return Err(not_found(id));
        };
        let input = stream_input(&data.file, connection, stream, dir);
        let result = pl_interp::apply(it, &input, cancelled)
            .map_err(|e| Problem::new(ProblemKind::Unprocessable, format!("Поток {id}: {e}.")))?;
        let times = crate::hypothesis::Times::new(&data, stream);
        // Действия подбираются ко всем сообщениям потока, и только потом остаются сообщения нужного
        // типа: иначе сообщению досталось бы действие соседнего сообщения другого типа.
        let messages: Vec<_> = result.messages.iter().collect();
        let first_ts: Vec<u64> = messages
            .iter()
            .map(|m| times.first_ts(m.start, m.end).unwrap_or(0))
            .collect();
        let own: Vec<&pl_actions::Action> = actions
            .iter()
            .copied()
            .filter(|a| a.belongs_to(&data.name))
            .collect();
        let assigned = crate::hypothesis::assign(&first_ts, &own, window_ns);
        for (m, action) in messages.iter().zip(assigned) {
            if samples.len() > pl_analysis::MAX_CORR_SAMPLES {
                break;
            }
            if request
                .message_id
                .as_ref()
                .is_some_and(|want| m.message_id.as_ref() != Some(want))
            {
                continue;
            }
            let Read::Bytes(bytes) = input.read(m.start, m.end - m.start) else {
                continue;
            };
            let mut params = std::collections::BTreeMap::new();
            if let Some(a) = action {
                // Целые и точные дробные значения журнала («-2.5»): фиксированная точка в байтах.
                let decimal = |v: &pl_actions::Param| match v {
                    pl_actions::Param::Int(i) => {
                        i64::try_from(*i).ok().map(pl_analysis::Decimal::from)
                    }
                    pl_actions::Param::Text(t) => pl_analysis::Decimal::parse(t),
                };
                for (k, v) in &a.params {
                    if let Some(d) = decimal(v) {
                        params.insert(format!("params.{k}"), d);
                    }
                }
                for (k, v) in &a.result {
                    if let Some(d) = decimal(v) {
                        params.insert(format!("result.{k}"), d);
                    }
                }
            }
            samples.push(CorrSample {
                stream: id.clone(),
                start: m.start,
                bytes: bytes.into_owned(),
                params,
                action: action.map(|a| a.action.clone()),
            });
        }
    }
    Ok(correlate(&samples))
}
