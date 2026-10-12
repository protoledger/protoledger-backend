//! Подсказки исследователю поверх собранных потоков: границы, изменчивость, пары запрос→ответ.

use pl_analysis::{
    ChecksumAlt, ChecksumFn, CorrSample, Correlations, DataRun, Exchange, ExchangeStats,
    FramingHints, Msg, StreamSample, Variability, VariabilityOptions, correlate, find_framing,
    pair_exchanges, variability,
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
        let result = pl_interp::apply(&it, &input, cancelled)
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
    if request.streams.is_empty() || request.streams.len() > MAX_REQUEST_STREAMS {
        return Err(bad(format!(
            "streams — от 1 до {MAX_REQUEST_STREAMS} потоков."
        )));
    }
    if request.window_ms.is_some_and(|w| w > 600_000) {
        return Err(bad("windowMs — не больше 600000."));
    }
    let it = effective(
        session,
        request.framing.as_ref(),
        request.message_id.is_some(),
    )?;
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
        let result = pl_interp::apply(&it, &input, cancelled)
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
