//! Предложения наблюдений и гипотез из найденных связей «байты ↔ значение из журнала действий».
//! Каждая связь, которая сошлась почти на всех примерах, превращается в заготовку наблюдения
//! с якорем на байты и гипотезы с тестом. Ничего не создаётся само: исследователь принимает.

use pl_core::Problem;
use pl_interp::Interpretation;
use pl_interp::schema::fixed_size;
use serde::Serialize;

use crate::analysis::{CorrelationRequest, MAX_REQUEST_STREAMS, correlations_on};
use crate::{ActionLogStore, SourceStore, resolve_stream, stream_input};

/// Связь предлагается, если сошлась почти везде.
const MIN_SHARE: u32 = 900;
const MAX_SUGGESTIONS: usize = 100;

#[derive(Debug, Clone)]
pub struct SuggestRequest {
    pub streams: Vec<String>,
    /// Журнал действий; без значения — все журналы проекта.
    pub log_id: Option<String>,
}

/// Заготовка наблюдения: якорь на байты примера и комментарий.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObservationDraft {
    pub source: String,
    pub stream: String,
    pub start: u64,
    pub end: u64,
    pub comment: String,
}

/// Заготовка гипотезы; основание — наблюдение из той же строки.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HypothesisDraft {
    pub statement: String,
    pub test: String,
}

/// Поле, которого в описании ещё нет: без него тест гипотезы не на что опереть.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldDraft {
    pub name: String,
    pub at: u32,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub len: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mask: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Suggestion {
    pub message_id: String,
    /// Значение из журнала: `params.<имя>` или `result.<имя>`.
    pub param: String,
    pub matches: u64,
    pub samples: u64,
    pub observation: ObservationDraft,
    pub hypothesis: HypothesisDraft,
    /// Поле описания на этих байтах; `null` — поля нет, его нужно добавить из `new_field`.
    pub field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_field: Option<FieldDraft>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Suggestions {
    pub items: Vec<Suggestion>,
    pub truncated: bool,
}

fn safe_name(param: &str) -> String {
    let last = param.rsplit('.').next().unwrap_or(param);
    let mut name: String = last
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    if !name.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
        name.insert(0, 'f');
    }
    name
}

fn expression_name(name: &str) -> bool {
    name.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && name
            .split('.')
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
}

/// Предложения по сохранённому или переданному описанию `it` на потоках запроса.
pub fn research_suggestions(
    it: &Interpretation,
    store: &SourceStore,
    logs: &ActionLogStore,
    request: &SuggestRequest,
    cancelled: &dyn Fn() -> bool,
) -> Result<Suggestions, Problem> {
    if request.streams.is_empty() || request.streams.len() > MAX_REQUEST_STREAMS {
        return Err(Problem::new(
            pl_core::ProblemKind::BadRequest,
            format!("streams — от 1 до {MAX_REQUEST_STREAMS} потоков."),
        ));
    }
    let mut out = Suggestions::default();
    for message in &it.messages {
        if cancelled() {
            out.truncated = true;
            break;
        }
        let found = correlations_on(
            it,
            store,
            logs,
            &CorrelationRequest {
                streams: request.streams.clone(),
                framing: None,
                message_id: Some(message.id.clone()),
                log_id: request.log_id.clone(),
                window_ms: None,
                action: None,
            },
            cancelled,
        )?;
        // Пример сообщения этого типа: на его байты встанет якорь наблюдения.
        let mut example: Option<(String, &str, u64)> = None;
        'streams: for id in &request.streams {
            let Some((data, conn, dir)) = resolve_stream(store, id) else {
                continue;
            };
            let (Some(connection), Some(stream)) = (
                data.connections.get(conn),
                data.connections.get(conn).and_then(|c| c.streams.get(dir)),
            ) else {
                continue;
            };
            let input = stream_input(&data.file, connection, stream, dir);
            let Ok(result) = pl_interp::apply(it, &input, cancelled) else {
                continue;
            };
            for m in &result.messages {
                if m.message_id.as_deref() == Some(message.id.as_str()) {
                    example = Some((data.sha256.clone(), id.as_str(), m.start));
                    break 'streams;
                }
            }
        }
        let Some((source, stream, start)) = example else {
            continue;
        };
        let mut taken: Vec<(u32, u32)> = Vec::new();
        for v in found
            .values
            .iter()
            .filter(|v| v.share_permille >= MIN_SHARE && expression_name(&v.param))
        {
            // Одни и те же байты — одна строка: лучшая связь идёт первой.
            if taken.iter().any(|(a, b)| v.at < *b && *a < v.at + v.size) {
                continue;
            }
            if out.items.len() >= MAX_SUGGESTIONS {
                out.truncated = true;
                break;
            }
            taken.push((v.at, v.at + v.size));
            let digits = match v.scale {
                1 => 0,
                10 => 1,
                100 => 2,
                1000 => 3,
                _ => continue,
            };
            // Одни и те же совпадения дают несколько чтений: «u16 по смещению 8» и «u8 по смещению 9»,
            // если старший байт — ноль. Поле описания ровно на байтах одного из них — тест опирается
            // на него; иначе предлагается самое узкое чтение, чтобы не поглотить соседний байт.
            let mut readings: Vec<(u32, String, u32)> = vec![(v.at, v.ty.to_owned(), v.size)];
            if v.mask.is_none() {
                for alt in &v.equivalent {
                    if let Some((ty, at)) = alt.split_once('@')
                        && let (Ok(at), Some(size)) =
                            (at.parse::<u32>(), crate::draft::type_size(ty))
                    {
                        readings.push((at, ty.to_owned(), size as u32));
                    }
                }
            }
            let described = readings.iter().find_map(|(at, ty, size)| {
                message
                    .fields
                    .iter()
                    .find(|f| {
                        f.at.abs() == Some(*at)
                            && fixed_size(f) == Some(u64::from(*size))
                            && f.mask == v.mask
                    })
                    .map(|f| (f, *at, ty.clone(), *size))
            });
            let existing = described.as_ref().map(|(f, ..)| *f);
            let (at, ty, size) = match &described {
                Some((_, at, ty, size)) => (*at, ty.clone(), *size),
                None if v.mask.is_none() => {
                    let (at, ty) = crate::draft::narrowest(v.at, v.ty, &v.equivalent);
                    let size = crate::draft::type_size(&ty).map_or(v.size, |s| s as u32);
                    (at, ty, size)
                }
                None => (v.at, v.ty.to_owned(), v.size),
            };
            let name = existing.map_or_else(|| safe_name(&v.param), |f| f.name.clone());
            let float = ty.starts_with('f');
            let test = if float {
                format!("dec({name}, 3) == dec(action.{}, 3)", v.param)
            } else if digits == 0 {
                format!("{name} == action.{}", v.param)
            } else {
                format!("{name} == dec(action.{}, {digits})", v.param)
            };
            let scale = if digits == 0 {
                String::new()
            } else {
                format!(", умноженному на {}", v.scale)
            };
            let bytes = if size == 1 {
                format!("Байт {at}")
            } else {
                format!("Байты {at}–{}", at + size - 1)
            };
            out.items.push(Suggestion {
                message_id: message.id.clone(),
                param: v.param.clone(),
                matches: v.matches,
                samples: v.samples,
                observation: ObservationDraft {
                    source: source.clone(),
                    stream: stream.to_owned(),
                    start: start + u64::from(at),
                    end: start + u64::from(at) + u64::from(size),
                    comment: format!(
                        "{bytes} сообщения {} ({}) равны значению «{}» из журнала действий{scale}: совпало в {} из {} сообщений.",
                        message.id, ty, v.param, v.matches, v.samples
                    ),
                },
                hypothesis: HypothesisDraft {
                    statement: format!(
                        "{name} в сообщении {} — значение «{}» из журнала действий{scale}",
                        message.id, v.param
                    ),
                    test,
                },
                field: existing.map(|f| f.name.clone()),
                new_field: existing.is_none().then(|| FieldDraft {
                    name,
                    at,
                    len: (ty == "bcd").then_some(size),
                    ty,
                    mask: v.mask,
                }),
            });
        }
    }
    Ok(out)
}
