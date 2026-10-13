//! Сравнение поведения в двух наборах записей по одному описанию: какие типы сообщений появились
//! и пропали, какие значения полей стали другими, как изменилось время ответа. Сценарии: до и
//! после обновления прошивки, штатная работа и сбой, два экземпляра устройства.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use pl_analysis::{Certainty, Msg, pair_exchanges};
use pl_core::{Problem, ProblemKind};
use pl_interp::{FieldState, Interpretation, Value};
use serde::Serialize;

use crate::{SourceData, stream_input};

/// Поле с таким числом разных значений считается перечислением: сравниваются сами значения.
const ENUM_VALUES: usize = 16;
/// Больше значений не запоминается: дальше сравнивается только диапазон.
const MAX_VALUES: usize = 64;
const MAX_LISTED: usize = 8;
const MAX_FIELDS: usize = 100;
/// Меньше пар запрос→ответ — медиана ни о чём не говорит.
const MIN_PAIRS: usize = 3;
/// Изменение медианы времени ответа меньше чем в полтора раза не отмечается.
const TIMING_RATIO: u64 = 1500;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SideSummary {
    pub sources: u64,
    pub messages: u64,
    /// Сообщений по категориям результата.
    pub counts: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeChange {
    /// Тип есть только во втором наборе.
    New,
    /// Тип есть только в первом наборе.
    Missing,
    Same,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeDiff {
    /// Тип сообщения; `null` — тип не определён.
    pub message_id: Option<String>,
    pub a: u64,
    pub b: u64,
    pub change: TypeChange,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ValueStats {
    pub samples: u64,
    /// Разных значений; не больше 64 — дальше не считается.
    pub distinct: u32,
    pub min: Option<i64>,
    pub max: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldChange {
    /// У поля-перечисления другие значения.
    Values,
    /// У числового поля другой диапазон.
    Range,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldDiff {
    pub message_id: String,
    pub field: String,
    pub change: FieldChange,
    pub a: ValueStats,
    pub b: ValueStats,
    /// Значения, которые есть только во втором наборе (до 8).
    pub new_values: Vec<String>,
    /// Значения, которые есть только в первом наборе (до 8).
    pub gone_values: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Timing {
    pub pairs: u64,
    pub median_ns: u64,
    pub max_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimingDiff {
    /// Тип запроса.
    pub message_id: String,
    pub a: Timing,
    pub b: Timing,
    /// Медиана второго набора относительно первого, в тысячных (1000 — без изменений).
    pub ratio_permille: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Comparison {
    pub a: SideSummary,
    pub b: SideSummary,
    pub types: Vec<TypeDiff>,
    /// Только поля, у которых значения или диапазон отличаются.
    pub fields: Vec<FieldDiff>,
    /// Время от запроса до ответа по типам запросов, которые есть в обоих наборах.
    pub timing: Vec<TimingDiff>,
    /// Главное словами: по строке на отличие.
    pub summary: Vec<String>,
    pub incomplete: bool,
}

#[derive(Default)]
struct FieldAcc {
    samples: u64,
    values: BTreeSet<String>,
    overflow: bool,
    min: Option<i64>,
    max: Option<i64>,
}

#[derive(Default)]
struct Side {
    summary: SideSummary,
    types: BTreeMap<Option<String>, u64>,
    fields: BTreeMap<(String, String), FieldAcc>,
    delays: BTreeMap<String, Vec<u64>>,
    incomplete: bool,
}

fn collect(
    sources: &[Arc<SourceData>],
    it: &Interpretation,
    cancelled: &dyn Fn() -> bool,
) -> Result<Side, Problem> {
    let mut side = Side::default();
    'sources: for data in sources {
        for connection in &data.connections {
            // Сообщения соединения с временем первого кадра — для пар запрос→ответ.
            let mut msgs: Vec<Msg> = Vec::new();
            let mut ids: Vec<Option<String>> = Vec::new();
            for (dir, stream) in connection.streams.iter().enumerate() {
                if cancelled() {
                    side.incomplete = true;
                    break 'sources;
                }
                let input = stream_input(&data.file, connection, stream, dir);
                let result = pl_interp::apply(it, &input, cancelled).map_err(|e| {
                    Problem::new(
                        ProblemKind::LimitExceeded,
                        format!("Разбор остановлен: {e}."),
                    )
                })?;
                if result.out_of_scope {
                    continue;
                }
                let times = crate::hypothesis::Times::new(data, stream);
                for m in &result.messages {
                    side.summary.messages += 1;
                    let category = serde_json::to_value(m.category)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_owned))
                        .unwrap_or_default();
                    *side.summary.counts.entry(category).or_default() += 1;
                    *side.types.entry(m.message_id.clone()).or_default() += 1;
                    let ts = times.first_ts(m.start, m.end).unwrap_or(0);
                    msgs.push(Msg {
                        id: ids.len(),
                        from_initiator: dir == 0,
                        first_ts_ns: ts,
                        last_ts_ns: ts,
                    });
                    ids.push(m.message_id.clone());
                    let Some(id) = &m.message_id else { continue };
                    for f in &m.fields {
                        if f.state != FieldState::Decoded {
                            continue;
                        }
                        let (text, number) = match &f.value {
                            Some(Value::Int(v)) => (v.to_string(), i64::try_from(*v).ok()),
                            Some(Value::Bool(v)) => (v.to_string(), None),
                            Some(Value::Str(s)) if s.chars().count() <= 32 => (s.clone(), None),
                            Some(v @ Value::Bytes(b)) if b.len() <= 8 => (v.to_string(), None),
                            _ => continue,
                        };
                        let acc = side.fields.entry((id.clone(), f.name.clone())).or_default();
                        acc.samples += 1;
                        if let Some(n) = number {
                            acc.min = Some(acc.min.map_or(n, |m| m.min(n)));
                            acc.max = Some(acc.max.map_or(n, |m| m.max(n)));
                        }
                        if acc.values.len() < MAX_VALUES {
                            acc.values.insert(text);
                        } else if !acc.values.contains(&text) {
                            acc.overflow = true;
                        }
                    }
                }
            }
            let (pairs, _) = pair_exchanges(&msgs);
            for pair in pairs {
                if !matches!(pair.certainty, Certainty::Certain | Certainty::Ordered) {
                    continue;
                }
                let request = pair.requests.first().and_then(|i| ids.get(*i));
                if let (Some(Some(id)), Some(delay)) = (request, pair.delay_ns) {
                    side.delays.entry(id.clone()).or_default().push(delay);
                }
            }
        }
        side.summary.sources += 1;
    }
    Ok(side)
}

fn stats(acc: &FieldAcc) -> ValueStats {
    ValueStats {
        samples: acc.samples,
        distinct: acc.values.len() as u32,
        min: acc.min,
        max: acc.max,
    }
}

fn timing(delays: &[u64]) -> Timing {
    let mut sorted = delays.to_vec();
    sorted.sort_unstable();
    Timing {
        pairs: sorted.len() as u64,
        median_ns: sorted.get(sorted.len() / 2).copied().unwrap_or(0),
        max_ns: sorted.last().copied().unwrap_or(0),
    }
}

fn millis(ns: u64) -> String {
    format!("{},{:01} мс", ns / 1_000_000, ns % 1_000_000 / 100_000)
}

/// Сравнивает поведение в записях `a` и `b` по описанию `it`.
pub fn compare(
    a: &[Arc<SourceData>],
    b: &[Arc<SourceData>],
    it: &Interpretation,
    cancelled: &dyn Fn() -> bool,
) -> Result<Comparison, Problem> {
    let first = collect(a, it, cancelled)?;
    let second = collect(b, it, cancelled)?;
    let mut summary: Vec<String> = Vec::new();

    let all_types: BTreeSet<&Option<String>> =
        first.types.keys().chain(second.types.keys()).collect();
    let mut types: Vec<TypeDiff> = all_types
        .into_iter()
        .map(|id| {
            let (in_a, in_b) = (
                first.types.get(id).copied().unwrap_or(0),
                second.types.get(id).copied().unwrap_or(0),
            );
            TypeDiff {
                message_id: id.clone(),
                a: in_a,
                b: in_b,
                change: match (in_a, in_b) {
                    (0, _) => TypeChange::New,
                    (_, 0) => TypeChange::Missing,
                    _ => TypeChange::Same,
                },
            }
        })
        .collect();
    types.sort_by_key(|t| (t.change, std::cmp::Reverse(t.a + t.b), t.message_id.clone()));
    for t in &types {
        let name = t.message_id.as_deref().unwrap_or("без типа");
        match t.change {
            TypeChange::New => summary.push(format!(
                "Новый тип сообщений во втором наборе: {name} ({} шт.)",
                t.b
            )),
            TypeChange::Missing => summary.push(format!(
                "Во втором наборе нет сообщений типа {name} (в первом — {} шт.)",
                t.a
            )),
            TypeChange::Same => {}
        }
    }

    let mut fields: Vec<FieldDiff> = Vec::new();
    for (key, in_a) in &first.fields {
        let Some(in_b) = second.fields.get(key) else {
            continue;
        };
        let enumeration = !in_a.overflow
            && !in_b.overflow
            && in_a.values.len() <= ENUM_VALUES
            && in_b.values.len() <= ENUM_VALUES;
        let list = |x: &BTreeSet<String>, y: &BTreeSet<String>| -> Vec<String> {
            x.difference(y).take(MAX_LISTED).cloned().collect()
        };
        let (change, new_values, gone_values) = if enumeration {
            let (new, gone) = (
                list(&in_b.values, &in_a.values),
                list(&in_a.values, &in_b.values),
            );
            if new.is_empty() && gone.is_empty() {
                continue;
            }
            (FieldChange::Values, new, gone)
        } else {
            // Счётчики и измерения: значения всегда разные, смотреть стоит только на диапазон.
            let wider = match (in_a.min, in_a.max, in_b.min, in_b.max) {
                (Some(a0), Some(a1), Some(b0), Some(b1)) => b0 < a0 || b1 > a1,
                _ => false,
            };
            if !wider {
                continue;
            }
            (FieldChange::Range, Vec::new(), Vec::new())
        };
        let (id, field) = key;
        summary.push(match change {
            FieldChange::Values if !new_values.is_empty() => format!(
                "{id}.{field}: во втором наборе новые значения — {}",
                new_values.join(", ")
            ),
            FieldChange::Values => format!(
                "{id}.{field}: во втором наборе не встречаются значения {}",
                gone_values.join(", ")
            ),
            FieldChange::Range => format!(
                "{id}.{field}: диапазон шире — {}…{} вместо {}…{}",
                in_b.min.unwrap_or(0),
                in_b.max.unwrap_or(0),
                in_a.min.unwrap_or(0),
                in_a.max.unwrap_or(0)
            ),
        });
        fields.push(FieldDiff {
            message_id: id.clone(),
            field: field.clone(),
            change,
            a: stats(in_a),
            b: stats(in_b),
            new_values,
            gone_values,
        });
    }
    fields.sort_by(|x, y| {
        (x.change, &x.message_id, &x.field).cmp(&(y.change, &y.message_id, &y.field))
    });
    fields.truncate(MAX_FIELDS);

    let mut timings: Vec<TimingDiff> = Vec::new();
    for (id, in_a) in &first.delays {
        let Some(in_b) = second.delays.get(id) else {
            continue;
        };
        if in_a.len() < MIN_PAIRS || in_b.len() < MIN_PAIRS {
            continue;
        }
        let (ta, tb) = (timing(in_a), timing(in_b));
        let ratio = tb
            .median_ns
            .saturating_mul(1000)
            .checked_div(ta.median_ns)
            .unwrap_or(1000);
        if ratio >= TIMING_RATIO {
            summary.push(format!(
                "Ответ на {id} стал медленнее: медиана {} вместо {}",
                millis(tb.median_ns),
                millis(ta.median_ns)
            ));
        } else if ratio.saturating_mul(TIMING_RATIO) <= 1_000_000 {
            summary.push(format!(
                "Ответ на {id} стал быстрее: медиана {} вместо {}",
                millis(tb.median_ns),
                millis(ta.median_ns)
            ));
        }
        timings.push(TimingDiff {
            message_id: id.clone(),
            a: ta,
            b: tb,
            ratio_permille: ratio,
        });
    }
    if summary.is_empty() {
        summary.push(
            "Отличий в типах сообщений, значениях полей и времени ответа не найдено.".to_owned(),
        );
    }
    Ok(Comparison {
        incomplete: first.incomplete || second.incomplete,
        a: first.summary,
        b: second.summary,
        types,
        fields,
        timing: timings,
        summary,
    })
}
