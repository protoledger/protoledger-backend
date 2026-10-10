//! Проверка гипотезы тестом-выражением на сообщениях корпуса.
//!
//! Тест может ссылаться на поля сообщения, поля парного ответа (`response.*`), параметры и результат
//! действия из журнала (`action.params.*`, `action.result.*`, `action.name`). Выражение, для которого
//! в сообщении нет нужных данных, к нему не применяется — это не успех и не неудача. Совпадение на k из n
//! примеров не доказывает гипотезу: итог — «контрпримеров нет» или «опровергнута».

use std::collections::BTreeMap;
use std::sync::Arc;

use pl_actions::{Action, Param};
use pl_core::{Problem, ProblemKind};
use pl_interp::expr::Context;
use pl_interp::{Expr, ExprError, Interpretation, MessageResult, Value};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::research::AnchorRef;
use crate::{LoadedLog, SourceData, stream_input};

const MAX_COUNTEREXAMPLES: usize = 50;
const MAX_ISSUES: usize = 20;
/// Окно между действием и первым кадром сообщения: часы клиента и запись могут расходиться.
pub const DEFAULT_WINDOW_MS: u64 = 2_000;
/// Допуск на случай, когда кадр записан чуть раньше момента, который отметил клиент.
const TOLERANCE_NS: u64 = 50_000_000;
const SUFFIX: [&str; 2] = ["ab", "ba"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Применимых сообщений не нашлось.
    Untested,
    /// Контрпримеров нет — это не доказательство.
    NoCounterexample,
    Refuted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Counterexample {
    pub anchor: AnchorRef,
    pub message_id: Option<String>,
    /// Значения имён из выражения на этом сообщении.
    pub values: BTreeMap<String, String>,
    pub action_line: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Issue {
    pub anchor: AnchorRef,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub test: String,
    pub verdict: Verdict,
    /// Сообщений, к которым тест применим.
    pub applicable: u64,
    /// Из них выполнилось.
    pub held: u64,
    /// Сообщений, к которым тест неприменим (нет нужных полей или действия).
    pub not_applicable: u64,
    pub counterexamples_total: u64,
    pub counterexamples: Vec<Counterexample>,
    /// Ошибки вычисления (несовместимые типы и т.п.): сообщения не учтены ни за, ни против.
    pub errors_total: u64,
    pub errors: Vec<Issue>,
    /// Журналы действий, использованные в тесте.
    pub logs: Vec<String>,
}

type Fields = BTreeMap<String, Value>;

struct Msg<'a> {
    result: &'a MessageResult,
    first_ts: u64,
    fields: Fields,
    action: Option<&'a Action>,
}

fn field_map(m: &MessageResult) -> Fields {
    m.fields
        .iter()
        .filter_map(|f| f.value.clone().map(|v| (f.name.clone(), v)))
        .collect()
}

fn param_value(p: &Param) -> Value {
    match p {
        Param::Int(i) => Value::Int(*i),
        Param::Text(t) => Value::Str(t.clone()),
    }
}

struct Ctx<'a> {
    fields: &'a Fields,
    response: Option<&'a Fields>,
    action: Option<&'a Action>,
    start: u64,
    len: u64,
}

impl Context for Ctx<'_> {
    fn get(&self, name: &str) -> Option<Value> {
        match name {
            "message.len" => Some(Value::Int(i128::from(self.len))),
            "message.start" => Some(Value::Int(i128::from(self.start))),
            "action.name" => self.action.map(|a| Value::Str(a.action.clone())),
            "action.result" => self.action.map(|a| Value::Str(a.result_raw.clone())),
            _ => {
                if let Some(key) = name.strip_prefix("response.") {
                    self.response?.get(key).cloned()
                } else if let Some(key) = name.strip_prefix("action.params.") {
                    self.action?.params.get(key).map(param_value)
                } else if let Some(key) = name.strip_prefix("action.result.") {
                    self.action?.result.get(key).map(param_value)
                } else {
                    self.fields.get(name).cloned()
                }
            }
        }
    }

    fn sum8(&self, _: i128, _: i128) -> Result<i128, ExprError> {
        Err(ExprError::UnknownFunction("sum8".to_owned()))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Моменты первого и последнего кадра сообщения по участкам потока (отсортированным по началу).
struct Times {
    spans: Vec<(u64, u64, u64)>,
    max_end: Vec<u64>,
}

impl Times {
    fn new(data: &SourceData, stream: &pl_reassembly::Stream) -> Self {
        let mut spans: Vec<(u64, u64, u64)> = stream
            .frames
            .iter()
            .map(|f| {
                (
                    f.start,
                    f.end,
                    data.index.frame(f.frame).map_or(0, |r| r.ts_ns),
                )
            })
            .collect();
        spans.sort_unstable();
        let mut max = 0;
        let max_end = spans
            .iter()
            .map(|s| {
                max = max.max(s.1);
                max
            })
            .collect();
        Self { spans, max_end }
    }

    fn first_ts(&self, start: u64, end: u64) -> Option<u64> {
        let lo = self.max_end.partition_point(|m| *m <= start);
        let hi = self.spans.partition_point(|s| s.0 < end);
        self.spans
            .get(lo..hi)?
            .iter()
            .filter(|s| s.1 > start)
            .map(|s| s.2)
            .min()
    }
}

/// Назначает действия сообщениям одного потока по порядку: пачка действий в один момент
/// соответствует пачке сообщений в одном сегменте. Сообщение без действия в окне остаётся без него.
fn assign<'a>(first_ts: &[u64], actions: &[&'a Action], window_ns: u64) -> Vec<Option<&'a Action>> {
    let mut used = vec![false; actions.len()];
    let mut out = Vec::with_capacity(first_ts.len());
    let mut from = 0usize;
    for ts in first_ts {
        let mut found = None;
        let mut i = from;
        while let Some(a) = actions.get(i) {
            if a.ts_ns > ts.saturating_add(TOLERANCE_NS) {
                break;
            }
            if !used.get(i).copied().unwrap_or(true) && ts.saturating_sub(a.ts_ns) <= window_ns {
                found = Some(i);
                break;
            }
            i += 1;
        }
        if let Some(i) = found {
            if let Some(u) = used.get_mut(i) {
                *u = true;
            }
            while used.get(from).copied().unwrap_or(false) {
                from += 1;
            }
            out.push(actions.get(i).copied());
        } else {
            out.push(None);
        }
    }
    out
}

pub struct TestOptions {
    pub window_ms: u64,
}

impl Default for TestOptions {
    fn default() -> Self {
        Self {
            window_ms: DEFAULT_WINDOW_MS,
        }
    }
}

/// Применяет тест к сообщениям всех записей проекта.
pub fn test_hypothesis(
    sources: &[Arc<SourceData>],
    it: &Interpretation,
    logs: &[Arc<LoadedLog>],
    expr_text: &str,
    options: &TestOptions,
) -> Result<Evidence, Problem> {
    let expr = Expr::parse(expr_text).map_err(|e| {
        Problem::new(
            ProblemKind::Unprocessable,
            format!("Тест гипотезы не разобран: {e}."),
        )
    })?;
    let names = expr.names();
    let mut actions: Vec<&Action> = logs.iter().flat_map(|l| l.actions.iter()).collect();
    actions.sort_by_key(|a| (a.ts_ns, a.line));
    let window_ns = options.window_ms.saturating_mul(1_000_000);

    let mut evidence = Evidence {
        test: expr_text.to_owned(),
        verdict: Verdict::Untested,
        applicable: 0,
        held: 0,
        not_applicable: 0,
        counterexamples_total: 0,
        counterexamples: Vec::new(),
        errors_total: 0,
        errors: Vec::new(),
        logs: logs.iter().map(|l| l.record.id.clone()).collect(),
    };

    for data in sources {
        for connection in &data.connections {
            let id = connection.id(&data.sha256);
            let mut results = Vec::new();
            let mut inputs = Vec::new();
            for (i, stream) in connection.streams.iter().enumerate() {
                let input = stream_input(&data.file, connection, stream, i);
                let result = pl_interp::apply(it, &input, &|| false).map_err(|e| {
                    Problem::new(
                        ProblemKind::LimitExceeded,
                        format!("Разбор остановлен: {e}."),
                    )
                })?;
                results.push(result);
                inputs.push(input);
            }
            // Сообщения по потокам со временем и назначенными действиями.
            let mut per_stream: Vec<Vec<Msg<'_>>> = Vec::new();
            for (i, stream) in connection.streams.iter().enumerate() {
                let times = Times::new(data, stream);
                let Some(result) = results.get(i) else {
                    continue;
                };
                let framed: Vec<(&MessageResult, u64)> = result
                    .messages
                    .iter()
                    .filter_map(|m| times.first_ts(m.start, m.end).map(|t| (m, t)))
                    .collect();
                let stamps: Vec<u64> = framed.iter().map(|(_, t)| *t).collect();
                let assigned = assign(&stamps, &actions, window_ns);
                per_stream.push(
                    framed
                        .into_iter()
                        .zip(assigned)
                        .map(|((m, t), action)| Msg {
                            result: m,
                            first_ts: t,
                            fields: field_map(m),
                            action,
                        })
                        .collect(),
                );
            }
            for (i, msgs) in per_stream.iter().enumerate() {
                let partner = per_stream.get(1 - i);
                for (k, m) in msgs.iter().enumerate() {
                    if m.result.message_id.is_none() {
                        continue;
                    }
                    // Парный ответ: сообщение встречного потока с тем же порядковым номером, отправленное
                    // не раньше запроса. Пачка запросов в одном сегменте получает ответы по порядку.
                    let response = partner
                        .and_then(|p| p.get(k))
                        .filter(|r| r.first_ts >= m.first_ts)
                        .map(|r| &r.fields);
                    let ctx = Ctx {
                        fields: &m.fields,
                        response,
                        action: m.action,
                        start: m.result.start,
                        len: m.result.end - m.result.start,
                    };
                    let anchor = || {
                        let sha256 = match inputs
                            .get(i)
                            .map(|inp| inp.read(m.result.start, m.result.end - m.result.start))
                        {
                            Some(pl_interp::Read::Bytes(b)) => Some(hex(&Sha256::digest(&b))),
                            _ => None,
                        };
                        AnchorRef {
                            source: data.sha256.clone(),
                            stream: format!("{id}:{}", SUFFIX.get(i).copied().unwrap_or("ab")),
                            start: m.result.start,
                            end: m.result.end,
                            sha256,
                        }
                    };
                    match expr.eval_bool(&ctx) {
                        Ok(true) => {
                            evidence.applicable += 1;
                            evidence.held += 1;
                        }
                        Ok(false) => {
                            evidence.applicable += 1;
                            evidence.counterexamples_total += 1;
                            if evidence.counterexamples.len() < MAX_COUNTEREXAMPLES {
                                evidence.counterexamples.push(Counterexample {
                                    anchor: anchor(),
                                    message_id: m.result.message_id.clone(),
                                    values: names
                                        .iter()
                                        .filter_map(|n| {
                                            ctx.get(n).map(|v| (n.clone(), v.to_string()))
                                        })
                                        .collect(),
                                    action_line: m.action.map(|a| a.line),
                                });
                            }
                        }
                        Err(ExprError::UnknownName(_)) => evidence.not_applicable += 1,
                        Err(e) => {
                            evidence.errors_total += 1;
                            if evidence.errors.len() < MAX_ISSUES {
                                evidence.errors.push(Issue {
                                    anchor: anchor(),
                                    detail: e.to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    evidence.verdict = if evidence.counterexamples_total > 0 {
        Verdict::Refuted
    } else if evidence.applicable > 0 {
        Verdict::NoCounterexample
    } else {
        Verdict::Untested
    };
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(line: u64, ts_ms: u64) -> Action {
        Action {
            line,
            ts_ns: ts_ms * 1_000_000,
            action: "x".to_owned(),
            params: BTreeMap::new(),
            result: BTreeMap::new(),
            result_raw: String::new(),
        }
    }

    #[test]
    fn actions_are_assigned_in_order_within_the_window() {
        let (a1, a2, a3) = (action(2, 1000), action(3, 1000), action(4, 9000));
        let actions = [&a1, &a2, &a3];
        let stamps = [1_000_100_000, 1_000_100_000, 5_000_000_000, 9_000_300_000];
        let got = assign(&stamps, &actions, 2_000_000_000);
        let lines: Vec<Option<u64>> = got.iter().map(|a| a.map(|x| x.line)).collect();
        assert_eq!(
            lines,
            [Some(2), Some(3), None, Some(4)],
            "пачка из двух — по порядку; без действия в окне — пусто"
        );
    }

    #[test]
    fn a_frame_slightly_before_the_action_still_matches() {
        let a = action(2, 1000);
        let got = assign(&[999_980_000], &[&a], 2_000_000_000);
        assert_eq!(got[0].map(|x| x.line), Some(2));
    }
}
