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
use pl_interp::{Algorithm, Expr, ExprError, Interpretation, MessageResult, Value};
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

    fn checksum(&self, a: &Algorithm, _: i128, _: i128) -> Result<i128, ExprError> {
        Err(ExprError::UnknownFunction(a.name.to_owned()))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Моменты первого и последнего кадра сообщения по участкам потока (отсортированным по началу).
pub(crate) struct Times {
    spans: Vec<(u64, u64, u64)>,
    max_end: Vec<u64>,
}

impl Times {
    pub(crate) fn new(data: &SourceData, stream: &pl_reassembly::Stream) -> Self {
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

    pub(crate) fn first_ts(&self, start: u64, end: u64) -> Option<u64> {
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

/// Пары запрос→ответ в соединении, по ходам: подряд идущие сообщения одной стороны — ход, ход
/// запросов сопоставляется со следующим ходом ответов. Пара есть, только когда запросов и ответов
/// в соседних ходах поровну; запрос без ответа и ответ без запроса пары не получают и не сдвигают
/// остальные.
pub(crate) struct Links {
    /// Для сообщения начавшей стороны — номер его ответа в потоке встречной.
    pub(crate) response_of: Vec<Option<usize>>,
    /// Для сообщения встречной стороны — на что оно отвечает.
    pub(crate) request_of: Vec<Answer>,
}

/// Чей это ответ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answer {
    /// Ответ на запрос с этим номером.
    To(usize),
    /// Запросов в ходе не меньше, чем ответов: каждый ответ — чей-то, но чей именно, по порядку
    /// не определить. Действие подбирается по времени.
    Someone,
    /// Запроса нет или ответов больше, чем запросов: сообщение могло прийти само.
    Nobody,
}

pub(crate) fn pair_turns(requests: &[u64], responses: &[u64]) -> Links {
    let msgs: Vec<pl_analysis::Msg> = requests
        .iter()
        .map(|ts| (*ts, true))
        .chain(responses.iter().map(|ts| (*ts, false)))
        .enumerate()
        .map(|(id, (ts, from_initiator))| pl_analysis::Msg {
            id,
            from_initiator,
            first_ts_ns: ts,
            last_ts_ns: ts,
        })
        .collect();
    let mut links = Links {
        response_of: vec![None; requests.len()],
        request_of: vec![Answer::Nobody; responses.len()],
    };
    for pair in pl_analysis::pair_exchanges(&msgs).0 {
        if pair.certainty == pl_analysis::Certainty::Ambiguous
            && pair.requests.len() >= pair.responses.len()
        {
            for resp in &pair.responses {
                if let Some(slot) = resp
                    .checked_sub(requests.len())
                    .and_then(|r| links.request_of.get_mut(r))
                {
                    *slot = Answer::Someone;
                }
            }
        }
        if !matches!(
            pair.certainty,
            pl_analysis::Certainty::Certain | pl_analysis::Certainty::Ordered
        ) {
            continue;
        }
        let (Some(req), Some(resp)) = (pair.requests.first(), pair.responses.first()) else {
            continue;
        };
        let Some(resp) = resp.checked_sub(requests.len()) else {
            continue;
        };
        if let Some(slot) = links.response_of.get_mut(*req) {
            *slot = Some(resp);
        }
        if let Some(slot) = links.request_of.get_mut(resp) {
            *slot = Answer::To(*req);
        }
    }
    links
}

fn exchange_links(per_stream: &[Vec<Msg<'_>>], initiator: usize) -> Links {
    let stamps = |i: usize| -> Vec<u64> {
        per_stream
            .get(i)
            .map_or_else(Vec::new, |m| m.iter().map(|x| x.first_ts).collect())
    };
    pair_turns(&stamps(initiator), &stamps(1 - initiator))
}

/// Назначает действия сообщениям одного потока: сообщению — ближайшее предшествующее
/// неиспользованное действие в окне; у пачки действий с одним временем (несколько действий
/// в одном сегменте) — по порядку строк журнала. Действие, сообщение которого не записано
/// (дыра), остаётся без пары и не сдвигает остальные.
pub(crate) fn assign<'a>(
    first_ts: &[u64],
    actions: &[&'a Action],
    window_ns: u64,
) -> Vec<Option<&'a Action>> {
    let mut used = vec![false; actions.len()];
    let mut out = Vec::with_capacity(first_ts.len());
    for ts in first_ts {
        let end = actions.partition_point(|a| a.ts_ns <= ts.saturating_add(TOLERANCE_NS));
        // Действия раньше окна не подходят никогда: без этой границы каждый поиск проходил бы
        // весь журнал, и на длинных записях время росло бы квадратично.
        let start = actions.partition_point(|a| a.ts_ns < ts.saturating_sub(window_ns));
        let in_window = |i: usize| {
            !used.get(i).copied().unwrap_or(true)
                && actions
                    .get(i)
                    .is_some_and(|a| ts.saturating_sub(a.ts_ns) <= window_ns)
        };
        let latest = (start..end)
            .rev()
            .filter(|&i| in_window(i))
            .filter_map(|i| actions.get(i).map(|a| a.ts_ns))
            .next();
        let found = latest.and_then(|t| {
            (start..end).find(|&i| in_window(i) && actions.get(i).is_some_and(|a| a.ts_ns == t))
        });
        if let Some(i) = found
            && let Some(u) = used.get_mut(i)
        {
            *u = true;
        }
        out.push(found.and_then(|i| actions.get(i).copied()));
    }
    out
}

pub struct TestOptions {
    pub window_ms: u64,
    /// Потоки, чьи сообщения проверяются; без значения — все. Парный ответ берётся из встречного
    /// потока, даже если тот в корпус не входит.
    pub corpus: Option<pl_verify::CorpusFilter>,
}

impl Default for TestOptions {
    fn default() -> Self {
        Self {
            window_ms: DEFAULT_WINDOW_MS,
            corpus: None,
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
        let actions: Vec<&Action> = actions
            .iter()
            .copied()
            .filter(|a| a.belongs_to(&data.name))
            .collect();
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
                // Сообщение целиком в дыре времени не имеет: оно остаётся в списке (порядок ответов
                // важен для пар) со временем предыдущего сообщения и без действия журнала.
                let mut last = 0u64;
                let framed: Vec<(&MessageResult, u64)> = result
                    .messages
                    .iter()
                    .map(|m| {
                        let t = times.first_ts(m.start, m.end);
                        last = t.unwrap_or(last);
                        (m, last)
                    })
                    .collect();
                let timed: Vec<u64> = result
                    .messages
                    .iter()
                    .map(|m| times.first_ts(m.start, m.end).unwrap_or(0))
                    .collect();
                let assigned = assign(&timed, &actions, window_ns);
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
            // Кто начинает обмен: сторона, чьё первое сообщение раньше. Сообщения без времени
            // (целиком в дыре, время 0) не в счёт.
            let first_real = |msgs: &Vec<Msg<'_>>| msgs.iter().map(|m| m.first_ts).find(|t| *t > 0);
            let initiator = match (
                per_stream.first().and_then(first_real),
                per_stream.get(1).and_then(first_real),
            ) {
                (Some(a), Some(b)) => Some(usize::from(a > b)),
                _ => None,
            };
            let links = initiator.map(|side| exchange_links(&per_stream, side));
            // Ответ проверяется с действием своего запроса. Сообщение, которое встречная сторона
            // могла прислать сама, действия не получает: по времени ему досталось бы чужое.
            if let (Some(side), Some(links)) = (initiator, &links) {
                let request_action = |k: usize| {
                    per_stream
                        .get(side)
                        .and_then(|m| m.get(k))
                        .and_then(|m| m.action)
                };
                let decided: Vec<Option<Option<&Action>>> = links
                    .request_of
                    .iter()
                    .map(|answer| match answer {
                        Answer::To(k) => Some(request_action(*k)),
                        Answer::Nobody => Some(None),
                        Answer::Someone => None,
                    })
                    .collect();
                if let Some(answers) = per_stream.get_mut(1 - side) {
                    for (m, action) in answers.iter_mut().zip(decided) {
                        if let Some(action) = action {
                            m.action = action;
                        }
                    }
                }
            }
            for (i, msgs) in per_stream.iter().enumerate() {
                let (src, dst) = if i == 0 {
                    (connection.a.port(), connection.b.port())
                } else {
                    (connection.b.port(), connection.a.port())
                };
                if options
                    .corpus
                    .as_ref()
                    .is_some_and(|c| !c.accepts(&data.sha256, i, src, dst))
                {
                    continue;
                }
                let partner = per_stream.get(1 - i);
                let stamps: Vec<u64> = msgs.iter().map(|m| m.first_ts).collect();
                let partner_unsure: Vec<bool> = partner.map_or_else(Vec::new, |p| {
                    p.iter()
                        // Граница неизвестна (тип не определить: заголовок в дыре) — сколько ответов
                        // скрыто, неизвестно. Неполное сообщение с целым заголовком счёт не сбивает.
                        .map(|m| {
                            m.result.message_id.is_none()
                                && matches!(
                                    m.result.category,
                                    pl_interp::Category::Incomplete
                                        | pl_interp::Category::Ambiguous
                                )
                        })
                        .collect()
                });
                // Ответы ищутся только для стороны, которая начинает обмен. После сообщения
                // встречной стороны с неизвестной границей счёт ответов ненадёжен: пар дальше нет.
                let unsure_from = partner_unsure.iter().position(|u| *u);
                let pairs: Vec<Option<usize>> = match (&links, initiator == Some(i)) {
                    (Some(links), true) => links
                        .response_of
                        .iter()
                        .map(|r| r.filter(|j| unsure_from.is_none_or(|u| *j < u)))
                        .collect(),
                    _ => vec![None; stamps.len()],
                };
                for (k, m) in msgs.iter().enumerate() {
                    if m.result.message_id.is_none() {
                        continue;
                    }
                    // Байтов нет или они неоднозначны: такое сообщение гипотезу ни подтверждает,
                    // ни опровергает.
                    if matches!(
                        m.result.category,
                        pl_interp::Category::Incomplete | pl_interp::Category::Ambiguous
                    ) {
                        evidence.not_applicable += 1;
                        continue;
                    }
                    // Парный ответ — по ходам обмена (exchange_links); ответ без байтов или с неоднозначными
                    // байтами парой не считается.
                    let response = pairs
                        .get(k)
                        .copied()
                        .flatten()
                        .and_then(|j| partner.and_then(|p| p.get(j)))
                        .filter(|r| {
                            !matches!(
                                r.result.category,
                                pl_interp::Category::Incomplete | pl_interp::Category::Ambiguous
                            )
                        })
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
            source: None,
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
    fn missing_message_does_not_shift_the_following_actions() {
        // Ответ на первое действие не записан (дыра): второе сообщение — второму действию.
        let (a1, a2, a3) = (action(2, 1000), action(3, 1100), action(4, 1200));
        let actions = [&a1, &a2, &a3];
        let got = assign(&[1_105_000_000, 1_205_000_000], &actions, 2_000_000_000);
        let lines: Vec<Option<u64>> = got.iter().map(|a| a.map(|x| x.line)).collect();
        assert_eq!(lines, [Some(3), Some(4)]);
    }

    #[test]
    fn long_journal_is_assigned_in_reasonable_time() {
        // 50 тыс. действий раз в секунду и столько же сообщений через миллисекунду после каждого.
        let actions: Vec<Action> = (0..50_000u64).map(|i| action(i + 2, i * 1000)).collect();
        let refs: Vec<&Action> = actions.iter().collect();
        let stamps: Vec<u64> = (0..50_000u64)
            .map(|i| i * 1_000_000_000 + 1_000_000)
            .collect();
        let got = assign(&stamps, &refs, 2_000_000_000);
        assert!(
            got.iter()
                .enumerate()
                .all(|(i, a)| a.map(|x| x.line) == Some(i as u64 + 2))
        );
    }

    #[test]
    fn responses_pair_by_turns_and_gaps_do_not_shift_them() {
        // Конвейер: запросы в 6 и 14, оба ответа в 18; пачка запросов в 30 и ответы 31, 31.
        let links = pair_turns(&[6, 14, 30, 30], &[18, 18, 31, 31]);
        assert_eq!(links.response_of, [Some(0), Some(1), Some(2), Some(3)]);
        assert_eq!(
            links.request_of,
            [Answer::To(0), Answer::To(1), Answer::To(2), Answer::To(3)]
        );
        // Ответ, пришедший раньше запроса, — не его ответ и ничей.
        let links = pair_turns(&[10, 20], &[5, 12, 25]);
        assert_eq!(links.response_of, [Some(1), Some(2)]);
        assert_eq!(
            links.request_of,
            [Answer::Nobody, Answer::To(0), Answer::To(1)]
        );
        // Четыре запроса без ответа, затем запрос с ответом: какой запрос подтверждён, неизвестно —
        // пар нет, но следующий обмен не сдвигается.
        let links = pair_turns(&[1, 2, 3, 4, 10, 20], &[11, 21]);
        assert_eq!(links.response_of, [None, None, None, None, None, Some(1)]);
        assert_eq!(links.request_of, [Answer::Someone, Answer::To(5)]);
        // Сообщение, которое встречная сторона прислала сама, после ответа: запрос один, ответов
        // два — действие запроса не достаётся ни одному.
        let links = pair_turns(&[10, 30], &[11, 12, 31]);
        assert_eq!(
            links.request_of,
            [Answer::Nobody, Answer::Nobody, Answer::To(1)]
        );
    }

    #[test]
    fn a_frame_slightly_before_the_action_still_matches() {
        let a = action(2, 1000);
        let got = assign(&[999_980_000], &[&a], 2_000_000_000);
        assert_eq!(got[0].map(|x| x.line), Some(2));
    }
}
