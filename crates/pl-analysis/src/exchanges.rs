//! Пары «запрос → ответ» по чередованию направлений внутри соединения.

use serde::Serialize;

/// Сообщение соединения: номер, сторона и время первого и последнего кадров.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Msg {
    pub id: usize,
    /// `true` — сообщение от инициатора (запрос), `false` — от второй стороны.
    pub from_initiator: bool,
    pub first_ts_ns: u64,
    pub last_ts_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Certainty {
    /// Один запрос и один ответ подряд.
    Certain,
    /// Запросов и ответов поровну: сопоставлены по порядку (конвейер), порядок — допущение.
    Ordered,
    /// Число запросов и ответов разное: какой ответ чей — неизвестно.
    Ambiguous,
    /// Запрос остался без ответа (конец записи).
    Unanswered,
    /// Ответ без запроса (запись началась посреди обмена).
    Unsolicited,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Exchange {
    pub requests: Vec<usize>,
    pub responses: Vec<usize>,
    /// Время от последнего кадра запроса до первого кадра ответа, нс (если ответ позже запроса).
    pub delay_ns: Option<u64>,
    pub certainty: Certainty,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeStats {
    pub exchanges: u64,
    pub certain: u64,
    pub ordered: u64,
    pub ambiguous: u64,
    pub unanswered: u64,
    pub unsolicited: u64,
    pub min_delay_ns: Option<u64>,
    pub median_delay_ns: Option<u64>,
    pub max_delay_ns: Option<u64>,
}

fn delay(req_last: Option<u64>, resp_first: Option<u64>) -> Option<u64> {
    Some(resp_first?.saturating_sub(req_last?))
}

/// Пары запрос→ответ. Сообщения упорядочиваются по времени первого кадра; подряд идущие сообщения
/// одной стороны образуют «ход», ход запросов сопоставляется со следующим ходом ответов.
pub fn pair_exchanges(messages: &[Msg]) -> (Vec<Exchange>, ExchangeStats) {
    let mut sorted: Vec<Msg> = messages.to_vec();
    sorted.sort_by_key(|m| (m.first_ts_ns, m.id));

    let mut turns: Vec<(bool, Vec<Msg>)> = Vec::new();
    for m in sorted {
        match turns.last_mut() {
            Some((side, list)) if *side == m.from_initiator => list.push(m),
            _ => turns.push((m.from_initiator, vec![m])),
        }
    }

    let mut out: Vec<Exchange> = Vec::new();
    let mut i = 0;
    while i < turns.len() {
        let Some((side, list)) = turns.get(i) else {
            break;
        };
        if !*side {
            // Ход ответов без предшествующего хода запросов.
            for m in list {
                out.push(Exchange {
                    requests: Vec::new(),
                    responses: vec![m.id],
                    delay_ns: None,
                    certainty: Certainty::Unsolicited,
                });
            }
            i += 1;
            continue;
        }
        match turns.get(i + 1) {
            Some((false, answers)) if answers.len() == list.len() => {
                let certainty = if list.len() == 1 {
                    Certainty::Certain
                } else {
                    Certainty::Ordered
                };
                for (req, resp) in list.iter().zip(answers) {
                    out.push(Exchange {
                        requests: vec![req.id],
                        responses: vec![resp.id],
                        delay_ns: delay(Some(req.last_ts_ns), Some(resp.first_ts_ns)),
                        certainty,
                    });
                }
                i += 2;
            }
            Some((false, answers)) => {
                out.push(Exchange {
                    requests: list.iter().map(|m| m.id).collect(),
                    responses: answers.iter().map(|m| m.id).collect(),
                    delay_ns: delay(
                        list.last().map(|m| m.last_ts_ns),
                        answers.first().map(|m| m.first_ts_ns),
                    ),
                    certainty: Certainty::Ambiguous,
                });
                i += 2;
            }
            _ => {
                for m in list {
                    out.push(Exchange {
                        requests: vec![m.id],
                        responses: Vec::new(),
                        delay_ns: None,
                        certainty: Certainty::Unanswered,
                    });
                }
                i += 1;
            }
        }
    }

    let mut stats = ExchangeStats {
        exchanges: out.len() as u64,
        ..ExchangeStats::default()
    };
    let mut delays: Vec<u64> = Vec::new();
    for e in &out {
        match e.certainty {
            Certainty::Certain => stats.certain += 1,
            Certainty::Ordered => stats.ordered += 1,
            Certainty::Ambiguous => stats.ambiguous += 1,
            Certainty::Unanswered => stats.unanswered += 1,
            Certainty::Unsolicited => stats.unsolicited += 1,
        }
        if matches!(e.certainty, Certainty::Certain | Certainty::Ordered)
            && let Some(d) = e.delay_ns
        {
            delays.push(d);
        }
    }
    delays.sort_unstable();
    stats.min_delay_ns = delays.first().copied();
    stats.max_delay_ns = delays.last().copied();
    stats.median_delay_ns = delays.get(delays.len() / 2).copied();
    (out, stats)
}
