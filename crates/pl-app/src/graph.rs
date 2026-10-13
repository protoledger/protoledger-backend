//! Граф обмена: какие типы сообщений встречаются, чем на них отвечают и что обычно идёт следом.
//! Строится по всем соединениям записей; это наблюдаемое поведение, а не заявленный автомат
//! состояний протокола.

use std::collections::BTreeMap;
use std::sync::Arc;

use pl_analysis::{Certainty, Msg, pair_exchanges};
use pl_core::{Problem, ProblemKind};
use pl_interp::Interpretation;
use serde::Serialize;

use crate::{SourceData, stream_input};

const MAX_EDGES: usize = 200;
/// Имя узла для сообщений, тип которых не определён.
const UNKNOWN: &str = "?";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphNode {
    /// Тип сообщения; `?` — тип не определён.
    pub id: String,
    /// Сколько раз сообщение отправила сторона, начавшая соединение, и сколько — встречная.
    pub requests: u64,
    pub responses: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeGraph {
    pub connections: u64,
    pub messages: u64,
    pub nodes: Vec<GraphNode>,
    /// Запрос → ответ: только пары, где ответ определён однозначно или по порядку.
    pub answers: Vec<GraphEdge>,
    /// Запрос → следующий запрос той же стороны в том же соединении.
    pub next: Vec<GraphEdge>,
    /// С каких запросов соединения начинаются.
    pub starts: Vec<GraphEdge>,
    /// Запросы, оставшиеся без ответа, и сообщения встречной стороны без запроса.
    pub unanswered: u64,
    pub unsolicited: u64,
    /// Граф в формате Graphviz DOT: сплошные стрелки — ответы, пунктирные — следующий запрос.
    pub dot: String,
    pub truncated: bool,
    pub incomplete: bool,
}

fn edges(map: BTreeMap<(String, String), u64>, truncated: &mut bool) -> Vec<GraphEdge> {
    let mut out: Vec<GraphEdge> = map
        .into_iter()
        .map(|((from, to), count)| GraphEdge { from, to, count })
        .collect();
    out.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| (&a.from, &a.to).cmp(&(&b.from, &b.to)))
    });
    if out.len() > MAX_EDGES {
        out.truncate(MAX_EDGES);
        *truncated = true;
    }
    out
}

/// Идентификатор типа — буквы, цифры и подчёркивания; остальное в DOT заменяется.
fn dot_id(id: &str) -> String {
    let clean: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("\"{clean}\"")
}

/// Граф обмена по описанию `it` на записях `sources`.
pub fn exchange_graph(
    sources: &[Arc<SourceData>],
    it: &Interpretation,
    cancelled: &dyn Fn() -> bool,
) -> Result<ExchangeGraph, Problem> {
    let mut nodes: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut answers: BTreeMap<(String, String), u64> = BTreeMap::new();
    let mut next: BTreeMap<(String, String), u64> = BTreeMap::new();
    let mut starts: BTreeMap<(String, String), u64> = BTreeMap::new();
    let (mut connections, mut messages, mut unanswered, mut unsolicited) = (0u64, 0u64, 0u64, 0u64);
    let mut incomplete = false;
    'sources: for data in sources {
        for connection in &data.connections {
            let mut msgs: Vec<Msg> = Vec::new();
            let mut ids: Vec<String> = Vec::new();
            for (dir, stream) in connection.streams.iter().enumerate() {
                if cancelled() {
                    incomplete = true;
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
                let mut last = 0u64;
                for m in &result.messages {
                    // Сообщение без времени (целиком в дыре) остаётся на своём месте в потоке.
                    last = times.first_ts(m.start, m.end).unwrap_or(last);
                    let id = m.message_id.clone().unwrap_or_else(|| UNKNOWN.to_owned());
                    let node = nodes.entry(id.clone()).or_default();
                    if dir == 0 {
                        node.0 += 1;
                    } else {
                        node.1 += 1;
                    }
                    msgs.push(Msg {
                        id: ids.len(),
                        from_initiator: dir == 0,
                        first_ts_ns: last,
                        last_ts_ns: last,
                    });
                    ids.push(id);
                }
            }
            if msgs.is_empty() {
                continue;
            }
            connections += 1;
            messages += msgs.len() as u64;
            let name = |i: &usize| ids.get(*i).cloned().unwrap_or_else(|| UNKNOWN.to_owned());
            // Запросы соединения по порядку: переходы «что идёт следом».
            let mut requests: Vec<&Msg> = msgs.iter().filter(|m| m.from_initiator).collect();
            requests.sort_by_key(|m| (m.first_ts_ns, m.id));
            if let Some(first) = requests.first() {
                *starts
                    .entry(("начало".to_owned(), name(&first.id)))
                    .or_default() += 1;
            }
            for pair in requests.windows(2) {
                if let [a, b] = pair {
                    *next.entry((name(&a.id), name(&b.id))).or_default() += 1;
                }
            }
            for pair in pair_exchanges(&msgs).0 {
                match pair.certainty {
                    Certainty::Certain | Certainty::Ordered => {
                        if let (Some(req), Some(resp)) =
                            (pair.requests.first(), pair.responses.first())
                        {
                            *answers.entry((name(req), name(resp))).or_default() += 1;
                        }
                    }
                    Certainty::Unanswered => unanswered += pair.requests.len() as u64,
                    Certainty::Unsolicited => unsolicited += pair.responses.len() as u64,
                    Certainty::Ambiguous => {}
                }
            }
        }
    }

    let mut truncated = false;
    let nodes: Vec<GraphNode> = nodes
        .into_iter()
        .map(|(id, (requests, responses))| GraphNode {
            id,
            requests,
            responses,
        })
        .collect();
    let answers = edges(answers, &mut truncated);
    let next = edges(next, &mut truncated);
    let starts = edges(starts, &mut truncated);

    let mut dot = String::from("digraph exchange {\n  rankdir=LR;\n  node [shape=box];\n");
    for n in &nodes {
        dot.push_str(&format!(
            "  {} [label=\"{}\\n{}\"];\n",
            dot_id(&n.id),
            dot_id(&n.id).trim_matches('"'),
            n.requests + n.responses
        ));
    }
    for e in &answers {
        dot.push_str(&format!(
            "  {} -> {} [label=\"{}\"];\n",
            dot_id(&e.from),
            dot_id(&e.to),
            e.count
        ));
    }
    for e in &next {
        dot.push_str(&format!(
            "  {} -> {} [label=\"{}\", style=dashed];\n",
            dot_id(&e.from),
            dot_id(&e.to),
            e.count
        ));
    }
    dot.push_str("}\n");

    Ok(ExchangeGraph {
        connections,
        messages,
        nodes,
        answers,
        next,
        starts,
        unanswered,
        unsolicited,
        dot,
        truncated,
        incomplete,
    })
}
