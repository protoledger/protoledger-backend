//! Карта покрытия: какие байты сообщений каждого типа описаны правилом, какие — гипотезой,
//! какие помечены неизвестными и какие не описаны вовсе. Честная граница знания о протоколе
//! и план следующего шага исследования.

use std::collections::BTreeMap;
use std::sync::Arc;

use pl_core::{Problem, ProblemKind};
use pl_interp::schema::Status;
use pl_interp::{FieldState, Interpretation};
use serde::Serialize;

use crate::{SourceData, stream_input};

/// По стольким первым байтам сообщения строится карта; остальное входит только в суммы.
pub const COVERAGE_MAP_BYTES: usize = 256;
const MAX_REGIONS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Cover {
    /// Поле со статусом «правило».
    Rule,
    /// Поле со статусом «гипотеза».
    Hypothesis,
    /// Зона, объявленная неизвестной.
    Unknown,
    /// Байт без описания.
    None,
}

/// Подряд идущие смещения с одним и тем же описанием.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverRegion {
    pub start: u32,
    pub end: u32,
    pub status: Cover,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hypothesis: Option<String>,
    /// Доля сообщений, у которых эти байты описаны именно так (среди тех, что до них дотягиваются).
    pub share_permille: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CoverBytes {
    pub total: u64,
    pub rule: u64,
    pub hypothesis: u64,
    pub unknown: u64,
    pub none: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeCoverage {
    /// Тип сообщения; `null` — сообщения, тип которых не определён.
    pub message_id: Option<String>,
    pub messages: u64,
    pub min_len: u64,
    pub max_len: u64,
    pub bytes: CoverBytes,
    /// Гипотезы, на которые опираются поля этого типа.
    pub hypotheses: Vec<String>,
    pub regions: Vec<CoverRegion>,
    /// Карта обрезана: сообщение длиннее отображаемой части или областей слишком много.
    pub map_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Coverage {
    pub sources: u64,
    pub messages: u64,
    pub bytes: CoverBytes,
    /// Доля байтов, описанных правилом или гипотезой.
    pub described_permille: u32,
    pub types: Vec<TypeCoverage>,
    /// Разбор прерван: посчитана только часть записей.
    pub incomplete: bool,
}

/// Что известно о байте по одному смещению: сколько раз он описан каждым способом и каким полем.
#[derive(Default, Clone)]
struct Column {
    seen: u64,
    by: BTreeMap<(Cover, Option<String>, Option<String>), u64>,
}

#[derive(Default)]
struct Tally {
    messages: u64,
    min_len: u64,
    max_len: u64,
    bytes: CoverBytes,
    hypotheses: std::collections::BTreeSet<String>,
    columns: Vec<Column>,
    long: bool,
}

fn permille(part: u64, whole: u64) -> u32 {
    part.saturating_mul(1000).checked_div(whole).unwrap_or(0) as u32
}

fn add(bytes: &mut CoverBytes, cover: Cover, n: u64) {
    bytes.total += n;
    match cover {
        Cover::Rule => bytes.rule += n,
        Cover::Hypothesis => bytes.hypothesis += n,
        Cover::Unknown => bytes.unknown += n,
        Cover::None => bytes.none += n,
    }
}

/// Карта покрытия описания `it` на записях `sources`.
pub fn coverage(
    sources: &[Arc<SourceData>],
    it: &Interpretation,
    cancelled: &dyn Fn() -> bool,
) -> Result<Coverage, Problem> {
    let mut tallies: BTreeMap<Option<String>, Tally> = BTreeMap::new();
    let mut incomplete = false;
    let mut counted_sources = 0u64;
    'sources: for data in sources {
        for connection in &data.connections {
            for (i, stream) in connection.streams.iter().enumerate() {
                if cancelled() {
                    incomplete = true;
                    break 'sources;
                }
                let input = stream_input(&data.file, connection, stream, i);
                let result = pl_interp::apply(it, &input, cancelled).map_err(|e| {
                    Problem::new(
                        ProblemKind::LimitExceeded,
                        format!("Разбор остановлен: {e}."),
                    )
                })?;
                if result.out_of_scope {
                    continue;
                }
                for m in &result.messages {
                    let len = m.end.saturating_sub(m.start);
                    let t = tallies.entry(m.message_id.clone()).or_default();
                    t.min_len = if t.messages == 0 {
                        len
                    } else {
                        t.min_len.min(len)
                    };
                    t.max_len = t.max_len.max(len);
                    t.messages += 1;
                    let shown = usize::try_from(len)
                        .map_or(COVERAGE_MAP_BYTES, |l| l.min(COVERAGE_MAP_BYTES));
                    t.long |= len > COVERAGE_MAP_BYTES as u64;
                    if t.columns.len() < shown {
                        t.columns.resize(shown, Column::default());
                    }
                    // Байты начала сообщения — поимённо; при наложении полей сильнее то, что известно твёрже.
                    let mut head: Vec<(Cover, Option<&str>, Option<&str>)> =
                        vec![(Cover::None, None, None); shown];
                    let mut described = [0u64; 3];
                    let mut spans: Vec<(u64, u64, Cover)> = Vec::new();
                    for f in &m.fields {
                        if matches!(f.state, FieldState::OutOfMessage) || f.len == 0 {
                            continue;
                        }
                        let cover = match (f.status, f.state) {
                            (_, FieldState::Unknown) | (Status::Unknown, _) => Cover::Unknown,
                            (Status::Rule, _) => Cover::Rule,
                            (Status::Hypothesis, _) => Cover::Hypothesis,
                        };
                        if let Some(h) = &f.hypothesis {
                            t.hypotheses.insert(h.clone());
                        }
                        let (from, to) = (f.at.max(m.start), (f.at + f.len).min(m.end));
                        if from >= to {
                            continue;
                        }
                        spans.push((from - m.start, to - m.start, cover));
                        for o in (from - m.start)..(to - m.start).min(shown as u64) {
                            if let Some(slot) = head.get_mut(o as usize)
                                && cover < slot.0
                            {
                                *slot = (cover, Some(f.name.as_str()), f.hypothesis.as_deref());
                            }
                        }
                    }
                    // Суммы по всему сообщению: отрезки без двойного счёта, сильнейшее описание первым.
                    spans.sort_by_key(|(from, to, cover)| (*cover, *from, *to));
                    let mut taken: Vec<(u64, u64)> = Vec::new();
                    for (from, to, cover) in spans {
                        let mut free = vec![(from, to)];
                        for (a, b) in &taken {
                            free = free
                                .into_iter()
                                .flat_map(|(x, y)| {
                                    let left = (x, y.min(*a));
                                    let right = (x.max(*b), y);
                                    [left, right].into_iter().filter(|(p, q)| p < q)
                                })
                                .collect();
                        }
                        for (x, y) in free {
                            if let Some(slot) = described.get_mut(cover as usize) {
                                *slot += y - x;
                            }
                            taken.push((x, y));
                        }
                    }
                    let [rule, hypothesis, unknown] = described;
                    add(&mut t.bytes, Cover::Rule, rule);
                    add(&mut t.bytes, Cover::Hypothesis, hypothesis);
                    add(&mut t.bytes, Cover::Unknown, unknown);
                    add(
                        &mut t.bytes,
                        Cover::None,
                        len.saturating_sub(rule + hypothesis + unknown),
                    );
                    for (column, (cover, field, hyp)) in t.columns.iter_mut().zip(head) {
                        column.seen += 1;
                        *column
                            .by
                            .entry((cover, field.map(str::to_owned), hyp.map(str::to_owned)))
                            .or_default() += 1;
                    }
                }
            }
        }
        counted_sources += 1;
    }

    let mut total = CoverBytes::default();
    let mut messages = 0u64;
    let mut types: Vec<TypeCoverage> = tallies
        .into_iter()
        .map(|(message_id, t)| {
            messages += t.messages;
            total.total += t.bytes.total;
            total.rule += t.bytes.rule;
            total.hypothesis += t.bytes.hypothesis;
            total.unknown += t.bytes.unknown;
            total.none += t.bytes.none;
            let mut regions: Vec<CoverRegion> = Vec::new();
            let mut truncated = t.long;
            for (offset, column) in t.columns.iter().enumerate() {
                let Some(((status, field, hypothesis), count)) = column
                    .by
                    .iter()
                    .max_by_key(|(key, count)| (**count, std::cmp::Reverse((*key).clone())))
                else {
                    continue;
                };
                let share = permille(*count, column.seen);
                let same = regions.last().is_some_and(|last| {
                    last.end == offset as u32
                        && last.status == *status
                        && last.field == *field
                        && last.share_permille == share
                });
                if same {
                    if let Some(last) = regions.last_mut() {
                        last.end += 1;
                    }
                } else if regions.len() >= MAX_REGIONS {
                    truncated = true;
                    break;
                } else {
                    regions.push(CoverRegion {
                        start: offset as u32,
                        end: offset as u32 + 1,
                        status: *status,
                        field: field.clone(),
                        hypothesis: hypothesis.clone(),
                        share_permille: share,
                    });
                }
            }
            TypeCoverage {
                message_id,
                messages: t.messages,
                min_len: t.min_len,
                max_len: t.max_len,
                bytes: t.bytes,
                hypotheses: t.hypotheses.into_iter().collect(),
                regions,
                map_truncated: truncated,
            }
        })
        .collect();
    // Самые частые типы первыми; сообщения без типа — в конце.
    types.sort_by_key(|t| {
        (
            t.message_id.is_none(),
            std::cmp::Reverse(t.messages),
            t.message_id.clone(),
        )
    });
    Ok(Coverage {
        sources: counted_sources,
        messages,
        described_permille: permille(total.rule + total.hypothesis, total.total),
        bytes: total,
        types,
        incomplete,
    })
}
