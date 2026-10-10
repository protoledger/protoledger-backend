//! Изменчивость по смещениям: какие байты сообщений постоянны, какие меняются, где похоже на счётчик.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::{MAX_COLUMNS, MAX_MESSAGES};

/// Столько первых байтов проверяется на «похоже на счётчик».
const COUNTER_SPAN: usize = 64;
const COUNTER_MESSAGES: usize = 20_000;
const MIN_COUNTER_STEPS: u64 = 5;
const TOP_VALUES: usize = 3;

#[derive(Debug, Clone, Default)]
pub struct VariabilityOptions {
    /// Анализировать сообщения именно этой длины; без значения — самой частой.
    pub length: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TopValue {
    pub value: u8,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Column {
    pub offset: u32,
    pub samples: u64,
    pub distinct: u32,
    /// Энтропия значений в тысячных долях бита (0 — всегда одно значение, 8000 — равномерно по 256).
    pub entropy_millibits: u32,
    /// Значение, если оно одно и то же во всех сообщениях.
    pub constant: Option<u8>,
    pub top: Vec<TopValue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionKind {
    Constant,
    Varying,
}

/// Подряд идущие смещения одного вида.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Region {
    pub start: u32,
    pub end: u32,
    pub kind: RegionKind,
    /// Для постоянной области — её байты, hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CounterHint {
    pub at: u32,
    pub width: u8,
    pub big_endian: bool,
    /// Пар соседних сообщений, где значение выросло ровно на 1, из всех пар.
    pub steps: u64,
    pub pairs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LengthClass {
    pub length: u64,
    pub count: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Variability {
    /// Сообщений на входе (без отброшенных пределом).
    pub messages: u64,
    /// Часть сообщений не вошла в анализ (предел числа).
    pub truncated: bool,
    /// Длины сообщений и их количество, частые первыми.
    pub classes: Vec<LengthClass>,
    /// Длина, по которой построены столбцы.
    pub length: u64,
    /// Сообщений этой длины.
    pub analysed: u64,
    pub columns: Vec<Column>,
    pub regions: Vec<Region>,
    pub counters: Vec<CounterHint>,
}

fn entropy_millibits(counts: &[u64; 256], total: u64) -> u32 {
    if total == 0 {
        return 0;
    }
    let t = total as f64;
    let bits: f64 = counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / t;
            -p * p.log2()
        })
        .sum();
    (bits * 1000.0).round() as u32
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn read(msg: &[u8], at: usize, width: u8, big_endian: bool) -> Option<u64> {
    let raw = msg.get(at..at + usize::from(width))?;
    let mut v = 0u64;
    if big_endian {
        for b in raw {
            v = (v << 8) | u64::from(*b);
        }
    } else {
        for b in raw.iter().rev() {
            v = (v << 8) | u64::from(*b);
        }
    }
    Some(v)
}

fn counters(messages: &[&[u8]], length: usize) -> Vec<CounterHint> {
    let sample = messages
        .get(..messages.len().min(COUNTER_MESSAGES))
        .unwrap_or_default();
    let mut out = Vec::new();
    for at in 0..length.min(COUNTER_SPAN) {
        for (width, big_endian) in [(1u8, true), (2, true), (2, false), (4, true), (4, false)] {
            if at + usize::from(width) > length {
                continue;
            }
            let mask = if width >= 8 {
                u64::MAX
            } else {
                (1u64 << (u32::from(width) * 8)) - 1
            };
            let mut steps = 0u64;
            let mut pairs = 0u64;
            let mut prev: Option<u64> = None;
            for m in sample {
                let Some(v) = read(m, at, width, big_endian) else {
                    continue;
                };
                if let Some(p) = prev {
                    pairs += 1;
                    if v == p.wrapping_add(1) & mask {
                        steps += 1;
                    }
                }
                prev = Some(v);
            }
            if steps >= MIN_COUNTER_STEPS && steps * 10 >= pairs * 8 {
                out.push(CounterHint {
                    at: at as u32,
                    width,
                    big_endian,
                    steps,
                    pairs,
                });
            }
        }
    }
    // Одно и то же значение в двух ширинах — один и тот же счётчик: оставляем самое узкое по смещению.
    out.sort_by_key(|c| (c.at, c.width, !c.big_endian));
    let mut kept: Vec<CounterHint> = Vec::new();
    for c in out {
        let overlaps = kept.iter().any(|k| {
            let k_end = k.at + u32::from(k.width);
            c.at >= k.at && c.at < k_end && c.steps == k.steps && c.pairs == k.pairs
        });
        if !overlaps {
            kept.push(c);
        }
    }
    kept.truncate(8);
    kept
}

/// Изменчивость байтов сообщений. Сообщения выравниваются по началу; берутся сообщения одной длины.
pub fn variability(messages: &[&[u8]], options: &VariabilityOptions) -> Variability {
    let truncated = messages.len() > MAX_MESSAGES;
    let messages = messages
        .get(..messages.len().min(MAX_MESSAGES))
        .unwrap_or_default();

    let mut by_len: BTreeMap<usize, u64> = BTreeMap::new();
    for m in messages {
        *by_len.entry(m.len()).or_default() += 1;
    }
    let mut classes: Vec<LengthClass> = by_len
        .iter()
        .map(|(len, count)| LengthClass {
            length: *len as u64,
            count: *count,
        })
        .collect();
    classes.sort_by_key(|c| (std::cmp::Reverse(c.count), c.length));
    classes.truncate(32);

    let length = options
        .length
        .or_else(|| classes.first().map(|c| c.length as usize))
        .unwrap_or(0);
    let same: Vec<&[u8]> = messages
        .iter()
        .copied()
        .filter(|m| m.len() == length)
        .collect();

    let width = length.min(MAX_COLUMNS);
    let mut counts = vec![[0u64; 256]; width];
    for m in &same {
        for (i, b) in m.iter().take(width).enumerate() {
            if let Some(c) = counts
                .get_mut(i)
                .and_then(|col| col.get_mut(usize::from(*b)))
            {
                *c += 1;
            }
        }
    }
    let total = same.len() as u64;
    let columns: Vec<Column> = counts
        .iter()
        .enumerate()
        .map(|(offset, col)| {
            let distinct = col.iter().filter(|c| **c > 0).count() as u32;
            let mut top: Vec<TopValue> = col
                .iter()
                .enumerate()
                .filter(|(_, c)| **c > 0)
                .map(|(v, c)| TopValue {
                    value: v as u8,
                    count: *c,
                })
                .collect();
            top.sort_by_key(|t| (std::cmp::Reverse(t.count), t.value));
            top.truncate(TOP_VALUES);
            Column {
                offset: offset as u32,
                samples: total,
                distinct,
                entropy_millibits: entropy_millibits(col, total),
                constant: (distinct == 1).then(|| top.first().map_or(0, |t| t.value)),
                top,
            }
        })
        .collect();

    let mut regions: Vec<Region> = Vec::new();
    for c in &columns {
        let kind = if c.constant.is_some() {
            RegionKind::Constant
        } else {
            RegionKind::Varying
        };
        match regions.last_mut() {
            Some(r) if r.kind == kind && r.end == c.offset => {
                r.end = c.offset + 1;
                if let (Some(bytes), Some(v)) = (&mut r.bytes, c.constant) {
                    bytes.push_str(&hex(&[v]));
                }
            }
            _ => regions.push(Region {
                start: c.offset,
                end: c.offset + 1,
                kind,
                bytes: c.constant.map(|v| hex(&[v])),
            }),
        }
    }

    Variability {
        messages: messages.len() as u64,
        truncated,
        classes,
        length: length as u64,
        analysed: total,
        columns,
        regions,
        counters: counters(&same, length),
    }
}
