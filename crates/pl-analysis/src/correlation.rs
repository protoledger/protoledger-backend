//! Корреляции байтов сообщений с действиями клиента: какое поле равно параметру действия, какой байт — код действия.
//!
//! Подсказки: совпадение на примерах не доказывает связь, поэтому у каждой есть число примеров, доля
//! и первый контрпример.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

/// Сколько сообщений участвует в анализе.
pub const MAX_CORR_SAMPLES: usize = 5_000;
/// Сколько первых байтов сообщения просматривается.
const MAX_OFFSET: usize = 64;
const MIN_SAMPLES: u64 = 5;
/// Доля совпадений (промилле), с которой связь показывается.
const MIN_SHARE: u32 = 800;
const MAX_HINTS: usize = 12;
const SCALES: [i64; 4] = [1, 10, 100, 1000];

/// Сообщение, к которому подобрано действие из журнала.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CorrSample {
    pub stream: String,
    pub start: u64,
    pub bytes: Vec<u8>,
    /// Числовые параметры и результат действия: `params.<имя>`, `result.<имя>`.
    pub params: BTreeMap<String, i64>,
    /// Имя действия, если к сообщению подобрано действие.
    pub action: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CorrCounter {
    pub stream: String,
    pub start: u64,
    /// Прочитанное значение и значение параметра.
    pub got: i64,
    pub expected: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValueHint {
    /// Имя из журнала: `params.value`, `result.applied`.
    pub param: String,
    pub at: u32,
    /// Тип поля в записи интерпретации: `u16le`, `i32be`…
    #[serde(rename = "type")]
    pub ty: &'static str,
    /// Связь: `декодированное = параметр × scale`.
    pub scale: i64,
    pub matches: u64,
    pub samples: u64,
    pub share_permille: u32,
    pub first_counterexample: Option<CorrCounter>,
    /// Другие чтения тех же байтов, дающие те же совпадения (например, старший байт числа).
    pub equivalent: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActionCode {
    pub action: String,
    pub value: u64,
    pub count: u64,
    pub of: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionHint {
    pub at: u32,
    #[serde(rename = "type")]
    pub ty: &'static str,
    pub purity_permille: u32,
    pub samples: u64,
    pub codes: Vec<ActionCode>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Correlations {
    pub samples: u64,
    pub with_action: u64,
    pub truncated: bool,
    pub values: Vec<ValueHint>,
    pub actions: Vec<ActionHint>,
}

#[derive(Debug, Clone, Copy)]
struct Ty {
    name: &'static str,
    width: usize,
    big_endian: bool,
    signed: bool,
}

const TYPES: [Ty; 9] = [
    Ty {
        name: "u8",
        width: 1,
        big_endian: true,
        signed: false,
    },
    Ty {
        name: "i8",
        width: 1,
        big_endian: true,
        signed: true,
    },
    Ty {
        name: "u16be",
        width: 2,
        big_endian: true,
        signed: false,
    },
    Ty {
        name: "u16le",
        width: 2,
        big_endian: false,
        signed: false,
    },
    Ty {
        name: "i16be",
        width: 2,
        big_endian: true,
        signed: true,
    },
    Ty {
        name: "i16le",
        width: 2,
        big_endian: false,
        signed: true,
    },
    Ty {
        name: "i32be",
        width: 4,
        big_endian: true,
        signed: true,
    },
    Ty {
        name: "i32le",
        width: 4,
        big_endian: false,
        signed: true,
    },
    Ty {
        name: "u32be",
        width: 4,
        big_endian: true,
        signed: false,
    },
];

fn decode(bytes: &[u8], at: usize, ty: Ty) -> Option<i64> {
    let raw = bytes.get(at..at.checked_add(ty.width)?)?;
    let mut v: u64 = 0;
    if ty.big_endian {
        for b in raw {
            v = (v << 8) | u64::from(*b);
        }
    } else {
        for b in raw.iter().rev() {
            v = (v << 8) | u64::from(*b);
        }
    }
    if ty.signed {
        let bits = (ty.width * 8) as u32;
        let shift = 64 - bits;
        Some(((v << shift) as i64) >> shift)
    } else {
        i64::try_from(v).ok()
    }
}

fn permille(part: u64, whole: u64) -> u32 {
    part.saturating_mul(1000)
        .checked_div(whole)
        .map_or(0, |v| u32::try_from(v).unwrap_or(1000))
}

fn fnv(hash: u64, value: u64) -> u64 {
    (hash ^ value).wrapping_mul(0x0000_0100_0000_01b3)
}

struct Found {
    hint: ValueHint,
    fingerprint: u64,
}

fn value_hints(samples: &[CorrSample]) -> Vec<ValueHint> {
    let names: BTreeSet<&String> = samples.iter().flat_map(|s| s.params.keys()).collect();
    let longest = samples.iter().map(|s| s.bytes.len()).max().unwrap_or(0);
    let mut found: Vec<Found> = Vec::new();
    for name in names {
        let with: Vec<(usize, &CorrSample, i64)> = samples
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.params.get(name).map(|v| (i, s, *v)))
            .collect();
        let distinct: BTreeSet<i64> = with.iter().map(|(_, _, v)| *v).collect();
        // Постоянный параметр совпадёт с любым постоянным байтом: связь по нему ничего не говорит.
        if with.len() as u64 >= MIN_SAMPLES && distinct.len() < 2 {
            continue;
        }
        for at in 0..longest.min(MAX_OFFSET) {
            for ty in TYPES {
                let readable: Vec<(usize, &CorrSample, i64, i64)> = with
                    .iter()
                    .filter_map(|(i, s, p)| decode(&s.bytes, at, ty).map(|d| (*i, *s, *p, d)))
                    .collect();
                let total = readable.len() as u64;
                if total < MIN_SAMPLES {
                    continue;
                }
                for scale in SCALES {
                    let mut matches = 0u64;
                    let mut fingerprint = 0xcbf2_9ce4_8422_2325u64;
                    let mut counter: Option<CorrCounter> = None;
                    for (i, s, p, d) in &readable {
                        if p.checked_mul(scale) == Some(*d) {
                            matches += 1;
                            fingerprint = fnv(fingerprint, *i as u64);
                        } else if counter.is_none() {
                            counter = Some(CorrCounter {
                                stream: s.stream.clone(),
                                start: s.start,
                                got: *d,
                                expected: *p,
                            });
                        }
                    }
                    let share = permille(matches, total);
                    if matches >= MIN_SAMPLES && share >= MIN_SHARE {
                        found.push(Found {
                            hint: ValueHint {
                                param: name.clone(),
                                at: at as u32,
                                ty: ty.name,
                                scale,
                                matches,
                                samples: total,
                                share_permille: share,
                                first_counterexample: counter,
                                equivalent: Vec::new(),
                            },
                            fingerprint,
                        });
                    }
                }
            }
        }
    }
    found.sort_by(|a, b| {
        let key = |f: &Found| {
            (
                std::cmp::Reverse(f.hint.share_permille),
                std::cmp::Reverse(f.hint.matches),
                f.hint.scale,
                f.hint.at,
                std::cmp::Reverse(f.hint.ty.len()),
                f.hint.ty.starts_with('i'),
                f.hint.ty,
            )
        };
        key(a).cmp(&key(b))
    });
    // Одно и то же совпадение на тех же примерах — одна находка; прочие чтения идут в `equivalent`.
    let mut out: Vec<ValueHint> = Vec::new();
    let mut seen: BTreeMap<(String, u64), usize> = BTreeMap::new();
    for f in found {
        let key = (f.hint.param.clone(), f.fingerprint);
        if let Some(&i) = seen.get(&key) {
            if let Some(h) = out.get_mut(i)
                && h.equivalent.len() < MAX_HINTS
            {
                h.equivalent.push(format!("{}@{}", f.hint.ty, f.hint.at));
            }
            continue;
        }
        if out.len() < MAX_HINTS {
            seen.insert(key, out.len());
            out.push(f.hint);
        }
    }
    out
}

fn action_hints(samples: &[CorrSample]) -> Vec<ActionHint> {
    let with: Vec<(&CorrSample, &String)> = samples
        .iter()
        .filter_map(|s| s.action.as_ref().map(|a| (s, a)))
        .collect();
    let actions: BTreeSet<&String> = with.iter().map(|(_, a)| *a).collect();
    if actions.len() < 2 {
        return Vec::new();
    }
    let longest = with.iter().map(|(s, _)| s.bytes.len()).max().unwrap_or(0);
    let mut out: Vec<ActionHint> = Vec::new();
    for at in 0..longest.min(MAX_OFFSET) {
        for ty in [TYPES[0], TYPES[2], TYPES[3]] {
            let mut per: BTreeMap<&String, BTreeMap<u64, u64>> = BTreeMap::new();
            let mut total = 0u64;
            for (s, a) in &with {
                if let Some(v) = decode(&s.bytes, at, ty).and_then(|v| u64::try_from(v).ok()) {
                    *per.entry(a).or_default().entry(v).or_default() += 1;
                    total += 1;
                }
            }
            if total < MIN_SAMPLES || per.len() < 2 {
                continue;
            }
            let mut codes: Vec<ActionCode> = per
                .iter()
                .filter_map(|(a, values)| {
                    let of: u64 = values.values().sum();
                    values
                        .iter()
                        .max_by_key(|(v, c)| (**c, std::cmp::Reverse(**v)))
                        .map(|(v, c)| ActionCode {
                            action: (*a).clone(),
                            value: *v,
                            count: *c,
                            of,
                        })
                })
                .collect();
            let pure: u64 = codes.iter().map(|c| c.count).sum();
            let distinct_values: BTreeSet<u64> = codes.iter().map(|c| c.value).collect();
            // Код действия: у разных действий разные значения, у одного действия — почти всегда одно.
            if permille(pure, total) >= MIN_SHARE && distinct_values.len() == codes.len() {
                codes.sort_by(|a, b| a.action.cmp(&b.action));
                out.push(ActionHint {
                    at: at as u32,
                    ty: ty.name,
                    purity_permille: permille(pure, total),
                    samples: total,
                    codes,
                });
            }
        }
    }
    out.sort_by_key(|h| (std::cmp::Reverse(h.purity_permille), h.at, h.ty.len()));
    // Тот же код в более широком типе — то же самое: оставляем самое узкое чтение на смещении.
    let mut kept: Vec<ActionHint> = Vec::new();
    for h in out {
        let same_codes = |k: &ActionHint| {
            k.codes == h.codes
                || k.codes
                    .iter()
                    .zip(&h.codes)
                    .all(|(a, b)| a.action == b.action && a.value == b.value)
        };
        if !kept.iter().any(|k| k.at == h.at && same_codes(k)) {
            kept.push(h);
        }
    }
    kept.truncate(MAX_HINTS);
    kept
}

/// Связи байтов сообщений с параметрами и именем действия.
pub fn correlate(samples: &[CorrSample]) -> Correlations {
    let truncated = samples.len() > MAX_CORR_SAMPLES;
    let samples = samples
        .get(..samples.len().min(MAX_CORR_SAMPLES))
        .unwrap_or_default();
    Correlations {
        samples: samples.len() as u64,
        with_action: samples.iter().filter(|s| s.action.is_some()).count() as u64,
        truncated,
        values: value_hints(samples),
        actions: action_hints(samples),
    }
}
