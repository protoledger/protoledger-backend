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

/// Точное десятичное значение параметра: `num / 10^exp` (журнал: «-2.5», «18.25»).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Decimal {
    pub num: i64,
    pub exp: u32,
}

impl From<i64> for Decimal {
    fn from(num: i64) -> Self {
        Self { num, exp: 0 }
    }
}

impl Decimal {
    /// Не больше трёх знаков после запятой (масштабы до 1000); лишние нули отбрасываются.
    pub fn parse(text: &str) -> Option<Self> {
        let t = text.trim();
        let (neg, t) = match t.strip_prefix('-') {
            Some(r) => (true, r),
            None => (false, t),
        };
        let (whole, frac) = t.split_once('.').unwrap_or((t, ""));
        let frac = frac.trim_end_matches('0');
        let digits = |x: &str| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit());
        if !digits(whole) || !(frac.is_empty() || digits(frac)) || frac.len() > 3 {
            return None;
        }
        let num: i64 = format!("{whole}{frac}").parse().ok()?;
        Some(Self {
            num: if neg { -num } else { num },
            exp: frac.len() as u32,
        })
    }

    /// `self × scale == value` без округления.
    fn times_equals(self, scale: i64, value: i64) -> bool {
        let lhs = i128::from(self.num) * i128::from(scale);
        let rhs = i128::from(value) * 10i128.pow(self.exp);
        lhs == rhs
    }
}

impl std::fmt::Display for Decimal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.exp == 0 {
            return write!(f, "{}", self.num);
        }
        let p = 10i64.pow(self.exp);
        let sign = if self.num < 0 { "-" } else { "" };
        let a = self.num.unsigned_abs();
        write!(
            f,
            "{sign}{}.{:0w$}",
            a / p as u64,
            a % p as u64,
            w = self.exp as usize
        )
    }
}

/// Сообщение, к которому подобрано действие из журнала.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CorrSample {
    pub stream: String,
    pub start: u64,
    pub bytes: Vec<u8>,
    /// Числовые параметры и результат действия: `params.<имя>`, `result.<имя>`.
    pub params: BTreeMap<String, Decimal>,
    /// Имя действия, если к сообщению подобрано действие.
    pub action: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CorrCounter {
    pub stream: String,
    pub start: u64,
    /// Прочитанное значение и значение параметра (целая часть, если он дробный).
    pub got: i64,
    pub expected: i64,
    /// Значение параметра точно, как в журнале («-2.5»).
    pub param_value: String,
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
    /// Размер поля в байтах (для `bcd` это его `len`).
    pub size: u32,
    /// Битовое поле: значение — биты маски, сдвинутые к младшему.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mask: Option<u64>,
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

/// Чтение байтов сообщения как значения: целое, двоично-десятичное, битовое поле, с плавающей точкой.
#[derive(Debug, Clone, Copy)]
enum Encoding {
    Int(Ty),
    Bcd { width: usize },
    Bits { mask: u8 },
    Float { width: usize, big_endian: bool },
}

/// Прочитанное значение: целое сравнивается с параметром через масштаб, десятичное — как есть.
#[derive(Debug, Clone, Copy)]
enum Reading {
    Int(i64),
    Dec(Decimal, i64),
}

/// Битовым полям нужно больше примеров, чем числам: один бит совпадает случайно в половине случаев.
const MIN_BIT_SAMPLES: u64 = 16;

fn encodings() -> Vec<Encoding> {
    let mut all: Vec<Encoding> = TYPES.into_iter().map(Encoding::Int).collect();
    all.extend([1usize, 2, 4].map(|width| Encoding::Bcd { width }));
    for (width, big_endian) in [(4, true), (4, false), (8, true), (8, false)] {
        all.push(Encoding::Float { width, big_endian });
    }
    // Подряд идущие биты одного байта, от одного до четырёх; весь байт — это уже u8.
    for bits in 1..=4u32 {
        for shift in 0..=(8 - bits) {
            all.push(Encoding::Bits {
                mask: (((1u16 << bits) - 1) << shift) as u8,
            });
        }
    }
    all
}

impl Encoding {
    fn name(self) -> &'static str {
        match self {
            Encoding::Int(ty) => ty.name,
            Encoding::Bcd { .. } => "bcd",
            Encoding::Bits { .. } => "u8",
            Encoding::Float {
                width: 4,
                big_endian: true,
            } => "f32be",
            Encoding::Float {
                width: 4,
                big_endian: false,
            } => "f32le",
            Encoding::Float {
                big_endian: true, ..
            } => "f64be",
            Encoding::Float { .. } => "f64le",
        }
    }

    fn size(self) -> usize {
        match self {
            Encoding::Int(ty) => ty.width,
            Encoding::Bcd { width } | Encoding::Float { width, .. } => width,
            Encoding::Bits { .. } => 1,
        }
    }

    /// Порядок при равных совпадениях: простое чтение раньше сложного.
    fn rank(self) -> u8 {
        match self {
            Encoding::Int(_) => 0,
            Encoding::Bcd { .. } => 1,
            Encoding::Float { .. } => 2,
            Encoding::Bits { .. } => 3,
        }
    }

    fn read(self, bytes: &[u8], at: usize) -> Option<Reading> {
        let raw = bytes.get(at..at.checked_add(self.size())?)?;
        match self {
            Encoding::Int(ty) => decode(bytes, at, ty).map(Reading::Int),
            Encoding::Bcd { .. } => raw
                .iter()
                .try_fold(0i64, |acc, b| {
                    let (high, low) = (b >> 4, b & 0x0f);
                    (high <= 9 && low <= 9).then(|| acc * 100 + i64::from(high * 10 + low))
                })
                .map(Reading::Int),
            Encoding::Bits { mask } => raw
                .first()
                .map(|b| Reading::Int(i64::from((b & mask) >> mask.trailing_zeros()))),
            Encoding::Float { big_endian, .. } => {
                let mut ordered = raw.to_vec();
                if !big_endian {
                    ordered.reverse();
                }
                let value = match ordered.as_slice() {
                    [a, b, c, d] => f64::from(f32::from_be_bytes([*a, *b, *c, *d])),
                    [a, b, c, d, e, f, g, h] => {
                        f64::from_be_bytes([*a, *b, *c, *d, *e, *f, *g, *h])
                    }
                    _ => return None,
                };
                // Кратчайшая десятичная запись: так же поле читает описание.
                let text = match ordered.len() {
                    4 => (value as f32).to_string(),
                    _ => value.to_string(),
                };
                let whole = if value.is_finite() {
                    value.trunc() as i64
                } else {
                    0
                };
                Decimal::parse(&text).map(|d| Reading::Dec(d, whole))
            }
        }
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
    rank: u8,
}

fn value_hints(samples: &[CorrSample]) -> Vec<ValueHint> {
    let names: BTreeSet<&String> = samples.iter().flat_map(|s| s.params.keys()).collect();
    let longest = samples.iter().map(|s| s.bytes.len()).max().unwrap_or(0);
    let mut found: Vec<Found> = Vec::new();
    let all = encodings();
    for name in names {
        let with: Vec<(usize, &CorrSample, Decimal)> = samples
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.params.get(name).map(|v| (i, s, *v)))
            .collect();
        let distinct: BTreeSet<Decimal> = with.iter().map(|(_, _, v)| *v).collect();
        // Постоянный параметр совпадёт с любым постоянным байтом: связь по нему ничего не говорит.
        if with.len() as u64 >= MIN_SAMPLES && distinct.len() < 2 {
            continue;
        }
        // Битовое поле имеет смысл только для флагов и коротких перечислений.
        let small = distinct
            .iter()
            .all(|d| d.exp == 0 && (0..16).contains(&d.num));
        for at in 0..longest.min(MAX_OFFSET) {
            for encoding in &all {
                let bits = matches!(encoding, Encoding::Bits { .. });
                if bits && !small {
                    continue;
                }
                let readable: Vec<(usize, &CorrSample, Decimal, Reading)> = with
                    .iter()
                    .filter_map(|(i, s, p)| encoding.read(&s.bytes, at).map(|d| (*i, *s, *p, d)))
                    .collect();
                let total = readable.len() as u64;
                if total < if bits { MIN_BIT_SAMPLES } else { MIN_SAMPLES } {
                    continue;
                }
                // Масштаб перебирается только у целых чтений: дробь и флаг сравниваются как есть.
                let scales: &[i64] = match encoding {
                    Encoding::Int(_) | Encoding::Bcd { .. } => &SCALES,
                    _ => &[1],
                };
                for &scale in scales {
                    let mut matches = 0u64;
                    let mut fingerprint = 0xcbf2_9ce4_8422_2325u64;
                    let mut counter: Option<CorrCounter> = None;
                    // Совпало ли хотя бы на двух разных значениях параметра. Если нет, байты могут быть
                    // постоянными и просто равняться самому частому значению — это не связь.
                    let mut first: Option<Decimal> = None;
                    let mut varied = false;
                    for (i, s, p, d) in &readable {
                        let (equal, got) = match d {
                            Reading::Int(v) => (p.times_equals(scale, *v), *v),
                            Reading::Dec(v, whole) => (v == p, *whole),
                        };
                        if equal {
                            matches += 1;
                            fingerprint = fnv(fingerprint, *i as u64);
                            match first {
                                None => first = Some(*p),
                                Some(seen) => varied |= seen != *p,
                            }
                        } else if counter.is_none() {
                            counter = Some(CorrCounter {
                                stream: s.stream.clone(),
                                start: s.start,
                                got,
                                expected: p.num / 10i64.pow(p.exp),
                                param_value: p.to_string(),
                            });
                        }
                    }
                    let share = permille(matches, total);
                    // Редкое значение параметра не должно теряться в общей доле: если байты совпадают
                    // только с самым частым значением, это его частота, а не связь. Проверка идёт
                    // вторым проходом и только для связей, прошедших остальные пороги.
                    let every_value_holds = || {
                        let mut per_value: BTreeMap<Decimal, (u64, u64)> = BTreeMap::new();
                        for (_, _, p, d) in &readable {
                            let equal = match d {
                                Reading::Int(v) => p.times_equals(scale, *v),
                                Reading::Dec(v, _) => v == p,
                            };
                            let entry = per_value.entry(*p).or_default();
                            entry.0 += 1;
                            entry.1 += u64::from(equal);
                        }
                        per_value
                            .values()
                            .all(|(seen, held)| *seen < 2 || held * 2 >= *seen)
                    };
                    if matches >= MIN_SAMPLES && share >= MIN_SHARE && varied && every_value_holds()
                    {
                        found.push(Found {
                            rank: encoding.rank(),
                            hint: ValueHint {
                                param: name.clone(),
                                at: at as u32,
                                ty: encoding.name(),
                                size: encoding.size() as u32,
                                mask: match encoding {
                                    Encoding::Bits { mask } => Some(u64::from(*mask)),
                                    _ => None,
                                },
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
                f.rank,
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
                h.equivalent.push(match (f.hint.ty, f.hint.mask) {
                    (_, Some(mask)) => format!("u8&0x{mask:02x}@{}", f.hint.at),
                    ("bcd", _) => format!("bcd{}@{}", f.hint.size, f.hint.at),
                    (ty, _) => format!("{ty}@{}", f.hint.at),
                });
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
