//! Поиск контрольной суммы: какое поле сообщения равно функции от остальных его байтов.
//!
//! Сами функции приходят снаружи списком: библиотека перебирает место поля, порядок байтов и
//! диапазон, а о конкретных алгоритмах не знает.

use std::collections::BTreeSet;

use serde::Serialize;

/// Функция-кандидат: имя, под которым она доступна в выражениях, и размер результата в байтах.
pub struct ChecksumFn<'a> {
    pub name: &'a str,
    pub title: &'a str,
    pub width: u8,
    pub compute: &'a dyn Fn(&[u8]) -> u64,
}

/// Сколько сообщений проверяется.
pub const MAX_CHECKSUM_MESSAGES: usize = 2_000;
/// Сообщения длиннее не проверяются: о них сказано в результате.
pub const MAX_CHECKSUM_MESSAGE_BYTES: usize = 64 << 10;
/// Сколько байтов сообщений проверяется за один запрос.
pub const MAX_CHECKSUM_BYTES: usize = 16 << 20;
/// Меньше совпадений — не подсказка: восемь случайных совпадений байта подряд невозможны на практике.
const MIN_MATCHES: u64 = 8;
/// Совпадать должно почти всё: редкие расхождения — испорченные сообщения, они станут контрпримером.
const MIN_SHARE: u32 = 800;
/// Одинаковые сообщения ничего не подтверждают: значения поля должны различаться.
const MIN_DISTINCT: usize = 3;
/// Диапазон может начинаться не с нуля: сигнатуру и заголовок иногда не считают.
const MAX_FROM: u8 = 8;
/// После поля в конце сообщения может стоять завершающий байт или два.
const MAX_TAIL_GAP: u8 = 2;
/// Поле в заголовке ищется по этим смещениям; считается всё, что после него.
const MAX_HEAD_AT: u8 = 16;
/// Первые различные сообщения, на которых отсеивается основная масса кандидатов.
const PROBE: usize = 12;
const MAX_HINTS: usize = 8;
const MAX_EQUIVALENT: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Place {
    /// Поле в конце: после него `gap` байт; считаются байты от `from` до поля.
    Tail { gap: u8, from: u8 },
    /// Поле по смещению `at`; считаются байты после него до конца сообщения.
    Head { at: u8 },
}

#[derive(Debug, Clone, Copy)]
struct Cand {
    place: Place,
    function: usize,
    width: u8,
    big_endian: bool,
}

impl Cand {
    /// Значение поля и диапазон под функцией; `None` — сообщение для кандидата слишком короткое.
    fn split<'m>(&self, m: &'m [u8]) -> Option<(u64, &'m [u8])> {
        let w = usize::from(self.width);
        let (at, range) = match self.place {
            Place::Tail { gap, from } => {
                let at = m.len().checked_sub(w + usize::from(gap))?;
                (at, m.get(usize::from(from)..at)?)
            }
            Place::Head { at } => {
                let at = usize::from(at);
                (at, m.get(at + w..)?)
            }
        };
        // Диапазон из одного байта — не сумма, а повтор этого байта.
        if range.len() < 2 {
            return None;
        }
        let field = m.get(at..at + w)?;
        let value = field.iter().enumerate().fold(0u64, |acc, (i, b)| {
            let shift = if self.big_endian { w - 1 - i } else { i } * 8;
            acc | (u64::from(*b) << shift)
        });
        Some((value, range))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumCounter {
    /// Номер сообщения во входном списке.
    pub index: u64,
    pub got: u64,
    pub expected: u64,
}

/// Та же проверка другой функцией или с другого смещения: на этих данных неотличима.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumAlt {
    pub algorithm: String,
    pub from: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumHint {
    /// Имя функции в выражениях и её название.
    pub algorithm: String,
    pub title: String,
    /// Место поля в записи описания: смещение от начала или `end-N`.
    pub at: String,
    /// Тип поля: `u8`, `u16be`, `u16le`, `u32be`, `u32le`.
    #[serde(rename = "type")]
    pub ty: String,
    /// Диапазон под функцией: от `from` до `to` (выражение над `message.len`).
    pub from: u32,
    pub to: String,
    /// Готовое выражение проверки; `checksum` — имя поля.
    pub expr: String,
    pub matches: u64,
    pub samples: u64,
    pub share_permille: u32,
    /// Сколько разных значений поля среди совпавших сообщений.
    pub distinct: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_counterexample: Option<ChecksumCounter>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub equivalent: Vec<ChecksumAlt>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumHints {
    /// Сколько сообщений проверено.
    pub messages: u64,
    /// Часть сообщений не вошла из-за пределов числа или объёма.
    pub truncated: bool,
    /// Сообщения длиннее предела пропущены.
    pub skipped_long: u64,
    /// Поиск прерван до конца.
    pub incomplete: bool,
    pub hints: Vec<ChecksumHint>,
}

#[derive(Default)]
struct Tally {
    samples: u64,
    matches: u64,
    values: BTreeSet<u64>,
    counter: Option<ChecksumCounter>,
}

fn candidates(functions: &[ChecksumFn<'_>]) -> Vec<Cand> {
    let mut out = Vec::new();
    for (function, f) in functions.iter().enumerate() {
        if !matches!(f.width, 1 | 2 | 4) {
            continue;
        }
        let orders: &[bool] = if f.width == 1 {
            &[true]
        } else {
            &[true, false]
        };
        for &big_endian in orders {
            let cand = |place| Cand {
                place,
                function,
                width: f.width,
                big_endian,
            };
            for gap in 0..=MAX_TAIL_GAP {
                for from in 0..=MAX_FROM {
                    out.push(cand(Place::Tail { gap, from }));
                }
            }
            for at in 0..=MAX_HEAD_AT {
                out.push(cand(Place::Head { at }));
            }
        }
    }
    out
}

fn permille(part: u64, whole: u64) -> u32 {
    if whole == 0 {
        0
    } else {
        (part.saturating_mul(1000) / whole) as u32
    }
}

fn type_name(width: u8, big_endian: bool) -> &'static str {
    match (width, big_endian) {
        (1, _) => "u8",
        (2, true) => "u16be",
        (2, false) => "u16le",
        (4, true) => "u32be",
        _ => "u32le",
    }
}

/// Ищет поля, равные одной из `functions` от остальных байтов сообщения.
pub fn find_checksums(
    messages: &[&[u8]],
    functions: &[ChecksumFn<'_>],
    cancelled: &dyn Fn() -> bool,
) -> ChecksumHints {
    let mut out = ChecksumHints::default();
    let mut taken: Vec<(u64, &[u8])> = Vec::new();
    let mut bytes = 0usize;
    for (index, m) in messages.iter().enumerate() {
        if m.len() > MAX_CHECKSUM_MESSAGE_BYTES {
            out.skipped_long += 1;
            continue;
        }
        if taken.len() >= MAX_CHECKSUM_MESSAGES || bytes + m.len() > MAX_CHECKSUM_BYTES {
            out.truncated = true;
            break;
        }
        bytes += m.len();
        taken.push((index as u64, m));
    }
    out.messages = taken.len() as u64;

    let mut seen: BTreeSet<&[u8]> = BTreeSet::new();
    let probe: Vec<&[u8]> = taken
        .iter()
        .map(|(_, m)| *m)
        .filter(|m| seen.insert(m))
        .take(PROBE)
        .collect();

    let holds = |c: &Cand, m: &[u8]| -> Option<(u64, u64)> {
        let (value, range) = c.split(m)?;
        let f = functions.get(c.function)?;
        Some((value, (f.compute)(range)))
    };

    let mut alive: Vec<Cand> = Vec::new();
    for c in candidates(functions) {
        if cancelled() {
            out.incomplete = true;
            return out;
        }
        let (mut samples, mut matches) = (0u64, 0u64);
        for m in &probe {
            if let Some((got, expected)) = holds(&c, m) {
                samples += 1;
                matches += u64::from(got == expected);
            }
        }
        if samples >= 4 && permille(matches, samples) >= MIN_SHARE {
            alive.push(c);
        }
    }

    let mut scored: Vec<(Cand, Tally)> = Vec::new();
    for c in alive {
        if cancelled() {
            out.incomplete = true;
            break;
        }
        let mut t = Tally::default();
        for (index, m) in &taken {
            let Some((got, expected)) = holds(&c, m) else {
                continue;
            };
            t.samples += 1;
            if got == expected {
                t.matches += 1;
                if t.values.len() < 64 {
                    t.values.insert(got);
                }
            } else if t.counter.is_none() {
                t.counter = Some(ChecksumCounter {
                    index: *index,
                    got,
                    expected,
                });
            }
        }
        if t.matches >= MIN_MATCHES
            && permille(t.matches, t.samples) >= MIN_SHARE
            && t.values.len() >= MIN_DISTINCT
        {
            scored.push((c, t));
        }
    }

    // Лучший первым; при равных — более широкое поле, самый широкий диапазон и функция из начала списка.
    let from_of = |c: &Cand| match c.place {
        Place::Tail { from, .. } => u32::from(from),
        Place::Head { at } => u32::from(at) + u32::from(c.width),
    };
    scored.sort_by_key(|(c, t)| {
        (
            std::cmp::Reverse(permille(t.matches, t.samples)),
            std::cmp::Reverse(t.matches),
            std::cmp::Reverse(c.width),
            from_of(c),
            c.function,
            c.place,
            !c.big_endian,
        )
    });

    // Одно поле — одна подсказка: остальные способы получить то же значение идут в «равнозначные».
    let field_of = |c: &Cand| match c.place {
        Place::Tail { gap, .. } => (0u8, gap, c.width, c.big_endian),
        Place::Head { at } => (1u8, at, c.width, c.big_endian),
    };
    // Младший байт 16-битной суммы сам сходится как 8-битная: часть уже найденного поля — не находка.
    let inside = |inner: &(u8, u8, u8, bool), outer: &(u8, u8, u8, bool)| {
        inner.0 == outer.0 && inner.1 >= outer.1 && inner.1 + inner.2 <= outer.1 + outer.2
    };
    let mut groups: Vec<((u8, u8, u8, bool), usize)> = Vec::new();
    for (c, t) in &scored {
        let Some(f) = functions.get(c.function) else {
            continue;
        };
        let key = field_of(c);
        if let Some((_, i)) = groups.iter().find(|(k, _)| *k == key) {
            if let Some(h) = out.hints.get_mut(*i)
                && h.matches == t.matches
                && h.equivalent.len() < MAX_EQUIVALENT
            {
                h.equivalent.push(ChecksumAlt {
                    algorithm: f.name.to_owned(),
                    from: from_of(c),
                });
            }
            continue;
        }
        if out.hints.len() >= MAX_HINTS || groups.iter().any(|(k, _)| inside(&key, k)) {
            continue;
        }
        groups.push((key, out.hints.len()));
        let (at, to) = match c.place {
            Place::Tail { gap, .. } => {
                let back = u32::from(gap) + u32::from(c.width);
                (format!("end-{back}"), format!("message.len - {back}"))
            }
            Place::Head { at } => (at.to_string(), "message.len".to_owned()),
        };
        let from = from_of(c);
        out.hints.push(ChecksumHint {
            algorithm: f.name.to_owned(),
            title: f.title.to_owned(),
            expr: format!("checksum == {}({from}, {to})", f.name),
            at,
            ty: type_name(c.width, c.big_endian).to_owned(),
            from,
            to,
            matches: t.matches,
            samples: t.samples,
            share_permille: permille(t.matches, t.samples),
            distinct: t.values.len() as u32,
            first_counterexample: t.counter.clone(),
            equivalent: Vec::new(),
        });
    }
    out
}
