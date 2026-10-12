//! Подсказки полей по поведению значений: счётчик, время, строка, записи «тип–длина–значение».
//!
//! На вход — сообщения одного вида (одного типа и одной стороны), по потокам и в порядке передачи.
//! Каждая подсказка — утверждение, которое выполняется почти на всех сообщениях, с числом
//! примеров и первым сообщением, где оно нарушено.

use std::collections::BTreeSet;

use serde::Serialize;

/// Сообщение, номер его потока и время первого кадра. Сообщения одного потока идут подряд.
#[derive(Debug, Clone, Copy)]
pub struct FieldSample<'a> {
    pub data: &'a [u8],
    pub stream: u32,
    pub ts_ns: u64,
}

/// Сколько сообщений участвует в поиске.
pub const MAX_FIELD_MESSAGES: usize = 20_000;
/// Поля ищутся среди первых байтов сообщения.
const SPAN: usize = 64;
const MIN_SAMPLES: u64 = 5;
const MIN_SHARE: u32 = 800;
const MAX_HINTS: usize = 32;
const MAX_EQUIVALENT: usize = 6;
/// Короче — не текст, а совпадение.
const MIN_TEXT: usize = 4;
const EXAMPLE_CHARS: usize = 32;
/// Отметка времени считается временем от эпохи, если расходится с часами записи меньше чем на год.
const EPOCH_SLACK_NS: u128 = 366 * 24 * 3600 * 1_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    /// Растёт на единицу с каждым сообщением потока.
    Counter,
    /// Растёт вместе со временем записи.
    Time,
    /// Длина и следом текст этой длины.
    String,
    /// Печатный текст на постоянном месте.
    Text,
    /// Записи «тип–длина–значение» до конца сообщения.
    Tlv,
}

/// То же поле, прочитанное иначе: на этих данных неотличимо.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldAlt {
    pub at: u32,
    #[serde(rename = "type")]
    pub ty: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldHint {
    pub kind: FieldKind,
    /// Смещение поля; у строки — смещение её длины.
    pub at: u32,
    /// Тип поля: у счётчика и времени — целое, у строки — тип её длины, у записей — тип длины записи.
    #[serde(rename = "type")]
    pub ty: String,
    /// Размер в байтах, когда он постоянен (счётчик, время, текст).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u32>,
    /// Единица времени: `s`, `ms` или `us`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<&'static str>,
    /// Время отсчитывается от эпохи Unix (совпадает с часами записи).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<bool>,
    /// Строка или записи доходят ровно до конца сообщения.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_end: Option<bool>,
    /// Пример текста из первого подходящего сообщения.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example: Option<String>,
    /// Сколько разных меток встретилось у записей.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<u32>,
    pub matches: u64,
    pub samples: u64,
    pub share_permille: u32,
    /// Номер первого сообщения во входном списке, где утверждение нарушено.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_counterexample: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub equivalent: Vec<FieldAlt>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldHints {
    pub messages: u64,
    pub truncated: bool,
    pub incomplete: bool,
    pub hints: Vec<FieldHint>,
}

fn permille(part: u64, whole: u64) -> u32 {
    part.saturating_mul(1000).checked_div(whole).unwrap_or(0) as u32
}

fn read(data: &[u8], at: usize, width: usize, big_endian: bool) -> Option<u64> {
    let bytes = data.get(at..at.checked_add(width)?)?;
    Some(bytes.iter().enumerate().fold(0u64, |acc, (i, b)| {
        let shift = if big_endian { width - 1 - i } else { i } * 8;
        acc | (u64::from(*b) << shift)
    }))
}

fn type_name(width: usize, big_endian: bool) -> String {
    match (width, big_endian) {
        (1, _) => "u8".to_owned(),
        (w, true) => format!("u{}be", w * 8),
        (w, false) => format!("u{}le", w * 8),
    }
}

/// Порядок перебора целых: двухбайтовые первыми — как у полей длины, широкое поле с нулями
/// в старших байтах на данных неотличимо от узкого.
fn integers(widths: &[usize]) -> Vec<(usize, bool)> {
    let mut out = Vec::new();
    for &w in widths {
        out.push((w, true));
        if w > 1 {
            out.push((w, false));
        }
    }
    out
}

fn base(kind: FieldKind, at: usize, ty: String, matches: u64, samples: u64) -> FieldHint {
    FieldHint {
        kind,
        at: at as u32,
        ty,
        size: None,
        unit: None,
        epoch: None,
        to_end: None,
        example: None,
        tags: None,
        matches,
        samples,
        share_permille: permille(matches, samples),
        first_counterexample: None,
        equivalent: Vec::new(),
    }
}

/// Добавляет подсказку; если её байты пересекаются с уже найденной того же вида — записывает
/// как равнозначное прочтение.
fn keep(
    out: &mut Vec<FieldHint>,
    spans: &mut Vec<(FieldKind, usize, usize, usize)>,
    hint: FieldHint,
    end: usize,
) {
    let start = hint.at as usize;
    let overlapping = spans
        .iter()
        .find(|(kind, s, e, _)| *kind == hint.kind && start < *e && *s < end);
    if let Some((_, _, _, index)) = overlapping {
        if let Some(first) = out.get_mut(*index)
            && first.equivalent.len() < MAX_EQUIVALENT
        {
            first.equivalent.push(FieldAlt {
                at: hint.at,
                ty: hint.ty,
            });
        }
        return;
    }
    if out.len() < MAX_HINTS {
        spans.push((hint.kind, start, end, out.len()));
        out.push(hint);
    }
}

fn printable(bytes: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(bytes).ok()?;
    let clean = text.chars().all(|c| !c.is_control() && c != '\u{fffd}');
    (clean && text.chars().any(char::is_alphanumeric)).then_some(text)
}

fn example(text: &str) -> String {
    text.chars().take(EXAMPLE_CHARS).collect()
}

/// Ищет поля с узнаваемым поведением.
pub fn find_fields(samples: &[FieldSample<'_>], cancelled: &dyn Fn() -> bool) -> FieldHints {
    let truncated = samples.len() > MAX_FIELD_MESSAGES;
    let samples = samples
        .get(..samples.len().min(MAX_FIELD_MESSAGES))
        .unwrap_or_default();
    let mut out = FieldHints {
        messages: samples.len() as u64,
        truncated,
        ..FieldHints::default()
    };
    let min_len = samples.iter().map(|s| s.data.len()).min().unwrap_or(0);
    let max_len = samples.iter().map(|s| s.data.len()).max().unwrap_or(0);
    let fixed_span = min_len.min(SPAN);
    let mut spans: Vec<(FieldKind, usize, usize, usize)> = Vec::new();
    // Соседние сообщения одного потока: номера во входном списке.
    let pairs: Vec<(usize, &FieldSample<'_>, &FieldSample<'_>)> = samples
        .windows(2)
        .enumerate()
        .filter_map(|(i, w)| match w {
            [a, b] if a.stream == b.stream => Some((i + 1, a, b)),
            _ => None,
        })
        .collect();

    // Счётчик: значение растёт на единицу от сообщения к сообщению.
    for (width, big_endian) in integers(&[2, 4, 1]) {
        for at in 0..fixed_span.saturating_sub(width - 1) {
            if cancelled() {
                out.incomplete = true;
                return out;
            }
            let mask = if width == 8 {
                u64::MAX
            } else {
                (1u64 << (width * 8)) - 1
            };
            let (mut steps, mut plus) = (0u64, 0u64);
            let mut counter = None;
            let mut values: BTreeSet<u64> = BTreeSet::new();
            for (index, a, b) in &pairs {
                let (Some(x), Some(y)) = (
                    read(a.data, at, width, big_endian),
                    read(b.data, at, width, big_endian),
                ) else {
                    continue;
                };
                steps += 1;
                if values.len() < 8 {
                    values.insert(x);
                    values.insert(y);
                }
                if y == (x + 1) & mask {
                    plus += 1;
                } else if counter.is_none() {
                    counter = Some(*index as u64);
                }
            }
            if steps >= MIN_SAMPLES && permille(plus, steps) >= MIN_SHARE && values.len() >= 3 {
                let mut hint = base(
                    FieldKind::Counter,
                    at,
                    type_name(width, big_endian),
                    plus,
                    steps,
                );
                hint.size = Some(width as u32);
                hint.first_counterexample = counter;
                keep(&mut out.hints, &mut spans, hint, at + width);
            }
        }
    }

    // Время: прирост значения совпадает с приростом времени записи в секундах, милли- или микросекундах.
    for (width, big_endian) in integers(&[4, 8]) {
        for at in 0..fixed_span.saturating_sub(width - 1) {
            if cancelled() {
                out.incomplete = true;
                return out;
            }
            let mut best: Option<(u64, u64, &'static str, bool, Option<u64>)> = None;
            for (unit, unit_ns) in [("s", 1_000_000_000u128), ("ms", 1_000_000), ("us", 1_000)] {
                let (mut steps, mut fit, mut moved) = (0u64, 0u64, 0u64);
                let mut epoch = true;
                let mut counter = None;
                for (index, a, b) in &pairs {
                    let (Some(x), Some(y)) = (
                        read(a.data, at, width, big_endian),
                        read(b.data, at, width, big_endian),
                    ) else {
                        continue;
                    };
                    if b.ts_ns <= a.ts_ns {
                        continue;
                    }
                    steps += 1;
                    let elapsed = u128::from(b.ts_ns - a.ts_ns);
                    let grown = u128::from(y.wrapping_sub(x)) * unit_ns;
                    let slack = (elapsed / 5).max(2 * unit_ns + 5_000_000);
                    if y >= x && grown.abs_diff(elapsed) <= slack {
                        fit += 1;
                        moved += u64::from(y != x);
                    } else if counter.is_none() {
                        counter = Some(*index as u64);
                    }
                    epoch &=
                        (u128::from(y) * unit_ns).abs_diff(u128::from(b.ts_ns)) <= EPOCH_SLACK_NS;
                }
                // Неподвижное значение «совпадает» с любыми короткими паузами: нужны настоящие приросты.
                if steps >= MIN_SAMPLES
                    && permille(fit, steps) >= MIN_SHARE
                    && moved >= 3
                    && best.as_ref().is_none_or(|(f, ..)| fit > *f)
                {
                    best = Some((fit, steps, unit, epoch, counter));
                }
            }
            if let Some((fit, steps, unit, epoch, counter)) = best {
                let mut hint = base(
                    FieldKind::Time,
                    at,
                    type_name(width, big_endian),
                    fit,
                    steps,
                );
                hint.size = Some(width as u32);
                hint.unit = Some(unit);
                hint.epoch = Some(epoch);
                hint.first_counterexample = counter;
                keep(&mut out.hints, &mut spans, hint, at + width);
            }
        }
    }

    // Строка: длина и сразу за ней печатный текст этой длины.
    let var_span = max_len.min(SPAN);
    for (width, big_endian) in integers(&[1, 2]) {
        for at in 0..var_span {
            if cancelled() {
                out.incomplete = true;
                return out;
            }
            let (mut seen, mut fit) = (0u64, 0u64);
            let mut to_end = true;
            let mut counter = None;
            let mut texts: BTreeSet<&str> = BTreeSet::new();
            let mut first: Option<&str> = None;
            let mut longest = 0usize;
            for (index, s) in samples.iter().enumerate() {
                let Some(length) = read(s.data, at, width, big_endian) else {
                    continue;
                };
                seen += 1;
                let start = at + width;
                let text = usize::try_from(length)
                    .ok()
                    .filter(|l| *l >= 1)
                    .and_then(|l| s.data.get(start..start.checked_add(l)?))
                    .and_then(printable);
                match text {
                    Some(text) => {
                        fit += 1;
                        to_end &= start + text.len() == s.data.len();
                        longest = longest.max(text.len());
                        first.get_or_insert(text);
                        if texts.len() < 8 {
                            texts.insert(text);
                        }
                    }
                    None if counter.is_none() => counter = Some(index as u64),
                    None => {}
                }
            }
            // Один и тот же короткий текст во всех сообщениях может быть совпадением байтов.
            let convincing = texts.len() >= 2 || longest >= 6;
            if fit >= MIN_SAMPLES && permille(fit, seen) >= MIN_SHARE && convincing {
                let mut hint = base(
                    FieldKind::String,
                    at,
                    type_name(width, big_endian),
                    fit,
                    seen,
                );
                hint.to_end = Some(to_end);
                hint.example = first.map(example);
                hint.first_counterexample = counter;
                keep(&mut out.hints, &mut spans, hint, at + width + longest);
            }
        }
    }

    // Текст на постоянном месте: подряд идущие смещения, где почти всегда печатный символ.
    let is_text = |o: usize| {
        let (mut seen, mut fit) = (0u64, 0u64);
        for s in samples {
            if let Some(b) = s.data.get(o) {
                seen += 1;
                fit += u64::from((0x20..0x7f).contains(b));
            }
        }
        seen >= MIN_SAMPLES && permille(fit, seen) >= MIN_SHARE
    };
    let mut run_start: Option<usize> = None;
    for o in 0..=fixed_span {
        if cancelled() {
            out.incomplete = true;
            return out;
        }
        match (o < fixed_span && is_text(o), run_start) {
            (true, None) => run_start = Some(o),
            (true, Some(_)) => {}
            (false, Some(start)) => {
                run_start = None;
                let inside_string = spans
                    .iter()
                    .any(|(kind, s, e, _)| *kind == FieldKind::String && start < *e && *s < o);
                if o - start < MIN_TEXT || inside_string {
                    continue;
                }
                let (mut fit, mut counter, mut first) = (0u64, None, None);
                for (index, s) in samples.iter().enumerate() {
                    match s.data.get(start..o).and_then(printable) {
                        Some(text) => {
                            fit += 1;
                            first.get_or_insert(text);
                        }
                        None if counter.is_none() => counter = Some(index as u64),
                        None => {}
                    }
                }
                let seen = samples.len() as u64;
                if fit >= MIN_SAMPLES && permille(fit, seen) >= MIN_SHARE {
                    let mut hint = base(FieldKind::Text, start, "string".to_owned(), fit, seen);
                    hint.size = Some((o - start) as u32);
                    hint.example = first.map(example);
                    hint.first_counterexample = counter;
                    keep(&mut out.hints, &mut spans, hint, o);
                }
            }
            (false, None) => {}
        }
    }

    // Записи «метка, длина, значение» подряд до самого конца сообщения.
    'tlv: for (width, big_endian) in integers(&[1, 2]) {
        for at in 0..var_span {
            if cancelled() {
                out.incomplete = true;
                return out;
            }
            let (mut seen, mut fit, mut records) = (0u64, 0u64, 0u64);
            let mut counter = None;
            let mut tags: BTreeSet<u8> = BTreeSet::new();
            for (index, s) in samples.iter().enumerate() {
                if s.data.len() <= at {
                    continue;
                }
                seen += 1;
                let mut pos = at;
                let mut count = 0u64;
                let mut own: Vec<u8> = Vec::new();
                let whole = loop {
                    if pos == s.data.len() {
                        break count >= 1;
                    }
                    let (Some(tag), Some(length)) =
                        (s.data.get(pos), read(s.data, pos + 1, width, big_endian))
                    else {
                        break false;
                    };
                    let Some(next) = usize::try_from(length)
                        .ok()
                        .and_then(|l| (pos + 1 + width).checked_add(l))
                        .filter(|n| *n <= s.data.len())
                    else {
                        break false;
                    };
                    own.push(*tag);
                    count += 1;
                    pos = next;
                };
                if whole {
                    fit += 1;
                    records += count;
                    if tags.len() < 64 {
                        tags.extend(own);
                    }
                } else if counter.is_none() {
                    counter = Some(index as u64);
                }
            }
            // Одна запись на сообщение — это просто поле длины; меток должно быть несколько.
            if fit >= MIN_SAMPLES
                && permille(fit, seen) >= MIN_SHARE
                && records >= fit * 2
                && tags.len() >= 2
            {
                let mut hint = base(FieldKind::Tlv, at, type_name(width, big_endian), fit, seen);
                hint.to_end = Some(true);
                hint.tags = Some(tags.len() as u32);
                hint.first_counterexample = counter;
                keep(&mut out.hints, &mut spans, hint, max_len);
                // Разбор с более позднего смещения — тот же список без первых записей.
                break 'tlv;
            }
        }
    }

    out.hints.sort_by_key(|h| (h.at, h.kind as u8));
    out
}
