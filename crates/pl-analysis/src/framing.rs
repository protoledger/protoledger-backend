//! Кандидаты границ сообщений: поле длины, фиксированный размер, начальная сигнатура, разделитель.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::{
    DataRun, MAX_STREAM_BYTES, MAX_STREAMS, MAX_TOTAL_BYTES, MAX_WALK_MESSAGES, StreamSample,
};

/// Дальше этого смещения поле длины не ищем.
const MAX_FIELD_OFFSET: usize = 32;
/// Длиннейшее сообщение, которое кандидат вправе заявить.
const MAX_CLAIMED: i64 = 1 << 20;
/// Поправка к длине: от `-MIN_ADJUST` до `заголовок + MAX_EXTRA`.
const MIN_ADJUST: i64 = 8;
const MAX_EXTRA: i64 = 16;
/// Кандидату нужно не меньше стольких подтверждённых сообщений на всех потоках.
const MIN_MESSAGES: u64 = 3;
/// Нижняя граница доли покрытых байтов (в промилле).
const MIN_SCORE: u32 = 600;
/// Поле длины подтверждается не меньше чем восемью сообщениями: на меньшем числе совпадения случайны.
const MIN_LENGTH_MESSAGES: u64 = 8;
/// Сколько первых байтов сообщения смотрим при проверке «начала похожи друг на друга».
const START_BYTES: usize = 8;
/// Доля начал сообщений (промилле), на которую должно сходиться значение хотя бы одного смещения.
const MIN_COHERENCE: u32 = 600;
/// И не меньше стольких начал с одним и тем же значением: на пяти и менее совпадения случайны.
const MIN_COHERENT_STARTS: u32 = 5;
/// Доля начал сообщений, совпавших с началами TCP-сегментов (и наоборот), промилле.
const MIN_ALIGNMENT: u32 = 600;
const MAX_HINTS: usize = 8;
const MAX_NGRAM: usize = 4;

/// Описание фрейминга в том виде, в каком его принимает интерпретация (`framing:`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FramingSpec {
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<LengthSpecHint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u32>,
    /// Разделитель или начало сообщения, hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<String>,
    pub status: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LengthSpecHint {
    pub at: u32,
    #[serde(rename = "type")]
    pub ty: &'static str,
    pub adjust: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterReason {
    /// Поле длины даёт длину меньше самого заголовка или больше предела.
    BadLength,
    /// Сообщение по длине не помещается в данные, но поток на этом не кончается.
    Overrun,
    /// Данные кончились раньше, чем поле длины.
    ShortHeader,
    /// Разбор не споткнулся, но это начало сообщения не похоже на остальные: похоже на сбитую границу.
    Dissimilar,
}

/// Первое место, где кандидат расходится с данными.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Counter {
    pub stream: String,
    /// Смещение внутри непрерывного участка потока.
    pub offset: u64,
    /// Номер непрерывного участка в потоке (с нуля).
    pub run: u32,
    pub reason: CounterReason,
    /// Значение поля длины в этом месте, если его удалось прочесть.
    pub value: Option<i64>,
}

/// Эквивалентное поле: даёт те же границы (например, младший байт того же числа).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldRef {
    pub at: u32,
    #[serde(rename = "type")]
    pub ty: &'static str,
    pub adjust: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LengthHint {
    pub at: u32,
    /// Ширина поля в байтах: 1, 2 или 4.
    pub width: u8,
    pub big_endian: bool,
    pub adjust: i64,
    /// Подтверждённых сообщений.
    pub messages: u64,
    /// Байты, разбитые на сообщения без противоречий, и все проверенные байты.
    pub covered_bytes: u64,
    pub total_bytes: u64,
    /// Доля покрытых байтов, промилле.
    pub score_permille: u32,
    pub streams_confirmed: u32,
    pub streams_total: u32,
    /// Сколько потоков кончились ровно на границе сообщения.
    pub streams_ended_exactly: u32,
    /// Доля начал сообщений с самым частым значением на одном из первых смещений, промилле.
    /// У настоящих границ начала обычно похожи (тип, сигнатура), у случайных — нет.
    pub start_coherence_permille: u32,
    /// Доля начал сообщений, совпавших с началами TCP-сегментов, промилле.
    pub segment_alignment_permille: u32,
    pub distinct_values: u32,
    pub min_length: u64,
    pub max_length: u64,
    pub first_counterexample: Option<Counter>,
    pub equivalent: Vec<FieldRef>,
    pub framing: FramingSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FixedHint {
    pub size: u32,
    pub messages: u64,
    pub score_permille: u32,
    pub framing: FramingSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureHint {
    /// Начало сообщения, hex.
    pub bytes: String,
    /// По каким началам посчитано: `segments` — начала TCP-сегментов, `length_candidate` — начала сообщений
    /// по лучшему кандидату поля длины (если в сегменте несколько сообщений).
    pub basis: &'static str,
    /// Сколько начал с этой сигнатурой из скольких.
    pub at_starts: u64,
    pub starts_total: u64,
    /// Сколько раз последовательность встречается во всех данных (если больше `atStarts` — она не только в начале).
    pub occurrences: u64,
    pub framing: FramingSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelimiterHint {
    /// Конец сообщения, hex.
    pub bytes: String,
    pub at_ends: u64,
    pub ends_total: u64,
    /// Сколько раз она встречается не на конце сегмента.
    pub inside: u64,
    pub framing: FramingSpec,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FramingHints {
    pub streams: Vec<String>,
    pub sampled_bytes: u64,
    /// Часть данных не вошла в анализ (предел размера или числа потоков).
    pub truncated: bool,
    /// Поиск прерван (отмена или время): список кандидатов по длине неполон или пуст.
    pub incomplete: bool,
    /// Сколько сообщений нужно, чтобы показать кандидата поля длины (меньше — совпадения случайны).
    pub min_messages: u64,
    pub length: Vec<LengthHint>,
    pub fixed: Vec<FixedHint>,
    pub signatures: Vec<SignatureHint>,
    pub delimiters: Vec<DelimiterHint>,
}

fn type_name(width: u8, big_endian: bool) -> &'static str {
    match (width, big_endian) {
        (1, _) => "u8",
        (2, true) => "u16be",
        (2, false) => "u16le",
        (_, true) => "u32be",
        (_, false) => "u32le",
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn read_value(data: &[u8], at: usize, width: u8, big_endian: bool) -> Option<i64> {
    let raw = data.get(at..at.checked_add(usize::from(width))?)?;
    let mut v: i64 = 0;
    if big_endian {
        for b in raw {
            v = (v << 8) | i64::from(*b);
        }
    } else {
        for b in raw.iter().rev() {
            v = (v << 8) | i64::from(*b);
        }
    }
    Some(v)
}

#[derive(Debug, Clone, Copy)]
struct Params {
    at: usize,
    width: u8,
    big_endian: bool,
    adjust: i64,
}

enum Stop {
    /// Дошли до конца участка ровно на границе сообщения.
    End,
    /// Остановились по пределу числа сообщений: хвост не проверялся.
    Limit,
    /// Последнее сообщение не дописано: запись кончилась раньше.
    Truncated,
    Fail(CounterReason, u64, Option<i64>),
}

struct Walk {
    ends: Vec<usize>,
    stop: Stop,
}

fn walk(data: &[u8], p: Params) -> Walk {
    let header = p.at + usize::from(p.width);
    let mut ends = Vec::new();
    let mut pos = 0usize;
    loop {
        if pos == data.len() {
            return Walk {
                ends,
                stop: Stop::End,
            };
        }
        if ends.len() >= MAX_WALK_MESSAGES {
            return Walk {
                ends,
                stop: Stop::Limit,
            };
        }
        let Some(value) = read_value(data, pos + p.at, p.width, p.big_endian) else {
            let stop = if ends.len() as u64 >= MIN_MESSAGES {
                Stop::Truncated
            } else {
                Stop::Fail(CounterReason::ShortHeader, pos as u64, None)
            };
            return Walk { ends, stop };
        };
        let total = value.saturating_add(p.adjust);
        if total < header as i64 || total > MAX_CLAIMED {
            return Walk {
                ends,
                stop: Stop::Fail(CounterReason::BadLength, pos as u64, Some(value)),
            };
        }
        let total = total as usize;
        if pos + total > data.len() {
            // Запись может обрываться на середине последнего сообщения; но заявленная длина не должна
            // быть намного выше уже виденных, иначе это скорее мусор.
            let plausible = ends.len() as u64 >= MIN_MESSAGES
                && total <= median_length(&ends).saturating_mul(3).max(64);
            let stop = if plausible {
                Stop::Truncated
            } else {
                Stop::Fail(CounterReason::Overrun, pos as u64, Some(value))
            };
            return Walk { ends, stop };
        }
        pos += total;
        ends.push(pos);
    }
}

fn median_length(ends: &[usize]) -> usize {
    let mut lengths: Vec<usize> = Vec::with_capacity(ends.len());
    let mut prev = 0usize;
    for end in ends {
        lengths.push(end - prev);
        prev = *end;
    }
    lengths.sort_unstable();
    lengths.get(lengths.len() / 2).copied().unwrap_or(0)
}

/// Итог проверки одного кандидата на всех потоках.
#[derive(Default)]
struct Score {
    messages: u64,
    covered: u64,
    total: u64,
    confirmed: u32,
    ended_exactly: u32,
    values: BTreeSet<i64>,
    min_length: Option<u64>,
    max_length: u64,
    counter: Option<Counter>,
    /// Отпечаток границ: одинаковые отпечатки — одно и то же разбиение.
    fingerprint: u64,
    /// Начал сообщений, и сколько из них совпало с началом сегмента.
    starts: u64,
    starts_on_segments: u64,
    /// Начал сегментов в проверенной части.
    segments_seen: u64,
    /// Гистограмма значений на первых `START_BYTES` смещениях начал сообщений.
    hist: Vec<u32>,
    /// Первые байты первого сообщения в участках, которые начинаются на границе сообщения.
    firsts: Vec<Vec<u8>>,
}

impl Score {
    /// Лучшее смещение: доля начал с самым частым значением и их число. Участок, который начинается на
    /// границе сообщения, обязан сам быть «как все»: иначе разбор лишь случайно попал в такт.
    fn coherence(&self) -> (u32, u32) {
        let (share, top, _, _) = self.coherence_at();
        (share, top)
    }

    /// То же, плюс смещение и значение, на которые сходятся начала.
    fn coherence_at(&self) -> (u32, u32, usize, u8) {
        let min_share = u64::from(MIN_COHERENCE);
        let mut best = 0u32;
        let mut best_at = (0usize, 0u8);
        for o in 0..START_BYTES {
            let Some(col) = self.hist.get(o * 256..(o + 1) * 256) else {
                continue;
            };
            let Some((top_value, top)) = col
                .iter()
                .enumerate()
                .max_by_key(|(v, c)| (**c, std::cmp::Reverse(*v)))
                .map(|(v, c)| (v, *c))
            else {
                continue;
            };
            let first_ok = self.firsts.iter().all(|f| match f.get(o) {
                Some(b) => {
                    usize::from(*b) == top_value
                        || u64::from(col.get(usize::from(*b)).copied().unwrap_or(0)) * 1000
                            >= min_share * self.starts
                }
                None => true,
            });
            if first_ok && top > best {
                best = top;
                best_at = (o, u8::try_from(top_value).unwrap_or(0));
            }
        }
        (
            permille(u64::from(best), self.starts),
            best,
            best_at.0,
            best_at.1,
        )
    }

    fn alignment(&self) -> (u32, u32) {
        (
            permille(self.starts_on_segments, self.starts),
            permille(self.starts_on_segments, self.segments_seen),
        )
    }
}

fn fnv(hash: u64, value: u64) -> u64 {
    (hash ^ value).wrapping_mul(0x0000_0100_0000_01b3)
}

fn stream_has_data(stream: &StreamSample) -> bool {
    stream.runs.iter().any(|r| !r.data.is_empty())
}

fn evaluate(streams: &[StreamSample], p: Params, cancelled: &dyn Fn() -> bool) -> Option<Score> {
    let mut score = Score {
        fingerprint: 0xcbf2_9ce4_8422_2325,
        hist: vec![0; START_BYTES * 256],
        ..Score::default()
    };
    for stream in streams {
        let mut stream_ok = stream_has_data(stream);
        let mut stream_exact = stream_ok;
        for (run_no, run) in stream.runs.iter().enumerate() {
            if run.data.is_empty() {
                continue;
            }
            if cancelled() {
                return None;
            }
            let w = walk(&run.data, p);
            let covered = w.ends.last().copied().unwrap_or(0);
            score.messages += w.ends.len() as u64;
            if run.starts_at_boundary {
                score
                    .firsts
                    .push(run.data.iter().take(START_BYTES).copied().collect());
            }
            let mut prev = 0usize;
            score.segments_seen += run.segment_starts.partition_point(|s| *s < covered) as u64;
            for end in &w.ends {
                score.starts += 1;
                if run.segment_starts.binary_search(&prev).is_ok() {
                    score.starts_on_segments += 1;
                }
                for o in 0..START_BYTES {
                    if let Some(b) = run.data.get(prev + o)
                        && let Some(c) = score.hist.get_mut(o * 256 + usize::from(*b))
                    {
                        *c += 1;
                    }
                }
                let len = (end - prev) as u64;
                score.min_length = Some(score.min_length.map_or(len, |m| m.min(len)));
                score.max_length = score.max_length.max(len);
                if let Some(v) = read_value(&run.data, prev + p.at, p.width, p.big_endian)
                    && score.values.len() < 4096
                {
                    score.values.insert(v);
                }
                score.fingerprint = fnv(score.fingerprint, *end as u64);
                prev = *end;
            }
            match w.stop {
                Stop::End => {
                    score.covered += covered as u64;
                    score.total += run.data.len() as u64;
                }
                Stop::Limit => {
                    score.covered += covered as u64;
                    score.total += covered as u64;
                    stream_exact = false;
                }
                Stop::Truncated => {
                    score.covered += run.data.len() as u64;
                    score.total += run.data.len() as u64;
                    stream_exact = false;
                }
                Stop::Fail(reason, offset, value) => {
                    score.covered += covered as u64;
                    score.total += run.data.len() as u64;
                    stream_ok = false;
                    stream_exact = false;
                    if score.counter.is_none() {
                        score.counter = Some(Counter {
                            stream: stream.id.clone(),
                            offset,
                            run: u32::try_from(run_no).unwrap_or(u32::MAX),
                            reason,
                            value,
                        });
                    }
                }
            }
        }
        if stream_ok {
            score.confirmed += 1;
        }
        if stream_exact {
            score.ended_exactly += 1;
        }
    }
    Some(score)
}

/// Первое начало сообщения, на котором байт со смещением `offset` не равен `value`.
fn first_dissimilar(
    streams: &[StreamSample],
    p: Params,
    offset: usize,
    value: u8,
) -> Option<Counter> {
    for stream in streams {
        for (run_no, run) in stream.runs.iter().enumerate() {
            let w = walk(&run.data, p);
            let mut start = 0usize;
            let starts = std::iter::once(0).chain(w.ends.iter().copied());
            for s in starts {
                start = s;
                if s >= run.data.len() {
                    break;
                }
                if run.data.get(s + offset).is_some_and(|b| *b != value) {
                    return Some(Counter {
                        stream: stream.id.clone(),
                        offset: s as u64,
                        run: u32::try_from(run_no).unwrap_or(u32::MAX),
                        reason: CounterReason::Dissimilar,
                        value: None,
                    });
                }
            }
            let _ = start;
        }
    }
    None
}

fn permille(part: u64, whole: u64) -> u32 {
    part.saturating_mul(1000)
        .checked_div(whole)
        .map_or(0, |v| u32::try_from(v).unwrap_or(1000))
}

struct Cand {
    p: Params,
    s: Score,
}

fn length_hints(streams: &[StreamSample], cancelled: &dyn Fn() -> bool) -> Vec<LengthHint> {
    let longest_run = streams
        .iter()
        .flat_map(|s| s.runs.iter())
        .map(|r| r.data.len())
        .max()
        .unwrap_or(0);
    let mut cands: Vec<Cand> = Vec::new();
    for at in 0..=MAX_FIELD_OFFSET {
        for (width, big_endian) in [(1u8, true), (2, true), (2, false), (4, true), (4, false)] {
            if at + usize::from(width) > longest_run {
                continue;
            }
            let header = (at + usize::from(width)) as i64;
            for adjust in -MIN_ADJUST..=header + MAX_EXTRA {
                let p = Params {
                    at,
                    width,
                    big_endian,
                    adjust,
                };
                let Some(s) = evaluate(streams, p, cancelled) else {
                    return Vec::new();
                };
                if s.messages >= MIN_LENGTH_MESSAGES && permille(s.covered, s.total) >= MIN_SCORE {
                    let (coherence, top) = s.coherence();
                    let (a, b) = s.alignment();
                    let coherent = coherence >= MIN_COHERENCE && top >= MIN_COHERENT_STARTS;
                    if coherent || (a >= MIN_ALIGNMENT && b >= MIN_ALIGNMENT) {
                        cands.push(Cand { p, s });
                    }
                }
            }
        }
    }
    // Постоянное поле — это фиксированный размер (его показывает отдельная подсказка), а не поле длины.
    cands.retain(|c| c.s.values.len() > 1);

    cands.sort_by(|a, b| {
        let key = |c: &Cand| {
            (
                std::cmp::Reverse(permille(c.s.covered, c.s.total)),
                std::cmp::Reverse(c.s.coherence().0.max(c.s.alignment().0)),
                std::cmp::Reverse(c.s.ended_exactly),
                std::cmp::Reverse(c.s.messages),
                c.p.at,
                std::cmp::Reverse(c.p.width),
                u8::from(!c.p.big_endian),
                c.p.adjust.unsigned_abs(),
            )
        };
        key(a).cmp(&key(b))
    });

    // Метка «не похоже на остальные» нужна только там, где разбор формально прошёл без ошибок.
    let mut dissimilar: BTreeMap<u64, Option<Counter>> = BTreeMap::new();
    let mut groups: BTreeMap<u64, usize> = BTreeMap::new();
    let mut out: Vec<LengthHint> = Vec::new();
    let streams_total = streams.iter().filter(|s| stream_has_data(s)).count() as u32;
    for c in &cands {
        let field = FieldRef {
            at: c.p.at as u32,
            ty: type_name(c.p.width, c.p.big_endian),
            adjust: c.p.adjust,
        };
        if let Some(&i) = groups.get(&c.s.fingerprint) {
            if let Some(h) = out.get_mut(i)
                && h.equivalent.len() < MAX_HINTS
            {
                h.equivalent.push(field);
            }
            continue;
        }
        if out.len() >= MAX_HINTS {
            continue;
        }
        groups.insert(c.s.fingerprint, out.len());
        let (share, _, at, value) = c.s.coherence_at();
        let counter = match (&c.s.counter, share < 1000) {
            (None, true) => dissimilar
                .entry(c.s.fingerprint)
                .or_insert_with(|| first_dissimilar(streams, c.p, at, value))
                .clone(),
            _ => c.s.counter.clone(),
        };
        out.push(LengthHint {
            at: c.p.at as u32,
            width: c.p.width,
            big_endian: c.p.big_endian,
            adjust: c.p.adjust,
            messages: c.s.messages,
            covered_bytes: c.s.covered,
            total_bytes: c.s.total,
            score_permille: permille(c.s.covered, c.s.total),
            streams_confirmed: c.s.confirmed,
            streams_total,
            streams_ended_exactly: c.s.ended_exactly,
            start_coherence_permille: c.s.coherence().0,
            segment_alignment_permille: c.s.alignment().0,
            distinct_values: c.s.values.len() as u32,
            min_length: c.s.min_length.unwrap_or(0),
            max_length: c.s.max_length,
            first_counterexample: counter,
            equivalent: Vec::new(),
            framing: FramingSpec {
                kind: "length_prefixed",
                length: Some(LengthSpecHint {
                    at: c.p.at as u32,
                    ty: type_name(c.p.width, c.p.big_endian),
                    adjust: c.p.adjust,
                }),
                size: None,
                bytes: None,
                status: "hypothesis",
            },
        });
    }
    out
}

fn fixed_hints(streams: &[StreamSample]) -> Vec<FixedHint> {
    let mut sizes: BTreeMap<usize, (u64, u64)> = BTreeMap::new();
    let mut total_bytes = 0u64;
    for run in streams.iter().flat_map(|s| s.runs.iter()) {
        total_bytes += run.data.len() as u64;
        for (a, b) in segments(run) {
            let e = sizes.entry(b - a).or_default();
            e.0 += 1;
            e.1 += (b - a) as u64;
        }
    }
    // Размер сообщения = размер сегмента, если он один и тот же у большинства сегментов.
    let mut out: Vec<FixedHint> = sizes
        .into_iter()
        .filter(|(size, (n, bytes))| *size > 0 && *n >= MIN_MESSAGES && *bytes * 2 >= total_bytes)
        .map(|(size, (n, bytes))| {
            let size = u32::try_from(size).unwrap_or(u32::MAX);
            FixedHint {
                size,
                messages: n,
                score_permille: permille(bytes, total_bytes),
                framing: FramingSpec {
                    kind: "fixed",
                    length: None,
                    size: Some(size),
                    bytes: None,
                    status: "hypothesis",
                },
            }
        })
        .collect();
    out.sort_by_key(|h| (std::cmp::Reverse(h.score_permille), h.size));
    out.truncate(3);
    out
}

fn count_occurrences(streams: &[StreamSample], pattern: &[u8]) -> u64 {
    if pattern.is_empty() {
        return 0;
    }
    streams
        .iter()
        .flat_map(|s| s.runs.iter())
        .map(|r| {
            r.data
                .windows(pattern.len())
                .filter(|w| *w == pattern)
                .count() as u64
        })
        .sum()
}

/// Сегменты участка как `[начало, конец)`.
fn segments(run: &DataRun) -> Vec<(usize, usize)> {
    let mut starts: Vec<usize> = run
        .segment_starts
        .iter()
        .copied()
        .filter(|s| *s < run.data.len())
        .collect();
    if starts.first() != Some(&0) {
        starts.push(0);
    }
    starts.sort_unstable();
    starts.dedup();
    let mut out = Vec::with_capacity(starts.len());
    for (i, s) in starts.iter().enumerate() {
        let end = starts.get(i + 1).copied().unwrap_or(run.data.len());
        out.push((*s, end));
    }
    out
}

fn signature_hints(streams: &[StreamSample], basis: &'static str) -> Vec<SignatureHint> {
    let mut starts_total = 0u64;
    let mut counts: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
    for run in streams.iter().flat_map(|s| s.runs.iter()) {
        for (a, b) in segments(run) {
            starts_total += 1;
            let seg = run.data.get(a..b).unwrap_or_default();
            for n in 1..=MAX_NGRAM {
                if let Some(prefix) = seg.get(..n) {
                    *counts.entry(prefix.to_vec()).or_default() += 1;
                }
            }
        }
    }
    let mut picked: Vec<(Vec<u8>, u64)> = counts
        .into_iter()
        .filter(|(_, n)| *n >= MIN_MESSAGES && *n * 10 >= starts_total * 6)
        .collect();
    // Из вложенных префиксов с одним и тем же числом оставляем самый длинный.
    let snapshot = picked.clone();
    picked.retain(|(k, n)| {
        !snapshot
            .iter()
            .any(|(other, m)| other.len() > k.len() && other.starts_with(k) && m == n)
    });
    let mut out: Vec<SignatureHint> = picked
        .into_iter()
        .map(|(bytes, at_starts)| SignatureHint {
            occurrences: count_occurrences(streams, &bytes),
            bytes: hex(&bytes),
            basis,
            at_starts,
            starts_total,
            framing: FramingSpec {
                kind: "magic",
                length: None,
                size: None,
                bytes: Some(hex(&bytes)),
                status: "hypothesis",
            },
        })
        .collect();
    out.sort_by(|a, b| {
        (
            std::cmp::Reverse(a.at_starts),
            std::cmp::Reverse(a.bytes.len()),
            &a.bytes,
        )
            .cmp(&(
                std::cmp::Reverse(b.at_starts),
                std::cmp::Reverse(b.bytes.len()),
                &b.bytes,
            ))
    });
    out.truncate(MAX_HINTS);
    out
}

fn delimiter_hints(streams: &[StreamSample]) -> Vec<DelimiterHint> {
    let mut ends_total = 0u64;
    let mut counts: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
    for run in streams.iter().flat_map(|s| s.runs.iter()) {
        for (a, b) in segments(run) {
            ends_total += 1;
            let seg = run.data.get(a..b).unwrap_or_default();
            for n in 1..=MAX_NGRAM {
                if let Some(start) = seg.len().checked_sub(n)
                    && let Some(tail) = seg.get(start..)
                {
                    *counts.entry(tail.to_vec()).or_default() += 1;
                }
            }
        }
    }
    let mut picked: Vec<(Vec<u8>, u64)> = counts
        .into_iter()
        .filter(|(_, n)| *n >= MIN_MESSAGES && *n * 10 >= ends_total * 6)
        .collect();
    let snapshot = picked.clone();
    picked.retain(|(k, n)| {
        !snapshot
            .iter()
            .any(|(other, m)| other.len() > k.len() && other.ends_with(k) && m == n)
    });
    let mut out: Vec<DelimiterHint> = picked
        .into_iter()
        .map(|(bytes, at_ends)| {
            let all = count_occurrences(streams, &bytes);
            DelimiterHint {
                inside: all.saturating_sub(at_ends),
                bytes: hex(&bytes),
                at_ends,
                ends_total,
                framing: FramingSpec {
                    kind: "delimiter",
                    length: None,
                    size: None,
                    bytes: Some(hex(&bytes)),
                    status: "hypothesis",
                },
            }
        })
        // Последовательность, которая постоянно встречается и внутри сообщений, разделителем не выглядит.
        .filter(|d| d.inside <= d.at_ends)
        .collect();
    out.sort_by(|a, b| {
        (
            std::cmp::Reverse(a.at_ends),
            a.inside,
            std::cmp::Reverse(a.bytes.len()),
            &a.bytes,
        )
            .cmp(&(
                std::cmp::Reverse(b.at_ends),
                b.inside,
                std::cmp::Reverse(b.bytes.len()),
                &b.bytes,
            ))
    });
    out.truncate(MAX_HINTS);
    out
}

/// Подсказки по границам сообщений. `cancelled` проверяется между кандидатами.
pub fn find_framing(streams: &[StreamSample], cancelled: &dyn Fn() -> bool) -> FramingHints {
    let mut truncated = streams.len() > MAX_STREAMS;
    let mut sample: Vec<StreamSample> = Vec::new();
    let mut total_budget = MAX_TOTAL_BYTES;
    for s in streams.iter().take(MAX_STREAMS) {
        let mut budget = MAX_STREAM_BYTES.min(total_budget);
        let mut runs = Vec::new();
        for run in &s.runs {
            if budget == 0 {
                truncated = true;
                break;
            }
            let take = run.data.len().min(budget);
            if take < run.data.len() {
                truncated = true;
            }
            budget -= take;
            total_budget -= take;
            let mut starts: Vec<usize> = run
                .segment_starts
                .iter()
                .copied()
                .filter(|p| *p < take)
                .collect();
            starts.push(0);
            starts.sort_unstable();
            starts.dedup();
            runs.push(DataRun {
                data: run.data.get(..take).unwrap_or_default().to_vec(),
                segment_starts: starts,
                starts_at_boundary: run.starts_at_boundary,
            });
        }
        sample.push(StreamSample {
            id: s.id.clone(),
            runs,
        });
    }
    let length = length_hints(&sample, cancelled);
    let mut signatures = signature_hints(&sample, "segments");
    if let Some(top) = length.first() {
        // Несколько сообщений в одном сегменте: начала берём из лучшего разбиения по полю длины.
        let params = Params {
            at: top.at as usize,
            width: top.width,
            big_endian: top.big_endian,
            adjust: top.adjust,
        };
        let aligned: Vec<StreamSample> = sample
            .iter()
            .map(|s| StreamSample {
                id: s.id.clone(),
                runs: s
                    .runs
                    .iter()
                    .map(|r| {
                        let mut starts = vec![0usize];
                        starts.extend(
                            walk(&r.data, params)
                                .ends
                                .into_iter()
                                .filter(|e| *e < r.data.len()),
                        );
                        DataRun {
                            data: r.data.clone(),
                            segment_starts: starts,
                            starts_at_boundary: r.starts_at_boundary,
                        }
                    })
                    .collect(),
            })
            .collect();
        for hint in signature_hints(&aligned, "length_candidate") {
            match signatures.iter_mut().find(|h| h.bytes == hint.bytes) {
                Some(existing)
                    if existing.at_starts * hint.starts_total
                        >= hint.at_starts * existing.starts_total => {}
                Some(existing) => *existing = hint,
                None => signatures.push(hint),
            }
        }
        signatures.sort_by(|a, b| {
            let share = |h: &SignatureHint| permille(h.at_starts, h.starts_total);
            (
                std::cmp::Reverse(share(a)),
                std::cmp::Reverse(a.bytes.len()),
                &a.bytes,
            )
                .cmp(&(
                    std::cmp::Reverse(share(b)),
                    std::cmp::Reverse(b.bytes.len()),
                    &b.bytes,
                ))
        });
        signatures.truncate(MAX_HINTS);
    }
    FramingHints {
        incomplete: cancelled(),
        min_messages: MIN_LENGTH_MESSAGES,
        streams: sample.iter().map(|s| s.id.clone()).collect(),
        sampled_bytes: sample
            .iter()
            .flat_map(|s| s.runs.iter())
            .map(|r| r.data.len() as u64)
            .sum(),
        truncated,
        length,
        fixed: fixed_hints(&sample),
        signatures,
        delimiters: delimiter_hints(&sample),
    }
}
