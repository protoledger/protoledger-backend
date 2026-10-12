//! Типы сообщений: какие байты делят сообщения на группы одинаковой формы.
//!
//! Сначала сообщения делятся по стороне обмена: запрос и ответ — разные сообщения, даже когда
//! код у них один. Затем в общем заголовке ищется байт-различитель: внутри его групп сообщения
//! ближе по длине и у них больше постоянных байтов, чем в целом. Оценка считается по каждой
//! стороне отдельно и усредняется — так счётчик или длина, которые хорошо «объясняют» только
//! ответы, не обходят настоящий код команды.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

/// Сообщение, сторона, которая его отправила (0 — начавшая соединение, 1 — вторая), и номер
/// потока: сообщения одного потока идут во входном списке подряд, в порядке передачи.
#[derive(Debug, Clone, Copy)]
pub struct TypeSample<'a> {
    pub data: &'a [u8],
    pub side: u8,
    pub stream: u32,
}

/// Сколько сообщений участвует в поиске типов.
pub const MAX_TYPE_MESSAGES: usize = 20_000;
/// Различитель ищется среди первых байтов, которые есть у каждого сообщения.
const KEY_SPAN: usize = 32;
/// Постоянные байты группы считаются на этом отрезке.
const CONST_SPAN: usize = 64;
/// Больше значений у одного байта — это номер или данные, а не тип.
const MAX_VALUES: usize = 24;
const MIN_MESSAGES: usize = 12;
/// Группа меньше в оценке различителя не участвует: редкий случай, а не подтверждение.
const MIN_GROUP: u64 = 3;
/// Сторона с меньшим числом сообщений в оценке не участвует.
const MIN_POOL: usize = 6;
/// Группы-типы должны покрывать почти все сообщения.
const MIN_COVERED: u32 = 800;
/// Первый различитель должен объяснять заметную часть формы, следующий — добавлять к уже найденному.
const MIN_SCORE: u32 = 200;
const MIN_EXTRA: u32 = 80;
const MAX_KEYS: usize = 2;
const MAX_TYPES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TypeKey {
    /// Байт по смещению от начала сообщения.
    Byte { at: u32 },
    /// Сторона обмена.
    Side,
}

/// Что можно использовать как различитель.
#[derive(Debug, Clone, Default)]
pub struct TypeOptions {
    /// Смещения, которые различителем быть не могут: поле длины.
    pub exclude: Vec<u32>,
    /// Сторону различителем не предлагать: её нечем выразить в описании.
    pub without_side: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyHint {
    #[serde(flatten)]
    pub key: TypeKey,
    /// Сколько разных значений принимает.
    pub values: u32,
    /// Какую долю разнообразия длин объясняют найденные различители вместе с этим.
    pub length_explained_permille: u32,
    /// Какая доля меняющихся байтов становится постоянной внутри групп.
    pub constant_gain_permille: u32,
    pub score_permille: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyValue {
    #[serde(flatten)]
    pub key: TypeKey,
    /// Значение байта или номер стороны.
    pub value: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConstBytes {
    pub start: u32,
    pub end: u32,
    /// Байты области, hex.
    pub bytes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeGroup {
    pub key: Vec<KeyValue>,
    pub count: u64,
    pub share_permille: u32,
    pub min_len: u64,
    pub max_len: u64,
    /// Сколько разных длин у сообщений группы.
    pub lengths: u32,
    /// Постоянные байты группы, которых нет среди постоянных для всех сообщений.
    pub constant: Vec<ConstBytes>,
    /// Номер первого сообщения группы во входном списке — пример.
    pub first: u64,
    /// Почти все сообщения группы одной длины, а это — другой: номер первого такого.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length_outlier: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeHints {
    pub messages: u64,
    pub truncated: bool,
    pub incomplete: bool,
    /// Различители: сторона обмена (или байт, который её повторяет), затем найденные байты
    /// по порядку вклада. Пусто — сообщения на типы не делятся.
    pub keys: Vec<KeyHint>,
    pub types: Vec<TypeGroup>,
    /// Сообщений в группах меньше трёх: они в списке, но на оценку различителя не влияли.
    pub rare: u64,
}

fn value_of(key: TypeKey, s: &TypeSample<'_>) -> u8 {
    match key {
        TypeKey::Byte { at } => s.data.get(at as usize).copied().unwrap_or(0),
        TypeKey::Side => s.side.min(1),
    }
}

/// Состояние байта внутри группы.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Seen {
    None,
    One(u8),
    Many,
}

struct Group {
    count: u64,
    first: u64,
    /// Длина → сколько сообщений и номер первого.
    lengths: BTreeMap<usize, (u64, u64)>,
    bytes: Vec<Seen>,
}

type Indexed<'a, 'b> = (usize, &'a TypeSample<'b>);

fn partition<'a, 'b: 'a>(
    samples: impl Iterator<Item = Indexed<'a, 'b>>,
    keys: &[TypeKey],
    span: usize,
) -> BTreeMap<Vec<u8>, Group> {
    let mut groups: BTreeMap<Vec<u8>, Group> = BTreeMap::new();
    for (index, s) in samples {
        let key: Vec<u8> = keys.iter().map(|k| value_of(*k, s)).collect();
        let g = groups.entry(key).or_insert_with(|| Group {
            count: 0,
            first: index as u64,
            lengths: BTreeMap::new(),
            bytes: vec![Seen::None; span],
        });
        g.count += 1;
        g.lengths.entry(s.data.len()).or_insert((0, index as u64)).0 += 1;
        for (seen, b) in g.bytes.iter_mut().zip(s.data) {
            *seen = match *seen {
                Seen::None => Seen::One(*b),
                Seen::One(v) if v == *b => Seen::One(v),
                _ => Seen::Many,
            };
        }
    }
    groups
}

fn entropy(counts: impl Iterator<Item = u64>, total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    counts
        .filter(|c| *c > 0)
        .map(|c| {
            let p = c as f64 / total as f64;
            -p * p.log2()
        })
        .sum()
}

fn permille(part: f64, whole: f64) -> u32 {
    if whole <= 0.0 {
        0
    } else {
        ((part / whole) * 1000.0).round().clamp(0.0, 1000.0) as u32
    }
}

fn varying(group: &Group) -> Vec<usize> {
    group
        .bytes
        .iter()
        .enumerate()
        .filter(|(_, s)| **s == Seen::Many)
        .map(|(o, _)| o)
        .collect()
}

/// Сообщения одной стороны (или все, если на стороны не делим) и их форма без разбиения.
struct Pool<'a, 'b> {
    members: Vec<Indexed<'a, 'b>>,
    varying: Vec<usize>,
    length_entropy: f64,
}

#[derive(Default, Clone, Copy)]
struct Score {
    length: u32,
    constant: u32,
    total: u32,
}

impl Pool<'_, '_> {
    /// Насколько разбиение по `keys` объясняет форму сообщений этой стороны; заодно — сколько
    /// сообщений попало в группы достаточного размера и сколько получилось групп.
    fn score(&self, keys: &[TypeKey], span: usize) -> (Score, u64, usize) {
        let n = self.members.len() as f64;
        let groups = partition(self.members.iter().copied(), keys, span);
        let conditional: f64 = groups
            .values()
            .map(|g| g.count as f64 / n * entropy(g.lengths.values().map(|(c, _)| *c), g.count))
            .sum();
        // Сам различитель внутри своей группы постоянен по определению и в счёт не идёт.
        let counted: Vec<usize> = self
            .varying
            .iter()
            .copied()
            .filter(|o| !keys.contains(&TypeKey::Byte { at: *o as u32 }))
            .collect();
        let mut gained = 0.0;
        let mut covered = 0u64;
        for g in groups.values().filter(|g| g.count >= MIN_GROUP) {
            covered += g.count;
            let constant = counted
                .iter()
                .filter(|o| matches!(g.bytes.get(**o), Some(Seen::One(_))))
                .count();
            gained += g.count as f64 * constant as f64;
        }
        let length = permille(self.length_entropy - conditional, self.length_entropy);
        let constant = permille(gained, n * counted.len() as f64);
        let total = match (self.length_entropy > 0.0, counted.is_empty()) {
            (true, false) => (length + constant) / 2,
            (true, true) => length,
            (false, _) => constant,
        };
        (
            Score {
                length,
                constant,
                total,
            },
            covered,
            groups.len(),
        )
    }
}

/// Байт ведёт себя как число элементов или длина: внутри уже найденных групп размер сообщения
/// растёт вместе с ним по прямой. Такой байт объясняет длину лучше любого кода, но типов не задаёт.
fn count_like(samples: &[TypeSample<'_>], keys: &[TypeKey], candidate: TypeKey) -> bool {
    /// Значение байта → длины сообщений с ним.
    type Lengths = BTreeMap<u8, BTreeSet<usize>>;
    let mut groups: BTreeMap<Vec<u8>, (u64, Lengths)> = BTreeMap::new();
    for s in samples {
        let mut key: Vec<u8> = keys.iter().map(|k| value_of(*k, s)).collect();
        key.push(s.side.min(1));
        let g = groups.entry(key).or_default();
        g.0 += 1;
        g.1.entry(value_of(candidate, s))
            .or_default()
            .insert(s.data.len());
    }
    let (mut varies, mut on_a_line) = (0u64, 0u64);
    for (count, by_value) in groups.values() {
        if by_value.len() < 2 {
            continue;
        }
        varies += count;
        let points: Option<Vec<(i64, i64)>> = by_value
            .iter()
            .map(|(v, lens)| match (lens.len(), lens.first()) {
                (1, Some(len)) => Some((i64::from(*v), *len as i64)),
                _ => None,
            })
            .collect();
        let Some(points) = points else {
            continue;
        };
        let (Some((v0, l0)), Some((v1, l1))) = (points.first(), points.get(1)) else {
            continue;
        };
        let line = points
            .iter()
            .all(|(v, l)| (l - l0) * (v1 - v0) == (l1 - l0) * (v - v0));
        // Каждая единица счётчика добавляет целое число байт; дробный шаг — совпадение кодов и длин.
        let whole_step = l1 > l0 && (l1 - l0) % (v1 - v0) == 0;
        if points.len() >= 3 && whole_step && line {
            on_a_line += count;
        }
    }
    on_a_line > 0 && on_a_line * 2 >= varies
}

/// Байт растёт на единицу от сообщения к сообщению своего потока: это номер, а не тип. В записи
/// по сценарию номер может случайно совпадать с командой и «объяснять» форму сообщений.
fn counter_like(samples: &[TypeSample<'_>], candidate: TypeKey) -> bool {
    let (mut steps, mut plus_one) = (0u64, 0u64);
    for pair in samples.windows(2) {
        let [a, b] = pair else { continue };
        if a.stream != b.stream {
            continue;
        }
        steps += 1;
        plus_one += u64::from(value_of(candidate, b) == value_of(candidate, a).wrapping_add(1));
    }
    steps >= 4 && plus_one * 5 >= steps * 3
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Ищет различители типа сообщений.
pub fn find_types(
    samples: &[TypeSample<'_>],
    options: &TypeOptions,
    cancelled: &dyn Fn() -> bool,
) -> TypeHints {
    let truncated = samples.len() > MAX_TYPE_MESSAGES;
    let samples = samples
        .get(..samples.len().min(MAX_TYPE_MESSAGES))
        .unwrap_or_default();
    let mut out = TypeHints {
        messages: samples.len() as u64,
        truncated,
        ..TypeHints::default()
    };
    if samples.len() < MIN_MESSAGES {
        return out;
    }
    let n = samples.len() as u64;
    let min_len = samples.iter().map(|s| s.data.len()).min().unwrap_or(0);
    let span = min_len.min(CONST_SPAN);
    let indexed = || samples.iter().enumerate();
    let whole = partition(indexed(), &[], span);
    let Some(all) = whole.values().next() else {
        return out;
    };
    let varying_all = varying(all);
    let allowed = |at: usize| !options.exclude.contains(&(at as u32));

    // Стороны и байт, который их повторяет: тогда условие пишется по байту, а не по порту.
    let both_sides = samples.iter().any(|s| s.side == 0) && samples.iter().any(|s| s.side != 0);
    let direction_byte = (0..min_len.min(KEY_SPAN))
        .filter(|at| allowed(*at))
        .find(|at| {
            let by_side = partition(indexed(), &[TypeKey::Side], span);
            let values: Vec<Option<u8>> = by_side
                .values()
                .map(|g| match g.bytes.get(*at) {
                    Some(Seen::One(v)) => Some(*v),
                    _ => None,
                })
                .collect();
            matches!(values.as_slice(), [Some(a), Some(b)] if a != b)
        })
        .map(|at| TypeKey::Byte { at: at as u32 });
    let base: Option<TypeKey> = match (both_sides, direction_byte) {
        (false, _) => None,
        (true, Some(byte)) => Some(byte),
        (true, None) => (!options.without_side).then_some(TypeKey::Side),
    };

    // Оценивается каждая сторона отдельно, даже когда сторону нечем записать в описании.
    let sides: &[Option<u8>] = if both_sides {
        &[Some(0), Some(1)]
    } else {
        &[None]
    };
    let pools: Vec<Pool<'_, '_>> = sides
        .iter()
        .map(|side| {
            indexed()
                .filter(|(_, s)| side.is_none_or(|x| s.side.min(1) == x))
                .collect::<Vec<_>>()
        })
        .filter(|members| members.len() >= MIN_POOL)
        .map(|members| {
            let groups = partition(members.iter().copied(), &[], span);
            let group = groups.values().next();
            Pool {
                varying: group.map(varying).unwrap_or_default(),
                length_entropy: group.map_or(0.0, |g| {
                    entropy(g.lengths.values().map(|(c, _)| *c), g.count)
                }),
                members,
            }
        })
        .collect();
    if pools.is_empty() {
        return out;
    }
    // Оценка набора различителей: среднее по сторонам; покрытие и число групп — по всем сообщениям.
    let evaluate = |keys: &[TypeKey]| -> (Score, u32, usize) {
        let mut sum = Score::default();
        let (mut covered, mut groups) = (0u64, 0usize);
        let mut scored = 0u64;
        for pool in &pools {
            let (s, c, g) = pool.score(keys, span);
            sum.length += s.length;
            sum.constant += s.constant;
            sum.total += s.total;
            covered += c;
            groups += g;
            scored += pool.members.len() as u64;
        }
        let k = pools.len() as u32;
        (
            Score {
                length: sum.length / k,
                constant: sum.constant / k,
                total: sum.total / k,
            },
            permille(covered as f64, scored as f64),
            groups,
        )
    };

    let length_entropy_all = entropy(all.lengths.values().map(|(c, _)| *c), n);
    let candidates: Vec<(TypeKey, u32)> = (0..min_len.min(KEY_SPAN))
        .filter(|at| allowed(*at))
        .map(|at| TypeKey::Byte { at: at as u32 })
        .filter(|key| Some(*key) != base)
        .filter_map(|key| {
            let mut values: BTreeSet<u8> = BTreeSet::new();
            // Байт, отличающийся от длины сообщения на постоянную величину, — длина, а не тип.
            let mut differences: BTreeSet<u8> = BTreeSet::new();
            for s in samples {
                let v = value_of(key, s);
                values.insert(v);
                differences.insert((s.data.len() as u8).wrapping_sub(v));
            }
            let length_like = differences.len() == 1 && length_entropy_all > 0.0;
            ((2..=MAX_VALUES).contains(&values.len())
                && values.len() as u64 * 4 <= n
                && !length_like
                && !counter_like(samples, key))
            .then_some((key, values.len() as u32))
        })
        .collect();

    let mut chosen: Vec<(TypeKey, u32, Score)> = Vec::new();
    let mut reached = 0u32;
    while chosen.len() < MAX_KEYS {
        let mut best: Option<(TypeKey, u32, Score)> = None;
        for (key, values) in &candidates {
            if cancelled() {
                out.incomplete = true;
                return out;
            }
            if chosen.iter().any(|(k, ..)| k == key) {
                continue;
            }
            let mut keys: Vec<TypeKey> = chosen.iter().map(|(k, ..)| *k).collect();
            if count_like(samples, &keys, *key) {
                continue;
            }
            keys.push(*key);
            let (s, covered, groups) = evaluate(&keys);
            if covered < MIN_COVERED || groups > MAX_TYPES {
                continue;
            }
            // При равной оценке остаётся меньшее смещение: кандидаты идут по возрастанию.
            if best.as_ref().is_none_or(|(_, _, b)| s.total > b.total) {
                best = Some((*key, *values, s));
            }
        }
        let needed = if chosen.is_empty() {
            MIN_SCORE
        } else {
            reached + MIN_EXTRA
        };
        match best {
            Some((key, values, s)) if s.total >= needed => {
                reached = s.total;
                chosen.push((key, values, s));
            }
            _ => break,
        }
    }
    if base.is_none() && chosen.is_empty() {
        return out;
    }

    if let Some(key) = base {
        out.keys.push(KeyHint {
            key,
            values: 2,
            length_explained_permille: 0,
            constant_gain_permille: 0,
            score_permille: 0,
        });
    }
    out.keys
        .extend(chosen.iter().map(|(key, values, s)| KeyHint {
            key: *key,
            values: *values,
            length_explained_permille: s.length,
            constant_gain_permille: s.constant,
            score_permille: s.total,
        }));

    let keys: Vec<TypeKey> = out.keys.iter().map(|k| k.key).collect();
    let is_key = |o: usize| keys.contains(&TypeKey::Byte { at: o as u32 });
    for (values, g) in &partition(indexed(), &keys, span) {
        if g.count < MIN_GROUP {
            out.rare += g.count;
        }
        let mut constant: Vec<ConstBytes> = Vec::new();
        let mut run: Option<(usize, Vec<u8>)> = None;
        for o in 0..=span {
            let own = match g.bytes.get(o) {
                // По двум сообщениям о постоянстве судить рано.
                Some(Seen::One(v))
                    if g.count >= MIN_GROUP && varying_all.contains(&o) && !is_key(o) =>
                {
                    Some(*v)
                }
                _ => None,
            };
            match (own, run.as_mut()) {
                (Some(v), Some((_, bytes))) => bytes.push(v),
                (Some(v), None) => run = Some((o, vec![v])),
                (None, _) => {
                    if let Some((start, bytes)) = run.take() {
                        constant.push(ConstBytes {
                            start: start as u32,
                            end: o as u32,
                            bytes: hex(&bytes),
                        });
                    }
                }
            }
        }
        let dominant = g.lengths.iter().max_by_key(|(len, (c, _))| (*c, *len));
        let length_outlier = dominant.and_then(|(len, (c, _))| {
            (c * 10 >= g.count * 9 && *c < g.count)
                .then(|| {
                    g.lengths
                        .iter()
                        .filter(|(l, _)| *l != len)
                        .map(|(_, (_, first))| *first)
                        .min()
                })
                .flatten()
        });
        out.types.push(TypeGroup {
            key: keys
                .iter()
                .zip(values)
                .map(|(key, value)| KeyValue {
                    key: *key,
                    value: *value,
                })
                .collect(),
            count: g.count,
            share_permille: permille(g.count as f64, n as f64),
            min_len: g.lengths.keys().next().copied().unwrap_or(0) as u64,
            max_len: g.lengths.keys().next_back().copied().unwrap_or(0) as u64,
            lengths: g.lengths.len() as u32,
            constant,
            first: g.first,
            length_outlier,
        });
    }
    out.types
        .sort_by(|a, b| b.count.cmp(&a.count).then(a.first.cmp(&b.first)));
    out.types.truncate(MAX_TYPES);
    out
}
