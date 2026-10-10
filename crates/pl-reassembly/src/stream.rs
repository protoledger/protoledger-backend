use pl_capture::TcpSegment;

use crate::{OverlapPolicy, ReassemblyError};

/// Сегментов (с данными) в одном направлении (`plan/security.md` §6).
pub const MAX_SEGMENTS_PER_STREAM: usize = 1_000_000;
/// Записанных байтов одного направления.
pub const MAX_STREAM_BYTES: u64 = 512 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameRef {
    pub frame: u32,
    /// Кадр повторяет байты, уже полученные из более раннего кадра.
    pub duplicate: bool,
}

/// Участок байтов в файле записи и кадры, из которых он известен.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bytes {
    pub file_offset: u64,
    pub frames: Vec<FrameRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PieceKind {
    Data(Bytes),
    /// ТЗ 7.3: дыра не заполняется — байтов нет.
    Gap,
    /// Перекрытие с разными байтами; `chosen` — вариант по политике проекта.
    Ambiguous {
        chosen: usize,
        variants: Vec<Bytes>,
    },
}

/// Участок потока `[start, end)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Piece {
    pub start: u64,
    pub end: u64,
    pub kind: PieceKind,
}

/// Что кадр дал потоку: диапазон по заголовкам (вместе с не записанной частью).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameSpan {
    pub frame: u32,
    pub start: u64,
    pub end: u64,
    pub duplicate: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stream {
    /// Начало известно (захвачен SYN этого направления); иначе смещение 0 — первый
    /// захваченный байт.
    pub start_available: bool,
    pub length: u64,
    pub pieces: Vec<Piece>,
    /// Кадры с данными, по номеру кадра.
    pub frames: Vec<FrameSpan>,
}

impl Stream {
    pub fn data_bytes(&self) -> u64 {
        self.sum(|k| matches!(k, PieceKind::Data(_)))
    }

    pub fn gap_bytes(&self) -> u64 {
        self.sum(|k| matches!(k, PieceKind::Gap))
    }

    pub fn ambiguous_bytes(&self) -> u64 {
        self.sum(|k| matches!(k, PieceKind::Ambiguous { .. }))
    }

    fn sum(&self, f: impl Fn(&PieceKind) -> bool) -> u64 {
        self.pieces
            .iter()
            .filter(|p| f(&p.kind))
            .map(|p| p.end - p.start)
            .sum()
    }

    /// Участки, пересекающие `[from, to)`, по порядку.
    pub fn pieces_in(&self, from: u64, to: u64) -> &[Piece] {
        let lo = self.pieces.partition_point(|p| p.end <= from);
        let hi = self.pieces.partition_point(|p| p.start < to);
        self.pieces.get(lo..hi.max(lo)).unwrap_or_default()
    }
}

struct Seg {
    frame: u32,
    start: u64,
    captured_end: u64,
    declared_end: u64,
    file_offset: u64,
    /// Все записанные байты уже были у более ранних кадров и совпали.
    duplicate: bool,
}

/// Смещение seq относительно `base` по модулю 2^32 (RFC 9293): отрицательное — раньше начала.
fn distance(seq: u32, base: u32) -> i64 {
    i64::from(seq.wrapping_sub(base) as i32)
}

/// Собирает одно направление. `segs` — сегменты с данными в порядке захвата;
/// `isn` — ISN, если захвачен SYN этого направления.
pub(crate) fn build(
    segs: &[&TcpSegment],
    isn: Option<u32>,
    file: &[u8],
    overlap: OverlapPolicy,
) -> Result<Stream, ReassemblyError> {
    if segs.len() > MAX_SEGMENTS_PER_STREAM {
        return Err(ReassemblyError::LimitExceeded {
            name: "сегментов в потоке",
            value: segs.len() as u64,
            max: MAX_SEGMENTS_PER_STREAM as u64,
        });
    }
    let mut stream = Stream {
        start_available: isn.is_some(),
        ..Stream::default()
    };
    let Some(first) = segs.first() else {
        return Ok(stream);
    };
    let base = match isn {
        Some(isn) => isn.wrapping_add(1),
        None => {
            // Без SYN начало — самый ранний по seq сегмент, даже если захвачен позже.
            let min = segs
                .iter()
                .map(|s| distance(s.seq, first.seq))
                .min()
                .unwrap_or(0);
            first.seq.wrapping_add(min as u32)
        }
    };

    let mut items: Vec<Seg> = Vec::with_capacity(segs.len());
    let mut captured_total = 0u64;
    for s in segs {
        let d = distance(s.seq, base);
        let declared_end = d + i64::from(s.payload_len);
        if declared_end <= 0 {
            continue;
        }
        // Байты до начала потока (повтор данных до SYN) отбрасываем.
        let skip = (-d).max(0) as u64;
        let start = d.max(0) as u64;
        let captured = u64::from(s.captured_len).saturating_sub(skip);
        captured_total += captured;
        items.push(Seg {
            frame: s.frame,
            start,
            captured_end: start + captured,
            declared_end: declared_end as u64,
            file_offset: s.payload_offset + skip,
            duplicate: captured > 0,
        });
    }
    if captured_total > MAX_STREAM_BYTES {
        return Err(ReassemblyError::LimitExceeded {
            name: "записанных байтов в направлении",
            value: captured_total,
            max: MAX_STREAM_BYTES,
        });
    }
    stream.length = items.iter().map(|s| s.declared_end).max().unwrap_or(0);

    let mut points: Vec<u64> = items
        .iter()
        .filter(|s| s.captured_end > s.start)
        .flat_map(|s| [s.start, s.captured_end])
        .collect();
    points.sort_unstable();
    points.dedup();
    let mut by_start: Vec<usize> = (0..items.len())
        .filter(|&i| items.get(i).is_some_and(|s| s.captured_end > s.start))
        .collect();
    by_start.sort_by_key(|&i| items.get(i).map_or(0, |s| s.start));

    // Активные сегменты — индексы в `items`, то есть в порядке захвата.
    let mut active: Vec<usize> = Vec::new();
    let mut next = 0;
    let mut cursor = 0u64;
    for w in points.windows(2) {
        let &[x, y] = w else { continue };
        active.retain(|&i| items.get(i).is_some_and(|s| s.captured_end > x));
        while let Some(&i) = by_start.get(next) {
            if items.get(i).is_none_or(|s| s.start > x) {
                break;
            }
            let pos = active.partition_point(|&a| a < i);
            active.insert(pos, i);
            next += 1;
        }
        if active.is_empty() {
            continue;
        }
        if x > cursor {
            push(&mut stream.pieces, cursor, x, PieceKind::Gap);
        }
        let kind = interval(&mut items, &active, x, y, file, overlap);
        push(&mut stream.pieces, x, y, kind);
        cursor = y;
    }
    if stream.length > cursor {
        push(&mut stream.pieces, cursor, stream.length, PieceKind::Gap);
    }

    stream.frames = items
        .iter()
        .map(|s| FrameSpan {
            frame: s.frame,
            start: s.start,
            end: s.declared_end,
            duplicate: s.duplicate,
        })
        .collect();
    stream.frames.sort_by_key(|f| f.frame);
    Ok(stream)
}

fn slice<'a>(file: &'a [u8], s: &Seg, x: u64, y: u64) -> &'a [u8] {
    let from = s.file_offset + (x - s.start);
    usize::try_from(from)
        .ok()
        .and_then(|f| file.get(f..f.checked_add(usize::try_from(y - x).ok()?)?))
        .unwrap_or_default()
}

/// Участок `[x, y)`, покрытый `active` (порядок захвата): данные или неоднозначность.
fn interval(
    items: &mut [Seg],
    active: &[usize],
    x: u64,
    y: u64,
    file: &[u8],
    overlap: OverlapPolicy,
) -> PieceKind {
    // Группы одинаковых байтов; внутри группы — порядок захвата.
    let mut groups: Vec<(Vec<u8>, Vec<usize>)> = Vec::new();
    for (k, &i) in active.iter().enumerate() {
        let Some(s) = items.get(i) else { continue };
        let bytes = slice(file, s, x, y);
        if k == 0 {
            if let Some(s) = items.get_mut(i) {
                s.duplicate = false;
            }
        } else if groups.first().is_none_or(|(g, _)| g.as_slice() != bytes)
            && let Some(s) = items.get_mut(i)
        {
            s.duplicate = false;
        }
        match groups.iter_mut().find(|(g, _)| g.as_slice() == bytes) {
            Some((_, members)) => members.push(i),
            None => groups.push((bytes.to_vec(), vec![i])),
        }
    }
    let to_bytes = |members: &[usize]| Bytes {
        file_offset: members
            .first()
            .and_then(|&i| items.get(i))
            .map_or(0, |s| s.file_offset + (x - s.start)),
        frames: members
            .iter()
            .enumerate()
            .filter_map(|(k, &i)| {
                items.get(i).map(|s| FrameRef {
                    frame: s.frame,
                    duplicate: k > 0,
                })
            })
            .collect(),
    };
    if groups.len() == 1 {
        let members = groups
            .first()
            .map(|(_, m)| m.as_slice())
            .unwrap_or_default();
        return PieceKind::Data(to_bytes(members));
    }
    let decisive = match overlap {
        OverlapPolicy::First => active.first(),
        OverlapPolicy::Last => active.last(),
    };
    let chosen = groups
        .iter()
        .position(|(_, m)| decisive.is_some_and(|d| m.contains(d)))
        .unwrap_or(0);
    PieceKind::Ambiguous {
        chosen,
        variants: groups.iter().map(|(_, m)| to_bytes(m)).collect(),
    }
}

fn contiguous(a: &Bytes, a_len: u64, b: &Bytes) -> bool {
    a.file_offset + a_len == b.file_offset && a.frames == b.frames
}

/// Добавляет участок, склеивая с предыдущим, если это продолжение того же.
fn push(pieces: &mut Vec<Piece>, start: u64, end: u64, kind: PieceKind) {
    if let Some(last) = pieces.last_mut()
        && last.end == start
    {
        let len = last.end - last.start;
        let joinable = match (&last.kind, &kind) {
            (PieceKind::Gap, PieceKind::Gap) => true,
            (PieceKind::Data(a), PieceKind::Data(b)) => contiguous(a, len, b),
            (
                PieceKind::Ambiguous {
                    chosen: ca,
                    variants: va,
                },
                PieceKind::Ambiguous {
                    chosen: cb,
                    variants: vb,
                },
            ) => {
                ca == cb
                    && va.len() == vb.len()
                    && va.iter().zip(vb).all(|(a, b)| contiguous(a, len, b))
            }
            _ => false,
        };
        if joinable {
            last.end = end;
            return;
        }
    }
    pieces.push(Piece { start, end, kind });
}
