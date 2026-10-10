//! Входной поток для применения интерпретации: участки известных байтов, дыры и неоднозначности.
//! Свой тип, чтобы библиотека не зависела от сборки TCP: адаптер пишет вызывающий.

use std::borrow::Cow;

use crate::schema::Direction;

/// Что известно об участке потока.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegionKind<'a> {
    Data(&'a [u8]),
    /// Перекрытие с разными байтами; `Some` — байты, принятые политикой, `None` — не принято ни одно.
    Ambiguous(Option<&'a [u8]>),
    Gap,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region<'a> {
    pub start: u64,
    pub end: u64,
    pub kind: RegionKind<'a>,
}

/// Откуда и куда идёт поток: нужно условию `scope.filter`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamMeta {
    pub direction: Direction,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamInput<'a> {
    pub meta: StreamMeta,
    pub length: u64,
    /// По порядку, без пропусков и перекрытий: покрывают `[0, length)`.
    pub regions: Vec<Region<'a>>,
}

/// Результат чтения диапазона потока.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Read<'a> {
    Bytes(Cow<'a, [u8]>),
    /// В диапазоне есть дыра: данных нет в записи.
    Gap,
    /// В диапазоне неоднозначность без принятых байтов (или принятые, но участок помечен).
    Ambiguous,
    /// Диапазон выходит за конец потока.
    OutOfRange,
}

impl<'a> StreamInput<'a> {
    fn first_region(&self, pos: u64) -> usize {
        self.regions.partition_point(|r| r.end <= pos)
    }

    /// Читает `[start, start+len)`. Сшивает участки; дыра и неоднозначность важнее байтов.
    pub fn read(&self, start: u64, len: u64) -> Read<'a> {
        let Some(end) = start.checked_add(len) else {
            return Read::OutOfRange;
        };
        if end > self.length {
            return Read::OutOfRange;
        }
        if len == 0 {
            return Read::Bytes(Cow::Borrowed(&[]));
        }
        let mut parts: Vec<&'a [u8]> = Vec::new();
        let mut ambiguous = false;
        let mut at = start;
        for r in self.regions.iter().skip(self.first_region(start)) {
            if r.start >= end {
                break;
            }
            let from = at.max(r.start);
            let to = end.min(r.end);
            let (Ok(a), Ok(b)) = (
                usize::try_from(from - r.start),
                usize::try_from(to - r.start),
            ) else {
                return Read::OutOfRange;
            };
            match &r.kind {
                RegionKind::Gap => return Read::Gap,
                RegionKind::Ambiguous(None) => return Read::Ambiguous,
                RegionKind::Ambiguous(Some(bytes)) => {
                    ambiguous = true;
                    parts.push(bytes.get(a..b).unwrap_or_default());
                }
                RegionKind::Data(bytes) => parts.push(bytes.get(a..b).unwrap_or_default()),
            }
            at = to;
        }
        if at != end {
            return Read::OutOfRange;
        }
        if ambiguous {
            return Read::Ambiguous;
        }
        match parts.as_slice() {
            [one] => Read::Bytes(Cow::Borrowed(one)),
            _ => Read::Bytes(Cow::Owned(parts.concat())),
        }
    }

    /// Первая дыра или неоднозначность в `[start, end)`: `(начало, конец, дыра ли)`.
    pub fn first_unknown(&self, start: u64, end: u64) -> Option<(u64, u64, bool)> {
        self.regions
            .iter()
            .skip(self.first_region(start))
            .take_while(|r| r.start < end)
            .find_map(|r| match r.kind {
                RegionKind::Gap => Some((r.start.max(start), r.end.min(end), true)),
                RegionKind::Ambiguous(_) => Some((r.start.max(start), r.end.min(end), false)),
                RegionKind::Data(_) => None,
            })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn meta() -> StreamMeta {
        StreamMeta {
            direction: Direction::AToB,
            src_ip: "10.0.0.10".to_owned(),
            dst_ip: "10.0.1.1".to_owned(),
            src_port: 49320,
            dst_port: 4710,
        }
    }

    /// Одним куском известных байтов.
    pub(crate) fn data(bytes: &[u8]) -> StreamInput<'_> {
        StreamInput {
            meta: meta(),
            length: bytes.len() as u64,
            regions: vec![Region {
                start: 0,
                end: bytes.len() as u64,
                kind: RegionKind::Data(bytes),
            }],
        }
    }

    #[test]
    fn reads_across_regions_and_reports_unknowns() {
        let input = StreamInput {
            meta: meta(),
            length: 12,
            regions: vec![
                Region {
                    start: 0,
                    end: 4,
                    kind: RegionKind::Data(&[1, 2, 3, 4]),
                },
                Region {
                    start: 4,
                    end: 6,
                    kind: RegionKind::Gap,
                },
                Region {
                    start: 6,
                    end: 8,
                    kind: RegionKind::Ambiguous(Some(&[7, 8])),
                },
                Region {
                    start: 8,
                    end: 10,
                    kind: RegionKind::Ambiguous(None),
                },
                Region {
                    start: 10,
                    end: 12,
                    kind: RegionKind::Data(&[11, 12]),
                },
            ],
        };
        assert_eq!(input.read(1, 2), Read::Bytes(Cow::Borrowed(&[2, 3])));
        assert_eq!(input.read(2, 3), Read::Gap);
        assert_eq!(input.read(6, 2), Read::Ambiguous);
        assert_eq!(input.read(8, 1), Read::Ambiguous);
        assert_eq!(input.read(10, 2), Read::Bytes(Cow::Borrowed(&[11, 12])));
        assert_eq!(input.read(10, 3), Read::OutOfRange);
        assert_eq!(input.read(u64::MAX, 2), Read::OutOfRange);
        assert_eq!(input.read(3, 0), Read::Bytes(Cow::Borrowed(&[])));
        assert_eq!(input.first_unknown(0, 12), Some((4, 6, true)));
        assert_eq!(input.first_unknown(6, 12), Some((6, 8, false)));
        assert_eq!(input.first_unknown(10, 12), None);
    }

    #[test]
    fn stitches_neighbouring_data_regions() {
        let input = StreamInput {
            meta: meta(),
            length: 4,
            regions: vec![
                Region {
                    start: 0,
                    end: 2,
                    kind: RegionKind::Data(&[1, 2]),
                },
                Region {
                    start: 2,
                    end: 4,
                    kind: RegionKind::Data(&[3, 4]),
                },
            ],
        };
        assert_eq!(input.read(1, 2), Read::Bytes(Cow::Owned(vec![2, 3])));
    }
}
