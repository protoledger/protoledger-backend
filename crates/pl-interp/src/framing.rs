//! Фрейминг: границы прикладных сообщений в направленном потоке (TCP-сегмент ≠ сообщение).

use crate::input::{Read, RegionKind, StreamInput};
use crate::schema::{Framing, FramingKind, IntType, MAX_MESSAGE_BYTES, parse_hex};

/// Предел числа сообщений в одном потоке (`plan/security.md` §6: 100 тыс. сообщений в профиле).
pub const MAX_MESSAGES_PER_STREAM: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unknown {
    Gap,
    Ambiguous,
}

/// Почему сообщение нельзя считать полным или законным.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Problem {
    /// Поток оборвался раньше конца сообщения.
    EndOfStream,
    /// Границу определить нельзя: на месте поля длины или разделителя дыра или неоднозначность.
    Unknown(Unknown),
    /// Поле длины даёт невозможную длину (меньше заголовка).
    BadLength(i128),
    /// Заявленная длина больше предела: память под неё не выделяется.
    TooLarge(i128),
    /// Байты вне сообщений (до первого маркера).
    Unframed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    pub start: u64,
    pub end: u64,
    pub problem: Option<Problem>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("сообщений в потоке больше предела {MAX_MESSAGES_PER_STREAM}")]
    TooManyMessages,
    #[error("разбор отменён")]
    Cancelled,
}

fn unknown_of(kind: &RegionKind<'_>) -> Unknown {
    match kind {
        RegionKind::Gap => Unknown::Gap,
        _ => Unknown::Ambiguous,
    }
}

pub fn read_int(bytes: &[u8], ty: IntType) -> Option<i128> {
    let n = ty.size();
    let raw = bytes.get(..n)?;
    let mut buf = [0u8; 16];
    let (to, from): (&mut [u8], &[u8]) = if ty.big_endian() {
        (buf.get_mut(16 - n..)?, raw)
    } else {
        (buf.get_mut(..n)?, raw)
    };
    to.copy_from_slice(from);
    let unsigned = if ty.big_endian() {
        u128::from_be_bytes(buf)
    } else {
        u128::from_le_bytes(buf)
    };
    if ty.signed() {
        let bits = (n * 8) as u32;
        let shift = 128 - bits;
        // Знаковое расширение из младших `bits` бит.
        Some(((unsigned << shift) as i128) >> shift)
    } else {
        i128::try_from(unsigned).ok()
    }
}

struct Search<'a> {
    input: &'a StreamInput<'a>,
}

enum Find {
    At(u64),
    /// Встретили дыру или неоднозначность: поиск продолжать нельзя, участок кончается на `end`.
    Unknown {
        end: u64,
        what: Unknown,
    },
    NotFound,
}

impl Search<'_> {
    /// Ищет `pattern` начиная с `from` по известным байтам.
    fn find(&self, pattern: &[u8], from: u64) -> Find {
        let mut carry: Vec<u8> = Vec::new();
        let mut carry_base = from;
        let first = self.input.regions.partition_point(|r| r.end <= from);
        for r in self.input.regions.iter().skip(first) {
            let bytes = match &r.kind {
                RegionKind::Data(b) => *b,
                RegionKind::Ambiguous(Some(b)) => *b,
                kind => {
                    return Find::Unknown {
                        end: r.end,
                        what: unknown_of(kind),
                    };
                }
            };
            let skip = usize::try_from(from.saturating_sub(r.start)).unwrap_or(0);
            let chunk = bytes.get(skip..).unwrap_or_default();
            if matches!(r.kind, RegionKind::Ambiguous(_)) {
                return Find::Unknown {
                    end: r.end,
                    what: Unknown::Ambiguous,
                };
            }
            carry.extend_from_slice(chunk);
            if let Some(i) = carry.windows(pattern.len()).position(|w| w == pattern) {
                return Find::At(carry_base + i as u64);
            }
            // Оставляем хвост на случай маркера на стыке участков.
            let keep = pattern.len().saturating_sub(1).min(carry.len());
            let drop = carry.len() - keep;
            carry.drain(..drop);
            carry_base += drop as u64;
        }
        Find::NotFound
    }
}

pub fn frame(
    framing: &Framing,
    input: &StreamInput<'_>,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<Frame>, FrameError> {
    let len = input.length;
    let mut out: Vec<Frame> = Vec::new();
    let push = |out: &mut Vec<Frame>, f: Frame| -> Result<(), FrameError> {
        if out.len() >= MAX_MESSAGES_PER_STREAM {
            return Err(FrameError::TooManyMessages);
        }
        if out.len().is_multiple_of(4096) && cancelled() {
            return Err(FrameError::Cancelled);
        }
        out.push(f);
        Ok(())
    };
    let search = Search { input };
    let mut pos = 0u64;
    match framing.kind {
        FramingKind::Fixed => {
            let size = u64::from(framing.size.unwrap_or(0).max(1));
            while pos < len {
                let end = pos.saturating_add(size);
                if end > len {
                    push(
                        &mut out,
                        Frame {
                            start: pos,
                            end: len,
                            problem: Some(Problem::EndOfStream),
                        },
                    )?;
                    break;
                }
                push(
                    &mut out,
                    Frame {
                        start: pos,
                        end,
                        problem: None,
                    },
                )?;
                pos = end;
            }
        }
        FramingKind::LengthPrefixed => {
            let Some(spec) = &framing.length else {
                return Ok(out);
            };
            let at = u64::from(spec.at);
            let size = spec.ty.size() as u64;
            while pos < len {
                let rest = Frame {
                    start: pos,
                    end: len,
                    problem: None,
                };
                let header = input.read(pos + at, size);
                let value = match header {
                    Read::Bytes(b) => read_int(&b, spec.ty),
                    Read::Gap => {
                        push(
                            &mut out,
                            Frame {
                                problem: Some(Problem::Unknown(Unknown::Gap)),
                                ..rest
                            },
                        )?;
                        break;
                    }
                    Read::Ambiguous => {
                        push(
                            &mut out,
                            Frame {
                                problem: Some(Problem::Unknown(Unknown::Ambiguous)),
                                ..rest
                            },
                        )?;
                        break;
                    }
                    Read::OutOfRange => {
                        push(
                            &mut out,
                            Frame {
                                problem: Some(Problem::EndOfStream),
                                ..rest
                            },
                        )?;
                        break;
                    }
                };
                let Some(total) = value.and_then(|v| v.checked_add(i128::from(spec.adjust))) else {
                    push(
                        &mut out,
                        Frame {
                            problem: Some(Problem::BadLength(i128::MAX)),
                            ..rest
                        },
                    )?;
                    break;
                };
                if total < i128::from(at + size) {
                    push(
                        &mut out,
                        Frame {
                            problem: Some(Problem::BadLength(total)),
                            ..rest
                        },
                    )?;
                    break;
                }
                if total > i128::from(MAX_MESSAGE_BYTES) {
                    push(
                        &mut out,
                        Frame {
                            problem: Some(Problem::TooLarge(total)),
                            ..rest
                        },
                    )?;
                    break;
                }
                let end = pos + u64::try_from(total).unwrap_or(u64::MAX);
                if end > len {
                    push(
                        &mut out,
                        Frame {
                            problem: Some(Problem::EndOfStream),
                            ..rest
                        },
                    )?;
                    break;
                }
                push(
                    &mut out,
                    Frame {
                        start: pos,
                        end,
                        problem: None,
                    },
                )?;
                pos = end;
            }
        }
        FramingKind::Delimiter => {
            let pattern = framing
                .bytes
                .as_deref()
                .and_then(parse_hex)
                .unwrap_or_default();
            if pattern.is_empty() {
                return Ok(out);
            }
            while pos < len {
                match search.find(&pattern, pos) {
                    Find::At(i) => {
                        let end = i + pattern.len() as u64;
                        push(
                            &mut out,
                            Frame {
                                start: pos,
                                end,
                                problem: None,
                            },
                        )?;
                        pos = end;
                    }
                    Find::Unknown { end, what } => {
                        push(
                            &mut out,
                            Frame {
                                start: pos,
                                end,
                                problem: Some(Problem::Unknown(what)),
                            },
                        )?;
                        pos = end;
                    }
                    Find::NotFound => {
                        push(
                            &mut out,
                            Frame {
                                start: pos,
                                end: len,
                                problem: Some(Problem::EndOfStream),
                            },
                        )?;
                        break;
                    }
                }
            }
        }
        FramingKind::Magic => {
            let pattern = framing
                .bytes
                .as_deref()
                .and_then(parse_hex)
                .unwrap_or_default();
            if pattern.is_empty() {
                return Ok(out);
            }
            // Начала сообщений — вхождения маркера; байты до первого — вне сообщений.
            let mut starts: Vec<u64> = Vec::new();
            let mut from = 0u64;
            let mut unknown_runs: Vec<(u64, u64, Unknown)> = Vec::new();
            while from < len {
                match search.find(&pattern, from) {
                    Find::At(i) => {
                        starts.push(i);
                        from = i + pattern.len() as u64;
                        if starts.len() > MAX_MESSAGES_PER_STREAM {
                            return Err(FrameError::TooManyMessages);
                        }
                    }
                    Find::Unknown { end, what } => {
                        unknown_runs.push((from, end, what));
                        from = end;
                    }
                    Find::NotFound => break,
                }
            }
            if starts.first().is_none_or(|&s| s > 0) {
                let end = starts.first().copied().unwrap_or(len);
                if end > 0 {
                    push(
                        &mut out,
                        Frame {
                            start: 0,
                            end,
                            problem: Some(Problem::Unframed),
                        },
                    )?;
                }
            }
            for (k, &s) in starts.iter().enumerate() {
                let end = starts.get(k + 1).copied().unwrap_or(len);
                let touched = unknown_runs
                    .iter()
                    .find(|(a, b, _)| *a < end && *b > s)
                    .map(|(_, _, w)| *w);
                push(
                    &mut out,
                    Frame {
                        start: s,
                        end,
                        problem: touched.map(Problem::Unknown),
                    },
                )?;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::tests::{data, meta};
    use crate::input::{Region, StreamInput};
    use crate::schema::{LengthSpec, Status};

    fn no_cancel() -> bool {
        false
    }

    fn prefixed(at: u32, ty: IntType, adjust: i64) -> Framing {
        Framing {
            kind: FramingKind::LengthPrefixed,
            length: Some(LengthSpec { at, ty, adjust }),
            size: None,
            bytes: None,
            status: Status::Rule,
        }
    }

    fn simple(kind: FramingKind, size: Option<u32>, bytes: Option<&str>) -> Framing {
        Framing {
            kind,
            length: None,
            size,
            bytes: bytes.map(str::to_owned),
            status: Status::Rule,
        }
    }

    fn spans(frames: &[Frame]) -> Vec<(u64, u64, Option<Problem>)> {
        frames.iter().map(|f| (f.start, f.end, f.problem)).collect()
    }

    #[test]
    fn reads_integers_in_both_orders() {
        assert_eq!(read_int(&[0x01, 0x02], IntType::U16be), Some(0x0102));
        assert_eq!(read_int(&[0x01, 0x02], IntType::U16le), Some(0x0201));
        assert_eq!(read_int(&[0xff], IntType::I8), Some(-1));
        assert_eq!(
            read_int(&[0xff, 0xff, 0xff, 0xfb], IntType::I32be),
            Some(-5)
        );
        assert_eq!(
            read_int(&[0xfb, 0xff, 0xff, 0xff], IntType::I32le),
            Some(-5)
        );
        assert_eq!(
            read_int(&[0xff; 8], IntType::U64le),
            Some(i128::from(u64::MAX))
        );
        assert_eq!(read_int(&[0xff; 8], IntType::I64be), Some(-1));
        assert_eq!(read_int(&[1], IntType::U16be), None);
    }

    #[test]
    fn length_prefixed_splits_messages_inside_segments() {
        // [len u8 = всего байт] + тело
        let bytes = [3, 9, 9, 2, 7, 4, 1, 1, 1];
        let frames = frame(&prefixed(0, IntType::U8, 0), &data(&bytes), &no_cancel).unwrap();
        assert_eq!(spans(&frames), [(0, 3, None), (3, 5, None), (5, 9, None)]);
    }

    #[test]
    fn length_prefixed_problems() {
        let cases: [(&[u8], u64, Problem); 4] = [
            (&[3, 1, 1, 9], 3, Problem::EndOfStream),
            (&[3, 1, 1, 1, 0], 3, Problem::BadLength(0)),
            (&[3, 1, 1, 200, 0, 0], 3, Problem::EndOfStream),
            (&[0xff, 1, 1], 0, Problem::EndOfStream),
        ];
        for (bytes, _, expected) in cases {
            let frames = frame(&prefixed(0, IntType::U8, 0), &data(bytes), &no_cancel).unwrap();
            assert_eq!(
                frames.last().and_then(|f| f.problem),
                Some(expected),
                "{bytes:?}"
            );
        }
        // Длина меньше самого заголовка и заявленные гигабайты не выделяют память.
        let tiny = frame(&prefixed(0, IntType::U8, 0), &data(&[0, 2, 3]), &no_cancel).unwrap();
        assert!(matches!(tiny[0].problem, Some(Problem::BadLength(0))));
        let huge = frame(
            &prefixed(0, IntType::U32be, 0),
            &data(&[0x7f, 0xff, 0xff, 0xff, 1]),
            &no_cancel,
        )
        .unwrap();
        assert!(matches!(huge[0].problem, Some(Problem::TooLarge(_))));
        assert_eq!(spans(&huge), [(0, 5, Some(Problem::TooLarge(0x7fff_ffff)))]);
    }

    #[test]
    fn gap_inside_a_known_length_message_keeps_boundaries() {
        let input = StreamInput {
            meta: meta(),
            length: 8,
            regions: vec![
                Region {
                    start: 0,
                    end: 2,
                    kind: RegionKind::Data(&[5, 0]),
                },
                Region {
                    start: 2,
                    end: 4,
                    kind: RegionKind::Gap,
                },
                Region {
                    start: 4,
                    end: 5,
                    kind: RegionKind::Data(&[0]),
                },
                Region {
                    start: 5,
                    end: 8,
                    kind: RegionKind::Data(&[3, 1, 1]),
                },
            ],
        };
        let frames = frame(&prefixed(0, IntType::U8, 0), &input, &no_cancel).unwrap();
        assert_eq!(spans(&frames), [(0, 5, None), (5, 8, None)]);
    }

    #[test]
    fn gap_over_length_field_stops_framing() {
        let input = StreamInput {
            meta: meta(),
            length: 6,
            regions: vec![
                Region {
                    start: 0,
                    end: 3,
                    kind: RegionKind::Data(&[3, 1, 1]),
                },
                Region {
                    start: 3,
                    end: 4,
                    kind: RegionKind::Gap,
                },
                Region {
                    start: 4,
                    end: 6,
                    kind: RegionKind::Data(&[1, 1]),
                },
            ],
        };
        let frames = frame(&prefixed(0, IntType::U8, 0), &input, &no_cancel).unwrap();
        assert_eq!(
            spans(&frames),
            [(0, 3, None), (3, 6, Some(Problem::Unknown(Unknown::Gap)))]
        );
    }

    #[test]
    fn fixed_and_delimiter_and_magic() {
        let fixed = frame(
            &simple(FramingKind::Fixed, Some(4), None),
            &data(&[0; 10]),
            &no_cancel,
        )
        .unwrap();
        assert_eq!(
            spans(&fixed),
            [
                (0, 4, None),
                (4, 8, None),
                (8, 10, Some(Problem::EndOfStream))
            ]
        );

        let lines = frame(
            &simple(FramingKind::Delimiter, None, Some("0d0a")),
            &data(b"ab\r\ncd\r\nef"),
            &no_cancel,
        )
        .unwrap();
        assert_eq!(
            spans(&lines),
            [
                (0, 4, None),
                (4, 8, None),
                (8, 10, Some(Problem::EndOfStream))
            ]
        );

        let magic = frame(
            &simple(FramingKind::Magic, None, Some("aa55")),
            &data(&[1, 0xaa, 0x55, 7, 0xaa, 0x55, 8, 9]),
            &no_cancel,
        )
        .unwrap();
        assert_eq!(
            spans(&magic),
            [(0, 1, Some(Problem::Unframed)), (1, 4, None), (4, 8, None)]
        );
        let none = frame(
            &simple(FramingKind::Magic, None, Some("aa55")),
            &data(&[0, 2, 3]),
            &no_cancel,
        )
        .unwrap();
        assert_eq!(spans(&none), [(0, 3, Some(Problem::Unframed))]);
    }

    #[test]
    fn delimiter_split_across_regions() {
        let input = StreamInput {
            meta: meta(),
            length: 6,
            regions: vec![
                Region {
                    start: 0,
                    end: 3,
                    kind: RegionKind::Data(b"ab\r"),
                },
                Region {
                    start: 3,
                    end: 6,
                    kind: RegionKind::Data(b"\ncd\r"),
                },
            ],
        };
        let input = StreamInput {
            length: 7,
            regions: vec![
                input.regions[0].clone(),
                Region {
                    start: 3,
                    end: 7,
                    kind: RegionKind::Data(b"\ncd\r"),
                },
            ],
            ..input
        };
        let lines = frame(
            &simple(FramingKind::Delimiter, None, Some("0d0a")),
            &input,
            &no_cancel,
        )
        .unwrap();
        assert_eq!(
            spans(&lines),
            [(0, 4, None), (4, 7, Some(Problem::EndOfStream))]
        );
    }

    #[test]
    fn delimiter_hits_gap() {
        let input = StreamInput {
            meta: meta(),
            length: 7,
            regions: vec![
                Region {
                    start: 0,
                    end: 3,
                    kind: RegionKind::Data(b"ab\n"),
                },
                Region {
                    start: 3,
                    end: 5,
                    kind: RegionKind::Gap,
                },
                Region {
                    start: 5,
                    end: 7,
                    kind: RegionKind::Data(b"c\n"),
                },
            ],
        };
        let frames = frame(
            &simple(FramingKind::Delimiter, None, Some("0a")),
            &input,
            &no_cancel,
        )
        .unwrap();
        assert_eq!(
            spans(&frames),
            [
                (0, 3, None),
                (3, 5, Some(Problem::Unknown(Unknown::Gap))),
                (5, 7, None)
            ]
        );
    }

    #[test]
    fn message_count_is_limited_and_cancellable() {
        let bytes = vec![1u8; MAX_MESSAGES_PER_STREAM + 10];
        let err = frame(
            &simple(FramingKind::Fixed, Some(1), None),
            &data(&bytes),
            &no_cancel,
        )
        .unwrap_err();
        assert_eq!(err, FrameError::TooManyMessages);
        let err = frame(
            &simple(FramingKind::Fixed, Some(1), None),
            &data(&[1; 100]),
            &|| true,
        )
        .unwrap_err();
        assert_eq!(err, FrameError::Cancelled);
    }
}
