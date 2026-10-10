//! Эталон для записи: что должен получить импорт и сборка TCP при политиках по умолчанию.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::tcp::{Conn, Dir, Emitted};

pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Expected {
    pub generator: String,
    pub format_version: u32,
    pub scenario: String,
    pub description: String,
    pub seed: u64,
    pub policy: Policy,
    pub frames: u32,
    pub snaplen: u32,
    /// Кадры вне обязательной области (не Ethernet/IPv4/TCP или фрагменты): пропуск с диагностикой.
    pub skipped: Vec<Skipped>,
    pub bad_checksum_frames: Vec<u32>,
    /// Узел, у которого все TCP-суммы неверны (offloading при захвате на нём самом).
    pub offloading_host: Option<String>,
    pub connections: Vec<ConnExpected>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub overlap: &'static str,
    pub checksum: &'static str,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            overlap: "first",
            checksum: "warn",
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Skipped {
    pub frame: u32,
    pub kind: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnExpected {
    pub client: String,
    pub server: String,
    pub first_frame: u32,
    /// Роли известны, только если захвачен SYN или SYN-ACK.
    pub roles_known: bool,
    pub client_to_server: StreamExpected,
    pub server_to_client: StreamExpected,
}

/// Собранный поток одного направления. Смещения — от ISN+1, если захвачен SYN
/// (SYN-ACK), иначе от первого захваченного сегмента с данными.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamExpected {
    pub start_known: bool,
    /// Длина с учётом дыр.
    pub length: u64,
    pub known_bytes: u64,
    /// sha256 известных байтов подряд, без дыр.
    pub sha256: String,
    pub gaps: Vec<Range>,
    pub ambiguous: Vec<Ambiguous>,
    pub duplicate_frames: Vec<u32>,
    /// Истинные границы прикладных сообщений (для поиска границ), включая попавшие в дыры.
    pub messages: Vec<Range>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Range {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ambiguous {
    pub offset: u64,
    pub length: u64,
    pub frames: Vec<u32>,
}

pub(crate) fn connection(c: &Conn) -> ConnExpected {
    ConnExpected {
        client: format!("{}:{}", c.client.ip, c.client_port),
        server: format!("{}:{}", c.server.ip, c.server_port),
        first_frame: c.first_frame.unwrap_or(0),
        roles_known: c.syn_captured.iter().any(|s| *s),
        client_to_server: direction(c, Dir::C2s),
        server_to_client: direction(c, Dir::S2c),
    }
}

fn direction(c: &Conn, dir: Dir) -> StreamExpected {
    let i = dir.idx();
    let start = c.isn[i].wrapping_add(1);
    let base = c.syn_captured[i].then_some(start);
    let mut s = stream(&c.emitted[i], base);
    s.expected.start_known = c.syn_captured[i];
    let shift = s.base.wrapping_sub(start) as u64;
    s.expected.messages = c.messages[i]
        .iter()
        .filter(|(off, _)| *off >= shift)
        .map(|&(off, len)| Range {
            offset: off - shift,
            length: len,
        })
        .collect();
    s.expected
}

struct Stream {
    base: u32,
    expected: StreamExpected,
}

fn rel(seq: u32, base: u32) -> u64 {
    let d = seq.wrapping_sub(base);
    debug_assert!(d < 1 << 31, "сегмент раньше начала потока");
    u64::from(d)
}

/// Наивная побайтовая сборка: медленно, зато очевидно верно — эталон для pl-reassembly.
fn stream(emitted: &[Emitted], base: Option<u32>) -> Stream {
    let data: Vec<&Emitted> = emitted.iter().filter(|e| e.len > 0).collect();
    let Some(base) = base.or_else(|| data.first().map(|e| e.seq)) else {
        return Stream {
            base: 0,
            expected: StreamExpected::default(),
        };
    };
    let length = data
        .iter()
        .map(|e| rel(e.seq, base) + u64::from(e.len))
        .max()
        .unwrap_or(0);

    let mut bytes: Vec<Option<(u8, u32)>> = vec![None; length as usize];
    let mut conflicts: BTreeMap<u64, BTreeSet<u32>> = BTreeMap::new();
    let mut duplicate_frames = Vec::new();
    for e in &data {
        let off = rel(e.seq, base) as usize;
        let mut all_seen = !e.captured.is_empty();
        for (k, &b) in e.captured.iter().enumerate() {
            let slot = &mut bytes[off + k];
            match *slot {
                None => {
                    *slot = Some((b, e.frame));
                    all_seen = false;
                }
                Some((old, first)) if old != b => {
                    let set = conflicts.entry((off + k) as u64).or_default();
                    set.insert(first);
                    set.insert(e.frame);
                    all_seen = false;
                }
                Some(_) => {}
            }
        }
        if all_seen {
            duplicate_frames.push(e.frame);
        }
    }

    let mut ambiguous: Vec<Ambiguous> = Vec::new();
    for (off, frames) in conflicts {
        let frames: Vec<u32> = frames.into_iter().collect();
        match ambiguous.last_mut() {
            Some(a) if a.offset + a.length == off && a.frames == frames => a.length += 1,
            _ => ambiguous.push(Ambiguous {
                offset: off,
                length: 1,
                frames,
            }),
        }
    }

    let mut gaps: Vec<Range> = Vec::new();
    let mut hasher = Sha256::new();
    let mut known_bytes = 0;
    for (off, slot) in bytes.iter().enumerate() {
        match slot {
            Some((b, _)) => {
                hasher.update([*b]);
                known_bytes += 1;
            }
            None => match gaps.last_mut() {
                Some(g) if g.offset + g.length == off as u64 => g.length += 1,
                _ => gaps.push(Range {
                    offset: off as u64,
                    length: 1,
                }),
            },
        }
    }

    Stream {
        base,
        expected: StreamExpected {
            start_known: false,
            length,
            known_bytes,
            sha256: hex(&hasher.finalize()),
            gaps,
            ambiguous,
            duplicate_frames,
            messages: Vec::new(),
        },
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn em(frame: u32, seq: u32, data: &[u8]) -> Emitted {
        Emitted {
            frame,
            seq,
            len: data.len() as u32,
            captured: data.to_vec(),
        }
    }

    #[test]
    fn reorder_and_wraparound() {
        let base = u32::MAX - 1;
        let e = [em(2, base.wrapping_add(3), b"de"), em(1, base, b"abc")];
        let s = stream(&e, Some(base)).expected;
        assert_eq!(s.length, 5);
        assert!(s.gaps.is_empty());
        assert_eq!(s.sha256, hex(&Sha256::digest(b"abcde")));
    }

    #[test]
    fn duplicate_gap_and_conflict() {
        let e = [
            em(1, 100, b"aaaa"),
            em(2, 100, b"aaaa"),
            em(3, 102, b"XY"),
            em(4, 110, b"zz"),
        ];
        let s = stream(&e, Some(100)).expected;
        assert_eq!(s.duplicate_frames, vec![2]);
        assert_eq!(
            s.ambiguous,
            vec![Ambiguous {
                offset: 2,
                length: 2,
                frames: vec![1, 3]
            }]
        );
        assert_eq!(
            s.gaps,
            vec![Range {
                offset: 4,
                length: 6
            }]
        );
        assert_eq!(s.length, 12);
        assert_eq!(s.known_bytes, 6);
    }

    #[test]
    fn truncated_tail_is_gap() {
        let e = [Emitted {
            frame: 1,
            seq: 0,
            len: 10,
            captured: b"abc".to_vec(),
        }];
        let s = stream(&e, Some(0)).expected;
        assert_eq!(
            s.gaps,
            vec![Range {
                offset: 3,
                length: 7
            }]
        );
    }
}
