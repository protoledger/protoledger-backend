//! Сборка TCP: соединения (с эпохами при повторе портов), направленные потоки и карта
//! сегментов «участок потока → кадры». Дыры и неоднозначности не заполняются.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]

mod stream;

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddrV4};

use pl_capture::{CaptureIndex, Checksum, TcpSegment, tcp_flags};

pub use stream::{
    Bytes, FrameRef, FrameSpan, MAX_SEGMENTS_PER_STREAM, MAX_STREAM_BYTES, Piece, PieceKind, Stream,
};

/// Соединений в одной записи (`plan/security.md` §6).
pub const MAX_CONNECTIONS: usize = 100_000;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OverlapPolicy {
    /// Брать байты более раннего по захвату сегмента.
    #[default]
    First,
    /// Брать байты более позднего сегмента.
    Last,
    /// Не выбирать: участок остаётся неоднозначным, без «принятых» байтов.
    Flag,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ChecksumPolicy {
    Ignore,
    #[default]
    Warn,
    /// Сегменты с неверной суммой не участвуют в потоке.
    Drop,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Policy {
    pub overlap: OverlapPolicy,
    pub checksum: ChecksumPolicy,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReassemblyError {
    #[error("Превышен предел «{name}»: {value}, допустимо не больше {max}.")]
    LimitExceeded {
        name: &'static str,
        value: u64,
        max: u64,
    },
    #[error("Сборка отменена.")]
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Close {
    Fin,
    Rst,
    Open,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Flag {
    Retransmissions,
    Gaps,
    Ambiguous,
    NoSyn,
    BadChecksum,
    Truncated,
    ReusedPorts,
}

impl Flag {
    pub fn code(self) -> &'static str {
        match self {
            Flag::Retransmissions => "retransmissions",
            Flag::Gaps => "gaps",
            Flag::Ambiguous => "ambiguous",
            Flag::NoSyn => "no_syn",
            Flag::BadChecksum => "bad_checksum",
            Flag::Truncated => "truncated",
            Flag::ReusedPorts => "reused_ports",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    /// Порядковый номер в записи по первому кадру, с 1.
    pub number: u32,
    /// Инициатор, если виден SYN или SYN-ACK; иначе меньший адрес:порт.
    pub a: SocketAddrV4,
    pub b: SocketAddrV4,
    pub roles_known: bool,
    pub first_frame: u32,
    pub last_frame: u32,
    pub first_ts_ns: u64,
    pub last_ts_ns: u64,
    pub frame_count: u32,
    pub close: Close,
    pub flags: BTreeSet<Flag>,
    /// `[a → b, b → a]`.
    pub streams: [Stream; 2],
}

impl Connection {
    /// `<первые 8 hex sha256 записи>:cNNNN`, как в контракте API.
    pub fn id(&self, source_sha256: &str) -> String {
        let prefix = source_sha256.get(..8).unwrap_or(source_sha256);
        format!("{prefix}:c{:04}", self.number)
    }
}

type Key = (SocketAddrV4, SocketAddrV4);

fn key(s: &TcpSegment) -> Key {
    if (s.src.ip(), s.src.port()) <= (s.dst.ip(), s.dst.port()) {
        (s.src, s.dst)
    } else {
        (s.dst, s.src)
    }
}

#[derive(Default)]
struct Epoch<'a> {
    segs: Vec<&'a TcpSegment>,
    /// Отправитель SYN и его ISN.
    syn: Option<(SocketAddrV4, u32)>,
    /// Отправитель SYN-ACK и его ISN.
    syn_ack: Option<(SocketAddrV4, u32)>,
    fin: bool,
    rst: bool,
    reused: bool,
}

impl Epoch<'_> {
    /// SYN начинает новое соединение, если это не повтор SYN текущего (D7, повтор портов).
    fn new_connection_by(&self, s: &TcpSegment) -> bool {
        if !s.has(tcp_flags::SYN) || s.has(tcp_flags::ACK) {
            return false;
        }
        match self.syn {
            Some((client, isn)) => self.rst || self.fin || client != s.src || isn != s.seq,
            None => true,
        }
    }
}

/// Итог по контрольным суммам записи: отличает offloading от повреждения по пути.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecksumReport {
    /// Сегментов с неверной суммой.
    pub bad: u64,
    /// Узлы, от которых есть сегменты с неверной суммой.
    pub bad_hosts: BTreeSet<Ipv4Addr>,
    /// Узел, у которого неверны суммы всех (не менее двух) его сегментов, при том что
    /// у остальных узлов все суммы верны: запись снята на нём самом, и сумму ещё не посчитала сетевая карта.
    pub offloading_host: Option<Ipv4Addr>,
}

pub fn checksum_report(idx: &CaptureIndex) -> ChecksumReport {
    let mut per_host: BTreeMap<Ipv4Addr, (u64, u64)> = BTreeMap::new();
    for s in &idx.segments {
        let entry = per_host.entry(*s.src.ip()).or_default();
        match s.checksum {
            Checksum::Ok => entry.0 += 1,
            Checksum::Bad => entry.1 += 1,
            _ => {}
        }
    }
    let bad_hosts: BTreeSet<Ipv4Addr> = per_host
        .iter()
        .filter(|(_, (_, bad))| *bad > 0)
        .map(|(host, _)| *host)
        .collect();
    let offloading_host = match bad_hosts.iter().next() {
        Some(host) if bad_hosts.len() == 1 => per_host
            .get(host)
            .filter(|(ok, bad)| *ok == 0 && *bad >= 2)
            .map(|_| *host),
        _ => None,
    };
    ChecksumReport {
        bad: per_host.values().map(|(_, bad)| bad).sum(),
        bad_hosts,
        offloading_host,
    }
}

pub fn reassemble(
    idx: &CaptureIndex,
    file: &[u8],
    policy: Policy,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<Connection>, ReassemblyError> {
    let mut epochs: Vec<Epoch<'_>> = Vec::new();
    let mut current: BTreeMap<Key, usize> = BTreeMap::new();
    for s in &idx.segments {
        let k = key(s);
        let at = match current.get(&k).copied() {
            Some(i) if !epochs.get(i).is_some_and(|e| e.new_connection_by(s)) => i,
            prev => {
                if epochs.len() >= MAX_CONNECTIONS {
                    return Err(ReassemblyError::LimitExceeded {
                        name: "соединений в записи",
                        value: epochs.len() as u64 + 1,
                        max: MAX_CONNECTIONS as u64,
                    });
                }
                epochs.push(Epoch {
                    reused: prev.is_some(),
                    ..Epoch::default()
                });
                current.insert(k, epochs.len() - 1);
                epochs.len() - 1
            }
        };
        let Some(e) = epochs.get_mut(at) else {
            continue;
        };
        if s.has(tcp_flags::SYN) {
            let slot = if s.has(tcp_flags::ACK) {
                &mut e.syn_ack
            } else {
                &mut e.syn
            };
            slot.get_or_insert((s.src, s.seq));
        }
        e.fin |= s.has(tcp_flags::FIN);
        e.rst |= s.has(tcp_flags::RST);
        e.segs.push(s);
    }

    let mut out = Vec::with_capacity(epochs.len());
    for (n, e) in epochs.iter().enumerate() {
        if cancelled() {
            return Err(ReassemblyError::Cancelled);
        }
        if let Some(c) = connection(n as u32 + 1, e, idx, file, policy)? {
            out.push(c);
        }
    }
    Ok(out)
}

fn connection(
    number: u32,
    e: &Epoch<'_>,
    idx: &CaptureIndex,
    file: &[u8],
    policy: Policy,
) -> Result<Option<Connection>, ReassemblyError> {
    let (Some(&first), Some(&last)) = (e.segs.first(), e.segs.last()) else {
        return Ok(None);
    };
    let (a, b) = match (e.syn, e.syn_ack) {
        (Some((client, _)), _) => (client, other(first, client)),
        (None, Some((server, _))) => (other(first, server), server),
        (None, None) => key(first),
    };
    let isn_of = |sender: SocketAddrV4| {
        [e.syn, e.syn_ack]
            .into_iter()
            .flatten()
            .find(|(who, _)| *who == sender)
            .map(|(_, isn)| isn)
    };
    let usable = |s: &&&TcpSegment| {
        s.payload_len > 0
            && !(policy.checksum == ChecksumPolicy::Drop && s.checksum == Checksum::Bad)
    };
    let dir = |from: SocketAddrV4| -> Result<Stream, ReassemblyError> {
        let segs: Vec<&TcpSegment> = e
            .segs
            .iter()
            .filter(usable)
            .filter(|s| s.src == from)
            .copied()
            .collect();
        stream::build(&segs, isn_of(from), file, policy.overlap)
    };
    let streams = [dir(a)?, dir(b)?];

    let mut flags = BTreeSet::new();
    let any_piece =
        |f: fn(&PieceKind) -> bool| streams.iter().any(|s| s.pieces.iter().any(|p| f(&p.kind)));
    if streams.iter().any(|s| s.frames.iter().any(|f| f.duplicate)) {
        flags.insert(Flag::Retransmissions);
    }
    if any_piece(|k| matches!(k, PieceKind::Gap)) {
        flags.insert(Flag::Gaps);
    }
    if any_piece(|k| matches!(k, PieceKind::Ambiguous { .. })) {
        flags.insert(Flag::Ambiguous);
    }
    if e.syn.is_none() {
        flags.insert(Flag::NoSyn);
    }
    if policy.checksum != ChecksumPolicy::Ignore
        && e.segs.iter().any(|s| s.checksum == Checksum::Bad)
    {
        flags.insert(Flag::BadChecksum);
    }
    if e.segs.iter().any(|s| s.captured_len < s.payload_len) {
        flags.insert(Flag::Truncated);
    }
    if e.reused {
        flags.insert(Flag::ReusedPorts);
    }

    let ts = |frame: u32| idx.frame(frame).map_or(0, |f| f.ts_ns);
    Ok(Some(Connection {
        number,
        a,
        b,
        roles_known: e.syn.is_some() || e.syn_ack.is_some(),
        first_frame: first.frame,
        last_frame: last.frame,
        first_ts_ns: ts(first.frame),
        last_ts_ns: ts(last.frame),
        frame_count: e.segs.len() as u32,
        close: if e.rst {
            Close::Rst
        } else if e.fin {
            Close::Fin
        } else {
            Close::Open
        },
        flags,
        streams,
    }))
}

fn other(s: &TcpSegment, known: SocketAddrV4) -> SocketAddrV4 {
    if s.src == known { s.dst } else { s.src }
}
