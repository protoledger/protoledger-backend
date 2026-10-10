use crate::capture::Capture;
use crate::net::{self, Fragment, Host, TcpHeader, tcp_flags};
use crate::rng::Rng;

/// Заголовки Ethernet + IPv4 + TCP без опций.
pub const HEADERS_LEN: usize = 14 + 20 + 20;
const WINDOW: u16 = 64240;
const MSG_MAGIC: u8 = 0xA5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    C2s,
    S2c,
}

impl Dir {
    pub(crate) fn idx(self) -> usize {
        match self {
            Dir::C2s => 0,
            Dir::S2c => 1,
        }
    }

    fn other(self) -> Dir {
        match self {
            Dir::C2s => Dir::S2c,
            Dir::S2c => Dir::C2s,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Segment {
    pub dir: Dir,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload: Vec<u8>,
}

impl Segment {
    /// Часть сегмента `[from, from + len)` с тем же направлением и флагами.
    pub fn part(&self, from: usize, len: usize) -> Segment {
        Segment {
            seq: self.seq.wrapping_add(from as u32),
            payload: self.payload[from..from + len].to_vec(),
            ..self.clone()
        }
    }
}

/// Что реально попало в запись: номер кадра, seq и захваченные байты нагрузки.
#[derive(Clone, Debug)]
pub(crate) struct Emitted {
    pub frame: u32,
    pub seq: u32,
    /// Длина нагрузки по заголовкам (до усечения snaplen).
    pub len: u32,
    pub captured: Vec<u8>,
}

/// Модель TCP-соединения: прикладные сообщения → сегменты → кадры, с учётом того,
/// что реально захвачено (эталон строится по захваченному, а не по отправленному).
#[derive(Clone, Debug)]
pub struct Conn {
    pub client: Host,
    pub server: Host,
    pub client_port: u16,
    pub server_port: u16,
    pub(crate) isn: [u32; 2],
    next: [u32; 2],
    pending: [Vec<u8>; 2],
    written: [u64; 2],
    /// Границы прикладных сообщений: смещение от ISN+1 и длина.
    pub(crate) messages: [Vec<(u64, u64)>; 2],
    pub(crate) emitted: [Vec<Emitted>; 2],
    /// Захвачен ли SYN (для C2s) и SYN-ACK (для S2c).
    pub(crate) syn_captured: [bool; 2],
    pub(crate) first_frame: Option<u32>,
}

impl Conn {
    pub fn new(
        client: Host,
        client_port: u16,
        server: Host,
        server_port: u16,
        isn: [u32; 2],
    ) -> Self {
        Self {
            client,
            server,
            client_port,
            server_port,
            isn,
            next: isn,
            pending: [Vec::new(), Vec::new()],
            written: [0, 0],
            messages: [Vec::new(), Vec::new()],
            emitted: [Vec::new(), Vec::new()],
            syn_captured: [false, false],
            first_frame: None,
        }
    }

    fn segment(&mut self, dir: Dir, flags: u8, payload: Vec<u8>, seq_len: u32) -> Segment {
        let i = dir.idx();
        let seg = Segment {
            dir,
            seq: self.next[i],
            ack: if flags & tcp_flags::ACK != 0 {
                self.next[dir.other().idx()]
            } else {
                0
            },
            flags,
            payload,
        };
        self.next[i] = self.next[i].wrapping_add(seq_len);
        seg
    }

    pub fn syn(&mut self) -> Segment {
        self.segment(Dir::C2s, tcp_flags::SYN, Vec::new(), 1)
    }

    pub fn syn_ack(&mut self) -> Segment {
        self.segment(Dir::S2c, tcp_flags::SYN | tcp_flags::ACK, Vec::new(), 1)
    }

    pub fn ack(&mut self, dir: Dir) -> Segment {
        self.segment(dir, tcp_flags::ACK, Vec::new(), 0)
    }

    pub fn fin(&mut self, dir: Dir) -> Segment {
        self.segment(dir, tcp_flags::FIN | tcp_flags::ACK, Vec::new(), 1)
    }

    pub fn rst(&mut self, dir: Dir) -> Segment {
        self.segment(dir, tcp_flags::RST | tcp_flags::ACK, Vec::new(), 0)
    }

    /// Пишет прикладное сообщение `[A5][тип][длина u16 BE][тело]` в буфер отправки.
    pub fn write(&mut self, dir: Dir, kind: u8, body: &[u8]) {
        let i = dir.idx();
        let len = 4 + body.len();
        self.messages[i].push((self.written[i], len as u64));
        self.written[i] += len as u64;
        let buf = &mut self.pending[i];
        buf.extend_from_slice(&[MSG_MAGIC, kind]);
        buf.extend_from_slice(&(body.len() as u16).to_be_bytes());
        buf.extend_from_slice(body);
    }

    pub fn write_random(&mut self, dir: Dir, rng: &mut Rng, kind: u8) {
        let n = rng.range(6, 48) as usize;
        self.write(dir, kind, &rng.bytes(n));
    }

    /// Сегмент с данными: до `max` байт из буфера отправки.
    pub fn send(&mut self, dir: Dir, max: usize) -> Segment {
        let buf = &mut self.pending[dir.idx()];
        let n = max.min(buf.len());
        let payload: Vec<u8> = buf.drain(..n).collect();
        self.segment(dir, tcp_flags::PSH | tcp_flags::ACK, payload, n as u32)
    }

    pub fn send_all(&mut self, dir: Dir) -> Segment {
        self.send(dir, usize::MAX)
    }

    pub(crate) fn frame(&self, seg: &Segment, bad_checksum: bool) -> Vec<u8> {
        let (src, dst, sport, dport) = match seg.dir {
            Dir::C2s => (self.client, self.server, self.client_port, self.server_port),
            Dir::S2c => (self.server, self.client, self.server_port, self.client_port),
        };
        let h = TcpHeader {
            src_port: sport,
            dst_port: dport,
            seq: seg.seq,
            ack: seg.ack,
            flags: seg.flags,
            window: WINDOW,
        };
        let tcp = net::tcp(src.ip, dst.ip, &h, &seg.payload, bad_checksum);
        let ident = (seg.seq as u16) ^ sport;
        let ip = net::ipv4(
            src.ip,
            dst.ip,
            net::IP_PROTO_TCP,
            ident,
            Fragment::default(),
            &tcp,
        );
        net::ethernet(dst.mac, src.mac, net::ETHERTYPE_IPV4, &ip)
    }

    /// Кладёт сегмент в запись и запоминает, какие байты нагрузки реально захвачены.
    pub(crate) fn emit(&mut self, cap: &mut Capture, seg: &Segment, bad_checksum: bool) -> u32 {
        let frame = cap.push(self.frame(seg, bad_checksum));
        let room = (cap.snaplen as usize).saturating_sub(HEADERS_LEN);
        let i = seg.dir.idx();
        if seg.flags & tcp_flags::SYN != 0 {
            self.syn_captured[i] = true;
        }
        self.emitted[i].push(Emitted {
            frame,
            seq: seg.seq,
            len: seg.payload.len() as u32,
            captured: seg.payload[..seg.payload.len().min(room)].to_vec(),
        });
        self.first_frame.get_or_insert(frame);
        frame
    }

    pub fn sender(&self, dir: Dir) -> Host {
        match dir {
            Dir::C2s => self.client,
            Dir::S2c => self.server,
        }
    }
}
