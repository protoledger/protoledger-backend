use crate::capture::{Capture, DEFAULT_SNAPLEN};
use crate::expected::{self, Expected, FORMAT_VERSION, Policy, Skipped};
use crate::net::{self, Fragment, Host, TcpHeader, tcp_flags};
use crate::rng::Rng;
use crate::tcp::{Conn, Dir, Segment};

const SERVER_PORT: u16 = 5020;

pub struct Scenario {
    pub name: &'static str,
    pub description: &'static str,
    snaplen: u32,
    build: fn(&mut Ctx) -> Vec<Conn>,
}

pub struct Generated {
    pub capture: Capture,
    pub expected: Expected,
}

pub const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "normal",
        description: "Рукопожатие, обмены запрос-ответ, два запроса в одном сегменте, ответ в двух сегментах, FIN",
        snaplen: DEFAULT_SNAPLEN,
        build: normal,
    },
    Scenario {
        name: "reorder",
        description: "Сегменты захвачены не по порядку; seq клиента переходит через 2^32",
        snaplen: DEFAULT_SNAPLEN,
        build: reorder,
    },
    Scenario {
        name: "duplicates",
        description: "Одинаковые повторы: запрос сразу, ответ позже",
        snaplen: DEFAULT_SNAPLEN,
        build: duplicates,
    },
    Scenario {
        name: "gap-truncation",
        description: "Сегмент клиента не захвачен (дыра); большой ответ усечён snaplen",
        snaplen: 160,
        build: gap_truncation,
    },
    Scenario {
        name: "overlap-conflict",
        description: "Повтор части сегмента с другими байтами (неоднозначно) и с теми же байтами (повтор)",
        snaplen: DEFAULT_SNAPLEN,
        build: overlap_conflict,
    },
    Scenario {
        name: "no-handshake",
        description: "Запись начата посреди соединения: нет SYN, роли и начало потоков неизвестны",
        snaplen: DEFAULT_SNAPLEN,
        build: no_handshake,
    },
    Scenario {
        name: "bad-checksum",
        description: "Offloading: у всех TCP-кадров клиента неверная контрольная сумма",
        snaplen: DEFAULT_SNAPLEN,
        build: bad_checksum,
    },
    Scenario {
        name: "port-reuse",
        description: "Три соединения с одним 4-кортежем: после FIN, после RST, новый ISN",
        snaplen: DEFAULT_SNAPLEN,
        build: port_reuse,
    },
    Scenario {
        name: "background",
        description: "Фоновый трафик вне обязательной области: ARP, UDP, IPv6, фрагменты IPv4",
        snaplen: DEFAULT_SNAPLEN,
        build: background,
    },
    Scenario {
        name: "mixed",
        description: "Два параллельных соединения со всеми дефектами сразу и фоновым трафиком",
        snaplen: DEFAULT_SNAPLEN,
        build: mixed,
    },
];

pub fn find(name: &str) -> Option<&'static Scenario> {
    SCENARIOS.iter().find(|s| s.name == name)
}

pub fn generate(sc: &Scenario, seed: u64) -> Generated {
    let mut ctx = Ctx {
        rng: Rng::new(seed),
        cap: Capture::new(sc.snaplen, seed),
        skipped: Vec::new(),
        bad: Vec::new(),
        offloading: None,
    };
    let mut conns = (sc.build)(&mut ctx);
    conns.sort_by_key(|c| c.first_frame);
    ctx.bad.sort_unstable();
    let expected = Expected {
        generator: "pl-synth".into(),
        format_version: FORMAT_VERSION,
        scenario: sc.name.into(),
        description: sc.description.into(),
        seed,
        policy: Policy::default(),
        frames: ctx.cap.frames.len() as u32,
        snaplen: sc.snaplen,
        skipped: ctx.skipped,
        bad_checksum_frames: ctx.bad,
        offloading_host: ctx.offloading.map(|h| h.ip.to_string()),
        connections: conns.iter().map(expected::connection).collect(),
    };
    Generated {
        capture: ctx.cap,
        expected,
    }
}

struct Ctx {
    rng: Rng,
    cap: Capture,
    skipped: Vec<Skipped>,
    bad: Vec<u32>,
    offloading: Option<Host>,
}

impl Ctx {
    fn conn(&mut self, client: Host, server: Host) -> Conn {
        let port = self.rng.range(40000, 60999) as u16;
        let isn = [self.rng.next_u32(), self.rng.next_u32()];
        Conn::new(client, port, server, SERVER_PORT, isn)
    }

    fn emit(&mut self, c: &mut Conn, seg: &Segment) -> u32 {
        let bad = self.offloading == Some(c.sender(seg.dir));
        let frame = c.emit(&mut self.cap, seg, bad);
        if bad {
            self.bad.push(frame);
        }
        frame
    }

    /// Кадр с неверной суммой не из-за offloading — повреждение по пути.
    fn emit_corrupted(&mut self, c: &mut Conn, seg: &Segment) -> u32 {
        let frame = c.emit(&mut self.cap, seg, true);
        self.bad.push(frame);
        frame
    }

    fn foreign(&mut self, frame: Vec<u8>, kind: &'static str) {
        let frame = self.cap.push(frame);
        self.skipped.push(Skipped { frame, kind });
    }

    fn handshake(&mut self, c: &mut Conn) {
        let s = c.syn();
        self.emit(c, &s);
        let s = c.syn_ack();
        self.emit(c, &s);
        let s = c.ack(Dir::C2s);
        self.emit(c, &s);
    }

    fn message(&mut self, c: &mut Conn, dir: Dir, kind: u8) -> Segment {
        c.write_random(dir, &mut self.rng, kind);
        c.send_all(dir)
    }

    fn request(&mut self, c: &mut Conn, kind: u8) -> u32 {
        let s = self.message(c, Dir::C2s, kind);
        self.emit(c, &s)
    }

    fn response(&mut self, c: &mut Conn, kind: u8) -> u32 {
        let s = self.message(c, Dir::S2c, kind | 0x80);
        self.emit(c, &s)
    }

    fn exchange(&mut self, c: &mut Conn, n: u8) {
        for k in 1..=n {
            self.request(c, k);
            self.response(c, k);
        }
    }

    fn close(&mut self, c: &mut Conn) {
        let s = c.fin(Dir::C2s);
        self.emit(c, &s);
        let s = c.fin(Dir::S2c);
        self.emit(c, &s);
        let s = c.ack(Dir::C2s);
        self.emit(c, &s);
    }
}

fn normal(ctx: &mut Ctx) -> Vec<Conn> {
    let mut c = ctx.conn(Host::new(0, 10), Host::new(1, 1));
    ctx.handshake(&mut c);
    ctx.exchange(&mut c, 2);

    c.write_random(Dir::C2s, &mut ctx.rng, 3);
    c.write_random(Dir::C2s, &mut ctx.rng, 4);
    let s = c.send_all(Dir::C2s);
    ctx.emit(&mut c, &s);
    ctx.response(&mut c, 3);

    let body = ctx.rng.bytes(120);
    c.write(Dir::S2c, 0x84, &body);
    let s = c.send(Dir::S2c, 50);
    ctx.emit(&mut c, &s);
    let s = c.ack(Dir::C2s);
    ctx.emit(&mut c, &s);
    let s = c.send_all(Dir::S2c);
    ctx.emit(&mut c, &s);

    ctx.close(&mut c);
    vec![c]
}

fn reorder(ctx: &mut Ctx) -> Vec<Conn> {
    let isn = [u32::MAX - 20, ctx.rng.next_u32()];
    let mut c = Conn::new(Host::new(0, 10), 41000, Host::new(1, 1), SERVER_PORT, isn);
    ctx.handshake(&mut c);

    let reqs: Vec<Segment> = (1..=3).map(|k| ctx.message(&mut c, Dir::C2s, k)).collect();
    for i in [1, 0, 2] {
        ctx.emit(&mut c, &reqs[i]);
    }
    let resps: Vec<Segment> = (1..=3)
        .map(|k| ctx.message(&mut c, Dir::S2c, 0x80 | k))
        .collect();
    for i in [2, 0, 1] {
        ctx.emit(&mut c, &resps[i]);
    }
    ctx.close(&mut c);
    vec![c]
}

fn duplicates(ctx: &mut Ctx) -> Vec<Conn> {
    let mut c = ctx.conn(Host::new(0, 10), Host::new(1, 1));
    ctx.handshake(&mut c);

    let req = ctx.message(&mut c, Dir::C2s, 1);
    ctx.emit(&mut c, &req);
    ctx.emit(&mut c, &req);
    let resp = ctx.message(&mut c, Dir::S2c, 0x81);
    ctx.emit(&mut c, &resp);
    ctx.exchange(&mut c, 1);
    ctx.cap.idle(200_000);
    ctx.emit(&mut c, &resp);

    ctx.close(&mut c);
    vec![c]
}

fn gap_truncation(ctx: &mut Ctx) -> Vec<Conn> {
    let mut c = ctx.conn(Host::new(0, 10), Host::new(1, 1));
    ctx.handshake(&mut c);
    ctx.exchange(&mut c, 1);

    // Отправлен, но не попал в запись.
    let _lost = ctx.message(&mut c, Dir::C2s, 2);
    ctx.request(&mut c, 3);
    ctx.response(&mut c, 3);

    let body = ctx.rng.bytes(300);
    c.write(Dir::S2c, 0x85, &body);
    let s = c.send_all(Dir::S2c);
    ctx.emit(&mut c, &s);

    ctx.exchange(&mut c, 1);
    ctx.close(&mut c);
    vec![c]
}

fn overlap_conflict(ctx: &mut Ctx) -> Vec<Conn> {
    let mut c = ctx.conn(Host::new(0, 10), Host::new(1, 1));
    ctx.handshake(&mut c);

    let body = ctx.rng.bytes(36);
    c.write(Dir::C2s, 1, &body);
    let s = c.send_all(Dir::C2s);
    ctx.emit(&mut c, &s);

    let mut conflicting = s.part(8, 16);
    for b in &mut conflicting.payload {
        *b ^= 0x5A;
    }
    ctx.emit(&mut c, &conflicting);
    ctx.emit(&mut c, &s.part(20, 10));

    ctx.response(&mut c, 1);
    ctx.exchange(&mut c, 1);
    ctx.close(&mut c);
    vec![c]
}

fn no_handshake(ctx: &mut Ctx) -> Vec<Conn> {
    let mut c = ctx.conn(Host::new(0, 10), Host::new(1, 1));
    // Рукопожатие и первые обмены были до начала записи.
    for k in 1..=2 {
        let _ = ctx.message(&mut c, Dir::C2s, k);
        let _ = ctx.message(&mut c, Dir::S2c, 0x80 | k);
    }
    ctx.exchange(&mut c, 3);
    ctx.close(&mut c);
    vec![c]
}

fn bad_checksum(ctx: &mut Ctx) -> Vec<Conn> {
    let client = Host::new(0, 10);
    ctx.offloading = Some(client);
    let mut c = ctx.conn(client, Host::new(1, 1));
    ctx.handshake(&mut c);
    ctx.exchange(&mut c, 3);
    ctx.close(&mut c);
    vec![c]
}

fn port_reuse(ctx: &mut Ctx) -> Vec<Conn> {
    let (client, server) = (Host::new(0, 10), Host::new(1, 1));
    let port = 45000;
    let mut isn = || [ctx.rng.next_u32(), ctx.rng.next_u32()];
    let mut a = Conn::new(client, port, server, SERVER_PORT, isn());
    let mut b = Conn::new(client, port, server, SERVER_PORT, isn());
    let mut c = Conn::new(client, port, server, SERVER_PORT, isn());

    ctx.handshake(&mut a);
    ctx.exchange(&mut a, 2);
    ctx.close(&mut a);

    ctx.cap.idle(2_000_000);
    ctx.handshake(&mut b);
    ctx.exchange(&mut b, 1);
    let s = b.rst(Dir::C2s);
    ctx.emit(&mut b, &s);

    ctx.cap.idle(500_000);
    ctx.handshake(&mut c);
    ctx.exchange(&mut c, 1);
    ctx.close(&mut c);
    vec![a, b, c]
}

/// TCP-сегмент постороннего потока, разрезанный на два IPv4-фрагмента.
fn fragmented_tcp(ctx: &mut Ctx, src: Host, dst: Host) -> [Vec<u8>; 2] {
    let h = TcpHeader {
        src_port: 41999,
        dst_port: SERVER_PORT,
        seq: ctx.rng.next_u32(),
        ack: ctx.rng.next_u32(),
        flags: tcp_flags::PSH | tcp_flags::ACK,
        window: 64240,
    };
    let payload = ctx.rng.bytes(40);
    let seg = net::tcp(src.ip, dst.ip, &h, &payload, false);
    let (head, tail) = seg.split_at(32);
    let ident = ctx.rng.next_u32() as u16;
    let frag = |f: Fragment, part: &[u8]| {
        let ip = net::ipv4(src.ip, dst.ip, net::IP_PROTO_TCP, ident, f, part);
        net::ethernet(dst.mac, src.mac, net::ETHERTYPE_IPV4, &ip)
    };
    [
        frag(
            Fragment {
                more: true,
                offset8: 0,
            },
            head,
        ),
        frag(
            Fragment {
                more: false,
                offset8: 4,
            },
            tail,
        ),
    ]
}

fn udp_v4(ctx: &mut Ctx, src: Host, dst: Host) -> Vec<u8> {
    let payload = ctx.rng.bytes(24);
    let udp = net::udp(src.ip, dst.ip, 53000, 53, &payload);
    let ident = ctx.rng.next_u32() as u16;
    let ip = net::ipv4(
        src.ip,
        dst.ip,
        net::IP_PROTO_UDP,
        ident,
        Fragment::default(),
        &udp,
    );
    net::ethernet(dst.mac, src.mac, net::ETHERTYPE_IPV4, &ip)
}

fn background(ctx: &mut Ctx) -> Vec<Conn> {
    let (client, server, other) = (Host::new(0, 10), Host::new(1, 1), Host::new(0, 77));
    let mut c = ctx.conn(client, server);

    ctx.foreign(net::arp_request(client, server.ip), "arp");
    ctx.handshake(&mut c);
    let f = udp_v4(ctx, client, Host::new(1, 53));
    ctx.foreign(f, "udp");
    ctx.exchange(&mut c, 1);
    let payload = ctx.rng.bytes(30);
    ctx.foreign(net::ipv6_udp(other, client, &payload), "ipv6");
    for f in fragmented_tcp(ctx, other, server) {
        ctx.foreign(f, "ipv4-fragment");
    }
    ctx.exchange(&mut c, 1);
    ctx.close(&mut c);
    vec![c]
}

fn mixed(ctx: &mut Ctx) -> Vec<Conn> {
    let server = Host::new(1, 1);
    let mut a = ctx.conn(Host::new(0, 10), server);
    let mut b = ctx.conn(Host::new(0, 11), server);

    ctx.handshake(&mut a);
    ctx.foreign(net::arp_request(Host::new(0, 11), server.ip), "arp");
    ctx.handshake(&mut b);

    let r1 = ctx.message(&mut a, Dir::C2s, 1);
    let r2 = ctx.message(&mut a, Dir::C2s, 2);
    ctx.emit(&mut a, &r2);
    ctx.request(&mut b, 1);
    ctx.emit(&mut a, &r1);

    let resp = ctx.message(&mut a, Dir::S2c, 0x81);
    ctx.emit(&mut a, &resp);
    let _lost = ctx.message(&mut b, Dir::S2c, 0x81);
    ctx.emit(&mut a, &resp);
    ctx.response(&mut a, 2);

    let f = udp_v4(ctx, Host::new(0, 11), Host::new(1, 53));
    ctx.foreign(f, "udp");
    ctx.request(&mut b, 2);
    let s = ctx.message(&mut b, Dir::S2c, 0x82);
    ctx.emit_corrupted(&mut b, &s);

    let body = ctx.rng.bytes(20);
    a.write(Dir::C2s, 3, &body);
    let s = a.send_all(Dir::C2s);
    let mut conflicting = s.part(4, 8);
    for x in &mut conflicting.payload {
        *x = !*x;
    }
    ctx.emit(&mut a, &s);
    ctx.emit(&mut a, &conflicting);
    ctx.response(&mut a, 3);

    ctx.close(&mut b);
    ctx.close(&mut a);
    vec![a, b]
}
