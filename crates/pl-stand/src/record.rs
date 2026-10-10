//! Запись трафика сеанса «клиент ↔ устройство» без сети и привилегий: те же сообщения, что и в
//! реальном сеансе, нарезаются на TCP-сегменты и кадры Ethernet. Результат детерминирован.

use std::net::Ipv4Addr;

use pl_synth::capture::{Capture, DEFAULT_SNAPLEN};
use pl_synth::net::{self, Fragment, Host, TcpHeader, tcp_flags};
use pl_synth::rng::Rng;

use crate::device::Device;
use crate::log::LogEntry;
use crate::proto::Message;
use crate::scenario::{Scenario, responses};

/// Максимальный размер данных в сегменте при MTU 1500.
const MSS: usize = 1460;
const WINDOW: u16 = 64240;

pub struct Recording {
    pub capture: Capture,
    pub log: Vec<LogEntry>,
}

struct Wire {
    cap: Capture,
    client: Host,
    server: Host,
    client_port: u16,
    server_port: u16,
    /// Следующий seq: клиент, устройство.
    next: [u32; 2],
    ident: u16,
}

impl Wire {
    fn push(&mut self, from_client: bool, flags: u8, payload: &[u8]) -> u32 {
        let (src, dst, sport, dport, i) = if from_client {
            (
                self.client,
                self.server,
                self.client_port,
                self.server_port,
                0,
            )
        } else {
            (
                self.server,
                self.client,
                self.server_port,
                self.client_port,
                1,
            )
        };
        let ack = if flags & tcp_flags::ACK != 0 {
            self.next[1 - i]
        } else {
            0
        };
        let header = TcpHeader {
            src_port: sport,
            dst_port: dport,
            seq: self.next[i],
            ack,
            flags,
            window: WINDOW,
        };
        let segment = net::tcp(src.ip, dst.ip, &header, payload, false);
        self.ident = self.ident.wrapping_add(1);
        let ip = net::ipv4(
            src.ip,
            dst.ip,
            net::IP_PROTO_TCP,
            self.ident,
            Fragment::default(),
            &segment,
        );
        let frame = self
            .cap
            .push(net::ethernet(dst.mac, src.mac, net::ETHERTYPE_IPV4, &ip));
        let syn_fin = u32::from(flags & (tcp_flags::SYN | tcp_flags::FIN) != 0);
        self.next[i] = self.next[i].wrapping_add(payload.len() as u32 + syn_fin);
        frame
    }

    /// Отправляет данные сегментами по MSS; возвращает номер первого кадра.
    /// Получатель подтверждает каждый второй сегмент и конец передачи.
    fn send(&mut self, from_client: bool, bytes: &[u8]) -> Option<u32> {
        let mut first = None;
        let chunks: Vec<&[u8]> = bytes.chunks(MSS).collect();
        let last = chunks.len().saturating_sub(1);
        for (n, chunk) in chunks.into_iter().enumerate() {
            let flags = if n == last {
                tcp_flags::PSH | tcp_flags::ACK
            } else {
                tcp_flags::ACK
            };
            let frame = self.push(from_client, flags, chunk);
            first.get_or_insert(frame);
            if n % 2 == 1 && n != last {
                self.push(!from_client, tcp_flags::ACK, &[]);
            }
        }
        first
    }
}

fn host(net_id: u8, id: u8) -> Host {
    Host::new(net_id, id)
}

pub fn record(scenario: &Scenario) -> Recording {
    let mut rng = Rng::new(scenario.seed);
    let (cnet, cid, cport) = scenario.client;
    let (snet, sid, sport) = scenario.server;
    let mut wire = Wire {
        cap: Capture::new(DEFAULT_SNAPLEN, scenario.seed),
        client: host(cnet, cid),
        server: host(snet, sid),
        client_port: cport,
        server_port: sport,
        next: [rng.next_u32(), rng.next_u32()],
        ident: 0x1000,
    };

    // Фоновый трафик до сеанса: запись содержит не только обмен с устройством.
    wire.cap.push(net::arp_request(wire.client, wire.server.ip));
    wire.cap.idle(30_000);
    let dns = net::udp(
        wire.client.ip,
        Ipv4Addr::new(10, 0, snet, 53),
        53011,
        53,
        b"\x12\x34\x01\x00",
    );
    let frame = net::ethernet(
        host(snet, 53).mac,
        wire.client.mac,
        net::ETHERTYPE_IPV4,
        &net::ipv4(
            wire.client.ip,
            Ipv4Addr::new(10, 0, snet, 53),
            net::IP_PROTO_UDP,
            0x0777,
            Fragment::default(),
            &dns,
        ),
    );
    wire.cap.push(frame);
    wire.cap.idle(120_000);

    wire.push(true, tcp_flags::SYN, &[]);
    wire.push(false, tcp_flags::SYN | tcp_flags::ACK, &[]);
    wire.push(true, tcp_flags::ACK, &[]);

    let mut device = Device::default();
    let mut log = Vec::new();
    let mut session = 0u8;
    for step in &scenario.steps {
        wire.cap.idle(step.pause_ms * 1000);
        let requests: Vec<Message> = step
            .acts
            .iter()
            .map(|act| {
                session = session.wrapping_add(1);
                act.request(session)
            })
            .collect();
        let bytes: Vec<u8> = requests.iter().flat_map(Message::encode).collect();
        let Some(first_frame) = wire.send(true, &bytes) else {
            continue;
        };
        let started = wire
            .cap
            .frames
            .get(first_frame as usize - 1)
            .map_or(0, |f| f.ts_us)
            .saturating_sub(rng.range(40, 400));

        let replies = responses(&mut device, &requests);
        for (act, reply) in step.acts.iter().zip(&replies) {
            log.push(LogEntry {
                ts_us: started,
                action: act.name(),
                params: act.params(),
                result: act.result(reply),
            });
        }
        wire.cap.idle(rng.range(300, 1800));
        let out: Vec<u8> = replies.iter().flat_map(Message::encode).collect();
        wire.send(false, &out);
        wire.push(true, tcp_flags::ACK, &[]);
    }

    wire.cap.idle(400_000);
    wire.push(true, tcp_flags::FIN | tcp_flags::ACK, &[]);
    wire.push(false, tcp_flags::FIN | tcp_flags::ACK, &[]);
    wire.push(true, tcp_flags::ACK, &[]);

    Recording {
        capture: wire.cap,
        log,
    }
}
