//! Описание протокола из YAML: разбор, проверка и применение к небольшому потоку с дырой.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pl_interp::schema::Direction;
use pl_interp::{Interpretation, Region, RegionKind, StreamInput, StreamMeta, apply};

/// Три сообщения `[2 байта][длина u16 BE][тело]` и оборванный хвост.
const STREAM: &[u8] = &[
    0xA5, 0x01, 0x00, 0x06, b'a', b'b', b'c', b'd', b'e', b'f', 0xA5, 0x02, 0x00, 0x02, 0xFF, 0xFE,
    0xA5, 0x03, 0x00, 0x00, 0xA5, 0x01, 0xFF,
];

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(it) = Interpretation::parse(text) else {
        return;
    };
    // Каноническая форма детерминирована.
    assert_eq!(it.digest(), it.digest());
    let (head, tail) = STREAM.split_at(16);
    let input = StreamInput {
        meta: StreamMeta {
            direction: Direction::AToB,
            src_ip: "10.0.0.1".to_owned(),
            dst_ip: "10.0.0.2".to_owned(),
            src_port: 40000,
            dst_port: 5020,
            start_available: true,
        },
        length: STREAM.len() as u64 + 8,
        regions: vec![
            Region {
                start: 0,
                end: 16,
                kind: RegionKind::Data(head),
            },
            Region {
                start: 16,
                end: 24,
                kind: RegionKind::Gap,
            },
            Region {
                start: 24,
                end: 24 + tail.len() as u64,
                kind: RegionKind::Data(tail),
            },
        ],
    };
    if let Ok(result) = apply(&it, &input, &|| false) {
        for m in &result.messages {
            assert!(m.start <= m.end && m.end <= input.length);
        }
    }
});
