//! Разбиение потока на сообщения и разбор полей: все виды фрейминга на произвольных байтах
//! с дырой и неоднозначным участком посреди потока.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pl_interp::schema::Direction;
use pl_interp::{Interpretation, Region, RegionKind, StreamInput, StreamMeta, apply};

const LENGTH_BE: &str = r#"format: protoledger/interpretation@1
framing: { kind: length_prefixed, length: { at: 2, type: u16be, adjust: 4 }, sync: "a5" }
messages:
  - id: m
    when: "kind < 0x80"
    fields:
      - { name: magic, at: 0, type: u8, expect: 0xA5, status: rule }
      - { name: kind, at: 1, type: u8 }
      - { name: n, at: 4, type: u8 }
      - name: items
        at: 5
        type: bytes
        repeat:
          count: "n"
          fields:
            - { name: v, at: 0, type: i16le }
      - { name: tail, at: end-1, type: u8 }
checks:
  - { id: C1, expr: "sum8(0, message.len - 1) == tail" }
"#;

const LENGTH_LE: &str = r#"format: protoledger/interpretation@1
framing: { kind: length_prefixed, length: { at: 0, type: u32le, adjust: 0 } }
messages:
  - id: m
    fields:
      - { name: len, at: 0, type: u32le }
      - { name: text, at: 4, type: string, len: to_end }
"#;

const DELIMITER: &str = r#"format: protoledger/interpretation@1
framing: { kind: delimiter, bytes: "0d0a" }
messages:
  - id: line
    fields:
      - { name: body, at: 0, type: bytes, len: to_end }
"#;

const MAGIC: &str = r#"format: protoledger/interpretation@1
framing: { kind: magic, bytes: "a55a" }
messages:
  - id: m
    fields:
      - { name: v, at: 2, type: u64be }
      - { name: w, at: end-8, type: i64le }
"#;

const FIXED: &str = r#"format: protoledger/interpretation@1
framing: { kind: fixed, size: 7 }
messages:
  - id: m
    when: "a == 0"
    fields:
      - { name: a, at: 0, type: u8 }
      - { name: rest, at: 1, type: unknown, len: 6 }
"#;

const DESCRIPTIONS: [&str; 5] = [LENGTH_BE, LENGTH_LE, DELIMITER, MAGIC, FIXED];

fuzz_target!(|data: &[u8]| {
    let Some((&choice, body)) = data.split_first() else {
        return;
    };
    let Some(text) = DESCRIPTIONS.get(usize::from(choice & 0x0F) % DESCRIPTIONS.len()) else {
        return;
    };
    let it = Interpretation::parse(text).expect("встроенное описание корректно");
    // Старшие биты первого байта задают дыру и неоднозначный участок посреди потока.
    let (head, tail) = body.split_at(body.len() / 2);
    let mut regions = vec![Region {
        start: 0,
        end: head.len() as u64,
        kind: RegionKind::Data(head),
    }];
    let mut at = head.len() as u64;
    if choice & 0x10 != 0 {
        regions.push(Region {
            start: at,
            end: at + 5,
            kind: RegionKind::Gap,
        });
        at += 5;
    }
    if choice & 0x20 != 0 && tail.len() >= 3 {
        regions.push(Region {
            start: at,
            end: at + 3,
            kind: RegionKind::Ambiguous((choice & 0x40 != 0).then_some(&tail[..3])),
        });
        at += 3;
    }
    regions.push(Region {
        start: at,
        end: at + tail.len() as u64,
        kind: RegionKind::Data(tail),
    });
    let length = at + tail.len() as u64;
    regions.retain(|r| r.end > r.start);
    let input = StreamInput {
        meta: StreamMeta {
            direction: Direction::AToB,
            src_ip: "10.0.0.1".to_owned(),
            dst_ip: "10.0.0.2".to_owned(),
            src_port: 40000,
            dst_port: 5020,
            start_available: choice & 0x80 == 0,
        },
        length,
        regions,
    };
    let result = apply(&it, &input, &|| false).expect("предел сообщений недостижим на малом входе");
    // Сообщения идут по порядку, не пересекаются и не выходят за поток.
    let mut prev = 0u64;
    for m in &result.messages {
        assert!(m.start >= prev && m.end >= m.start && m.end <= length);
        prev = m.end;
    }
});
