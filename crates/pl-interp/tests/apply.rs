//! Применение интерпретации к потокам: категории результата, поля, покрытие.

use pl_interp::schema::{Direction, Interpretation, Status};
use pl_interp::{
    Category, FieldState, MessageResult, Region, RegionKind, StreamInput, StreamMeta, StreamResult,
    Value, ViolationKind, apply,
};

/// Протокол: `a5 | тип | всего байт | данные | сумма всех предыдущих`.
const SPEC: &str = r#"
format: protoledger/interpretation@1
scope: { direction: a_to_b, filter: "dst_port == 4710" }
framing: { kind: length_prefixed, length: { at: 2, type: u8 }, status: rule }
messages:
  - id: echo
    when: "type == 1"
    fields:
      - { name: magic, at: 0, type: bytes, len: 1, expect: "a5", status: rule }
      - { name: type, at: 1, type: u8, status: rule }
      - { name: total, at: 2, type: u8, status: rule }
      - { name: text, at: 3, type: string, len: "total - 4", status: hypothesis, hypothesis: H1 }
      - { name: sum, at: end-1, type: u8, status: rule }
  - id: opaque
    when: "type == 2"
    fields:
      - { name: type, at: 1, type: u8, status: rule }
      - { name: rest, at: 3, type: unknown, len: to_end }
  - id: setpoint
    when: "type == 3"
    fields:
      - { name: type, at: 1, type: u8, status: rule }
      - { name: value, at: 3, type: i16be, status: hypothesis, hypothesis: H2, expect: 7 }
      - { name: tail, at: 5, type: u8, status: rule }
hypotheses:
  - { id: H1, statement: "text — текст" }
  - { id: H2, statement: "value — уставка" }
checks:
  - { id: C1, kind: structural, expr: "sum == sum8(0, message.len - 1)", description: "сумма не сходится", message: echo }
"#;

fn spec() -> Interpretation {
    Interpretation::parse(SPEC).unwrap()
}

fn meta() -> StreamMeta {
    StreamMeta {
        direction: Direction::AToB,
        src_ip: "10.0.0.10".to_owned(),
        dst_ip: "10.0.1.1".to_owned(),
        src_port: 49320,
        dst_port: 4710,
        start_available: true,
    }
}

fn whole(bytes: &[u8]) -> StreamInput<'_> {
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

fn msg(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut m = vec![0xa5, kind, (payload.len() + 4) as u8];
    m.extend_from_slice(payload);
    let sum = m.iter().fold(0u8, |a, b| a.wrapping_add(*b));
    m.push(sum);
    m
}

fn run(bytes: &[u8]) -> StreamResult {
    apply(&spec(), &whole(bytes), &|| false).unwrap()
}

fn first(bytes: &[u8]) -> MessageResult {
    run(bytes).messages.remove(0)
}

fn with_regions(bytes: &[u8], parts: &[(u64, u64, Option<&str>)]) -> StreamInput<'static> {
    // Участки данных копируются в утечённый срез: тесту достаточно времени жизни `'static`.
    let leaked: &'static [u8] = Box::leak(bytes.to_vec().into_boxed_slice());
    StreamInput {
        meta: meta(),
        length: bytes.len() as u64,
        regions: parts
            .iter()
            .map(|&(start, end, kind)| Region {
                start,
                end,
                kind: match kind {
                    Some("gap") => RegionKind::Gap,
                    Some("ambiguous") => RegionKind::Ambiguous(None),
                    _ => RegionKind::Data(&leaked[start as usize..end as usize]),
                },
            })
            .collect(),
    }
}

#[test]
fn matched_message_has_decoded_fields_and_coverage() {
    let r = run(&msg(1, b"hi"));
    assert_eq!(r.messages.len(), 1);
    let m = &r.messages[0];
    assert_eq!(m.category, Category::Matched, "{:?}", m.violations);
    assert_eq!(m.message_id.as_deref(), Some("echo"));
    let text = m.fields.iter().find(|f| f.name == "text").unwrap();
    assert_eq!((text.at, text.len), (3, 2));
    assert_eq!(text.value, Some(Value::Str("hi".to_owned())));
    assert_eq!(text.status, Status::Hypothesis);
    assert_eq!(m.unknown_bytes, 0, "поля покрывают сообщение целиком");
}

#[test]
fn several_messages_in_one_stream() {
    let bytes = [msg(1, b"a"), msg(1, b"bc"), msg(2, &[9, 9, 9])].concat();
    let r = run(&bytes);
    assert_eq!(r.counts().get(&Category::Matched), Some(&3));
    let opaque = &r.messages[2];
    assert_eq!(opaque.message_id.as_deref(), Some("opaque"));
    assert_eq!(opaque.unknown_bytes, 6, "всё, кроме байта типа, не описано");
    assert_eq!(r.unknown_bytes(), opaque.unknown_bytes);
}

#[test]
fn broken_check_and_expect_make_message_violated() {
    let mut bad_sum = msg(1, b"hi");
    let last = bad_sum.len() - 1;
    bad_sum[last] ^= 0xff;
    let m = first(&bad_sum);
    assert_eq!(m.category, Category::Violated);
    assert_eq!(m.violations[0].kind, ViolationKind::Check);
    assert_eq!(m.violations[0].id, "C1");
    assert_eq!(m.violations[0].detail, "сумма не сходится");

    let mut bad_magic = msg(1, b"hi");
    bad_magic[0] = 0xa6;
    let m = first(&bad_magic);
    assert_eq!(m.category, Category::Violated);
    assert!(
        m.violations
            .iter()
            .any(|v| v.kind == ViolationKind::Expect && v.id == "magic")
    );
}

#[test]
fn failed_hypothesis_expectation_does_not_break_the_rule_verdict() {
    // value ожидается 7 (гипотеза): другое значение — замечание, но не нарушение правила.
    let m = first(&msg(3, &[0, 9, 1]));
    assert_eq!(m.category, Category::Matched);
    assert_eq!(m.violations.len(), 1);
    assert_eq!(m.violations[0].status, Status::Hypothesis);
    assert!(first(&msg(3, &[0, 7, 1])).violations.is_empty());
}

#[test]
fn unknown_type_is_unmatched_not_violated() {
    let m = first(&msg(9, b"zz"));
    assert_eq!(m.category, Category::Unmatched);
    assert_eq!(m.message_id, None);
    assert_eq!(m.unknown_bytes, m.end - m.start);
}

#[test]
fn gap_makes_message_incomplete_with_partial_fields() {
    let bytes = msg(1, b"hello");
    let n = bytes.len() as u64;
    let input = with_regions(&bytes, &[(0, 5, None), (5, 7, Some("gap")), (7, n, None)]);
    let r = apply(&spec(), &input, &|| false).unwrap();
    assert_eq!(r.messages.len(), 1);
    let m = &r.messages[0];
    assert_eq!(m.category, Category::Incomplete);
    assert_eq!(
        m.message_id.as_deref(),
        Some("echo"),
        "тип известен: он до дыры"
    );
    let text = m.fields.iter().find(|f| f.name == "text").unwrap();
    assert_eq!(text.state, FieldState::Gap);
    assert_eq!(text.value, None);
    let sum = m.fields.iter().find(|f| f.name == "sum").unwrap();
    assert_eq!(
        sum.state,
        FieldState::Decoded,
        "известное за дырой разбирается"
    );
    assert!(
        m.violations.is_empty(),
        "по неполным данным нарушений не объявляем: {:?}",
        m.violations
    );
}

#[test]
fn gap_over_the_type_field_is_incomplete_not_unmatched() {
    let bytes = msg(1, b"hello");
    let n = bytes.len() as u64;
    let input = with_regions(&bytes, &[(0, 1, None), (1, 2, Some("gap")), (2, n, None)]);
    let m = apply(&spec(), &input, &|| false)
        .unwrap()
        .messages
        .remove(0);
    assert_eq!(m.category, Category::Incomplete);
    assert_eq!(m.message_id, None);
}

#[test]
fn ambiguous_region_gives_ambiguous_category() {
    let bytes = msg(1, b"hello");
    let n = bytes.len() as u64;
    let input = with_regions(
        &bytes,
        &[(0, 3, None), (3, 5, Some("ambiguous")), (5, n, None)],
    );
    let m = apply(&spec(), &input, &|| false)
        .unwrap()
        .messages
        .remove(0);
    assert_eq!(m.category, Category::Ambiguous);
    assert!(m.fields.iter().any(|f| f.state == FieldState::Ambiguous));
}

#[test]
fn truncated_tail_is_incomplete() {
    let mut bytes = msg(1, b"hello");
    bytes.truncate(6);
    assert_eq!(first(&bytes).category, Category::Incomplete);
}

#[test]
fn framing_failures_are_reported_with_the_right_category() {
    // Длина 0 — невозможна: правило фрейминга нарушено, дальше поток не режем.
    let m = first(&[0xa5, 1, 0, 0, 0]);
    assert_eq!(m.category, Category::Violated);
    assert_eq!(m.violations[0].kind, ViolationKind::Framing);

    let huge = Interpretation::parse(
        "format: protoledger/interpretation@1\nframing: { kind: length_prefixed, length: { at: 0, type: u32be } }\n",
    )
    .unwrap();
    let m = apply(&huge, &whole(&[0x7f, 0xff, 0xff, 0xff, 0]), &|| false)
        .unwrap()
        .messages
        .remove(0);
    assert_eq!(m.category, Category::LimitExceeded);
}

#[test]
fn scope_limits_what_is_applied() {
    let bytes = msg(1, b"hi");
    let mut input = whole(&bytes);
    input.meta.dst_port = 80;
    assert!(apply(&spec(), &input, &|| false).unwrap().out_of_scope);
    let mut input = whole(&bytes);
    input.meta.direction = Direction::BToA;
    assert!(apply(&spec(), &input, &|| false).unwrap().out_of_scope);
    assert!(
        !apply(&spec(), &whole(&bytes), &|| false)
            .unwrap()
            .out_of_scope
    );
}

#[test]
fn field_beyond_message_is_a_rule_violation() {
    // Сообщение типа 3 короче описания: поле tail за границей.
    let m = first(&[0xa5, 3, 5, 0, 7]);
    assert_eq!(m.category, Category::Violated);
    assert!(
        m.violations
            .iter()
            .any(|v| v.kind == ViolationKind::FieldRange)
    );
}

#[test]
fn evaluation_errors_do_not_panic() {
    let weird = Interpretation::parse(
        "format: protoledger/interpretation@1\nframing: { kind: fixed, size: 4 }\nmessages:\n  - id: m\n    fields:\n      - { name: a, at: 0, type: u8, status: rule }\nchecks:\n  - { id: C, expr: \"a / 0 == 1\" }\n",
    )
    .unwrap();
    let m = apply(&weird, &whole(&[1, 2, 3, 4]), &|| false)
        .unwrap()
        .messages
        .remove(0);
    assert_eq!(m.category, Category::Violated);
    assert!(m.violations[0].detail.contains("деление на ноль"));
}

#[test]
fn hostile_streams_never_panic() {
    // Случайные байты под правилами: разбор завершается, категории осмысленные.
    let mut state = 12345u64;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as u8
    };
    for _ in 0..300 {
        let len = (next() as usize) % 200;
        let bytes: Vec<u8> = (0..len).map(|_| next()).collect();
        let r = apply(&spec(), &whole(&bytes), &|| false).unwrap();
        for m in &r.messages {
            assert!(m.start <= m.end && m.end <= bytes.len() as u64);
        }
    }
}

/// Протокол с сигнатурой и группой: `a6 5c | длина тела u8 | число n | n × (время u16, флаг u8)`.
const GROUPS: &str = r#"
format: protoledger/interpretation@1
framing: { kind: length_prefixed, length: { at: 2, type: u8, adjust: 3 }, sync: "a65c", status: rule }
messages:
  - id: batch
    fields:
      - { name: sig, at: 0, type: bytes, len: 2, expect: "a65c", status: rule }
      - { name: body, at: 2, type: u8, status: rule }
      - { name: n, at: 3, type: u8, status: rule }
      - name: items
        at: 4
        type: bytes
        status: rule
        repeat:
          count: "n"
          fields:
            - { name: time, at: 0, type: u16be, status: rule }
            - { name: flag, at: 2, type: u8, status: hypothesis, hypothesis: H1 }
hypotheses:
  - { id: H1, statement: "flag — признак" }
checks:
  - { id: C1, expr: "body == n * 3 + 1", description: "длина тела не сходится с числом элементов" }
  - { id: C2, expr: "items.0.time < 1000", description: "первое время слишком велико" }
"#;

fn batch(items: &[(u16, u8)]) -> Vec<u8> {
    let mut m = vec![0xa6, 0x5c, (items.len() * 3 + 1) as u8, items.len() as u8];
    for (t, f) in items {
        m.extend_from_slice(&t.to_be_bytes());
        m.push(*f);
    }
    m
}

fn groups() -> Interpretation {
    Interpretation::parse(GROUPS).unwrap()
}

#[test]
fn repeat_group_decodes_every_item_by_name() {
    let bytes = batch(&[(100, 1), (200, 0), (300, 1)]);
    let r = apply(&groups(), &whole(&bytes), &|| false).unwrap();
    let m = &r.messages[0];
    assert_eq!(m.category, Category::Matched, "{:?}", m.violations);
    assert_eq!(m.unknown_bytes, 0);
    let value = |name: &str| {
        m.fields
            .iter()
            .find(|f| f.name == name)
            .and_then(|f| f.value.clone())
    };
    assert_eq!(value("items.0.time"), Some(Value::Int(100)));
    assert_eq!(value("items.2.time"), Some(Value::Int(300)));
    assert_eq!(value("items.1.flag"), Some(Value::Int(0)));
    let group = m.fields.iter().find(|f| f.name == "items").unwrap();
    assert_eq!(
        (group.at, group.len, group.state),
        (4, 9, FieldState::Decoded)
    );
    let flag = m.fields.iter().find(|f| f.name == "items.1.flag").unwrap();
    assert_eq!((flag.at, flag.status), (4 + 3 + 2, Status::Hypothesis));
}

#[test]
fn repeat_group_beyond_the_message_is_a_violation() {
    // Число элементов 5, а в теле только 2.
    let mut bytes = batch(&[(1, 1), (2, 2)]);
    bytes[3] = 5;
    let r = apply(&groups(), &whole(&bytes), &|| false).unwrap();
    let m = &r.messages[0];
    assert_eq!(m.category, Category::Violated);
    assert!(
        m.violations
            .iter()
            .any(|v| v.kind == ViolationKind::FieldRange && v.id == "items")
    );
}

#[test]
fn sync_skips_the_tail_of_a_message_whose_start_was_not_captured() {
    let mut bytes = batch(&[(7, 1), (8, 0)]).split_off(3);
    let second = batch(&[(9, 1)]);
    bytes.extend_from_slice(&second);
    let mut input = whole(&bytes);
    input.meta.start_available = false;
    let r = apply(&groups(), &input, &|| false).unwrap();
    let cats: Vec<_> = r.messages.iter().map(|m| (m.start, m.category)).collect();
    // Хвост без начала — неполное сообщение, дальше разбор идёт по сигнатуре.
    assert_eq!(
        cats,
        vec![
            (0, Category::Incomplete),
            (bytes.len() as u64 - second.len() as u64, Category::Matched)
        ]
    );
}

#[test]
fn sync_continues_after_a_gap_over_the_length_field() {
    let a = batch(&[(1, 1)]);
    let b = batch(&[(2, 0), (3, 1)]);
    let c = batch(&[(4, 1)]);
    let bytes = [a.clone(), b.clone(), c.clone()].concat();
    let (b0, c0) = (a.len() as u64, (a.len() + b.len()) as u64);
    // Дыра закрывает сигнатуру и длину второго сообщения.
    let input = with_regions(
        &bytes,
        &[
            (0, b0, None),
            (b0, b0 + 3, Some("gap")),
            (b0 + 3, bytes.len() as u64, None),
        ],
    );
    let r = apply(&groups(), &input, &|| false).unwrap();
    let cats: Vec<_> = r.messages.iter().map(|m| (m.start, m.category)).collect();
    assert_eq!(
        cats,
        vec![
            (0, Category::Matched),
            (b0, Category::Incomplete),
            (c0, Category::Matched)
        ]
    );
}

#[test]
fn repeat_and_sync_are_validated() {
    let bad = [
        // repeat только у bytes
        GROUPS.replace(
            "        type: bytes\n        status: rule\n        repeat:",
            "        type: u8\n        status: rule\n        repeat:",
        ),
        // у элемента нужен постоянный размер
        GROUPS.replace(
            "{ name: flag, at: 2, type: u8,",
            "{ name: flag, at: 2, type: string, len: \"n\",",
        ),
        // число повторений — по ранее объявленным полям
        GROUPS.replace("count: \"n\"", "count: \"later\""),
        // сигнатура — hex
        GROUPS.replace("sync: \"a65c\"", "sync: \"zz\""),
    ];
    for (i, text) in bad.iter().enumerate() {
        assert!(
            Interpretation::parse(text).is_err(),
            "случай {i} должен быть отклонён"
        );
    }
}

/// Запрос и ответ с одинаковыми байтами: тип сообщения решает сторона, а не содержимое.
const BY_PORT: &str = r#"
format: protoledger/interpretation@1
framing: { kind: length_prefixed, length: { at: 0, type: u8 }, status: rule }
messages:
  - id: request
    when: "dst_port == 4710 && code == 3"
    fields:
      - { name: code, at: 1, type: u8, status: rule }
  - id: response
    when: "src_port == 4710 && code == 3"
    fields:
      - { name: code, at: 1, type: u8, status: rule }
"#;

#[test]
fn when_sees_stream_ports_and_addresses() {
    let it = Interpretation::parse(BY_PORT).unwrap();
    let bytes = [2u8, 3];
    let to_device = apply(&it, &whole(&bytes), &|| false).unwrap();
    assert_eq!(to_device.messages[0].message_id.as_deref(), Some("request"));

    let mut back = whole(&bytes);
    back.meta.src_port = 4710;
    back.meta.dst_port = 49320;
    let from_device = apply(&it, &back, &|| false).unwrap();
    assert_eq!(
        from_device.messages[0].message_id.as_deref(),
        Some("response")
    );

    let by_ip = BY_PORT.replace(
        r#""dst_port == 4710 && code == 3""#,
        r#"'dst_ip == "10.0.1.1" && code == 3'"#,
    );
    let it = Interpretation::parse(&by_ip).unwrap();
    let found = apply(&it, &whole(&bytes), &|| false).unwrap();
    assert_eq!(found.messages[0].message_id.as_deref(), Some("request"));
}

#[test]
fn field_named_like_a_stream_name_wins_in_when() {
    let spec = r#"
format: protoledger/interpretation@1
framing: { kind: length_prefixed, length: { at: 0, type: u8 }, status: rule }
messages:
  - id: own
    when: "dst_port == 3"
    fields:
      - { name: dst_port, at: 1, type: u8, status: rule }
"#;
    let it = Interpretation::parse(spec).unwrap();
    let found = apply(&it, &whole(&[2u8, 3]), &|| false).unwrap();
    assert_eq!(found.messages[0].message_id.as_deref(), Some("own"));
    assert_eq!(found.messages[0].category, Category::Matched);
}

#[test]
fn unknown_name_in_when_is_still_rejected() {
    let bad = BY_PORT.replace("dst_port == 4710", "port == 4710");
    assert!(Interpretation::parse(&bad).is_err());
}

/// Сообщение `длина | данные | CRC-16/MODBUS младшим байтом вперёд` — как в кадрах Modbus RTU.
const WITH_CRC: &str = r#"
format: protoledger/interpretation@1
framing: { kind: length_prefixed, length: { at: 0, type: u8 }, status: rule }
messages:
  - id: frame
    fields:
      - { name: total, at: 0, type: u8, status: rule }
      - { name: crc, at: end-2, type: u16le, status: rule }
checks:
  - { id: C1, kind: structural, expr: "crc == crc16_modbus(0, message.len - 2)", description: "CRC не сходится" }
"#;

#[test]
fn crc_check_passes_on_intact_bytes_and_catches_a_flipped_bit() {
    let it = Interpretation::parse(WITH_CRC).unwrap();
    let mut bytes = vec![7u8, 0x01, 0x03, 0x00, 0x2a];
    let crc = pl_interp::Algorithm::by_name("crc16_modbus")
        .unwrap()
        .compute(&bytes) as u16;
    bytes.extend_from_slice(&crc.to_le_bytes());

    let ok = apply(&it, &whole(&bytes), &|| false).unwrap();
    assert_eq!(ok.messages[0].category, Category::Matched);

    bytes[3] ^= 0x10;
    let broken = apply(&it, &whole(&bytes), &|| false).unwrap();
    assert_eq!(broken.messages[0].category, Category::Violated);
    assert_eq!(broken.messages[0].violations[0].kind, ViolationKind::Check);
}

#[test]
fn checksum_range_outside_the_message_is_an_error_not_a_panic() {
    let spec = WITH_CRC.replace("message.len - 2", "message.len + 1");
    let it = Interpretation::parse(&spec).unwrap();
    let bytes = [5u8, 1, 2, 3, 4];
    let out = apply(&it, &whole(&bytes), &|| false).unwrap();
    assert_eq!(out.messages[0].category, Category::Violated);
    assert!(
        out.messages[0].violations[0]
            .detail
            .contains("не вычислилась")
    );
}

/// Сообщение `длина | флаги | f32be | f32le | f64be | BCD ×2`.
const ENCODINGS: &str = r#"
format: protoledger/interpretation@1
framing: { kind: length_prefixed, length: { at: 0, type: u8 }, status: rule }
messages:
  - id: reading
    when: "mode == 5"
    fields:
      - { name: total, at: 0, type: u8, status: rule }
      - { name: alarm, at: 1, type: u8, mask: 0x01, status: rule }
      - { name: mode, at: 1, type: u8, mask: 0x38, status: rule }
      - { name: temperature, at: 2, type: f32be, status: rule }
      - { name: threshold, at: 6, type: f32le, status: rule }
      - { name: ratio, at: 10, type: f64be, status: rule }
      - { name: serial, at: 18, type: bcd, len: 2, status: rule, expect: 1234 }
checks:
  - { id: C1, kind: structural, expr: "dec(temperature, 1) == 215 && dec(threshold, 1) == 0 - 25" }
  - { id: C2, kind: structural, expr: "ratio == \"0.1\" && serial + alarm == 1235" }
"#;

fn reading() -> Vec<u8> {
    let mut m = vec![20u8, 0b1010_1101];
    m.extend_from_slice(&21.5f32.to_be_bytes());
    m.extend_from_slice(&(-2.5f32).to_le_bytes());
    m.extend_from_slice(&0.1f64.to_be_bytes());
    m.extend_from_slice(&[0x12, 0x34]);
    m
}

#[test]
fn floats_bcd_and_bit_fields_are_decoded() {
    let it = Interpretation::parse(ENCODINGS).unwrap();
    let out = apply(&it, &whole(&reading()), &|| false).unwrap();
    let m = &out.messages[0];
    assert_eq!(m.category, Category::Matched, "{:?}", m.violations);
    let value = |name: &str| {
        m.fields
            .iter()
            .find(|f| f.name == name)
            .and_then(|f| f.value.clone())
    };
    // Битовые поля одного байта: младший бит и три бита со сдвигом.
    assert_eq!(value("alarm"), Some(Value::Int(1)));
    assert_eq!(value("mode"), Some(Value::Int(5)));
    // Кратчайшая десятичная запись, а не «21.299999237».
    assert_eq!(value("temperature"), Some(Value::Str("21.5".to_owned())));
    assert_eq!(value("threshold"), Some(Value::Str("-2.5".to_owned())));
    assert_eq!(value("ratio"), Some(Value::Str("0.1".to_owned())));
    assert_eq!(value("serial"), Some(Value::Int(1234)));
    // Два битовых поля одного байта не считают его дважды.
    assert_eq!(m.unknown_bytes, 0);
}

#[test]
fn a_float_that_is_not_exact_in_binary_still_reads_as_written() {
    let spec = ENCODINGS.replace("dec(temperature, 1) == 215", "dec(temperature, 1) == 213");
    let it = Interpretation::parse(&spec).unwrap();
    let mut bytes = reading();
    bytes[2..6].copy_from_slice(&21.3f32.to_be_bytes());
    let out = apply(&it, &whole(&bytes), &|| false).unwrap();
    assert_eq!(out.messages[0].category, Category::Matched);
}

#[test]
fn broken_bcd_and_not_a_number_do_not_panic_or_pass() {
    let it = Interpretation::parse(ENCODINGS).unwrap();
    let mut bytes = reading();
    bytes[18] = 0x1f;
    bytes[2..6].copy_from_slice(&f32::NAN.to_be_bytes());
    let out = apply(&it, &whole(&bytes), &|| false).unwrap();
    let m = &out.messages[0];
    let serial = m.fields.iter().find(|f| f.name == "serial").unwrap();
    assert_eq!(serial.value, None);
    // «NaN» — не десятичная запись: проверка не вычисляется, а не проходит молча.
    assert_eq!(m.category, Category::Violated);
}

#[test]
fn new_field_types_are_validated() {
    let bad = [
        ("type: bcd, len: 2", "type: bcd"),
        ("type: bcd, len: 2", "type: bcd, len: 9"),
        ("type: f32be, status", "type: f32be, len: 4, status"),
        ("mask: 0x38", "mask: 0"),
        ("mask: 0x38", "mask: 0x100"),
        ("type: f32le, status", "type: f32le, mask: 1, status"),
        ("expect: 1234", "expect: \"12\""),
    ];
    for (from, to) in bad {
        assert!(ENCODINGS.contains(from), "{from}");
        assert!(
            Interpretation::parse(&ENCODINGS.replace(from, to)).is_err(),
            "принято: {to}"
        );
    }
}

/// Пакет в духе MQTT: `тип и флаги | оставшаяся длина varint | длина темы u16 | тема | номер
/// пакета varint | данные до конца`. Места полей после темы зависят от её длины.
const VARINT: &str = r#"
format: protoledger/interpretation@1
framing: { kind: length_prefixed, length: { at: 1, type: varint }, status: rule }
messages:
  - id: publish
    when: "kind == 3"
    fields:
      - { name: kind, at: 0, type: u8, mask: 0xf0, status: rule }
      - { name: remaining, at: 1, type: varint, status: rule }
      - { name: topic_len, at: next, type: u16be, status: rule }
      - { name: topic, at: next, type: string, len: "topic_len", status: rule }
      - { name: packet_id, at: next, type: varint, status: rule }
      - { name: payload, at: next, type: bytes, len: to_end, status: rule }
checks:
  - { id: C1, kind: structural, expr: "remaining + 2 == message.len || remaining + 3 == message.len" }
"#;

fn varint(mut value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn publish(topic: &str, packet_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut body = (topic.len() as u16).to_be_bytes().to_vec();
    body.extend_from_slice(topic.as_bytes());
    body.extend(varint(packet_id));
    body.extend_from_slice(payload);
    let mut m = vec![0x30];
    m.extend(varint(body.len() as u32));
    m.extend(body);
    m
}

#[test]
fn varint_length_frames_messages_and_next_places_fields_after_variable_ones() {
    let it = Interpretation::parse(VARINT).unwrap();
    // Второе сообщение длиннее 127 байт: поле длины занимает два байта, номер пакета — тоже два.
    let long = vec![0x55u8; 200];
    let mut bytes = publish("a/b", 5, b"on");
    bytes.extend(publish("plant/line-2/temperature", 300, &long));
    bytes.extend(publish("x", 0, b""));
    let out = apply(&it, &whole(&bytes), &|| false).unwrap();
    assert_eq!(out.messages.len(), 3);
    for m in &out.messages {
        assert_eq!(m.category, Category::Matched, "{:?}", m.violations);
        assert_eq!(m.unknown_bytes, 0);
    }
    let value = |i: usize, name: &str| {
        out.messages[i]
            .fields
            .iter()
            .find(|f| f.name == name)
            .and_then(|f| f.value.clone())
    };
    assert_eq!(value(0, "topic"), Some(Value::Str("a/b".to_owned())));
    assert_eq!(value(0, "packet_id"), Some(Value::Int(5)));
    assert_eq!(value(0, "payload"), Some(Value::Bytes(b"on".to_vec())));
    assert_eq!(value(1, "remaining"), Some(Value::Int(228)));
    assert_eq!(
        value(1, "topic"),
        Some(Value::Str("plant/line-2/temperature".to_owned()))
    );
    assert_eq!(value(1, "packet_id"), Some(Value::Int(300)));
    assert_eq!(value(1, "payload"), Some(Value::Bytes(long.clone())));
    assert_eq!(value(2, "payload"), Some(Value::Bytes(Vec::new())));
    // Поля второго сообщения сдвинуты на байт: длина заняла два.
    let topic = out.messages[1]
        .fields
        .iter()
        .find(|f| f.name == "topic")
        .unwrap();
    assert_eq!(topic.at - out.messages[1].start, 5);
}

#[test]
fn broken_varints_are_reported_not_trusted() {
    let it = Interpretation::parse(VARINT).unwrap();
    // Поле длины без завершающего байта: границу сообщения определить нельзя.
    let endless = [
        0x30u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
    ];
    let out = apply(&it, &whole(&endless), &|| false).unwrap();
    assert!(out.messages.iter().all(|m| m.category != Category::Matched));

    // Тема заявлена длиннее сообщения: поля после неё места не получают, и это видно.
    let mut bytes = publish("a/b", 5, b"on");
    bytes[3] = 0x40;
    let out = apply(&it, &whole(&bytes), &|| false).unwrap();
    let m = &out.messages[0];
    assert_eq!(m.category, Category::Violated);
    assert!(
        m.violations.iter().any(|v| v.id == "packet_id"),
        "{:?}",
        m.violations
    );

    // Сообщение оборвано посреди поля длины.
    let out = apply(&it, &whole(&[0x30, 0x80]), &|| false).unwrap();
    assert_eq!(out.messages[0].category, Category::Incomplete);
}

#[test]
fn next_and_varint_are_validated() {
    assert!(
        Interpretation::parse(&VARINT.replace("at: next, type: u16be", "at: nxt, type: u16be"))
            .is_err()
    );
    assert!(
        Interpretation::parse(&VARINT.replace(
            "at: 1, type: varint, status",
            "at: 1, type: varint, len: 2, status"
        ))
        .is_err()
    );
    // Поле с местом «next» не годится для условия: его место заранее неизвестно.
    assert!(Interpretation::parse(&VARINT.replace("kind == 3", "topic_len == 3")).is_err());
}
