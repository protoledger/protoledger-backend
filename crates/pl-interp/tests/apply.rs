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
