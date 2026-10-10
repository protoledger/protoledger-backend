//! Интерпретация стенда («ключ ответов») применяется к его записям: сообщения выделяются
//! и разбираются, типы и значения совпадают с журналом действий.

use std::path::PathBuf;

use pl_app::stream_input;
use pl_capture::{Limits, index};
use pl_interp::{Category, Interpretation, StreamResult, Value, apply};
use pl_reassembly::{Policy, reassemble};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/stand")
}

fn interpretation() -> Interpretation {
    let text = std::fs::read_to_string(fixtures().join("interpretation.yaml")).unwrap();
    Interpretation::parse(&text).unwrap_or_else(|e| panic!("interpretation.yaml: {e}"))
}

/// Результаты для направлений единственного соединения: `[клиент → устройство, устройство → клиент]`.
fn apply_to(name: &str) -> [StreamResult; 2] {
    let file = std::fs::read(fixtures().join(name)).unwrap();
    let idx = index(&file, Limits::default(), &|| false, &mut |_| {}).unwrap();
    let conns = reassemble(&idx, &file, Policy::default(), &|| false).unwrap();
    assert_eq!(conns.len(), 1);
    let it = interpretation();
    [0, 1].map(|i| {
        let input = stream_input(&file, &conns[0], &conns[0].streams[i], i);
        apply(&it, &input, &|| false).unwrap()
    })
}

fn ids(r: &StreamResult) -> Vec<&str> {
    r.messages
        .iter()
        .map(|m| m.message_id.as_deref().unwrap_or("?"))
        .collect()
}

fn field_values(r: &StreamResult, message: &str, field: &str) -> Vec<i128> {
    r.messages
        .iter()
        .filter(|m| m.message_id.as_deref() == Some(message))
        .filter_map(|m| m.fields.iter().find(|f| f.name == field))
        .filter_map(|f| match f.value {
            Some(Value::Int(v)) => Some(v),
            _ => None,
        })
        .collect()
}

#[test]
fn main_recording_is_fully_described() {
    let [requests, replies] = apply_to("main.pcapng");
    for r in [&requests, &replies] {
        assert!(!r.out_of_scope);
        assert_eq!(
            r.counts().get(&Category::Matched),
            Some(&(r.messages.len() as u64)),
            "{:?}",
            r.counts()
        );
        assert_eq!(r.unknown_bytes(), 0, "поля покрывают сообщения целиком");
    }
    assert_eq!(requests.messages.len(), 16);
    assert_eq!(replies.messages.len(), 16);
    assert_eq!(
        ids(&requests)
            .iter()
            .filter(|i| **i == "set_param_req")
            .count(),
        6
    );
    assert_eq!(
        field_values(&requests, "set_param_req", "value"),
        [21, 37, 1000, 300, 5, 2]
    );
    assert_eq!(
        field_values(&replies, "set_param_resp", "result"),
        [0, 0, 0, 1, 0, 0]
    );

    // Ответ канала 3 — одно сообщение около 60 КиБ на десятки сегментов.
    let big = replies
        .messages
        .iter()
        .map(|m| m.end - m.start)
        .max()
        .unwrap();
    assert!(big > 59_000, "{big}");
    let samples = replies
        .messages
        .iter()
        .flat_map(|m| &m.fields)
        .find(|f| f.name == "samples" && f.len == 60_000);
    assert!(samples.is_some());
}

#[test]
fn extra_recording_shows_values_above_u16() {
    let [requests, _] = apply_to("extra.pcapng");
    let values = field_values(&requests, "set_param_req", "value");
    assert_eq!(values, [70_000, -5, 123_456, 1]);
    assert!(
        values.iter().any(|v| *v > i128::from(u16::MAX)),
        "значение больше 65535 помещается только в 32 бита"
    );
}

#[test]
fn replies_follow_requests_in_order() {
    let [requests, replies] = apply_to("main.pcapng");
    let expected = |id: &str| match id {
        "read_param_req" => "read_param_resp",
        "set_param_req" => "set_param_resp",
        "measure_req" => "measure_resp",
        other => panic!("{other}"),
    };
    let want: Vec<&str> = ids(&requests).into_iter().map(expected).collect();
    assert_eq!(ids(&replies), want);
}

#[test]
fn narrowing_the_scope_leaves_other_traffic_alone() {
    let file = std::fs::read(fixtures().join("main.pcapng")).unwrap();
    let idx = index(&file, Limits::default(), &|| false, &mut |_| {}).unwrap();
    let conns = reassemble(&idx, &file, Policy::default(), &|| false).unwrap();
    let narrow = interpretation_with_filter("dst_port == 80");
    let input = stream_input(&file, &conns[0], &conns[0].streams[0], 0);
    assert!(apply(&narrow, &input, &|| false).unwrap().out_of_scope);
}

fn interpretation_with_filter(filter: &str) -> Interpretation {
    let text = std::fs::read_to_string(fixtures().join("interpretation.yaml")).unwrap();
    let replaced = text.replace("dst_port == 4710 || src_port == 4710", filter);
    Interpretation::parse(&replaced).unwrap()
}
