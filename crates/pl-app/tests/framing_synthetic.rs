//! Поиск границ на синтетических записях: кандидат поля длины находит истинные границы из эталона
//! `fixtures/synthetic/*.expected.json` (формат сообщений `[A5][тип][длина u16 BE][тело]`).

use std::path::PathBuf;

use pl_app::{SourceData, SourceStore, analyze_with, framing_hints, stream_input};
use pl_interp::Interpretation;
use pl_interp::schema::Framing;
use pl_reassembly::Policy;
use serde_json::Value;

fn synthetic() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/synthetic")
}

fn load(name: &str) -> (SourceStore, SourceData, Value) {
    let file = std::fs::read(synthetic().join(format!("{name}.pcapng"))).unwrap();
    let data = analyze_with(
        file,
        format!("{name}.pcapng"),
        "imp-0001".to_owned(),
        Policy::default(),
        &|| false,
        &mut |_, _, _, _| {},
    )
    .unwrap();
    let expected: Value = serde_json::from_str(
        &std::fs::read_to_string(synthetic().join(format!("{name}.expected.json"))).unwrap(),
    )
    .unwrap();
    let store = SourceStore::default();
    store.insert(
        analyze_with(
            std::fs::read(synthetic().join(format!("{name}.pcapng"))).unwrap(),
            format!("{name}.pcapng"),
            "imp-0001".to_owned(),
            Policy::default(),
            &|| false,
            &mut |_, _, _, _| {},
        )
        .unwrap(),
    );
    (store, data, expected)
}

/// Идентификаторы направленных потоков без дыр и неоднозначностей и их истинные сообщения.
/// Поток: идентификатор, номер соединения, направление и истинные сообщения `(смещение, длина)`.
type Truth = (String, usize, usize, Vec<(u64, u64)>);

fn clean_streams(data: &SourceData, expected: &Value) -> Vec<Truth> {
    let mut out = Vec::new();
    for (ci, connection) in data.connections.iter().enumerate() {
        let truth = &expected["connections"][ci];
        for (si, key) in ["clientToServer", "serverToClient"].iter().enumerate() {
            let side = &truth[*key];
            let clean = side["gaps"].as_array().is_some_and(Vec::is_empty)
                && side["ambiguous"].as_array().is_some_and(Vec::is_empty);
            let messages: Vec<(u64, u64)> = side["messages"]
                .as_array()
                .map(|m| {
                    m.iter()
                        .map(|x| (x["offset"].as_u64().unwrap(), x["length"].as_u64().unwrap()))
                        .collect()
                })
                .unwrap_or_default();
            // Направления в соединении — a→b и b→a; клиент — `a`, если виден SYN.
            let index = if connection.roles_known {
                si
            } else {
                usize::MAX
            };
            if clean && !messages.is_empty() && index < 2 {
                let id = format!("{}:{}", connection.id(&data.sha256), ["ab", "ba"][index]);
                out.push((id, ci, index, messages));
            }
        }
    }
    out
}

fn boundaries(data: &SourceData, ci: usize, si: usize, framing: &Framing) -> Vec<(u64, u64)> {
    let connection = &data.connections[ci];
    let input = stream_input(&data.file, connection, &connection.streams[si], si);
    pl_interp::framing::frame(framing, &input, &|| false)
        .unwrap()
        .into_iter()
        .filter(|f| f.problem.is_none())
        .map(|f| (f.start, f.end - f.start))
        .collect()
}

/// Поле длины протокола — u16 BE на смещении 2; его младший байт (смещение 3) даёт те же границы.
fn is_length_field(h: &pl_analysis::LengthHint) -> bool {
    (h.at, h.width, h.big_endian) == (2, 2, true)
        || (h.at, h.width) == (3, 1)
        || h.equivalent.iter().any(|f| f.at == 2 && f.ty == "u16be")
}

fn check(name: &str, must_find: bool) {
    let (store, data, expected) = load(name);
    let streams = clean_streams(&data, &expected);
    assert!(!streams.is_empty(), "{name}: нет чистых потоков");
    let ids: Vec<String> = streams.iter().map(|s| s.0.clone()).collect();
    let hints = framing_hints(&store, &ids, &|| false).unwrap();
    let Some(top) = hints.length.first() else {
        assert!(!must_find, "{name}: поле длины не найдено");
        return;
    };
    assert!(is_length_field(top), "{name}: {top:?}");
    assert_eq!(top.score_permille, 1000, "{name}");
    // Границы по найденному кандидату совпадают с истиной на каждом потоке.
    let framing: Framing =
        serde_json::from_value(serde_json::to_value(&top.framing).unwrap()).unwrap();
    // Проверка, что описание принимается интерпретацией как есть.
    let doc = serde_json::json!({"format": "protoledger/interpretation@1", "framing": framing, "messages": []});
    Interpretation::parse(&doc.to_string()).unwrap();
    for (id, ci, si, truth) in &streams {
        assert_eq!(
            &boundaries(&data, *ci, *si, &framing),
            truth,
            "{name}: {id}"
        );
    }
}

#[test]
fn length_field_is_found_where_there_are_enough_messages() {
    // В синтетических записях сообщений мало: порог подтверждений (8) достигнут только в этих двух.
    check("normal", true);
    check("port-reuse", true);
}

#[test]
fn a_hint_is_never_shown_below_the_confirmation_threshold() {
    for name in ["reorder", "duplicates", "no-handshake", "bad-checksum"] {
        let (store, data, _) = load(name);
        let ids: Vec<String> = data
            .connections
            .iter()
            .flat_map(|c| ["ab", "ba"].map(|d| format!("{}:{d}", c.id(&data.sha256))))
            .collect();
        let hints = framing_hints(&store, &ids, &|| false).unwrap();
        assert!(
            hints.length.is_empty(),
            "{name}: {:?}",
            hints.length.first()
        );
        assert_eq!(hints.min_messages, 8);
    }
}

#[test]
fn defects_do_not_produce_wrong_boundaries() {
    // Сценарии с дырами и перекрытиями: если подсказка показана, это поле длины протокола, а не случайное.
    for name in ["mixed", "overlap-conflict", "gap-truncation"] {
        let (store, data, _) = load(name);
        let all: Vec<String> = data
            .connections
            .iter()
            .flat_map(|c| ["ab", "ba"].map(|d| format!("{}:{d}", c.id(&data.sha256))))
            .collect();
        let hints = framing_hints(&store, &all, &|| false).unwrap();
        if let Some(top) = hints.length.first() {
            assert!(is_length_field(top), "{name}: {top:?}");
            // Дыра — контрпример, а не «данные»: доля покрытия ниже полной или контрпример назван.
            assert!(
                top.score_permille == 1000 || top.first_counterexample.is_some(),
                "{name}"
            );
        }
    }
}
