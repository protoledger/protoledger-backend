//! Подсказки исследователю на записях стенда: границы, изменчивость, пары запрос→ответ.

use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use pl_app::OpenMode;
use pl_server::AppState;
use serde_json::{Value, json};
use tower::ServiceExt;

fn stand(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/stand")
        .join(name)
}

fn project_state(name: &str) -> AppState {
    let dir = std::env::temp_dir().join(format!("pl-analysis-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let state = AppState::new(dir);
    state
        .session
        .open(&state.jobs, "demo.protoledger", OpenMode::Create)
        .unwrap();
    state
}

async fn call(
    state: &AppState,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "localhost:8080")
        .header("x-protoledger-token", state.guard.token());
    let body = match body {
        Some(v) => {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let response = pl_server::router(state.clone())
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn wait_jobs(state: &AppState) {
    for job in state.jobs.list() {
        let mut rx = state.jobs.subscribe(&job.id).unwrap();
        while !rx.borrow_and_update().state.is_terminal() {
            rx.changed().await.unwrap();
        }
    }
}

/// Проект с записью стенда; возвращает состояние и идентификаторы потоков первого соединения.
async fn setup(name: &str) -> (AppState, String, String, String) {
    let state = project_state(name);
    let path = stand("main.pcapng").to_string_lossy().into_owned();
    call(
        &state,
        Method::POST,
        "/api/sources",
        Some(json!({ "path": path })),
    )
    .await;
    wait_jobs(&state).await;
    let (_, conns) = call(&state, Method::GET, "/api/connections", None).await;
    let c = &conns["items"][0];
    (
        state,
        c["id"].as_str().unwrap().to_owned(),
        c["streams"][0]["id"].as_str().unwrap().to_owned(),
        c["streams"][1]["id"].as_str().unwrap().to_owned(),
    )
}

#[tokio::test]
async fn framing_hints_find_the_length_field_without_any_description() {
    let (state, _, ab, ba) = setup("framing").await;
    let (status, hints) = call(
        &state,
        Method::POST,
        "/api/analysis/framing",
        Some(json!({ "streams": [ab, ba] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{hints}");
    assert_eq!(hints["incomplete"], false);
    let top = &hints["length"][0];
    assert_eq!(top["framing"]["kind"], "length_prefixed", "{hints}");
    assert_eq!(top["framing"]["length"]["type"], "u16le");
    assert_eq!(top["framing"]["length"]["at"], 4);
    assert_eq!(top["framing"]["length"]["adjust"], 7);
    assert_eq!(top["scorePermille"], 1000);
    assert_eq!(top["framing"]["status"], "hypothesis");
    // Сигнатура начала — два первых байта протокола стенда, найденные по данным.
    assert_eq!(hints["signatures"][0]["bytes"], "5ac3");

    let (status, _) = call(
        &state,
        Method::POST,
        "/api/analysis/framing",
        Some(json!({ "streams": [] })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/analysis/framing",
        Some(json!({ "streams": ["00000000:c0001:ab"] })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/analysis/framing",
        Some(json!({ "streams": ["x"], "лишнее": 1 })),
    )
    .await;
    assert!(status.is_client_error());
}

#[tokio::test]
async fn variability_uses_the_framing_from_a_hint() {
    let (state, _, ab, _) = setup("variability").await;
    let (_, hints) = call(
        &state,
        Method::POST,
        "/api/analysis/framing",
        Some(json!({ "streams": [ab.clone()] })),
    )
    .await;
    let framing = hints["length"][0]["framing"].clone();
    let (status, v) = call(
        &state,
        Method::POST,
        "/api/analysis/variability",
        Some(json!({ "streams": [ab.clone()], "framing": framing })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v["messages"].as_u64().unwrap() >= 8);
    // Две первые позиции — сигнатура, постоянная во всех сообщениях.
    assert_eq!(v["columns"][0]["constant"], 0x5a);
    assert_eq!(v["columns"][1]["constant"], 0xc3);
    assert_eq!(v["regions"][0]["kind"], "constant");
    assert_eq!(v["regions"][0]["bytes"], "5ac3");

    // Без фрейминга и без интерпретации — понятный отказ; тип без интерпретации — тоже.
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/analysis/variability",
        Some(json!({ "streams": [ab.clone()] })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/analysis/variability",
        Some(json!({ "streams": [ab], "framing": framing, "messageId": "x" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn exchanges_pair_requests_with_responses() {
    let (state, conn, ab, _) = setup("exchanges").await;
    let (_, hints) = call(
        &state,
        Method::POST,
        "/api/analysis/framing",
        Some(json!({ "streams": [ab] })),
    )
    .await;
    let framing = hints["length"][0]["framing"].clone();
    let (status, page) = call(
        &state,
        Method::POST,
        "/api/exchanges",
        Some(json!({ "connection": conn, "framing": framing, "limit": 5 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["limit"], 5);
    assert!(page["total"].as_u64().unwrap() >= 5);
    assert_eq!(page["items"].as_array().unwrap().len(), 5);
    let first = &page["items"][0];
    // Клиент шлёт запросы пачками: порядок ответов — допущение, поэтому «по порядку», а не «точно».
    assert!(
        matches!(first["certainty"].as_str(), Some("certain" | "ordered")),
        "{first}"
    );
    assert_eq!(first["requests"][0]["stream"], format!("{conn}:ab"));
    assert_eq!(first["responses"][0]["stream"], format!("{conn}:ba"));
    assert!(first["delayNs"].as_u64().unwrap() < 1_000_000_000);
    assert!(page["stats"]["certain"].as_u64().unwrap() >= 1);

    let (status, _) = call(
        &state,
        Method::POST,
        "/api/exchanges",
        Some(json!({ "connection": "ffffffff:c0001", "framing": framing })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/exchanges",
        Some(json!({ "connection": conn })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/exchanges",
        Some(json!({ "connection": conn, "framing": framing, "limit": 0 })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Проект со стендом, журналом действий и интерпретацией («ключ ответов»).
async fn with_log(name: &str) -> (AppState, String) {
    let (state, _, ab, _) = setup(name).await;
    let log = stand("main.actions.csv").to_string_lossy().into_owned();
    let mapping =
        json!({ "time": "time", "action": "action", "params": "params", "result": "result" });
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/action-logs",
        Some(json!({ "path": log, "mapping": mapping })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let yaml = std::fs::read_to_string(stand("interpretation.yaml")).unwrap();
    call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(json!({ "yaml": yaml })),
    )
    .await;
    (state, ab)
}

#[tokio::test]
async fn correlations_link_message_bytes_with_action_parameters() {
    let (state, ab) = with_log("corr").await;
    let (status, c) = call(
        &state,
        Method::POST,
        "/api/analysis/correlations",
        Some(json!({ "streams": [ab.clone()], "messageId": "set_param_req" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{c}");
    assert!(c["withAction"].as_u64().unwrap() >= 3, "{c}");
    let hint = c["values"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["param"] == "params.value")
        .unwrap_or_else(|| panic!("нет связи с params.value: {c}"));
    assert!(
        matches!(hint["type"].as_str(), Some("u32be" | "i32be")),
        "{hint}"
    );
    assert_eq!(hint["scale"], 1);
    assert_eq!(hint["sharePermille"], 1000);
    assert!(hint["firstCounterexample"].is_null());

    // Сообщению достаётся только его действие: у set_param шесть действий в журнале, и параметры
    // соседних действий (канал измерения) к нему не примешиваются.
    assert_eq!(c["withAction"], 6, "{c}");
    assert_eq!(
        hint["samples"], 6,
        "все шесть set_param связаны со своим действием: {hint}"
    );
    assert_eq!(hint["matches"], 6, "{hint}");
    assert!(
        c["values"]
            .as_array()
            .unwrap()
            .iter()
            .all(|h| h["param"] != "params.channel"),
        "{c}"
    );
    let (_, reads) = call(
        &state,
        Method::POST,
        "/api/analysis/correlations",
        Some(json!({ "streams": [ab.clone()], "messageId": "read_param_req" })),
    )
    .await;
    assert_eq!(reads["withAction"], 4, "{reads}");

    // Без фильтра по типу: байт типа сообщения — код действия.
    let (_, all) = call(
        &state,
        Method::POST,
        "/api/analysis/correlations",
        Some(json!({ "streams": [ab.clone()] })),
    )
    .await;
    assert!(!all["actions"].as_array().unwrap().is_empty(), "{all}");

    let (status, _) = call(
        &state,
        Method::POST,
        "/api/analysis/correlations",
        Some(json!({ "streams": [ab.clone()], "logId": "log-9" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/analysis/correlations",
        Some(json!({ "streams": [ab], "windowMs": 9999999 })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn correlations_need_an_action_log() {
    let (state, _, ab, _) = setup("corr-nolog").await;
    let (_, hints) = call(
        &state,
        Method::POST,
        "/api/analysis/framing",
        Some(json!({ "streams": [ab.clone()] })),
    )
    .await;
    let framing = hints["length"][0]["framing"].clone();
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/analysis/correlations",
        Some(json!({ "streams": [ab], "framing": framing })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

/// Действие, которого нет в журнале, не подменяется действием соседнего сообщения другого типа.
#[tokio::test]
async fn correlations_do_not_borrow_actions_from_other_message_types() {
    let (state, _, ab, _) = setup("corr-borrow").await;
    // Из журнала убрано первое изменение уставки; за полторы секунды до него — чтение параметра.
    let log: String = std::fs::read_to_string(stand("main.actions.csv"))
        .unwrap()
        .lines()
        .filter(|l| !l.contains("param=setpoint;value=21"))
        .map(|l| format!("{l}\n"))
        .collect();
    let dir = std::env::temp_dir().join(format!("pl-analysis-test-{}-log", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("partial.actions.csv");
    std::fs::write(&path, log).unwrap();
    let mapping =
        json!({ "time": "time", "action": "action", "params": "params", "result": "result" });
    let (status, body) = call(
        &state,
        Method::POST,
        "/api/action-logs",
        Some(json!({ "path": path.to_string_lossy(), "mapping": mapping })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let yaml = std::fs::read_to_string(stand("interpretation.yaml")).unwrap();
    call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(json!({ "yaml": yaml })),
    )
    .await;

    let (status, c) = call(
        &state,
        Method::POST,
        "/api/analysis/correlations",
        Some(json!({ "streams": [ab], "messageId": "set_param_req" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{c}");
    assert_eq!(c["samples"], 6, "{c}");
    assert_eq!(
        c["withAction"], 5,
        "шестому сообщению действие не досталось: {c}"
    );
    let value = c["values"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["param"] == "params.value")
        .unwrap_or_else(|| panic!("{c}"));
    assert_eq!(
        (value["matches"].as_u64(), value["samples"].as_u64()),
        (Some(5), Some(5))
    );
}

#[tokio::test]
async fn checksums_find_the_trailing_sum_of_the_stand_protocol() {
    let (state, _, ab, ba) = setup("checksums").await;
    let (_, hints) = call(
        &state,
        Method::POST,
        "/api/analysis/framing",
        Some(json!({ "streams": [ab.clone()] })),
    )
    .await;
    let framing = hints["length"][0]["framing"].clone();
    let (status, found) = call(
        &state,
        Method::POST,
        "/api/analysis/checksums",
        Some(json!({ "streams": [ab.clone(), ba.clone()], "framing": framing })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{found}");
    assert_eq!(found["incomplete"], false);
    assert!(found["messages"].as_u64().unwrap() >= 8);
    // Протокол стенда кончается суммой всех предыдущих байтов; движок об этом не знает.
    let top = &found["hints"][0];
    assert_eq!(top["algorithm"], "sum8", "{found}");
    assert_eq!(top["at"], "end-1");
    assert_eq!(top["type"], "u8");
    assert_eq!(top["from"], 0);
    assert_eq!(top["expr"], "checksum == sum8(0, message.len - 1)");
    assert_eq!(top["sharePermille"], 1000);
    assert!(top.get("firstCounterexample").is_none());
    assert_eq!(found["hints"].as_array().unwrap().len(), 1, "{found}");
    assert_eq!(found["checked"].as_array().unwrap().len(), 20);

    // Без фрейминга и без сохранённой интерпретации границ сообщений нет.
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/analysis/checksums",
        Some(json!({ "streams": [ab] })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/analysis/checksums",
        Some(json!({ "streams": [], "framing": framing })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/analysis/checksums",
        Some(json!({ "streams": ["00000000:c0001:ab"], "framing": framing })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn types_split_messages_by_side_and_the_type_byte() {
    let (state, _, ab, ba) = setup("types").await;
    let (_, hints) = call(
        &state,
        Method::POST,
        "/api/analysis/framing",
        Some(json!({ "streams": [ab.clone()] })),
    )
    .await;
    let framing = hints["length"][0]["framing"].clone();
    let (status, found) = call(
        &state,
        Method::POST,
        "/api/analysis/types",
        Some(json!({ "streams": [ab.clone(), ba.clone()], "framing": framing })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{found}");
    // Протокол стенда: тип — третий байт, у ответа он со старшим битом; движок об этом не знает.
    assert_eq!(found["keys"][0]["kind"], "side", "{found}");
    assert_eq!(found["keys"][1]["kind"], "byte");
    assert_eq!(found["keys"][1]["at"], 2);
    assert_eq!(
        found["fields"],
        json!([{ "name": "b2", "at": 2, "type": "u8" }])
    );
    let types = found["types"].as_array().unwrap();
    let whens: Vec<&str> = types.iter().map(|t| t["when"].as_str().unwrap()).collect();
    assert!(
        whens.contains(&"dst_port == 4710 && b2 == 0x02"),
        "{whens:?}"
    );
    assert!(
        whens.contains(&"src_port == 4710 && b2 == 0x82"),
        "{whens:?}"
    );
    let total: u64 = types.iter().map(|t| t["count"].as_u64().unwrap()).sum();
    assert_eq!(total, found["messages"].as_u64().unwrap());
    // Пример ведёт к настоящему сообщению потока.
    let example = &types[0]["example"];
    assert!(example["stream"] == json!(ab) || example["stream"] == json!(ba));
    assert!(example["end"].as_u64().unwrap() > example["start"].as_u64().unwrap());

    // Найденные условия принимаются описанием как есть.
    let messages: Vec<String> = types
        .iter()
        .map(|t| {
            format!(
                "  - id: {}\n    when: \"{}\"\n    fields:\n      - {{ name: b2, at: 2, type: u8, status: hypothesis, hypothesis: H1 }}\n",
                t["id"].as_str().unwrap(),
                t["when"].as_str().unwrap()
            )
        })
        .collect();
    let yaml = format!(
        "format: protoledger/interpretation@1\nframing: {}\nmessages:\n{}hypotheses:\n  - {{ id: H1, statement: \"b2 — тип сообщения\" }}\n",
        framing,
        messages.concat()
    );
    let (status, saved) = call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(json!({ "yaml": yaml })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{saved}");

    let (status, _) = call(
        &state,
        Method::POST,
        "/api/analysis/types",
        Some(json!({ "streams": [] })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/analysis/types",
        Some(json!({ "streams": ["00000000:c0001:ab"], "framing": framing })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn field_hints_find_the_request_counter_even_under_a_type_filter() {
    let (state, _, ab, _) = setup("fields").await;
    let (_, hints) = call(
        &state,
        Method::POST,
        "/api/analysis/framing",
        Some(json!({ "streams": [ab.clone()] })),
    )
    .await;
    let framing = hints["length"][0]["framing"].clone();
    // Сообщения одного типа: номер запроса среди них идёт с пропусками, но счётчик ищется по потоку.
    let (status, found) = call(
        &state,
        Method::POST,
        "/api/analysis/fields",
        Some(json!({ "streams": [ab.clone()], "framing": framing, "match": [{ "at": 2, "value": 2 }] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{found}");
    assert_eq!(found["incomplete"], false);
    let all = found["hints"].as_array().unwrap();
    let counter = all.iter().find(|h| h["kind"] == "counter").unwrap();
    assert_eq!(counter["at"], 3, "{found}");
    assert_eq!(counter["type"], "u8");
    assert_eq!(counter["sharePermille"], 1000);
    assert!(
        counter["summary"]
            .as_str()
            .unwrap()
            .contains("растёт на единицу")
    );
    // Отобраны только сообщения с байтом типа 02.
    let (_, everything) = call(
        &state,
        Method::POST,
        "/api/analysis/fields",
        Some(json!({ "streams": [ab.clone()], "framing": framing })),
    )
    .await;
    assert!(found["messages"].as_u64().unwrap() < everything["messages"].as_u64().unwrap());
    // Ложного «времени» на постоянных байтах заголовка нет.
    assert!(all.iter().all(|h| h["kind"] != "time"), "{found}");

    let (status, _) = call(
        &state,
        Method::POST,
        "/api/analysis/fields",
        Some(json!({ "streams": [ab.clone()], "framing": framing, "match": [{ "at": 2, "value": 256 }] })),
    )
    .await;
    assert!(status.is_client_error());
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/analysis/fields",
        Some(json!({ "streams": [ab] })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn draft_describes_the_stand_protocol_and_survives_a_run() {
    let (state, ab) = with_log("draft").await;
    let ba = ab.replace(":ab", ":ba");
    let (status, draft) = call(
        &state,
        Method::POST,
        "/api/analysis/draft",
        Some(json!({ "streams": [ab.clone(), ba] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{draft}");
    assert_eq!(draft["incomplete"], false);
    let yaml = draft["yaml"].as_str().unwrap();
    // Найдено без знаний о протоколе: границы, сигнатура, тип, счётчик, связи с журналом, сумма.
    for expected in [
        r#""length":{"at":4,"type":"u16le","adjust":7}"#,
        r#""sync":"5ac3""#,
        r#"when: "dst_port == 4710 && b2 == 0x02""#,
        "name: counter, at: 3, type: u8",
        r#"test: "value == action.params.value""#,
        "name: checksum, at: end-1, type: u8",
        r#"expr: "checksum == sum8(0, message.len - 1)""#,
    ] {
        assert!(
            yaml.contains(expected),
            "нет «{expected}» в черновике:\n{yaml}"
        );
    }
    let titles: Vec<&str> = draft["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["title"].as_str().unwrap())
        .collect();
    assert_eq!(
        titles,
        [
            "Границы сообщений",
            "Типы сообщений",
            "Счётчик",
            "Связи с журналом действий",
            "Контрольная сумма",
            "Проверка черновика"
        ]
    );
    let summary = &draft["summary"];
    assert_eq!(summary["counts"]["matched"], summary["messages"], "{draft}");
    assert_eq!(summary["types"], 6);

    // Черновик сохраняется как есть; прогон не находит ни нарушений, ни опровергнутых гипотез.
    let (status, saved) = call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(json!({ "yaml": yaml })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    let (status, _) = call(&state, Method::POST, "/api/runs", Some(json!({}))).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    wait_jobs(&state).await;
    let (_, runs) = call(&state, Method::GET, "/api/runs", None).await;
    let id = runs["items"][0]["id"].as_str().unwrap().to_owned();
    let (_, run) = call(&state, Method::GET, &format!("/api/runs/{id}"), None).await;
    assert_eq!(run["summary"]["counterexamples"], 0, "{run}");
    let hypotheses = run["hypotheses"].as_array().unwrap();
    assert!(!hypotheses.is_empty());
    for h in hypotheses {
        assert_eq!(h["verdict"], "no_counterexample", "{h}");
    }
}

#[tokio::test]
async fn draft_without_boundaries_is_refused_with_a_reason() {
    let (state, _, ab, _) = setup("draft-none").await;
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/analysis/draft",
        Some(json!({ "streams": [] })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/analysis/draft",
        Some(json!({ "streams": ["00000000:c0001:ab"] })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // Без журнала черновик тоже собирается, просто без связей с действиями.
    let (status, draft) = call(
        &state,
        Method::POST,
        "/api/analysis/draft",
        Some(json!({ "streams": [ab.clone(), ab.replace(":ab", ":ba")] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{draft}");
    assert!(!draft["yaml"].as_str().unwrap().contains("action."));
}

#[tokio::test]
async fn explain_byte_gathers_everything_known_about_it() {
    let (state, ab) = with_log("explain").await;
    let (_, sources) = call(&state, Method::GET, "/api/sources?limit=1", None).await;
    let source = sources["items"][0]["sha256"].as_str().unwrap().to_owned();
    let (status, observation) = call(
        &state,
        Method::POST,
        "/api/observations",
        Some(json!({
            "anchor": { "source": source, "stream": ab, "start": 2, "end": 4 },
            "comment": "тип и номер сеанса"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{observation}");
    let (status, hypothesis) = call(
        &state,
        Method::POST,
        "/api/hypotheses",
        Some(json!({ "statement": "байт 3 — номер сеанса", "basis": [observation["id"]] })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{hypothesis}");
    let (status, _) = call(&state, Method::POST, "/api/runs", Some(json!({}))).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    wait_jobs(&state).await;

    let (status, e) = call(
        &state,
        Method::GET,
        &format!("/api/streams/{ab}/explain?offset=3"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{e}");
    assert_eq!((&e["kind"], &e["offset"]), (&json!("data"), &json!(3)));
    assert!(e["value"].is_u64());
    // Откуда байт: первый кадр с данными потока.
    let frame = &e["frames"][0];
    assert!(frame["frame"].as_u64().unwrap() >= 1);
    assert_eq!(
        (&frame["start"], &frame["duplicate"]),
        (&json!(0), &json!(false))
    );
    assert!(frame["tsNs"].as_u64().unwrap() > 0);
    // К чему относится: первое сообщение потока и поле описания стенда.
    assert_eq!(e["message"]["start"], 0);
    assert_eq!(e["message"]["offset"], 3);
    assert!(e["message"]["messageId"].is_string(), "{e}");
    let field = &e["fields"][0];
    assert_eq!(
        (&field["start"], &field["end"]),
        (&json!(3), &json!(4)),
        "{e}"
    );
    assert!(field["value"].is_string());
    // Что о нём записал исследователь.
    assert_eq!(e["observations"][0]["id"], observation["id"]);
    assert_eq!(e["hypotheses"][0]["id"], hypothesis["id"]);
    // Где проверен.
    let run = &e["runs"][0];
    assert_eq!(run["sameInterpretation"], true, "{e}");
    assert_eq!(run["category"], "matched");
    assert_eq!(run["messageId"], e["message"]["messageId"]);

    // Байт без наблюдений: списки пусты, остальное на месте.
    let (_, other) = call(
        &state,
        Method::GET,
        &format!("/api/streams/{ab}/explain?offset=0"),
        None,
    )
    .await;
    assert_eq!(other["observations"], json!([]));
    assert_eq!(other["hypotheses"], json!([]));
    assert_eq!(other["fields"][0]["status"], "rule");

    for (path, expected) in [
        (
            format!("/api/streams/{ab}/explain?offset=99999999"),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!("/api/streams/{ab}/explain"),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!("/api/streams/{ab}/explain?offset=-1"),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/api/streams/00000000:c0001:ab/explain?offset=0".to_owned(),
            StatusCode::NOT_FOUND,
        ),
    ] {
        let (status, _) = call(&state, Method::GET, &path, None).await;
        assert_eq!(status, expected, "{path}");
    }
}
