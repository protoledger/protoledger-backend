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
/// Описания ещё нет, типы сообщений не названы: связи одного действия отбираются по его имени,
/// и поля других действий в ответ не попадают.
#[tokio::test]
async fn correlations_can_be_limited_to_one_action() {
    let (state, ab) = with_log("corr-action").await;
    let ask = |body: Value| {
        let state = state.clone();
        async move {
            call(
                &state,
                Method::POST,
                "/api/analysis/correlations",
                Some(body),
            )
            .await
        }
    };
    let (status, all) = ask(json!({ "streams": [ab.clone()] })).await;
    assert_eq!(status, StatusCode::OK, "{all}");
    let (status, one) = ask(json!({ "streams": [ab.clone()], "action": "set_param" })).await;
    assert_eq!(status, StatusCode::OK, "{one}");

    assert_eq!(one["samples"], 6, "{one}");
    assert_eq!(one["withAction"], one["samples"]);
    assert!(all["samples"].as_u64().unwrap() > 6, "{all}");
    let params = |c: &Value| -> Vec<String> {
        c["values"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["param"].as_str().unwrap().to_owned())
            .collect()
    };
    assert!(params(&one).contains(&"params.value".to_owned()), "{one}");
    // Номер канала есть только у измерений.
    assert!(!params(&one).iter().any(|p| p.contains("channel")), "{one}");

    let (status, none) = ask(json!({ "streams": [ab], "action": "нет такого" })).await;
    assert_eq!(status, StatusCode::OK, "{none}");
    assert_eq!(none["samples"], 0);
}

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

#[tokio::test]
async fn entropy_map_is_reported_per_stream() {
    let (state, _, ab, ba) = setup("entropy").await;
    let (status, found) = call(
        &state,
        Method::POST,
        "/api/analysis/entropy",
        Some(json!({ "streams": [ab.clone(), ba.clone()] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{found}");
    let streams = found["streams"].as_array().unwrap();
    assert_eq!(streams.len(), 2);
    for s in streams {
        let (bytes, length) = (s["bytes"].as_u64().unwrap(), s["length"].as_u64().unwrap());
        assert!(bytes <= length, "{s}");
        // Участки лежат внутри потока и не длиннее просмотренного.
        let mut covered = 0;
        for r in s["regions"].as_array().unwrap() {
            let (start, end) = (r["start"].as_u64().unwrap(), r["end"].as_u64().unwrap());
            assert!(start < end && end <= length, "{r}");
            covered += end - start;
        }
        assert!(covered <= bytes, "{s}");
        assert!(!s["summary"].as_str().unwrap().is_empty());
    }
    // Запросы стенда — короткие структурированные сообщения: на сжатие они не похожи.
    assert_eq!(streams[0]["highBytes"], 0, "{found}");

    let (status, _) = call(
        &state,
        Method::POST,
        "/api/analysis/entropy",
        Some(json!({ "streams": [] })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/analysis/entropy",
        Some(json!({ "streams": ["00000000:c0001:ab"] })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn every_action_of_the_journal_gets_its_exchange() {
    let (state, ab) = with_log("exchanges-all").await;
    let (status, page) = call(
        &state,
        Method::GET,
        "/api/action-logs/log-0001/exchanges?limit=500",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let rows = page["items"].as_array().unwrap();
    assert_eq!(rows.len() as u64, page["total"].as_u64().unwrap());
    let count = |state: &str| rows.iter().filter(|r| r["state"] == state).count() as u64;
    assert_eq!(count("paired"), page["paired"].as_u64().unwrap());
    assert_eq!(count("request_only"), page["requestOnly"].as_u64().unwrap());
    assert_eq!(count("not_found"), page["notFound"].as_u64().unwrap());
    // Запись стенда сделана по этому журналу: почти каждое действие находит запрос и ответ.
    assert!(count("paired") * 10 >= rows.len() as u64 * 8, "{page}");
    for row in rows.iter().filter(|r| r["state"] == "paired") {
        let (request, response) = (&row["request"], &row["response"]);
        assert_eq!(request["stream"], json!(ab), "{row}");
        assert_ne!(response["stream"], request["stream"]);
        assert!(response["tsNs"].as_u64().unwrap() >= request["tsNs"].as_u64().unwrap());
        assert_eq!(
            row["delayNs"].as_u64().unwrap(),
            response["tsNs"].as_u64().unwrap() - request["tsNs"].as_u64().unwrap()
        );
        assert_eq!(row["candidates"], 1);
    }
    // Запрос уставки и ответ на него — свои типы сообщений.
    let set = rows
        .iter()
        .find(|r| r["action"] == "set_param" && r["state"] == "paired")
        .unwrap_or_else(|| panic!("нет обмена для set_param: {page}"));
    assert_eq!(set["request"]["messageId"], "set_param_req");
    assert_eq!(set["response"]["messageId"], "set_param_resp");

    let (_, small) = call(
        &state,
        Method::GET,
        "/api/action-logs/log-0001/exchanges?limit=2&offset=1",
        None,
    )
    .await;
    assert_eq!(small["items"].as_array().unwrap().len(), 2);
    assert_eq!(small["items"][0], rows[1]);
    for (path, expected) in [
        (
            "/api/action-logs/log-0001/exchanges?limit=0",
            StatusCode::BAD_REQUEST,
        ),
        ("/api/action-logs/log-9999/exchanges", StatusCode::NOT_FOUND),
    ] {
        let (status, _) = call(&state, Method::GET, path, None).await;
        assert_eq!(status, expected, "{path}");
    }
}

/// Часы журнала отстают от записи на 3,2 с: в окне после действий данных почти нет. Движок находит
/// поправку сам, называет её в «что дальше» и не предлагает ничего, когда часы согласованы.
#[tokio::test]
async fn a_shifted_journal_clock_is_found_and_reported() {
    let (state, _, _, _) = setup("clock").await;
    let log = stand("main.actions.csv").to_string_lossy().into_owned();
    let import = |offset: i64| {
        let (state, log) = (state.clone(), log.clone());
        async move {
            let mapping = json!({ "time": "time", "action": "action", "params": "params",
                "result": "result", "clockOffsetMs": offset });
            call(
                &state,
                Method::POST,
                "/api/action-logs",
                Some(json!({ "path": log, "mapping": mapping })),
            )
            .await
        }
    };
    let (status, _) = import(-3200).await;
    assert_eq!(status, StatusCode::OK);
    let (status, late) = call(
        &state,
        Method::GET,
        "/api/action-logs/log-0001/clock-offset",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{late}");
    let offset = late["offsetMs"]
        .as_i64()
        .unwrap_or_else(|| panic!("{late}"));
    assert!((3100..=3200).contains(&offset), "{late}");
    assert_eq!(late["matchedShifted"], late["actions"], "{late}");
    assert!(late["matchedNow"].as_u64().unwrap() < late["actions"].as_u64().unwrap());
    assert_eq!(late["currentOffsetMs"], -3200);
    assert!(late["reason"].as_str().unwrap().contains("с поправкой"));

    let (_, next) = call(&state, Method::GET, "/api/project/next-steps", None).await;
    let step = next["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "fix_journal_clock")
        .unwrap_or_else(|| panic!("нет шага о часах: {next}"));
    assert!(
        step["detail"]
            .as_str()
            .unwrap()
            .contains("main.actions.csv")
    );

    // Тот же журнал без сдвига: поправка не предлагается.
    let (status, _) = import(0).await;
    assert_eq!(status, StatusCode::OK);
    let (_, exact) = call(
        &state,
        Method::GET,
        "/api/action-logs/log-0002/clock-offset",
        None,
    )
    .await;
    assert!(exact["offsetMs"].is_null(), "{exact}");
    assert_eq!(exact["matchedNow"], exact["actions"], "{exact}");

    for (path, expected) in [
        (
            "/api/action-logs/log-0001/clock-offset?windowMs=0",
            StatusCode::BAD_REQUEST,
        ),
        (
            "/api/action-logs/log-9999/clock-offset",
            StatusCode::NOT_FOUND,
        ),
    ] {
        let (status, _) = call(&state, Method::GET, path, None).await;
        assert_eq!(status, expected, "{path}");
    }
}

/// Две записи сняты в одно время, у каждой свой журнал без колонки записи: по времени действия
/// второго журнала подходят и к первой записи. Журнал относится к той записи, где нашлось больше
/// его действий, и пары из чужой записи не берутся.
#[tokio::test]
async fn a_journal_without_a_capture_column_is_bound_to_its_recording() {
    let (state, ab) = with_log("two-journals").await;
    let mapping =
        json!({ "time": "time", "action": "action", "params": "params", "result": "result" });
    call(
        &state,
        Method::POST,
        "/api/sources",
        Some(json!({ "path": stand("extra.pcapng").to_string_lossy() })),
    )
    .await;
    wait_jobs(&state).await;
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/action-logs",
        Some(json!({ "path": stand("extra.actions.csv").to_string_lossy(), "mapping": mapping })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let main_source = ab.split(':').next().unwrap().to_owned();

    for (log, own) in [("log-0001", true), ("log-0002", false)] {
        let (status, page) = call(
            &state,
            Method::GET,
            &format!("/api/action-logs/{log}/exchanges?limit=500"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let rows = page["items"].as_array().unwrap();
        assert!(!rows.is_empty());
        for row in rows.iter().filter(|r| !r["request"].is_null()) {
            let stream = row["request"]["stream"].as_str().unwrap();
            assert_eq!(stream.starts_with(&main_source), own, "{log}: {row}");
            assert_eq!(row["candidates"], 1, "{log}: {row}");
        }
        // Уставка находит запрос уставки, а не соседнее по времени сообщение другой записи.
        for row in rows.iter().filter(|r| r["action"] == "set_param") {
            assert_eq!(row["request"]["messageId"], "set_param_req", "{log}: {row}");
        }
    }
}

#[tokio::test]
async fn next_steps_follow_the_state_of_the_project() {
    let ids = |v: &Value| -> Vec<String> {
        v["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["id"].as_str().unwrap().to_owned())
            .collect()
    };
    // Пустой проект: только импорт записи.
    let empty = project_state("next-empty");
    let (status, next) = call(&empty, Method::GET, "/api/project/next-steps", None).await;
    assert_eq!(status, StatusCode::OK, "{next}");
    assert_eq!(ids(&next), ["import_capture"]);
    assert_eq!(next["steps"][0]["screen"], "sources");

    // Запись есть, описания нет: сначала границы, журнал — следом.
    let (state, _, _, _) = setup("next-capture").await;
    let (_, next) = call(&state, Method::GET, "/api/project/next-steps", None).await;
    assert_eq!(ids(&next), ["find_framing", "import_journal"]);

    // Запись, журнал и описание: пора запускать проверку.
    let (state, _) = with_log("next-run").await;
    let (_, next) = call(&state, Method::GET, "/api/project/next-steps", None).await;
    assert_eq!(ids(&next)[0], "first_run", "{next}");
    assert_eq!(next["state"]["hasInterpretation"], true);
    assert_eq!(next["state"]["runs"], 0);

    // После прогона первый шаг — уже не запуск; состояние называет прогон.
    call(&state, Method::POST, "/api/runs", Some(json!({}))).await;
    wait_jobs(&state).await;
    let (_, next) = call(&state, Method::GET, "/api/project/next-steps", None).await;
    assert!(!ids(&next).contains(&"first_run".to_owned()), "{next}");
    assert_eq!(next["state"]["lastRun"], "run-0001");
    assert_eq!(next["state"]["lastRunStale"], false);

    // Описание изменили по существу: прогон устарел, шаг — перезапуск.
    let yaml = std::fs::read_to_string(stand("interpretation.yaml"))
        .unwrap()
        .replace("type: i32be", "type: u32be");
    let (status, _) = call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(json!({ "yaml": yaml })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, next) = call(&state, Method::GET, "/api/project/next-steps", None).await;
    assert_eq!(ids(&next)[0], "rerun", "{next}");
    assert!(
        next["steps"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("run-0001")
    );
}

#[tokio::test]
async fn suggestions_turn_journal_links_into_observations_and_tested_hypotheses() {
    let (state, ab) = with_log("suggestions").await;
    let ba = ab.replace(":ab", ":ba");
    let (status, found) = call(
        &state,
        Method::POST,
        "/api/analysis/suggestions",
        Some(json!({ "streams": [ab.clone(), ba] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{found}");
    let items = found["items"].as_array().unwrap();
    let value = items
        .iter()
        .find(|s| s["messageId"] == "set_param_req" && s["param"] == "params.value")
        .unwrap_or_else(|| panic!("нет заготовки для значения уставки: {found}"));
    // На этих байтах в описании стенда уже есть поле: тест опирается на него.
    assert_eq!(value["field"], "value");
    assert!(value.get("newField").is_none());
    assert_eq!(value["hypothesis"]["test"], "value == action.params.value");
    assert_eq!(value["matches"], value["samples"]);

    // Заготовки принимаются обычными запросами: наблюдение, затем гипотеза с ним в основании.
    let o = &value["observation"];
    let (status, observation) = call(
        &state,
        Method::POST,
        "/api/observations",
        Some(json!({
            "anchor": { "source": o["source"], "stream": o["stream"], "start": o["start"], "end": o["end"] },
            "comment": o["comment"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{observation}");
    let (status, hypothesis) = call(
        &state,
        Method::POST,
        "/api/hypotheses",
        Some(json!({
            "statement": value["hypothesis"]["statement"],
            "basis": [observation["id"]],
            "test": value["hypothesis"]["test"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{hypothesis}");
    // Тест принятой гипотезы выполняется на записи без контрпримеров.
    let id = hypothesis["id"].as_str().unwrap();
    let (status, tested) = call(
        &state,
        Method::POST,
        &format!("/api/hypotheses/{id}/test"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tested}");
    let text = tested.to_string();
    assert!(text.contains("no_counterexample"), "{text}");

    // Описание без этого поля: заготовка называет поле, которое нужно добавить.
    let yaml = std::fs::read_to_string(stand("interpretation.yaml"))
        .unwrap()
        .replace(
            "      - { name: value, at: 7, type: i32be, status: hypothesis, hypothesis: H2 }\n",
            "",
        );
    let (status, saved) = call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(json!({ "yaml": yaml })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    let (_, found) = call(
        &state,
        Method::POST,
        "/api/analysis/suggestions",
        Some(json!({ "streams": [ab.clone()] })),
    )
    .await;
    let fresh = found["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["messageId"] == "set_param_req" && s["param"] == "params.value")
        .unwrap_or_else(|| panic!("{found}"));
    assert!(fresh["field"].is_null());
    assert_eq!(fresh["newField"]["name"], "value");
    assert!(fresh["newField"]["at"].is_u64());

    let (status, _) = call(
        &state,
        Method::POST,
        "/api/analysis/suggestions",
        Some(json!({ "streams": [] })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
