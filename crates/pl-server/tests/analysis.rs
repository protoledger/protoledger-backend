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
