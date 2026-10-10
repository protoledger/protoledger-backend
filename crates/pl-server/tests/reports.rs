//! Отчёт по проекту через API: оба формата, прогон по умолчанию, ошибки.

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
    let dir = std::env::temp_dir().join(format!("pl-reports-test-{}-{name}", std::process::id()));
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

async fn setup(name: &str) -> AppState {
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
    state
}

#[tokio::test]
async fn report_without_a_project_is_conflict() {
    let dir = std::env::temp_dir().join(format!("pl-reports-test-{}-none", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = AppState::new(dir);
    let (status, problem) = call(
        &state,
        Method::POST,
        "/api/reports",
        Some(json!({ "format": "md" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(problem["detail"].is_string());
}

#[tokio::test]
async fn report_is_available_in_both_formats() {
    let state = setup("formats").await;
    let yaml = std::fs::read_to_string(stand("interpretation.yaml")).unwrap();
    call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(json!({ "yaml": yaml })),
    )
    .await;
    let (status, _) = call(&state, Method::POST, "/api/runs", Some(json!({}))).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    wait_jobs(&state).await;
    call(
        &state,
        Method::POST,
        "/api/questions",
        Some(json!({ "text": "Что значит <b>режим</b>?" })),
    )
    .await;

    let (status, md) = call(
        &state,
        Method::POST,
        "/api/reports",
        Some(json!({ "format": "md" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(md["format"], "md");
    assert_eq!(md["fileName"], "report.md");
    let text = md["content"].as_str().unwrap();
    assert!(text.contains("# Отчёт по проекту"), "{text}");
    assert!(text.contains("run-0001"), "{text}");
    assert!(text.contains("main.pcapng"));

    let (status, html) = call(
        &state,
        Method::POST,
        "/api/reports",
        Some(json!({ "format": "html", "runId": "run-0001" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let page = html["content"].as_str().unwrap();
    assert!(page.contains("Content-Security-Policy"));
    assert!(page.contains("&lt;b&gt;режим&lt;/b&gt;"));
    assert!(!page.contains("<script"));
}

#[tokio::test]
async fn report_rejects_bad_requests() {
    let state = setup("bad").await;
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/reports",
        Some(json!({ "format": "pdf" })),
    )
    .await;
    assert!(status.is_client_error());
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/reports",
        Some(json!({ "format": "md", "runId": "run-0099" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/reports",
        Some(json!({ "format": "md", "лишнее": 1 })),
    )
    .await;
    assert!(status.is_client_error());
}
