use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use pl_app::{JobState, OpenMode};
use pl_server::AppState;
use serde_json::Value;
use tower::ServiceExt;

const BOUNDARY: &str = "----plboundary";

fn fixture_bytes(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic")
        .join(name);
    std::fs::read(path).unwrap()
}

fn multipart(field: &str, file_name: &str, bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{file_name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    body
}

fn state_with_project(name: &str) -> AppState {
    let dir = std::env::temp_dir().join(format!("pl-upload-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let state = AppState::new(dir);
    state
        .session
        .open(&state.jobs, "demo.protoledger", OpenMode::Create)
        .unwrap();
    state
}

async fn post(state: &AppState, content_type: &str, body: Vec<u8>) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/api/sources")
        .header(header::HOST, "localhost:8080")
        .header("x-protoledger-token", state.guard.token())
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body))
        .unwrap();
    let response = pl_server::router(state.clone())
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn upload(state: &AppState, field: &str, name: &str, bytes: &[u8]) -> (StatusCode, Value) {
    post(
        state,
        &format!("multipart/form-data; boundary={BOUNDARY}"),
        multipart(field, name, bytes),
    )
    .await
}

#[allow(clippy::let_and_return)] // временный Ref не должен пережить rx
async fn finish(state: &AppState, job_id: &str) -> pl_app::Job {
    let mut rx = state.jobs.subscribe(job_id).unwrap();
    while !rx.borrow_and_update().state.is_terminal() {
        rx.changed().await.unwrap();
    }
    let job = rx.borrow().clone();
    job
}

fn project_root(state: &AppState) -> PathBuf {
    state.session.read().as_ref().unwrap().root().to_path_buf()
}

fn leftovers(state: &AppState) -> usize {
    let uploads = project_root(state).join(".cache/uploads");
    std::fs::read_dir(uploads).map(|d| d.count()).unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread")]
async fn uploaded_capture_is_imported_and_cleaned_up() {
    let state = state_with_project("ok");
    let bytes = fixture_bytes("mixed.pcapng");
    let (status, body) = upload(&state, "file", "../../мой запись.pcapng", &bytes).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let job = finish(&state, body["jobId"].as_str().unwrap()).await;
    assert_eq!(job.state, JobState::Succeeded, "{:?}", job.error);

    let sha = job.result.unwrap()["sourceSha256"]
        .as_str()
        .unwrap()
        .to_owned();
    let copy = project_root(&state)
        .join("sources")
        .join(format!("{sha}.pcapng"));
    assert_eq!(std::fs::read(copy).unwrap(), bytes);

    let source = state.sources.get(&sha).unwrap();
    assert_eq!(source.name, "мой запись.pcapng");
    assert_eq!(leftovers(&state), 0, "временные файлы загрузки остались");
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_without_project_is_conflict() {
    let state = AppState::default();
    let (status, body) = upload(&state, "file", "a.pcap", &fixture_bytes("normal.pcap")).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_without_file_field_is_bad_request() {
    let state = state_with_project("nofield");
    let (status, _) = upload(&state, "other", "a.pcap", b"x").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(leftovers(&state), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_of_non_capture_fails_job_and_cleans_up() {
    let state = state_with_project("garbage");
    let (status, body) = upload(
        &state,
        "file",
        "notes.pcap",
        "это не запись трафика".as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let job = finish(&state, body["jobId"].as_str().unwrap()).await;
    assert_eq!(job.state, JobState::Failed);
    assert_eq!(job.error.unwrap().status, 422);
    assert_eq!(leftovers(&state), 0);
    assert!(state.session.read().as_ref().unwrap().imports().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_upload_is_rejected_without_leftovers() {
    let mut state = state_with_project("big");
    state.max_upload = 100;
    let (status, body) = upload(&state, "file", "big.pcap", &fixture_bytes("normal.pcap")).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_eq!(body["limit"]["name"], "max_source_size");
    assert_eq!(leftovers(&state), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_bigger_than_json_limit_is_allowed() {
    let state = state_with_project("large");
    let mut bytes = fixture_bytes("normal.pcap");
    // Хвост после последнего пакета: файл больше 8 МиБ, но остаётся корректной записью.
    bytes.resize(9 << 20, 0);
    let (status, body) = upload(&state, "file", "large.pcap", &bytes).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    finish(&state, body["jobId"].as_str().unwrap()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unsupported_content_type_is_415() {
    let state = state_with_project("ct");
    let (status, _) = post(&state, "text/plain", b"x".to_vec()).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}
