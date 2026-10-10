//! Злые записи через HTTP API: каждая импортируется, задача завершается (успехом или понятной
//! ошибкой), сервер продолжает работать и отвечает на запросы.

use std::path::PathBuf;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use pl_app::{JobState, OpenMode};
use pl_server::AppState;
use serde_json::{Value, json};
use tower::ServiceExt;

fn state(name: &str) -> AppState {
    let dir = std::env::temp_dir().join(format!("pl-hostile-api-{}-{name}", std::process::id()));
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

async fn import(state: &AppState, path: PathBuf) -> pl_app::Job {
    let (status, body) = call(
        state,
        Method::POST,
        "/api/sources",
        Some(json!({ "path": path.to_string_lossy() })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let id = body["jobId"].as_str().unwrap().to_owned();
    let mut rx = state.jobs.subscribe(&id).unwrap();
    let wait = async {
        while !rx.borrow_and_update().state.is_terminal() {
            rx.changed().await.unwrap();
        }
    };
    tokio::time::timeout(Duration::from_secs(60), wait)
        .await
        .expect("задача импорта зависла");
    let job = rx.borrow().clone();
    job
}

fn hostile_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/hostile")
}

#[tokio::test(flavor = "multi_thread")]
async fn every_hostile_file_is_handled_and_server_stays_alive() {
    let state = state("all");
    let mut imported = 0;
    for sample in pl_hostile::samples() {
        let path = hostile_dir().join(format!("{}.{}", sample.name, sample.extension));
        let job = import(&state, path).await;
        match job.state {
            JobState::Succeeded => imported += 1,
            JobState::Failed => {
                let problem = job.error.expect("у ошибки есть описание");
                assert!(
                    matches!(problem.status, 413 | 422),
                    "{}: неожиданный статус {}",
                    sample.name,
                    problem.status
                );
                assert!(
                    problem.detail.is_some(),
                    "{}: нет текста ошибки",
                    sample.name
                );
            }
            other => panic!("{}: задача в состоянии {other:?}", sample.name),
        }
        // После каждого файла сервер отвечает.
        let (status, _) = call(&state, Method::GET, "/api/sources?limit=1", None).await;
        assert_eq!(status, StatusCode::OK, "{}", sample.name);
    }
    assert!(imported > 20, "импортировано слишком мало: {imported}");

    // Всё, что импортировалось, читается через API без ошибок сервера.
    let (_, sources) = call(&state, Method::GET, "/api/sources?limit=500", None).await;
    for source in sources["items"].as_array().unwrap() {
        let sha = source["sha256"].as_str().unwrap();
        let (status, _) = call(
            &state,
            Method::GET,
            &format!("/api/sources/{sha}/diagnostics"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, conns) = call(
            &state,
            Method::GET,
            &format!("/api/connections?source={sha}&limit=500"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        for conn in conns["items"].as_array().unwrap() {
            for stream in conn["streams"].as_array().unwrap() {
                let id = stream["id"].as_str().unwrap();
                let (status, _) = call(
                    &state,
                    Method::GET,
                    &format!("/api/streams/{id}/bytes?from=0&len=65536"),
                    None,
                )
                .await;
                assert_eq!(status, StatusCode::OK, "{id}");
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn hostile_strings_are_returned_as_data_not_markup() {
    let state = state("strings");
    let path = hostile_dir().join("payload-hostile-strings.pcap");
    let job = import(&state, path).await;
    assert_eq!(job.state, JobState::Succeeded, "{:?}", job.error);
    let (_, conns) = call(&state, Method::GET, "/api/connections", None).await;
    let id = conns["items"][0]["streams"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let response = pl_server::router(state.clone())
        .oneshot(
            Request::get(format!("/api/streams/{id}/bytes?len=4096"))
                .header(header::HOST, "localhost:8080")
                .header("x-protoledger-token", state.guard.token())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // Байты — только в base64 внутри JSON с типом application/json: браузер не примет их за разметку.
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    let text = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(!text.contains("<script>"), "сырые байты попали в ответ");
}

#[tokio::test(flavor = "multi_thread")]
async fn connection_limit_is_reported_as_problem() {
    let state = state("limit");
    let dir = std::env::temp_dir().join(format!("pl-hostile-large-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("connections-over-limit.pcap");
    std::fs::write(&path, pl_hostile::large("connections-over-limit").unwrap()).unwrap();
    let job = import(&state, path).await;
    assert_eq!(job.state, JobState::Failed);
    let problem = job.error.unwrap();
    assert_eq!(problem.status, 413);
    assert!(problem.limit.is_some());
    let _ = std::fs::remove_dir_all(dir);
    let (status, _) = call(&state, Method::GET, "/api/health", None).await;
    assert_eq!(status, StatusCode::OK);
}
