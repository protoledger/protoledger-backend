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

#[allow(clippy::let_and_return)] // временный Ref не должен пережить rx
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
async fn connections_over_the_limit_are_diagnosed_not_fatal() {
    let state = state("limit");
    let dir = std::env::temp_dir().join(format!("pl-hostile-large-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("connections-over-limit.pcap");
    std::fs::write(&path, pl_hostile::large("connections-over-limit").unwrap()).unwrap();
    // ТЗ 7.3: запись открывается, соединения в пределе собраны, остальное — явная диагностика.
    let job = import(&state, path).await;
    assert_eq!(job.state, JobState::Succeeded, "{:?}", job.error);
    let (_, sources) = call(&state, Method::GET, "/api/sources", None).await;
    let sha = sources["items"][0]["sha256"].as_str().unwrap().to_owned();
    let (_, conns) = call(&state, Method::GET, "/api/connections?limit=1", None).await;
    assert_eq!(
        conns["total"],
        pl_reassembly::MAX_CONNECTIONS as u64,
        "{conns}"
    );
    let (status, diag) = call(
        &state,
        Method::GET,
        &format!("/api/sources/{sha}/diagnostics"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{diag}");
    let limit = diag["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["code"] == "limit_exceeded")
        .unwrap_or_else(|| panic!("нет limit_exceeded: {diag}"));
    assert!(limit["count"].as_u64().unwrap() > 0);
    assert_eq!(limit["severity"], "warning");
    let _ = std::fs::remove_dir_all(dir);
    let (status, _) = call(&state, Method::GET, "/api/health", None).await;
    assert_eq!(status, StatusCode::OK);
}

/// Злые журналы и описания протокола через API: ответ — успех или понятная ошибка клиента,
/// никогда не ошибка сервера, и сервер после каждого файла отвечает.
#[tokio::test(flavor = "multi_thread")]
async fn hostile_journals_and_descriptions_never_break_the_server() {
    let state = state("inputs");
    let (mut accepted, mut rejected) = (0, 0);
    for sample in pl_hostile::inputs::journals() {
        let path = hostile_dir()
            .join("journals")
            .join(format!("{}.{}", sample.name, sample.extension));
        let format = if sample.name.starts_with("json-") {
            "json"
        } else {
            "kv"
        };
        let mapping = json!({ "time": "time", "action": "action", "params": "params", "result": "result", "paramsFormat": format });
        let (status, body) = call(
            &state,
            Method::POST,
            "/api/action-logs",
            Some(json!({ "path": path.to_string_lossy(), "mapping": mapping })),
        )
        .await;
        match status.as_u16() {
            200 => accepted += 1,
            413 | 422 => {
                assert!(
                    body["detail"].is_string(),
                    "{}: нет текста ошибки",
                    sample.name
                );
                rejected += 1;
            }
            other => panic!("{}: неожиданный статус {other}: {body}", sample.name),
        }
        let (status, _) = call(&state, Method::GET, "/api/action-logs", None).await;
        assert_eq!(status, StatusCode::OK, "{}", sample.name);
    }
    assert!(
        accepted >= 5 && rejected >= 5,
        "{accepted} принято, {rejected} отклонено"
    );

    let (mut saved, mut refused) = (0, 0);
    for sample in pl_hostile::inputs::interpretations() {
        let Ok(yaml) = String::from_utf8(sample.bytes.clone()) else {
            continue;
        };
        let (status, body) = call(
            &state,
            Method::PUT,
            "/api/interpretation",
            Some(json!({ "yaml": yaml })),
        )
        .await;
        match status.as_u16() {
            200 => saved += 1,
            413 | 422 => {
                assert!(
                    body["detail"].is_string(),
                    "{}: нет текста ошибки",
                    sample.name
                );
                refused += 1;
            }
            other => panic!("{}: неожиданный статус {other}: {body}", sample.name),
        }
        let (status, _) = call(&state, Method::GET, "/api/project", None).await;
        assert_eq!(status, StatusCode::OK, "{}", sample.name);
    }
    assert!(
        saved >= 3 && refused >= 8,
        "{saved} сохранено, {refused} отклонено"
    );

    // Строки с разметкой возвращаются как данные.
    let (_, logs) = call(&state, Method::GET, "/api/action-logs", None).await;
    let html = logs["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["name"] == "html-and-controls.csv")
        .expect("журнал с разметкой принят");
    let (status, actions) = call(
        &state,
        Method::GET,
        &format!(
            "/api/action-logs/{}/actions?limit=10",
            html["id"].as_str().unwrap()
        ),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(actions["items"][0]["action"], "<script>alert(1)</script>");
}
