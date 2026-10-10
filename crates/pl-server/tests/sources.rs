use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use pl_app::JobState;
use pl_server::AppState;
use serde_json::{Value, json};
use tower::ServiceExt;

/// Состояние с открытым проектом во временном каталоге.
fn project_state(name: &str) -> AppState {
    let dir = std::env::temp_dir().join(format!("pl-sources-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let state = AppState::new(dir);
    state
        .session
        .open(&state.jobs, "demo.protoledger", pl_app::OpenMode::Create)
        .unwrap();
    state
}

async fn wait_jobs(state: &AppState) {
    for job in state.jobs.list() {
        let mut rx = state.jobs.subscribe(&job.id).unwrap();
        while !rx.borrow_and_update().state.is_terminal() {
            rx.changed().await.unwrap();
        }
    }
}

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

async fn send(
    state: &AppState,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(path);
    let body = match body {
        Some(v) => {
            req = req.header(header::CONTENT_TYPE, "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let resp = pl_server::router(state.clone())
        .oneshot(req.body(body).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn get(state: &AppState, path: &str) -> (StatusCode, Value) {
    send(state, Method::GET, path, None).await
}

/// Импортирует запись и ждёт конца задачи; возвращает sha256.
async fn import(state: &AppState, name: &str) -> String {
    let (status, body) = send(
        state,
        Method::POST,
        "/api/sources",
        Some(json!({ "path": fixture(name) })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let id = body["jobId"].as_str().unwrap().to_owned();
    let mut rx = state.jobs.subscribe(&id).unwrap();
    while !rx.borrow().state.is_terminal() {
        rx.changed().await.unwrap();
    }
    let job = rx.borrow().clone();
    assert_eq!(job.state, JobState::Succeeded, "{:?}", job.error);
    job.result.unwrap()["sourceSha256"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn import_then_explore() {
    let state = project_state("t1");
    let sha = import(&state, "mixed.pcapng").await;

    let (status, sources) = get(&state, "/api/sources").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sources["total"], 1);
    let src = &sources["items"][0];
    assert_eq!(src["sha256"], sha);
    assert_eq!(src["importId"], "imp-0001");
    assert_eq!(
        (src["format"].as_str(), src["status"].as_str()),
        (Some("pcapng"), Some("ready"))
    );
    assert_eq!(
        (src["frameCount"].as_u64(), src["connectionCount"].as_u64()),
        (Some(25), Some(2))
    );

    let (_, conns) = get(&state, "/api/connections").await;
    assert_eq!(conns["total"], 2);
    let c2 = &conns["items"][1];
    assert_eq!(c2["id"], format!("{}:c0002", &sha[..8]));
    assert_eq!(c2["a"]["address"], "10.0.0.11");
    assert!(c2["flags"].as_array().unwrap().contains(&json!("gaps")));
    assert_eq!(c2["streams"][1]["gapBytes"], 27);
    assert!(
        c2["firstFrameTime"]
            .as_str()
            .unwrap()
            .starts_with("2026-10-01T00:00:00.")
    );

    let (_, gaps) = get(&state, "/api/connections?flag=gaps").await;
    assert_eq!(gaps["total"], 1);
    let (_, by_addr) = get(&state, "/api/connections?address=10.0.0.10&limit=1").await;
    assert_eq!(
        (
            by_addr["total"].as_u64(),
            by_addr["items"].as_array().unwrap().len()
        ),
        (Some(1), 1)
    );

    let stream = c2["streams"][1]["id"].as_str().unwrap().to_owned();
    let (status, bytes) = get(
        &state,
        &format!("/api/streams/{stream}/bytes?from=0&len=100000"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes["length"], bytes["streamLength"]);
    let segs = bytes["segments"].as_array().unwrap();
    assert_eq!(segs[0]["status"], "gap");
    assert_eq!(segs[0]["data"], Value::Null);
    assert_eq!(segs[1]["status"], "data");
    let data_frame = segs[1]["frames"][0]["frameNo"].as_u64().unwrap();

    let (_, part) = get(
        &state,
        &format!("/api/streams/{stream}/bytes?from=20&len=10"),
    )
    .await;
    assert_eq!(
        (part["from"].as_u64(), part["length"].as_u64()),
        (Some(20), Some(10))
    );
    assert_eq!(part["segments"][0]["start"], 20);

    let (status, frame) = get(&state, &format!("/api/frames/{sha}/{data_frame}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(frame["streamRange"]["stream"], stream);
    assert_eq!(frame["tcp"]["checksum"], "bad");
    assert!(frame["payload"]["length"].as_u64().unwrap() > 0);

    let (_, syn) = get(&state, &format!("/api/frames/{sha}/1")).await;
    assert_eq!(syn["tcp"]["flags"], json!(["syn"]));
    assert_eq!(syn["streamRange"], Value::Null);
    assert_eq!(syn["ethernet"]["etherType"], 2048);

    let (_, diag) = get(&state, &format!("/api/sources/{sha}/diagnostics")).await;
    assert_eq!(diag["frames"]["total"], 25);
    let codes: Vec<&str> = diag["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["code"].as_str().unwrap())
        .collect();
    assert!(
        codes.contains(&"non_ip") && codes.contains(&"non_tcp") && codes.contains(&"bad_checksum")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ambiguous_segment_has_variants() {
    let state = project_state("t2");
    let sha = import(&state, "overlap-conflict.pcapng").await;
    let (_, bytes) = get(
        &state,
        &format!("/api/streams/{}:c0001:ab/bytes", &sha[..8]),
    )
    .await;
    let amb = bytes["segments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["status"] == "ambiguous")
        .unwrap();
    let variants = amb["variants"].as_array().unwrap();
    assert_eq!(variants.len(), 2);
    assert_eq!(amb["data"], variants[0]["data"]);
    assert_ne!(variants[0]["data"], variants[1]["data"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn errors_are_problem_details() {
    let state = project_state("t3");
    let sha = import(&state, "normal.pcap").await;

    for (path, want) in [
        ("/api/streams/nope/bytes", StatusCode::NOT_FOUND),
        (
            "/api/streams/00000000:c0001:ab/bytes",
            StatusCode::NOT_FOUND,
        ),
        (
            &format!("/api/streams/{}:c0009:ab/bytes", &sha[..8]),
            StatusCode::NOT_FOUND,
        ),
        (
            &format!("/api/streams/{}:c0001:ab/bytes?len=0", &sha[..8]),
            StatusCode::BAD_REQUEST,
        ),
        (
            &format!("/api/streams/{}:c0001:ab/bytes?len=2000000", &sha[..8]),
            StatusCode::BAD_REQUEST,
        ),
        (&format!("/api/frames/{sha}/0"), StatusCode::NOT_FOUND),
        (&format!("/api/frames/{sha}/999"), StatusCode::NOT_FOUND),
        ("/api/sources/abc/diagnostics", StatusCode::NOT_FOUND),
        ("/api/connections?flag=weird", StatusCode::BAD_REQUEST),
        ("/api/connections?limit=0", StatusCode::BAD_REQUEST),
        ("/api/connections?port=notanumber", StatusCode::BAD_REQUEST),
    ] {
        let (status, body) = get(&state, path).await;
        assert_eq!(status, want, "{path}: {body}");
        assert!(
            body["type"]
                .as_str()
                .unwrap()
                .starts_with("urn:protoledger:problem:"),
            "{path}"
        );
    }

    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/sources")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from("x"))
        .unwrap();
    let resp = pl_server::router(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test(flavor = "multi_thread")]
async fn import_of_non_capture_fails_job() {
    let state = project_state("t4");
    let readme = fixture("README.md");
    let (status, body) = send(
        &state,
        Method::POST,
        "/api/sources",
        Some(json!({ "path": readme })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let mut rx = state
        .jobs
        .subscribe(body["jobId"].as_str().unwrap())
        .unwrap();
    while !rx.borrow().state.is_terminal() {
        rx.changed().await.unwrap();
    }
    let job = rx.borrow().clone();
    assert_eq!(job.state, JobState::Failed);
    assert_eq!(job.error.unwrap().status, 422);
    let (_, sources) = get(&state, "/api/sources").await;
    assert_eq!(sources["total"], 0);
}

#[tokio::test]
async fn import_requires_open_project() {
    let state = AppState::default();
    let (status, body) = send(
        &state,
        Method::POST,
        "/api/sources",
        Some(json!({ "path": fixture("normal.pcap") })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["type"], "urn:protoledger:problem:no-project");
}

#[tokio::test]
async fn import_copies_into_project_and_survives_reopen() {
    let state = project_state("reopen");
    let sha = import(&state, "normal.pcap").await;
    let root = state.session.read().as_ref().unwrap().root().to_path_buf();
    let copy = root.join("sources").join(format!("{sha}.pcap"));
    assert!(copy.is_file(), "копии записи нет в проекте");

    // Новая сессия на том же каталоге: проект открывается, записи разбираются заново.
    let workspace = root.parent().unwrap().to_path_buf();
    let fresh = AppState::new(workspace);
    let (status, body) = send(
        &fresh,
        Method::POST,
        "/api/project",
        Some(json!({ "path": "demo.protoledger", "mode": "open" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["sourceCount"], 1);
    wait_jobs(&fresh).await;
    let (_, list) = get(&fresh, "/api/sources").await;
    assert_eq!(list["items"][0]["sha256"], sha.as_str());
    assert_eq!(list["items"][0]["importId"], "imp-0001");
    let (status, _) = get(&fresh, "/api/connections").await;
    assert_eq!(status, StatusCode::OK);
}
