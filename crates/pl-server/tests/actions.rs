//! Журнал действий: импорт, просмотр и поиск обмена по действию на записи стенда.

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

fn stand_mapping() -> Value {
    json!({ "time": "time", "action": "action", "params": "params", "result": "result" })
}

fn project_state(name: &str) -> AppState {
    let dir = std::env::temp_dir().join(format!("pl-actions-test-{}-{name}", std::process::id()));
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

async fn import_log(state: &AppState, mapping: Value) -> (StatusCode, Value) {
    let path = stand("main.actions.csv").to_string_lossy().into_owned();
    call(
        state,
        Method::POST,
        "/api/action-logs",
        Some(json!({ "path": path, "mapping": mapping })),
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn import_view_and_filter_the_stand_log() {
    let state = setup("import").await;
    let (status, log) = import_log(&state, stand_mapping()).await;
    assert_eq!(status, StatusCode::OK, "{log}");
    assert_eq!(
        (
            log["id"].as_str(),
            log["rows"].as_u64(),
            log["skipped"].as_u64()
        ),
        (Some("log-0001"), Some(16), Some(0))
    );
    assert_eq!(log["name"], "main.actions.csv");
    assert!(
        log["firstTime"]
            .as_str()
            .unwrap()
            .starts_with("2026-10-01T00:00:00.356")
    );

    let (_, list) = call(&state, Method::GET, "/api/action-logs", None).await;
    assert_eq!(list["items"].as_array().unwrap().len(), 1);

    let (_, page) = call(
        &state,
        Method::GET,
        "/api/action-logs/log-0001/actions?limit=100",
        None,
    )
    .await;
    assert_eq!(page["total"], 16);
    let set21 = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["params"]["value"] == 21)
        .unwrap();
    assert_eq!(set21["action"], "set_param");
    assert_eq!(set21["params"]["param"], "setpoint");
    assert_eq!(set21["result"], json!({ "status": "ok", "applied": 21 }));
    assert_eq!(set21["line"], 5, "номер строки файла: заголовок — первая");

    let (_, sets) = call(
        &state,
        Method::GET,
        "/api/action-logs/log-0001/actions?action=set_param",
        None,
    )
    .await;
    assert_eq!(sets["total"], 6);
    let (_, late) = call(
        &state,
        Method::GET,
        "/api/action-logs/log-0001/actions?from=2026-10-01T00:00:10Z",
        None,
    )
    .await;
    assert!(late["total"].as_u64().unwrap() < 16);
    let (status, _) = call(
        &state,
        Method::GET,
        "/api/action-logs/log-0001/actions?from=вчера",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn exchange_is_found_by_action_time() {
    let state = setup("exchange").await;
    import_log(&state, stand_mapping()).await;

    // Без интерпретации — только кадры с данными в окне.
    let (status, frames_only) = call(
        &state,
        Method::GET,
        "/api/action-logs/log-0001/actions/5/exchange?before=100&after=400",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{frames_only}");
    assert_eq!(frames_only["interpretationApplied"], false);
    let frames = frames_only["frames"].as_array().unwrap();
    assert_eq!(
        frames.len(),
        2,
        "запрос клиента и ответ устройства: {frames:?}"
    );
    assert!(frames[0]["stream"].as_str().unwrap().ends_with(":ab"));
    assert!(frames[1]["stream"].as_str().unwrap().ends_with(":ba"));
    assert_eq!(frames_only["messages"], json!([]));

    // С интерпретацией — сообщения с типами и категориями.
    let yaml = std::fs::read_to_string(stand("interpretation.yaml")).unwrap();
    call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(json!({ "yaml": yaml })),
    )
    .await;
    let (_, found) = call(
        &state,
        Method::GET,
        "/api/action-logs/log-0001/actions/5/exchange?before=100&after=400",
        None,
    )
    .await;
    assert_eq!(found["interpretationApplied"], true);
    let ids: Vec<&str> = found["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["messageId"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["set_param_req", "set_param_resp"]);
    assert_eq!(found["messages"][0]["category"], "matched");
    assert_eq!(found["action"]["params"]["value"], 21);

    // Окно слишком узкое: после действия — ничего.
    let (_, narrow) = call(
        &state,
        Method::GET,
        "/api/action-logs/log-0001/actions/5/exchange?before=0&after=0",
        None,
    )
    .await;
    assert_eq!(narrow["frames"], json!([]));

    // Действие «измерение канала 3» — ответ около 60 КиБ одним сообщением на десятки кадров.
    let (_, big) = call(
        &state,
        Method::GET,
        "/api/action-logs/log-0001/actions?action=get_measurement&limit=100",
        None,
    )
    .await;
    let channel3 = big["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["params"]["channel"] == 3)
        .unwrap();
    let line = channel3["line"].as_u64().unwrap();
    let (_, ex) = call(
        &state,
        Method::GET,
        &format!("/api/action-logs/log-0001/actions/{line}/exchange?after=2000"),
        None,
    )
    .await;
    assert!(ex["frames"].as_array().unwrap().len() > 40);
    let resp = ex["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["messageId"] == "measure_resp")
        .unwrap();
    assert!(resp["end"].as_u64().unwrap() - resp["start"].as_u64().unwrap() > 59_000);
    assert_ne!(
        resp["firstTime"], resp["lastTime"],
        "сообщение занимает много кадров по времени"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn clock_offset_moves_the_window() {
    let state = setup("offset").await;
    // Часы клиента отстают на 10 секунд: без поправки обмена в окне нет.
    let shifted = json!({ "time": "time", "action": "action", "params": "params", "result": "result", "clockOffsetMs": -10000 });
    import_log(&state, shifted).await;
    let (_, none) = call(
        &state,
        Method::GET,
        "/api/action-logs/log-0001/actions/5/exchange?before=100&after=400",
        None,
    )
    .await;
    assert_eq!(
        none["frames"],
        json!([]),
        "сдвинутое время не совпадает с записью"
    );

    let fixed = json!({ "time": "time", "action": "action", "params": "params", "result": "result", "clockOffsetMs": 10000 });
    let (_, second) = call(
        &state,
        Method::POST,
        "/api/action-logs",
        Some(json!({ "path": stand("main.actions.csv").to_string_lossy(), "mapping": fixed })),
    )
    .await;
    assert_eq!(second["id"], "log-0002");
    let (_, back) = call(
        &state,
        Method::GET,
        "/api/action-logs/log-0002/actions/5/exchange?before=100&after=400",
        None,
    )
    .await;
    assert_eq!(back["frames"].as_array().unwrap().len(), 0, "ещё дальше");
    // Верная поправка — ноль: запись совпадает.
    let (_, zero) = call(&state, Method::POST, "/api/action-logs", Some(json!({ "path": stand("main.actions.csv").to_string_lossy(), "mapping": stand_mapping() }))).await;
    let id = zero["id"].as_str().unwrap().to_owned();
    let (_, ok) = call(
        &state,
        Method::GET,
        &format!("/api/action-logs/{id}/actions/5/exchange?before=100&after=400"),
        None,
    )
    .await;
    assert_eq!(ok["frames"].as_array().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_survive_reopen_and_bad_input_is_explained() {
    let state = setup("reopen").await;
    import_log(&state, stand_mapping()).await;
    let fresh = AppState::new(state.session.workspace().to_path_buf());
    call(
        &fresh,
        Method::POST,
        "/api/project",
        Some(json!({ "path": "demo.protoledger", "mode": "open" })),
    )
    .await;
    let (_, list) = call(&fresh, Method::GET, "/api/action-logs", None).await;
    assert_eq!(list["items"][0]["rows"], 16);
    let (_, page) = call(
        &fresh,
        Method::GET,
        "/api/action-logs/log-0001/actions",
        None,
    )
    .await;
    assert_eq!(page["total"], 16);

    // Колонки не найдены, формат времени не тот, нет проекта.
    let (status, body) = import_log(&fresh, json!({ "time": "когда", "action": "action" })).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body["detail"].as_str().unwrap().contains("когда"), "{body}");
    let (status, body) = import_log(
        &fresh,
        json!({ "time": "time", "action": "action", "timeFormat": "unix_seconds" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let (status, _) = import_log(&AppState::default(), stand_mapping()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    for path in [
        "/api/action-logs/log-0099/actions",
        "/api/action-logs/log-0001/actions/9999/exchange",
    ] {
        let (status, _) = call(&fresh, Method::GET, path, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
    let (status, _) = call(
        &fresh,
        Method::GET,
        "/api/action-logs/log-0001/actions/5/exchange?after=99999999",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn multipart_upload_of_a_log() {
    let state = project_state("multipart");
    let csv = std::fs::read(stand("extra.actions.csv")).unwrap();
    let boundary = "----plb";
    let mapping = stand_mapping().to_string();
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"mapping\"\r\n\r\n{mapping}\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"extra.actions.csv\"\r\nContent-Type: text/csv\r\n\r\n").as_bytes());
    body.extend_from_slice(&csv);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let request = Request::builder()
        .method("POST")
        .uri("/api/action-logs")
        .header(header::HOST, "localhost:8080")
        .header("x-protoledger-token", state.guard.token())
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap();
    let response = pl_server::router(state.clone())
        .oneshot(request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let log: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        (log["name"].as_str(), log["rows"].as_u64()),
        (Some("extra.actions.csv"), Some(11))
    );
    let (_, page) = call(
        &state,
        Method::GET,
        "/api/action-logs/log-0001/actions?action=set_param",
        None,
    )
    .await;
    let values: Vec<i64> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["params"]["value"].as_i64().unwrap())
        .collect();
    assert_eq!(values, [70_000, -5, 123_456, 1]);
}
