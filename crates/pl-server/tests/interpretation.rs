//! Интерпретация через API: ревизии, проверка, предпросмотр на записи стенда.

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

fn answer_key() -> String {
    std::fs::read_to_string(stand("interpretation.yaml")).unwrap()
}

fn project_state(name: &str) -> AppState {
    let dir = std::env::temp_dir().join(format!("pl-interp-test-{}-{name}", std::process::id()));
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

/// Импортирует запись стенда; возвращает идентификатор потока «клиент → устройство».
async fn import_stand(state: &AppState, name: &str) -> (String, String) {
    let path = stand(name).to_string_lossy().into_owned();
    let (status, _) = call(
        state,
        Method::POST,
        "/api/sources",
        Some(json!({ "path": path })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    wait_jobs(state).await;
    let (_, conns) = call(state, Method::GET, "/api/connections", None).await;
    let streams = &conns["items"][0]["streams"];
    (
        streams[0]["id"].as_str().unwrap().to_owned(),
        streams[1]["id"].as_str().unwrap().to_owned(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn revisions_are_saved_validated_and_listed() {
    let state = project_state("revisions");
    let (status, _) = call(&state, Method::GET, "/api/interpretation", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, saved) = call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(json!({ "yaml": answer_key() })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(
        (saved["rev"].as_u64(), saved["created"].as_bool()),
        (Some(1), Some(true))
    );
    let digest = saved["digest"].as_str().unwrap().to_owned();
    assert_eq!(digest.len(), 64);

    // Тот же смысл, другое форматирование — новой ревизии нет.
    let reformatted = format!("# комментарий\n{}", answer_key());
    let (_, again) = call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(json!({ "yaml": reformatted })),
    )
    .await;
    assert_eq!(
        (again["rev"].as_u64(), again["created"].as_bool()),
        (Some(1), Some(false))
    );

    // Изменение смысла — новая ревизия; первая остаётся прежней.
    let changed = answer_key().replace("adjust: 7", "adjust: 8");
    let (_, second) = call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(json!({ "yaml": changed.clone() })),
    )
    .await;
    assert_eq!(second["rev"], 2);
    let (_, first) = call(&state, Method::GET, "/api/interpretation/revisions/1", None).await;
    assert_eq!(first["digest"], digest.as_str());
    assert!(first["yaml"].as_str().unwrap().contains("adjust: 7"));
    let (_, current) = call(&state, Method::GET, "/api/interpretation", None).await;
    assert_eq!(current["rev"], 2);
    let (_, list) = call(&state, Method::GET, "/api/interpretation/revisions", None).await;
    assert_eq!(list["items"].as_array().unwrap().len(), 2);
    let (status, _) = call(&state, Method::GET, "/api/interpretation/revisions/9", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Ревизии переживают переоткрытие проекта.
    let fresh = AppState::new(state.session.workspace().to_path_buf());
    call(
        &fresh,
        Method::POST,
        "/api/project",
        Some(json!({ "path": "demo.protoledger", "mode": "open" })),
    )
    .await;
    let (_, reopened) = call(&fresh, Method::GET, "/api/interpretation", None).await;
    assert_eq!(reopened["rev"], 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_interpretation_is_422_and_not_saved() {
    let state = project_state("invalid");
    for bad in [
        "format: protoledger/interpretation@9\nframing: { kind: fixed, size: 4 }\n".to_owned(),
        answer_key().replace("kind: length_prefixed", "kind: bogus"),
        "не: [yaml".to_owned(),
        answer_key().replace("hypothesis: H2", "hypothesis: H77"),
    ] {
        let (status, body) = call(
            &state,
            Method::PUT,
            "/api/interpretation",
            Some(json!({ "yaml": bad })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body["detail"]
                .as_str()
                .unwrap()
                .contains("Интерпретация не"),
            "{body}"
        );
    }
    let (_, list) = call(&state, Method::GET, "/api/interpretation/revisions", None).await;
    assert!(list["items"].as_array().unwrap().is_empty());
    let (status, _) = call(
        &AppState::default(),
        Method::GET,
        "/api/interpretation/revisions",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test(flavor = "multi_thread")]
async fn preview_applies_saved_revision_to_the_stand_recording() {
    let state = project_state("preview");
    let (requests, replies) = import_stand(&state, "main.pcapng").await;
    call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(json!({ "yaml": answer_key() })),
    )
    .await;

    let (status, page) = call(
        &state,
        Method::POST,
        "/api/interpretation/preview",
        Some(json!({ "stream": requests, "limit": 500 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["rev"], 1);
    assert_eq!(page["outOfScope"], false);
    assert_eq!(page["counts"], json!({ "matched": 16 }));
    assert_eq!(page["unknownBytes"], 0);
    assert_eq!(page["total"], 16);

    // Значения из журнала: уставки 21, 37, 1000.
    let values: Vec<i64> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["messageId"] == "set_param_req")
        .map(|m| {
            m["fields"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["name"] == "value")
                .unwrap()["value"]
                .as_i64()
                .unwrap()
        })
        .collect();
    assert_eq!(values, [21, 37, 1000, 300, 5, 2]);
    let value_field = &page["items"][3]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "value")
        .unwrap()
        .clone();
    assert_eq!(
        (
            value_field["status"].as_str(),
            value_field["hypothesis"].as_str()
        ),
        (Some("hypothesis"), Some("H2"))
    );
    assert_eq!(value_field["valueType"], "int");

    // Байты — hex-строкой, не сырым текстом.
    let signature = page["items"][0]["fields"][0].clone();
    assert_eq!(
        (signature["valueType"].as_str(), signature["value"].as_str()),
        (Some("bytes"), Some("5ac3"))
    );

    // Страницы и фильтр по категории.
    let (_, small) = call(
        &state,
        Method::POST,
        "/api/interpretation/preview",
        Some(json!({ "stream": replies, "limit": 5, "offset": 10 })),
    )
    .await;
    assert_eq!(small["items"].as_array().unwrap().len(), 5);
    assert_eq!(small["total"], 16);
    let (_, none) = call(
        &state,
        Method::POST,
        "/api/interpretation/preview",
        Some(json!({ "stream": replies, "category": "violated" })),
    )
    .await;
    assert_eq!(none["total"], 0);
    assert_eq!(
        none["counts"],
        json!({ "matched": 16 }),
        "сводка не зависит от фильтра"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn preview_with_unsaved_yaml_shows_what_a_wrong_hypothesis_does() {
    let state = project_state("override");
    let (requests, _) = import_stand(&state, "extra.pcapng").await;

    // Без сохранённой ревизии и без yaml применять нечего.
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/interpretation/preview",
        Some(json!({ "stream": requests })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Гипотеза «значение — u16 по смещению 9» с ожиданием 70000 не выполняется, и это видно.
    let naive = answer_key().replace(
        "      - { name: value, at: 7, type: i32be, status: hypothesis, hypothesis: H2 }\n      - { name: checksum, at: end-1, type: u8, status: rule }\n  - id: set_param_resp",
        "      - { name: value, at: 9, type: u16be, status: hypothesis, hypothesis: H2, expect: 70000 }\n      - { name: checksum, at: end-1, type: u8, status: rule }\n  - id: set_param_resp",
    );
    assert_ne!(naive, answer_key());
    let (status, body) = call(
        &state,
        Method::POST,
        "/api/interpretation/preview",
        Some(json!({ "stream": requests, "yaml": naive })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "expect 70000 не подходит к u16: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn preview_scope_and_errors() {
    let state = project_state("scope");
    let (requests, _) = import_stand(&state, "main.pcapng").await;
    let narrow = answer_key().replace("dst_port == 4710 || src_port == 4710", "dst_port == 80");
    let (_, page) = call(
        &state,
        Method::POST,
        "/api/interpretation/preview",
        Some(json!({ "stream": requests, "yaml": narrow })),
    )
    .await;
    assert_eq!(page["outOfScope"], true);
    assert_eq!(page["total"], 0);

    for (body, expected) in [
        (
            json!({ "stream": "нет:c0001:ab", "yaml": answer_key() }),
            StatusCode::NOT_FOUND,
        ),
        (
            json!({ "stream": requests, "yaml": answer_key(), "limit": 0 }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "stream": requests, "yaml": answer_key(), "лишнее": 1 }),
            StatusCode::BAD_REQUEST,
        ),
        (json!({ "yaml": answer_key() }), StatusCode::BAD_REQUEST),
    ] {
        let (status, _) = call(
            &state,
            Method::POST,
            "/api/interpretation/preview",
            Some(body.clone()),
        )
        .await;
        assert_eq!(status, expected, "{body}");
    }
}
