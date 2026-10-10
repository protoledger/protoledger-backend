//! Наблюдения, гипотезы и вопросы на записи стенда: основания, тесты против журнала действий.

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
    let dir = std::env::temp_dir().join(format!("pl-research-test-{}-{name}", std::process::id()));
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

/// Проект с записью стенда, журналом действий и интерпретацией («ключ ответов»).
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
    let log = stand("main.actions.csv").to_string_lossy().into_owned();
    let mapping =
        json!({ "time": "time", "action": "action", "params": "params", "result": "result" });
    call(
        &state,
        Method::POST,
        "/api/action-logs",
        Some(json!({ "path": log, "mapping": mapping })),
    )
    .await;
    let yaml = std::fs::read_to_string(stand("interpretation.yaml")).unwrap();
    call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(json!({ "yaml": yaml })),
    )
    .await;
    state
}

/// Якорь на поле `value` запроса «уставка = 21»: поток клиента, смещение и длина берутся из предпросмотра.
async fn value_anchor(state: &AppState) -> Value {
    let (_, conns) = call(state, Method::GET, "/api/connections", None).await;
    let source = conns["items"][0]["source"].as_str().unwrap().to_owned();
    let stream = conns["items"][0]["streams"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (_, page) = call(
        state,
        Method::POST,
        "/api/interpretation/preview",
        Some(json!({ "stream": stream, "limit": 500 })),
    )
    .await;
    let field = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["messageId"] == "set_param_req")
        .flat_map(|m| m["fields"].as_array().unwrap().iter())
        .find(|f| f["name"] == "value" && f["value"] == 21)
        .unwrap()
        .clone();
    let (at, len) = (
        field["at"].as_u64().unwrap(),
        field["len"].as_u64().unwrap(),
    );
    json!({ "source": source, "stream": stream, "start": at, "end": at + len })
}

#[tokio::test(flavor = "multi_thread")]
async fn observation_pins_bytes_and_cannot_be_orphaned() {
    let state = setup("observation").await;
    let anchor = value_anchor(&state).await;
    let (status, obs) = call(
        &state,
        Method::POST,
        "/api/observations",
        Some(json!({ "anchor": anchor, "comment": "здесь 21" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{obs}");
    assert_eq!(obs["id"], "obs-1");
    assert_eq!(obs["anchorState"], "ok");
    assert_eq!(
        obs["anchor"]["sha256"].as_str().map(str::len),
        Some(64),
        "хеш байтов зафиксирован"
    );

    // Якорь на несуществующие байты и пустой комментарий отклоняются.
    let beyond = json!({ "source": anchor["source"], "stream": anchor["stream"], "start": 0, "end": 99_999_999 });
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/observations",
        Some(json!({ "anchor": beyond, "comment": "x" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let nowhere =
        json!({ "source": anchor["source"], "stream": "нет:c0001:ab", "start": 0, "end": 1 });
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/observations",
        Some(json!({ "anchor": nowhere, "comment": "x" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/observations",
        Some(json!({ "anchor": anchor, "comment": "  " })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (_, edited) = call(
        &state,
        Method::PUT,
        "/api/observations/obs-1",
        Some(json!({ "comment": "уставка 21" })),
    )
    .await;
    assert_eq!(edited["comment"], "уставка 21");
    let (_, second) = call(
        &state,
        Method::POST,
        "/api/observations",
        Some(json!({ "anchor": anchor, "comment": "то же место" })),
    )
    .await;
    assert_eq!(second["id"], "obs-2");

    // Основание гипотезы удалить нельзя, пока на него ссылаются.
    call(
        &state,
        Method::POST,
        "/api/hypotheses",
        Some(json!({ "statement": "value — уставка", "basis": ["obs-1"] })),
    )
    .await;
    let (status, body) = call(&state, Method::DELETE, "/api/observations/obs-1", None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (status, _) = call(&state, Method::DELETE, "/api/observations/obs-2", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call(&state, Method::GET, "/api/observations/obs-2", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Идентификаторы не переиспользуются.
    let (_, third) = call(
        &state,
        Method::POST,
        "/api/observations",
        Some(json!({ "anchor": anchor, "comment": "ещё" })),
    )
    .await;
    assert_eq!(
        third["id"], "obs-2",
        "номер считается по существующим записям"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn hypothesis_validation_and_statuses() {
    let state = setup("validation").await;
    let anchor = value_anchor(&state).await;
    call(
        &state,
        Method::POST,
        "/api/observations",
        Some(json!({ "anchor": anchor, "comment": "x" })),
    )
    .await;

    let (status, h1) = call(&state, Method::POST, "/api/hypotheses", Some(json!({ "statement": "param — идентификатор", "basis": ["obs-1"], "test": "param >= 1" }))).await;
    assert_eq!(
        (status, h1["id"].as_str(), h1["status"].as_str()),
        (StatusCode::CREATED, Some("H1"), Some("proposed"))
    );
    for (body, expected) in [
        (
            json!({ "statement": "x", "basis": ["obs-9"] }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "statement": "x", "test": "1 +" }),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (json!({ "statement": "" }), StatusCode::BAD_REQUEST),
        (json!({ "basis": [] }), StatusCode::BAD_REQUEST),
        (
            json!({ "statement": "x", "status": "superseded" }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "statement": "x", "лишнее": 1 }),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let (status, _) = call(&state, Method::POST, "/api/hypotheses", Some(body.clone())).await;
        assert_eq!(status, expected, "{body}");
    }

    let (_, h2) = call(
        &state,
        Method::POST,
        "/api/hypotheses",
        Some(json!({ "statement": "value — значение u16" })),
    )
    .await;
    assert_eq!(h2["id"], "H2");
    let (status, _) = call(
        &state,
        Method::PUT,
        "/api/hypotheses/H2",
        Some(json!({ "status": "superseded" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "для superseded нужен supersededBy"
    );
    let (status, body) = call(
        &state,
        Method::PUT,
        "/api/hypotheses/H2",
        Some(json!({ "status": "superseded", "supersededBy": "H1" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["supersededBy"], "H1");
    let (status, _) = call(&state, Method::DELETE, "/api/hypotheses/H1", None).await;
    assert_eq!(status, StatusCode::CONFLICT, "H1 заменяет H2");
    let (_, back) = call(
        &state,
        Method::PUT,
        "/api/hypotheses/H2",
        Some(json!({ "status": "refuted" })),
    )
    .await;
    assert_eq!(
        (back["status"].as_str(), back["supersededBy"].clone()),
        (Some("refuted"), Value::Null)
    );
    let (status, _) = call(
        &state,
        Method::PUT,
        "/api/hypotheses/H9",
        Some(json!({ "note": "x" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_against_the_action_log_supports_and_refutes() {
    let state = setup("tests").await;
    let (_, h) = call(&state, Method::POST, "/api/hypotheses", Some(json!({ "statement": "value — устанавливаемое значение", "test": "value == action.params.value" }))).await;
    assert_eq!(h["id"], "H1");

    let (status, ok) = call(
        &state,
        Method::POST,
        "/api/hypotheses/H1/test",
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{ok}");
    assert_eq!(ok["verdict"], "no_counterexample");
    assert_eq!(
        (ok["applicable"].as_u64(), ok["held"].as_u64()),
        (Some(6), Some(6)),
        "6 запросов на запись, все совпали"
    );
    assert!(
        ok["notApplicable"].as_u64().unwrap() >= 26,
        "остальные сообщения не про запись значения"
    );
    assert_eq!(ok["counterexamples"], json!([]));
    assert_eq!(ok["status"], "proposed", "проверка не меняет статус");

    // Ответ устройства принял значение не всегда: усиление 300 вне диапазона — устройство оставило 1.
    call(&state, Method::POST, "/api/hypotheses", Some(json!({ "statement": "устройство применяет заданное", "test": "response.applied == action.params.value" }))).await;
    let (_, bad) = call(
        &state,
        Method::POST,
        "/api/hypotheses/H2/test",
        Some(json!({ "logId": "log-0001" })),
    )
    .await;
    assert_eq!(bad["verdict"], "refuted", "{bad}");
    assert_eq!(
        (
            bad["applicable"].as_u64(),
            bad["held"].as_u64(),
            bad["counterexamplesTotal"].as_u64()
        ),
        (Some(6), Some(5), Some(1))
    );
    let cx = &bad["counterexamples"][0];
    assert_eq!(cx["values"]["action.params.value"], "300");
    assert_eq!(cx["values"]["response.applied"], "1");
    assert_eq!(cx["messageId"], "set_param_req");
    assert_eq!(cx["anchor"]["sha256"].as_str().map(str::len), Some(64));
    assert!(cx["actionLine"].as_u64().is_some());

    // Тест без применимых сообщений — «не проверено», а не «подтверждено».
    call(
        &state,
        Method::POST,
        "/api/hypotheses",
        Some(json!({ "statement": "про несуществующее поле", "test": "nothing == 1" })),
    )
    .await;
    let (_, none) = call(
        &state,
        Method::POST,
        "/api/hypotheses/H3/test",
        Some(json!({})),
    )
    .await;
    assert_eq!(
        (none["verdict"].as_str(), none["applicable"].as_u64()),
        (Some("untested"), Some(0))
    );

    // Несовместимые типы — ошибка вычисления, видимая отдельно.
    call(
        &state,
        Method::POST,
        "/api/hypotheses",
        Some(json!({ "statement": "тип", "test": "value == 'abc'" })),
    )
    .await;
    let (_, typed) = call(
        &state,
        Method::POST,
        "/api/hypotheses/H4/test",
        Some(json!({})),
    )
    .await;
    assert!(typed["errorsTotal"].as_u64().unwrap() > 0, "{typed}");
    assert_eq!(typed["verdict"], "untested");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_preconditions_are_explained() {
    let state = project_state("preconditions");
    call(
        &state,
        Method::POST,
        "/api/hypotheses",
        Some(json!({ "statement": "без теста" })),
    )
    .await;
    let (status, body) = call(
        &state,
        Method::POST,
        "/api/hypotheses/H1/test",
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    call(
        &state,
        Method::PUT,
        "/api/hypotheses/H1",
        Some(json!({ "test": "value == 1" })),
    )
    .await;
    let (status, body) = call(
        &state,
        Method::POST,
        "/api/hypotheses/H1/test",
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "нет интерпретации: {body}");
    let yaml = std::fs::read_to_string(stand("interpretation.yaml")).unwrap();
    call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(json!({ "yaml": yaml })),
    )
    .await;
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/hypotheses/H1/test",
        Some(json!({ "logId": "log-0009" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/hypotheses/H1/test",
        Some(json!({ "windowMs": 999_999_999 })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(&AppState::default(), Method::GET, "/api/hypotheses", None).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test(flavor = "multi_thread")]
async fn questions_and_persistence() {
    let state = setup("persist").await;
    let anchor = value_anchor(&state).await;
    call(
        &state,
        Method::POST,
        "/api/observations",
        Some(json!({ "anchor": anchor, "comment": "наблюдение" })),
    )
    .await;
    call(
        &state,
        Method::POST,
        "/api/hypotheses",
        Some(json!({ "statement": "гипотеза", "basis": ["obs-1"], "status": "supported" })),
    )
    .await;
    let (status, q) = call(
        &state,
        Method::POST,
        "/api/questions",
        Some(json!({ "text": "Что означает параметр 3?" })),
    )
    .await;
    assert_eq!(
        (status, q["id"].as_str(), q["status"].as_str()),
        (StatusCode::CREATED, Some("q-1"), Some("open"))
    );
    let (_, closed) = call(
        &state,
        Method::PUT,
        "/api/questions/q-1",
        Some(json!({ "status": "closed", "answer": "режим работы" })),
    )
    .await;
    assert_eq!(
        (closed["status"].as_str(), closed["answer"].as_str()),
        (Some("closed"), Some("режим работы"))
    );

    // Всё лежит в проекте и переживает переоткрытие; файлы — YAML в корне проекта.
    let root = state.session.read().as_ref().unwrap().root().to_path_buf();
    for file in ["observations.yaml", "hypotheses.yaml", "questions.yaml"] {
        assert!(root.join(file).is_file(), "{file}");
    }
    let fresh = AppState::new(state.session.workspace().to_path_buf());
    call(
        &fresh,
        Method::POST,
        "/api/project",
        Some(json!({ "path": "demo.protoledger", "mode": "open" })),
    )
    .await;
    wait_jobs(&fresh).await;
    let (_, hs) = call(&fresh, Method::GET, "/api/hypotheses", None).await;
    assert_eq!(hs["items"][0]["basis"], json!(["obs-1"]));
    assert_eq!(hs["items"][0]["status"], "supported");
    let (_, os) = call(&fresh, Method::GET, "/api/observations", None).await;
    assert_eq!(
        os["items"][0]["anchorState"], "ok",
        "якорь проверяется после пересборки записи"
    );
    let (_, qs) = call(&fresh, Method::GET, "/api/questions", None).await;
    assert_eq!(qs["items"][0]["status"], "closed");
    let (status, _) = call(&fresh, Method::DELETE, "/api/questions/q-1", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}
