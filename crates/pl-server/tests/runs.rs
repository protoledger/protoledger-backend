//! Прогоны проверки через API на записях стенда: сводка, контрпримеры, устаревание, сравнение.

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
    let dir = std::env::temp_dir().join(format!("pl-runs-test-{}-{name}", std::process::id()));
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

async fn import(state: &AppState, name: &str) {
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
}

async fn save_interpretation(state: &AppState, yaml: &str) -> u64 {
    let (status, body) = call(
        state,
        Method::PUT,
        "/api/interpretation",
        Some(json!({ "yaml": yaml })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["rev"].as_u64().unwrap()
}

/// Запускает прогон и возвращает его идентификатор.
async fn run(state: &AppState, body: Value) -> String {
    let (status, accepted) = call(state, Method::POST, "/api/runs", Some(body)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
    let job_id = accepted["jobId"].as_str().unwrap().to_owned();
    wait_jobs(state).await;
    let job = state.jobs.get(&job_id).unwrap();
    assert_eq!(job.state, pl_app::JobState::Succeeded, "{:?}", job.error);
    job.result.unwrap()["runId"].as_str().unwrap().to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn run_summarizes_the_whole_corpus() {
    let state = project_state("summary");
    import(&state, "main.pcapng").await;
    import(&state, "extra.pcapng").await;
    save_interpretation(&state, &answer_key()).await;

    let id = run(&state, json!({})).await;
    assert_eq!(id, "run-0001");
    let (status, run) = call(&state, Method::GET, &format!("/api/runs/{id}"), None).await;
    assert_eq!(status, StatusCode::OK, "{run}");
    let summary = &run["summary"];
    assert_eq!(summary["streams"], 4);
    assert_eq!(
        summary["messages"], 54,
        "16+16 основной и 11+11 дополнительной записи"
    );
    assert_eq!(summary["counts"], json!({ "matched": 54 }));
    assert_eq!(summary["unknownBytes"], 0);
    assert_eq!(summary["counterexamples"], 0);
    assert_eq!(summary["byMessage"]["set_param_req"]["matched"], 10);
    assert_eq!(run["stale"], false);
    assert_eq!(run["revision"], 1);
    assert_eq!(run["streams"].as_array().unwrap().len(), 4);

    // Таблица сообщений и фильтры.
    let (_, all) = call(
        &state,
        Method::GET,
        &format!("/api/runs/{id}/items?limit=500"),
        None,
    )
    .await;
    assert_eq!(all["total"], 54);
    let (_, sets) = call(
        &state,
        Method::GET,
        &format!("/api/runs/{id}/items?messageId=set_param_req&limit=5"),
        None,
    )
    .await;
    assert_eq!(
        (
            sets["total"].as_u64(),
            sets["items"].as_array().unwrap().len()
        ),
        (Some(10), 5)
    );
    let (_, none) = call(
        &state,
        Method::GET,
        &format!("/api/runs/{id}/items?category=violated"),
        None,
    )
    .await;
    assert_eq!(none["total"], 0);
    let stream = run["streams"][0]["id"].as_str().unwrap();
    let (_, one) = call(
        &state,
        Method::GET,
        &format!("/api/runs/{id}/items?stream={stream}"),
        None,
    )
    .await;
    assert_eq!(one["total"], 16);

    let (_, list) = call(&state, Method::GET, "/api/runs", None).await;
    assert_eq!(list["total"], 1);
    assert_eq!(list["items"][0]["id"], "run-0001");
}

#[tokio::test(flavor = "multi_thread")]
async fn corpus_filters_are_applied_and_recorded() {
    let state = project_state("corpus");
    import(&state, "main.pcapng").await;
    import(&state, "extra.pcapng").await;
    save_interpretation(&state, &answer_key()).await;

    let (_, sources) = call(&state, Method::GET, "/api/sources", None).await;
    let first = sources["items"][0]["sha256"].as_str().unwrap().to_owned();
    let id = run(
        &state,
        json!({ "corpus": { "sources": [first], "direction": "a_to_b", "port": 4710 } }),
    )
    .await;
    let (_, run) = call(&state, Method::GET, &format!("/api/runs/{id}"), None).await;
    assert_eq!(run["summary"]["streams"], 1);
    assert_eq!(run["summary"]["messages"], 16);
    assert_eq!(run["corpus"]["direction"], "a_to_b");
    assert_eq!(run["corpus"]["port"], 4710);
    assert_eq!(run["sources"].as_array().unwrap().len(), 1);

    let empty = run_status(&state, json!({ "corpus": { "port": 80 } })).await;
    assert_eq!(
        empty,
        StatusCode::ACCEPTED,
        "пустой корпус — это результат, а не ошибка запроса"
    );
}

async fn run_status(state: &AppState, body: Value) -> StatusCode {
    let (status, _) = call(state, Method::POST, "/api/runs", Some(body)).await;
    wait_jobs(state).await;
    status
}

#[tokio::test(flavor = "multi_thread")]
async fn counterexamples_staleness_and_diff() {
    let state = project_state("diff");
    import(&state, "main.pcapng").await;
    save_interpretation(&state, &answer_key()).await;
    let first = run(&state, json!({})).await;

    // Ошибочное правило: проверка суммы теперь заведомо ложная.
    let broken = answer_key().replace(
        "checksum == sum8(0, message.len - 1)",
        "checksum == sum8(0, message.len - 1) + 1",
    );
    assert_ne!(broken, answer_key());
    assert_eq!(save_interpretation(&state, &broken).await, 2);

    // Первый прогон устарел: интерпретация изменилась, но он остался читаемым.
    let (_, old) = call(&state, Method::GET, &format!("/api/runs/{first}"), None).await;
    assert_eq!(old["stale"], true);
    assert_eq!(old["staleReasons"], json!(["interpretation"]));
    assert_eq!(
        old["summary"]["counts"],
        json!({ "matched": 32 }),
        "результат устаревшего прогона не пересчитывается"
    );

    let second = run(&state, json!({})).await;
    let (_, bad) = call(&state, Method::GET, &format!("/api/runs/{second}"), None).await;
    assert_eq!(bad["stale"], false);
    assert_eq!(bad["summary"]["counts"], json!({ "violated": 32 }));
    assert_eq!(bad["summary"]["counterexamples"], 32);
    let cx = &bad["counterexamples"][0];
    assert_eq!(cx["category"], "violated");
    assert_eq!(cx["violations"][0]["id"], "C2");
    assert_eq!(cx["anchor"]["sha256"].as_str().map(str::len), Some(64));
    assert!(cx["anchor"]["stream"].as_str().unwrap().ends_with(":ab"));

    // Прогон по старой ревизии даёт прежний результат.
    let again = run(&state, json!({ "revision": 1 })).await;
    let (_, replay) = call(&state, Method::GET, &format!("/api/runs/{again}"), None).await;
    assert_eq!(replay["summary"]["counts"], json!({ "matched": 32 }));
    assert_eq!(replay["revision"], 1);
    assert_eq!(replay["stale"], true, "по ревизии 1, а текущая — 2");

    // Сравнение: первый → второй — всё ухудшилось; второй → первый — исправилось.
    let (status, worse) = call(
        &state,
        Method::GET,
        &format!("/api/runs/diff?a={first}&b={second}&limit=5"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{worse}");
    assert_eq!(worse["totals"]["regressed"], 32);
    assert_eq!(worse["totals"]["fixed"], 0);
    assert_eq!(worse["items"].as_array().unwrap().len(), 5);
    assert_eq!(worse["staleA"], true);
    assert_eq!(worse["staleB"], false);
    let (_, better) = call(
        &state,
        Method::GET,
        &format!("/api/runs/diff?a={second}&b={first}&kind=fixed"),
        None,
    )
    .await;
    assert_eq!(better["totals"]["fixed"], 32);
    assert_eq!(better["total"], 32);
    let (_, same) = call(
        &state,
        Method::GET,
        &format!("/api/runs/diff?a={first}&b={again}"),
        None,
    )
    .await;
    assert_eq!(same["totals"]["unchanged"], 32);
    assert_eq!(same["total"], 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn changing_build_settings_makes_runs_stale() {
    let state = project_state("settings");
    import(&state, "main.pcapng").await;
    save_interpretation(&state, &answer_key()).await;
    let id = run(&state, json!({})).await;

    let (status, _) = call(
        &state,
        Method::PATCH,
        "/api/project/settings",
        Some(json!({ "overlapPolicy": "last" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    wait_jobs(&state).await;
    let (_, run) = call(&state, Method::GET, &format!("/api/runs/{id}"), None).await;
    assert_eq!(run["staleReasons"], json!(["settings"]));
}

#[tokio::test(flavor = "multi_thread")]
async fn runs_survive_reopen_and_errors_are_clear() {
    let state = project_state("errors");
    // Нет интерпретации и записей.
    let (status, body) = call(&state, Method::POST, "/api/runs", Some(json!({}))).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    import(&state, "main.pcapng").await;
    let (status, body) = call(&state, Method::POST, "/api/runs", Some(json!({}))).await;
    assert_eq!(status, StatusCode::CONFLICT, "нет интерпретации: {body}");
    save_interpretation(&state, &answer_key()).await;
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/runs",
        Some(json!({ "revision": 9 })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/runs",
        Some(json!({ "лишнее": 1 })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let id = run(&state, json!({})).await;
    let fresh = AppState::new(state.session.workspace().to_path_buf());
    call(
        &fresh,
        Method::POST,
        "/api/project",
        Some(json!({ "path": "demo.protoledger", "mode": "open" })),
    )
    .await;
    wait_jobs(&fresh).await;
    let (status, reopened) = call(&fresh, Method::GET, &format!("/api/runs/{id}"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reopened["summary"]["messages"], 32);
    assert_eq!(reopened["stale"], false);

    for path in [
        "/api/runs/run-0099",
        "/api/runs/../project",
        "/api/runs/run-0099/items",
        "/api/runs/diff?a=run-0001&b=run-0099",
    ] {
        let (status, _) = call(&fresh, Method::GET, path, None).await;
        assert!(
            matches!(status, StatusCode::NOT_FOUND | StatusCode::BAD_REQUEST),
            "{path}: {status}"
        );
    }
    let (status, _) = call(&fresh, Method::GET, "/api/runs/diff?a=run-0001", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
