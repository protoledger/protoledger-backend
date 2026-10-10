//! Политики сборки (ТЗ 7.3, D4 и D6) через API: смена настроек заново собирает записи.

use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use pl_app::OpenMode;
use pl_server::AppState;
use serde_json::{Value, json};
use tower::ServiceExt;

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn project_state(name: &str) -> AppState {
    let dir = std::env::temp_dir().join(format!("pl-settings-test-{}-{name}", std::process::id()));
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

async fn import(state: &AppState, name: &str) -> String {
    let (status, body) = call(
        state,
        Method::POST,
        "/api/sources",
        Some(json!({ "path": fixture(name) })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    wait_jobs(state).await;
    let (_, list) = call(state, Method::GET, "/api/sources", None).await;
    list["items"][0]["sha256"].as_str().unwrap().to_owned()
}

async fn patch(state: &AppState, body: Value) -> (StatusCode, Value) {
    let result = call(state, Method::PATCH, "/api/project/settings", Some(body)).await;
    wait_jobs(state).await;
    result
}

/// Все участки потоков записи: `(статус, есть ли принятые байты, base64)`.
async fn segments(state: &AppState, sha: &str) -> Vec<(String, Option<String>)> {
    let (_, conns) = call(
        state,
        Method::GET,
        &format!("/api/connections?source={sha}&limit=500"),
        None,
    )
    .await;
    let mut out = Vec::new();
    for conn in conns["items"].as_array().unwrap() {
        for stream in conn["streams"].as_array().unwrap() {
            let id = stream["id"].as_str().unwrap();
            let (_, bytes) = call(
                state,
                Method::GET,
                &format!("/api/streams/{id}/bytes?len=65536"),
                None,
            )
            .await;
            for seg in bytes["segments"].as_array().unwrap() {
                out.push((
                    seg["status"].as_str().unwrap().to_owned(),
                    seg["data"].as_str().map(str::to_owned),
                ));
            }
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn overlap_policy_changes_what_is_accepted_but_ambiguity_stays_visible() {
    let state = project_state("overlap");
    let sha = import(&state, "overlap-conflict.pcapng").await;

    let first = segments(&state, &sha).await;
    assert!(first.iter().any(|(s, d)| s == "ambiguous" && d.is_some()));

    let (status, body) = patch(&state, json!({ "overlapPolicy": "last" })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["settings"]["overlapPolicy"], "last");
    let last = segments(&state, &sha).await;
    let ambiguous = |v: &[(String, Option<String>)]| -> Vec<Option<String>> {
        v.iter()
            .filter(|(s, _)| s == "ambiguous")
            .map(|(_, d)| d.clone())
            .collect()
    };
    assert_eq!(ambiguous(&first).len(), ambiguous(&last).len());
    assert_ne!(
        ambiguous(&first),
        ambiguous(&last),
        "«last» принимает другие байты, чем «first»"
    );

    let (_, body) = patch(&state, json!({ "overlapPolicy": "flag" })).await;
    assert_eq!(body["settings"]["overlapPolicy"], "flag");
    let flagged = segments(&state, &sha).await;
    let amb = ambiguous(&flagged);
    assert_eq!(amb.len(), ambiguous(&first).len());
    assert!(
        amb.iter().all(Option::is_none),
        "при «flag» принятых байтов нет"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn checksum_policy_drop_removes_bad_segments() {
    let state = project_state("checksum");
    let sha = import(&state, "bad-checksum.pcapng").await;
    let total = |v: &[(String, Option<String>)]| {
        v.iter()
            .filter(|(s, _)| s == "data")
            .map(|(_, d)| d.as_ref().map_or(0, String::len))
            .sum::<usize>()
    };
    let warned = total(&segments(&state, &sha).await);
    assert!(warned > 0);

    let (status, _) = patch(&state, json!({ "checksumPolicy": "drop" })).await;
    assert_eq!(status, StatusCode::OK);
    let dropped = total(&segments(&state, &sha).await);
    assert!(
        dropped < warned,
        "при «drop» байты кадров с неверной суммой не попадают в поток"
    );

    // Диагностика называет узел с offloading.
    let (_, diag) = call(
        &state,
        Method::GET,
        &format!("/api/sources/{sha}/diagnostics"),
        None,
    )
    .await;
    let detail = diag["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["code"] == "bad_checksum")
        .map(|i| i["detail"].as_str().unwrap().to_owned())
        .expect("есть замечание про суммы");
    assert!(
        detail.contains("10.0.0.10") && detail.contains("offloading"),
        "{detail}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_survive_reopen_and_validate_input() {
    let state = project_state("persist");
    import(&state, "normal.pcapng").await;
    patch(
        &state,
        json!({ "overlapPolicy": "last", "checksumPolicy": "ignore" }),
    )
    .await;

    let workspace = state.session.workspace().to_path_buf();
    let fresh = AppState::new(workspace);
    let (status, body) = call(
        &fresh,
        Method::POST,
        "/api/project",
        Some(json!({ "path": "demo.protoledger", "mode": "open" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["settings"],
        json!({ "overlapPolicy": "last", "checksumPolicy": "ignore" })
    );
    // Открытие запускает пересборку записей: пока она идёт, настройки менять нельзя (409).
    wait_jobs(&fresh).await;

    for bad in [
        json!({}),
        json!({ "overlapPolicy": "nope" }),
        json!({ "unknown": 1 }),
    ] {
        let (status, _) = call(
            &fresh,
            Method::PATCH,
            "/api/project/settings",
            Some(bad.clone()),
        )
        .await;
        // Пустое тело допустимо для сервера (ничего не меняет), остальное — ошибка запроса.
        let expected = if bad == json!({}) {
            StatusCode::OK
        } else {
            StatusCode::BAD_REQUEST
        };
        assert_eq!(status, expected, "{bad}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_without_project_are_conflict() {
    let state = AppState::default();
    let (status, body) = call(
        &state,
        Method::PATCH,
        "/api/project/settings",
        Some(json!({ "overlapPolicy": "last" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}
