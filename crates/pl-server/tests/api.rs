use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use pl_app::JobKind;
use pl_core::{Problem, ProblemKind};
use pl_server::AppState;
use tower::ServiceExt;

async fn call(state: &AppState, method: Method, path: &str) -> axum::response::Response {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .body(Body::empty())
        .unwrap();
    pl_server::router(state.clone())
        .oneshot(request)
        .await
        .unwrap()
}

async fn get(path: &str) -> axum::response::Response {
    call(&AppState::default(), Method::GET, path).await
}

async fn text(response: axum::response::Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_str(&text(response).await).unwrap()
}

#[tokio::test]
async fn health_returns_ok() {
    let response = get("/api/health").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json(response).await["status"], "ok");
}

#[tokio::test]
async fn unknown_api_path_is_problem_details() {
    let response = get("/api/nope").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/problem+json"
    );
}

#[tokio::test]
async fn root_serves_embedded_page() {
    let response = get("/").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
}

#[tokio::test]
async fn spa_route_falls_back_to_index() {
    assert_eq!(get("/explore").await.status(), StatusCode::OK);
}

#[tokio::test]
async fn unknown_job_is_not_found() {
    assert_eq!(
        get("/api/jobs/job-9999").await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get("/api/jobs/job-9999/events").await.status(),
        StatusCode::NOT_FOUND
    );
    let response = call(&AppState::default(), Method::DELETE, "/api/jobs/job-9999").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn finished_job_streams_state_and_closes() {
    let state = AppState::default();
    let id = state
        .jobs
        .spawn(JobKind::Import, |_| async {
            Ok(serde_json::json!({ "importId": "imp-0001" }))
        })
        .unwrap();
    // Ждём завершения, чтобы поток отдал одно событие и закрылся.
    let mut rx = state.jobs.subscribe(&id).unwrap();
    while !rx.borrow_and_update().state.is_terminal() {
        rx.changed().await.unwrap();
    }

    let response = call(&state, Method::GET, &format!("/api/jobs/{id}/events")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream")
    );
    let body = text(response).await;
    assert!(body.contains("event: state"), "{body}");
    assert!(body.contains("\"state\":\"succeeded\""), "{body}");
    assert!(body.contains("imp-0001"), "{body}");

    let job = json(call(&state, Method::GET, &format!("/api/jobs/{id}")).await).await;
    assert_eq!(job["state"], "succeeded");
    let list = json(call(&state, Method::GET, "/api/jobs").await).await;
    assert_eq!(list["items"][0]["id"], id.as_str());
}

#[tokio::test]
async fn delete_cancels_running_job() {
    let state = AppState::default();
    let id = state
        .jobs
        .spawn(JobKind::Import, |ctx| async move {
            ctx.cancel_token().cancelled().await;
            Err(Problem::new(ProblemKind::Conflict, "отменено"))
        })
        .unwrap();

    let response = call(&state, Method::DELETE, &format!("/api/jobs/{id}")).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(json(response).await["state"], "cancelling");

    let mut rx = state.jobs.subscribe(&id).unwrap();
    while !rx.borrow_and_update().state.is_terminal() {
        rx.changed().await.unwrap();
    }
    let again = call(&state, Method::DELETE, &format!("/api/jobs/{id}")).await;
    assert_eq!(again.status(), StatusCode::CONFLICT);
}
