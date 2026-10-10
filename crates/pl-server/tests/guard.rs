use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use pl_server::AppState;
use tower::ServiceExt;

const SPEC: &str = include_str!("../../../openapi.yaml");

struct Req<'a> {
    method: Method,
    path: &'a str,
    host: Option<&'a str>,
    origin: Option<&'a str>,
    token: Option<&'a str>,
    body: Option<(&'a str, String)>,
}

fn req(method: Method, path: &str) -> Req<'_> {
    Req {
        method,
        path,
        host: Some("localhost:8080"),
        origin: None,
        token: None,
        body: None,
    }
}

async fn send(state: &AppState, r: Req<'_>) -> axum::response::Response {
    let mut b = Request::builder().method(r.method).uri(r.path);
    if let Some(h) = r.host {
        b = b.header(header::HOST, h);
    }
    if let Some(o) = r.origin {
        b = b.header(header::ORIGIN, o);
    }
    if let Some(t) = r.token {
        b = b.header("x-protoledger-token", t);
    }
    let body = match r.body {
        Some((ct, body)) => {
            b = b.header(header::CONTENT_TYPE, ct);
            Body::from(body)
        }
        None => Body::empty(),
    };
    pl_server::router(state.clone())
        .oneshot(b.body(body).unwrap())
        .await
        .unwrap()
}

async fn status(state: &AppState, r: Req<'_>) -> StatusCode {
    send(state, r).await.status()
}

async fn text(response: axum::response::Response) -> String {
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

/// Каждый путь контракта (кроме health) без токена — 401: проверка не зависит от обработчика.
#[tokio::test]
async fn every_contract_endpoint_requires_token() {
    let state = AppState::default();
    let spec: serde_json::Value = serde_saphyr::from_str(SPEC).unwrap();
    let mut checked = 0;
    for (path, item) in spec["paths"].as_object().unwrap() {
        if path == "/api/health" {
            continue;
        }
        let url = path.replace(['{', '}'], "x");
        for method in item.as_object().unwrap().keys() {
            let method = Method::from_bytes(method.to_uppercase().as_bytes()).unwrap();
            let s = status(&state, req(method.clone(), &url)).await;
            assert_eq!(s, StatusCode::UNAUTHORIZED, "{method} {path}");
            let r = Req {
                token: Some("wrong"),
                ..req(method.clone(), &url)
            };
            assert_eq!(
                status(&state, r).await,
                StatusCode::UNAUTHORIZED,
                "{method} {path}: неверный токен"
            );
            checked += 1;
        }
    }
    assert!(checked >= 10, "проверено слишком мало маршрутов: {checked}");
    // Неизвестный путь внутри /api тоже защищён.
    assert_eq!(
        status(&state, req(Method::GET, "/api/nope")).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn valid_token_passes() {
    let state = AppState::default();
    let token = state.guard.token().to_owned();
    let r = Req {
        token: Some(&token),
        ..req(Method::GET, "/api/jobs")
    };
    assert_eq!(status(&state, r).await, StatusCode::OK);
}

#[tokio::test]
async fn foreign_host_is_forbidden_everywhere() {
    let state = AppState::default();
    let token = state.guard.token().to_owned();
    for host in [
        "evil.com",
        "evil.com:8080",
        "localhost.evil.com",
        "127.0.0.1.nip.io:8080",
        "0.0.0.0:8080",
    ] {
        for path in ["/api/jobs", "/api/health", "/", "/explore"] {
            let r = Req {
                host: Some(host),
                token: Some(&token),
                ..req(Method::GET, path)
            };
            assert_eq!(
                status(&state, r).await,
                StatusCode::FORBIDDEN,
                "{host} {path}"
            );
        }
    }
    let r = Req {
        host: None,
        token: Some(&token),
        ..req(Method::GET, "/api/jobs")
    };
    assert_eq!(status(&state, r).await, StatusCode::FORBIDDEN, "без Host");
}

#[tokio::test]
async fn loopback_hosts_are_accepted() {
    let state = AppState::default();
    let token = state.guard.token().to_owned();
    for host in [
        "127.0.0.1:8080",
        "localhost:3000",
        "[::1]:8080",
        "LOCALHOST:8080",
    ] {
        let r = Req {
            host: Some(host),
            token: Some(&token),
            ..req(Method::GET, "/api/jobs")
        };
        assert_eq!(status(&state, r).await, StatusCode::OK, "{host}");
    }
}

#[tokio::test]
async fn foreign_origin_is_forbidden() {
    let state = AppState::default();
    let token = state.guard.token().to_owned();
    for origin in [
        "http://evil.com",
        "http://localhost:3000",
        "null",
        "https://localhost:8080",
        "http://localhost:9999",
    ] {
        let r = Req {
            origin: Some(origin),
            token: Some(&token),
            ..req(Method::GET, "/api/jobs")
        };
        assert_eq!(status(&state, r).await, StatusCode::FORBIDDEN, "{origin}");
    }
    let own = Req {
        origin: Some("http://localhost:8080"),
        token: Some(&token),
        ..req(Method::GET, "/api/jobs")
    };
    assert_eq!(status(&state, own).await, StatusCode::OK);
    // Запрос из чужой формы отсекается по Origin, даже если токен угадан.
    let post = Req {
        origin: Some("http://evil.com"),
        token: Some(&token),
        body: Some(("application/json", r#"{"path":"/etc/passwd"}"#.to_owned())),
        ..req(Method::POST, "/api/sources")
    };
    assert_eq!(status(&state, post).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn health_needs_no_token_but_checks_host() {
    let state = AppState::default();
    assert_eq!(
        status(&state, req(Method::GET, "/api/health")).await,
        StatusCode::OK
    );
    let r = Req {
        host: Some("evil.com"),
        ..req(Method::GET, "/api/health")
    };
    assert_eq!(status(&state, r).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn docs_exist_only_in_dev_build() {
    let state = AppState::default();
    let response = send(&state, req(Method::GET, "/api/docs/")).await;
    if cfg!(feature = "dev-tools") {
        assert_eq!(response.status(), StatusCode::OK);
    } else {
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn security_headers_on_every_response() {
    let state = AppState::default();
    for path in ["/", "/api/health", "/api/nope"] {
        let response = send(&state, req(Method::GET, path)).await;
        let h = response.headers();
        assert_eq!(h["x-content-type-options"], "nosniff", "{path}");
        assert_eq!(h["referrer-policy"], "no-referrer", "{path}");
        let csp = h["content-security-policy"].to_str().unwrap();
        assert!(
            csp.contains("default-src 'self'") && csp.contains("frame-ancestors 'none'"),
            "{path}"
        );
        assert!(!h.contains_key("access-control-allow-origin"), "{path}");
    }
}

#[tokio::test]
async fn index_carries_session_token_and_is_not_cached() {
    let state = AppState::default();
    let response = send(&state, req(Method::GET, "/")).await;
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let html = text(response).await;
    let expected = format!(
        "name=\"protoledger-token\" content=\"{}\"",
        state.guard.token()
    );
    assert!(html.contains(&expected), "{html}");
    assert!(!html.contains("__PROTOLEDGER_TOKEN__"));
}

#[tokio::test]
async fn tokens_differ_between_sessions() {
    assert_ne!(
        AppState::default().guard.token(),
        AppState::default().guard.token()
    );
}

#[tokio::test]
async fn oversized_json_body_is_rejected() {
    let state = AppState::default();
    let token = state.guard.token().to_owned();
    let big = format!(r#"{{"path":"{}"}}"#, "a".repeat(9 << 20));
    let r = Req {
        token: Some(&token),
        body: Some(("application/json", big)),
        ..req(Method::POST, "/api/project")
    };
    let response = send(&state, r).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/problem+json"
    );
}
