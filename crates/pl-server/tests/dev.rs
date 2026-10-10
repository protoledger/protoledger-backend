#![cfg(feature = "dev-tools")]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use pl_server::AppState;
use pl_server::dev::{DevConfig, OPENAPI_YAML};
use tower::ServiceExt;

async fn get(state: AppState, path: &str) -> (StatusCode, String) {
    let response = pl_server::router(state)
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn dev_state() -> AppState {
    AppState {
        dev: Some(DevConfig::new("dev-token-123".to_owned()).unwrap()),
        ..AppState::default()
    }
}

#[tokio::test]
async fn docs_page_and_spec_are_served() {
    let (status, html) = get(AppState::default(), "/api/docs/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("swagger"), "{html}");

    let (status, yaml) = get(AppState::default(), "/api/docs/openapi.yaml").await;
    assert_eq!(status, StatusCode::OK);
    assert!(yaml.starts_with("openapi: 3.1.0"));
}

#[tokio::test]
async fn dev_token_is_injected_only_in_dev_mode() {
    let (_, script) = get(dev_state(), "/api/docs/swagger-initializer.js").await;
    assert!(script.contains("X-Protoledger-Token") && script.contains("dev-token-123"));

    let (_, script) = get(AppState::default(), "/api/docs/swagger-initializer.js").await;
    assert!(!script.contains("X-Protoledger-Token"));
}

#[test]
fn dev_token_must_be_safe() {
    assert!(DevConfig::new("short".to_owned()).is_err());
    assert!(DevConfig::new("bad\"token;alert(1)".to_owned()).is_err());
    assert!(DevConfig::new("good-token_1234".to_owned()).is_ok());
}

/// Реализованные маршруты должны быть описаны в контракте.
#[test]
fn implemented_routes_are_in_contract() {
    let spec: serde_json::Value = serde_saphyr::from_str(OPENAPI_YAML).unwrap();
    for path in [
        "/api/health",
        "/api/jobs",
        "/api/jobs/{id}",
        "/api/jobs/{id}/events",
    ] {
        assert!(
            spec["paths"].get(path).is_some(),
            "в openapi.yaml нет {path}"
        );
    }
    assert!(spec["paths"]["/api/jobs/{id}"].get("delete").is_some());
}

/// Каждый ответ в контракте должен иметь пример: по ним работает мок фронта.
#[test]
fn every_response_has_example() {
    let spec: serde_json::Value = serde_saphyr::from_str(OPENAPI_YAML).unwrap();
    for (path, item) in spec["paths"].as_object().unwrap() {
        for (method, op) in item.as_object().unwrap() {
            for (status, response) in op["responses"].as_object().unwrap() {
                if response.get("$ref").is_some() {
                    continue;
                }
                let has_example = response["content"]
                    .as_object()
                    .is_some_and(|c| c.values().all(|m| m.get("example").is_some()));
                assert!(has_example, "{method} {path} {status}: нет example");
            }
        }
    }
}
