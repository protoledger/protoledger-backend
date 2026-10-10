//! Инструменты разработки: Swagger UI и dev-режим. Компилируются только с feature `dev-tools`
//! (ADR 0011): в сборке для жюри этого кода и строк нет.

use axum::Router;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use utoipa_swagger_ui::{Config, SwaggerUi};

/// Контракт, описанный вручную; источник истины для моков и клиента фронта.
pub const OPENAPI_YAML: &str = include_str!("../../../openapi.yaml");

/// Настройки `serve --dev`.
#[derive(Debug, Clone)]
pub struct DevConfig {
    /// Фиксированный токен сессии (из `PROTOLEDGER_DEV_TOKEN`).
    pub token: String,
    /// Origin dev-сервера фронта, которому разрешён доступ к API.
    pub allowed_origin: String,
}

impl DevConfig {
    pub const FRONT_ORIGIN: &'static str = "http://localhost:3000";

    /// Токен попадает в JS страницы документации, поэтому допускаем только безопасные символы.
    pub fn new(token: String) -> Result<Self, String> {
        let valid = token.len() >= 8
            && token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if !valid {
            return Err(
                "PROTOLEDGER_DEV_TOKEN: нужно не меньше 8 символов из латиницы, цифр, «-» и «_»."
                    .to_owned(),
            );
        }
        Ok(Self {
            token,
            allowed_origin: Self::FRONT_ORIGIN.to_owned(),
        })
    }
}

async fn spec() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/yaml; charset=utf-8")],
        OPENAPI_YAML,
    )
}

/// Свой `swagger-initializer.js`: подставляет токен сессии во все запросы «Try it out».
fn initializer(token: Option<&str>) -> String {
    let interceptor = match token.and_then(|t| serde_json::to_string(t).ok()) {
        Some(token) => format!(
            "requestInterceptor: function (req) {{ req.headers['X-Protoledger-Token'] = {token}; return req; }},"
        ),
        None => String::new(),
    };
    format!(
        "window.onload = function () {{\n  window.ui = SwaggerUIBundle({{\n    url: '/api/docs/openapi.yaml',\n    dom_id: '#swagger-ui',\n    deepLinking: true,\n    {interceptor}\n    presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],\n    layout: 'StandaloneLayout'\n  }});\n}};\n"
    )
}

pub fn docs_routes(dev: Option<&DevConfig>) -> Router {
    let script = initializer(dev.map(|d| d.token.as_str()));
    let swagger: Router = SwaggerUi::new("/api/docs")
        .config(Config::new(["/api/docs/openapi.yaml"]))
        .into();
    Router::new()
        .route("/api/docs/openapi.yaml", get(spec))
        .route(
            "/api/docs/swagger-initializer.js",
            get(move || {
                let script = script.clone();
                async move {
                    (
                        [(
                            header::CONTENT_TYPE,
                            "application/javascript; charset=utf-8",
                        )],
                        script,
                    )
                }
            }),
        )
        .merge(swagger)
}
