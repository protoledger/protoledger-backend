use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

use crate::AppState;

#[derive(RustEmbed)]
#[folder = "$UI_DIST"]
struct Ui;

const TOKEN_PLACEHOLDER: &str = "__PROTOLEDGER_TOKEN__";

/// Кладёт токен сессии в `<meta name="protoledger-token">`: подменяет заглушку или добавляет тег в `<head>`.
fn with_token(html: &str, token: &str) -> String {
    if html.contains(TOKEN_PLACEHOLDER) {
        return html.replace(TOKEN_PLACEHOLDER, token);
    }
    let meta = format!("<meta name=\"protoledger-token\" content=\"{token}\">");
    match html.find("</head>") {
        Some(at) => format!("{}{meta}{}", &html[..at], &html[at..]),
        None => format!("{meta}{html}"),
    }
}

/// Отдаёт файл встроенного интерфейса; неизвестные пути — `index.html` (маршруты SPA).
pub async fn serve_ui(State(state): State<AppState>, uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let (file, name) = match Ui::get(path) {
        Some(file) if !path.is_empty() => (file, path),
        _ => match Ui::get("index.html") {
            Some(file) => (file, "index.html"),
            None => return StatusCode::NOT_FOUND.into_response(),
        },
    };
    let mime = mime_guess::from_path(name).first_or_octet_stream();
    let content_type = [(header::CONTENT_TYPE, mime.as_ref().to_owned())];
    if name == "index.html" {
        let html = String::from_utf8_lossy(&file.data);
        let body = with_token(&html, state.guard.token());
        // Токен свой у каждого запуска: страницу нельзя кэшировать.
        return (
            content_type,
            [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
            body,
        )
            .into_response();
    }
    (content_type, file.data.into_owned()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_replaces_placeholder() {
        let html =
            "<head><meta name=\"protoledger-token\" content=\"__PROTOLEDGER_TOKEN__\"></head>";
        assert!(with_token(html, "abc").contains("content=\"abc\""));
    }

    #[test]
    fn token_is_injected_without_placeholder() {
        assert_eq!(
            with_token("<head></head>", "abc"),
            "<head><meta name=\"protoledger-token\" content=\"abc\"></head>"
        );
        assert!(with_token("<p>x</p>", "abc").starts_with("<meta"));
    }
}
