use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "$UI_DIST"]
struct Ui;

/// Отдаёт файл встроенного интерфейса; неизвестные пути — `index.html` (маршруты SPA).
pub async fn serve_ui(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let (file, name) = match Ui::get(path) {
        Some(file) if !path.is_empty() => (file, path),
        _ => match Ui::get("index.html") {
            Some(file) => (file, "index.html"),
            None => return StatusCode::NOT_FOUND.into_response(),
        },
    };
    let mime = mime_guess::from_path(name).first_or_octet_stream();
    (
        [(header::CONTENT_TYPE, mime.as_ref().to_owned())],
        file.data.into_owned(),
    )
        .into_response()
}
