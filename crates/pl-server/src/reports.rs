//! Отчёт по проекту: Markdown или HTML текстом в JSON, чтобы браузер не отображал его как страницу.

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use pl_core::ProblemKind;
use serde::{Deserialize, Serialize};

use crate::json::ApiJson;
use crate::{ApiError, AppState};

pub fn routes() -> Router<AppState> {
    Router::new().route("/reports", post(create))
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum Format {
    Md,
    Html,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    format: Format,
    /// Прогон для отчёта; без значения — последний.
    #[serde(default)]
    run_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Report {
    format: Format,
    /// Предлагаемое имя файла при сохранении.
    file_name: String,
    content: String,
}

async fn create(
    State(state): State<AppState>,
    ApiJson(request): ApiJson<Request>,
) -> Result<Json<Report>, ApiError> {
    let report = tokio::task::spawn_blocking(move || {
        let data = pl_app::collect_report(
            &state.session,
            &state.sources,
            &state.actions,
            request.run_id.as_deref(),
        )?;
        let (content, ext) = match request.format {
            Format::Md => (pl_report::markdown(&data), "md"),
            Format::Html => (pl_report::html(&data), "html"),
        };
        Ok::<_, pl_core::Problem>(Report {
            format: request.format,
            file_name: format!("report.{ext}"),
            content,
        })
    })
    .await
    .map_err(|_| {
        ApiError::new(
            ProblemKind::Internal,
            "Операция завершилась сбоем, повторите.",
        )
    })?
    .map_err(ApiError)?;
    Ok(Json(report))
}
