use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use pl_app::{OpenMode, ProjectInfo};
use serde::Deserialize;

use crate::json::ApiJson;
use crate::{ApiError, AppState};

pub fn routes() -> Router<AppState> {
    Router::new().route("/project", get(get_project).post(open_project))
}

#[derive(Deserialize)]
struct OpenProjectRequest {
    path: String,
    mode: OpenMode,
}

async fn get_project(State(state): State<AppState>) -> Result<Json<ProjectInfo>, ApiError> {
    state.session.current().map(Json).map_err(ApiError)
}

async fn open_project(
    State(state): State<AppState>,
    ApiJson(request): ApiJson<OpenProjectRequest>,
) -> Result<Json<ProjectInfo>, ApiError> {
    let opened = {
        let state = state.clone();
        // Файловые операции короткие, но блокирующие: не держим рантайм.
        tokio::task::spawn_blocking(move || {
            state.session.open(&state.jobs, &request.path, request.mode)
        })
        .await
    };
    let info = opened
        .map_err(|_| {
            ApiError::new(
                pl_core::ProblemKind::Internal,
                "Не удалось открыть проект, повторите.",
            )
        })?
        .map_err(ApiError)?;
    // Записи прежнего проекта не должны остаться видны; записи нового разбираются фоновой задачей.
    state.sources.clear();
    pl_app::reload_sources(&state.jobs, &state.sources, &state.session).map_err(ApiError)?;
    Ok(Json(info))
}
