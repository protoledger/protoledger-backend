use axum::extract::State;
use axum::routing::{get, patch};
use axum::{Json, Router};
use pl_app::{OpenMode, ProjectInfo, SettingsPatch};
use serde::Deserialize;

use crate::json::ApiJson;
use crate::{ApiError, AppState};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/project", get(get_project).post(open_project))
        .route("/project/settings", patch(update_settings))
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
    // Журналы действий небольшие: заново разбираются сразу, без задачи.
    pl_app::reload_action_logs(&state.session, &state.actions);
    pl_app::reload_sources(&state.jobs, &state.sources, &state.session).map_err(ApiError)?;
    Ok(Json(info))
}

/// Меняет политики сборки и заново собирает записи проекта фоновой задачей.
async fn update_settings(
    State(state): State<AppState>,
    ApiJson(patch): ApiJson<SettingsPatch>,
) -> Result<Json<ProjectInfo>, ApiError> {
    let updated = {
        let state = state.clone();
        tokio::task::spawn_blocking(move || state.session.update_settings(&state.jobs, patch)).await
    };
    let (info, changed) = updated
        .map_err(|_| {
            ApiError::new(
                pl_core::ProblemKind::Internal,
                "Не удалось сохранить настройки, повторите.",
            )
        })?
        .map_err(ApiError)?;
    if changed {
        state.sources.clear();
        pl_app::reload_sources(&state.jobs, &state.sources, &state.session).map_err(ApiError)?;
    }
    Ok(Json(info))
}
