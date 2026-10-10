//! Подсказки исследователю: границы сообщений, изменчивость байтов, пары запрос→ответ.
//! Всё — гипотезы с основаниями; ничего не сохраняется в проект.

use std::time::{Duration, Instant};

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use pl_app::{ExchangeView, VariabilityRequest};
use pl_core::ProblemKind;
use pl_interp::schema::Framing;
use serde::{Deserialize, Serialize};

use crate::json::ApiJson;
use crate::{ApiError, AppState};

/// Дольше этого подсказки не ищутся: ответ приходит с признаком `incomplete`.
const SEARCH_TIMEOUT: Duration = Duration::from_secs(20);
const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 500;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/analysis/framing", post(framing))
        .route("/analysis/variability", post(variability))
        .route("/exchanges", post(exchanges))
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, pl_core::Problem> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| {
            ApiError::new(
                ProblemKind::Internal,
                "Операция завершилась сбоем, повторите.",
            )
        })?
        .map_err(ApiError)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FramingRequest {
    streams: Vec<String>,
}

async fn framing(
    State(state): State<AppState>,
    ApiJson(request): ApiJson<FramingRequest>,
) -> Result<Json<pl_analysis::FramingHints>, ApiError> {
    let hints = blocking(move || {
        let started = Instant::now();
        pl_app::framing_hints(&state.sources, &request.streams, &|| {
            started.elapsed() > SEARCH_TIMEOUT
        })
    })
    .await?;
    Ok(Json(hints))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VariabilityBody {
    streams: Vec<String>,
    #[serde(default)]
    framing: Option<Framing>,
    #[serde(default)]
    message_id: Option<String>,
    #[serde(default)]
    length: Option<usize>,
}

async fn variability(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<VariabilityBody>,
) -> Result<Json<pl_analysis::Variability>, ApiError> {
    let result = blocking(move || {
        let started = Instant::now();
        pl_app::message_variability(
            &state.session,
            &state.sources,
            &VariabilityRequest {
                streams: body.streams,
                framing: body.framing,
                message_id: body.message_id,
                length: body.length,
            },
            &|| started.elapsed() > SEARCH_TIMEOUT,
        )
    })
    .await?;
    Ok(Json(result))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExchangesBody {
    connection: String,
    #[serde(default)]
    framing: Option<Framing>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExchangePage {
    items: Vec<ExchangeView>,
    total: usize,
    limit: usize,
    offset: usize,
    stats: pl_analysis::ExchangeStats,
}

async fn exchanges(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<ExchangesBody>,
) -> Result<Json<ExchangePage>, ApiError> {
    let limit = body.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(ApiError::new(
            ProblemKind::BadRequest,
            format!("limit — от 1 до {MAX_LIMIT}."),
        ));
    }
    let offset = body.offset.unwrap_or(0);
    let page = blocking(move || {
        let started = Instant::now();
        let (all, stats) = pl_app::connection_exchanges(
            &state.session,
            &state.sources,
            &body.connection,
            body.framing.as_ref(),
            &|| started.elapsed() > SEARCH_TIMEOUT,
        )?;
        let total = all.len();
        Ok(ExchangePage {
            items: all.into_iter().skip(offset).take(limit).collect(),
            total,
            limit,
            offset,
            stats,
        })
    })
    .await?;
    Ok(Json(page))
}
