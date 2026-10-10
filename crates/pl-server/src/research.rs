//! Наблюдения, гипотезы и вопросы исследователя.

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use pl_app::{
    AnchorRef, AnchorState, Evidence, Hypothesis, HypothesisInput, Observation, Question,
    QuestionStatus, TestOptions,
};
use pl_core::ProblemKind;
use serde::{Deserialize, Serialize};

use crate::json::ApiJson;
use crate::{ApiError, AppState};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/observations",
            get(list_observations).post(create_observation),
        )
        .route(
            "/observations/{id}",
            get(show_observation)
                .put(edit_observation)
                .delete(remove_observation),
        )
        .route("/hypotheses", get(list_hypotheses).post(create_hypothesis))
        .route(
            "/hypotheses/{id}",
            get(show_hypothesis)
                .put(edit_hypothesis)
                .delete(remove_hypothesis),
        )
        .route("/hypotheses/{id}/test", post(run_test))
        .route("/questions", get(list_questions).post(create_question))
        .route(
            "/questions/{id}",
            axum::routing::put(edit_question).delete(remove_question),
        )
}

fn blocking_failed() -> ApiError {
    ApiError::new(
        ProblemKind::Internal,
        "Операция завершилась сбоем, повторите.",
    )
}

/// Файловые операции с проектом короткие, но блокирующие.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, pl_core::Problem> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| blocking_failed())?
        .map_err(ApiError)
}

// ------------------------------------------------------------ наблюдения

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ObservationDto {
    #[serde(flatten)]
    observation: Observation,
    anchor_state: AnchorState,
}

fn observation_dto(state: &AppState, o: Observation) -> ObservationDto {
    ObservationDto {
        anchor_state: pl_app::anchor_state(&state.sources, &o.anchor),
        observation: o,
    }
}

#[derive(Serialize)]
struct ItemList<T> {
    items: Vec<T>,
}

async fn list_observations(
    State(state): State<AppState>,
) -> Result<Json<ItemList<ObservationDto>>, ApiError> {
    let items = blocking({
        let state = state.clone();
        move || pl_app::research_load::<Observation>(&state.session)
    })
    .await?;
    Ok(Json(ItemList {
        items: items
            .into_iter()
            .map(|o| observation_dto(&state, o))
            .collect(),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewObservation {
    anchor: NewAnchor,
    comment: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewAnchor {
    source: String,
    stream: String,
    start: u64,
    end: u64,
}

async fn create_observation(
    State(state): State<AppState>,
    ApiJson(request): ApiJson<NewObservation>,
) -> Result<(StatusCode, Json<ObservationDto>), ApiError> {
    let anchor = AnchorRef {
        source: request.anchor.source,
        stream: request.anchor.stream,
        start: request.anchor.start,
        end: request.anchor.end,
        sha256: None,
    };
    let created = blocking({
        let state = state.clone();
        move || pl_app::add_observation(&state.session, &state.sources, anchor, request.comment)
    })
    .await?;
    Ok((StatusCode::CREATED, Json(observation_dto(&state, created))))
}

async fn show_observation(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ObservationDto>, ApiError> {
    let item = blocking({
        let state = state.clone();
        move || pl_app::research_get::<Observation>(&state.session, &id)
    })
    .await?;
    Ok(Json(observation_dto(&state, item)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EditObservation {
    comment: String,
}

async fn edit_observation(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(request): ApiJson<EditObservation>,
) -> Result<Json<ObservationDto>, ApiError> {
    let item = blocking({
        let state = state.clone();
        move || pl_app::update_observation(&state.session, &id, request.comment)
    })
    .await?;
    Ok(Json(observation_dto(&state, item)))
}

async fn remove_observation(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    blocking(move || pl_app::delete_observation(&state.session, &id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

// --------------------------------------------------------------- гипотезы

async fn list_hypotheses(
    State(state): State<AppState>,
) -> Result<Json<ItemList<Hypothesis>>, ApiError> {
    let items = blocking(move || pl_app::research_load::<Hypothesis>(&state.session)).await?;
    Ok(Json(ItemList { items }))
}

async fn create_hypothesis(
    State(state): State<AppState>,
    ApiJson(input): ApiJson<HypothesisInput>,
) -> Result<(StatusCode, Json<Hypothesis>), ApiError> {
    let created = blocking(move || pl_app::add_hypothesis(&state.session, input)).await?;
    Ok((StatusCode::CREATED, Json(created)))
}

async fn show_hypothesis(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Hypothesis>, ApiError> {
    Ok(Json(
        blocking(move || pl_app::research_get::<Hypothesis>(&state.session, &id)).await?,
    ))
}

async fn edit_hypothesis(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(input): ApiJson<HypothesisInput>,
) -> Result<Json<Hypothesis>, ApiError> {
    Ok(Json(
        blocking(move || pl_app::update_hypothesis(&state.session, &id, input)).await?,
    ))
}

async fn remove_hypothesis(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    blocking(move || pl_app::delete_hypothesis(&state.session, &id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TestRequest {
    /// Журнал действий; без значения — все журналы проекта.
    #[serde(default)]
    log_id: Option<String>,
    /// Окно между действием и сообщением, мс.
    #[serde(default)]
    window_ms: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TestResult {
    hypothesis: String,
    statement: String,
    status: pl_app::HypothesisStatus,
    #[serde(flatten)]
    evidence: Evidence,
}

/// Проверяет тест гипотезы на всех записях проекта. Результат не меняет статус гипотезы: статус ставит исследователь.
async fn run_test(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(request): ApiJson<TestRequest>,
) -> Result<Json<TestResult>, ApiError> {
    if request.window_ms.is_some_and(|w| w > 600_000) {
        return Err(ApiError::new(
            ProblemKind::BadRequest,
            "windowMs — не больше 600000.",
        ));
    }
    let result = blocking(move || {
        let hypothesis = pl_app::research_get::<Hypothesis>(&state.session, &id)?;
        let expr = hypothesis.test.clone().ok_or_else(|| {
            pl_core::Problem::new(ProblemKind::Conflict, format!("У гипотезы {id} нет теста: добавьте выражение в поле test."))
        })?;
        let interpretation = pl_app::current_interpretation(&state.session).ok_or_else(|| {
            pl_core::Problem::new(ProblemKind::Conflict, "Интерпретации ещё нет: тест применяется к полям сообщений, сохраните её через PUT /api/interpretation.")
        })?;
        let logs = match &request.log_id {
            Some(log) => vec![state.actions.get(log).ok_or_else(|| {
                pl_core::Problem::new(ProblemKind::NotFound, format!("Журнала действий {log} нет."))
            })?],
            None => state.actions.list(),
        };
        let options = TestOptions { window_ms: request.window_ms.unwrap_or(pl_app::DEFAULT_WINDOW_MS) };
        let evidence = pl_app::test_hypothesis(&pl_app::all_sources(&state.sources), &interpretation, &logs, &expr, &options)?;
        Ok(TestResult { hypothesis: hypothesis.id, statement: hypothesis.statement, status: hypothesis.status, evidence })
    })
    .await?;
    Ok(Json(result))
}

// ---------------------------------------------------------------- вопросы

async fn list_questions(
    State(state): State<AppState>,
) -> Result<Json<ItemList<Question>>, ApiError> {
    let items = blocking(move || pl_app::research_load::<Question>(&state.session)).await?;
    Ok(Json(ItemList { items }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewQuestion {
    text: String,
}

async fn create_question(
    State(state): State<AppState>,
    ApiJson(request): ApiJson<NewQuestion>,
) -> Result<(StatusCode, Json<Question>), ApiError> {
    let created = blocking(move || pl_app::add_question(&state.session, request.text)).await?;
    Ok((StatusCode::CREATED, Json(created)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EditQuestion {
    text: Option<String>,
    status: Option<QuestionStatus>,
    answer: Option<String>,
}

async fn edit_question(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(request): ApiJson<EditQuestion>,
) -> Result<Json<Question>, ApiError> {
    Ok(Json(
        blocking(move || {
            pl_app::update_question(
                &state.session,
                &id,
                request.text,
                request.status,
                request.answer,
            )
        })
        .await?,
    ))
}

async fn remove_question(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    blocking(move || pl_app::delete_question(&state.session, &id)).await?;
    Ok(StatusCode::NO_CONTENT)
}
