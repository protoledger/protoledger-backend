//! Прогоны проверки: запуск задачей, сводка, контрпримеры, таблица сообщений, сравнение.

use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::routing::get;
use axum::{Json, Router};
use pl_app::Session;
use pl_core::ProblemKind;
use pl_interp::Category;
use pl_verify::{
    Change, ChangeKind, CorpusFilter, Counterexample, DiffTotals, Run, StaleReason, Summary,
};
use serde::{Deserialize, Serialize};

use crate::json::ApiJson;
use crate::{ApiError, AppState};

const DEFAULT_LIMIT: u64 = 100;
const MAX_LIMIT: u64 = 500;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/runs", get(list).post(start))
        .route("/runs/diff", get(diff))
        .route("/runs/{id}", get(show))
        .route("/runs/{id}/items", get(items))
}

fn blocking_failed() -> ApiError {
    ApiError::new(
        ProblemKind::Internal,
        "Операция завершилась сбоем, повторите.",
    )
}

fn bad_request(detail: impl Into<String>) -> ApiError {
    ApiError::new(ProblemKind::BadRequest, detail)
}

fn query<T>(q: Result<Query<T>, QueryRejection>) -> Result<T, ApiError> {
    q.map(|Query(v)| v)
        .map_err(|e| bad_request(format!("Некорректные параметры запроса: {}", e.body_text())))
}

fn page(limit: Option<u64>, offset: Option<u64>) -> Result<(usize, usize), ApiError> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(bad_request(format!("limit — от 1 до {MAX_LIMIT}.")));
    }
    Ok((
        limit as usize,
        usize::try_from(offset.unwrap_or(0)).unwrap_or(usize::MAX),
    ))
}

// ------------------------------------------------------------------ запуск

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartRequest {
    #[serde(default)]
    corpus: CorpusFilter,
    #[serde(default)]
    revision: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JobAccepted {
    job_id: String,
}

async fn start(
    State(state): State<AppState>,
    ApiJson(request): ApiJson<StartRequest>,
) -> Result<(StatusCode, HeaderMap, Json<JobAccepted>), ApiError> {
    let job_id = pl_app::start_verify(
        &state.jobs,
        &state.sources,
        &state.session,
        request.corpus,
        request.revision,
    )?;
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&format!("/api/jobs/{job_id}")) {
        headers.insert(header::LOCATION, v);
    }
    Ok((StatusCode::ACCEPTED, headers, Json(JobAccepted { job_id })))
}

// ------------------------------------------------------------------ чтение

fn read_run(state: &AppState, id: &str) -> Result<(Run, Vec<StaleReason>), ApiError> {
    let text = {
        let guard = state.session.read();
        let project = guard
            .as_ref()
            .ok_or_else(|| ApiError(Session::no_project()))?;
        project.read_run(id).map_err(|e| ApiError(e.into()))?
    };
    let run: Run = serde_json::from_str(&text).map_err(|_| {
        ApiError::new(
            ProblemKind::Unprocessable,
            format!("Файл прогона {id} повреждён."),
        )
    })?;
    let stale = pl_app::current_signature(&state.session, &state.sources)
        .map(|c| pl_verify::stale_reasons(&run, &c))
        .unwrap_or_default();
    Ok((run, stale))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunHead {
    id: String,
    revision: Option<u32>,
    interpretation_digest: String,
    settings_digest: String,
    corpus: CorpusFilter,
    sources: Vec<String>,
    engine_version: String,
    summary: Summary,
    stale: bool,
    stale_reasons: Vec<StaleReason>,
}

fn head(run: &Run, stale: Vec<StaleReason>) -> RunHead {
    RunHead {
        id: run.id.clone(),
        revision: run.inputs.revision,
        interpretation_digest: run.inputs.interpretation_digest.clone(),
        settings_digest: run.inputs.settings_digest.clone(),
        corpus: run.inputs.corpus.clone(),
        sources: run.inputs.sources.clone(),
        engine_version: run.inputs.engine_version.clone(),
        summary: run.summary.clone(),
        stale: !stale.is_empty(),
        stale_reasons: stale,
    }
}

#[derive(Deserialize)]
struct PageQuery {
    limit: Option<u64>,
    offset: Option<u64>,
}

#[derive(Serialize)]
struct RunList {
    items: Vec<RunHead>,
    total: u64,
    limit: u64,
    offset: u64,
}

async fn list(
    State(state): State<AppState>,
    q: Result<Query<PageQuery>, QueryRejection>,
) -> Result<Json<RunList>, ApiError> {
    let q = query(q)?;
    let (limit, offset) = page(q.limit, q.offset)?;
    let result = tokio::task::spawn_blocking(move || -> Result<RunList, ApiError> {
        let ids: Vec<String> = {
            let guard = state.session.read();
            let project = guard
                .as_ref()
                .ok_or_else(|| ApiError(Session::no_project()))?;
            project
                .run_ids()
                .into_iter()
                .rev()
                .map(str::to_owned)
                .collect()
        };
        let total = ids.len() as u64;
        let mut items = Vec::new();
        for id in ids.iter().skip(offset).take(limit) {
            let (run, stale) = read_run(&state, id)?;
            items.push(head(&run, stale));
        }
        Ok(RunList {
            items,
            total,
            limit: limit as u64,
            offset: offset as u64,
        })
    })
    .await
    .map_err(|_| blocking_failed())??;
    Ok(Json(result))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StreamHead {
    id: String,
    source: String,
    out_of_scope: bool,
    counts: std::collections::BTreeMap<Category, u64>,
    unknown_bytes: u64,
    message_bytes: u64,
    messages: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunDetail {
    #[serde(flatten)]
    head: RunHead,
    streams: Vec<StreamHead>,
    counterexamples: Vec<Counterexample>,
}

async fn show(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<RunDetail>, ApiError> {
    let detail = tokio::task::spawn_blocking(move || -> Result<RunDetail, ApiError> {
        let (run, stale) = read_run(&state, &id)?;
        Ok(RunDetail {
            streams: run
                .streams
                .iter()
                .map(|s| StreamHead {
                    id: s.id.clone(),
                    source: s.source.clone(),
                    out_of_scope: s.out_of_scope,
                    counts: s.counts.clone(),
                    unknown_bytes: s.unknown_bytes,
                    message_bytes: s.message_bytes,
                    messages: s.messages.len() as u64,
                })
                .collect(),
            counterexamples: run.counterexamples.clone(),
            head: head(&run, stale),
        })
    })
    .await
    .map_err(|_| blocking_failed())??;
    Ok(Json(detail))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ItemsQuery {
    stream: Option<String>,
    category: Option<Category>,
    message_id: Option<String>,
    limit: Option<u64>,
    offset: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ItemDto {
    stream: String,
    start: u64,
    end: u64,
    category: Category,
    message_id: Option<String>,
}

#[derive(Serialize)]
struct ItemPage {
    items: Vec<ItemDto>,
    total: u64,
    limit: u64,
    offset: u64,
}

async fn items(
    State(state): State<AppState>,
    Path(id): Path<String>,
    q: Result<Query<ItemsQuery>, QueryRejection>,
) -> Result<Json<ItemPage>, ApiError> {
    let q = query(q)?;
    let (limit, offset) = page(q.limit, q.offset)?;
    let result = tokio::task::spawn_blocking(move || -> Result<ItemPage, ApiError> {
        let (run, _) = read_run(&state, &id)?;
        let selected = run
            .streams
            .iter()
            .filter(|s| q.stream.as_ref().is_none_or(|w| &s.id == w))
            .flat_map(|s| s.messages.iter().map(move |m| (s, m)))
            .filter(|(_, m)| q.category.is_none_or(|c| m.2 == c))
            .filter(|(_, m)| {
                q.message_id
                    .as_ref()
                    .is_none_or(|w| m.3.as_ref() == Some(w) || (w == "?" && m.3.is_none()))
            });
        let mut total = 0u64;
        let mut items = Vec::new();
        for (s, m) in selected {
            if total as usize >= offset && items.len() < limit {
                items.push(ItemDto {
                    stream: s.id.clone(),
                    start: m.0,
                    end: m.1,
                    category: m.2,
                    message_id: m.3.clone(),
                });
            }
            total += 1;
        }
        Ok(ItemPage {
            items,
            total,
            limit: limit as u64,
            offset: offset as u64,
        })
    })
    .await
    .map_err(|_| blocking_failed())??;
    Ok(Json(result))
}

// --------------------------------------------------------------- сравнение

#[derive(Deserialize)]
struct DiffQuery {
    a: String,
    b: String,
    kind: Option<ChangeKind>,
    limit: Option<u64>,
    offset: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DiffPage {
    a: String,
    b: String,
    stale_a: bool,
    stale_b: bool,
    totals: DiffTotals,
    counts_a: std::collections::BTreeMap<Category, u64>,
    counts_b: std::collections::BTreeMap<Category, u64>,
    items: Vec<Change>,
    total: u64,
    limit: u64,
    offset: u64,
}

async fn diff(
    State(state): State<AppState>,
    q: Result<Query<DiffQuery>, QueryRejection>,
) -> Result<Json<DiffPage>, ApiError> {
    let q = query(q)?;
    let (limit, offset) = page(q.limit, q.offset)?;
    let result = tokio::task::spawn_blocking(move || -> Result<DiffPage, ApiError> {
        let (a, stale_a) = read_run(&state, &q.a)?;
        let (b, stale_b) = read_run(&state, &q.b)?;
        let d = pl_verify::diff(&a, &b);
        let selected: Vec<&Change> = d
            .changes
            .iter()
            .filter(|c| q.kind.is_none_or(|k| c.kind == k))
            .collect();
        Ok(DiffPage {
            a: d.a.clone(),
            b: d.b.clone(),
            stale_a: !stale_a.is_empty(),
            stale_b: !stale_b.is_empty(),
            totals: d.totals.clone(),
            counts_a: d.counts_a.clone(),
            counts_b: d.counts_b.clone(),
            total: selected.len() as u64,
            items: selected
                .into_iter()
                .skip(offset)
                .take(limit)
                .cloned()
                .collect(),
            limit: limit as u64,
            offset: offset as u64,
        })
    })
    .await
    .map_err(|_| blocking_failed())??;
    Ok(Json(result))
}
