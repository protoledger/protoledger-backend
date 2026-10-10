//! Интерпретация протокола: сохранение ревизий и предпросмотр применения к потоку.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use pl_app::{Session, stream_input};
use pl_core::{Problem, ProblemKind};
use pl_interp::{
    Category, FieldResult, Interpretation, MessageResult, SchemaError, StreamResult, Value,
    ViolationKind, schema::Status,
};
use serde::{Deserialize, Serialize};

use crate::json::ApiJson;
use crate::sources::resolve_stream;
use crate::{ApiError, AppState};

const DEFAULT_LIMIT: u64 = 100;
const MAX_LIMIT: u64 = 500;
/// Целые за пределами точного представления в JSON-числе отдаются строкой.
const SAFE_INT: i128 = 9_007_199_254_740_991;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/interpretation", get(current).put(save))
        .route("/interpretation/revisions", get(revisions))
        .route("/interpretation/revisions/{rev}", get(revision))
        .route("/interpretation/preview", post(preview))
}

fn schema_problem(e: SchemaError) -> ApiError {
    let detail = match &e {
        SchemaError::TooLarge => "Файл интерпретации больше 4 МиБ.".to_owned(),
        SchemaError::Yaml(why) => format!("Интерпретация не разобрана как YAML: {why}"),
        SchemaError::Invalid(why) => format!("Интерпретация не прошла проверку: {why}."),
    };
    ApiError(Problem::new(ProblemKind::Unprocessable, detail))
}

fn blocking_failed() -> ApiError {
    ApiError::new(
        ProblemKind::Internal,
        "Операция завершилась сбоем, повторите.",
    )
}

#[derive(Serialize)]
struct Doc {
    rev: u32,
    digest: String,
    yaml: String,
}

#[derive(Serialize)]
struct RevisionDto {
    rev: u32,
    digest: String,
}

#[derive(Serialize)]
struct RevisionList {
    items: Vec<RevisionDto>,
}

#[derive(Serialize)]
struct SaveResult {
    rev: u32,
    digest: String,
    created: bool,
}

#[derive(Deserialize)]
struct SaveRequest {
    yaml: String,
}

async fn current(State(state): State<AppState>) -> Result<Json<Doc>, ApiError> {
    let read = tokio::task::spawn_blocking(move || -> Result<Option<Doc>, Problem> {
        let guard = state.session.read();
        let project = guard.as_ref().ok_or_else(Session::no_project)?;
        Ok(project
            .current_interpretation()
            .map_err(Problem::from)?
            .map(|(r, yaml)| Doc {
                rev: r.rev,
                digest: r.digest,
                yaml,
            }))
    })
    .await
    .map_err(|_| blocking_failed())?
    .map_err(ApiError)?;
    read.map(Json).ok_or_else(|| {
        ApiError::new(
            ProblemKind::NotFound,
            "Интерпретация ещё не сохранена: передайте её через PUT /api/interpretation.",
        )
    })
}

async fn save(
    State(state): State<AppState>,
    ApiJson(request): ApiJson<SaveRequest>,
) -> Result<Json<SaveResult>, ApiError> {
    let saved = tokio::task::spawn_blocking(move || -> Result<SaveResult, ApiError> {
        // Сначала проверка: невалидное описание ревизией не становится.
        let parsed = Interpretation::parse(&request.yaml).map_err(schema_problem)?;
        let digest = parsed.digest();
        let mut guard = state.session.write();
        let project = guard
            .as_mut()
            .ok_or_else(|| ApiError(Session::no_project()))?;
        let (record, created) = project
            .save_interpretation(&request.yaml, &digest)
            .map_err(|e| ApiError(e.into()))?;
        Ok(SaveResult {
            rev: record.rev,
            digest: record.digest,
            created,
        })
    })
    .await
    .map_err(|_| blocking_failed())??;
    Ok(Json(saved))
}

async fn revisions(State(state): State<AppState>) -> Result<Json<RevisionList>, ApiError> {
    let guard = state.session.read();
    let project = guard
        .as_ref()
        .ok_or_else(|| ApiError(Session::no_project()))?;
    Ok(Json(RevisionList {
        items: project
            .interpretation_revisions()
            .iter()
            .map(|r| RevisionDto {
                rev: r.rev,
                digest: r.digest.clone(),
            })
            .collect(),
    }))
}

async fn revision(
    State(state): State<AppState>,
    Path(rev): Path<u32>,
) -> Result<Json<Doc>, ApiError> {
    let doc = tokio::task::spawn_blocking(move || -> Result<Doc, Problem> {
        let guard = state.session.read();
        let project = guard.as_ref().ok_or_else(Session::no_project)?;
        let (r, yaml) = project.read_interpretation(rev).map_err(Problem::from)?;
        Ok(Doc {
            rev: r.rev,
            digest: r.digest,
            yaml,
        })
    })
    .await
    .map_err(|_| blocking_failed())?
    .map_err(ApiError)?;
    Ok(Json(doc))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreviewRequest {
    stream: String,
    yaml: Option<String>,
    category: Option<Category>,
    limit: Option<u64>,
    offset: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FieldDto {
    name: String,
    at: u64,
    len: u64,
    status: Status,
    hypothesis: Option<String>,
    state: pl_interp::FieldState,
    value_type: Option<&'static str>,
    value: Option<serde_json::Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ViolationDto {
    kind: ViolationKind,
    id: String,
    detail: String,
    status: Status,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MessageDto {
    start: u64,
    end: u64,
    category: Category,
    message_id: Option<String>,
    unknown_bytes: u64,
    fields: Vec<FieldDto>,
    violations: Vec<ViolationDto>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreviewPage {
    /// Ревизия, если применялась сохранённая интерпретация.
    rev: Option<u32>,
    digest: String,
    out_of_scope: bool,
    counts: std::collections::BTreeMap<Category, u64>,
    unknown_bytes: u64,
    items: Vec<MessageDto>,
    total: u64,
    limit: u64,
    offset: u64,
}

fn value_json(v: &Value) -> (&'static str, serde_json::Value) {
    match v {
        Value::Int(i) if i.abs() <= SAFE_INT => (
            "int",
            serde_json::Value::from(i64::try_from(*i).unwrap_or(0)),
        ),
        Value::Int(i) => ("int", serde_json::Value::String(i.to_string())),
        Value::Bool(b) => ("bool", serde_json::Value::Bool(*b)),
        Value::Str(s) => ("string", serde_json::Value::String(s.clone())),
        Value::Bytes(_) => ("bytes", serde_json::Value::String(v.to_string())),
    }
}

fn field_dto(f: &FieldResult) -> FieldDto {
    let (value_type, value) = match f.value.as_ref().map(value_json) {
        Some((t, v)) => (Some(t), Some(v)),
        None => (None, None),
    };
    FieldDto {
        name: f.name.clone(),
        at: f.at,
        len: f.len,
        status: f.status,
        hypothesis: f.hypothesis.clone(),
        state: f.state,
        value_type,
        value,
    }
}

fn message_dto(m: &MessageResult) -> MessageDto {
    MessageDto {
        start: m.start,
        end: m.end,
        category: m.category,
        message_id: m.message_id.clone(),
        unknown_bytes: m.unknown_bytes,
        fields: m.fields.iter().map(field_dto).collect(),
        violations: m
            .violations
            .iter()
            .map(|v| ViolationDto {
                kind: v.kind,
                id: v.id.clone(),
                detail: v.detail.clone(),
                status: v.status,
            })
            .collect(),
    }
}

/// Применяет интерпретацию к потоку без сохранения результатов.
async fn preview(
    State(state): State<AppState>,
    ApiJson(request): ApiJson<PreviewRequest>,
) -> Result<Json<PreviewPage>, ApiError> {
    let limit = request.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(ApiError::new(
            ProblemKind::BadRequest,
            format!("limit — от 1 до {MAX_LIMIT}."),
        ));
    }
    let offset = request.offset.unwrap_or(0);
    let page = tokio::task::spawn_blocking(move || -> Result<PreviewPage, ApiError> {
        let (rev, yaml) = match request.yaml {
            Some(yaml) => (None, yaml),
            None => {
                let guard = state.session.read();
                let project = guard
                    .as_ref()
                    .ok_or_else(|| ApiError(Session::no_project()))?;
                let (r, yaml) = project
                    .current_interpretation()
                    .map_err(|e| ApiError(e.into()))?
                    .ok_or_else(|| {
                        ApiError::new(
                            ProblemKind::NotFound,
                            "Интерпретация ещё не сохранена: передайте yaml в запросе.",
                        )
                    })?;
                (Some(r.rev), yaml)
            }
        };
        let it = Interpretation::parse(&yaml).map_err(schema_problem)?;
        let (data, conn, dir) = resolve_stream(&state, &request.stream)?;
        let connection = data
            .connections
            .get(conn)
            .ok_or_else(|| ApiError::new(ProblemKind::NotFound, "Потока нет."))?;
        let stream = connection
            .streams
            .get(dir)
            .ok_or_else(|| ApiError::new(ProblemKind::NotFound, "Потока нет."))?;
        let input = stream_input(&data.file, connection, stream, dir);
        let result: StreamResult = pl_interp::apply(&it, &input, &|| false).map_err(|e| {
            ApiError(Problem::new(
                ProblemKind::LimitExceeded,
                format!("Разбор остановлен: {e}."),
            ))
        })?;
        let selected: Vec<&MessageResult> = result
            .messages
            .iter()
            .filter(|m| request.category.is_none_or(|c| m.category == c))
            .collect();
        let items = selected
            .iter()
            .skip(usize::try_from(offset).unwrap_or(usize::MAX))
            .take(limit as usize)
            .map(|m| message_dto(m))
            .collect();
        Ok(PreviewPage {
            rev,
            digest: it.digest(),
            out_of_scope: result.out_of_scope,
            counts: result.counts(),
            unknown_bytes: result.unknown_bytes(),
            items,
            total: selected.len() as u64,
            limit,
            offset,
        })
    })
    .await
    .map_err(|_| blocking_failed())??;
    Ok(Json(page))
}
