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
        .route("/interpretation/field-hints", post(field_hints))
        .route("/interpretation/fix-hints", post(fix_hints))
        .route("/interpretation/coverage", post(coverage))
        .route("/interpretation/graph", post(graph))
        .route("/interpretation/compare", post(compare))
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
    /// То же описание разобранным: интерфейс показывает и правит его без текста YAML.
    structure: serde_json::Value,
}

/// Разобранное описание как JSON; текст в проекте уже прошёл проверку при сохранении.
fn structure_of(yaml: &str) -> serde_json::Value {
    Interpretation::parse(yaml)
        .ok()
        .and_then(|i| serde_json::to_value(i).ok())
        .unwrap_or(serde_json::Value::Null)
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
#[serde(rename_all = "camelCase")]
struct SaveRequest {
    /// Текст описания; вместо него можно передать `structure`.
    #[serde(default)]
    yaml: Option<String>,
    /// Описание структурой (как в ответе GET): сохраняется как YAML.
    #[serde(default)]
    structure: Option<serde_json::Value>,
    /// Ревизия, от которой сделана правка (0 — интерпретации ещё не было).
    base_rev: Option<u32>,
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
                structure: structure_of(&yaml),
                yaml,
            }))
    })
    .await
    .map_err(|_| blocking_failed())?
    .map_err(ApiError)?;
    read.map(Json).ok_or_else(|| {
        ApiError::new(
            ProblemKind::NotFound,
            "Описание протокола ещё не составлено: на экране «Протокол» нажмите «Составить описание».",
        )
    })
}

async fn save(
    State(state): State<AppState>,
    ApiJson(request): ApiJson<SaveRequest>,
) -> Result<Json<SaveResult>, ApiError> {
    let saved = tokio::task::spawn_blocking(move || -> Result<SaveResult, ApiError> {
        // Сначала проверка: невалидное описание ревизией не становится.
        let text = match (request.yaml, request.structure) {
            (Some(yaml), None) => yaml,
            (None, Some(structure)) => {
                let parsed: Interpretation = serde_json::from_value(structure).map_err(|e| {
                    ApiError::new(
                        ProblemKind::Unprocessable,
                        format!("Описание не прошло проверку: {e}."),
                    )
                })?;
                parsed.to_yaml().map_err(schema_problem)?
            }
            _ => {
                return Err(ApiError::new(
                    ProblemKind::BadRequest,
                    "Передайте описание одним способом: текстом yaml или структурой structure.",
                ));
            }
        };
        let parsed = Interpretation::parse(&text).map_err(schema_problem)?;
        let digest = parsed.digest();
        let mut guard = state.session.write();
        let project = guard
            .as_mut()
            .ok_or_else(|| ApiError(Session::no_project()))?;
        // Правка от устаревшей ревизии молча затёрла бы чужую (другая вкладка, «Применить кандидата»).
        // Тот же смысл, что у последней ревизии, — не конфликт: новой ревизии всё равно не будет.
        if let Some(base) = request.base_rev {
            let last = project.interpretation_revisions().last();
            let latest = last.map_or(0, |r| r.rev);
            let same = last.is_some_and(|r| r.digest == digest);
            if base != latest && !same {
                // Ревизии новее последней в проекте нет: правку делали в другом проекте.
                let detail = match (base > latest, latest) {
                    (true, 0) => format!(
                        "Правка сделана от ревизии {base}, а в открытом проекте описания ещё нет: похоже, открыт другой проект. Обновите страницу."
                    ),
                    (true, _) => format!(
                        "Правка сделана от ревизии {base}, а последняя ревизия открытого проекта — {latest}: похоже, открыт другой проект. Обновите страницу."
                    ),
                    (false, _) => format!(
                        "Описание изменилось: правка сделана от ревизии {base}, а после неё сохранена ревизия {latest}. Откройте ревизию {latest} и перенесите правку."
                    ),
                };
                return Err(ApiError::new(ProblemKind::Conflict, detail));
            }
        }
        let (record, created) = project
            .save_interpretation(&text, &digest)
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
    Path(rev): Path<String>,
) -> Result<Json<Doc>, ApiError> {
    // Номер разбирается здесь, чтобы отказ пришёл в общем формате ошибок, а не текстом фреймворка.
    let rev: u32 = rev
        .parse()
        .map_err(|_| ApiError::new(ProblemKind::BadRequest, "Номер ревизии — целое число от 1."))?;
    let doc = tokio::task::spawn_blocking(move || -> Result<Doc, Problem> {
        let guard = state.session.read();
        let project = guard.as_ref().ok_or_else(Session::no_project)?;
        let (r, yaml) = project.read_interpretation(rev).map_err(Problem::from)?;
        Ok(Doc {
            rev: r.rev,
            digest: r.digest,
            structure: structure_of(&yaml),
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompareRequest {
    /// Первый и второй наборы записей (sha256).
    a: Vec<String>,
    b: Vec<String>,
    /// Несохранённый текст описания; без него берётся текущая ревизия.
    yaml: Option<String>,
}

/// Сравнение поведения в двух наборах записей по одному описанию.
async fn compare(
    State(state): State<AppState>,
    ApiJson(request): ApiJson<CompareRequest>,
) -> Result<Json<pl_app::Comparison>, ApiError> {
    if request.a.is_empty() || request.b.is_empty() {
        return Err(ApiError::new(
            ProblemKind::BadRequest,
            "Нужны оба набора записей: a и b — хотя бы по одной записи.",
        ));
    }
    let result = tokio::task::spawn_blocking(move || -> Result<pl_app::Comparison, ApiError> {
        let yaml = match request.yaml {
            Some(yaml) => yaml,
            None => {
                let guard = state.session.read();
                let project = guard
                    .as_ref()
                    .ok_or_else(|| ApiError(Session::no_project()))?;
                project
                    .current_interpretation()
                    .map_err(|e| ApiError(e.into()))?
                    .ok_or_else(|| {
                        ApiError::new(
                            ProblemKind::NotFound,
                            "Интерпретация ещё не сохранена: передайте yaml в запросе.",
                        )
                    })?
                    .1
            }
        };
        if state.session.read().is_none() {
            return Err(ApiError(Session::no_project()));
        }
        let it = Interpretation::parse(&yaml).map_err(schema_problem)?;
        let all = pl_app::all_sources(&state.sources);
        let pick = |wanted: &[String]| {
            wanted
                .iter()
                .map(|sha| {
                    all.iter()
                        .find(|s| &s.sha256 == sha)
                        .cloned()
                        .ok_or_else(|| {
                            ApiError::new(
                                ProblemKind::NotFound,
                                format!("Записи {sha} нет в проекте."),
                            )
                        })
                })
                .collect::<Result<Vec<_>, _>>()
        };
        let (a, b) = (pick(&request.a)?, pick(&request.b)?);
        let started = std::time::Instant::now();
        pl_app::compare(&a, &b, &it, &|| {
            started.elapsed() > std::time::Duration::from_secs(20)
        })
        .map_err(ApiError)
    })
    .await
    .map_err(|_| blocking_failed())??;
    Ok(Json(result))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CoverageRequest {
    /// Несохранённый текст описания; без него берётся текущая ревизия.
    yaml: Option<String>,
    /// Записи (sha256); без значения — все записи проекта.
    sources: Option<Vec<String>>,
}

/// Граф обмена: типы сообщений, ответы на них и переходы между запросами.
async fn graph(
    State(state): State<AppState>,
    ApiJson(request): ApiJson<CoverageRequest>,
) -> Result<Json<pl_app::ExchangeGraph>, ApiError> {
    let result = tokio::task::spawn_blocking(move || -> Result<pl_app::ExchangeGraph, ApiError> {
        let yaml = match request.yaml {
            Some(yaml) => yaml,
            None => {
                let guard = state.session.read();
                let project = guard
                    .as_ref()
                    .ok_or_else(|| ApiError(Session::no_project()))?;
                project
                    .current_interpretation()
                    .map_err(|e| ApiError(e.into()))?
                    .ok_or_else(|| {
                        ApiError::new(
                            ProblemKind::NotFound,
                            "Интерпретация ещё не сохранена: передайте yaml в запросе.",
                        )
                    })?
                    .1
            }
        };
        if state.session.read().is_none() {
            return Err(ApiError(Session::no_project()));
        }
        let it = Interpretation::parse(&yaml).map_err(schema_problem)?;
        let mut sources = pl_app::all_sources(&state.sources);
        if let Some(wanted) = &request.sources {
            if let Some(missing) = wanted
                .iter()
                .find(|sha| !sources.iter().any(|s| &s.sha256 == *sha))
            {
                return Err(ApiError::new(
                    ProblemKind::NotFound,
                    format!("Записи {missing} нет в проекте."),
                ));
            }
            sources.retain(|s| wanted.contains(&s.sha256));
        }
        let started = std::time::Instant::now();
        pl_app::exchange_graph(&sources, &it, &|| {
            started.elapsed() > std::time::Duration::from_secs(20)
        })
        .map_err(ApiError)
    })
    .await
    .map_err(|_| blocking_failed())??;
    Ok(Json(result))
}

/// Карта покрытия: какие байты сообщений каждого типа описаны и насколько твёрдо.
async fn coverage(
    State(state): State<AppState>,
    ApiJson(request): ApiJson<CoverageRequest>,
) -> Result<Json<pl_app::Coverage>, ApiError> {
    let map = tokio::task::spawn_blocking(move || -> Result<pl_app::Coverage, ApiError> {
        let yaml = match request.yaml {
            Some(yaml) => yaml,
            None => {
                let guard = state.session.read();
                let project = guard
                    .as_ref()
                    .ok_or_else(|| ApiError(Session::no_project()))?;
                project
                    .current_interpretation()
                    .map_err(|e| ApiError(e.into()))?
                    .ok_or_else(|| {
                        ApiError::new(
                            ProblemKind::NotFound,
                            "Интерпретация ещё не сохранена: передайте yaml в запросе.",
                        )
                    })?
                    .1
            }
        };
        if state.session.read().is_none() {
            return Err(ApiError(Session::no_project()));
        }
        let it = Interpretation::parse(&yaml).map_err(schema_problem)?;
        let mut sources = pl_app::all_sources(&state.sources);
        if let Some(wanted) = &request.sources {
            if let Some(missing) = wanted
                .iter()
                .find(|sha| !sources.iter().any(|s| &s.sha256 == *sha))
            {
                return Err(ApiError::new(
                    ProblemKind::NotFound,
                    format!("Записи {missing} нет в проекте."),
                ));
            }
            sources.retain(|s| wanted.contains(&s.sha256));
        }
        let started = std::time::Instant::now();
        pl_app::coverage(&sources, &it, &|| {
            started.elapsed() > std::time::Duration::from_secs(20)
        })
        .map_err(ApiError)
    })
    .await
    .map_err(|_| blocking_failed())??;
    Ok(Json(map))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FixHintsRequest {
    hypothesis: String,
    /// Несохранённый текст описания; без него берётся текущая ревизия.
    yaml: Option<String>,
    window_ms: Option<u64>,
}

/// Подсказка исправления гипотезы: какая правка поля или теста убирает контрпримеры.
async fn fix_hints(
    State(state): State<AppState>,
    ApiJson(request): ApiJson<FixHintsRequest>,
) -> Result<Json<pl_app::FixHints>, ApiError> {
    if request.window_ms.is_some_and(|w| w > 600_000) {
        return Err(ApiError::new(
            ProblemKind::BadRequest,
            "windowMs — не больше 600000.",
        ));
    }
    let hints = tokio::task::spawn_blocking(move || -> Result<pl_app::FixHints, ApiError> {
        let yaml = match request.yaml {
            Some(yaml) => yaml,
            None => {
                let guard = state.session.read();
                let project = guard
                    .as_ref()
                    .ok_or_else(|| ApiError(Session::no_project()))?;
                project
                    .current_interpretation()
                    .map_err(|e| ApiError(e.into()))?
                    .ok_or_else(|| {
                        ApiError::new(
                            ProblemKind::NotFound,
                            "Интерпретация ещё не сохранена: передайте yaml в запросе.",
                        )
                    })?
                    .1
            }
        };
        if state.session.read().is_none() {
            return Err(ApiError(Session::no_project()));
        }
        let it = Interpretation::parse(&yaml).map_err(schema_problem)?;
        let started = std::time::Instant::now();
        let options = pl_app::TestOptions {
            window_ms: request.window_ms.unwrap_or(pl_app::DEFAULT_WINDOW_MS),
            ..pl_app::TestOptions::default()
        };
        pl_app::hypothesis_fix_hints(
            &pl_app::all_sources(&state.sources),
            &state.actions.list(),
            &it,
            &request.hypothesis,
            &options,
            &|| started.elapsed() > std::time::Duration::from_secs(20),
        )
        .map_err(ApiError)
    })
    .await
    .map_err(|_| blocking_failed())??;
    Ok(Json(hints))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FieldHintsRequest {
    message_id: String,
    field: String,
    /// Несохранённый текст описания; без него берётся текущая ревизия.
    yaml: Option<String>,
    window_ms: Option<u64>,
}

/// Подсказка типа поля: какое чтение тех же байтов согласуется с тестами гипотез и проверками.
async fn field_hints(
    State(state): State<AppState>,
    ApiJson(request): ApiJson<FieldHintsRequest>,
) -> Result<Json<pl_app::FieldHints>, ApiError> {
    if request.window_ms.is_some_and(|w| w > 600_000) {
        return Err(ApiError::new(
            ProblemKind::BadRequest,
            "windowMs — не больше 600000.",
        ));
    }
    let hints = tokio::task::spawn_blocking(move || -> Result<pl_app::FieldHints, ApiError> {
        let yaml = match request.yaml {
            Some(yaml) => yaml,
            None => {
                let guard = state.session.read();
                let project = guard
                    .as_ref()
                    .ok_or_else(|| ApiError(Session::no_project()))?;
                project
                    .current_interpretation()
                    .map_err(|e| ApiError(e.into()))?
                    .ok_or_else(|| {
                        ApiError::new(
                            ProblemKind::NotFound,
                            "Интерпретация ещё не сохранена: передайте yaml в запросе.",
                        )
                    })?
                    .1
            }
        };
        if state.session.read().is_none() {
            return Err(ApiError(Session::no_project()));
        }
        let it = Interpretation::parse(&yaml).map_err(schema_problem)?;
        let started = std::time::Instant::now();
        let options = pl_app::TestOptions {
            window_ms: request.window_ms.unwrap_or(pl_app::DEFAULT_WINDOW_MS),
            ..pl_app::TestOptions::default()
        };
        pl_app::field_type_hints(
            &pl_app::all_sources(&state.sources),
            &state.actions.list(),
            &it,
            &request.message_id,
            &request.field,
            &options,
            &|| started.elapsed() > std::time::Duration::from_secs(20),
        )
        .map_err(ApiError)
    })
    .await
    .map_err(|_| {
        ApiError::new(
            ProblemKind::Internal,
            "Операция завершилась сбоем, повторите.",
        )
    })??;
    Ok(Json(hints))
}
