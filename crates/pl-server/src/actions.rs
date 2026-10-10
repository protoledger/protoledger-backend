//! Журналы действий: импорт с сопоставлением колонок, просмотр, поиск обмена по действию.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::rejection::QueryRejection;
use axum::extract::{DefaultBodyLimit, FromRequest, Multipart, Path, Query, Request, State};
use axum::http::header;
use axum::routing::get;
use axum::{Json, Router};
use pl_actions::{Action, Mapping, Param};
use pl_app::{LoadedLog, Session};
use pl_core::{Problem, ProblemKind};
use pl_interp::Category;
use serde::{Deserialize, Serialize};

use crate::encode::rfc3339;
use crate::{ApiError, AppState};

const DEFAULT_LIMIT: u64 = 100;
const MAX_LIMIT: u64 = 500;
const DEFAULT_BEFORE_MS: u64 = 500;
const DEFAULT_AFTER_MS: u64 = 5_000;
const MAX_WINDOW_MS: u64 = 600_000;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/action-logs",
            get(list).post(import).layer(DefaultBodyLimit::disable()),
        )
        .route("/action-logs/{id}/actions", get(actions))
        .route("/action-logs/{id}/actions/{line}/exchange", get(exchange))
}

fn bad_request(detail: impl Into<String>) -> ApiError {
    ApiError::new(ProblemKind::BadRequest, detail)
}

fn not_found(detail: impl Into<String>) -> ApiError {
    ApiError::new(ProblemKind::NotFound, detail)
}

fn blocking_failed() -> ApiError {
    ApiError::new(
        ProblemKind::Internal,
        "Операция завершилась сбоем, повторите.",
    )
}

fn query<T>(q: Result<Query<T>, QueryRejection>) -> Result<T, ApiError> {
    q.map(|Query(v)| v)
        .map_err(|e| bad_request(format!("Некорректные параметры запроса: {}", e.body_text())))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RowErrorDto {
    line: u64,
    why: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LogDto {
    id: String,
    sha256: String,
    name: String,
    rows: u64,
    skipped: u64,
    errors: Vec<RowErrorDto>,
    mapping: Mapping,
    first_time: Option<String>,
    last_time: Option<String>,
}

fn log_dto(l: &LoadedLog) -> LogDto {
    let range = l.time_range();
    LogDto {
        id: l.record.id.clone(),
        sha256: l.record.sha256.clone(),
        name: l.record.name.clone(),
        rows: l.record.rows,
        skipped: l.skipped,
        errors: l
            .errors
            .iter()
            .map(|e| RowErrorDto {
                line: e.line,
                why: e.why.clone(),
            })
            .collect(),
        mapping: l.record.mapping.clone(),
        first_time: range.map(|r| rfc3339(r.0)),
        last_time: range.map(|r| rfc3339(r.1)),
    }
}

#[derive(Serialize)]
struct LogList {
    items: Vec<LogDto>,
}

async fn list(State(state): State<AppState>) -> Result<Json<LogList>, ApiError> {
    if state.session.read().is_none() {
        return Err(ApiError(Session::no_project()));
    }
    Ok(Json(LogList {
        items: state.actions.list().iter().map(|l| log_dto(l)).collect(),
    }))
}

#[derive(Deserialize)]
struct ImportByPath {
    path: PathBuf,
    mapping: Mapping,
}

fn read_file(path: &std::path::Path) -> Result<Vec<u8>, Problem> {
    let unreadable = |e: std::io::Error| {
        Problem::new(
            ProblemKind::Unprocessable,
            format!("Не удалось прочитать файл: {e}."),
        )
    };
    let meta = std::fs::symlink_metadata(path).map_err(unreadable)?;
    if !meta.file_type().is_file() {
        return Err(Problem::new(
            ProblemKind::Unprocessable,
            "Можно импортировать только обычный файл.",
        ));
    }
    if meta.len() > pl_actions::MAX_FILE_BYTES as u64 {
        return Err(Problem::new(
            ProblemKind::LimitExceeded,
            "Файл журнала больше предела 256 МиБ.",
        ));
    }
    std::fs::read(path).map_err(unreadable)
}

/// Импорт: JSON `{path, mapping}` или multipart с полями `file` и `mapping` (JSON).
async fn import(State(state): State<AppState>, request: Request) -> Result<Json<LogDto>, ApiError> {
    if state.session.read().is_none() {
        return Err(ApiError(Session::no_project()));
    }
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let (name, bytes, mapping) = if content_type.starts_with("application/json") {
        let body = axum::body::to_bytes(request.into_body(), crate::MAX_JSON_BODY)
            .await
            .map_err(|_| {
                ApiError::new(ProblemKind::LimitExceeded, "Тело запроса слишком большое.")
            })?;
        let req: ImportByPath = serde_json::from_slice(&body)
            .map_err(|_| bad_request("Ожидается JSON {\"path\": \"…\", \"mapping\": {\"time\": \"…\", \"action\": \"…\"}}."))?;
        let name = req
            .path
            .file_name()
            .map_or_else(|| "журнал".to_owned(), |n| n.to_string_lossy().into_owned());
        let path = req.path.clone();
        let bytes = tokio::task::spawn_blocking(move || read_file(&path))
            .await
            .map_err(|_| blocking_failed())?
            .map_err(ApiError)?;
        (name, bytes, req.mapping)
    } else if content_type.starts_with("multipart/form-data") {
        let mut multipart = Multipart::from_request(request, &state)
            .await
            .map_err(|_| bad_request("Тело запроса не похоже на multipart/form-data."))?;
        let (mut file, mut mapping) = (None, None);
        while let Some(mut field) = multipart
            .next_field()
            .await
            .map_err(|_| bad_request("Загрузка прервана или повреждена."))?
        {
            match field.name() {
                Some("file") => {
                    let name = field.file_name().unwrap_or("журнал.csv").to_owned();
                    let mut bytes = Vec::new();
                    while let Some(chunk) = field
                        .chunk()
                        .await
                        .map_err(|_| bad_request("Загрузка прервана."))?
                    {
                        if bytes.len() + chunk.len() > pl_actions::MAX_FILE_BYTES {
                            return Err(ApiError::new(
                                ProblemKind::LimitExceeded,
                                "Файл журнала больше предела 256 МиБ.",
                            ));
                        }
                        bytes.extend_from_slice(&chunk);
                    }
                    file = Some((name, bytes));
                }
                Some("mapping") => {
                    let text = field
                        .text()
                        .await
                        .map_err(|_| bad_request("Поле mapping не читается."))?;
                    mapping = Some(serde_json::from_str::<Mapping>(&text).map_err(|e| {
                        bad_request(format!("Поле mapping — JSON сопоставления колонок: {e}"))
                    })?);
                }
                _ => {}
            }
        }
        match (file, mapping) {
            (Some((name, bytes)), Some(mapping)) => (name, bytes, mapping),
            _ => {
                return Err(bad_request(
                    "Нужны поля file (файл журнала) и mapping (сопоставление колонок, JSON).",
                ));
            }
        }
    } else {
        return Err(ApiError::new(
            ProblemKind::UnsupportedMedia,
            "Ожидается application/json или multipart/form-data.",
        ));
    };
    let loaded = tokio::task::spawn_blocking(move || {
        pl_app::import_action_log(&state.session, &state.actions, &name, &bytes, mapping)
    })
    .await
    .map_err(|_| blocking_failed())?
    .map_err(ApiError)?;
    Ok(Json(log_dto(&loaded)))
}

// ------------------------------------------------------------- действия

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ActionDto {
    /// Номер строки файла журнала.
    line: u64,
    time: String,
    action: String,
    params: BTreeMap<String, Param>,
    result: BTreeMap<String, Param>,
    result_raw: String,
}

fn action_dto(a: &Action) -> ActionDto {
    ActionDto {
        line: a.line,
        time: rfc3339(a.ts_ns),
        action: a.action.clone(),
        params: a.params.clone(),
        result: a.result.clone(),
        result_raw: a.result_raw.clone(),
    }
}

#[derive(Deserialize)]
struct ActionsQuery {
    from: Option<String>,
    to: Option<String>,
    action: Option<String>,
    limit: Option<u64>,
    offset: Option<u64>,
}

#[derive(Serialize)]
struct ActionPage {
    items: Vec<ActionDto>,
    total: u64,
    limit: u64,
    offset: u64,
}

fn log(state: &AppState, id: &str) -> Result<Arc<LoadedLog>, ApiError> {
    if state.session.read().is_none() {
        return Err(ApiError(Session::no_project()));
    }
    state
        .actions
        .get(id)
        .ok_or_else(|| not_found(format!("Журнала действий {id} нет.")))
}

fn time_param(raw: &Option<String>, name: &str) -> Result<Option<u64>, ApiError> {
    raw.as_deref()
        .map(|s| {
            pl_actions::parse_rfc3339_ns(s).ok_or_else(|| {
                bad_request(format!(
                    "{name} — время RFC 3339, например 2026-10-01T12:00:00Z."
                ))
            })
        })
        .transpose()
}

async fn actions(
    State(state): State<AppState>,
    Path(id): Path<String>,
    q: Result<Query<ActionsQuery>, QueryRejection>,
) -> Result<Json<ActionPage>, ApiError> {
    let q = query(q)?;
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(bad_request(format!("limit — от 1 до {MAX_LIMIT}.")));
    }
    let (from, to) = (time_param(&q.from, "from")?, time_param(&q.to, "to")?);
    let log = log(&state, &id)?;
    let selected: Vec<&Action> = log
        .actions
        .iter()
        .filter(|a| from.is_none_or(|f| a.ts_ns >= f) && to.is_none_or(|t| a.ts_ns <= t))
        .filter(|a| q.action.as_ref().is_none_or(|w| &a.action == w))
        .collect();
    let offset = q.offset.unwrap_or(0);
    Ok(Json(ActionPage {
        total: selected.len() as u64,
        items: selected
            .into_iter()
            .skip(usize::try_from(offset).unwrap_or(usize::MAX))
            .take(limit as usize)
            .map(action_dto)
            .collect(),
        limit,
        offset,
    }))
}

// -------------------------------------------------------------- обмен

#[derive(Deserialize)]
struct ExchangeQuery {
    /// Сколько миллисекунд до действия включать в окно.
    before: Option<u64>,
    after: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FrameHitDto {
    source: String,
    stream: String,
    frame_no: u32,
    time: String,
    start: u64,
    end: u64,
    duplicate: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MessageHitDto {
    source: String,
    stream: String,
    start: u64,
    end: u64,
    category: Category,
    message_id: Option<String>,
    first_time: String,
    last_time: String,
}

#[derive(Serialize)]
struct Window {
    from: String,
    to: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExchangeDto {
    action: ActionDto,
    window: Window,
    /// Применялась ли сохранённая интерпретация (иначе в ответе только кадры).
    interpretation_applied: bool,
    frames: Vec<FrameHitDto>,
    messages: Vec<MessageHitDto>,
}

async fn exchange(
    State(state): State<AppState>,
    Path((id, line)): Path<(String, u64)>,
    q: Result<Query<ExchangeQuery>, QueryRejection>,
) -> Result<Json<ExchangeDto>, ApiError> {
    let q = query(q)?;
    let (before, after) = (
        q.before.unwrap_or(DEFAULT_BEFORE_MS),
        q.after.unwrap_or(DEFAULT_AFTER_MS),
    );
    if before > MAX_WINDOW_MS || after > MAX_WINDOW_MS {
        return Err(bad_request(format!(
            "Окно не больше {MAX_WINDOW_MS} мс в каждую сторону."
        )));
    }
    let log = log(&state, &id)?;
    let action = log
        .action(line)
        .ok_or_else(|| not_found(format!("В журнале {id} нет действия со строки {line}.")))?
        .clone();
    let from = action.ts_ns.saturating_sub(before * 1_000_000);
    let to = action.ts_ns.saturating_add(after * 1_000_000);
    let found = tokio::task::spawn_blocking(move || {
        let interpretation = pl_app::current_interpretation(&state.session);
        let found = pl_app::find_exchange(
            &pl_app::all_sources(&state.sources),
            interpretation.as_ref(),
            from,
            to,
        );
        (found, interpretation.is_some())
    })
    .await
    .map_err(|_| blocking_failed())?;
    let (found, applied) = found;
    Ok(Json(ExchangeDto {
        action: action_dto(&action),
        window: Window {
            from: rfc3339(from),
            to: rfc3339(to),
        },
        interpretation_applied: applied,
        frames: found
            .frames
            .iter()
            .map(|f| FrameHitDto {
                source: f.source.clone(),
                stream: f.stream.clone(),
                frame_no: f.frame_no,
                time: rfc3339(f.ts_ns),
                start: f.start,
                end: f.end,
                duplicate: f.duplicate,
            })
            .collect(),
        messages: found
            .messages
            .iter()
            .map(|m| MessageHitDto {
                source: m.source.clone(),
                stream: m.stream.clone(),
                start: m.start,
                end: m.end,
                category: m.category,
                message_id: m.message_id.clone(),
                first_time: rfc3339(m.first_ts_ns),
                last_time: rfc3339(m.last_ts_ns),
            })
            .collect(),
    }))
}
