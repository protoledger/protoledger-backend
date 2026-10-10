use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::get;
use axum::{Json, Router};
use futures_util::StreamExt;
use futures_util::stream::{self, Stream};
use pl_app::{Job, JobProgress};
use pl_core::{Problem, ProblemKind};
use serde::Serialize;
use tokio::sync::watch;

use crate::{ApiError, AppState};

/// Предел жизни одного SSE-потока (T21).
const SSE_MAX_DURATION: Duration = Duration::from_secs(30 * 60);

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/jobs", get(list_jobs))
        .route("/jobs/{id}", get(get_job).delete(cancel_job))
        .route("/jobs/{id}/events", get(job_events))
}

#[derive(Serialize)]
struct JobList {
    items: Vec<Job>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProgressEvent {
    job_id: String,
    #[serde(flatten)]
    progress: JobProgress,
}

async fn list_jobs(State(state): State<AppState>) -> Json<JobList> {
    Json(JobList {
        items: state.jobs.list(),
    })
}

fn not_found(id: &str) -> ApiError {
    ApiError::new(ProblemKind::NotFound, format!("Задача {id} не найдена."))
}

async fn get_job(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Job>, ApiError> {
    state.jobs.get(&id).map(Json).ok_or_else(|| not_found(&id))
}

async fn cancel_job(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<Job>), ApiError> {
    let job = state
        .jobs
        .cancel(&id)
        .map_err(|problem: Problem| ApiError(problem))?;
    Ok((StatusCode::ACCEPTED, Json(job)))
}

async fn job_events(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let rx = state.jobs.subscribe(&id).ok_or_else(|| not_found(&id))?;
    // Долгое соединение закрываем: клиент переподключится и сразу получит текущее состояние.
    let stream = event_stream(rx).take_until(tokio::time::sleep(SSE_MAX_DURATION));
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}

fn event(name: &str, data: &impl Serialize) -> Event {
    Event::default()
        .event(name)
        .json_data(data)
        .unwrap_or_else(|_| Event::default().event(name))
}

struct Feed {
    rx: watch::Receiver<Job>,
    last: Job,
    sent_first: bool,
    done: bool,
}

/// Первым — текущее состояние; дальше `state` при смене состояния и `progress` при смене прогресса.
/// `watch` склеивает быстрые обновления, но последнее (терминальное) значение не теряется.
fn event_stream(mut rx: watch::Receiver<Job>) -> impl Stream<Item = Result<Event, Infallible>> {
    let last = rx.borrow_and_update().clone();
    let feed = Feed {
        rx,
        last,
        sent_first: false,
        done: false,
    };
    stream::unfold(feed, |mut feed| async move {
        if feed.done {
            return None;
        }
        if !feed.sent_first {
            feed.sent_first = true;
            feed.done = feed.last.state.is_terminal();
            let ev = event("state", &feed.last);
            return Some((Ok(ev), feed));
        }
        feed.rx.changed().await.ok()?;
        let current = feed.rx.borrow_and_update().clone();
        let ev = if current.state != feed.last.state {
            event("state", &current)
        } else {
            event(
                "progress",
                &ProgressEvent {
                    job_id: current.id.clone(),
                    progress: current.progress,
                },
            )
        };
        feed.done = current.state.is_terminal();
        feed.last = current;
        Some((Ok(ev), feed))
    })
}
