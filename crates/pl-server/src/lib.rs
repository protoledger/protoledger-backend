//! HTTP-сервер движка: REST `/api`, встроенный интерфейс.

#[cfg(feature = "dev-tools")]
pub mod dev;
mod encode;
mod error;
mod guard;
mod interpretation;
mod jobs;
mod json;
mod project;
mod runs;
mod sources;
mod spa;
mod upload;

use std::net::SocketAddr;
use std::path::PathBuf;

use axum::routing::get;
use axum::{Json, Router};
use pl_app::{JobRegistry, Session, SourceStore};
use pl_core::ProblemKind;
use serde::Serialize;

pub use error::ApiError;
pub use guard::{Guard, TOKEN_HEADER};

/// Лимит тела JSON-запроса (`plan/security.md` §6).
pub(crate) const MAX_JSON_BODY: usize = 8 << 20;

/// Общее состояние сервера.
#[derive(Clone)]
pub struct AppState {
    pub jobs: JobRegistry,
    pub sources: SourceStore,
    pub session: Session,
    pub guard: Guard,
    /// Предел размера загружаемой записи, байт.
    pub max_upload: u64,
    #[cfg(feature = "dev-tools")]
    pub dev: Option<dev::DevConfig>,
}

impl AppState {
    pub fn new(workspace: PathBuf) -> Self {
        Self {
            jobs: JobRegistry::default(),
            sources: SourceStore::default(),
            session: Session::new(workspace),
            guard: Guard::random(),
            max_upload: pl_project::MAX_SOURCE_SIZE,
            #[cfg(feature = "dev-tools")]
            dev: None,
        }
    }
}

impl AppState {
    /// Состояние для запуска: в dev-режиме токен и разрешённый origin фронта заданы заранее.
    pub fn from_config(config: &ServerConfig) -> Self {
        #[allow(unused_mut)]
        let mut state = Self::new(config.workspace.clone());
        #[cfg(feature = "dev-tools")]
        if let Some(dev) = &config.dev {
            state.guard = Guard::with_token(dev.token.clone(), vec![dev.allowed_origin.clone()]);
            state.dev = Some(dev.clone());
        }
        state
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new(PathBuf::from("."))
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub addr: SocketAddr,
    pub workspace: PathBuf,
    #[cfg(feature = "dev-tools")]
    pub dev: Option<dev::DevConfig>,
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
}

async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn api_not_found() -> ApiError {
    ApiError::new(ProblemKind::NotFound, "Такого пути в API нет.")
}

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .merge(jobs::routes())
        .merge(sources::routes())
        .merge(project::routes())
        .merge(interpretation::routes())
        .merge(runs::routes())
        .fallback(api_not_found);
    #[cfg(feature = "dev-tools")]
    let docs = dev::docs_routes(state.dev.as_ref());
    let guard_state = state.clone();
    let app = Router::new()
        .nest("/api", api)
        .fallback(spa::serve_ui)
        .layer(axum::extract::DefaultBodyLimit::max(MAX_JSON_BODY))
        .with_state(state);
    #[cfg(feature = "dev-tools")]
    let app = app.merge(docs);
    // Внешний слой: проверяет и API, и встроенный интерфейс (токен лежит в index.html).
    app.layer(axum::middleware::from_fn_with_state(
        guard_state,
        guard::enforce,
    ))
}

pub async fn serve(config: ServerConfig) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(config.addr).await?;
    tracing::info!(
        addr = %listener.local_addr()?,
        workspace = %config.workspace.display(),
        "сервер запущен"
    );
    axum::serve(listener, router(AppState::from_config(&config)))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
}
