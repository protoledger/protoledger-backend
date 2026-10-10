//! HTTP-сервер движка: REST `/api`, встроенный интерфейс.

#[cfg(feature = "dev-tools")]
pub mod dev;
mod encode;
mod error;
mod jobs;
mod json;
mod project;
mod sources;
mod spa;

use std::net::SocketAddr;
use std::path::PathBuf;

use axum::routing::get;
use axum::{Json, Router};
use pl_app::{JobRegistry, Session, SourceStore};
use pl_core::ProblemKind;
use serde::Serialize;

pub use error::ApiError;

/// Общее состояние сервера.
#[derive(Clone)]
pub struct AppState {
    pub jobs: JobRegistry,
    pub sources: SourceStore,
    pub session: Session,
    #[cfg(feature = "dev-tools")]
    pub dev: Option<dev::DevConfig>,
}

impl AppState {
    pub fn new(workspace: PathBuf) -> Self {
        Self {
            jobs: JobRegistry::default(),
            sources: SourceStore::default(),
            session: Session::new(workspace),
            #[cfg(feature = "dev-tools")]
            dev: None,
        }
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
        .fallback(api_not_found);
    #[cfg(feature = "dev-tools")]
    let docs = dev::docs_routes(state.dev.as_ref());
    let app = Router::new()
        .nest("/api", api)
        .fallback(spa::serve_ui)
        .with_state(state);
    #[cfg(feature = "dev-tools")]
    let app = app.merge(docs);
    app
}

pub async fn serve(config: ServerConfig) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(config.addr).await?;
    tracing::info!(
        addr = %listener.local_addr()?,
        workspace = %config.workspace.display(),
        "сервер запущен"
    );
    axum::serve(
        listener,
        router(AppState {
            #[cfg(feature = "dev-tools")]
            dev: config.dev.clone(),
            ..AppState::new(config.workspace.clone())
        }),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}
