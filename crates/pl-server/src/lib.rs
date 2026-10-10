//! HTTP-сервер движка: REST `/api`, встроенный интерфейс.

mod error;
mod spa;

use std::net::SocketAddr;
use std::path::PathBuf;

use axum::routing::get;
use axum::{Json, Router};
use pl_core::ProblemKind;
use serde::Serialize;

pub use error::ApiError;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub addr: SocketAddr,
    pub workspace: PathBuf,
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

pub fn router() -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .fallback(api_not_found);
    Router::new().nest("/api", api).fallback(spa::serve_ui)
}

pub async fn serve(config: ServerConfig) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(config.addr).await?;
    tracing::info!(
        addr = %listener.local_addr()?,
        workspace = %config.workspace.display(),
        "сервер запущен"
    );
    axum::serve(listener, router())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
}
