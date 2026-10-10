use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use pl_core::{Problem, ProblemKind};

/// Ошибка обработчика; отдаётся клиенту как `application/problem+json`.
#[derive(Debug)]
pub struct ApiError(pub Problem);

impl ApiError {
    pub fn new(kind: ProblemKind, detail: impl Into<String>) -> Self {
        Self(Problem::new(kind, detail))
    }
}

impl From<Problem> for ApiError {
    fn from(problem: Problem) -> Self {
        Self(problem)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.0.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut response = (status, Json(self.0)).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}
