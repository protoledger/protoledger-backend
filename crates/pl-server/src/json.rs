use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};
use pl_core::ProblemKind;
use serde::de::DeserializeOwned;

use crate::ApiError;

/// `Json` с ошибками в формате Problem Details вместо текста axum.
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(request, state).await {
            Ok(axum::Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(match rejection {
                JsonRejection::MissingJsonContentType(_) => ApiError::new(
                    ProblemKind::UnsupportedMedia,
                    "Ожидается Content-Type: application/json.",
                ),
                JsonRejection::BytesRejection(_) => ApiError::new(
                    ProblemKind::LimitExceeded,
                    "Тело запроса слишком большое или не читается.",
                ),
                _ => ApiError::new(
                    ProblemKind::BadRequest,
                    "Тело запроса — некорректный JSON или в нём неверные поля.",
                ),
            }),
        }
    }
}
