use serde::Serialize;

/// Виды ошибок API; `type` в ответе — `urn:protoledger:problem:<код>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProblemKind {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    NoProject,
    Conflict,
    LimitExceeded,
    UnsupportedMedia,
    Unprocessable,
    TooManyJobs,
    Internal,
}

impl ProblemKind {
    pub fn code(self) -> &'static str {
        match self {
            Self::BadRequest => "bad-request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not-found",
            Self::NoProject => "no-project",
            Self::Conflict => "conflict",
            Self::LimitExceeded => "limit-exceeded",
            Self::UnsupportedMedia => "unsupported-media",
            Self::Unprocessable => "unprocessable",
            Self::TooManyJobs => "too-many-jobs",
            Self::Internal => "internal",
        }
    }

    pub fn status(self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::NoProject | Self::Conflict => 409,
            Self::LimitExceeded => 413,
            Self::UnsupportedMedia => 415,
            Self::Unprocessable => 422,
            Self::TooManyJobs => 429,
            Self::Internal => 500,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::BadRequest => "Некорректный запрос",
            Self::Unauthorized => "Нет доступа",
            Self::Forbidden => "Запрос отклонён",
            Self::NotFound => "Не найдено",
            Self::NoProject => "Проект не открыт",
            Self::Conflict => "Конфликт состояния",
            Self::LimitExceeded => "Превышен предел",
            Self::UnsupportedMedia => "Неподдерживаемый тип",
            Self::Unprocessable => "Не принято",
            Self::TooManyJobs => "Слишком много задач",
            Self::Internal => "Внутренняя ошибка",
        }
    }
}

/// Превышенный защитный предел.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Limit {
    pub name: &'static str,
    pub value: u64,
    pub unit: &'static str,
}

/// Тело ошибки по RFC 9457.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Problem {
    #[serde(rename = "type", serialize_with = "serialize_kind")]
    pub kind: ProblemKind,
    pub title: &'static str,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<Limit>,
}

fn serialize_kind<S: serde::Serializer>(kind: &ProblemKind, s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(&format_args!("urn:protoledger:problem:{}", kind.code()))
}

impl Problem {
    pub fn new(kind: ProblemKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            title: kind.title(),
            status: kind.status(),
            detail: Some(detail.into()),
            limit: None,
        }
    }

    pub fn with_limit(mut self, limit: Limit) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Ошибка файловой системы при операции `op` («создание проекта», «запись прогона»).
    /// Нет прав и нет места — состояние окружения, которое пользователь может исправить сам:
    /// это понятный отказ, а не «внутренняя ошибка».
    pub fn io(op: &str, err: &std::io::Error) -> Self {
        use std::io::ErrorKind;
        match err.kind() {
            ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem => Self::new(
                ProblemKind::Conflict,
                format!(
                    "Нет прав на запись ({op}). Проверьте владельца папки проектов и права на неё; \
                     при запуске в Docker папка должна принадлежать пользователю контейнера \
                     (HOST_UID и HOST_GID в .env)."
                ),
            ),
            ErrorKind::StorageFull | ErrorKind::QuotaExceeded => Self::new(
                ProblemKind::Conflict,
                format!("На диске не хватило места ({op}). Освободите место и повторите."),
            ),
            _ => Self::new(
                ProblemKind::Internal,
                format!(
                    "Не удалось выполнить операцию «{op}» с файлами проекта. Проверьте права и свободное место."
                ),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_as_problem_details() {
        let p = Problem::new(ProblemKind::NotFound, "Поток не существует.");
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["type"], "urn:protoledger:problem:not-found");
        assert_eq!(json["status"], 404);
        assert!(json.get("limit").is_none());
    }

    #[test]
    fn filesystem_refusals_are_explained_not_internal() {
        use std::io::{Error, ErrorKind};
        let denied = Problem::io(
            "создание проекта",
            &Error::from(ErrorKind::PermissionDenied),
        );
        assert_eq!(denied.status, 409);
        assert!(
            denied
                .detail
                .as_deref()
                .unwrap()
                .contains("Нет прав на запись")
        );
        let read_only = Problem::io("запись", &Error::from(ErrorKind::ReadOnlyFilesystem));
        assert_eq!(read_only.status, 409);
        let full = Problem::io("копирование записи", &Error::from(ErrorKind::StorageFull));
        assert_eq!(full.status, 409);
        assert!(full.detail.as_deref().unwrap().contains("места"));
        let other = Problem::io("чтение", &Error::from(ErrorKind::UnexpectedEof));
        assert_eq!(other.status, 500);
    }
}
