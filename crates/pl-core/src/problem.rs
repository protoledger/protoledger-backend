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

/// Превышенный защитный предел (`plan/security.md` §6).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Limit {
    pub name: String,
    pub value: u64,
    pub unit: String,
}

/// Тело ошибки по RFC 9457.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Problem {
    #[serde(rename = "type")]
    pub kind: String,
    pub title: String,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<Limit>,
}

impl Problem {
    pub fn new(kind: ProblemKind, detail: impl Into<String>) -> Self {
        Self {
            kind: format!("urn:protoledger:problem:{}", kind.code()),
            title: kind.title().to_owned(),
            status: kind.status(),
            detail: Some(detail.into()),
            limit: None,
        }
    }

    pub fn with_limit(mut self, limit: Limit) -> Self {
        self.limit = Some(limit);
        self
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
}
