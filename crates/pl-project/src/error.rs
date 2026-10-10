use pl_core::{Limit, Problem, ProblemKind};

#[derive(Debug, thiserror::Error)]
pub enum ProjectError {
    #[error("путь не подходит: {0}")]
    InvalidPath(&'static str),
    #[error("папка не найдена")]
    Missing,
    #[error("папка не похожа на проект protoledger")]
    NotAProject,
    #[error("папка уже существует и не пуста")]
    AlreadyExists,
    #[error("проект создан более новой версией (формат {found}, поддерживается {supported})")]
    UnsupportedVersion { found: u32, supported: u32 },
    #[error("project.yaml повреждён: {0}")]
    InvalidManifest(String),
    #[error("это не обычный файл")]
    NotRegularFile,
    #[error("файл не похож на PCAP или PCAPNG")]
    NotCapture,
    #[error("превышен предел {name}: {value} {unit}")]
    LimitExceeded {
        name: &'static str,
        value: u64,
        unit: &'static str,
    },
    #[error("запись {0} не найдена в проекте")]
    UnknownSource(String),
    #[error("ревизии интерпретации {0} нет в проекте")]
    UnknownRevision(u32),
    #[error("прогон {0} не найден в проекте")]
    UnknownRun(String),
    #[error("операция отменена")]
    Cancelled,
    #[error("ошибка ввода-вывода при операции «{op}»: {source}")]
    Io {
        op: &'static str,
        #[source]
        source: std::io::Error,
    },
}

impl ProjectError {
    pub(crate) fn io(op: &'static str) -> impl FnOnce(std::io::Error) -> Self {
        move |source| Self::Io { op, source }
    }
}

/// Ошибка проекта в виде ответа API (тексты — для пользователя, по-русски).
impl From<ProjectError> for Problem {
    fn from(err: ProjectError) -> Self {
        match err {
            ProjectError::InvalidPath(why) => Problem::new(
                ProblemKind::BadRequest,
                format!("Недопустимый путь: {why}."),
            ),
            ProjectError::Missing => {
                Problem::new(ProblemKind::BadRequest, "Папка или файл не найдены.")
            }
            ProjectError::NotAProject => Problem::new(
                ProblemKind::Unprocessable,
                "Папка не похожа на проект protoledger: нет project.yaml.",
            ),
            ProjectError::AlreadyExists => Problem::new(
                ProblemKind::Conflict,
                "Папка уже существует и не пуста. Выберите другое имя или откройте её как проект.",
            ),
            ProjectError::UnsupportedVersion { found, supported } => Problem::new(
                ProblemKind::Unprocessable,
                format!(
                    "Проект создан более новой версией protoledger (формат {found}, эта версия понимает {supported}). Обновите приложение."
                ),
            ),
            ProjectError::InvalidManifest(why) => Problem::new(
                ProblemKind::Unprocessable,
                format!("Файл project.yaml повреждён или не соответствует формату: {why}"),
            ),
            ProjectError::NotRegularFile => Problem::new(
                ProblemKind::BadRequest,
                "Нужен обычный файл, а не папка или устройство.",
            ),
            ProjectError::NotCapture => Problem::new(
                ProblemKind::Unprocessable,
                "Файл не похож на PCAP или PCAPNG.",
            ),
            ProjectError::LimitExceeded { name, value, unit } => Problem::new(
                ProblemKind::LimitExceeded,
                format!("Превышен защитный предел: больше {value} {unit}."),
            )
            .with_limit(Limit { name, value, unit }),
            ProjectError::UnknownSource(sha) => Problem::new(
                ProblemKind::NotFound,
                format!("Запись {sha} не найдена в проекте."),
            ),
            ProjectError::UnknownRevision(rev) => Problem::new(
                ProblemKind::NotFound,
                format!("Ревизии интерпретации {rev} в проекте нет."),
            ),
            ProjectError::UnknownRun(id) => Problem::new(
                ProblemKind::NotFound,
                format!("Прогона {id} в проекте нет."),
            ),
            ProjectError::Cancelled => Problem::new(ProblemKind::Conflict, "Операция отменена."),
            ProjectError::Io { op, .. } => Problem::new(
                ProblemKind::Internal,
                format!(
                    "Не удалось выполнить операцию «{op}» с файлами проекта. Проверьте права и свободное место."
                ),
            ),
        }
    }
}
