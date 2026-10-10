//! Сценарии движка поверх библиотечных крейтов: реестр долгих задач, импорт записей, сессия с проектом.

mod jobs;
mod session;
mod sources;

pub use jobs::{
    Job, JobContext, JobKind, JobProgress, JobRegistry, JobState, MAX_CONCURRENT_JOBS,
    ProgressStage, ProgressUnit,
};
pub use session::{OpenMode, ProjectInfo, Session};
pub use sources::{SourceData, SourceStore, analyze, import_path, read_capture_file};
