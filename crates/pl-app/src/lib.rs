//! Сценарии движка поверх библиотечных крейтов: реестр долгих задач, сессия с открытым проектом.

mod jobs;
mod session;

pub use jobs::{
    Job, JobContext, JobKind, JobProgress, JobRegistry, JobState, MAX_CONCURRENT_JOBS,
    ProgressStage, ProgressUnit,
};
pub use session::{OpenMode, ProjectInfo, Session};
