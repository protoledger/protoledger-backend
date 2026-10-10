//! Сценарии движка поверх библиотечных крейтов: реестр долгих задач.

mod jobs;

pub use jobs::{
    Job, JobContext, JobKind, JobProgress, JobRegistry, JobState, MAX_CONCURRENT_JOBS,
    ProgressStage, ProgressUnit,
};
