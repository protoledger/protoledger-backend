//! Сценарии движка поверх библиотечных крейтов: реестр долгих задач, импорт записей, сессия с проектом.

mod actions;
mod interp;
mod jobs;
mod session;
mod sources;
mod verify;

pub use actions::{
    ActionLogStore, Exchange, FrameHit, LoadedLog, MessageHit, all_sources, current_interpretation,
    find_exchange, import_action_log, reload_action_logs,
};
pub use interp::{StreamApplied, apply_to_source, stream_input};
pub use jobs::{
    Job, JobContext, JobKind, JobProgress, JobRegistry, JobState, MAX_CONCURRENT_JOBS,
    ProgressStage, ProgressUnit,
};
pub use session::{OpenMode, ProjectInfo, Session, SettingsPatch};
pub use sources::{
    SourceData, SourceStore, analyze, import_path, read_capture_file, reload_sources,
};
pub use verify::{current_signature, start_verify};
