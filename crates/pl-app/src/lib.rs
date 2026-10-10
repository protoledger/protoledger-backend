//! Сценарии движка поверх библиотечных крейтов: реестр долгих задач, импорт записей, сессия с проектом.

mod actions;
mod hypothesis;
mod interp;
mod jobs;
mod report;
mod research;
mod session;
mod sources;
mod verify;

pub use actions::{
    ActionLogStore, Exchange, FrameHit, LoadedLog, MessageHit, all_sources, current_interpretation,
    find_exchange, import_action_log, reload_action_logs,
};
pub use hypothesis::{
    Counterexample, DEFAULT_WINDOW_MS, Evidence, Issue, TestOptions, Verdict, test_hypothesis,
};
pub use interp::{StreamApplied, apply_to_source, stream_input};
pub use jobs::{
    Job, JobContext, JobKind, JobProgress, JobRegistry, JobState, MAX_CONCURRENT_JOBS,
    ProgressStage, ProgressUnit,
};
pub use report::collect as collect_report;
pub use research::{
    AnchorRef, AnchorState, Hypothesis, HypothesisInput, HypothesisStatus, Observation, Question,
    QuestionStatus, add_hypothesis, add_observation, add_question, anchor_state, delete_hypothesis,
    delete_observation, delete_question, get as research_get, load as research_load,
    resolve_stream, update_hypothesis, update_observation, update_question,
};
pub use session::{OpenMode, ProjectInfo, Session, SettingsPatch};
pub use sources::{
    SourceData, SourceStore, analyze, analyze_with, import_path, load_project_sources, policy_from,
    read_capture_file, reload_sources,
};
pub use verify::{current_signature, execute_run, start_verify};
