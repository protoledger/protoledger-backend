//! Формат проекта на диске (ADR 0006): папка `<имя>.protoledger/`, манифест, неизменные копии записей.
//!
//! Весь ввод считаем недоверенным: пути из манифеста не используются — имена файлов строятся
//! из проверенного sha256 и формата.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;
mod manifest;
mod project;

pub use error::ProjectError;
pub use manifest::{
    ChecksumPolicy, FORMAT_VERSION, ImportRecord, InterpretationRevision, Manifest, OverlapPolicy,
    Settings, SourceFormat,
};
pub use project::{
    MAX_INTERPRETATION_SIZE, MAX_MANIFEST_SIZE, MAX_SOURCE_SIZE, Project, Source, SourceStatus,
    is_valid_sha256,
};
