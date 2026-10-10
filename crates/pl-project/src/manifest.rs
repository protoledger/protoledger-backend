use serde::{Deserialize, Serialize};

/// Версия формата `project.yaml`; проекты новее отказываются открываться.
pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SourceFormat {
    Pcap,
    Pcapng,
}

impl SourceFormat {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Pcap => "pcap",
            Self::Pcapng => "pcapng",
        }
    }
}

/// Какие байты брать при перекрытии с различающимся содержимым (ADR 0006).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OverlapPolicy {
    First,
    Last,
    Flag,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChecksumPolicy {
    Ignore,
    Warn,
    Drop,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub overlap_policy: OverlapPolicy,
    pub checksum_policy: ChecksumPolicy,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            overlap_policy: OverlapPolicy::First,
            checksum_policy: ChecksumPolicy::Warn,
        }
    }
}

/// Факт добавления записи в проект. Повторный импорт того же файла — новая запись списка.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImportRecord {
    /// `imp-0001`, …
    pub id: String,
    pub sha256: String,
    /// Исходное имя файла; только для показа, в путях не участвует.
    pub name: String,
    pub format: SourceFormat,
    pub size_bytes: u64,
}

/// Ревизия интерпретации: файл `interpretation/history/<rev>.yaml` неизменен, `digest` — его sha256 канонической формы.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InterpretationRevision {
    pub rev: u32,
    pub digest: String,
}

/// Сохранённый прогон проверки: `runs/<id>.json`, `id` вида `run-0001`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RunRef {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub format_version: u32,
    pub engine_version: String,
    pub name: String,
    #[serde(default)]
    pub settings: Settings,
    #[serde(default)]
    pub imports: Vec<ImportRecord>,
    #[serde(default)]
    pub interpretations: Vec<InterpretationRevision>,
    #[serde(default)]
    pub runs: Vec<RunRef>,
}
