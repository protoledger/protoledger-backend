//! Прогоны проверки: интерпретация применяется к корпусу, результат — сводка по всему набору,
//! контрпримеры с якорями, сравнение прогонов и признаки устаревания (ТЗ R4, ADR 0006).
//!
//! Чистая библиотека: потоки приходят от вызывающего, ничего не читается с диска. Результат
//! детерминирован: порядок потоков и сообщений стабилен, времени выполнения в нём нет.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]

use std::collections::BTreeMap;

use pl_interp::schema::Status;
use pl_interp::{Category, Interpretation, MessageResult, StreamInput, ViolationKind, apply};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Контрпримеров в одном прогоне (остальные — в счётчике и в таблице сообщений).
pub const MAX_COUNTEREXAMPLES: usize = 1_000;
/// Сообщений в одном прогоне (`plan/security.md` §6: профиль — 100 тысяч).
pub const MAX_MESSAGES: usize = 2_000_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("прогон отменён")]
    Cancelled,
    #[error("в прогоне больше {MAX_MESSAGES} сообщений: сузьте корпус")]
    TooManyMessages,
    #[error("разбор потока {stream}: {why}")]
    Stream { stream: String, why: String },
}

/// Поток корпуса.
pub struct StreamTarget<'a> {
    /// Идентификатор направленного потока (`d05c6bf0:c0001:ab`).
    pub id: String,
    /// sha256 записи.
    pub source: String,
    pub input: StreamInput<'a>,
}

/// Строка сообщения: `[начало, конец, категория, тип сообщения]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageRow(pub u64, pub u64, pub Category, pub Option<String>);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamRun {
    pub id: String,
    pub source: String,
    pub out_of_scope: bool,
    pub counts: BTreeMap<Category, u64>,
    pub unknown_bytes: u64,
    pub message_bytes: u64,
    pub messages: Vec<MessageRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Anchor {
    pub source: String,
    pub stream: String,
    pub start: u64,
    pub end: u64,
    /// sha256 байтов сообщения; `None`, если в них есть дыра или неоднозначность.
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViolationRow {
    pub kind: ViolationKind,
    pub id: String,
    pub detail: String,
    pub status: Status,
}

/// Данные, на которых правило или гипотеза не выполняются.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Counterexample {
    pub anchor: Anchor,
    pub category: Category,
    pub message_id: Option<String>,
    pub violations: Vec<ViolationRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub streams: u64,
    pub out_of_scope_streams: u64,
    pub messages: u64,
    pub message_bytes: u64,
    /// Байты сообщений вне описанных полей и в зонах `unknown`.
    pub unknown_bytes: u64,
    pub counts: BTreeMap<Category, u64>,
    /// Разбивка по типам сообщений; `?` — тип не определён.
    pub by_message: BTreeMap<String, BTreeMap<Category, u64>>,
    pub counterexamples: u64,
    pub counterexamples_truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectionFilter {
    AToB,
    BToA,
}

/// Фильтры корпуса: что именно проверялось. Показываются рядом с результатом, чтобы сводка не скрывала состав.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CorpusFilter {
    /// Записи (sha256); без значения — все.
    #[serde(default)]
    pub sources: Option<Vec<String>>,
    #[serde(default)]
    pub direction: Option<DirectionFilter>,
    /// Порт любой из сторон.
    #[serde(default)]
    pub port: Option<u16>,
}

impl CorpusFilter {
    /// Входит ли поток записи `source` в корпус: `direction_index` 0 — a→b, 1 — b→a.
    pub fn accepts(
        &self,
        source: &str,
        direction_index: usize,
        src_port: u16,
        dst_port: u16,
    ) -> bool {
        self.sources
            .as_ref()
            .is_none_or(|s| s.iter().any(|x| x == source))
            && match self.direction {
                None => true,
                Some(DirectionFilter::AToB) => direction_index == 0,
                Some(DirectionFilter::BToA) => direction_index == 1,
            }
            && self.port.is_none_or(|p| p == src_port || p == dst_port)
    }
}

/// Условия, подписывающие прогон: от них зависит, актуален ли результат.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunInputs {
    pub revision: Option<u32>,
    pub interpretation_digest: String,
    pub settings_digest: String,
    /// sha256 записей корпуса, по возрастанию.
    pub sources: Vec<String>,
    pub corpus: CorpusFilter,
    pub engine_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Run {
    pub id: String,
    pub inputs: RunInputs,
    pub summary: Summary,
    pub streams: Vec<StreamRun>,
    pub counterexamples: Vec<Counterexample>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// sha256 канонического JSON: для подписи настроек и других входов прогона.
pub fn digest_of<T: Serialize>(value: &T) -> String {
    hex(&Sha256::digest(
        serde_json::to_string(value).unwrap_or_default().as_bytes(),
    ))
}

fn is_counterexample(m: &MessageResult) -> bool {
    m.category == Category::Violated
        || m.violations
            .iter()
            .any(|v| v.status != Status::Unknown && v.kind != ViolationKind::Framing)
}

fn anchor(target: &StreamTarget<'_>, m: &MessageResult) -> Anchor {
    let sha256 = match target.input.read(m.start, m.end - m.start) {
        pl_interp::Read::Bytes(bytes) => Some(hex(&Sha256::digest(&bytes))),
        _ => None,
    };
    Anchor {
        source: target.source.clone(),
        stream: target.id.clone(),
        start: m.start,
        end: m.end,
        sha256,
    }
}

/// Применяет интерпретацию к корпусу. `progress(сделано, всего)` — по потокам.
pub fn execute(
    it: &Interpretation,
    targets: &[StreamTarget<'_>],
    inputs: RunInputs,
    cancelled: &dyn Fn() -> bool,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<Run, VerifyError> {
    let mut summary = Summary {
        streams: targets.len() as u64,
        ..Summary::default()
    };
    let mut streams = Vec::with_capacity(targets.len());
    let mut counterexamples = Vec::new();
    for (n, target) in targets.iter().enumerate() {
        if cancelled() {
            return Err(VerifyError::Cancelled);
        }
        progress(n as u64, targets.len() as u64);
        let result = apply(it, &target.input, cancelled).map_err(|e| match e {
            pl_interp::framing::FrameError::Cancelled => VerifyError::Cancelled,
            other => VerifyError::Stream {
                stream: target.id.clone(),
                why: other.to_string(),
            },
        })?;
        summary.out_of_scope_streams += u64::from(result.out_of_scope);
        let mut rows = Vec::with_capacity(result.messages.len());
        let mut message_bytes = 0;
        for m in &result.messages {
            if summary.messages >= MAX_MESSAGES as u64 {
                return Err(VerifyError::TooManyMessages);
            }
            summary.messages += 1;
            message_bytes += m.end - m.start;
            *summary.counts.entry(m.category).or_default() += 1;
            let key = m.message_id.clone().unwrap_or_else(|| "?".to_owned());
            *summary
                .by_message
                .entry(key)
                .or_default()
                .entry(m.category)
                .or_default() += 1;
            if is_counterexample(m) {
                summary.counterexamples += 1;
                if counterexamples.len() < MAX_COUNTEREXAMPLES {
                    counterexamples.push(Counterexample {
                        anchor: anchor(target, m),
                        category: m.category,
                        message_id: m.message_id.clone(),
                        violations: m
                            .violations
                            .iter()
                            .map(|v| ViolationRow {
                                kind: v.kind,
                                id: v.id.clone(),
                                detail: v.detail.clone(),
                                status: v.status,
                            })
                            .collect(),
                    });
                }
            }
            rows.push(MessageRow(m.start, m.end, m.category, m.message_id.clone()));
        }
        summary.message_bytes += message_bytes;
        summary.unknown_bytes += result.unknown_bytes();
        streams.push(StreamRun {
            id: target.id.clone(),
            source: target.source.clone(),
            out_of_scope: result.out_of_scope,
            counts: result.counts(),
            unknown_bytes: result.unknown_bytes(),
            message_bytes,
            messages: rows,
        });
    }
    summary.counterexamples_truncated = summary.counterexamples > counterexamples.len() as u64;
    progress(targets.len() as u64, targets.len() as u64);
    Ok(Run {
        id: String::new(),
        inputs,
        summary,
        streams,
        counterexamples,
    })
}

// ------------------------------------------------------------ устаревание

/// Текущие условия проекта для сверки с подписью прогона.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Current {
    pub interpretation_digest: Option<String>,
    pub settings_digest: String,
    /// sha256 записей, доступных сейчас.
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaleReason {
    /// Интерпретацию изменили после прогона.
    Interpretation,
    /// Изменены настройки сборки потоков.
    Settings,
    /// Записи корпуса пропали из проекта.
    Sources,
}

pub fn stale_reasons(run: &Run, current: &Current) -> Vec<StaleReason> {
    let mut out = Vec::new();
    if current.interpretation_digest.as_deref() != Some(run.inputs.interpretation_digest.as_str()) {
        out.push(StaleReason::Interpretation);
    }
    if current.settings_digest != run.inputs.settings_digest {
        out.push(StaleReason::Settings);
    }
    if !run
        .inputs
        .sources
        .iter()
        .all(|s| current.sources.contains(s))
    {
        out.push(StaleReason::Sources);
    }
    out
}

// -------------------------------------------------------------- сравнение

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// Стало лучше: нарушенное или неохваченное теперь совпало.
    Fixed,
    /// Стало хуже.
    Regressed,
    /// Категория другого рода, не лучше и не хуже.
    Changed,
    /// Сообщения не было в первом прогоне.
    Added,
    /// Сообщения нет во втором прогоне.
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Change {
    pub stream: String,
    pub start: u64,
    pub end: u64,
    pub kind: ChangeKind,
    pub from: Option<Category>,
    pub to: Option<Category>,
    pub message_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DiffTotals {
    pub fixed: u64,
    pub regressed: u64,
    pub changed: u64,
    pub added: u64,
    pub removed: u64,
    pub unchanged: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunDiff {
    pub a: String,
    pub b: String,
    pub totals: DiffTotals,
    pub counts_a: BTreeMap<Category, u64>,
    pub counts_b: BTreeMap<Category, u64>,
    pub changes: Vec<Change>,
}

/// Качество категории: чем меньше, тем лучше.
fn rank(c: Category) -> u8 {
    match c {
        Category::Matched => 0,
        Category::Ambiguous | Category::Incomplete => 1,
        Category::Unmatched | Category::Violated | Category::LimitExceeded => 2,
    }
}

/// Сравнивает прогоны по сообщениям: ключ — поток и начало сообщения.
pub fn diff(a: &Run, b: &Run) -> RunDiff {
    type Key<'x> = (&'x str, u64);
    let index = |run: &'_ Run| -> BTreeMap<(String, u64), MessageRow> {
        run.streams
            .iter()
            .flat_map(|s| {
                s.messages
                    .iter()
                    .map(move |m| ((s.id.clone(), m.0), m.clone()))
            })
            .collect()
    };
    let _: Option<Key<'_>> = None;
    let (ia, ib) = (index(a), index(b));
    let mut totals = DiffTotals::default();
    let mut changes = Vec::new();
    let keys: std::collections::BTreeSet<&(String, u64)> = ia.keys().chain(ib.keys()).collect();
    for key in keys {
        let (left, right) = (ia.get(key), ib.get(key));
        let kind = match (left, right) {
            (Some(l), Some(r)) if l.2 == r.2 && l.1 == r.1 && l.3 == r.3 => {
                totals.unchanged += 1;
                continue;
            }
            (Some(l), Some(r)) => match rank(r.2).cmp(&rank(l.2)) {
                std::cmp::Ordering::Less => ChangeKind::Fixed,
                std::cmp::Ordering::Greater => ChangeKind::Regressed,
                std::cmp::Ordering::Equal => ChangeKind::Changed,
            },
            (None, Some(_)) => ChangeKind::Added,
            _ => ChangeKind::Removed,
        };
        match kind {
            ChangeKind::Fixed => totals.fixed += 1,
            ChangeKind::Regressed => totals.regressed += 1,
            ChangeKind::Changed => totals.changed += 1,
            ChangeKind::Added => totals.added += 1,
            ChangeKind::Removed => totals.removed += 1,
        }
        let shown = right.or(left);
        changes.push(Change {
            stream: key.0.clone(),
            start: key.1,
            end: shown.map_or(key.1, |m| m.1),
            kind,
            from: left.map(|m| m.2),
            to: right.map(|m| m.2),
            message_id: shown.and_then(|m| m.3.clone()),
        });
    }
    let totals_counts = |r: &Run| r.summary.counts.clone();
    RunDiff {
        a: a.id.clone(),
        b: b.id.clone(),
        totals,
        counts_a: totals_counts(a),
        counts_b: totals_counts(b),
        changes,
    }
}
