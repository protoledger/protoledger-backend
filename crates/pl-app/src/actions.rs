//! Журналы действий проекта и поиск обмена по действию.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use pl_actions::{Action, LogError, Mapping, RowError};
use pl_core::{Limit, Problem, ProblemKind};
use pl_interp::{Category, Interpretation};
use pl_project::ActionLogRecord;
use pl_verify::RunInputs;

use crate::{Session, SourceData, SourceStore, stream_input};

/// Разобранный журнал в памяти.
#[derive(Debug)]
pub struct LoadedLog {
    pub record: ActionLogRecord,
    pub actions: Vec<Action>,
    /// Строки, которые не разобрались (первые 100).
    pub errors: Vec<RowError>,
    pub skipped: u64,
}

impl LoadedLog {
    pub fn time_range(&self) -> Option<(u64, u64)> {
        let first = self.actions.iter().map(|a| a.ts_ns).min()?;
        let last = self.actions.iter().map(|a| a.ts_ns).max()?;
        Some((first, last))
    }

    pub fn action(&self, line: u64) -> Option<&Action> {
        self.actions.iter().find(|a| a.line == line)
    }
}

#[derive(Clone, Default)]
pub struct ActionLogStore {
    inner: Arc<RwLock<Vec<Arc<LoadedLog>>>>,
}

impl ActionLogStore {
    /// Все записи журналов проекта в порядке импорта, включая заменённые.
    pub fn all(&self) -> Vec<Arc<LoadedLog>> {
        self.inner.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Действующие журналы: файл, импортированный повторно, представлен последней записью —
    /// иначе его действия учитывались бы дважды, со старым и с новым сопоставлением.
    pub fn list(&self) -> Vec<Arc<LoadedLog>> {
        let all = self.all();
        all.iter()
            .enumerate()
            .filter(|(i, l)| {
                !all.iter()
                    .skip(i + 1)
                    .any(|next| next.record.sha256 == l.record.sha256)
            })
            .map(|(_, l)| Arc::clone(l))
            .collect()
    }

    pub fn get(&self, id: &str) -> Option<Arc<LoadedLog>> {
        self.all().into_iter().find(|l| l.record.id == id)
    }

    /// Запись, заменившая эту: последний импорт того же файла.
    pub fn replaced_by(&self, id: &str) -> Option<String> {
        let all = self.all();
        let sha256 = &all.iter().find(|l| l.record.id == id)?.record.sha256;
        let last = all.iter().rev().find(|l| &l.record.sha256 == sha256)?;
        (last.record.id != id).then(|| last.record.id.clone())
    }

    /// Журналы, по которым выполнен сохранённый прогон, в порядке импорта: запись с тем
    /// сопоставлением, которое прогон запомнил, иначе — первый импорт файла.
    pub fn for_run(&self, inputs: &RunInputs) -> Vec<Arc<LoadedLog>> {
        let all = self.all();
        let chosen: Vec<&str> = inputs
            .logs
            .iter()
            .filter_map(|sha256| {
                let mut same = all.iter().filter(|l| &l.record.sha256 == sha256);
                match inputs.log_mappings.get(sha256) {
                    Some(digest) => {
                        same.rfind(|l| &pl_verify::digest_of(&l.record.mapping) == digest)
                    }
                    None => same.next(),
                }
            })
            .map(|l| l.record.id.as_str())
            .collect();
        all.iter()
            .filter(|l| chosen.contains(&l.record.id.as_str()))
            .cloned()
            .collect()
    }

    pub fn clear(&self) {
        self.inner
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    /// Хранилище с готовыми журналами — для командной строки, где проекта нет.
    pub fn from_logs(logs: Vec<Arc<LoadedLog>>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(logs)),
        }
    }

    fn push(&self, log: Arc<LoadedLog>) {
        self.inner
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .push(log);
    }
}

fn log_problem(e: LogError) -> Problem {
    match e {
        LogError::TooLarge | LogError::TooManyRows => {
            Problem::new(ProblemKind::LimitExceeded, e.to_string()).with_limit(Limit {
                name: "max_action_log_size",
                value: pl_actions::MAX_FILE_BYTES as u64,
                unit: "bytes",
            })
        }
        other => Problem::new(
            ProblemKind::Unprocessable,
            format!("Журнал действий не разобран: {other}."),
        ),
    }
}

/// Разбирает и сохраняет журнал в проект. Без открытого проекта — `409`.
pub fn import_action_log(
    session: &Session,
    store: &ActionLogStore,
    name: &str,
    bytes: &[u8],
    mapping: Mapping,
) -> Result<Arc<LoadedLog>, Problem> {
    let parsed = pl_actions::parse(bytes, &mapping).map_err(log_problem)?;
    let mut guard = session.write();
    let project = guard.as_mut().ok_or_else(Session::no_project)?;
    let record = project
        .add_action_log(name, bytes, &mapping, parsed.actions.len() as u64)
        .map_err(Problem::from)?;
    let loaded = Arc::new(LoadedLog {
        record,
        actions: parsed.actions,
        errors: parsed.errors,
        skipped: parsed.skipped,
    });
    store.push(Arc::clone(&loaded));
    Ok(loaded)
}

/// Сопоставления действующих журналов, отличные от первого импорта того же файла:
/// sha256 → дайджест. Пока файл импортирован один раз, здесь пусто.
pub fn mapping_overrides(records: &[ActionLogRecord]) -> BTreeMap<String, String> {
    let mut first: BTreeMap<&str, String> = BTreeMap::new();
    let mut last: BTreeMap<&str, String> = BTreeMap::new();
    for r in records {
        let digest = pl_verify::digest_of(&r.mapping);
        first
            .entry(r.sha256.as_str())
            .or_insert_with(|| digest.clone());
        last.insert(r.sha256.as_str(), digest);
    }
    last.into_iter()
        .filter(|(sha256, digest)| first.get(sha256) != Some(digest))
        .map(|(sha256, digest)| (sha256.to_owned(), digest))
        .collect()
}

/// Разбирает сохранённую копию журнала заново с другой поправкой часов. Новая запись заменяет
/// прежнюю в анализе; прежняя остаётся в проекте: по ней воспроизводятся старые прогоны.
pub fn apply_clock_offset(
    session: &Session,
    store: &ActionLogStore,
    id: &str,
    clock_offset_ms: i64,
) -> Result<Arc<LoadedLog>, Problem> {
    let log = store.get(id).ok_or_else(|| {
        Problem::new(ProblemKind::NotFound, format!("Журнала действий {id} нет."))
    })?;
    if let Some(newer) = store.replaced_by(id) {
        return Err(Problem::new(
            ProblemKind::Conflict,
            format!("Журнал {id} заменён записью {newer}: поправку применяют к ней."),
        ));
    }
    if log.record.mapping.clock_offset_ms == clock_offset_ms {
        return Err(Problem::new(
            ProblemKind::Conflict,
            format!("Поправка часов журнала {id} уже равна {clock_offset_ms} мс."),
        ));
    }
    let bytes = {
        let guard = session.read();
        let project = guard.as_ref().ok_or_else(Session::no_project)?;
        project.read_action_log(id).map_err(Problem::from)?
    };
    let mapping = Mapping {
        clock_offset_ms,
        ..log.record.mapping.clone()
    };
    import_action_log(session, store, &log.record.name, &bytes, mapping)
}

/// После открытия проекта заново разбирает его журналы; испорченные пропускаются с записью в лог.
pub fn reload_action_logs(session: &Session, store: &ActionLogStore) {
    store.clear();
    let guard = session.read();
    let Some(project) = guard.as_ref() else {
        return;
    };
    for record in project.action_logs() {
        let parsed = project
            .read_action_log(&record.id)
            .map_err(|e| e.to_string())
            .and_then(|bytes| {
                pl_actions::parse(&bytes, &record.mapping).map_err(|e| e.to_string())
            });
        match parsed {
            Ok(p) => store.push(Arc::new(LoadedLog {
                record: record.clone(),
                actions: p.actions,
                errors: p.errors,
                skipped: p.skipped,
            })),
            Err(why) => tracing::warn!(log = %record.id, "журнал действий не загружен: {why}"),
        }
    }
}

// --------------------------------------------------------- поиск обмена

/// Кадр с данными потока в окне времени.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHit {
    pub source: String,
    pub stream: String,
    pub frame_no: u32,
    pub ts_ns: u64,
    pub start: u64,
    pub end: u64,
    pub duplicate: bool,
}

/// Сообщение, чьи кадры попали в окно.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageHit {
    pub source: String,
    pub stream: String,
    pub start: u64,
    pub end: u64,
    pub category: Category,
    pub message_id: Option<String>,
    pub first_ts_ns: u64,
    pub last_ts_ns: u64,
}

#[derive(Debug, Default)]
pub struct Exchange {
    pub frames: Vec<FrameHit>,
    pub messages: Vec<MessageHit>,
}

const SUFFIX: [&str; 2] = ["ab", "ba"];

/// Ищет в записях кадры и сообщения во временном окне `[from_ns, to_ns]`.
pub fn find_exchange(
    sources: &[Arc<SourceData>],
    interpretation: Option<&Interpretation>,
    from_ns: u64,
    to_ns: u64,
) -> Exchange {
    let mut out = Exchange::default();
    for data in sources {
        for connection in &data.connections {
            let id = connection.id(&data.sha256);
            for (i, stream) in connection.streams.iter().enumerate() {
                let stream_id = format!("{id}:{}", SUFFIX.get(i).copied().unwrap_or("ab"));
                let ts = |frame_no: u32| data.index.frame(frame_no).map_or(0, |f| f.ts_ns);
                let hits: Vec<_> = stream
                    .frames
                    .iter()
                    .filter(|f| (from_ns..=to_ns).contains(&ts(f.frame)))
                    .collect();
                if hits.is_empty() {
                    continue;
                }
                out.frames.extend(hits.iter().map(|f| FrameHit {
                    source: data.sha256.clone(),
                    stream: stream_id.clone(),
                    frame_no: f.frame,
                    ts_ns: ts(f.frame),
                    start: f.start,
                    end: f.end,
                    duplicate: f.duplicate,
                }));
                let Some(it) = interpretation else {
                    continue;
                };
                let input = stream_input(&data.file, connection, stream, i);
                let Ok(result) = pl_interp::apply(it, &input, &|| false) else {
                    continue;
                };
                for m in &result.messages {
                    let times: Vec<u64> = stream
                        .frames
                        .iter()
                        .filter(|f| f.start < m.end && f.end > m.start)
                        .map(|f| ts(f.frame))
                        .collect();
                    let (Some(first), Some(last)) = (times.iter().min(), times.iter().max()) else {
                        continue;
                    };
                    // Сообщение входит в обмен, если хотя бы один его кадр попал в окно.
                    if times.iter().any(|t| (from_ns..=to_ns).contains(t)) {
                        out.messages.push(MessageHit {
                            source: data.sha256.clone(),
                            stream: stream_id.clone(),
                            start: m.start,
                            end: m.end,
                            category: m.category,
                            message_id: m.message_id.clone(),
                            first_ts_ns: *first,
                            last_ts_ns: *last,
                        });
                    }
                }
            }
        }
    }
    out.frames.sort_by_key(|f| (f.ts_ns, f.frame_no));
    out.messages.sort_by_key(|m| (m.first_ts_ns, m.start));
    out
}

/// Текущая интерпретация проекта для поиска обмена; `None`, если не сохранялась или не разбирается.
pub fn current_interpretation(session: &Session) -> Option<Interpretation> {
    let guard = session.read();
    let (_, yaml) = guard.as_ref()?.current_interpretation().ok().flatten()?;
    Interpretation::parse(&yaml).ok()
}

/// Все записи проекта для поиска.
pub fn all_sources(store: &SourceStore) -> Vec<Arc<SourceData>> {
    store.list()
}
