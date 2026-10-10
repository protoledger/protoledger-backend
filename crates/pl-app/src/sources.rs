use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use pl_capture::{CaptureError, CaptureIndex, Format, Limits};
use pl_core::{Limit, Problem, ProblemKind};
use pl_reassembly::{Connection, Policy, ReassemblyError};
use sha2::{Digest, Sha256};

use pl_project::Project;

use crate::{JobContext, JobKind, JobRegistry, ProgressStage, ProgressUnit, Session};

/// Разобранная запись: файл целиком в памяти, индекс кадров и соединения.
#[derive(Debug)]
pub struct SourceData {
    pub sha256: String,
    pub import_id: String,
    pub name: String,
    pub file: Vec<u8>,
    pub index: CaptureIndex,
    pub connections: Vec<Connection>,
}

impl SourceData {
    pub fn format(&self) -> Format {
        self.index.format
    }

    /// Первые 8 hex sha256 — префикс идентификаторов соединений и потоков.
    pub fn prefix(&self) -> &str {
        self.sha256.get(..8).unwrap_or(&self.sha256)
    }
}

#[derive(Default)]
struct Inner {
    sources: Vec<Arc<SourceData>>,
}

/// Записи текущей сессии в порядке импорта.
#[derive(Clone, Default)]
pub struct SourceStore {
    inner: Arc<RwLock<Inner>>,
}

impl SourceStore {
    // Отравление возможно только при панике внутри коротких секций; данные целы.
    fn read(&self) -> RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(|p| p.into_inner())
    }

    fn write(&self) -> RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(|p| p.into_inner())
    }

    /// Забывает все записи (при смене проекта).
    pub fn clear(&self) {
        self.write().sources.clear();
    }

    /// Повторный импорт той же записи заменяет её данные и `importId`, места в списке не меняет.
    pub fn insert(&self, data: SourceData) {
        let data = Arc::new(data);
        let mut inner = self.write();
        match inner.sources.iter_mut().find(|s| s.sha256 == data.sha256) {
            Some(slot) => *slot = data,
            None => inner.sources.push(data),
        }
    }

    pub fn list(&self) -> Vec<Arc<SourceData>> {
        self.read().sources.clone()
    }

    pub fn get(&self, sha256: &str) -> Option<Arc<SourceData>> {
        self.read()
            .sources
            .iter()
            .find(|s| s.sha256 == sha256)
            .cloned()
    }

    pub fn by_prefix(&self, prefix: &str) -> Option<Arc<SourceData>> {
        self.read()
            .sources
            .iter()
            .find(|s| s.prefix() == prefix)
            .cloned()
    }
}

fn capture_problem(e: CaptureError) -> Problem {
    match e {
        CaptureError::NotCapture => Problem::new(ProblemKind::Unprocessable, e.to_string()),
        CaptureError::LimitExceeded { name, value, .. } => {
            Problem::new(ProblemKind::LimitExceeded, e.to_string()).with_limit(Limit {
                name,
                value,
                unit: "",
            })
        }
        CaptureError::Cancelled => Problem::new(ProblemKind::Conflict, e.to_string()),
    }
}

fn reassembly_problem(e: ReassemblyError) -> Problem {
    match e {
        ReassemblyError::LimitExceeded { name, value, .. } => {
            Problem::new(ProblemKind::LimitExceeded, e.to_string()).with_limit(Limit {
                name,
                value,
                unit: "",
            })
        }
        ReassemblyError::Cancelled => Problem::new(ProblemKind::Conflict, e.to_string()),
    }
}

/// Индексирует и собирает запись. Синхронно и долго — вызывать вне потоков рантайма.
pub fn analyze(
    file: Vec<u8>,
    name: String,
    import_id: String,
    policy: Policy,
    ctx: &JobContext,
) -> Result<SourceData, Problem> {
    analyze_with(
        file,
        name,
        import_id,
        policy,
        &|| ctx.is_cancelled(),
        &mut |stage, done, total, unit| {
            ctx.progress(stage, done, total, unit);
        },
    )
}

/// То же без задачи: для командной строки и тестов.
pub fn analyze_with(
    file: Vec<u8>,
    name: String,
    import_id: String,
    policy: Policy,
    cancelled: &dyn Fn() -> bool,
    progress: &mut dyn FnMut(ProgressStage, u64, u64, ProgressUnit),
) -> Result<SourceData, Problem> {
    let total = file.len() as u64;
    let sha256: String = Sha256::digest(&file)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    progress(ProgressStage::Reading, 0, total, ProgressUnit::Bytes);
    let index = pl_capture::index(&file, Limits::default(), cancelled, &mut |done| {
        progress(ProgressStage::Reading, done, total, ProgressUnit::Bytes);
    })
    .map_err(capture_problem)?;
    let frames = index.frames.len() as u64;
    progress(ProgressStage::Reassembling, 0, frames, ProgressUnit::Frames);
    let connections =
        pl_reassembly::reassemble(&index, &file, policy, cancelled).map_err(reassembly_problem)?;
    progress(
        ProgressStage::Reassembling,
        frames,
        frames,
        ProgressUnit::Frames,
    );
    Ok(SourceData {
        sha256,
        import_id,
        name,
        file,
        index,
        connections,
    })
}

/// Читает только обычный файл (не каталог, не устройство, не симлинк), размер — до чтения.
pub fn read_capture_file(path: &Path) -> Result<Vec<u8>, Problem> {
    let unreadable = |e: std::io::Error| {
        Problem::new(
            ProblemKind::Unprocessable,
            format!("Не удалось прочитать файл: {e}."),
        )
    };
    let meta = std::fs::symlink_metadata(path).map_err(unreadable)?;
    if !meta.file_type().is_file() {
        return Err(Problem::new(
            ProblemKind::Unprocessable,
            "Можно импортировать только обычный файл записи.",
        ));
    }
    if meta.len() > pl_capture::MAX_FILE_BYTES {
        return Err(capture_problem(CaptureError::LimitExceeded {
            name: "размер файла записи, байт",
            value: meta.len(),
            max: pl_capture::MAX_FILE_BYTES,
        }));
    }
    std::fs::read(path).map_err(unreadable)
}

fn policy_of(project: &Project) -> Policy {
    policy_from(project.manifest().settings)
}

/// Политики сборки потоков из настроек проекта.
pub fn policy_from(settings: pl_project::Settings) -> Policy {
    Policy {
        // «flag» собирает как «first»: неоднозначность и так видна в карте потока.
        overlap: match settings.overlap_policy {
            pl_project::OverlapPolicy::First => pl_reassembly::OverlapPolicy::First,
            pl_project::OverlapPolicy::Last => pl_reassembly::OverlapPolicy::Last,
            pl_project::OverlapPolicy::Flag => pl_reassembly::OverlapPolicy::Flag,
        },
        checksum: match settings.checksum_policy {
            pl_project::ChecksumPolicy::Ignore => pl_reassembly::ChecksumPolicy::Ignore,
            pl_project::ChecksumPolicy::Warn => pl_reassembly::ChecksumPolicy::Warn,
            pl_project::ChecksumPolicy::Drop => pl_reassembly::ChecksumPolicy::Drop,
        },
    }
}

fn blocking_failed() -> Problem {
    Problem::new(
        ProblemKind::Internal,
        "Разбор записи завершился сбоем. Сервер работает, повторите операцию.",
    )
}

/// Запускает импорт записи по пути: копия в проект, затем разбор. Результат задачи —
/// `{sourceSha256, importId}`. Без открытого проекта — `409`.
/// `cleanup` — временная папка загрузки: удаляется после задачи при любом исходе.
pub fn import_path(
    jobs: &JobRegistry,
    store: &SourceStore,
    session: &Session,
    path: PathBuf,
    cleanup: Option<PathBuf>,
) -> Result<String, Problem> {
    if session.read().is_none() {
        return Err(Session::no_project());
    }
    let (store, session) = (store.clone(), session.clone());
    jobs.spawn(JobKind::Import, move |ctx| async move {
        let work = tokio::task::spawn_blocking(move || {
            let (record, copy, policy) = {
                // Блокировка проекта держится на время копирования: манифест меняется атомарно.
                let mut guard = session.write();
                let project = guard.as_mut().ok_or_else(Session::no_project)?;
                let cancelled = || ctx.is_cancelled();
                let record = project
                    .add_source(&path, &cancelled, &mut |done| {
                        ctx.progress(ProgressStage::Reading, done, 0, ProgressUnit::Bytes);
                    })
                    .map_err(Problem::from)?;
                let copy = project.source_path(&record.sha256).map_err(Problem::from)?;
                (record, copy, policy_of(project))
            };
            let file = read_capture_file(&copy)?;
            analyze(file, record.name, record.id, policy, &ctx)
        });
        let outcome = work.await;
        if let Some(dir) = cleanup {
            let _ = std::fs::remove_dir_all(dir);
        }
        let data = outcome.map_err(|_| blocking_failed())??;
        let result = serde_json::json!({
            "sourceSha256": data.sha256,
            "importId": data.import_id,
        });
        store.insert(data);
        Ok(result)
    })
}

/// После открытия проекта заново разбирает его записи из копий в `sources/`.
/// Записи появляются в списке по мере готовности; повреждённые и пропавшие пропускаются.
pub fn reload_sources(
    jobs: &JobRegistry,
    store: &SourceStore,
    session: &Session,
) -> Result<Option<String>, Problem> {
    let plan: Vec<_> = match session.read().as_ref() {
        Some(project) => {
            let policy = policy_of(project);
            project
                .sources()
                .into_iter()
                .filter_map(|s| {
                    let copy = project.source_path(&s.sha256).ok()?;
                    Some((s, copy, policy))
                })
                .collect()
        }
        None => return Err(Session::no_project()),
    };
    if plan.is_empty() {
        return Ok(None);
    }
    let store = store.clone();
    jobs.spawn(JobKind::Import, move |ctx| async move {
        let work = tokio::task::spawn_blocking(move || {
            for (source, copy, policy) in plan {
                if ctx.is_cancelled() {
                    break;
                }
                let file = match read_capture_file(&copy) {
                    Ok(file) => file,
                    Err(problem) => {
                        tracing::warn!(import = %source.import_id, "запись проекта недоступна: {:?}", problem.detail);
                        continue;
                    }
                };
                match analyze(file, source.name, source.import_id, policy, &ctx) {
                    // Копия подменена: хеш не совпал, такую запись не показываем (T11).
                    Ok(data) if data.sha256 == source.sha256 => store.insert(data),
                    Ok(_) => tracing::warn!("копия записи не совпала с sha256"),
                    Err(problem) => tracing::warn!("запись не разобрана: {:?}", problem.detail),
                }
            }
        });
        work.await.map_err(|_| blocking_failed())?;
        Ok(serde_json::Value::Null)
    })
    .map(Some)
}

/// Разбирает записи открытого проекта из копий в `sources/` синхронно (для командной строки).
/// Копия, не совпавшая с sha256, не загружается и попадает в список проблем.
pub fn load_project_sources(
    session: &Session,
    store: &SourceStore,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<String>, Problem> {
    let (plan, policy) = {
        let guard = session.read();
        let project = guard.as_ref().ok_or_else(Session::no_project)?;
        let plan: Vec<_> = project
            .sources()
            .into_iter()
            .filter_map(|s| project.source_path(&s.sha256).ok().map(|p| (s, p)))
            .collect();
        (plan, policy_of(project))
    };
    let mut problems = Vec::new();
    for (source, path) in plan {
        let file = match read_capture_file(&path) {
            Ok(file) => file,
            Err(p) => {
                problems.push(format!("{}: {}", source.name, p.detail.unwrap_or_default()));
                continue;
            }
        };
        let data = analyze_with(
            file,
            source.name.clone(),
            source.import_id,
            policy,
            cancelled,
            &mut |_, _, _, _| {},
        )?;
        if data.sha256 == source.sha256 {
            store.insert(data);
        } else {
            problems.push(format!(
                "{}: копия в проекте не совпала с sha256, запись не загружена",
                source.name
            ));
        }
    }
    Ok(problems)
}
