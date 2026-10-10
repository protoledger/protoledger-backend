use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use pl_capture::{CaptureError, CaptureIndex, Format, Limits};
use pl_core::{Limit, Problem, ProblemKind};
use pl_reassembly::{Connection, Policy, ReassemblyError};
use sha2::{Digest, Sha256};

use crate::{JobContext, JobKind, JobRegistry, ProgressStage, ProgressUnit};

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
    imports: u64,
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

    pub fn next_import_id(&self) -> String {
        let mut inner = self.write();
        inner.imports += 1;
        format!("imp-{:04}", inner.imports)
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
    let total = file.len() as u64;
    let sha256: String = Sha256::digest(&file)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let cancelled = || ctx.is_cancelled();
    ctx.progress(ProgressStage::Reading, 0, total, ProgressUnit::Bytes);
    let index = pl_capture::index(&file, Limits::default(), &cancelled, &mut |done| {
        ctx.progress(ProgressStage::Reading, done, total, ProgressUnit::Bytes);
    })
    .map_err(capture_problem)?;
    let frames = index.frames.len() as u64;
    ctx.progress(ProgressStage::Reassembling, 0, frames, ProgressUnit::Frames);
    let connections =
        pl_reassembly::reassemble(&index, &file, policy, &cancelled).map_err(reassembly_problem)?;
    ctx.progress(
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

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "запись".into())
}

/// Запускает импорт записи по пути; возвращает id задачи. Результат задачи —
/// `{sourceSha256, importId}`.
pub fn import_path(
    jobs: &JobRegistry,
    store: &SourceStore,
    path: PathBuf,
    policy: Policy,
) -> Result<String, Problem> {
    let store = store.clone();
    jobs.spawn(JobKind::Import, move |ctx| async move {
        let import_id = store.next_import_id();
        let work = tokio::task::spawn_blocking(move || {
            let file = read_capture_file(&path)?;
            analyze(file, file_name(&path), import_id, policy, &ctx)
        });
        let data = work.await.map_err(|_| {
            Problem::new(
                ProblemKind::Internal,
                "Разбор записи завершился сбоем. Сервер работает, повторите импорт.",
            )
        })??;
        let result = serde_json::json!({
            "sourceSha256": data.sha256,
            "importId": data.import_id,
        });
        store.insert(data);
        Ok(result)
    })
}
