use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};

use pl_core::{Limit, Problem, ProblemKind};
use serde::Serialize;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

/// Предел одновременных долгих задач (`plan/security.md` §6).
pub const MAX_CONCURRENT_JOBS: usize = 2;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    Import,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Cancelling,
    Succeeded,
    Failed,
    Cancelled,
}

impl JobState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProgressStage {
    Reading,
    Reassembling,
    Saving,
    Done,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProgressUnit {
    Frames,
    Bytes,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct JobProgress {
    pub stage: ProgressStage,
    pub done: u64,
    /// 0 — пока неизвестно.
    pub total: u64,
    pub unit: ProgressUnit,
}

/// Снимок задачи; ровно то, что отдаёт API.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Job {
    pub id: String,
    pub kind: JobKind,
    pub state: JobState,
    pub progress: JobProgress,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Problem>,
}

struct Entry {
    tx: watch::Sender<Job>,
    cancel: CancellationToken,
}

#[derive(Default)]
struct Inner {
    next_id: u64,
    jobs: BTreeMap<String, Entry>,
}

/// Реестр долгих задач: прогресс, отмена, изоляция паник.
#[derive(Clone, Default)]
pub struct JobRegistry {
    inner: Arc<Mutex<Inner>>,
}

/// Что получает сама задача: токен отмены и отчёт о прогрессе.
#[derive(Clone)]
pub struct JobContext {
    cancel: CancellationToken,
    tx: watch::Sender<Job>,
}

impl JobContext {
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub fn progress(&self, stage: ProgressStage, done: u64, total: u64, unit: ProgressUnit) {
        self.tx.send_modify(|job| {
            job.progress = JobProgress {
                stage,
                done,
                total,
                unit,
            };
        });
    }
}

impl JobRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // Отравление возможно только при панике внутри наших коротких секций; данные целы.
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Запускает задачу; вызывать внутри рантайма tokio.
    /// Паника в `work` превращается в ошибку задачи, сервер продолжает работать.
    pub fn spawn<F, Fut>(&self, kind: JobKind, work: F) -> Result<String, Problem>
    where
        F: FnOnce(JobContext) -> Fut + Send + 'static,
        Fut: Future<Output = Result<serde_json::Value, Problem>> + Send + 'static,
    {
        let cancel = CancellationToken::new();
        let (id, tx) = {
            let mut inner = self.lock();
            let active = inner
                .jobs
                .values()
                .filter(|e| !e.tx.borrow().state.is_terminal())
                .count();
            if active >= MAX_CONCURRENT_JOBS {
                return Err(Problem::new(
                    ProblemKind::TooManyJobs,
                    format!(
                        "Одновременно можно выполнять не больше {MAX_CONCURRENT_JOBS} задач, дождитесь завершения."
                    ),
                )
                .with_limit(Limit {
                    name: "max_concurrent_jobs",
                    value: MAX_CONCURRENT_JOBS as u64,
                    unit: "jobs",
                }));
            }
            inner.next_id += 1;
            let id = format!("job-{:04}", inner.next_id);
            let (tx, _rx) = watch::channel(Job {
                id: id.clone(),
                kind,
                state: JobState::Running,
                progress: JobProgress {
                    stage: ProgressStage::Reading,
                    done: 0,
                    total: 0,
                    unit: ProgressUnit::Frames,
                },
                result: None,
                error: None,
            });
            inner.jobs.insert(
                id.clone(),
                Entry {
                    tx: tx.clone(),
                    cancel: cancel.clone(),
                },
            );
            (id, tx)
        };

        let ctx = JobContext {
            cancel: cancel.clone(),
            tx: tx.clone(),
        };
        // Вложенный spawn нужен, чтобы JoinHandle сообщил о панике, а не уронил наблюдателя.
        let handle = tokio::spawn(work(ctx));
        tokio::spawn(async move {
            let outcome = handle.await;
            let cancelled = cancel.is_cancelled();
            tx.send_modify(|job| match outcome {
                _ if cancelled => job.state = JobState::Cancelled,
                Ok(Ok(result)) => {
                    job.state = JobState::Succeeded;
                    job.progress.stage = ProgressStage::Done;
                    job.result = Some(result);
                }
                Ok(Err(problem)) => {
                    job.state = JobState::Failed;
                    job.error = Some(problem);
                }
                Err(err) => {
                    // Содержимое паники в лог не пишем: оно может включать данные записи.
                    tracing::error!(job = %job.id, panicked = err.is_panic(), "задача завершилась сбоем");
                    job.state = JobState::Failed;
                    job.error = Some(Problem::new(
                        ProblemKind::Internal,
                        "Задача завершилась сбоем. Остальные задачи и сервер работают, повторите операцию.",
                    ));
                }
            });
        });
        Ok(id)
    }

    /// Есть ли незавершённые задачи (проект нельзя закрыть, пока они идут).
    pub fn has_active(&self) -> bool {
        self.lock()
            .jobs
            .values()
            .any(|e| !e.tx.borrow().state.is_terminal())
    }

    pub fn get(&self, id: &str) -> Option<Job> {
        self.lock().jobs.get(id).map(|e| e.tx.borrow().clone())
    }

    /// Подписка на изменения задачи (для SSE).
    pub fn subscribe(&self, id: &str) -> Option<watch::Receiver<Job>> {
        self.lock().jobs.get(id).map(|e| e.tx.subscribe())
    }

    /// Задачи сессии, новые первыми.
    pub fn list(&self) -> Vec<Job> {
        self.lock()
            .jobs
            .values()
            .rev()
            .map(|e| e.tx.borrow().clone())
            .collect()
    }

    /// Запрашивает отмену; завершённая задача — конфликт.
    pub fn cancel(&self, id: &str) -> Result<Job, Problem> {
        let inner = self.lock();
        let entry = inner.jobs.get(id).ok_or_else(|| {
            Problem::new(ProblemKind::NotFound, format!("Задача {id} не найдена."))
        })?;
        if entry.tx.borrow().state.is_terminal() {
            return Err(Problem::new(
                ProblemKind::Conflict,
                format!("Задача {id} уже завершена."),
            ));
        }
        entry.cancel.cancel();
        entry.tx.send_if_modified(|job| {
            let alive = !job.state.is_terminal();
            if alive {
                job.state = JobState::Cancelling;
            }
            alive
        });
        Ok(entry.tx.borrow().clone())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    async fn finished(registry: &JobRegistry, id: &str) -> Job {
        let mut rx = registry.subscribe(id).expect("задача есть");
        loop {
            let job = rx.borrow_and_update().clone();
            if job.state.is_terminal() {
                return job;
            }
            rx.changed().await.expect("задача не исчезает");
        }
    }

    #[tokio::test]
    async fn successful_job_keeps_result() {
        let registry = JobRegistry::new();
        let id = registry
            .spawn(JobKind::Import, |ctx| async move {
                ctx.progress(ProgressStage::Reading, 5, 10, ProgressUnit::Frames);
                Ok(serde_json::json!({ "ok": true }))
            })
            .unwrap();
        let job = finished(&registry, &id).await;
        assert_eq!(job.state, JobState::Succeeded);
        assert_eq!(job.progress.stage, ProgressStage::Done);
        assert_eq!(job.result, Some(serde_json::json!({ "ok": true })));
    }

    #[tokio::test]
    async fn panic_becomes_failed_job() {
        let registry = JobRegistry::new();
        let id = registry
            .spawn(JobKind::Import, |_ctx| async move {
                if true {
                    panic!("сбой");
                }
                Ok(serde_json::Value::Null)
            })
            .unwrap();
        let job = finished(&registry, &id).await;
        assert_eq!(job.state, JobState::Failed);
        assert_eq!(job.error.map(|p| p.status), Some(500));
        // Реестр продолжает принимать задачи.
        assert!(
            registry
                .spawn(JobKind::Import, |_| async { Ok(serde_json::Value::Null) })
                .is_ok()
        );
    }

    #[tokio::test]
    async fn cancel_stops_job() {
        let registry = JobRegistry::new();
        let id = registry
            .spawn(JobKind::Import, |ctx| async move {
                ctx.cancel_token().cancelled().await;
                Err(Problem::new(ProblemKind::Conflict, "отменено"))
            })
            .unwrap();
        let cancelling = registry.cancel(&id).unwrap();
        assert_eq!(cancelling.state, JobState::Cancelling);
        assert_eq!(finished(&registry, &id).await.state, JobState::Cancelled);
        assert_eq!(registry.cancel(&id).unwrap_err().status, 409);
    }

    #[tokio::test]
    async fn concurrent_limit_is_enforced() {
        let registry = JobRegistry::new();
        let blocker = |ctx: JobContext| async move {
            ctx.cancel_token().cancelled().await;
            Ok(serde_json::Value::Null)
        };
        let first = registry.spawn(JobKind::Import, blocker).unwrap();
        registry.spawn(JobKind::Import, blocker).unwrap();
        let err = registry.spawn(JobKind::Import, blocker).unwrap_err();
        assert_eq!(err.status, 429);
        assert!(err.limit.is_some());

        registry.cancel(&first).unwrap();
        finished(&registry, &first).await;
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(registry.spawn(JobKind::Import, blocker).is_ok());
    }

    #[tokio::test]
    async fn unknown_job_is_not_found() {
        assert_eq!(
            JobRegistry::new().cancel("job-9999").unwrap_err().status,
            404
        );
    }
}
