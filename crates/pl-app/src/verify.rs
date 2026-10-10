//! Прогон проверки как долгая задача: интерпретация применяется к потокам корпуса, результат
//! сохраняется в проект.

use std::sync::Arc;

use pl_core::{Problem, ProblemKind};
use pl_interp::Interpretation;
use pl_project::{ChecksumPolicy, OverlapPolicy};
use pl_verify::{CorpusFilter, Current, RunInputs, StreamTarget};
use serde::Serialize;

use crate::{
    JobKind, JobRegistry, ProgressStage, ProgressUnit, Session, SourceData, SourceStore,
    stream_input,
};

const DIRECTION_SUFFIX: [&str; 2] = ["ab", "ba"];

#[derive(Serialize)]
struct SettingsSignature {
    overlap: OverlapPolicy,
    checksum: ChecksumPolicy,
}

fn blocking_failed() -> Problem {
    Problem::new(
        ProblemKind::Internal,
        "Прогон завершился сбоем. Сервер работает, повторите.",
    )
}

fn verify_problem(e: pl_verify::VerifyError) -> Problem {
    match e {
        pl_verify::VerifyError::Cancelled => Problem::new(ProblemKind::Conflict, "Прогон отменён."),
        pl_verify::VerifyError::TooManyMessages => Problem::new(
            ProblemKind::LimitExceeded,
            "В прогоне слишком много сообщений: сузьте корпус фильтрами.",
        ),
        other => Problem::new(ProblemKind::Unprocessable, other.to_string()),
    }
}

/// Условия проекта сейчас, для сверки с подписью прогона.
pub fn current_signature(session: &Session, store: &SourceStore) -> Option<Current> {
    let guard = session.read();
    let project = guard.as_ref()?;
    let settings = project.manifest().settings;
    Some(Current {
        interpretation_digest: project
            .interpretation_revisions()
            .last()
            .map(|r| r.digest.clone()),
        settings_digest: pl_verify::digest_of(&SettingsSignature {
            overlap: settings.overlap_policy,
            checksum: settings.checksum_policy,
        }),
        sources: store.list().iter().map(|s| s.sha256.clone()).collect(),
    })
}

/// Все потоки записей корпуса, по порядку записей, соединений и направлений.
fn targets<'a>(sources: &'a [Arc<SourceData>], corpus: &CorpusFilter) -> Vec<StreamTarget<'a>> {
    let mut out = Vec::new();
    for data in sources {
        for connection in &data.connections {
            let id = connection.id(&data.sha256);
            for (i, stream) in connection.streams.iter().enumerate() {
                let input = stream_input(&data.file, connection, stream, i);
                if !corpus.accepts(&data.sha256, i, input.meta.src_port, input.meta.dst_port) {
                    continue;
                }
                out.push(StreamTarget {
                    id: format!("{id}:{}", DIRECTION_SUFFIX.get(i).copied().unwrap_or("ab")),
                    source: data.sha256.clone(),
                    input,
                });
            }
        }
    }
    out
}

/// Прогон без задачи: интерпретация применяется к потокам корпуса, результат не сохраняется.
pub fn execute_run(
    interpretation: &Interpretation,
    revision: Option<u32>,
    sources: &[Arc<SourceData>],
    corpus: &CorpusFilter,
    settings_digest: String,
    cancelled: &dyn Fn() -> bool,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<pl_verify::Run, Problem> {
    let targets = targets(sources, corpus);
    let mut used: Vec<String> = targets.iter().map(|t| t.source.clone()).collect();
    used.sort();
    used.dedup();
    let inputs = RunInputs {
        revision,
        interpretation_digest: interpretation.digest(),
        settings_digest,
        sources: used,
        corpus: corpus.clone(),
        engine_version: env!("CARGO_PKG_VERSION").to_owned(),
    };
    pl_verify::execute(interpretation, &targets, inputs, cancelled, progress)
        .map_err(verify_problem)
}

/// Запускает прогон; результат задачи — `{runId}`.
pub fn start_verify(
    jobs: &JobRegistry,
    store: &SourceStore,
    session: &Session,
    corpus: CorpusFilter,
    revision: Option<u32>,
) -> Result<String, Problem> {
    // Проверки до запуска: проект, интерпретация и её корректность.
    let (rev, yaml) = {
        let guard = session.read();
        let project = guard.as_ref().ok_or_else(Session::no_project)?;
        let found = match revision {
            Some(r) => project.read_interpretation(r).map_err(Problem::from)?,
            None => project
                .current_interpretation()
                .map_err(Problem::from)?
                .ok_or_else(|| {
                    Problem::new(
                        ProblemKind::Conflict,
                        "Интерпретации ещё нет: сохраните её через PUT /api/interpretation.",
                    )
                })?,
        };
        (found.0.rev, found.1)
    };
    let interpretation = Interpretation::parse(&yaml).map_err(|e| {
        Problem::new(
            ProblemKind::Unprocessable,
            format!("Интерпретация не проходит проверку: {e}"),
        )
    })?;
    if store.list().is_empty() {
        return Err(Problem::new(
            ProblemKind::Conflict,
            "В проекте нет разобранных записей: импортируйте запись и дождитесь конца импорта.",
        ));
    }

    let (store, session) = (store.clone(), session.clone());
    jobs.spawn(JobKind::Verify, move |ctx| async move {
        let work = tokio::task::spawn_blocking(move || -> Result<String, Problem> {
            let sources = store.list();
            let current = current_signature(&session, &store).ok_or_else(Session::no_project)?;
            let cancelled = || ctx.is_cancelled();
            let mut run = execute_run(
                &interpretation,
                Some(rev),
                &sources,
                &corpus,
                current.settings_digest,
                &cancelled,
                &mut |done, total| {
                    ctx.progress(ProgressStage::Verifying, done, total, ProgressUnit::Streams)
                },
            )?;

            ctx.progress(ProgressStage::Saving, 0, 0, ProgressUnit::Bytes);
            let mut guard = session.write();
            let project = guard.as_mut().ok_or_else(Session::no_project)?;
            run.id = project.next_run_id();
            let json = serde_json::to_string(&run).map_err(|_| blocking_failed())?;
            project.save_run(&run.id, &json).map_err(Problem::from)?;
            Ok(run.id)
        });
        let id = work.await.map_err(|_| blocking_failed())??;
        Ok(serde_json::json!({ "runId": id }))
    })
}
