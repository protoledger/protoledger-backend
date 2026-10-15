//! Прогон проверки как долгая задача: интерпретация применяется к потокам корпуса, результат
//! сохраняется в проект.

use std::sync::Arc;

use pl_core::{Problem, ProblemKind};
use pl_interp::Interpretation;
use pl_project::{ChecksumPolicy, OverlapPolicy};
use pl_verify::{
    Anchor, CorpusFilter, Current, HypothesisExample, HypothesisRun, HypothesisVerdict, RunInputs,
    StreamTarget,
};
use serde::Serialize;

use crate::{
    ActionLogStore, JobKind, JobRegistry, LoadedLog, ProgressStage, ProgressUnit, Session,
    SourceData, SourceStore, TestOptions, Verdict, stream_input, test_hypothesis,
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
        logs: log_digests(project.action_logs().iter().map(|l| l.sha256.clone())),
        log_mappings: crate::actions::mapping_overrides(project.action_logs()),
    })
}

fn log_digests(digests: impl Iterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = digests.collect();
    out.sort();
    out.dedup();
    out
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

/// Прогон без задачи: интерпретация применяется к потокам корпуса, тесты её гипотез — к записям
/// корпуса с журналами действий; результат не сохраняется.
#[allow(clippy::too_many_arguments)]
pub fn execute_run(
    interpretation: &Interpretation,
    revision: Option<u32>,
    sources: &[Arc<SourceData>],
    logs: &[Arc<LoadedLog>],
    corpus: &CorpusFilter,
    settings_digest: String,
    hypothesis_tests: bool,
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
        sources: used.clone(),
        corpus: corpus.clone(),
        engine_version: env!("CARGO_PKG_VERSION").to_owned(),
        logs: log_digests(logs.iter().map(|l| l.record.sha256.clone())),
        log_mappings: Default::default(),
    };
    let mut run = pl_verify::execute(interpretation, &targets, inputs, cancelled, progress)
        .map_err(verify_problem)?;

    if !hypothesis_tests {
        return Ok(run);
    }
    // ТЗ R4: тесты гипотез — часть прогона и считаются по тем же потокам, что и сводка:
    // условия фильтрации одни для всего результата.
    let options = TestOptions {
        corpus: Some(corpus.clone()),
        ..TestOptions::default()
    };
    let corpus_sources: Vec<Arc<SourceData>> = sources
        .iter()
        .filter(|s| used.binary_search(&s.sha256).is_ok())
        .cloned()
        .collect();
    for h in &interpretation.hypotheses {
        let Some(test) = &h.test else { continue };
        if cancelled() {
            return Err(verify_problem(pl_verify::VerifyError::Cancelled));
        }
        let evidence = test_hypothesis(&corpus_sources, interpretation, logs, test, &options)?;
        let outcome = HypothesisRun {
            id: h.id.clone(),
            test: test.clone(),
            verdict: match evidence.verdict {
                Verdict::Untested => HypothesisVerdict::Untested,
                Verdict::NoCounterexample => HypothesisVerdict::NoCounterexample,
                Verdict::Refuted => HypothesisVerdict::Refuted,
            },
            applicable: evidence.applicable,
            held: evidence.held,
            not_applicable: evidence.not_applicable,
            counterexamples: evidence.counterexamples_total,
            errors: evidence.errors_total,
        };
        let examples = evidence
            .counterexamples
            .into_iter()
            .map(|c| {
                let values = c
                    .values
                    .iter()
                    .map(|(k, v)| format!("{k} = {v}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let line = c
                    .action_line
                    .map(|l| format!(" (строка журнала {l})"))
                    .unwrap_or_default();
                HypothesisExample {
                    anchor: Anchor {
                        source: c.anchor.source,
                        stream: c.anchor.stream,
                        start: c.anchor.start,
                        end: c.anchor.end,
                        sha256: c.anchor.sha256,
                    },
                    message_id: c.message_id,
                    detail: format!("{}: тест «{test}» не выполнился: {values}{line}", h.id),
                }
            })
            .collect();
        run.add_hypothesis(outcome, examples);
    }
    Ok(run)
}

/// Запускает прогон; результат задачи — `{runId}`.
pub fn start_verify(
    jobs: &JobRegistry,
    store: &SourceStore,
    logs: &ActionLogStore,
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
                        "Описания протокола ещё нет: на экране «Протокол» нажмите «Составить описание».",
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

    let (store, session, logs) = (store.clone(), session.clone(), logs.clone());
    jobs.spawn(JobKind::Verify, move |ctx| async move {
        let work = tokio::task::spawn_blocking(move || -> Result<String, Problem> {
            let sources = store.list();
            let current = current_signature(&session, &store).ok_or_else(Session::no_project)?;
            let cancelled = || ctx.is_cancelled();
            let mut run = execute_run(
                &interpretation,
                Some(rev),
                &sources,
                &logs.list(),
                &corpus,
                current.settings_digest,
                true,
                &cancelled,
                &mut |done, total| {
                    ctx.progress(ProgressStage::Verifying, done, total, ProgressUnit::Streams)
                },
            )?;

            ctx.progress(ProgressStage::Saving, 0, 0, ProgressUnit::Bytes);
            // Сопоставления журналов — из той же подписи, с которой прогон потом сверяется.
            run.inputs.log_mappings = current.log_mappings;
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
