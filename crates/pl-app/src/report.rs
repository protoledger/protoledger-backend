//! Данные отчёта по проекту: собираются из проекта, загруженных записей и журналов.

use pl_core::{Problem, ProblemKind};
use pl_interp::schema::{Direction, FramingKind};
use pl_report::{
    ActionLogInfo, CounterexampleInfo, HypothesisInfo, HypothesisTestInfo, InterpretationInfo,
    ObservationInfo, QuestionInfo, ReportData, RunInfo, SourceInfo,
};
use pl_verify::{Run, StaleReason};

use crate::research::{AnchorState, Hypothesis, Observation, Question, QuestionStatus};
use crate::{
    ActionLogStore, Session, SourceStore, TestOptions, Verdict, anchor_state, current_signature,
    research_load, test_hypothesis,
};

fn direction_title(d: Direction) -> &'static str {
    match d {
        Direction::Any => "любое",
        Direction::AToB => "a → b",
        Direction::BToA => "b → a",
    }
}

fn framing_title(kind: FramingKind) -> &'static str {
    match kind {
        FramingKind::LengthPrefixed => "длина в заголовке",
        FramingKind::Delimiter => "разделитель",
        FramingKind::Fixed => "фиксированный размер",
        FramingKind::Magic => "маркер начала",
    }
}

fn counterexample(c: &pl_verify::Counterexample) -> CounterexampleInfo {
    CounterexampleInfo {
        stream: c.anchor.stream.clone(),
        start: c.anchor.start,
        end: c.anchor.end,
        sha256: c.anchor.sha256.clone(),
        category: c.category.code().to_owned(),
        message_id: c.message_id.clone(),
        details: c
            .violations
            .iter()
            .map(|v| format!("{}: {}", v.id, v.detail))
            .collect(),
    }
}

fn run_info(run: &Run, stale: Vec<StaleReason>) -> RunInfo {
    let corpus = &run.inputs.corpus;
    let mut filters = Vec::new();
    if let Some(s) = &corpus.sources {
        filters.push(format!("записей: {}", s.len()));
    }
    if let Some(d) = corpus.direction {
        filters.push(
            match d {
                pl_verify::DirectionFilter::AToB => "направление a → b",
                pl_verify::DirectionFilter::BToA => "направление b → a",
            }
            .to_owned(),
        );
    }
    if let Some(p) = corpus.port {
        filters.push(format!("порт {p}"));
    }
    RunInfo {
        id: run.id.clone(),
        revision: run.inputs.revision,
        interpretation_digest: run.inputs.interpretation_digest.clone(),
        settings: run.inputs.settings_digest.clone(),
        corpus: if filters.is_empty() {
            "все записи".to_owned()
        } else {
            filters.join(", ")
        },
        engine_version: run.inputs.engine_version.clone(),
        stale_reasons: stale
            .into_iter()
            .map(|r| {
                match r {
                    StaleReason::Interpretation => "interpretation",
                    StaleReason::Settings => "settings",
                    StaleReason::Sources => "sources",
                }
                .to_owned()
            })
            .collect(),
        streams: run.summary.streams,
        out_of_scope_streams: run.summary.out_of_scope_streams,
        messages: run.summary.messages,
        unknown_bytes: run.summary.unknown_bytes,
        counts: run
            .summary
            .counts
            .iter()
            .map(|(c, n)| (c.code().to_owned(), *n))
            .collect(),
        by_message: run
            .summary
            .by_message
            .iter()
            .map(|(m, counts)| {
                (
                    m.clone(),
                    counts
                        .iter()
                        .map(|(c, n)| (c.code().to_owned(), *n))
                        .collect(),
                )
            })
            .collect(),
        counterexamples_total: run.summary.counterexamples,
        counterexamples: run.counterexamples.iter().map(counterexample).collect(),
    }
}

/// Собирает данные отчёта. `run_id` — прогон; без него берётся последний из сохранённых.
pub fn collect(
    session: &Session,
    store: &SourceStore,
    logs: &ActionLogStore,
    run_id: Option<&str>,
) -> Result<ReportData, Problem> {
    let (project_name, settings, source_list, run_text, interpretation_yaml, revision, log_records) = {
        let guard = session.read();
        let project = guard.as_ref().ok_or_else(Session::no_project)?;
        let run_text = match run_id {
            Some(id) => Some(project.read_run(id).map_err(|_| {
                Problem::new(
                    ProblemKind::NotFound,
                    format!("Прогона {id} в проекте нет."),
                )
            })?),
            None => match project.run_ids().last() {
                Some(id) => project.read_run(id).ok(),
                None => None,
            },
        };
        let current = project.current_interpretation().ok().flatten();
        let settings = project.manifest().settings;
        (
            project.name().to_owned(),
            format!(
                "перекрытия — {}, контрольные суммы — {}",
                match settings.overlap_policy {
                    pl_project::OverlapPolicy::First => "брать первое",
                    pl_project::OverlapPolicy::Last => "брать последнее",
                    pl_project::OverlapPolicy::Flag => "помечать расхождение",
                },
                match settings.checksum_policy {
                    pl_project::ChecksumPolicy::Ignore => "не проверять",
                    pl_project::ChecksumPolicy::Warn => "предупреждать",
                    pl_project::ChecksumPolicy::Drop => "отбрасывать неверные",
                }
            ),
            project.sources(),
            run_text,
            current.as_ref().map(|(_, y)| y.clone()),
            current.map(|(r, _)| r),
            project.action_logs().to_vec(),
        )
    };

    let run = match run_text {
        Some(text) => Some(
            serde_json::from_str::<Run>(&text)
                .map_err(|_| Problem::new(ProblemKind::Conflict, "Файл прогона повреждён."))?,
        ),
        None => None,
    };
    let stale = match (&run, current_signature(session, store)) {
        (Some(run), Some(current)) => pl_verify::stale_reasons(run, &current),
        _ => Vec::new(),
    };

    let loaded = store.list();
    let interpretation = interpretation_yaml
        .as_deref()
        .and_then(|y| pl_interp::Interpretation::parse(y).ok());

    let sources = source_list
        .iter()
        .map(|s| {
            let data = loaded.iter().find(|d| d.sha256 == s.sha256);
            SourceInfo {
                name: s.name.clone(),
                sha256: s.sha256.clone(),
                size_bytes: s.size_bytes,
                format: s.format.extension().to_owned(),
                frames: data.map_or(0, |d| d.index.frames.len() as u64),
                connections: data.map_or(0, |d| d.connections.len() as u64),
                diagnostics: data.map_or_else(Vec::new, |d| {
                    d.index
                        .diagnostics
                        .groups
                        .iter()
                        .map(|(c, g)| (c.code().to_owned(), g.count))
                        .collect()
                }),
            }
        })
        .collect();

    let action_logs = log_records
        .iter()
        .map(|r| ActionLogInfo {
            id: r.id.clone(),
            name: r.name.clone(),
            rows: r.rows,
            skipped: logs.get(&r.id).map_or(0, |l| l.skipped),
        })
        .collect();

    let observations_raw: Vec<Observation> = research_load(session)?;
    let observations: Vec<ObservationInfo> = observations_raw
        .iter()
        .map(|o| ObservationInfo {
            id: o.id.clone(),
            comment: o.comment.clone(),
            stream: o.anchor.stream.clone(),
            start: o.anchor.start,
            end: o.anchor.end,
            sha256: o.anchor.sha256.clone(),
            anchor_state: match anchor_state(store, &o.anchor) {
                AnchorState::Ok => "ok",
                AnchorState::Broken => "broken",
                AnchorState::Unavailable => "unavailable",
            }
            .to_owned(),
        })
        .collect();

    let hypotheses_raw: Vec<Hypothesis> = research_load(session)?;
    let all_logs = logs.list();
    let hypotheses = hypotheses_raw
        .iter()
        .map(|h| {
            let result = match (&h.test, &interpretation) {
                (Some(expr), Some(it)) => {
                    test_hypothesis(&loaded, it, &all_logs, expr, &TestOptions::default())
                        .ok()
                        .map(|e| HypothesisTestInfo {
                            verdict: match e.verdict {
                                Verdict::Untested => "untested",
                                Verdict::NoCounterexample => "no_counterexample",
                                Verdict::Refuted => "refuted",
                            }
                            .to_owned(),
                            applicable: e.applicable,
                            held: e.held,
                            counterexamples_total: e.counterexamples_total,
                            counterexamples: e
                                .counterexamples
                                .iter()
                                .map(|c| {
                                    format!(
                                        "{} [{}, {}): {}",
                                        c.anchor.stream,
                                        c.anchor.start,
                                        c.anchor.end,
                                        c.values
                                            .iter()
                                            .map(|(k, v)| format!("{k} = {v}"))
                                            .collect::<Vec<_>>()
                                            .join(", ")
                                    )
                                })
                                .collect(),
                        })
                }
                _ => None,
            };
            HypothesisInfo {
                id: h.id.clone(),
                statement: h.statement.clone(),
                status: serde_json::to_value(h.status)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default(),
                basis: h.basis.clone(),
                test: h.test.clone(),
                superseded_by: h.superseded_by.clone(),
                note: h.note.clone(),
                result,
            }
        })
        .collect();

    let questions_raw: Vec<Question> = research_load(session)?;
    let questions = questions_raw
        .iter()
        .map(|q| QuestionInfo {
            id: q.id.clone(),
            text: q.text.clone(),
            open: q.status == QuestionStatus::Open,
            answer: q.answer.clone(),
        })
        .collect();

    Ok(ReportData {
        project: project_name,
        engine_version: env!("CARGO_PKG_VERSION").to_owned(),
        settings,
        sources,
        action_logs,
        interpretation: interpretation.map(|it| InterpretationInfo {
            rev: revision.as_ref().map_or(0, |r| r.rev),
            digest: revision.map(|r| r.digest).unwrap_or_default(),
            direction: direction_title(it.scope.direction).to_owned(),
            filter: it.scope.filter.clone(),
            framing: framing_title(it.framing.kind).to_owned(),
            messages: it.messages.iter().map(|m| m.id.clone()).collect(),
        }),
        run: run.map(|r| run_info(&r, stale)),
        observations,
        hypotheses,
        questions,
    })
}
