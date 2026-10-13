//! `protoledger verify`: перепроверка проекта — прогоны воспроизводятся, источники целы.

use std::path::PathBuf;

use clap::Args;
use pl_app::{Session, SourceStore};
use pl_interp::Interpretation;
use pl_project::{Project, SourceStatus};
use pl_verify::Run;

use crate::common::{Exit, fail};

#[derive(Args)]
pub struct VerifyArgs {
    /// Папка проекта (.protoledger)
    pub project: PathBuf,
    /// Проверить только этот прогон (run-0001); без значения — все
    #[arg(long)]
    pub run: Option<String>,
}

fn counts(run: &Run) -> String {
    run.summary
        .counts
        .iter()
        .map(|(c, n)| format!("{}: {n}", c.code()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Чем два результата отличаются (первые отличия).
fn differences(old: &Run, new: &Run) -> Vec<String> {
    let mut out = Vec::new();
    if old.summary != new.summary {
        out.push(format!(
            "сводка: было [{}], стало [{}]",
            counts(old),
            counts(new)
        ));
    }
    for (a, b) in old.streams.iter().zip(&new.streams) {
        if a != b {
            out.push(format!("поток {}: таблица сообщений изменилась", a.id));
        }
    }
    if old.streams.len() != new.streams.len() {
        out.push(format!(
            "число потоков: было {}, стало {}",
            old.streams.len(),
            new.streams.len()
        ));
    }
    if old.counterexamples != new.counterexamples && old.summary == new.summary {
        out.push("контрпримеры изменились".to_owned());
    }
    for (a, b) in old.hypotheses.iter().zip(&new.hypotheses) {
        if a != b {
            out.push(format!("гипотеза {}: итог теста изменился", a.id));
        }
    }
    if old.hypotheses.len() != new.hypotheses.len() {
        out.push(format!(
            "тестов гипотез: было {}, стало {}",
            old.hypotheses.len(),
            new.hypotheses.len()
        ));
    }
    out.truncate(10);
    out
}

pub fn run(args: VerifyArgs) -> Result<Exit, String> {
    let path = crate::common::project_path(&args.project);
    let project = Project::open(&path).map_err(|e| format!("{}: {}", args.project.display(), e))?;
    let workspace = path.parent().map(PathBuf::from).unwrap_or_default();
    let session = Session::new(workspace);
    let store = SourceStore::default();

    // Источники: копия должна совпадать с sha256.
    let mut differs = false;
    for source in project.sources() {
        match project
            .check_source(&source.sha256, &|| false)
            .map_err(|e| e.to_string())?
        {
            SourceStatus::Ready => {
                println!("запись {}: цела ({})", source.name, &source.sha256[..8])
            }
            SourceStatus::Missing => {
                println!("запись {}: КОПИИ НЕТ в проекте", source.name);
                differs = true;
            }
            SourceStatus::Damaged => {
                println!("запись {}: КОПИЯ ИЗМЕНЕНА (sha256 не совпал)", source.name);
                differs = true;
            }
        }
    }
    let ids: Vec<String> = match &args.run {
        Some(id) => vec![id.clone()],
        None => project.run_ids().into_iter().map(str::to_owned).collect(),
    };
    let stored: Vec<(String, Run)> = ids
        .iter()
        .map(|id| {
            let text = project.read_run(id).map_err(|e| e.to_string())?;
            let run: Run =
                serde_json::from_str(&text).map_err(|_| format!("прогон {id} повреждён"))?;
            Ok((id.clone(), run))
        })
        .collect::<Result<_, String>>()?;
    let revisions: Vec<(u32, String)> = stored
        .iter()
        .filter_map(|(_, r)| r.inputs.revision)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|rev| {
            project
                .read_interpretation(rev)
                .map(|(_, text)| (rev, text))
                .map_err(|e| e.to_string())
        })
        .collect::<Result<_, String>>()?;
    session.attach(project);

    let problems = pl_app::load_project_sources(&session, &store, &|| false)
        .map_err(|p| fail(&args.project, &p))?;
    for p in &problems {
        println!("{p}");
        differs = true;
    }
    if stored.is_empty() {
        println!("Сохранённых прогонов нет: проверять нечего.");
    }
    // Журналы действий проекта: по ним прогон выполняет тесты гипотез.
    let logs = pl_app::ActionLogStore::default();
    pl_app::reload_action_logs(&session, &logs);
    let logs = logs.list();
    let current = pl_app::current_signature(&session, &store);
    let sources = store.list();
    for (id, old) in &stored {
        let Some(rev) = old.inputs.revision else {
            println!("{id}: прогон без ревизии интерпретации, пропущен");
            continue;
        };
        let text = revisions
            .iter()
            .find(|(r, _)| *r == rev)
            .map(|(_, t)| t.as_str())
            .unwrap_or_default();
        let interpretation =
            Interpretation::parse(text).map_err(|e| format!("ревизия {rev}: {e}"))?;
        let settings_digest = current
            .as_ref()
            .map_or_else(String::new, |c| c.settings_digest.clone());
        // Прогон повторяется на своих записях: импортированные позже — повод для нового прогона,
        // а не отличие в старом.
        let run_sources: Vec<_> = sources
            .iter()
            .filter(|s| old.inputs.sources.contains(&s.sha256))
            .cloned()
            .collect();
        // Прогон сохранён до того, как тесты гипотез стали частью прогона: сравнивать их не с чем.
        let legacy =
            old.hypotheses.is_empty() && interpretation.hypotheses.iter().any(|h| h.test.is_some());
        let mut new = pl_app::execute_run(
            &interpretation,
            Some(rev),
            &run_sources,
            // Те же журналы, что у прогона: смена журналов — устаревание, а не невоспроизводимость.
            &logs
                .iter()
                .filter(|l| old.inputs.logs.contains(&l.record.sha256))
                .cloned()
                .collect::<Vec<_>>(),
            &old.inputs.corpus,
            settings_digest.clone(),
            !legacy,
            &|| false,
            &mut |_, _| {},
        )
        .map_err(|p| fail(&args.project, &p))?;
        new.id = id.clone();
        let diffs = differences(old, &new);
        let settings_changed = settings_digest != old.inputs.settings_digest;
        if diffs.is_empty() {
            let note = if settings_changed {
                " (настройки сборки изменены, результат тот же)"
            } else if legacy {
                " (сохранён без тестов гипотез: они не сравнивались)"
            } else {
                ""
            };
            println!(
                "{id}: результат воспроизводится — {} сообщений, {}{note}",
                old.summary.messages,
                counts(old)
            );
        } else {
            differs = true;
            let why = if settings_changed {
                " Настройки сборки потоков изменены после прогона."
            } else {
                ""
            };
            println!("{id}: РЕЗУЛЬТАТ ОТЛИЧАЕТСЯ.{why}");
            for d in diffs {
                println!("  - {d}");
            }
        }
    }
    Ok(if differs { Exit::Differences } else { Exit::Ok })
}
