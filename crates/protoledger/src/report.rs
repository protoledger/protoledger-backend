//! `protoledger report`: отчёт по проекту в Markdown или HTML.

use std::path::PathBuf;

use clap::{Args, ValueEnum};
use pl_app::{ActionLogStore, Session, SourceStore};
use pl_project::Project;

use crate::common::{Exit, fail};

#[derive(Clone, Copy, ValueEnum)]
pub enum Format {
    Md,
    Html,
}

#[derive(Args)]
pub struct ReportArgs {
    /// Папка проекта (.protoledger)
    pub project: PathBuf,
    /// Прогон для отчёта (run-0001); без значения — последний
    #[arg(long)]
    pub run: Option<String>,
    #[arg(long, value_enum, default_value = "md")]
    pub format: Format,
    /// Файл результата; без значения — в stdout
    #[arg(long)]
    pub out: Option<PathBuf>,
}

pub fn run(args: ReportArgs) -> Result<Exit, String> {
    let project =
        Project::open(&args.project).map_err(|e| format!("{}: {e}", args.project.display()))?;
    let session = Session::new(args.project.parent().map(PathBuf::from).unwrap_or_default());
    session.attach(project);
    let store = SourceStore::default();
    let logs = ActionLogStore::default();

    let problems = pl_app::load_project_sources(&session, &store, &|| false)
        .map_err(|p| fail(&args.project, &p))?;
    for p in &problems {
        eprintln!("{p}");
    }
    pl_app::reload_action_logs(&session, &logs);
    let data = pl_app::collect_report(&session, &store, &logs, args.run.as_deref())
        .map_err(|p| fail(&args.project, &p))?;
    let text = match args.format {
        Format::Md => pl_report::markdown(&data),
        Format::Html => pl_report::html(&data),
    };
    match &args.out {
        Some(path) => std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))?,
        None => print!("{text}"),
    }
    Ok(Exit::Ok)
}
