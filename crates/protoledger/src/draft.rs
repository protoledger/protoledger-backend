//! `protoledger draft` — черновик описания протокола по записям, без проекта.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Args;
use pl_app::{ActionLogStore, DraftRequest, LoadedLog, MAX_REQUEST_STREAMS, SourceStore};

use crate::apply::{load_mapping, policy};
use crate::common::{Exit, fail};

#[derive(Args)]
pub struct DraftArgs {
    /// Записи PCAP/PCAPNG; можно указать несколько раз
    #[arg(long = "input", required = true)]
    pub inputs: Vec<PathBuf>,
    /// Журнал действий (CSV): по нему ищутся поля, равные параметрам действий
    #[arg(long)]
    pub action_log: Option<PathBuf>,
    /// Сопоставление колонок журнала (YAML или JSON)
    #[arg(long, requires = "action_log")]
    pub mapping: Option<PathBuf>,
    /// Политика перекрытий: first, last или flag
    #[arg(long, default_value = "first")]
    pub overlap: String,
    /// Политика контрольных сумм: ignore, warn или drop
    #[arg(long, default_value = "warn")]
    pub checksum: String,
    /// Куда записать описание; без значения — в стандартный вывод
    #[arg(long)]
    pub out: Option<PathBuf>,
}

pub fn run(args: DraftArgs) -> Result<Exit, String> {
    let policy = policy(&args.overlap, &args.checksum)?;
    let store = SourceStore::default();
    let mut streams: Vec<String> = Vec::new();
    let mut skipped = 0usize;
    for (n, path) in args.inputs.iter().enumerate() {
        let bytes = pl_app::read_capture_file(path).map_err(|p| fail(path, &p))?;
        let name = path
            .file_name()
            .map_or_else(|| "запись".to_owned(), |f| f.to_string_lossy().into_owned());
        let id = format!("imp-{:04}", n + 1);
        let data = pl_app::analyze_with(bytes, name, id, policy, &|| false, &mut |_, _, _, _| {})
            .map_err(|p| fail(path, &p))?;
        for connection in &data.connections {
            let id = connection.id(&data.sha256);
            for suffix in ["ab", "ba"] {
                if streams.len() < MAX_REQUEST_STREAMS {
                    streams.push(format!("{id}:{suffix}"));
                } else {
                    skipped += 1;
                }
            }
        }
        store.insert(data);
    }
    if streams.is_empty() {
        return Err("в записях нет ни одного TCP-соединения с данными".to_owned());
    }

    let mut logs = Vec::new();
    if let Some(log_path) = &args.action_log {
        let mapping_path = args
            .mapping
            .as_ref()
            .ok_or("--action-log требует --mapping")?;
        let mapping = load_mapping(mapping_path)?;
        let bytes = std::fs::read(log_path).map_err(|e| format!("{}: {e}", log_path.display()))?;
        let parsed = pl_actions::parse(&bytes, &mapping)
            .map_err(|e| format!("{}: {e}", log_path.display()))?;
        logs.push(Arc::new(LoadedLog {
            record: pl_project::ActionLogRecord {
                id: "log-0001".to_owned(),
                sha256: String::new(),
                name: log_path
                    .file_name()
                    .map_or_else(String::new, |f| f.to_string_lossy().into_owned()),
                mapping,
                rows: parsed.actions.len() as u64,
            },
            actions: parsed.actions,
            errors: parsed.errors,
            skipped: parsed.skipped,
        }));
    }

    let draft = pl_app::draft_interpretation(
        &store,
        &ActionLogStore::from_logs(logs),
        &DraftRequest {
            streams,
            log_id: None,
        },
        &|| false,
    )
    .map_err(|p| p.detail.unwrap_or_else(|| p.title.to_owned()))?;

    // Описание — в файл или стандартный вывод; ход сборки — в stderr, чтобы вывод оставался описанием.
    for step in &draft.steps {
        eprintln!("{}: {}", step.title, step.detail);
    }
    if skipped > 0 {
        eprintln!("В анализ вошли первые {MAX_REQUEST_STREAMS} потоков; не вошло: {skipped}.");
    }
    match &args.out {
        Some(path) => {
            std::fs::write(path, &draft.yaml).map_err(|e| format!("{}: {e}", path.display()))?
        }
        None => print!("{}", draft.yaml),
    }
    Ok(Exit::Ok)
}
