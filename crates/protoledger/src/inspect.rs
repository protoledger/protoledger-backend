//! `protoledger coverage`, `compare`, `graph` — взгляд на записи через готовое описание, без проекта:
//! что в сообщениях описано, чем отличаются два набора записей, как устроен обмен.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Args;
use pl_app::SourceData;
use pl_interp::Interpretation;
use pl_reassembly::Policy;

use crate::apply::policy;
use crate::common::{Exit, fail, read_text};

/// Общее для трёх команд: описание и политики сборки потоков.
#[derive(Args)]
pub struct Common {
    /// Файл интерпретации (YAML, protoledger/interpretation@1)
    #[arg(long)]
    pub interpretation: PathBuf,
    /// Политика перекрытий: first, last или flag
    #[arg(long, default_value = "first")]
    pub overlap: String,
    /// Политика контрольных сумм: ignore, warn или drop
    #[arg(long, default_value = "warn")]
    pub checksum: String,
    /// Куда записать результат; без значения — в стандартный вывод
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Args)]
pub struct CoverageArgs {
    #[command(flatten)]
    pub common: Common,
    /// Записи PCAP/PCAPNG; можно указать несколько раз
    #[arg(long = "input", required = true)]
    pub inputs: Vec<PathBuf>,
}

#[derive(Args)]
pub struct CompareArgs {
    #[command(flatten)]
    pub common: Common,
    /// Записи первого набора; можно указать несколько раз
    #[arg(long = "a", required = true)]
    pub first: Vec<PathBuf>,
    /// Записи второго набора; можно указать несколько раз
    #[arg(long = "b", required = true)]
    pub second: Vec<PathBuf>,
}

#[derive(Args)]
pub struct GraphArgs {
    #[command(flatten)]
    pub common: Common,
    /// Записи PCAP/PCAPNG; можно указать несколько раз
    #[arg(long = "input", required = true)]
    pub inputs: Vec<PathBuf>,
    /// Вывести только граф в формате Graphviz DOT
    #[arg(long)]
    pub dot: bool,
}

fn interpretation(common: &Common) -> Result<Interpretation, String> {
    let text = read_text(&common.interpretation)?;
    Interpretation::parse(&text).map_err(|e| format!("{}: {e}", common.interpretation.display()))
}

fn load(paths: &[PathBuf], policy: Policy, offset: usize) -> Result<Vec<Arc<SourceData>>, String> {
    let mut sources = Vec::new();
    for (n, path) in paths.iter().enumerate() {
        let bytes = pl_app::read_capture_file(path).map_err(|p| fail(path, &p))?;
        let name = path
            .file_name()
            .map_or_else(|| "запись".to_owned(), |f| f.to_string_lossy().into_owned());
        let id = format!("imp-{:04}", offset + n + 1);
        let data = pl_app::analyze_with(bytes, name, id, policy, &|| false, &mut |_, _, _, _| {})
            .map_err(|p| fail(path, &p))?;
        sources.push(Arc::new(data));
    }
    Ok(sources)
}

fn write(out: Option<&Path>, text: &str) -> Result<(), String> {
    match out {
        Some(path) => std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display())),
        None => {
            print!("{text}");
            Ok(())
        }
    }
}

fn json<T: serde::Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string_pretty(value)
        .map(|s| s + "\n")
        .map_err(|e| e.to_string())
}

fn problem(p: pl_core::Problem) -> String {
    p.detail.unwrap_or_else(|| p.title.to_owned())
}

pub fn coverage(args: CoverageArgs) -> Result<Exit, String> {
    let it = interpretation(&args.common)?;
    let policy = policy(&args.common.overlap, &args.common.checksum)?;
    let sources = load(&args.inputs, policy, 0)?;
    let map = pl_app::coverage(&sources, &it, &|| false).map_err(problem)?;
    eprintln!(
        "Сообщений: {}, описано байтов: {} из {} ({} %); неизвестных зон: {}, без описания: {}.",
        map.messages,
        map.bytes.rule + map.bytes.hypothesis,
        map.bytes.total,
        map.described_permille / 10,
        map.bytes.unknown,
        map.bytes.none
    );
    write(args.common.out.as_deref(), &json(&map)?)?;
    Ok(Exit::Ok)
}

pub fn compare(args: CompareArgs) -> Result<Exit, String> {
    let it = interpretation(&args.common)?;
    let policy = policy(&args.common.overlap, &args.common.checksum)?;
    let first = load(&args.first, policy, 0)?;
    let second = load(&args.second, policy, first.len())?;
    let diff = pl_app::compare(&first, &second, &it, &|| false).map_err(problem)?;
    for line in &diff.summary {
        eprintln!("{line}");
    }
    // Код 1 — отличия есть: удобно в сценариях «до и после обновления».
    let differs = !diff.fields.is_empty()
        || diff
            .types
            .iter()
            .any(|t| t.change != pl_app::TypeChange::Same);
    write(args.common.out.as_deref(), &json(&diff)?)?;
    Ok(if differs { Exit::Differences } else { Exit::Ok })
}

pub fn graph(args: GraphArgs) -> Result<Exit, String> {
    let it = interpretation(&args.common)?;
    let policy = policy(&args.common.overlap, &args.common.checksum)?;
    let sources = load(&args.inputs, policy, 0)?;
    let graph = pl_app::exchange_graph(&sources, &it, &|| false).map_err(problem)?;
    eprintln!(
        "Соединений: {}, сообщений: {}, типов: {}; запросов без ответа: {}, сообщений без запроса: {}.",
        graph.connections,
        graph.messages,
        graph.nodes.len(),
        graph.unanswered,
        graph.unsolicited
    );
    let text = if args.dot {
        graph.dot.clone()
    } else {
        json(&graph)?
    };
    write(args.common.out.as_deref(), &text)?;
    Ok(Exit::Ok)
}
