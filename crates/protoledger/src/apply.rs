//! `protoledger apply`: интерпретация + записи → JSON с результатом и диагностикой, без проекта.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Args;
use pl_app::{LoadedLog, SourceData};
use pl_interp::{Category, Interpretation, MessageResult, Value};
use pl_reassembly::{ChecksumPolicy, OverlapPolicy, Policy};
use serde::Serialize;

use crate::common::{Exit, fail, read_text};

#[derive(Args)]
pub struct ApplyArgs {
    /// Файл интерпретации (YAML, protoledger/interpretation@1)
    #[arg(long)]
    pub interpretation: PathBuf,
    /// Записи PCAP/PCAPNG; можно указать несколько раз
    #[arg(long = "input", required = true)]
    pub inputs: Vec<PathBuf>,
    /// Журнал действий (CSV); нужен для тестов гипотез из интерпретации
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
    /// Куда записать результат; без значения — в стандартный вывод
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Код возврата 1, если есть сообщения не в категории matched
    #[arg(long)]
    pub strict: bool,
}

pub fn policy(overlap: &str, checksum: &str) -> Result<Policy, String> {
    Ok(Policy {
        overlap: match overlap {
            "first" => OverlapPolicy::First,
            "last" => OverlapPolicy::Last,
            "flag" => OverlapPolicy::Flag,
            other => return Err(format!("--overlap: first, last или flag, а не «{other}»")),
        },
        checksum: match checksum {
            "ignore" => ChecksumPolicy::Ignore,
            "warn" => ChecksumPolicy::Warn,
            "drop" => ChecksumPolicy::Drop,
            other => return Err(format!("--checksum: ignore, warn или drop, а не «{other}»")),
        },
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FieldView {
    name: String,
    at: u64,
    len: u64,
    status: pl_interp::schema::Status,
    hypothesis: Option<String>,
    state: pl_interp::FieldState,
    value_type: Option<&'static str>,
    value: Option<serde_json::Value>,
    /// Длинное значение (байты, строка) в результате усечено; длина поля — в `len`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    value_truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ViolationView {
    kind: pl_interp::ViolationKind,
    id: String,
    detail: String,
    status: pl_interp::schema::Status,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MessageView {
    start: u64,
    end: u64,
    category: Category,
    message_id: Option<String>,
    unknown_bytes: u64,
    fields: Vec<FieldView>,
    violations: Vec<ViolationView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StreamView {
    id: String,
    out_of_scope: bool,
    counts: BTreeMap<Category, u64>,
    unknown_bytes: u64,
    messages: Vec<MessageView>,
}

#[derive(Serialize)]
struct DiagnosticView {
    code: &'static str,
    count: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InputView {
    name: String,
    sha256: String,
    format: &'static str,
    frames: u64,
    connections: u64,
    diagnostics: Vec<DiagnosticView>,
    streams: Vec<StreamView>,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct SummaryView {
    inputs: u64,
    streams: u64,
    out_of_scope_streams: u64,
    messages: u64,
    unknown_bytes: u64,
    counts: BTreeMap<Category, u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HypothesisView {
    id: String,
    statement: String,
    test: String,
    #[serde(flatten)]
    evidence: pl_app::Evidence,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyView {
    overlap: &'static str,
    checksum: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Output {
    format: &'static str,
    engine_version: &'static str,
    interpretation_digest: String,
    policy: PolicyView,
    summary: SummaryView,
    inputs: Vec<InputView>,
    hypotheses: Vec<HypothesisView>,
}

/// Сколько байт длинного значения показываем в результате.
const SHOWN_BYTES: usize = 256;

fn value_json(v: &Value) -> (&'static str, serde_json::Value, bool) {
    const SAFE: i128 = 9_007_199_254_740_991;
    match v {
        Value::Int(i) if i.abs() <= SAFE => (
            "int",
            serde_json::Value::from(i64::try_from(*i).unwrap_or(0)),
            false,
        ),
        Value::Int(i) => ("int", serde_json::Value::String(i.to_string()), false),
        Value::Bool(b) => ("bool", serde_json::Value::Bool(*b), false),
        Value::Str(text) => {
            let shown: String = text.chars().take(SHOWN_BYTES).collect();
            (
                "string",
                serde_json::Value::String(shown),
                text.chars().count() > SHOWN_BYTES,
            )
        }
        Value::Bytes(bytes) => {
            let shown = Value::Bytes(bytes.iter().take(SHOWN_BYTES).copied().collect());
            (
                "bytes",
                serde_json::Value::String(shown.to_string()),
                bytes.len() > SHOWN_BYTES,
            )
        }
    }
}

fn message_view(m: &MessageResult) -> MessageView {
    MessageView {
        start: m.start,
        end: m.end,
        category: m.category,
        message_id: m.message_id.clone(),
        unknown_bytes: m.unknown_bytes,
        fields: m
            .fields
            .iter()
            .map(|f| {
                let (value_type, value, value_truncated) = match f.value.as_ref().map(value_json) {
                    Some((t, v, cut)) => (Some(t), Some(v), cut),
                    None => (None, None, false),
                };
                FieldView {
                    name: f.name.clone(),
                    at: f.at,
                    len: f.len,
                    status: f.status,
                    hypothesis: f.hypothesis.clone(),
                    state: f.state,
                    value_type,
                    value,
                    value_truncated,
                }
            })
            .collect(),
        violations: m
            .violations
            .iter()
            .map(|v| ViolationView {
                kind: v.kind,
                id: v.id.clone(),
                detail: v.detail.clone(),
                status: v.status,
            })
            .collect(),
    }
}

fn load_mapping(path: &Path) -> Result<pl_actions::Mapping, String> {
    let text = read_text(path)?;
    serde_saphyr::from_str(&text).map_err(|e| {
        format!(
            "{}: сопоставление колонок не разобрано: {e}",
            path.display()
        )
    })
}

pub fn run(args: ApplyArgs) -> Result<Exit, String> {
    let policy = policy(&args.overlap, &args.checksum)?;
    let text = read_text(&args.interpretation)?;
    let interpretation = Interpretation::parse(&text)
        .map_err(|e| format!("{}: {e}", args.interpretation.display()))?;

    let mut sources: Vec<Arc<SourceData>> = Vec::new();
    for path in &args.inputs {
        let bytes = pl_app::read_capture_file(path).map_err(|p| fail(path, &p))?;
        let name = path
            .file_name()
            .map_or_else(|| "запись".to_owned(), |n| n.to_string_lossy().into_owned());
        let id = format!("imp-{:04}", sources.len() + 1);
        let data = pl_app::analyze_with(bytes, name, id, policy, &|| false, &mut |_, _, _, _| {})
            .map_err(|p| fail(path, &p))?;
        sources.push(Arc::new(data));
    }

    let mut summary = SummaryView {
        inputs: sources.len() as u64,
        ..SummaryView::default()
    };
    let mut inputs = Vec::new();
    for data in &sources {
        let applied =
            pl_app::apply_to_source(&interpretation, data, &|| false).map_err(|e| e.to_string())?;
        let mut streams = Vec::new();
        for a in applied {
            let connection = data.connections.iter().find(|c| c.number == a.connection);
            let id = connection.map_or_else(String::new, |c| {
                format!(
                    "{}:{}",
                    c.id(&data.sha256),
                    if a.direction_index == 0 { "ab" } else { "ba" }
                )
            });
            summary.streams += 1;
            summary.out_of_scope_streams += u64::from(a.result.out_of_scope);
            summary.messages += a.result.messages.len() as u64;
            summary.unknown_bytes += a.result.unknown_bytes();
            for (category, n) in a.result.counts() {
                *summary.counts.entry(category).or_default() += n;
            }
            streams.push(StreamView {
                id,
                out_of_scope: a.result.out_of_scope,
                counts: a.result.counts(),
                unknown_bytes: a.result.unknown_bytes(),
                messages: a.result.messages.iter().map(message_view).collect(),
            });
        }
        inputs.push(InputView {
            name: data.name.clone(),
            sha256: data.sha256.clone(),
            format: data.format().name(),
            frames: data.index.frames.len() as u64,
            connections: data.connections.len() as u64,
            diagnostics: data
                .index
                .diagnostics
                .groups
                .iter()
                .map(|(code, g)| DiagnosticView {
                    code: code.code(),
                    count: g.count,
                })
                .collect(),
            streams,
        });
    }

    // Гипотезы из интерпретации с тестом проверяются на журнале действий, если он передан.
    let mut hypotheses = Vec::new();
    if let Some(log_path) = &args.action_log {
        let mapping_path = args
            .mapping
            .as_ref()
            .ok_or("--action-log требует --mapping")?;
        let mapping = load_mapping(mapping_path)?;
        let bytes = std::fs::read(log_path).map_err(|e| format!("{}: {e}", log_path.display()))?;
        let parsed = pl_actions::parse(&bytes, &mapping)
            .map_err(|e| format!("{}: {e}", log_path.display()))?;
        let record = pl_project::ActionLogRecord {
            id: "log-0001".to_owned(),
            sha256: String::new(),
            name: log_path
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
            mapping,
            rows: parsed.actions.len() as u64,
        };
        let log = Arc::new(LoadedLog {
            record,
            actions: parsed.actions,
            errors: parsed.errors,
            skipped: parsed.skipped,
        });
        for h in interpretation
            .hypotheses
            .iter()
            .filter(|h| h.test.is_some())
        {
            let test = h.test.clone().unwrap_or_default();
            let evidence = pl_app::test_hypothesis(
                &sources,
                &interpretation,
                &[Arc::clone(&log)],
                &test,
                &pl_app::TestOptions::default(),
            )
            .map_err(|p| format!("гипотеза {}: {}", h.id, p.detail.unwrap_or_default()))?;
            hypotheses.push(HypothesisView {
                id: h.id.clone(),
                statement: h.statement.clone(),
                test,
                evidence,
            });
        }
    }

    let output = Output {
        format: "protoledger/apply-result@1",
        engine_version: env!("CARGO_PKG_VERSION"),
        interpretation_digest: interpretation.digest(),
        policy: PolicyView {
            overlap: match policy.overlap {
                OverlapPolicy::First => "first",
                OverlapPolicy::Last => "last",
                OverlapPolicy::Flag => "flag",
            },
            checksum: match policy.checksum {
                ChecksumPolicy::Ignore => "ignore",
                ChecksumPolicy::Warn => "warn",
                ChecksumPolicy::Drop => "drop",
            },
        },
        summary,
        inputs,
        hypotheses,
    };
    let json = serde_json::to_string_pretty(&output).map_err(|e| e.to_string())? + "\n";
    match &args.out {
        Some(path) => {
            std::fs::write(path, &json).map_err(|e| format!("{}: {e}", path.display()))?
        }
        None => print!("{json}"),
    }
    let not_matched: u64 = output
        .summary
        .counts
        .iter()
        .filter(|(c, _)| **c != Category::Matched)
        .map(|(_, n)| *n)
        .sum();
    eprintln!(
        "Применено: потоков {}, сообщений {} (совпало {}, не совпало {}), неописанных байт {}.",
        output.summary.streams,
        output.summary.messages,
        output
            .summary
            .counts
            .get(&Category::Matched)
            .copied()
            .unwrap_or(0),
        not_matched,
        output.summary.unknown_bytes,
    );
    Ok(if args.strict && not_matched > 0 {
        Exit::Differences
    } else {
        Exit::Ok
    })
}
