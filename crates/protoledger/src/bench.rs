//! `protoledger bench`: время этапов и пиковая память на записях каталога или файла.

use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::Args;
use pl_capture::{Limits, index};
use pl_interp::Interpretation;
use pl_reassembly::{Policy, reassemble};
use serde::Serialize;

use crate::common::{Exit, read_text};

#[derive(Args)]
pub struct BenchArgs {
    /// Записи PCAP/PCAPNG или каталоги с ними (каталог — без вложенных)
    #[arg(required = true)]
    pub paths: Vec<PathBuf>,
    /// Описание протокола: тогда замеряется и применение к потокам
    #[arg(long)]
    pub interpretation: Option<PathBuf>,
    /// Сколько раз повторить; в результат идёт лучшее время каждого этапа
    #[arg(long, default_value_t = 1)]
    pub repeat: u32,
    /// Вывести JSON вместо таблицы
    #[arg(long)]
    pub json: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Timings {
    read_ms: f64,
    index_ms: f64,
    reassemble_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    apply_ms: Option<f64>,
    total_ms: f64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FileResult {
    name: String,
    size_bytes: u64,
    frames: u64,
    tcp_segments: u64,
    connections: u64,
    stream_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    messages: Option<u64>,
    timings: Timings,
    /// Скорость полного разбора (чтение, индекс, сборка), МиБ/с.
    mib_per_second: f64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Report {
    engine_version: &'static str,
    cpus: usize,
    repeat: u32,
    files: Vec<FileResult>,
    /// Пик resident-памяти процесса (VmHWM из /proc/self/status); на системах без /proc — `null`.
    peak_memory_bytes: Option<u64>,
}

fn ms(d: std::time::Duration) -> f64 {
    (d.as_secs_f64() * 10_000.0).round() / 10.0
}

fn peak_memory() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    kib.checked_mul(1024)
}

fn collect(paths: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    for p in paths {
        let meta = std::fs::metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
        if meta.is_dir() {
            let mut found: Vec<PathBuf> = std::fs::read_dir(p)
                .map_err(|e| format!("{}: {e}", p.display()))?
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|f| {
                    f.is_file()
                        && f.extension()
                            .and_then(|e| e.to_str())
                            .is_some_and(|e| matches!(e, "pcap" | "pcapng"))
                })
                .collect();
            found.sort();
            out.extend(found);
        } else {
            out.push(p.clone());
        }
    }
    if out.is_empty() {
        return Err("Записей .pcap и .pcapng не найдено.".to_owned());
    }
    Ok(out)
}

fn measure(path: &Path, it: Option<&Interpretation>, repeat: u32) -> Result<FileResult, String> {
    let name = path
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let fail = |e: String| format!("{}: {e}", path.display());
    let mut best: Option<Timings> = None;
    let mut counts = (0u64, 0u64, 0u64, 0u64, None::<u64>, 0u64);
    for _ in 0..repeat.max(1) {
        let started = Instant::now();
        let file = std::fs::read(path).map_err(|e| fail(e.to_string()))?;
        let read = started.elapsed();

        let t = Instant::now();
        let idx = index(&file, Limits::default(), &|| false, &mut |_| {})
            .map_err(|e| fail(e.to_string()))?;
        let index_time = t.elapsed();

        let t = Instant::now();
        let connections = reassemble(&idx, &file, Policy::default(), &|| false)
            .map_err(|e| fail(e.to_string()))?;
        let reassemble_time = t.elapsed();

        let mut messages = None;
        let mut apply_time = None;
        if let Some(it) = it {
            let t = Instant::now();
            let mut n = 0u64;
            for c in &connections {
                for (i, stream) in c.streams.iter().enumerate() {
                    let input = pl_app::stream_input(&file, c, stream, i);
                    let result =
                        pl_interp::apply(it, &input, &|| false).map_err(|e| fail(e.to_string()))?;
                    n += result.messages.len() as u64;
                }
            }
            messages = Some(n);
            apply_time = Some(t.elapsed());
        }
        let total = started.elapsed();
        counts = (
            file.len() as u64,
            idx.frames.len() as u64,
            idx.segments.len() as u64,
            connections.len() as u64,
            messages,
            connections
                .iter()
                .flat_map(|c| c.streams.iter())
                .map(|s| s.length)
                .sum(),
        );
        let now = Timings {
            read_ms: ms(read),
            index_ms: ms(index_time),
            reassemble_ms: ms(reassemble_time),
            apply_ms: apply_time.map(ms),
            total_ms: ms(total),
        };
        best = Some(match best {
            None => now,
            Some(b) => Timings {
                read_ms: b.read_ms.min(now.read_ms),
                index_ms: b.index_ms.min(now.index_ms),
                reassemble_ms: b.reassemble_ms.min(now.reassemble_ms),
                apply_ms: match (b.apply_ms, now.apply_ms) {
                    (Some(a), Some(c)) => Some(a.min(c)),
                    (a, c) => a.or(c),
                },
                total_ms: b.total_ms.min(now.total_ms),
            },
        });
    }
    let timings = best.ok_or_else(|| fail("нет результата".to_owned()))?;
    let parse_ms = timings.read_ms + timings.index_ms + timings.reassemble_ms;
    let mib = counts.0 as f64 / f64::from(1 << 20);
    Ok(FileResult {
        name,
        size_bytes: counts.0,
        frames: counts.1,
        tcp_segments: counts.2,
        connections: counts.3,
        stream_bytes: counts.5,
        messages: counts.4,
        mib_per_second: if parse_ms > 0.0 {
            (mib / (parse_ms / 1000.0) * 10.0).round() / 10.0
        } else {
            0.0
        },
        timings,
    })
}

pub fn run(args: BenchArgs) -> Result<Exit, String> {
    let interpretation = match &args.interpretation {
        Some(path) => Some(
            Interpretation::parse(&read_text(path)?)
                .map_err(|e| format!("{}: {e}", path.display()))?,
        ),
        None => None,
    };
    let files = collect(&args.paths)?;
    let results = files
        .iter()
        .map(|f| measure(f, interpretation.as_ref(), args.repeat))
        .collect::<Result<Vec<_>, _>>()?;
    let report = Report {
        engine_version: env!("CARGO_PKG_VERSION"),
        cpus: std::thread::available_parallelism().map_or(1, usize::from),
        repeat: args.repeat.max(1),
        files: results,
        peak_memory_bytes: peak_memory(),
    };
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "{:<28} {:>10} {:>9} {:>6} {:>9} {:>9} {:>9} {:>9}",
            "запись", "МиБ", "кадров", "соед.", "чтение", "индекс", "сборка", "всего"
        );
        for f in &report.files {
            println!(
                "{:<28} {:>10.1} {:>9} {:>6} {:>7.0}мс {:>7.0}мс {:>7.0}мс {:>7.0}мс  ({} МиБ/с)",
                f.name,
                f.size_bytes as f64 / f64::from(1 << 20),
                f.frames,
                f.connections,
                f.timings.read_ms,
                f.timings.index_ms,
                f.timings.reassemble_ms,
                f.timings.total_ms,
                f.mib_per_second
            );
            if let (Some(a), Some(m)) = (f.timings.apply_ms, f.messages) {
                println!("{:<28} применение описания: {a:.0} мс, сообщений {m}", "");
            }
        }
        match report.peak_memory_bytes {
            Some(b) => println!("Пик памяти: {:.0} МиБ", b as f64 / f64::from(1 << 20)),
            None => println!("Пик памяти: недоступен (нет /proc)"),
        }
    }
    Ok(Exit::Ok)
}
