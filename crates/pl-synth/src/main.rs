use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use pl_synth::{Format, SCENARIOS, Scenario};

#[derive(Parser)]
#[command(
    name = "pl-synth",
    about = "Генератор синтетических записей трафика с дефектами захвата"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Список сценариев
    List,
    /// Запись контрольного профиля для замеров (по умолчанию: 1000 соединений, 250 тыс. кадров, файл около 100 МиБ)
    Profile {
        /// Файл результата
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long, default_value_t = 1000)]
        connections: usize,
        #[arg(long, default_value_t = 250_000)]
        frames: usize,
        /// Размер файла, МиБ
        #[arg(long, default_value_t = 100)]
        mib: usize,
        #[arg(long, value_enum, default_value_t = Format::Pcapng)]
        format: Format,
    },
    /// Записать сценарии в каталог: <имя>.<формат> и <имя>.expected.json
    Generate {
        /// Каталог для файлов
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long, value_enum, default_value_t = Format::Pcapng)]
        format: Format,
        /// Сценарии; по умолчанию все
        scenarios: Vec<String>,
    },
}

fn main() -> ExitCode {
    match Cli::parse().cmd {
        Cmd::List => {
            for s in SCENARIOS {
                println!("{:<18} {}", s.name, s.description);
            }
            ExitCode::SUCCESS
        }
        Cmd::Profile {
            out,
            seed,
            connections,
            frames,
            mib,
            format,
        } => {
            let capture = pl_synth::profile(connections, frames, mib << 20, seed);
            match std::fs::write(&out, capture.encode(format)) {
                Ok(()) => {
                    println!(
                        "{}: {} кадров, {} соединений",
                        out.display(),
                        capture.frames.len(),
                        connections
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("ошибка: {}: {e}", out.display());
                    ExitCode::from(2)
                }
            }
        }
        Cmd::Generate {
            out,
            seed,
            format,
            scenarios,
        } => match run(&out, seed, format, &scenarios) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("ошибка: {e}");
                ExitCode::from(2)
            }
        },
    }
}

fn run(out: &PathBuf, seed: u64, format: Format, names: &[String]) -> Result<(), String> {
    let selected: Vec<&Scenario> = if names.is_empty() {
        SCENARIOS.iter().collect()
    } else {
        names
            .iter()
            .map(|n| pl_synth::find(n).ok_or_else(|| format!("нет сценария «{n}», см. list")))
            .collect::<Result<_, _>>()?
    };
    std::fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    for sc in selected {
        let g = pl_synth::generate(sc, seed);
        let capture = out.join(format!("{}.{}", sc.name, format.extension()));
        let expected = out.join(format!("{}.expected.json", sc.name));
        let json = serde_json::to_string_pretty(&g.expected).map_err(|e| e.to_string())? + "\n";
        std::fs::write(&capture, g.capture.encode(format))
            .map_err(|e| format!("{}: {e}", capture.display()))?;
        std::fs::write(&expected, json).map_err(|e| format!("{}: {e}", expected.display()))?;
        println!(
            "{}: {} кадров, {} соединений",
            capture.display(),
            g.expected.frames,
            g.expected.connections.len()
        );
    }
    Ok(())
}
