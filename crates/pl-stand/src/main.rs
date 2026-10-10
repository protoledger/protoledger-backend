use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use pl_stand::{client, device, log, record, scenario};
use pl_synth::capture::Format;

#[derive(Parser)]
#[command(name = "pl-stand", about = "Стенд-устройство для тестовых данных")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Список сценариев
    List,
    /// Записать сценарии без сети: pcapng + журнал действий
    Record {
        /// Каталог результата
        #[arg(long)]
        out: PathBuf,
        /// Формат записи
        #[arg(long, value_enum, default_value = "pcapng")]
        format: Format,
        /// Имена сценариев; без них — все
        names: Vec<String>,
    },
    /// Запустить устройство по TCP
    Device {
        #[arg(long, default_value = "127.0.0.1:4710")]
        listen: SocketAddr,
    },
    /// Выполнить сценарий клиентом по TCP и записать журнал действий
    Client {
        #[arg(long, default_value = "127.0.0.1:4710")]
        addr: SocketAddr,
        #[arg(long)]
        scenario: String,
        /// Файл журнала действий
        #[arg(long)]
        log: PathBuf,
        /// Не выдерживать паузы сценария
        #[arg(long)]
        fast: bool,
    },
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::List => {
            for s in scenario::all() {
                println!("{:<8} {}", s.name, s.description);
            }
            Ok(())
        }
        Command::Record { out, format, names } => {
            let selected: Vec<_> = if names.is_empty() {
                scenario::all()
            } else {
                names
                    .iter()
                    .map(|n| scenario::find(n).ok_or_else(|| format!("нет сценария «{n}»")))
                    .collect::<Result<_, _>>()?
            };
            std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
            for s in selected {
                let rec = record::record(&s);
                let pcap = out.join(format!("{}.{}", s.name, format.extension()));
                let csv = out.join(format!("{}.actions.csv", s.name));
                std::fs::write(&pcap, rec.capture.encode(format)).map_err(|e| e.to_string())?;
                std::fs::write(&csv, log::to_csv(&rec.log)).map_err(|e| e.to_string())?;
                println!(
                    "{}: {} кадров, {} действий",
                    s.name,
                    rec.capture.frames.len(),
                    rec.log.len()
                );
            }
            Ok(())
        }
        Command::Device { listen } => {
            let listener = TcpListener::bind(listen).map_err(|e| e.to_string())?;
            println!("устройство слушает {listen}");
            device::serve(listener);
            Ok(())
        }
        Command::Client {
            addr,
            scenario: name,
            log: path,
            fast,
        } => {
            let s = scenario::find(&name).ok_or_else(|| format!("нет сценария «{name}»"))?;
            let entries = client::run(addr, &s, fast).map_err(|e| e.to_string())?;
            std::fs::write(&path, log::to_csv(&entries)).map_err(|e| e.to_string())?;
            println!("{}: {} действий", s.name, entries.len());
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}
