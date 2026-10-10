mod apply;
mod bench;
mod common;
mod report;
mod verify;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use pl_server::ServerConfig;

#[derive(Parser)]
#[command(name = "protoledger", version, about = "Лаборатория протоколов")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Запустить локальный сервер с интерфейсом
    Serve {
        /// Адрес прослушивания
        #[arg(long, default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST))]
        host: IpAddr,
        #[arg(long, default_value_t = 8080)]
        port: u16,
        /// Каталог, где лежат проекты
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
        /// Режим разработки: токен из PROTOLEDGER_DEV_TOKEN, origin фронта http://localhost:3000
        #[cfg(feature = "dev-tools")]
        #[arg(long)]
        dev: bool,
    },
    /// Вывести контракт API (openapi.yaml)
    #[cfg(feature = "dev-tools")]
    Openapi,
    /// Применить интерпретацию к записям: результат JSON и диагностика, без проекта
    Apply(apply::ApplyArgs),
    /// Перепроверить проект: источники целы, прогоны воспроизводятся (0 — совпало, 1 — отличия, 2 — ошибка)
    Verify(verify::VerifyArgs),
    /// Сформировать отчёт
    Report(report::ReportArgs),
    /// Замерить время этапов и пиковую память на записях
    Bench(bench::BenchArgs),
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt().with_target(false).init();
    match Cli::parse().command {
        Command::Serve {
            host,
            port,
            workspace,
            #[cfg(feature = "dev-tools")]
            dev,
        } => {
            #[cfg(feature = "dev-tools")]
            let dev = if dev {
                let token = std::env::var("PROTOLEDGER_DEV_TOKEN").unwrap_or_default();
                match pl_server::dev::DevConfig::new(token) {
                    Ok(config) => Some(config),
                    Err(message) => {
                        eprintln!("{message}");
                        return ExitCode::from(2);
                    }
                }
            } else {
                None
            };
            let config = ServerConfig {
                addr: SocketAddr::new(host, port),
                workspace,
                #[cfg(feature = "dev-tools")]
                dev,
            };
            match pl_server::serve(config).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(err) => {
                    eprintln!("Не удалось запустить сервер: {err}");
                    ExitCode::from(2)
                }
            }
        }
        #[cfg(feature = "dev-tools")]
        Command::Openapi => {
            print!("{}", pl_server::dev::OPENAPI_YAML);
            ExitCode::SUCCESS
        }
        Command::Apply(args) => finish(apply::run(args)),
        Command::Verify(args) => finish(verify::run(args)),
        Command::Report(args) => finish(report::run(args)),
        Command::Bench(args) => finish(bench::run(args)),
    }
}

/// Код возврата: 0 — всё совпало, 1 — есть отличия, 2 — ошибка.
fn finish(result: Result<common::Exit, String>) -> ExitCode {
    match result {
        Ok(exit) => ExitCode::from(exit.code()),
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}
