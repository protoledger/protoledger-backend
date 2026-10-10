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
    },
    /// Применить интерпретацию к записям
    Apply,
    /// Перепроверить проект
    Verify,
    /// Сформировать отчёт
    Report,
    /// Замерить время и память
    Bench,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt().with_target(false).init();
    match Cli::parse().command {
        Command::Serve {
            host,
            port,
            workspace,
        } => {
            let config = ServerConfig {
                addr: SocketAddr::new(host, port),
                workspace,
            };
            match pl_server::serve(config).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(err) => {
                    eprintln!("Не удалось запустить сервер: {err}");
                    ExitCode::from(2)
                }
            }
        }
        Command::Apply | Command::Verify | Command::Report | Command::Bench => {
            eprintln!("Команда пока не реализована.");
            ExitCode::from(2)
        }
    }
}
