//! Настольное приложение: движок поднимается в процессе на свободном порту
//! 127.0.0.1 и открывается в окне. SPA и API те же, что у `protoledger serve`.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::{File, OpenOptions, TryLockError};
use std::io::Write;
use std::net::{Ipv4Addr, TcpListener};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tauri::async_runtime::JoinHandle;
use tauri::{Manager, RunEvent, Url, WebviewUrl, WebviewWindowBuilder};
use tokio::sync::Notify;

/// Сколько ждём завершения запросов после закрытия окна.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

type Server = Mutex<Option<JoinHandle<std::io::Result<()>>>>;

/// Журнал последнего запуска — рядом с проектами: в релизной сборке под Windows консоли нет.
const LOG_FILE: &str = "protoledger.log";
/// Блокировку держит запущенный экземпляр, порт его движка — в соседнем файле.
const LOCK_FILE: &str = ".protoledger-desktop.lock";
const PORT_FILE: &str = ".protoledger-desktop.port";

/// Кто обслуживает окно: свой движок или движок уже запущенного экземпляра.
enum Engine {
    /// Блокировка папки проектов, держится до выхода.
    Own(File),
    /// Второй запуск: два движка на одной папке писали бы в одни проекты.
    Running(u16),
}

fn claim_workspace(workspace: &Path, port: u16) -> Result<Engine, Box<dyn std::error::Error>> {
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(workspace.join(LOCK_FILE))?;
    match lock.try_lock() {
        Ok(()) => {
            let mut file = File::create(workspace.join(PORT_FILE))?;
            write!(file, "{port}")?;
            Ok(Engine::Own(lock))
        }
        Err(TryLockError::WouldBlock) => {
            let text = std::fs::read_to_string(workspace.join(PORT_FILE))?;
            Ok(Engine::Running(text.trim().parse()?))
        }
        Err(TryLockError::Error(e)) => Err(e.into()),
    }
}

fn main() {
    if let Err(err) = run() {
        tracing::error!("приложение завершилось с ошибкой: {err}");
        eprintln!("protoledger: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Порт занимаем до создания окна: первый запрос WebView ждёт в очереди сокета.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let stop = Arc::new(Notify::new());

    let app = tauri::Builder::default()
        .setup({
            let stop = stop.clone();
            move |app| {
                let workspace = app.path().document_dir()?.join("protoledger");
                std::fs::create_dir_all(&workspace)?;
                let port = match claim_workspace(&workspace, port)? {
                    Engine::Running(other) => other,
                    Engine::Own(lock) => {
                        let log = File::create(workspace.join(LOG_FILE))?;
                        tracing_subscriber::fmt()
                            .with_target(false)
                            .with_ansi(false)
                            .with_writer(Mutex::new(log))
                            .init();
                        tracing::info!(
                            version = env!("CARGO_PKG_VERSION"),
                            port,
                            "приложение запущено"
                        );
                        app.manage(Mutex::new(lock));
                        let state = pl_server::AppState::new(workspace);
                        let server =
                            tauri::async_runtime::spawn(async move {
                                let listener = tokio::net::TcpListener::from_std(listener)?;
                                pl_server::serve_on(listener, state, async move {
                                    stop.notified().await
                                })
                                .await
                            });
                        app.manage::<Server>(Mutex::new(Some(server)));
                        port
                    }
                };
                let origin: Url = format!("http://127.0.0.1:{port}/").parse()?;

                WebviewWindowBuilder::new(app, "main", WebviewUrl::External(origin.clone()))
                    .title("protoledger")
                    .inner_size(1440.0, 900.0)
                    .min_inner_size(1024.0, 640.0)
                    // Окно показывает только встроенный движок: внешние адреса не открываются.
                    .on_navigation(move |url| same_origin(url, &origin))
                    .build()?;
                Ok(())
            }
        })
        .build(tauri::generate_context!())?;

    app.run(move |app, event| {
        if let RunEvent::Exit = event {
            stop.notify_one();
            let server = app
                .try_state::<Server>()
                .and_then(|s| s.lock().ok().and_then(|mut s| s.take()));
            if let Some(server) = server {
                // Таймер создаётся внутри рантайма: вне его tokio::time паникует.
                let done = tauri::async_runtime::block_on(async move {
                    tokio::time::timeout(SHUTDOWN_GRACE, server).await
                });
                match done {
                    Ok(_) => tracing::info!("окно закрыто, сервер остановлен"),
                    Err(_) => tracing::warn!("сервер не остановился за {SHUTDOWN_GRACE:?}"),
                }
            }
        }
    });
    Ok(())
}

fn same_origin(url: &Url, origin: &Url) -> bool {
    url.scheme() == origin.scheme() && url.host() == origin.host() && url.port() == origin.port()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigation_stays_on_engine() {
        let origin: Url = "http://127.0.0.1:4100/".parse().unwrap();
        let ok = |s: &str| same_origin(&s.parse().unwrap(), &origin);
        assert!(ok("http://127.0.0.1:4100/project/streams?id=1"));
        assert!(!ok("http://127.0.0.1:4101/"));
        assert!(!ok("http://localhost:4100/"));
        assert!(!ok("https://127.0.0.1:4100/"));
        assert!(!ok("https://example.com/"));
        assert!(!ok("file:///C:/Windows/win.ini"));
    }
}
