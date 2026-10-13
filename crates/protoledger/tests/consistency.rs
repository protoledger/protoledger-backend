//! Командная строка и интерфейс идут одним движком: `protoledger apply` и прогон проверки через
//! HTTP API на одной записи с тем же описанием и журналом дают одни и те же сообщения, категории
//! и итоги гипотез.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

struct Server {
    child: Child,
    port: u16,
    token: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Один запрос на соединение: `(код, тело)`.
fn http(port: u16, token: &str, method: &str, path: &str, body: Option<&Value>) -> (u16, String) {
    let body = body.map(Value::to_string).unwrap_or_default();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\
         X-Protoledger-Token: {token}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    assert!(
        !head.to_ascii_lowercase().contains("transfer-encoding"),
        "ответ без длины: {head}"
    );
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (status, body.to_owned())
}

impl Server {
    fn start(name: &str) -> Server {
        let dir =
            std::env::temp_dir().join(format!("pl-consistency-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Свободный порт: занять, узнать номер, отпустить.
        let port = TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let child = Command::new(env!("CARGO_BIN_EXE_protoledger"))
            .args(["serve", "--workspace"])
            .arg(&dir)
            .args(["--port", &port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut server = Server {
            child,
            port,
            token: String::new(),
        };
        let started = Instant::now();
        loop {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                let (status, page) = http(port, "", "GET", "/", None);
                if status == 200 {
                    let marker = "name=\"protoledger-token\" content=\"";
                    let from = page.find(marker).expect("токен на странице") + marker.len();
                    let rest = page.get(from..).unwrap();
                    server.token = rest.get(..rest.find('"').unwrap()).unwrap().to_owned();
                    return server;
                }
            }
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "движок не запустился"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn call(&self, method: &str, path: &str, body: Option<Value>) -> Value {
        let (status, text) = http(self.port, &self.token, method, path, body.as_ref());
        assert!(
            (200..300).contains(&status),
            "{method} {path}: {status} {text}"
        );
        serde_json::from_str(&text).unwrap_or(Value::Null)
    }

    fn job(&self, started: &Value) -> Value {
        let id = started["jobId"].as_str().expect("jobId");
        let begun = Instant::now();
        loop {
            let state = self.call("GET", &format!("/api/jobs/{id}"), None);
            match state["state"].as_str() {
                Some("succeeded") => return state["result"].clone(),
                Some("running" | "queued") => {}
                _ => panic!("задача {id}: {state}"),
            }
            assert!(
                begun.elapsed() < Duration::from_secs(60),
                "задача {id} зависла"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn verdicts(list: &Value) -> BTreeMap<String, String> {
    list.as_array()
        .into_iter()
        .flatten()
        .map(|h| {
            (
                h["id"].as_str().unwrap_or_default().to_owned(),
                h["verdict"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect()
}

#[test]
fn apply_and_a_run_through_the_api_agree() {
    let capture = repo("fixtures/stand/extra.pcapng");
    let log = repo("fixtures/stand/extra.actions.csv");
    let spec = repo("fixtures/stand/interpretation.yaml");
    let mapping =
        json!({ "time": "time", "action": "action", "params": "params", "result": "result" });

    // Путь интерфейса: проект, импорт, журнал, описание, прогон.
    let server = Server::start("run");
    server.call(
        "POST",
        "/api/project",
        Some(json!({ "path": "check.protoledger", "mode": "create" })),
    );
    let imported = server.call("POST", "/api/sources", Some(json!({ "path": capture })));
    server.job(&imported);
    server.call(
        "POST",
        "/api/action-logs",
        Some(json!({ "path": log, "mapping": mapping })),
    );
    let yaml = std::fs::read_to_string(&spec).unwrap();
    server.call("PUT", "/api/interpretation", Some(json!({ "yaml": yaml })));
    let started = server.call("POST", "/api/runs", Some(json!({})));
    server.job(&started);
    let run = server.call("GET", "/api/runs/run-0001", None);
    let items = server.call("GET", "/api/runs/run-0001/items?limit=500", None);

    // Путь командной строки на тех же файлах.
    let dir = std::env::temp_dir().join(format!("pl-consistency-{}-cli", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mapping_file = dir.join("mapping.yaml");
    std::fs::write(
        &mapping_file,
        "time: time\naction: action\nparams: params\nresult: result\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_protoledger"))
        .arg("apply")
        .arg("--interpretation")
        .arg(&spec)
        .arg("--input")
        .arg(&capture)
        .arg("--action-log")
        .arg(&log)
        .arg("--mapping")
        .arg(&mapping_file)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let applied: Value = serde_json::from_slice(&out.stdout).unwrap();

    for key in ["messages", "counts", "unknownBytes"] {
        assert_eq!(
            run["summary"][key], applied["summary"][key],
            "сводка: {key}"
        );
    }
    let total = applied["summary"]["messages"].as_u64().unwrap();
    assert!(total > 0);
    let tested = verdicts(&applied["hypotheses"]);
    assert!(!tested.is_empty(), "в apply нет итогов гипотез");
    assert_eq!(verdicts(&run["hypotheses"]), tested, "итоги гипотез");

    // Каждое сообщение: поток, границы, тип, категория.
    let row = |stream: &Value, m: &Value| {
        format!(
            "{}:{}-{}:{}:{}",
            stream.as_str().unwrap_or_default(),
            m["start"],
            m["end"],
            m["messageId"],
            m["category"]
        )
    };
    let mut from_api: Vec<String> = items["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| row(&m["stream"], m))
        .collect();
    let mut from_cli: Vec<String> = applied["inputs"][0]["streams"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|s| {
            s["messages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| row(&s["id"], m))
                .collect::<Vec<_>>()
        })
        .collect();
    from_api.sort();
    from_cli.sort();
    assert_eq!(from_api.len() as u64, total);
    assert_eq!(from_api, from_cli, "сообщения по одному");
}

/// Поправка часов журнала заменяет его запись в анализе, а прогоны до и после поправки
/// остаются воспроизводимыми: каждый повторяется со своим сопоставлением колонок.
#[test]
fn runs_before_and_after_a_clock_fix_both_verify() {
    let mapping =
        json!({ "time": "time", "action": "action", "params": "params", "result": "result" });
    let server = Server::start("clock");
    server.call(
        "POST",
        "/api/project",
        Some(json!({ "path": "check.protoledger", "mode": "create" })),
    );
    let imported = server.call(
        "POST",
        "/api/sources",
        Some(json!({ "path": repo("fixtures/stand/main.pcapng") })),
    );
    server.job(&imported);
    server.call(
        "POST",
        "/api/action-logs",
        Some(json!({ "path": repo("fixtures/stand/main.actions.csv"), "mapping": mapping })),
    );
    let yaml = std::fs::read_to_string(repo("fixtures/stand/interpretation.yaml")).unwrap();
    server.call("PUT", "/api/interpretation", Some(json!({ "yaml": yaml })));
    let run = |id: &str| {
        let started = server.call("POST", "/api/runs", Some(json!({})));
        server.job(&started);
        server.call("GET", &format!("/api/runs/{id}"), None)
    };
    let before = run("run-0001");
    assert_eq!(before["stale"], false);

    // Десять минут — действия уходят из окон своих обменов: тесты гипотез остаются без примеров.
    let offset = "/api/action-logs/log-0001/clock-offset";
    let shifted = server.call("POST", offset, Some(json!({ "clockOffsetMs": 600_000 })));
    assert_eq!(shifted["id"], "log-0002");
    assert_eq!(shifted["mapping"]["clockOffsetMs"], 600_000);
    let logs = server.call("GET", "/api/action-logs", None);
    assert_eq!(logs["items"][0]["replacedBy"], "log-0002", "{logs}");
    assert!(logs["items"][1].get("replacedBy").is_none(), "{logs}");

    let status =
        |path: &str, body: Value| http(server.port, &server.token, "POST", path, Some(&body)).0;
    assert_eq!(
        status(offset, json!({ "clockOffsetMs": 5 })),
        409,
        "заменён"
    );
    let current = "/api/action-logs/log-0002/clock-offset";
    assert_eq!(status(current, json!({ "clockOffsetMs": 600_000 })), 409);
    assert_eq!(status(current, json!({})), 400);
    assert_eq!(
        status(
            "/api/action-logs/log-9999/clock-offset",
            json!({ "clockOffsetMs": 5 })
        ),
        404
    );
    assert_eq!(
        http(
            server.port,
            "",
            "POST",
            current,
            Some(&json!({ "clockOffsetMs": 5 }))
        )
        .0,
        401
    );

    let stale = server.call("GET", "/api/runs/run-0001", None);
    assert_eq!(stale["staleReasons"], json!(["action_logs"]), "{stale}");
    let after = run("run-0002");
    assert_eq!(after["stale"], false);
    assert_ne!(
        verdicts(&before["hypotheses"]),
        verdicts(&after["hypotheses"]),
        "со сдвигом в десять минут действия не находят свои сообщения"
    );

    // Обратная поправка возвращает сопоставление первого импорта: первый прогон снова актуален.
    let restored = server.call("POST", current, Some(json!({ "clockOffsetMs": 0 })));
    assert_eq!(restored["id"], "log-0003");
    assert_eq!(
        server.call("GET", "/api/runs/run-0001", None)["stale"],
        false
    );
    assert_eq!(
        server.call("GET", "/api/runs/run-0002", None)["staleReasons"],
        json!(["action_logs"])
    );
    drop(server);

    let root = std::env::temp_dir()
        .join(format!("pl-consistency-{}-clock", std::process::id()))
        .join("check.protoledger");
    // Прогон на первом импорте журнала записан как раньше, без нового поля.
    let saved = |id: &str| std::fs::read_to_string(root.join("runs").join(id)).unwrap();
    assert!(!saved("run-0001.json").contains("logMappings"));
    assert!(saved("run-0002.json").contains("logMappings"));

    let out = Command::new(env!("CARGO_BIN_EXE_protoledger"))
        .arg("verify")
        .arg(&root)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    for id in ["run-0001", "run-0002"] {
        assert!(
            stdout.contains(&format!("{id}: результат воспроизводится")),
            "{stdout}"
        );
    }

    // Состав журналов в отчёте не скрыт: заменённые записи названы.
    let out = Command::new(env!("CARGO_BIN_EXE_protoledger"))
        .args(["report", "--format", "md"])
        .arg(&root)
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        report.matches("заменён записью log-0003").count(),
        2,
        "{report}"
    );
}
