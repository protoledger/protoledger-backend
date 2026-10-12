//! Злые запросы по всем путям контракта: кривые тела, параметры пути и запроса. Ответ — успех или
//! отказ клиенту с описанием ошибки, но никогда не ошибка сервера; сервер после этого отвечает.

use std::path::PathBuf;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use pl_app::{JobState, OpenMode};
use pl_server::AppState;
use serde_json::{Value, json};
use tower::ServiceExt;

const SPEC: &str = include_str!("../../../openapi.yaml");

fn stand(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/stand")
        .join(name)
}

fn workspace(name: &str) -> AppState {
    let dir = std::env::temp_dir().join(format!("pl-sweep-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    AppState::new(dir)
}

struct Reply {
    status: StatusCode,
    body: Vec<u8>,
}

/// Запрос с верным токеном. Зависание дольше 20 секунд — тоже дефект.
async fn send(
    state: &AppState,
    method: &Method,
    uri: &str,
    content_type: Option<&str>,
    body: Vec<u8>,
) -> Result<Reply, String> {
    let mut request = Request::builder()
        .method(method.clone())
        .uri(uri)
        .header(header::HOST, "localhost:8080")
        .header("x-protoledger-token", state.guard.token());
    if let Some(ct) = content_type {
        request = request.header(header::CONTENT_TYPE, ct);
    }
    let Ok(request) = request.body(Body::from(body)) else {
        // Адрес, который не собрать в запрос, до сервера не дойдёт.
        return Ok(Reply {
            status: StatusCode::BAD_REQUEST,
            body: Vec::new(),
        });
    };
    let call = async {
        let response = pl_server::router(state.clone())
            .oneshot(request)
            .await
            .map_err(|e| e.to_string())?;
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|e| e.to_string())?
            .to_bytes()
            .to_vec();
        Ok::<_, String>(Reply { status, body })
    };
    tokio::time::timeout(Duration::from_secs(20), call)
        .await
        .map_err(|_| "нет ответа за 20 секунд".to_owned())?
}

async fn ok_json(state: &AppState, method: Method, uri: &str, body: Value) -> Value {
    let reply = send(
        state,
        &method,
        uri,
        Some("application/json"),
        body.to_string().into_bytes(),
    )
    .await
    .unwrap();
    assert!(
        reply.status.is_success(),
        "{method} {uri}: {} {}",
        reply.status,
        String::from_utf8_lossy(&reply.body)
    );
    serde_json::from_slice(&reply.body).unwrap_or(Value::Null)
}

async fn wait_jobs(state: &AppState) {
    for job in state.jobs.list() {
        let Some(mut rx) = state.jobs.subscribe(&job.id) else {
            continue;
        };
        let wait = async {
            while !rx.borrow_and_update().state.is_terminal() {
                if rx.changed().await.is_err() {
                    break;
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(60), wait)
            .await
            .expect("задача зависла");
    }
}

/// Проект с записью стенда, журналом, описанием, прогоном, наблюдением, гипотезой и вопросом;
/// возвращает настоящие идентификаторы, чтобы злые запросы доходили до обработчиков.
async fn populated(name: &str) -> (AppState, Vec<String>) {
    let state = workspace(name);
    state
        .session
        .open(&state.jobs, "demo.protoledger", OpenMode::Create)
        .unwrap();
    let path = stand("main.pcapng").to_string_lossy().into_owned();
    ok_json(
        &state,
        Method::POST,
        "/api/sources",
        json!({ "path": path }),
    )
    .await;
    wait_jobs(&state).await;
    let mapping =
        json!({ "time": "time", "action": "action", "params": "params", "result": "result" });
    let log = stand("main.actions.csv").to_string_lossy().into_owned();
    let log = ok_json(
        &state,
        Method::POST,
        "/api/action-logs",
        json!({ "path": log, "mapping": mapping }),
    )
    .await;
    let yaml = std::fs::read_to_string(stand("interpretation.yaml")).unwrap();
    ok_json(
        &state,
        Method::PUT,
        "/api/interpretation",
        json!({ "yaml": yaml }),
    )
    .await;
    ok_json(&state, Method::POST, "/api/runs", json!({})).await;
    wait_jobs(&state).await;
    let conns = ok_json_get(&state, "/api/connections").await;
    let conn = conns["items"][0]["id"].as_str().unwrap().to_owned();
    let stream = conns["items"][0]["streams"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let source = conns["items"][0]["source"].as_str().unwrap().to_owned();
    ok_json(
        &state,
        Method::POST,
        "/api/observations",
        json!({ "anchor": { "source": source, "stream": stream, "start": 0, "end": 4 }, "comment": "сигнатура" }),
    )
    .await;
    ok_json(
        &state,
        Method::POST,
        "/api/hypotheses",
        json!({ "statement": "тип сообщения", "basis": ["obs-1"], "test": "type >= 1" }),
    )
    .await;
    ok_json(
        &state,
        Method::POST,
        "/api/questions",
        json!({ "text": "что такое режим 3?" }),
    )
    .await;
    let job = state.jobs.list().first().map(|j| j.id.clone()).unwrap();
    let ids = vec![
        conn,
        stream,
        source,
        log["id"].as_str().unwrap_or("log-0001").to_owned(),
        "run-0001".to_owned(),
        "obs-1".to_owned(),
        "H1".to_owned(),
        "q-1".to_owned(),
        "1".to_owned(),
        "2".to_owned(),
        job,
    ];
    (state, ids)
}

async fn ok_json_get(state: &AppState, uri: &str) -> Value {
    let reply = send(state, &Method::GET, uri, None, Vec::new())
        .await
        .unwrap();
    assert!(reply.status.is_success(), "{uri}: {}", reply.status);
    serde_json::from_slice(&reply.body).unwrap()
}

/// Значения для параметров пути: бессмыслица, обход каталогов, границы чисел, управляющие символы.
fn path_values() -> Vec<String> {
    vec![
        "x".to_owned(),
        "0".to_owned(),
        "-1".to_owned(),
        "18446744073709551616".to_owned(),
        "%2e%2e%2f%2e%2e%2fsecret".to_owned(),
        "..%5c..%5cwindows%5cwin.ini".to_owned(),
        "%00".to_owned(),
        "%0d%0aX-Injected:%201".to_owned(),
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E".to_owned(),
        "%F0%9F%92%A5%E2%80%AE".to_owned(),
        "a".repeat(3000),
        "ffffffff:c9999:ab".to_owned(),
        "run-9999".to_owned(),
    ]
}

fn queries() -> Vec<String> {
    vec![
        String::new(),
        "?limit=0".to_owned(),
        "?limit=-1&offset=-1".to_owned(),
        "?limit=99999999999999999999&offset=99999999999999999999".to_owned(),
        "?limit=abc&offset=%00".to_owned(),
        "?from=18446744073709551615&len=18446744073709551615".to_owned(),
        "?from=-5&len=-5".to_owned(),
        "?a=run-0001&b=run-0001&kind=nope".to_owned(),
        "?a=..%2f..%2fx&b=%00".to_owned(),
        "?source=%3Cscript%3E&port=70000&address=999.1.1.1&flag=nope".to_owned(),
        "?port=-1&flag=gaps&flag=gaps&flag=gaps".to_owned(),
        "?before=-1&after=99999999999999999999".to_owned(),
        "?stream=x&category=nope&action=%E2%80%AE".to_owned(),
        format!("?q={}", "A".repeat(6000)),
        "?%00=%00&&&===".to_owned(),
    ]
}

/// Тела запросов: `(тип содержимого, байты)`.
fn bodies() -> Vec<(Option<&'static str>, Vec<u8>)> {
    let json_ct = Some("application/json");
    let wrong_types = json!({
        "path": 123, "mode": [], "yaml": {}, "stream": null, "streams": "x", "messageId": 7,
        "field": [], "mapping": "x", "format": 5, "corpus": "x", "revision": "one",
        "connection": {}, "framing": "x", "text": [], "comment": {}, "anchor": "x",
        "statement": 5, "basis": "x", "test": [], "status": "nope", "limit": "много",
        "overlapPolicy": 1, "checksumPolicy": 2, "runId": [], "logId": {}, "windowMs": "долго"
    });
    let hostile_values = json!({
        "path": "../../../../etc/passwd", "mode": "open", "yaml": "format: x\n",
        "stream": "ffffffff:c0001:ab", "streams": ["../x", "\u{0}", "a:b:c:d"],
        "messageId": "<script>", "field": "a.b.c.d.e", "format": "html",
        "mapping": { "time": "\u{202E}", "action": "" },
        "corpus": { "sources": ["../../x"], "direction": "a_to_b", "port": 65535 },
        "revision": 4294967295u32, "connection": "ffffffff:c0001",
        "framing": { "kind": "fixed", "size": 0 }, "text": "\u{0}\u{1b}[31m",
        "comment": "x".repeat(20_000),
        "anchor": { "source": "f".repeat(64), "stream": "x", "start": 18446744073709551615u64, "end": 0 },
        "statement": "", "basis": ["obs-999"], "test": "((((", "status": "superseded",
        "supersededBy": "H1", "overlapPolicy": "last", "checksumPolicy": "drop",
        "runId": "run-9999", "logId": "log-9999", "windowMs": 600001
    });
    let plausible = json!({
        "path": "C:\\Windows\\win.ini", "mode": "create", "yaml": "a: &a [*a]",
        "streams": [], "messageId": "set_param_req", "field": "value",
        "framing": { "kind": "length_prefixed", "length": { "at": 4294967295u32, "type": "u64be", "adjust": -9223372036854775808i64 } },
        "connection": "", "format": "md", "text": "?", "comment": "", "statement": "s",
        "anchor": { "source": "", "stream": "", "start": 0, "end": 0 }
    });
    vec![
        (None, Vec::new()),
        (json_ct, Vec::new()),
        (json_ct, b"{}".to_vec()),
        (json_ct, b"[]".to_vec()),
        (json_ct, b"null".to_vec()),
        (json_ct, "\"строка\"".as_bytes().to_vec()),
        (json_ct, b"{\"path\":".to_vec()),
        (json_ct, vec![0xFF, 0xFE, 0x00, 0x80]),
        (json_ct, [b"[".repeat(5000), b"]".repeat(5000)].concat()),
        (json_ct, wrong_types.to_string().into_bytes()),
        (json_ct, hostile_values.to_string().into_bytes()),
        (json_ct, plausible.to_string().into_bytes()),
        (json_ct, json!({ "лишнее": 1 }).to_string().into_bytes()),
        (Some("text/plain"), b"path=/etc/passwd".to_vec()),
        (Some("application/x-www-form-urlencoded"), b"path=%2Fetc%2Fpasswd".to_vec()),
        (Some("multipart/form-data"), b"--x\r\n\r\n--x--".to_vec()),
        (
            Some("multipart/form-data; boundary=x"),
            b"--x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../../evil.pcap\"\r\n\r\nne zapis\r\n--x\r\nContent-Disposition: form-data; name=\"mapping\"\r\n\r\n{\r\n--x--\r\n".to_vec(),
        ),
        (
            Some("multipart/form-data; boundary=x"),
            b"--x\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\n".to_vec(),
        ),
    ]
}

/// Подставляет в шаблон пути значения; `real` — настоящие идентификаторы проекта.
fn expand(template: &str, values: &[String]) -> Vec<String> {
    if !template.contains('{') {
        return vec![template.to_owned()];
    }
    let mut out = Vec::new();
    for v in values {
        let mut url = String::new();
        let mut rest = template;
        while let Some(open) = rest.find('{') {
            url.push_str(&rest[..open]);
            url.push_str(v);
            rest = rest[open..].split_once('}').map_or("", |(_, tail)| tail);
        }
        url.push_str(rest);
        out.push(url);
    }
    // Смешанные подстановки для путей с двумя параметрами: настоящий первый, злой второй.
    if template.matches('{').count() == 2 {
        for (a, b) in values.iter().zip(values.iter().rev()) {
            let first = template.find('}').unwrap();
            let head = &template[..=first];
            let tail = &template[first + 1..];
            let open = head.find('{').unwrap();
            let tail_open = tail.find('{').unwrap();
            let tail_close = tail.find('}').unwrap();
            out.push(format!(
                "{}{a}{}{b}{}",
                &head[..open],
                &tail[..tail_open],
                &tail[tail_close + 1..]
            ));
        }
    }
    out
}

/// Проходит все пути и методы контракта, возвращает число запросов и список дефектов.
async fn sweep(state: &AppState, real: &[String]) -> (usize, Vec<String>) {
    let spec: Value = serde_saphyr::from_str(SPEC).unwrap();
    let mut values = path_values();
    values.extend(real.iter().cloned());
    let mut sent = 0usize;
    let mut defects: Vec<String> = Vec::new();
    for (template, item) in spec["paths"].as_object().unwrap() {
        // Поток событий задачи держит соединение, пока задача идёт: настоящие задачи тут завершены,
        // а незавершённых злые запросы не оставляют — см. wait_jobs ниже.
        for (method, operation) in item.as_object().unwrap() {
            let documented = &operation["responses"];
            let method = Method::from_bytes(method.to_uppercase().as_bytes()).unwrap();
            let with_body = matches!(method, Method::POST | Method::PUT | Method::PATCH);
            for url in expand(template, &values) {
                let variants: Vec<(String, Option<&'static str>, Vec<u8>)> = if with_body {
                    bodies()
                        .into_iter()
                        .map(|(ct, body)| (url.clone(), ct, body))
                        .collect()
                } else {
                    queries()
                        .into_iter()
                        .map(|q| (format!("{url}{q}"), None, Vec::new()))
                        .collect()
                };
                for (uri, content_type, body) in variants {
                    sent += 1;
                    let shown: String = uri.chars().take(120).collect();
                    match send(state, &method, &uri, content_type, body.clone()).await {
                        Err(why) => defects.push(format!("{method} {template} | {why} | {shown}")),
                        Ok(reply) => {
                            // Каждый код ответа должен быть описан в контракте для этой операции.
                            if documented.get(reply.status.as_str()).is_none() {
                                defects.push(format!(
                                    "{method} {template} | код {} не описан в контракте | {shown} [{}; {} байт тела]",
                                    reply.status.as_u16(),
                                    content_type.unwrap_or("-"),
                                    body.len()
                                ));
                            }
                            if reply.status.is_server_error() {
                                defects.push(format!(
                                    "{method} {template} | ошибка сервера {} | {shown} [{}; {} байт тела] {}",
                                    reply.status,
                                    content_type.unwrap_or("-"),
                                    body.len(),
                                    String::from_utf8_lossy(&reply.body)
                                        .chars()
                                        .take(200)
                                        .collect::<String>()
                                ));
                            } else if reply.status.is_client_error()
                                && uri.starts_with("/api")
                                && !serde_json::from_slice::<Value>(&reply.body).is_ok_and(|v| {
                                    v["type"]
                                        .as_str()
                                        .is_some_and(|t| t.starts_with("urn:protoledger:problem:"))
                                })
                            {
                                defects.push(format!(
                                    "{method} {template} | отказ {} без описания ошибки | {shown}",
                                    reply.status
                                ));
                            }
                        }
                    }
                }
            }
        }
        // Задачи, запущенные злыми запросами, должны завершиться; сервер — отвечать.
        wait_jobs(state).await;
        match send(state, &Method::GET, "/api/health", None, Vec::new()).await {
            Ok(r) if r.status == StatusCode::OK => {}
            other => defects.push(format!(
                "после {template} сервер не отвечает: {:?}",
                other.map(|r| r.status)
            )),
        }
    }
    // Задача может упасть с понятной ошибкой, но не с «внутренней».
    for job in state.jobs.list() {
        if job.state == JobState::Failed && job.error.as_ref().is_some_and(|p| p.status >= 500) {
            defects.push(format!(
                "задача {} завершилась внутренней ошибкой: {:?}",
                job.id,
                job.error.and_then(|p| p.detail)
            ));
        }
    }
    // Один пример на группу «метод, путь, вид дефекта».
    defects.sort();
    let mut grouped: Vec<String> = Vec::new();
    let mut last_key = String::new();
    let mut count = 0usize;
    for d in &defects {
        let key: String = d.splitn(3, " | ").take(2).collect::<Vec<_>>().join(" | ");
        if key == last_key {
            count += 1;
            continue;
        }
        if let Some(prev) = grouped.last_mut() {
            prev.push_str(&format!(" (всего {count})"));
        }
        grouped.push(d.clone());
        last_key = key;
        count = 1;
    }
    if let Some(prev) = grouped.last_mut() {
        prev.push_str(&format!(" (всего {count})"));
    }
    (sent, grouped)
}

fn report(sent: usize, defects: &[String]) {
    assert!(sent > 500, "запросов слишком мало: {sent}");
    assert!(
        defects.is_empty(),
        "видов дефектов: {} на {sent} запросов\n{}",
        defects.len(),
        defects
            .iter()
            .take(120)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn hostile_requests_without_a_project_never_fail_the_server() {
    let state = workspace("empty");
    let (sent, defects) = sweep(&state, &[]).await;
    report(sent, &defects);
}

#[tokio::test(flavor = "multi_thread")]
async fn hostile_requests_against_a_real_project_never_fail_the_server() {
    let (state, real) = populated("project").await;
    let (sent, defects) = sweep(&state, &real).await;
    report(sent, &defects);
    // Проект после всего открывается и отдаёт данные.
    let (status, _) = (
        send(&state, &Method::GET, "/api/project", None, Vec::new())
            .await
            .unwrap()
            .status,
        (),
    );
    assert!(
        status == StatusCode::OK || status == StatusCode::CONFLICT,
        "{status}"
    );
}
