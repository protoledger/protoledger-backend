//! Ответы движка сверяются со схемами `openapi.yaml`: типы, обязательные поля, перечисления и
//! отсутствие полей, которых нет в контракте. Проект — записи стенда с журналами, описанием,
//! двумя прогонами, наблюдением, гипотезой и вопросом.

use std::path::PathBuf;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, header};
use http_body_util::BodyExt;
use pl_app::OpenMode;
use pl_server::AppState;
use serde_json::{Value, json};
use tower::ServiceExt;

const SPEC: &str = include_str!("../../../openapi.yaml");

fn stand(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/stand")
        .join(name)
}

// ------------------------------------------------------------- проверка схем

struct Checker {
    spec: Value,
    problems: Vec<String>,
}

impl Checker {
    fn resolve<'a>(&'a self, mut schema: &'a Value) -> &'a Value {
        while let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
            schema = reference
                .trim_start_matches("#/")
                .split('/')
                .fold(&self.spec, |node, key| &node[key]);
        }
        schema
    }

    /// Свойства схемы вместе со свойствами частей `allOf`.
    fn properties<'a>(&'a self, schema: &'a Value, out: &mut Vec<(&'a String, &'a Value)>) {
        let schema = self.resolve(schema);
        if let Some(props) = schema.get("properties").and_then(Value::as_object) {
            out.extend(props.iter());
        }
        for part in schema
            .get("allOf")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            self.properties(part, out);
        }
    }

    fn type_ok(name: &str, v: &Value) -> bool {
        match name {
            "null" => v.is_null(),
            "integer" => v.is_i64() || v.is_u64(),
            "number" => v.is_number(),
            "string" => v.is_string(),
            "boolean" => v.is_boolean(),
            "array" => v.is_array(),
            "object" => v.is_object(),
            _ => true,
        }
    }

    fn check(&mut self, schema: &Value, v: &Value, path: &str) {
        let schema = self.resolve(schema).clone();
        for key in ["oneOf", "anyOf"] {
            if let Some(options) = schema.get(key).and_then(Value::as_array) {
                let before = self.problems.len();
                let fits = options.iter().any(|option| {
                    let mark = self.problems.len();
                    self.check(option, v, path);
                    let ok = self.problems.len() == mark;
                    self.problems.truncate(mark);
                    ok
                });
                self.problems.truncate(before);
                if !fits {
                    self.problems
                        .push(format!("{path}: не подходит ни один вариант {key}"));
                }
                return;
            }
        }
        if let Some(parts) = schema.get("allOf").and_then(Value::as_array) {
            for part in parts {
                let part = self.resolve(part).clone();
                // Неизвестные поля проверяются один раз — по объединению свойств.
                let mut relaxed = part.clone();
                if let Some(o) = relaxed.as_object_mut() {
                    o.insert("additionalProperties".to_owned(), Value::Bool(true));
                }
                self.check(&relaxed, v, path);
            }
        }
        let types: Vec<String> = match schema.get("type") {
            Some(Value::String(t)) => vec![t.clone()],
            Some(Value::Array(list)) => list
                .iter()
                .filter_map(|t| t.as_str().map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        };
        if !types.is_empty() && !types.iter().any(|t| Self::type_ok(t, v)) {
            self.problems.push(format!(
                "{path}: ожидался тип {}, пришло {v}",
                types.join("|")
            ));
            return;
        }
        if let Some(allowed) = schema.get("enum").and_then(Value::as_array)
            && !allowed.contains(v)
        {
            self.problems
                .push(format!("{path}: значение {v} не из перечисления"));
        }
        if let (Some(min), Some(n)) = (schema.get("minimum").and_then(Value::as_f64), v.as_f64())
            && n < min
        {
            self.problems
                .push(format!("{path}: {n} меньше минимума {min}"));
        }
        if let (Some(max), Some(n)) = (schema.get("maximum").and_then(Value::as_f64), v.as_f64())
            && n > max
        {
            self.problems
                .push(format!("{path}: {n} больше максимума {max}"));
        }
        if let Some(items) = v.as_array() {
            if let Some(max) = schema.get("maxItems").and_then(Value::as_u64)
                && items.len() as u64 > max
            {
                self.problems
                    .push(format!("{path}: элементов больше {max}"));
            }
            if let Some(min) = schema.get("minItems").and_then(Value::as_u64)
                && (items.len() as u64) < min
            {
                self.problems
                    .push(format!("{path}: элементов меньше {min}"));
            }
            if let Some(item_schema) = schema.get("items") {
                // Первых элементов достаточно: остальные той же формы.
                for (i, item) in items.iter().take(50).enumerate() {
                    self.check(item_schema, item, &format!("{path}[{i}]"));
                }
            }
        }
        if let Some(object) = v.as_object() {
            for required in schema
                .get("required")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                if !object.contains_key(required) {
                    self.problems
                        .push(format!("{path}: нет обязательного поля {required}"));
                }
            }
            let mut known = Vec::new();
            self.properties(&schema, &mut known);
            let known: Vec<(String, Value)> = known
                .into_iter()
                .map(|(k, s)| (k.clone(), s.clone()))
                .collect();
            let additional = schema.get("additionalProperties").cloned();
            for (key, value) in object {
                let here = format!("{path}.{key}");
                if let Some((_, property)) = known.iter().find(|(k, _)| k == key) {
                    self.check(property, value, &here);
                } else {
                    match &additional {
                        Some(Value::Bool(true)) => {}
                        Some(extra) if extra.is_object() => self.check(extra, value, &here),
                        _ if known.is_empty() && schema.get("type").is_none() => {}
                        _ => self.problems.push(format!("{here}: поля нет в контракте")),
                    }
                }
            }
        }
    }
}

// ------------------------------------------------------------------ запросы

struct Api {
    state: AppState,
    checker: Checker,
    checked: usize,
}

impl Api {
    async fn raw(&self, method: &Method, uri: &str, body: Option<&Value>) -> (u16, Value) {
        let mut request = Request::builder()
            .method(method.clone())
            .uri(uri)
            .header(header::HOST, "localhost:8080")
            .header("x-protoledger-token", self.state.guard.token());
        let body = match body {
            Some(v) => {
                request = request.header(header::CONTENT_TYPE, "application/json");
                Body::from(v.to_string())
            }
            None => Body::empty(),
        };
        let response = pl_server::router(self.state.clone())
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status().as_u16();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// Запрос и сверка ответа со схемой операции `template` для полученного кода.
    async fn call(
        &mut self,
        method: Method,
        template: &str,
        uri: &str,
        body: Option<Value>,
        expect: u16,
    ) -> Value {
        let (status, value) = self.raw(&method, uri, body.as_ref()).await;
        let label = format!("{method} {template} → {status}");
        assert_eq!(status, expect, "{label}: {value}");
        let operation = &self.checker.spec["paths"][template][method.as_str().to_lowercase()];
        assert!(operation.is_object(), "{label}: операции нет в контракте");
        let response = self
            .checker
            .resolve(&operation["responses"][status.to_string()])
            .clone();
        assert!(response.is_object(), "{label}: код не описан в контракте");
        let content = &response["content"];
        let schema = content["application/json"]
            .get("schema")
            .or_else(|| content["application/problem+json"].get("schema"));
        if let Some(schema) = schema {
            let before = self.checker.problems.len();
            self.checker.check(schema, &value, &label);
            // Одна форма ошибки на операцию — достаточно первых расхождений.
            self.checker.problems.truncate(before + 12);
        } else {
            assert!(value.is_null(), "{label}: тело есть, а в контракте его нет");
        }
        self.checked += 1;
        value
    }

    async fn get(&mut self, template: &str, uri: &str) -> Value {
        self.call(Method::GET, template, uri, None, 200).await
    }

    async fn post(&mut self, template: &str, uri: &str, body: Value, expect: u16) -> Value {
        self.call(Method::POST, template, uri, Some(body), expect)
            .await
    }

    async fn wait_jobs(&self) {
        for job in self.state.jobs.list() {
            let Some(mut rx) = self.state.jobs.subscribe(&job.id) else {
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
}

#[tokio::test(flavor = "multi_thread")]
async fn responses_match_the_contract_schemas() {
    let dir = std::env::temp_dir().join(format!("pl-contract-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let state = AppState::new(dir);
    let mut api = Api {
        state: state.clone(),
        checker: Checker {
            spec: serde_saphyr::from_str(SPEC).unwrap(),
            problems: Vec::new(),
        },
        checked: 0,
    };

    // Без проекта: отказ в общем формате.
    api.call(Method::GET, "/api/project", "/api/project", None, 409)
        .await;
    api.get("/api/health", "/api/health").await;

    state
        .session
        .open(&state.jobs, "demo.protoledger", OpenMode::Create)
        .unwrap();
    api.get("/api/project", "/api/project").await;
    for name in ["main.pcapng", "extra.pcapng"] {
        let path = stand(name).to_string_lossy().into_owned();
        let job = api
            .post("/api/sources", "/api/sources", json!({ "path": path }), 202)
            .await;
        let id = job["jobId"].as_str().unwrap().to_owned();
        api.wait_jobs().await;
        api.get("/api/jobs/{id}", &format!("/api/jobs/{id}")).await;
    }
    api.get("/api/jobs", "/api/jobs").await;
    let mapping =
        json!({ "time": "time", "action": "action", "params": "params", "result": "result" });
    let mut log_id = String::new();
    for name in ["main.actions.csv", "extra.actions.csv"] {
        let path = stand(name).to_string_lossy().into_owned();
        let log = api
            .post(
                "/api/action-logs",
                "/api/action-logs",
                json!({ "path": path, "mapping": mapping }),
                200,
            )
            .await;
        if log_id.is_empty() {
            log_id = log["id"].as_str().unwrap().to_owned();
        }
    }

    let sources = api.get("/api/sources", "/api/sources?limit=10").await;
    let sha = sources["items"][0]["sha256"].as_str().unwrap().to_owned();
    api.get(
        "/api/sources/{sha256}/diagnostics",
        &format!("/api/sources/{sha}/diagnostics"),
    )
    .await;
    let conns = api
        .get("/api/connections", "/api/connections?limit=5")
        .await;
    let conn = conns["items"][0]["id"].as_str().unwrap().to_owned();
    let stream = conns["items"][0]["streams"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let source = conns["items"][0]["source"].as_str().unwrap().to_owned();
    let bytes = api
        .get(
            "/api/streams/{stream}/bytes",
            &format!("/api/streams/{stream}/bytes?from=0&len=512"),
        )
        .await;
    let frame = bytes["segments"][0]["frames"][0]["frameNo"]
        .as_u64()
        .or_else(|| bytes["pieces"][0]["frames"][0]["frameNo"].as_u64())
        .unwrap_or(4);
    api.get(
        "/api/frames/{source}/{frameNo}",
        &format!("/api/frames/{source}/{frame}"),
    )
    .await;

    // Описание с ошибкой типа, затем верное: два прогона для сравнения.
    let key = std::fs::read_to_string(stand("interpretation.yaml")).unwrap();
    let wrong = key.replace("type: i32be", "type: u32be");
    api.call(
        Method::PUT,
        "/api/interpretation",
        "/api/interpretation",
        Some(json!({ "yaml": wrong })),
        200,
    )
    .await;
    api.post("/api/runs", "/api/runs", json!({}), 202).await;
    api.wait_jobs().await;
    api.call(
        Method::PUT,
        "/api/interpretation",
        "/api/interpretation",
        Some(json!({ "yaml": key })),
        200,
    )
    .await;
    api.post("/api/runs", "/api/runs", json!({}), 202).await;
    api.wait_jobs().await;
    api.get("/api/interpretation", "/api/interpretation").await;
    api.get(
        "/api/interpretation/revisions",
        "/api/interpretation/revisions",
    )
    .await;
    api.get(
        "/api/interpretation/revisions/{rev}",
        "/api/interpretation/revisions/1",
    )
    .await;
    api.post(
        "/api/interpretation/preview",
        "/api/interpretation/preview",
        json!({ "stream": stream, "limit": 20 }),
        200,
    )
    .await;
    api.post(
        "/api/interpretation/field-hints",
        "/api/interpretation/field-hints",
        json!({ "yaml": wrong, "messageId": "set_param_req", "field": "value" }),
        200,
    )
    .await;

    api.get("/api/runs", "/api/runs?limit=10").await;
    for run in ["run-0001", "run-0002"] {
        api.get("/api/runs/{id}", &format!("/api/runs/{run}")).await;
        api.get(
            "/api/runs/{id}/items",
            &format!("/api/runs/{run}/items?limit=20"),
        )
        .await;
    }
    api.get("/api/runs/diff", "/api/runs/diff?a=run-0001&b=run-0002")
        .await;

    api.get("/api/action-logs", "/api/action-logs").await;
    let actions = api
        .get(
            "/api/action-logs/{id}/actions",
            &format!("/api/action-logs/{log_id}/actions?limit=20"),
        )
        .await;
    let line = actions["items"][3]["line"].as_u64().unwrap_or(2);
    api.get(
        "/api/action-logs/{id}/actions/{line}/exchange",
        &format!("/api/action-logs/{log_id}/actions/{line}/exchange"),
    )
    .await;

    api.post(
        "/api/observations",
        "/api/observations",
        json!({ "anchor": { "source": source, "stream": stream, "start": 0, "end": 4 }, "comment": "сигнатура" }),
        201,
    )
    .await;
    api.get("/api/observations", "/api/observations").await;
    api.get("/api/observations/{id}", "/api/observations/obs-1")
        .await;
    api.call(
        Method::PUT,
        "/api/observations/{id}",
        "/api/observations/obs-1",
        Some(json!({ "comment": "сигнатура 5A C3" })),
        200,
    )
    .await;
    api.post(
        "/api/hypotheses",
        "/api/hypotheses",
        json!({ "statement": "value — параметр действия", "basis": ["obs-1"], "test": "value == action.params.value" }),
        201,
    )
    .await;
    api.get("/api/hypotheses", "/api/hypotheses").await;
    api.get("/api/hypotheses/{id}", "/api/hypotheses/H1").await;
    api.call(
        Method::PUT,
        "/api/hypotheses/{id}",
        "/api/hypotheses/H1",
        Some(json!({ "status": "supported", "note": "на двух записях" })),
        200,
    )
    .await;
    api.post(
        "/api/hypotheses/{id}/test",
        "/api/hypotheses/H1/test",
        json!({}),
        200,
    )
    .await;
    api.post(
        "/api/questions",
        "/api/questions",
        json!({ "text": "что такое режим 3?" }),
        201,
    )
    .await;
    api.get("/api/questions", "/api/questions").await;
    api.call(
        Method::PUT,
        "/api/questions/{id}",
        "/api/questions/q-1",
        Some(json!({ "status": "closed", "answer": "режим калибровки" })),
        200,
    )
    .await;

    let framing = api
        .post(
            "/api/analysis/framing",
            "/api/analysis/framing",
            json!({ "streams": [stream] }),
            200,
        )
        .await;
    let hint = framing["length"][0]["framing"].clone();
    api.post(
        "/api/analysis/variability",
        "/api/analysis/variability",
        json!({ "streams": [stream], "framing": hint }),
        200,
    )
    .await;
    api.post(
        "/api/analysis/correlations",
        "/api/analysis/correlations",
        json!({ "streams": [stream], "messageId": "set_param_req" }),
        200,
    )
    .await;
    api.post(
        "/api/exchanges",
        "/api/exchanges",
        json!({ "connection": conn, "limit": 10 }),
        200,
    )
    .await;
    for format in ["md", "html"] {
        api.post(
            "/api/reports",
            "/api/reports",
            json!({ "format": format }),
            200,
        )
        .await;
    }
    api.call(
        Method::PATCH,
        "/api/project/settings",
        "/api/project/settings",
        Some(json!({ "overlapPolicy": "first", "checksumPolicy": "warn" })),
        200,
    )
    .await;

    // Отказы — тоже по схеме.
    api.call(
        Method::GET,
        "/api/runs/{id}",
        "/api/runs/run-9999",
        None,
        404,
    )
    .await;
    api.call(Method::GET, "/api/runs", "/api/runs?limit=0", None, 400)
        .await;
    api.post(
        "/api/interpretation/preview",
        "/api/interpretation/preview",
        json!({ "stream": stream, "yaml": "не описание: [" }),
        422,
    )
    .await;

    assert!(api.checked >= 55, "проверено ответов: {}", api.checked);
    assert!(
        api.checker.problems.is_empty(),
        "расхождений с контрактом: {}\n{}",
        api.checker.problems.len(),
        api.checker.problems.join("\n")
    );
}

/// Сама проверка ловит расхождения: лишнее поле, не тот тип, значение вне перечисления,
/// пропущенное обязательное поле — в том числе внутри `allOf`, `oneOf` и ссылок.
#[test]
fn the_checker_itself_catches_mismatches() {
    let spec = json!({
        "components": { "schemas": {
            "Base": { "type": "object", "required": ["id"], "properties": { "id": { "type": "string" } } },
            "Item": {
                "allOf": [
                    { "$ref": "#/components/schemas/Base" },
                    { "type": "object", "required": ["kind"], "properties": {
                        "kind": { "type": "string", "enum": ["a", "b"] },
                        "size": { "type": ["integer", "null"], "minimum": 0 },
                        "tags": { "type": "array", "maxItems": 2, "items": { "type": "string" } },
                        "extra": { "oneOf": [{ "type": "string" }, { "type": "null" }] }
                    } }
                ]
            }
        } }
    });
    let schema = json!({ "$ref": "#/components/schemas/Item" });
    let problems = |value: Value| {
        let mut checker = Checker {
            spec: spec.clone(),
            problems: Vec::new(),
        };
        checker.check(&schema, &value, "$");
        checker.problems
    };
    assert!(
        problems(json!({ "id": "x", "kind": "a", "size": null, "tags": ["t"], "extra": null }))
            .is_empty()
    );
    let has = |value: Value, needle: &str| {
        let found = problems(value);
        assert!(
            found.iter().any(|p| p.contains(needle)),
            "ожидалось «{needle}», найдено {found:?}"
        );
    };
    has(
        json!({ "id": "x", "kind": "a", "лишнее": 1 }),
        "поля нет в контракте",
    );
    has(json!({ "kind": "a" }), "нет обязательного поля id");
    has(json!({ "id": "x" }), "нет обязательного поля kind");
    has(json!({ "id": 5, "kind": "a" }), "ожидался тип string");
    has(json!({ "id": "x", "kind": "c" }), "не из перечисления");
    has(
        json!({ "id": "x", "kind": "a", "size": -1 }),
        "меньше минимума",
    );
    has(
        json!({ "id": "x", "kind": "a", "tags": ["1", "2", "3"] }),
        "элементов больше",
    );
    has(
        json!({ "id": "x", "kind": "a", "tags": [1] }),
        "ожидался тип string",
    );
    has(
        json!({ "id": "x", "kind": "a", "extra": 7 }),
        "ни один вариант oneOf",
    );
}
