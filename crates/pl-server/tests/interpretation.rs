//! Интерпретация через API: ревизии, проверка, предпросмотр на записи стенда.

use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use pl_app::OpenMode;
use pl_server::AppState;
use serde_json::{Value, json};
use tower::ServiceExt;

fn stand(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/stand")
        .join(name)
}

fn answer_key() -> String {
    std::fs::read_to_string(stand("interpretation.yaml")).unwrap()
}

fn project_state(name: &str) -> AppState {
    let dir = std::env::temp_dir().join(format!("pl-interp-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let state = AppState::new(dir);
    state
        .session
        .open(&state.jobs, "demo.protoledger", OpenMode::Create)
        .unwrap();
    state
}

async fn call(
    state: &AppState,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "localhost:8080")
        .header("x-protoledger-token", state.guard.token());
    let body = match body {
        Some(v) => {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let response = pl_server::router(state.clone())
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn wait_jobs(state: &AppState) {
    for job in state.jobs.list() {
        let mut rx = state.jobs.subscribe(&job.id).unwrap();
        while !rx.borrow_and_update().state.is_terminal() {
            rx.changed().await.unwrap();
        }
    }
}

/// Импортирует запись стенда; возвращает идентификатор потока «клиент → устройство».
async fn import_stand(state: &AppState, name: &str) -> (String, String) {
    let path = stand(name).to_string_lossy().into_owned();
    let (status, _) = call(
        state,
        Method::POST,
        "/api/sources",
        Some(json!({ "path": path })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    wait_jobs(state).await;
    let (_, conns) = call(state, Method::GET, "/api/connections", None).await;
    let streams = &conns["items"][0]["streams"];
    (
        streams[0]["id"].as_str().unwrap().to_owned(),
        streams[1]["id"].as_str().unwrap().to_owned(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn revisions_are_saved_validated_and_listed() {
    let state = project_state("revisions");
    let (status, _) = call(&state, Method::GET, "/api/interpretation", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, saved) = call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(json!({ "yaml": answer_key() })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(
        (saved["rev"].as_u64(), saved["created"].as_bool()),
        (Some(1), Some(true))
    );
    let digest = saved["digest"].as_str().unwrap().to_owned();
    assert_eq!(digest.len(), 64);

    // Тот же смысл, другое форматирование — новой ревизии нет.
    let reformatted = format!("# комментарий\n{}", answer_key());
    let (_, again) = call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(json!({ "yaml": reformatted })),
    )
    .await;
    assert_eq!(
        (again["rev"].as_u64(), again["created"].as_bool()),
        (Some(1), Some(false))
    );

    // Изменение смысла — новая ревизия; первая остаётся прежней.
    let changed = answer_key().replace("adjust: 7", "adjust: 8");
    let (_, second) = call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(json!({ "yaml": changed.clone() })),
    )
    .await;
    assert_eq!(second["rev"], 2);
    let (_, first) = call(&state, Method::GET, "/api/interpretation/revisions/1", None).await;
    assert_eq!(first["digest"], digest.as_str());
    assert!(first["yaml"].as_str().unwrap().contains("adjust: 7"));
    let (_, current) = call(&state, Method::GET, "/api/interpretation", None).await;
    assert_eq!(current["rev"], 2);
    let (_, list) = call(&state, Method::GET, "/api/interpretation/revisions", None).await;
    assert_eq!(list["items"].as_array().unwrap().len(), 2);
    let (status, _) = call(&state, Method::GET, "/api/interpretation/revisions/9", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Ревизии переживают переоткрытие проекта.
    let fresh = AppState::new(state.session.workspace().to_path_buf());
    call(
        &fresh,
        Method::POST,
        "/api/project",
        Some(json!({ "path": "demo.protoledger", "mode": "open" })),
    )
    .await;
    let (_, reopened) = call(&fresh, Method::GET, "/api/interpretation", None).await;
    assert_eq!(reopened["rev"], 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_base_rev_is_409_and_not_saved() {
    let state = project_state("base-rev");
    let put = |yaml: String, base: Option<u32>| {
        let mut body = json!({ "yaml": yaml });
        if let Some(b) = base {
            body["baseRev"] = json!(b);
        }
        body
    };
    // Первая ревизия от пустого проекта: baseRev = 0.
    let (status, first) = call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(put(answer_key(), Some(0))),
    )
    .await;
    assert_eq!(
        (status, first["rev"].as_u64()),
        (StatusCode::OK, Some(1)),
        "{first}"
    );

    // Две «вкладки» от ревизии 1: первая сохраняет, вторая получает 409, ревизия 3 не появляется.
    let a = answer_key().replace("adjust: 7", "adjust: 8");
    let b = answer_key().replace("adjust: 7", "adjust: 9");
    let (status, saved) = call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(put(a.clone(), Some(1))),
    )
    .await;
    assert_eq!((status, saved["rev"].as_u64()), (StatusCode::OK, Some(2)));
    let (status, conflict) = call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(put(b, Some(1))),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
    assert!(conflict["detail"].as_str().unwrap().contains("ревизия 2"));
    let (_, list) = call(&state, Method::GET, "/api/interpretation/revisions", None).await;
    assert_eq!(list["items"].as_array().unwrap().len(), 2);

    // Тот же смысл от устаревшей ревизии — не конфликт; без baseRev — как раньше.
    let (status, same) = call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(put(a, Some(1))),
    )
    .await;
    assert_eq!(
        (status, same["created"].as_bool()),
        (StatusCode::OK, Some(false))
    );
    let c = answer_key().replace("adjust: 7", "adjust: 10");
    let (status, free) = call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(put(c, None)),
    )
    .await;
    assert_eq!((status, free["rev"].as_u64()), (StatusCode::OK, Some(3)));

    // Ревизии новее последней нет: во второй вкладке открыт другой проект.
    let d = answer_key().replace("adjust: 7", "adjust: 11");
    let (status, other) = call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(put(d, Some(7))),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{other}");
    assert!(
        other["detail"].as_str().unwrap().contains("другой проект"),
        "{other}"
    );
    let (_, list) = call(&state, Method::GET, "/api/interpretation/revisions", None).await;
    assert_eq!(list["items"].as_array().unwrap().len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_interpretation_is_422_and_not_saved() {
    let state = project_state("invalid");
    for bad in [
        "format: protoledger/interpretation@9\nframing: { kind: fixed, size: 4 }\n".to_owned(),
        answer_key().replace("kind: length_prefixed", "kind: bogus"),
        "не: [yaml".to_owned(),
        answer_key().replace("hypothesis: H2", "hypothesis: H77"),
    ] {
        let (status, body) = call(
            &state,
            Method::PUT,
            "/api/interpretation",
            Some(json!({ "yaml": bad })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body["detail"]
                .as_str()
                .unwrap()
                .contains("Интерпретация не"),
            "{body}"
        );
    }
    let (_, list) = call(&state, Method::GET, "/api/interpretation/revisions", None).await;
    assert!(list["items"].as_array().unwrap().is_empty());
    let (status, _) = call(
        &AppState::default(),
        Method::GET,
        "/api/interpretation/revisions",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test(flavor = "multi_thread")]
async fn preview_applies_saved_revision_to_the_stand_recording() {
    let state = project_state("preview");
    let (requests, replies) = import_stand(&state, "main.pcapng").await;
    call(
        &state,
        Method::PUT,
        "/api/interpretation",
        Some(json!({ "yaml": answer_key() })),
    )
    .await;

    let (status, page) = call(
        &state,
        Method::POST,
        "/api/interpretation/preview",
        Some(json!({ "stream": requests, "limit": 500 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["rev"], 1);
    assert_eq!(page["outOfScope"], false);
    assert_eq!(page["counts"], json!({ "matched": 16 }));
    assert_eq!(page["unknownBytes"], 0);
    assert_eq!(page["total"], 16);

    // Значения из журнала: уставки 21, 37, 1000.
    let values: Vec<i64> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["messageId"] == "set_param_req")
        .map(|m| {
            m["fields"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["name"] == "value")
                .unwrap()["value"]
                .as_i64()
                .unwrap()
        })
        .collect();
    assert_eq!(values, [21, 37, 1000, 300, 5, 2]);
    let value_field = &page["items"][3]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "value")
        .unwrap()
        .clone();
    assert_eq!(
        (
            value_field["status"].as_str(),
            value_field["hypothesis"].as_str()
        ),
        (Some("hypothesis"), Some("H2"))
    );
    assert_eq!(value_field["valueType"], "int");

    // Байты — hex-строкой, не сырым текстом.
    let signature = page["items"][0]["fields"][0].clone();
    assert_eq!(
        (signature["valueType"].as_str(), signature["value"].as_str()),
        (Some("bytes"), Some("5ac3"))
    );

    // Страницы и фильтр по категории.
    let (_, small) = call(
        &state,
        Method::POST,
        "/api/interpretation/preview",
        Some(json!({ "stream": replies, "limit": 5, "offset": 10 })),
    )
    .await;
    assert_eq!(small["items"].as_array().unwrap().len(), 5);
    assert_eq!(small["total"], 16);
    let (_, none) = call(
        &state,
        Method::POST,
        "/api/interpretation/preview",
        Some(json!({ "stream": replies, "category": "violated" })),
    )
    .await;
    assert_eq!(none["total"], 0);
    assert_eq!(
        none["counts"],
        json!({ "matched": 16 }),
        "сводка не зависит от фильтра"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn preview_with_unsaved_yaml_shows_what_a_wrong_hypothesis_does() {
    let state = project_state("override");
    let (requests, _) = import_stand(&state, "extra.pcapng").await;

    // Без сохранённой ревизии и без yaml применять нечего.
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/interpretation/preview",
        Some(json!({ "stream": requests })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Гипотеза «значение — u16 по смещению 9» с ожиданием 70000 не выполняется, и это видно.
    let naive = answer_key().replace(
        "      - { name: value, at: 7, type: i32be, status: hypothesis, hypothesis: H2 }\n      - { name: checksum, at: end-1, type: u8, status: rule }\n  - id: set_param_resp",
        "      - { name: value, at: 9, type: u16be, status: hypothesis, hypothesis: H2, expect: 70000 }\n      - { name: checksum, at: end-1, type: u8, status: rule }\n  - id: set_param_resp",
    );
    assert_ne!(naive, answer_key());
    let (status, body) = call(
        &state,
        Method::POST,
        "/api/interpretation/preview",
        Some(json!({ "stream": requests, "yaml": naive })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "expect 70000 не подходит к u16: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn preview_scope_and_errors() {
    let state = project_state("scope");
    let (requests, _) = import_stand(&state, "main.pcapng").await;
    let narrow = answer_key().replace("dst_port == 4710 || src_port == 4710", "dst_port == 80");
    let (_, page) = call(
        &state,
        Method::POST,
        "/api/interpretation/preview",
        Some(json!({ "stream": requests, "yaml": narrow })),
    )
    .await;
    assert_eq!(page["outOfScope"], true);
    assert_eq!(page["total"], 0);

    for (body, expected) in [
        (
            json!({ "stream": "нет:c0001:ab", "yaml": answer_key() }),
            StatusCode::NOT_FOUND,
        ),
        (
            json!({ "stream": requests, "yaml": answer_key(), "limit": 0 }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "stream": requests, "yaml": answer_key(), "лишнее": 1 }),
            StatusCode::BAD_REQUEST,
        ),
        (json!({ "yaml": answer_key() }), StatusCode::BAD_REQUEST),
    ] {
        let (status, _) = call(
            &state,
            Method::POST,
            "/api/interpretation/preview",
            Some(body.clone()),
        )
        .await;
        assert_eq!(status, expected, "{body}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn field_hints_suggest_the_type_that_removes_counterexamples() {
    let state = project_state("field-hints");
    import_stand(&state, "main.pcapng").await;
    import_stand(&state, "extra.pcapng").await;
    for log in ["main.actions.csv", "extra.actions.csv"] {
        let mapping =
            json!({ "time": "time", "action": "action", "params": "params", "result": "result" });
        let path = stand(log).to_string_lossy().into_owned();
        let (status, body) = call(
            &state,
            Method::POST,
            "/api/action-logs",
            Some(json!({ "path": path, "mapping": mapping })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    // Ошибка исследователя: значение параметра описано как беззнаковое.
    let unsigned = answer_key().replace("type: i32be", "type: u32be");
    let request = json!({ "yaml": unsigned, "messageId": "set_param_req", "field": "value" });
    let (status, hints) = call(
        &state,
        Method::POST,
        "/api/interpretation/field-hints",
        Some(request),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{hints}");
    assert_eq!(hints["currentType"], "u32be");
    assert_eq!(hints["suggested"], "i32be", "{hints}");
    assert!(
        hints["hypotheses"]
            .as_array()
            .unwrap()
            .contains(&json!("H2")),
        "{hints}"
    );
    assert!(
        hints["messages"]
            .as_array()
            .unwrap()
            .contains(&json!("set_param_req")),
        "{hints}"
    );
    let candidate = |ty: &str| {
        hints["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["type"] == ty)
            .unwrap_or_else(|| panic!("нет варианта {ty}: {hints}"))
            .clone()
    };
    let (now, better) = (candidate("u32be"), candidate("i32be"));
    assert_eq!(now["current"], true);
    assert!(now["counterexamples"].as_u64().unwrap() >= 1, "{now}");
    assert_eq!(now["negative"], 0);
    assert_eq!(better["counterexamples"], 0, "{better}");
    assert!(
        better["negative"].as_u64().unwrap() >= 1,
        "−5 из дополнительной записи: {better}"
    );
    assert!(better["min"].as_i64().unwrap() < 0);
    assert!(better["tests"][0]["held"].as_u64().unwrap() > 0);
    // Обратный порядок байтов даёт больше противоречий, чем верный тип.
    assert!(candidate("i32le")["counterexamples"].as_u64().unwrap() >= 1);
    assert_eq!(hints["candidates"].as_array().unwrap().len(), 4);

    // Верное описание: советовать нечего.
    let (status, fine) = call(
        &state,
        Method::POST,
        "/api/interpretation/field-hints",
        Some(json!({ "yaml": answer_key(), "messageId": "set_param_req", "field": "value" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fine["currentType"], "i32be");
    assert!(fine["suggested"].is_null(), "{fine}");
}

#[tokio::test(flavor = "multi_thread")]
async fn field_hints_explain_what_they_cannot_do() {
    let state = project_state("field-hints-errors");
    import_stand(&state, "main.pcapng").await;
    let ask = |body: Value| {
        let state = state.clone();
        async move {
            call(
                &state,
                Method::POST,
                "/api/interpretation/field-hints",
                Some(body),
            )
            .await
        }
    };
    let (status, problem) = ask(json!({ "messageId": "set_param_req", "field": "value" })).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "нет сохранённого описания: {problem}"
    );
    let yaml = answer_key();
    let (status, _) = ask(json!({ "yaml": yaml, "messageId": "нет", "field": "value" })).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) =
        ask(json!({ "yaml": yaml, "messageId": "set_param_req", "field": "нет" })).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, problem) =
        ask(json!({ "yaml": yaml, "messageId": "set_param_req", "field": "signature" })).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{problem}");
    let (status, _) = ask(json!({ "yaml": "не yaml: [", "messageId": "m", "field": "f" })).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, _) = ask(json!({ "yaml": yaml, "messageId": "set_param_req", "field": "value", "windowMs": 9_999_999 })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn fix_hints_propose_the_edit_that_removes_counterexamples() {
    let state = project_state("fix-hints");
    import_stand(&state, "main.pcapng").await;
    import_stand(&state, "extra.pcapng").await;
    for log in ["main.actions.csv", "extra.actions.csv"] {
        let mapping =
            json!({ "time": "time", "action": "action", "params": "params", "result": "result" });
        let path = stand(log).to_string_lossy().into_owned();
        call(
            &state,
            Method::POST,
            "/api/action-logs",
            Some(json!({ "path": path, "mapping": mapping })),
        )
        .await;
    }
    let ask = |yaml: String| {
        let state = state.clone();
        async move {
            call(
                &state,
                Method::POST,
                "/api/interpretation/fix-hints",
                Some(json!({ "yaml": yaml, "hypothesis": "H2" })),
            )
            .await
        }
    };

    // Знак: значение описано беззнаковым, отрицательное из дополнительной записи его опровергает.
    let (status, hints) = ask(answer_key().replace("type: i32be", "type: u32be")).await;
    assert_eq!(status, StatusCode::OK, "{hints}");
    assert_eq!(hints["current"]["verdict"], "refuted", "{hints}");
    let best = &hints["fixes"][0];
    assert_eq!(best["kind"], "sign", "{hints}");
    assert_eq!(
        (&best["fromType"], &best["toType"]),
        (&json!("u32be"), &json!("i32be"))
    );
    assert_eq!(best["field"], "value");
    assert_eq!(best["result"]["counterexamples"], 0);
    assert!(
        best["summary"]
            .as_str()
            .unwrap()
            .contains("value: читать как число со знаком")
    );
    assert!(
        best["messages"]
            .as_array()
            .unwrap()
            .contains(&json!("set_param_req"))
    );

    // Масштаб: тест сравнивает с параметром, умноженным на десять.
    let test_line = "value == action.params.value";
    assert!(
        answer_key().contains(test_line),
        "тест H2 в описании стенда изменился"
    );
    let scaled = answer_key().replace(test_line, "value == dec(action.params.value, 1)");
    let (status, hints) = ask(scaled).await;
    assert_eq!(status, StatusCode::OK, "{hints}");
    let best = &hints["fixes"][0];
    assert_eq!(best["kind"], "scale", "{hints}");
    assert_eq!(best["test"], test_line);
    assert_eq!(best["result"]["counterexamples"], 0);

    // Верное описание: исправлять нечего.
    let (status, fine) = ask(answer_key()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fine["current"]["counterexamples"], 0, "{fine}");
    assert_eq!(fine["fixes"], json!([]));

    // Гипотезы нет или у неё нет теста — понятный отказ.
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/interpretation/fix-hints",
        Some(json!({ "yaml": answer_key(), "hypothesis": "H999" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        &state,
        Method::POST,
        "/api/interpretation/fix-hints",
        Some(json!({ "hypothesis": "H2" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "нет сохранённого описания");
}

#[tokio::test(flavor = "multi_thread")]
async fn coverage_shows_what_is_described_and_what_is_not() {
    let state = project_state("coverage");
    import_stand(&state, "main.pcapng").await;
    let ask = |body: Value| {
        let state = state.clone();
        async move {
            call(
                &state,
                Method::POST,
                "/api/interpretation/coverage",
                Some(body),
            )
            .await
        }
    };
    let (status, map) = ask(json!({ "yaml": answer_key() })).await;
    assert_eq!(status, StatusCode::OK, "{map}");
    assert_eq!(map["incomplete"], false);
    assert_eq!(map["sources"], 1);
    // Суммы сходятся на каждом уровне: байт учтён ровно одним видом описания.
    let sums = |b: &Value| {
        ["rule", "hypothesis", "unknown", "none"]
            .iter()
            .map(|k| b[*k].as_u64().unwrap())
            .sum::<u64>()
    };
    assert_eq!(sums(&map["bytes"]), map["bytes"]["total"].as_u64().unwrap());
    let types = map["types"].as_array().unwrap();
    assert!(types.len() >= 4, "{map}");
    let mut messages = 0;
    let mut bytes = 0;
    for t in types {
        assert_eq!(
            sums(&t["bytes"]),
            t["bytes"]["total"].as_u64().unwrap(),
            "{t}"
        );
        messages += t["messages"].as_u64().unwrap();
        bytes += t["bytes"]["total"].as_u64().unwrap();
        // Области идут подряд и без пересечений.
        let mut end = 0;
        for r in t["regions"].as_array().unwrap() {
            assert_eq!(r["start"].as_u64().unwrap(), end, "{t}");
            end = r["end"].as_u64().unwrap();
        }
    }
    assert_eq!(messages, map["messages"].as_u64().unwrap());
    assert_eq!(bytes, map["bytes"]["total"].as_u64().unwrap());
    // Запрос уставки описан целиком: сигнатура — правило, значение — гипотеза H2.
    let set = types
        .iter()
        .find(|t| t["messageId"] == "set_param_req")
        .unwrap();
    assert_eq!(set["bytes"]["none"], 0, "{set}");
    let regions = set["regions"].as_array().unwrap();
    assert_eq!(regions[0]["status"], "rule");
    let value = regions.iter().find(|r| r["field"] == "value").unwrap();
    assert_eq!(
        (
            &value["status"],
            &value["hypothesis"],
            &value["sharePermille"]
        ),
        (&json!("hypothesis"), &json!("H2"), &json!(1000))
    );
    assert!(set["hypotheses"].as_array().unwrap().contains(&json!("H2")));

    // Описание только из границ: тип ни у одного сообщения не определён, всё без описания.
    let bare = "format: protoledger/interpretation@1\nframing: { kind: length_prefixed, length: { at: 4, type: u16le, adjust: 7 }, status: rule }\nmessages: []\n";
    let (status, empty) = ask(json!({ "yaml": bare })).await;
    assert_eq!(status, StatusCode::OK, "{empty}");
    assert_eq!(empty["describedPermille"], 0);
    assert_eq!(empty["types"][0]["messageId"], Value::Null);
    assert_eq!(empty["bytes"]["none"], empty["bytes"]["total"]);

    let (status, _) = ask(json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "нет сохранённого описания");
    let (status, _) = ask(json!({ "yaml": answer_key(), "sources": ["нет"] })).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn compare_shows_what_changed_between_two_recordings() {
    let state = project_state("compare");
    import_stand(&state, "main.pcapng").await;
    import_stand(&state, "extra.pcapng").await;
    let (_, sources) = call(&state, Method::GET, "/api/sources?limit=10", None).await;
    let sha = |name: &str| {
        sources["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == name)
            .unwrap_or_else(|| panic!("нет записи {name}: {sources}"))["sha256"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let (main, extra) = (sha("main.pcapng"), sha("extra.pcapng"));
    let ask = |body: Value| {
        let state = state.clone();
        async move {
            call(
                &state,
                Method::POST,
                "/api/interpretation/compare",
                Some(body),
            )
            .await
        }
    };
    let (status, diff) = ask(json!({ "a": [main], "b": [extra], "yaml": answer_key() })).await;
    assert_eq!(status, StatusCode::OK, "{diff}");
    assert_eq!(diff["incomplete"], false);
    assert_eq!(
        (&diff["a"]["sources"], &diff["b"]["sources"]),
        (&json!(1), &json!(1))
    );
    // Дополнительная запись сделана другим клиентом: уставки −5, 70000 и 123456 в основной не встречались.
    let value = diff["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["messageId"] == "set_param_req" && f["field"] == "value")
        .unwrap_or_else(|| panic!("нет отличия в значении уставки: {diff}"));
    assert_eq!(value["change"], "values");
    let new: Vec<&str> = value["newValues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(new.contains(&"-5") && new.contains(&"70000"), "{value}");
    assert!(value["b"]["min"].as_i64().unwrap() < 0);
    let summary = diff["summary"].as_array().unwrap();
    assert!(
        summary.iter().any(|s| s
            .as_str()
            .unwrap()
            .starts_with("set_param_req.value: во втором наборе новые значения")),
        "{summary:?}"
    );
    // Чтений измерений в дополнительной записи нет: тип отмечен пропавшим.
    let types = diff["types"].as_array().unwrap();
    let total: u64 = types.iter().map(|t| t["a"].as_u64().unwrap()).sum();
    assert_eq!(total, diff["a"]["messages"].as_u64().unwrap());
    for t in types {
        let expected = match (t["a"].as_u64().unwrap(), t["b"].as_u64().unwrap()) {
            (0, _) => "new",
            (_, 0) => "missing",
            _ => "same",
        };
        assert_eq!(t["change"], expected, "{t}");
    }

    // Запись, сравнённая сама с собой, отличий не даёт.
    let (status, same) = ask(json!({ "a": [main], "b": [main], "yaml": answer_key() })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(same["fields"], json!([]));
    assert!(
        same["types"]
            .as_array()
            .unwrap()
            .iter()
            .all(|t| t["change"] == "same")
    );
    assert_eq!(same["summary"].as_array().unwrap().len(), 1);
    for t in same["timing"].as_array().unwrap() {
        assert_eq!(t["ratioPermille"], 1000, "{t}");
    }

    let (status, _) = ask(json!({ "a": [], "b": [main], "yaml": answer_key() })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = ask(json!({ "a": [main], "b": ["нет"], "yaml": answer_key() })).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = ask(json!({ "a": [main], "b": [extra] })).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "нет сохранённого описания");
}

#[tokio::test(flavor = "multi_thread")]
async fn exchange_graph_shows_answers_and_transitions() {
    let state = project_state("graph");
    import_stand(&state, "main.pcapng").await;
    let (status, g) = call(
        &state,
        Method::POST,
        "/api/interpretation/graph",
        Some(json!({ "yaml": answer_key() })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{g}");
    assert_eq!(g["incomplete"], false);
    assert!(g["connections"].as_u64().unwrap() >= 1);
    // Сумма по узлам — все сообщения.
    let nodes = g["nodes"].as_array().unwrap();
    let total: u64 = nodes
        .iter()
        .map(|n| n["requests"].as_u64().unwrap() + n["responses"].as_u64().unwrap())
        .sum();
    assert_eq!(total, g["messages"].as_u64().unwrap());
    // На запрос уставки устройство отвечает своим типом ответа — и только им.
    let answers = g["answers"].as_array().unwrap();
    let to_set: Vec<&Value> = answers
        .iter()
        .filter(|e| e["from"] == "set_param_req")
        .collect();
    assert_eq!(to_set.len(), 1, "{g}");
    assert_eq!(to_set[0]["to"], "set_param_resp");
    let requests = nodes.iter().find(|n| n["id"] == "set_param_req").unwrap()["requests"]
        .as_u64()
        .unwrap();
    assert_eq!(to_set[0]["count"].as_u64().unwrap(), requests);
    // Переходов между запросами на один меньше, чем запросов в соединении.
    let next: u64 = g["next"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["count"].as_u64().unwrap())
        .sum();
    let all_requests: u64 = nodes.iter().map(|n| n["requests"].as_u64().unwrap()).sum();
    assert_eq!(next + g["connections"].as_u64().unwrap(), all_requests);
    assert_eq!(g["starts"][0]["from"], "начало");
    let dot = g["dot"].as_str().unwrap();
    assert!(
        dot.starts_with("digraph exchange {")
            && dot.contains("\"set_param_req\" -> \"set_param_resp\""),
        "{dot}"
    );

    let (status, _) = call(
        &state,
        Method::POST,
        "/api/interpretation/graph",
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "нет сохранённого описания");
}
