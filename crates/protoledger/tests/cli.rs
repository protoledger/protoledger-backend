//! Командная строка: `apply` на записях стенда совпадает с эталоном, `verify` различает «совпало»,
//! «отличается» и «ошибка» по коду возврата.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use pl_app::{Session, SourceStore};
use pl_interp::Interpretation;
use pl_project::Project;

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_protoledger"))
        .args(args)
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn mapping_file(dir: &Path) -> PathBuf {
    let path = dir.join("mapping.yaml");
    std::fs::write(
        &path,
        "time: time\naction: action\nparams: params\nresult: result\n",
    )
    .unwrap();
    path
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pl-cli-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Сверка с эталоном; `BLESS=1` обновляет файлы (результат нужно просмотреть).
fn golden(name: &str, actual: &str) {
    let path = repo("fixtures/stand/expected").join(name);
    if std::env::var_os("BLESS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e} (BLESS=1 cargo test -p protoledger --test cli)",
            path.display()
        )
    });
    assert!(
        expected == actual,
        "{name}: результат apply отличается от эталона (BLESS=1 обновит после проверки)"
    );
}

fn apply(input: &str, extra: &[&str]) -> Output {
    let interpretation = repo("fixtures/stand/interpretation.yaml");
    let input = repo(input);
    let mut args = vec![
        "apply",
        "--interpretation",
        interpretation.to_str().unwrap(),
        "--input",
        input.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    run(&args)
}

#[test]
fn apply_matches_the_committed_results() {
    let dir = temp("golden");
    let mapping = mapping_file(&dir);
    for (name, input, log) in [
        (
            "apply-main.json",
            "fixtures/stand/main.pcapng",
            "fixtures/stand/main.actions.csv",
        ),
        (
            "apply-extra.json",
            "fixtures/stand/extra.pcapng",
            "fixtures/stand/extra.actions.csv",
        ),
    ] {
        let log = repo(log);
        let out = apply(
            input,
            &[
                "--action-log",
                log.to_str().unwrap(),
                "--mapping",
                mapping.to_str().unwrap(),
            ],
        );
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert!(
            text(&out.stderr).contains("совпало"),
            "краткая сводка в stderr"
        );
        golden(name, &text(&out.stdout));
    }
}

#[test]
fn apply_is_deterministic_and_writes_to_a_file() {
    let dir = temp("file");
    let target = dir.join("result.json");
    let a = apply(
        "fixtures/stand/main.pcapng",
        &["--out", target.to_str().unwrap()],
    );
    assert_eq!(a.status.code(), Some(0));
    assert!(a.stdout.is_empty());
    let b = apply("fixtures/stand/main.pcapng", &[]);
    assert_eq!(std::fs::read_to_string(&target).unwrap(), text(&b.stdout));
    let json: serde_json::Value = serde_json::from_str(&text(&b.stdout)).unwrap();
    assert_eq!(json["format"], "protoledger/apply-result@1");
    assert_eq!(json["summary"]["counts"]["matched"], 32);
}

#[test]
fn apply_reports_hypotheses_with_a_log_and_exit_codes() {
    let dir = temp("codes");
    let mapping = mapping_file(&dir);
    let log = repo("fixtures/stand/main.actions.csv");
    let ok = apply(
        "fixtures/stand/main.pcapng",
        &[
            "--action-log",
            log.to_str().unwrap(),
            "--mapping",
            mapping.to_str().unwrap(),
        ],
    );
    let json: serde_json::Value = serde_json::from_str(&text(&ok.stdout)).unwrap();
    assert_eq!(json["hypotheses"][0]["verdict"], "no_counterexample");
    assert_eq!(json["hypotheses"][0]["held"], 6);

    // Неверное правило: --strict даёт код 1, без него — 0.
    let broken = std::fs::read_to_string(repo("fixtures/stand/interpretation.yaml"))
        .unwrap()
        .replace("checksum == sum8(0, message.len - 1)", "checksum == 7");
    let path = dir.join("broken.yaml");
    std::fs::write(&path, broken).unwrap();
    let input = repo("fixtures/stand/main.pcapng");
    let base = [
        "apply",
        "--interpretation",
        path.to_str().unwrap(),
        "--input",
        input.to_str().unwrap(),
    ];
    let lenient = run(&base);
    assert_eq!(lenient.status.code(), Some(0));
    let strict = run(&[&base[..], &["--strict"]].concat());
    assert_eq!(strict.status.code(), Some(1), "{}", text(&strict.stderr));

    // Ошибки ввода — код 2 и понятное сообщение.
    for args in [
        vec![
            "apply",
            "--interpretation",
            "нет.yaml",
            "--input",
            input.to_str().unwrap(),
        ],
        vec![
            "apply",
            "--interpretation",
            path.to_str().unwrap(),
            "--input",
            "нет.pcap",
        ],
        vec![
            "apply",
            "--interpretation",
            path.to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--overlap",
            "всегда",
        ],
    ] {
        let out = run(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(!out.stderr.is_empty());
    }
    let not_capture = dir.join("text.pcap");
    std::fs::write(&not_capture, "это не запись").unwrap();
    let out = run(&[
        "apply",
        "--interpretation",
        path.to_str().unwrap(),
        "--input",
        not_capture.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("не является записью"),
        "{}",
        text(&out.stderr)
    );
}

/// Проект с записью стенда, интерпретацией и одним прогоном — собирается библиотекой, без сервера.
fn project_with_run(name: &str) -> PathBuf {
    let dir = temp(name);
    let root = dir.join("demo.protoledger");
    let mut project = Project::create(&root).unwrap();
    for file in ["main.pcapng", "extra.pcapng"] {
        project
            .add_source(&repo("fixtures/stand").join(file), &|| false, &mut |_| {})
            .unwrap();
    }
    let yaml = std::fs::read_to_string(repo("fixtures/stand/interpretation.yaml")).unwrap();
    let digest = Interpretation::parse(&yaml).unwrap().digest();
    project.save_interpretation(&yaml, &digest).unwrap();

    let session = Session::new(dir.clone());
    session.attach(project);
    let store = SourceStore::default();
    assert!(
        pl_app::load_project_sources(&session, &store, &|| false)
            .unwrap()
            .is_empty()
    );
    let current = pl_app::current_signature(&session, &store).unwrap();
    let it = Interpretation::parse(&yaml).unwrap();
    let sources: Vec<_> = store.list();
    let mut run = pl_app::execute_run(
        &it,
        Some(1),
        &sources,
        &Default::default(),
        current.settings_digest,
        &|| false,
        &mut |_, _| {},
    )
    .unwrap();
    {
        let mut guard = session.write();
        let project = guard.as_mut().unwrap();
        run.id = project.next_run_id();
        project
            .save_run(&run.id, &serde_json::to_string(&run).unwrap())
            .unwrap();
    }
    add_research(&session, &store);
    root
}

/// Наблюдение, гипотеза с тестом и вопрос; текст нарочно содержит разметку.
fn add_research(session: &Session, store: &SourceStore) {
    let logs = pl_app::ActionLogStore::default();
    let mapping =
        serde_saphyr::from_str("time: time\naction: action\nparams: params\nresult: result\n")
            .unwrap();
    let csv = std::fs::read(repo("fixtures/stand/main.actions.csv")).unwrap();
    pl_app::import_action_log(session, &logs, "main.actions.csv", &csv, mapping).unwrap();

    let data = store.list().into_iter().next().unwrap();
    let anchor = pl_app::AnchorRef {
        source: data.sha256.clone(),
        stream: format!("{}:ab", data.connections[0].id(&data.sha256)),
        start: 0,
        end: 8,
        sha256: None,
    };
    let observation = pl_app::add_observation(
        session,
        store,
        anchor,
        "заголовок <script>alert(1)</script> | в _таблице_".to_owned(),
    )
    .unwrap();
    pl_app::add_hypothesis(
        session,
        pl_app::HypothesisInput {
            statement: Some("value совпадает с параметром действия".to_owned()),
            basis: Some(vec![observation.id]),
            test: Some("message.len > 5".to_owned()),
            ..Default::default()
        },
    )
    .unwrap();
    pl_app::add_question(session, "Что означает режим 3?".to_owned()).unwrap();
}

#[test]
fn verify_confirms_a_reproducible_project() {
    let root = project_with_run("ok");
    let out = run(&["verify", root.to_str().unwrap()]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(
        stdout.contains("run-0001: результат воспроизводится"),
        "{stdout}"
    );
    assert!(stdout.contains("main.pcapng: цела"), "{stdout}");
}

#[test]
fn verify_detects_a_tampered_result() {
    let root = project_with_run("tampered");
    let path = root.join("runs/run-0001.json");
    let tampered =
        std::fs::read_to_string(&path)
            .unwrap()
            .replacen("\"matched\":54", "\"matched\":53", 1);
    assert_ne!(
        tampered,
        std::fs::read_to_string(&path).unwrap(),
        "в прогоне есть счётчик matched"
    );
    std::fs::write(&path, tampered).unwrap();
    let out = run(&["verify", root.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stdout));
    assert!(text(&out.stdout).contains("РЕЗУЛЬТАТ ОТЛИЧАЕТСЯ"));
}

#[test]
fn verify_detects_a_modified_source_copy() {
    let root = project_with_run("source");
    let sources = root.join("sources");
    let copy = std::fs::read_dir(&sources)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "pcapng"))
        .unwrap();
    let mut perms = std::fs::metadata(&copy).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    std::fs::set_permissions(&copy, perms).unwrap();
    let mut bytes = std::fs::read(&copy).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&copy, bytes).unwrap();
    let out = run(&["verify", root.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stdout));
    assert!(
        text(&out.stdout).contains("КОПИЯ ИЗМЕНЕНА"),
        "{}",
        text(&out.stdout)
    );
}

#[test]
fn verify_errors_have_code_two() {
    let dir = temp("errors");
    assert_eq!(
        run(&["verify", dir.join("нет").to_str().unwrap()])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        run(&["verify", dir.to_str().unwrap()]).status.code(),
        Some(2)
    );
    let root = project_with_run("badrun");
    assert_eq!(
        run(&["verify", root.to_str().unwrap(), "--run", "run-0099"])
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn report_describes_the_project_in_both_formats() {
    let root = project_with_run("report");
    let md = run(&["report", root.to_str().unwrap()]);
    let md_text = text(&md.stdout);
    assert_eq!(md.status.code(), Some(0), "{}", text(&md.stderr));
    for needle in [
        "# Отчёт по проекту",
        "## Область применимости",
        "main.pcapng",
        "## Результат проверки",
        "совпало",
        "## Гипотезы",
        "выполнилась на",
        "это не доказательство",
        "## Наблюдения",
        "## Открытые вопросы",
        "Что означает режим 3?",
        "protoledger verify",
    ] {
        assert!(
            md_text.contains(needle),
            "в отчёте нет «{needle}»:\n{md_text}"
        );
    }
    assert!(
        !md_text.contains("<script>"),
        "разметка в Markdown экранируется"
    );

    let html = run(&["report", root.to_str().unwrap(), "--format", "html"]);
    let html_text = text(&html.stdout);
    assert_eq!(html.status.code(), Some(0));
    assert!(html_text.contains("Content-Security-Policy"));
    assert!(!html_text.contains("<script"), "в отчёте нет скриптов");
    assert!(html_text.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(!html_text.contains("http://") && !html_text.contains("https://"));
}

#[test]
fn report_is_deterministic_and_goes_to_a_file() {
    let root = project_with_run("report-file");
    let target = root.parent().unwrap().join("report.html");
    let a = run(&[
        "report",
        root.to_str().unwrap(),
        "--format",
        "html",
        "--out",
        target.to_str().unwrap(),
    ]);
    assert_eq!(a.status.code(), Some(0), "{}", text(&a.stderr));
    assert!(a.stdout.is_empty());
    let b = run(&["report", root.to_str().unwrap(), "--format", "html"]);
    assert_eq!(std::fs::read_to_string(&target).unwrap(), text(&b.stdout));
}

#[test]
fn report_flags_a_stale_run_and_rejects_bad_input() {
    let root = project_with_run("report-stale");
    let mut project = Project::open(&root).unwrap();
    let yaml = std::fs::read_to_string(repo("fixtures/stand/interpretation.yaml"))
        .unwrap()
        .replace("length + 7 == message.len", "length + 8 == message.len");
    let digest = Interpretation::parse(&yaml).unwrap().digest();
    project.save_interpretation(&yaml, &digest).unwrap();
    drop(project);
    let out = run(&["report", root.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("прогон устарел"),
        "{}",
        text(&out.stdout)
    );

    assert_eq!(
        run(&["report", root.to_str().unwrap(), "--run", "run-0099"])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(run(&["report", "нет-такого"]).status.code(), Some(2));
}
