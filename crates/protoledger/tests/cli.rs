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
        &[],
        &Default::default(),
        current.settings_digest,
        true,
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

    // Свой путь пользователь пишет как привык: с «..» и «.» тоже.
    let roundabout = root.join("..").join(".").join(root.file_name().unwrap());
    for command in ["verify", "report"] {
        let out = run(&[command, roundabout.to_str().unwrap()]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{command}: {}",
            text(&out.stderr)
        );
    }
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

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// R5: перенос проекта — копирование папки; на другой машине `verify` даёт тот же результат.
#[test]
fn a_copied_project_verifies_and_reports_the_same() {
    let root = project_with_run("transfer");
    let original = run(&["verify", root.to_str().unwrap()]);
    assert_eq!(
        original.status.code(),
        Some(0),
        "{}",
        text(&original.stdout)
    );

    // Служебный кэш в перенос не входит: проект собирается заново.
    let _ = std::fs::remove_dir_all(root.join(".cache"));
    let elsewhere = temp("transfer-copy").join("перенесённый.protoledger");
    copy_dir(&root, &elsewhere);

    // В проекте нет абсолютных путей: ни временной папки, ни имени пользователя.
    let dir = root
        .parent()
        .unwrap()
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/");
    let manifest = std::fs::read_to_string(elsewhere.join("project.yaml"))
        .unwrap()
        .replace(std::path::MAIN_SEPARATOR, "/");
    assert!(!manifest.contains(&dir), "в манифесте абсолютный путь");

    let copied = run(&["verify", elsewhere.to_str().unwrap()]);
    assert_eq!(copied.status.code(), Some(0), "{}", text(&copied.stdout));
    let strip = |s: &str| {
        s.lines()
            .filter(|l| l.starts_with("run-"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(strip(&text(&original.stdout)), strip(&text(&copied.stdout)));

    let a = run(&["report", root.to_str().unwrap(), "--format", "md"]);
    let b = run(&["report", elsewhere.to_str().unwrap(), "--format", "md"]);
    assert_eq!(
        text(&a.stdout),
        text(&b.stdout),
        "отчёт не зависит от места"
    );
}

#[test]
fn bench_reports_stages_for_every_capture_in_a_directory() {
    let dir = repo("fixtures/synthetic");
    let interpretation = repo("fixtures/synthetic/interpretation.yaml");
    let out = run(&[
        "bench",
        dir.to_str().unwrap(),
        "--interpretation",
        interpretation.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let json: serde_json::Value = serde_json::from_str(&text(&out.stdout)).unwrap();
    let files = json["files"].as_array().unwrap();
    assert!(files.len() >= 10, "{files:?}");
    let normal = files.iter().find(|f| f["name"] == "normal.pcapng").unwrap();
    assert_eq!(normal["frames"], 15);
    assert_eq!(normal["connections"], 1);
    assert_eq!(normal["messages"], 8);
    assert!(normal["timings"]["totalMs"].as_f64().is_some());
    assert!(json["peakMemoryBytes"].is_null() || json["peakMemoryBytes"].as_u64().unwrap() > 0);

    let table = run(&["bench", dir.join("normal.pcapng").to_str().unwrap()]);
    assert_eq!(table.status.code(), Some(0));
    assert!(text(&table.stdout).contains("normal.pcapng"));
}

#[test]
fn bench_errors_have_code_two() {
    assert_eq!(run(&["bench", "нет-такого"]).status.code(), Some(2));
    let empty = temp("bench-empty");
    assert_eq!(
        run(&["bench", empty.to_str().unwrap()]).status.code(),
        Some(2)
    );
    let text_file = empty.join("x.pcap");
    std::fs::write(&text_file, "не запись").unwrap();
    assert_eq!(
        run(&["bench", text_file.to_str().unwrap()]).status.code(),
        Some(2)
    );
}

#[test]
fn verify_accepts_a_run_saved_before_hypothesis_tests() {
    let root = project_with_run("legacy-run");
    let path = root.join("runs/run-0001.json");
    let mut run: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert!(
        !run["hypotheses"].as_array().unwrap().is_empty(),
        "у прогона есть итоги тестов"
    );
    run.as_object_mut().unwrap().remove("hypotheses");
    std::fs::write(&path, serde_json::to_string(&run).unwrap()).unwrap();
    let out = self::run(&["verify", root.to_str().unwrap()]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("без тестов гипотез"), "{stdout}");
}

#[test]
fn verify_reruns_a_run_on_its_own_sources_after_a_later_import() {
    let root = project_with_run("later-import");
    let mut project = Project::open(&root).unwrap();
    project
        .add_source(
            &repo("fixtures/synthetic/normal.pcapng"),
            &|| false,
            &mut |_| {},
        )
        .unwrap();
    drop(project);
    let out = run(&["verify", root.to_str().unwrap()]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("normal.pcapng: цела"), "{stdout}");
    assert!(
        stdout.contains("run-0001: результат воспроизводится"),
        "{stdout}"
    );
}

#[test]
fn draft_builds_a_description_that_apply_accepts_on_another_recording() {
    let dir = temp("draft");
    let mapping = mapping_file(&dir);
    let out = dir.join("draft.yaml");
    let made = run(&[
        "draft",
        "--input",
        repo("fixtures/stand/main.pcapng").to_str().unwrap(),
        "--action-log",
        repo("fixtures/stand/main.actions.csv").to_str().unwrap(),
        "--mapping",
        mapping.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(made.status.success(), "{}", text(&made.stderr));
    // Ход сборки — в stderr, по строке на шаг.
    let steps = text(&made.stderr);
    for title in [
        "Границы сообщений:",
        "Типы сообщений:",
        "Контрольная сумма:",
        "Проверка черновика:",
    ] {
        assert!(steps.contains(title), "нет шага «{title}»:\n{steps}");
    }
    let yaml = std::fs::read_to_string(&out).unwrap();
    assert!(yaml.contains("format: protoledger/interpretation@1"));
    assert!(
        yaml.contains("checksum == sum8(0, message.len - 1)"),
        "{yaml}"
    );

    // Черновик, собранный по основной записи, применяется к дополнительной без правки.
    let applied = run(&[
        "apply",
        "--interpretation",
        out.to_str().unwrap(),
        "--input",
        repo("fixtures/stand/extra.pcapng").to_str().unwrap(),
        "--strict",
    ]);
    assert_eq!(applied.status.code(), Some(0), "{}", text(&applied.stderr));
    let json: serde_json::Value = serde_json::from_str(&text(&applied.stdout)).unwrap();
    assert_eq!(
        json["summary"]["counts"]["matched"],
        json["summary"]["messages"]
    );

    // Без --out описание идёт в стандартный вывод; запись без данных — понятная ошибка.
    let printed = run(&[
        "draft",
        "--input",
        repo("fixtures/stand/main.pcapng").to_str().unwrap(),
    ]);
    assert!(text(&printed.stdout).starts_with("# Черновик описания"));
    let missing = run(&["draft", "--input", dir.join("нет.pcap").to_str().unwrap()]);
    assert_eq!(missing.status.code(), Some(2));
}

#[test]
fn coverage_compare_and_graph_work_without_a_project() {
    let spec = repo("fixtures/stand/interpretation.yaml");
    let (main, extra) = (
        repo("fixtures/stand/main.pcapng"),
        repo("fixtures/stand/extra.pcapng"),
    );
    let (spec, main, extra) = (
        spec.to_str().unwrap(),
        main.to_str().unwrap(),
        extra.to_str().unwrap(),
    );

    let coverage = run(&["coverage", "--interpretation", spec, "--input", main]);
    assert_eq!(
        coverage.status.code(),
        Some(0),
        "{}",
        text(&coverage.stderr)
    );
    let map: serde_json::Value = serde_json::from_str(&text(&coverage.stdout)).unwrap();
    assert!(map["describedPermille"].as_u64().unwrap() > 0);
    assert!(text(&coverage.stderr).contains("описано байтов"));

    // Записи отличаются значениями уставки: код 1 и строка о новых значениях.
    let differs = run(&[
        "compare",
        "--interpretation",
        spec,
        "--a",
        main,
        "--b",
        extra,
    ]);
    assert_eq!(differs.status.code(), Some(1), "{}", text(&differs.stderr));
    assert!(text(&differs.stderr).contains("set_param_req.value"));
    let same = run(&[
        "compare",
        "--interpretation",
        spec,
        "--a",
        main,
        "--b",
        main,
    ]);
    assert_eq!(same.status.code(), Some(0));

    let graph = run(&["graph", "--interpretation", spec, "--input", main, "--dot"]);
    assert_eq!(graph.status.code(), Some(0));
    let dot = text(&graph.stdout);
    assert!(dot.starts_with("digraph exchange {"), "{dot}");
    assert!(dot.contains("\"set_param_req\" -> \"set_param_resp\""));
    let full = run(&["graph", "--interpretation", spec, "--input", main]);
    let json: serde_json::Value = serde_json::from_str(&text(&full.stdout)).unwrap();
    assert!(json["nodes"].as_array().unwrap().len() >= 4);

    let broken = run(&["coverage", "--interpretation", main, "--input", main]);
    assert_eq!(
        broken.status.code(),
        Some(2),
        "запись вместо описания — ошибка"
    );
}

#[test]
fn export_writes_a_wireshark_dissector() {
    let spec = repo("fixtures/stand/interpretation.yaml");
    let out = run(&[
        "export",
        "--interpretation",
        spec.to_str().unwrap(),
        "--name",
        "stand",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let lua = text(&out.stdout);
    assert!(lua.contains(r#"Proto("stand""#), "{lua}");
    assert!(lua.contains("tcp:add(4710, proto)"));
    assert!(lua.contains(r#"ProtoField.int32("stand.set_param_req.value""#));

    let bad = run(&[
        "export",
        "--interpretation",
        spec.to_str().unwrap(),
        "--name",
        "Stand 1",
    ]);
    assert_eq!(bad.status.code(), Some(2));
    assert!(text(&bad.stderr).contains("имя протокола"));
}

fn tshark_available() -> bool {
    Command::new("tshark")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Диссектор в tshark и `apply` должны увидеть одни и те же сообщения и значения полей.
/// Тест пропускается, если tshark не установлен; в CI он обязателен (`PL_REQUIRE_TSHARK=1`).
#[test]
fn exported_dissector_agrees_with_apply_in_tshark() {
    if !tshark_available() {
        assert!(
            std::env::var_os("PL_REQUIRE_TSHARK").is_none(),
            "tshark обязателен (PL_REQUIRE_TSHARK), но не найден"
        );
        eprintln!("tshark не найден: сверка пропущена");
        return;
    }
    let dir = temp("export-tshark");
    let lua = dir.join("stand.lua");
    let spec = repo("fixtures/stand/interpretation.yaml");
    let out = run(&[
        "export",
        "--interpretation",
        spec.to_str().unwrap(),
        "--name",
        "stand",
        "--out",
        lua.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));

    // Поля диссектора и то же поле в результате apply: (сообщение, поле).
    let fields = [
        ("set_param_req", "value"),
        ("read_param_resp", "value"),
        ("set_param_resp", "applied"),
        ("measure_resp", "count"),
        ("measure_req", "channel"),
    ];
    for name in ["main", "extra"] {
        let capture = format!("fixtures/stand/{name}.pcapng");
        let mut args = vec![
            "-X".to_owned(),
            format!("lua_script:{}", lua.display()),
            "-r".to_owned(),
            repo(&capture).to_str().unwrap().to_owned(),
            "-Y".to_owned(),
            "stand".to_owned(),
            "-T".to_owned(),
            "fields".to_owned(),
            "-E".to_owned(),
            "occurrence=a".to_owned(),
            "-E".to_owned(),
            "aggregator=,".to_owned(),
            "-e".to_owned(),
            "tcp.srcport".to_owned(),
            "-e".to_owned(),
            "stand.message".to_owned(),
        ];
        for (message, field) in fields {
            args.push("-e".to_owned());
            args.push(format!("stand.{message}.{field}"));
        }
        let shown = Command::new("tshark").args(&args).output().unwrap();
        let (table, errors) = (text(&shown.stdout), text(&shown.stderr));
        assert!(shown.status.success(), "tshark: {errors}");

        // Сообщения по направлениям в порядке кадров и значения каждого поля.
        let mut by_port = std::collections::BTreeMap::<String, Vec<String>>::new();
        let mut values = vec![Vec::<String>::new(); fields.len()];
        for line in table.lines() {
            let cols: Vec<&str> = line.split('\t').collect();
            let list = |i: usize| {
                cols.get(i)
                    .into_iter()
                    .flat_map(|c| c.split(','))
                    .filter(|v| !v.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            };
            by_port.entry(list(0).concat()).or_default().extend(list(1));
            for (i, column) in values.iter_mut().enumerate() {
                column.extend(list(i + 2));
            }
        }
        let mut seen: Vec<Vec<String>> = by_port.into_values().collect();
        seen.sort();
        values.iter_mut().for_each(|v| v.sort());

        let applied = apply(&capture, &[]);
        let result: serde_json::Value = serde_json::from_slice(&applied.stdout).unwrap();
        let mut expected = Vec::new();
        let mut expected_values = vec![Vec::<String>::new(); fields.len()];
        for stream in result["inputs"][0]["streams"].as_array().unwrap() {
            let mut ids = Vec::new();
            for m in stream["messages"].as_array().unwrap() {
                let id = m["messageId"].as_str().unwrap();
                ids.push(id.to_owned());
                for (i, (message, field)) in fields.iter().enumerate() {
                    if id != *message {
                        continue;
                    }
                    for f in m["fields"].as_array().unwrap() {
                        if f["name"] == *field {
                            expected_values[i].push(f["value"].to_string());
                        }
                    }
                }
            }
            expected.push(ids);
        }
        expected.sort();
        expected_values.iter_mut().for_each(|v| v.sort());

        assert_eq!(seen, expected, "{name}: сообщения; tshark: {errors}");
        for (i, (message, field)) in fields.iter().enumerate() {
            assert!(!expected_values[i].is_empty(), "{name}: {message}.{field}");
            assert_eq!(
                values[i], expected_values[i],
                "{name}: {message}.{field}; tshark: {errors}"
            );
        }
    }
}

#[test]
fn apply_says_when_streams_are_outside_the_scope() {
    let dir = temp("out-of-scope");
    let spec = dir.join("other-port.yaml");
    let stand = std::fs::read_to_string(repo("fixtures/stand/interpretation.yaml")).unwrap();
    std::fs::write(&spec, stand.replace("4710", "1")).unwrap();
    let capture = repo("fixtures/stand/main.pcapng");
    let out = run(&[
        "apply",
        "--interpretation",
        spec.to_str().unwrap(),
        "--input",
        capture.to_str().unwrap(),
    ]);
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(err.contains("сообщений 0"), "{err}");
    assert!(
        err.contains("Вне области описания (scope): потоков 2 из 2"),
        "{err}"
    );
    // Когда всё в области, строки нет.
    let inside = apply("fixtures/stand/main.pcapng", &[]);
    assert!(!text(&inside.stderr).contains("Вне области"));
}
