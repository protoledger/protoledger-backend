//! Злые журналы, описания протокола и манифесты проекта: ничего не падает и не виснет, итог
//! совпадает с эталоном `fixtures/hostile/inputs.expected.json`
//! (`BLESS=1 cargo test -p pl-hostile --test inputs` обновляет его; результат нужно просмотреть).

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use pl_actions::{LogError, Mapping};
use pl_hostile::inputs::{interpretations, journals, large_journal, manifests};
use pl_interp::schema::Direction;
use pl_interp::{Interpretation, Region, RegionKind, SchemaError, StreamInput, StreamMeta};
use pl_project::{Project, ProjectError};

const BUDGET: Duration = Duration::from_secs(20);

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/hostile")
}

fn guarded(name: &str, f: impl FnOnce() -> String) -> String {
    let started = Instant::now();
    let out = catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| panic!("{name}: паника"));
    let took = started.elapsed();
    assert!(took < BUDGET, "{name}: {took:?}, больше {BUDGET:?}");
    out
}

fn mapping(name: &str) -> Mapping {
    let format = if name.starts_with("json-") {
        "json"
    } else {
        "kv"
    };
    serde_json::from_value(serde_json::json!({
        "time": "time", "action": "action", "params": "params", "result": "result",
        "paramsFormat": format,
    }))
    .unwrap()
}

fn journal(name: &str, bytes: &[u8]) -> String {
    match pl_actions::parse(bytes, &mapping(name)) {
        Ok(log) => format!(
            "ok actions={} row_errors={} skipped={}",
            log.actions.len(),
            log.errors.len(),
            log.skipped
        ),
        Err(e) => format!(
            "error: {}",
            match e {
                LogError::TooLarge => "too_large",
                LogError::TooManyRows => "too_many_rows",
                LogError::NotUtf8 => "not_utf8",
                LogError::Empty => "empty",
                LogError::MissingColumn(..) => "missing_column",
                LogError::Csv { .. } => "csv",
                LogError::MostlyBroken { .. } => "mostly_broken",
                LogError::Mapping(_) => "mapping",
            }
        ),
    }
}

/// Поток из трёх сообщений `[2 байта][длина u16 BE][тело]` и хвоста: на нём проверяется, что
/// принятое описание применяется за разумное время и без гигантских выделений.
fn sample_stream() -> Vec<u8> {
    let mut out = Vec::new();
    for body in [&b"abcdef"[..], &[0xFF; 40], &[]] {
        out.extend_from_slice(&[0xA5, 0x01]);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
    }
    out.extend_from_slice(&[0xA5, 0x01, 0xFF]);
    out
}

fn interpretation(text: &[u8]) -> String {
    let Ok(text) = std::str::from_utf8(text) else {
        return "error: not_utf8".to_owned();
    };
    let it = match Interpretation::parse(text) {
        Ok(it) => it,
        Err(SchemaError::TooLarge) => return "error: too_large".to_owned(),
        Err(SchemaError::Yaml(_)) => return "error: yaml".to_owned(),
        Err(SchemaError::Invalid(_)) => return "error: invalid".to_owned(),
    };
    let data = sample_stream();
    let input = StreamInput {
        meta: StreamMeta {
            direction: Direction::AToB,
            src_ip: "10.0.0.1".into(),
            dst_ip: "10.0.0.2".into(),
            src_port: 40000,
            dst_port: 5020,
            start_available: true,
        },
        length: data.len() as u64,
        regions: vec![Region {
            start: 0,
            end: data.len() as u64,
            kind: RegionKind::Data(&data),
        }],
    };
    match pl_interp::apply(&it, &input, &|| false) {
        Ok(result) => {
            let counts: Vec<String> = result
                .counts()
                .iter()
                .map(|(c, n)| format!("{}:{n}", c.code()))
                .collect();
            format!(
                "ok messages={} [{}]",
                result.messages.len(),
                counts.join(" ")
            )
        }
        Err(e) => format!("ok, apply error: {e}"),
    }
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pl-hostile-inputs-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn project_error(e: &ProjectError) -> &'static str {
    match e {
        ProjectError::InvalidPath(_) => "invalid_path",
        ProjectError::Missing => "missing",
        ProjectError::NotAProject => "not_a_project",
        ProjectError::AlreadyExists => "already_exists",
        ProjectError::UnsupportedVersion { .. } => "unsupported_version",
        ProjectError::InvalidManifest(_) => "invalid_manifest",
        ProjectError::NotRegularFile => "not_regular_file",
        ProjectError::NotCapture => "not_capture",
        ProjectError::LimitExceeded { .. } => "limit_exceeded",
        ProjectError::UnknownSource(_) => "unknown_source",
        ProjectError::UnknownRevision(_) => "unknown_revision",
        ProjectError::UnknownRun(_) => "unknown_run",
        ProjectError::UnknownActionLog(_) => "unknown_action_log",
        _ => "other",
    }
}

/// Открывает проект с таким манифестом и пробует всё прочитать. Снаружи папки лежит «секрет»:
/// ни одна операция не должна его вернуть.
fn project(name: &str, manifest: &[u8]) -> String {
    let dir = temp(name);
    std::fs::write(dir.join("secret"), b"TOP-SECRET").unwrap();
    std::fs::write(dir.join("outside.json"), b"TOP-SECRET").unwrap();
    let root = dir.join("demo.protoledger");
    for sub in [
        "sources",
        "runs",
        "action-logs",
        "interpretation/history",
        ".cache",
    ] {
        std::fs::create_dir_all(root.join(sub)).unwrap();
    }
    std::fs::write(root.join("project.yaml"), manifest).unwrap();
    let project = match Project::open(&root) {
        Ok(p) => p,
        Err(e) => return format!("error: {}", project_error(&e)),
    };
    let leaked = |bytes: &[u8]| bytes.windows(10).any(|w| w == b"TOP-SECRET");
    let mut notes = Vec::new();
    for source in project.sources() {
        match project.check_source(&source.sha256, &|| false) {
            Ok(status) => notes.push(format!("source:{status:?}").to_lowercase()),
            Err(e) => notes.push(format!("source:{}", project_error(&e))),
        }
        assert!(
            project
                .source_path(&source.sha256)
                .map_or(true, |p| p.starts_with(&root)),
            "{name}: путь записи вне проекта"
        );
    }
    for id in project.run_ids() {
        match project.read_run(id) {
            Ok(text) => {
                assert!(
                    !leaked(text.as_bytes()),
                    "{name}: прочитан файл вне проекта"
                );
                notes.push("run:read".to_owned());
            }
            Err(e) => notes.push(format!("run:{}", project_error(&e))),
        }
    }
    for log in project.action_logs() {
        match project.read_action_log(&log.id) {
            Ok(bytes) => {
                assert!(!leaked(&bytes), "{name}: прочитан файл вне проекта");
                notes.push("log:read".to_owned());
            }
            Err(e) => notes.push(format!("log:{}", project_error(&e))),
        }
    }
    for rev in project.interpretation_revisions() {
        match project.read_interpretation(rev.rev) {
            Ok((_, text)) => {
                assert!(
                    !leaked(text.as_bytes()),
                    "{name}: прочитан файл вне проекта"
                );
                notes.push("revision:read".to_owned());
            }
            Err(e) => notes.push(format!("revision:{}", project_error(&e))),
        }
    }
    format!("ok {}", notes.join(" ")).trim_end().to_owned()
}

fn write_if_changed(path: &Path, bytes: &[u8]) {
    if std::fs::read(path).ok().as_deref() != Some(bytes) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
}

/// Группа образцов: подкаталог, образцы и способ разбора.
type Group = (
    &'static str,
    Vec<pl_hostile::Sample>,
    fn(&str, &[u8]) -> String,
);

#[test]
fn hostile_inputs_match_expected_outcomes() {
    let bless = std::env::var_os("BLESS").is_some();
    let mut actual: BTreeMap<String, String> = BTreeMap::new();
    let groups: [Group; 3] = [
        ("journals", journals(), |n, b| journal(n, b)),
        ("interpretations", interpretations(), |_, b| {
            interpretation(b)
        }),
        ("projects", manifests(), |n, b| project(n, b)),
    ];
    for (group, samples, analyse) in groups {
        for s in samples {
            let rel = if group == "projects" {
                format!("{group}/{}/project.yaml", s.name)
            } else {
                format!("{group}/{}.{}", s.name, s.extension)
            };
            let path = fixtures().join(&rel);
            if bless {
                write_if_changed(&path, &s.bytes);
            }
            let committed = std::fs::read(&path).unwrap_or_else(|e| {
                panic!("{rel}: {e} (BLESS=1 cargo test -p pl-hostile --test inputs)")
            });
            assert!(
                committed == s.bytes,
                "{rel}: файл отличается от генератора (BLESS=1 обновит)"
            );
            let outcome = guarded(&rel, || analyse(s.name, &committed));
            actual.insert(rel, outcome);
        }
    }
    let text = serde_json::to_string_pretty(&actual).unwrap() + "\n";
    let path = fixtures().join("inputs.expected.json");
    if bless {
        write_if_changed(&path, text.as_bytes());
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        expected == text,
        "итог разбора злых входов отличается от эталона (BLESS=1 обновит после просмотра):\n{text}"
    );
}

#[test]
fn every_sample_has_a_description_and_a_unique_name() {
    for (group, samples) in [
        ("journals", journals()),
        ("interpretations", interpretations()),
        ("projects", manifests()),
    ] {
        let mut names: Vec<&str> = samples.iter().map(|s| s.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "{group}: имена повторяются");
        assert!(samples.iter().all(|s| !s.what.is_empty()));
    }
}

#[test]
fn large_journals_are_rejected_or_parsed_in_time() {
    let over = large_journal("rows-over-limit").unwrap();
    assert_eq!(
        guarded("rows-over-limit", || journal("rows-over-limit", &over)),
        "error: too_many_rows"
    );
    let line = large_journal("one-line-64-mib").unwrap();
    let outcome = guarded("one-line-64-mib", || journal("one-line-64-mib", &line));
    assert!(
        outcome.starts_with("ok") || outcome.starts_with("error"),
        "{outcome}"
    );
}

#[test]
fn oversized_text_inputs_hit_their_limits() {
    let big = format!(
        "format: protoledger/interpretation@1\n# {}\n",
        "x".repeat(5 << 20)
    );
    assert_eq!(interpretation(big.as_bytes()), "error: too_large");
    let manifest = format!("formatVersion: 1\n# {}\n", "x".repeat(5 << 20));
    let outcome = project("huge-manifest", manifest.as_bytes());
    assert!(outcome.starts_with("error"), "{outcome}");
}

#[test]
fn a_replaced_source_copy_is_reported_as_damaged() {
    let dir = temp("replaced-copy");
    let root = dir.join("demo.protoledger");
    let mut project = Project::create(&root).unwrap();
    let capture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/synthetic/normal.pcapng");
    let source = project
        .add_source(&capture, &|| false, &mut |_| {})
        .unwrap();
    let copy = project.source_path(&source.sha256).unwrap();
    let mut perms = std::fs::metadata(&copy).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    std::fs::set_permissions(&copy, perms).unwrap();
    // Подмена на другую, тоже правильную запись: формат цел, содержимое не то.
    std::fs::copy(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/synthetic/reorder.pcapng"),
        &copy,
    )
    .unwrap();
    let reopened = Project::open(&root).unwrap();
    let status = reopened.check_source(&source.sha256, &|| false).unwrap();
    assert_eq!(format!("{status:?}"), "Damaged");
}

#[cfg(unix)]
#[test]
fn a_symlinked_sources_directory_is_not_followed() {
    let dir = temp("symlinked-sources");
    let outside = dir.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let root = dir.join("demo.protoledger");
    let mut project = Project::create(&root).unwrap();
    let capture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/synthetic/normal.pcapng");
    let source = project
        .add_source(&capture, &|| false, &mut |_| {})
        .unwrap();
    drop(project);
    // Каталог записей подменён ссылкой наружу, внутри — файл с тем же именем.
    let name = format!("{}.pcapng", source.sha256);
    std::fs::copy(root.join("sources").join(&name), outside.join(&name)).unwrap();
    std::fs::remove_dir_all(root.join("sources")).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("sources")).unwrap();
    match Project::open(&root) {
        Err(_) => {}
        Ok(p) => {
            let status = p.check_source(&source.sha256, &|| false);
            assert!(
                !matches!(
                    status.as_ref().map(|s| format!("{s:?}")).as_deref(),
                    Ok("Ready")
                ),
                "запись за символической ссылкой принята как своя: {status:?}"
            );
        }
    }
}
