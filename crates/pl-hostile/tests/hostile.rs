//! Злые записи через конвейер разбора: ничего не падает, не виснет, результат совпадает с эталоном.
//!
//! Эталон `fixtures/hostile/expected.json` обновляется командой
//! `BLESS=1 cargo test -p pl-hostile`; новый результат нужно просмотреть глазами.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use pl_capture::{CaptureError, Limits, index};
use pl_reassembly::{ChecksumPolicy, OverlapPolicy, Policy, ReassemblyError, reassemble};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/hostile")
}

/// Краткий итог разбора для сверки с эталоном.
fn analyse(bytes: &[u8]) -> String {
    let idx = match index(bytes, Limits::default(), &|| false, &mut |_| {}) {
        Ok(idx) => idx,
        Err(CaptureError::NotCapture) => return "error: not_capture".to_owned(),
        Err(CaptureError::LimitExceeded { name, .. }) => {
            return format!("error: limit_exceeded ({name})");
        }
        Err(CaptureError::Cancelled) => return "error: cancelled".to_owned(),
    };
    let diag: Vec<String> = idx
        .diagnostics
        .groups
        .iter()
        .map(|(code, g)| format!("{}:{}", code.code(), g.count))
        .collect();
    let policy = Policy {
        overlap: OverlapPolicy::First,
        checksum: ChecksumPolicy::Warn,
    };
    let conns = match reassemble(&idx, bytes, policy, &|| false) {
        Ok(c) => c,
        Err(ReassemblyError::LimitExceeded { name, .. }) => {
            return format!("frames={} error: limit_exceeded ({name})", idx.frames.len());
        }
        Err(ReassemblyError::Cancelled) => return "error: cancelled".to_owned(),
    };
    let longest = conns
        .iter()
        .flat_map(|c| c.streams.iter())
        .map(|s| s.length)
        .max()
        .unwrap_or(0);
    let gaps: u64 = conns
        .iter()
        .flat_map(|c| c.streams.iter())
        .map(|s| s.gap_bytes())
        .sum();
    format!(
        "ok frames={} segments={} connections={} longest_stream={longest} gap_bytes={gaps} diag=[{}]",
        idx.frames.len(),
        idx.segments.len(),
        conns.len(),
        diag.join(" ")
    )
}

/// Запуск с защитой от паники и контролем времени.
fn guarded(name: &str, bytes: &[u8], budget: Duration) -> String {
    let started = Instant::now();
    let result = catch_unwind(AssertUnwindSafe(|| analyse(bytes)));
    let took = started.elapsed();
    let summary = result.unwrap_or_else(|_| panic!("{name}: паника при разборе"));
    assert!(
        took < budget,
        "{name}: разбор занял {took:?}, больше {budget:?}"
    );
    summary
}

#[test]
fn committed_files_are_up_to_date() {
    for s in pl_hostile::samples() {
        let path = fixtures().join(format!("{}.{}", s.name, s.extension));
        let on_disk = std::fs::read(&path).unwrap_or_else(|e| {
            panic!(
                "{}: {e} (cargo run -p pl-hostile -- --out fixtures/hostile)",
                path.display()
            )
        });
        assert!(
            on_disk == s.bytes,
            "{} устарел: cargo run -p pl-hostile -- --out fixtures/hostile",
            path.display()
        );
    }
}

#[test]
fn hostile_samples_match_expected_outcomes() {
    let mut actual = BTreeMap::new();
    for s in pl_hostile::samples() {
        let key = format!("{}.{}", s.name, s.extension);
        let summary = guarded(&key, &s.bytes, Duration::from_secs(10));
        actual.insert(key, summary);
    }
    let path = fixtures().join("expected.json");
    if std::env::var_os("BLESS").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&actual).unwrap() + "\n").unwrap();
        return;
    }
    let expected: BTreeMap<String, String> = serde_json::from_str(
        &std::fs::read_to_string(&path)
            .expect("нет expected.json: BLESS=1 cargo test -p pl-hostile"),
    )
    .unwrap();
    for (key, summary) in &actual {
        assert_eq!(expected.get(key), Some(summary), "{key}");
    }
    assert_eq!(expected.len(), actual.len(), "в эталоне есть лишние файлы");
}

#[test]
fn no_giant_allocation_on_declared_lengths() {
    // Заявленные 4 ГиБ не должны превращаться в выделение памяти: файл разбирается мгновенно.
    for name in [
        "pcap-caplen-huge",
        "pcapng-block-length-huge",
        "tcp-seq-jump-2gib",
    ] {
        let s = pl_hostile::samples()
            .into_iter()
            .find(|s| s.name == name)
            .unwrap();
        let summary = guarded(name, &s.bytes, Duration::from_secs(2));
        assert!(!summary.contains("panic"), "{name}: {summary}");
    }
}

#[test]
fn seq_jump_becomes_a_gap_not_bytes() {
    let s = pl_hostile::samples()
        .into_iter()
        .find(|s| s.name == "tcp-seq-jump-1gib")
        .unwrap();
    let summary = analyse(&s.bytes);
    assert!(summary.contains("connections=1"), "{summary}");
    // Гигабайтная дыра — только число в метаданных потока.
    assert!(summary.contains("gap_bytes=1073741"), "{summary}");
}

#[test]
fn seq_jump_of_half_the_space_is_ignored_safely() {
    let s = pl_hostile::samples()
        .into_iter()
        .find(|s| s.name == "tcp-seq-jump-2gib")
        .unwrap();
    let summary = analyse(&s.bytes);
    assert!(
        summary.contains("connections=1") && summary.contains("longest_stream=5"),
        "{summary}"
    );
}

#[test]
fn large_records_hit_limits_or_finish_in_time() {
    let over = pl_hostile::large("connections-over-limit").unwrap();
    let summary = guarded("connections-over-limit", &over, Duration::from_secs(60));
    assert!(summary.contains("limit_exceeded"), "{summary}");

    let tiny = pl_hostile::large("tiny-segments").unwrap();
    let summary = guarded("tiny-segments", &tiny, Duration::from_secs(60));
    assert!(
        summary.starts_with("ok") && summary.contains("longest_stream=100000"),
        "{summary}"
    );
}

/// Мутации настоящих записей: случайные порчи не должны ронять разбор.
#[test]
fn mutated_real_captures_never_panic() {
    let seeds: Vec<Vec<u8>> = [
        "normal.pcap",
        "mixed.pcapng",
        "gap-truncation.pcapng",
        "overlap-conflict.pcapng",
    ]
    .iter()
    .map(|n| {
        std::fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/synthetic")
                .join(n),
        )
        .unwrap()
    })
    .collect();
    let iterations: u64 = std::env::var("FUZZ_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1500);
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        // SplitMix64: воспроизводимо без внешних зависимостей.
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    for n in 0..iterations {
        let mut data = seeds[(next() % seeds.len() as u64) as usize].clone();
        for _ in 0..(1 + next() % 8) {
            let len = data.len().max(1) as u64;
            let at = (next() % len) as usize;
            match next() % 6 {
                0 => {
                    let i = at.min(data.len() - 1);
                    data[i] ^= 1 << (next() % 8);
                }
                1 => {
                    let i = at.min(data.len() - 1);
                    data[i] = (next() & 0xFF) as u8;
                }
                2 => data.truncate(at.max(1)),
                3 => {
                    let end = (at + 1 + (next() % 8) as usize).min(data.len());
                    for b in &mut data[at.min(end)..end] {
                        *b = 0xFF;
                    }
                }
                4 => {
                    let cut = (at + (next() % 64) as usize).min(data.len());
                    data.drain(at.min(cut)..cut);
                }
                _ => data
                    .splice(at..at, (0..(next() % 16)).map(|_| (next() & 0xFF) as u8))
                    .for_each(drop),
            }
            if data.is_empty() {
                data.push(0);
            }
        }
        let started = Instant::now();
        let result = catch_unwind(AssertUnwindSafe(|| analyse(&data)));
        assert!(
            result.is_ok(),
            "паника на мутации №{n} (длина {})",
            data.len()
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "мутация №{n} разбирается слишком долго"
        );
    }
}
