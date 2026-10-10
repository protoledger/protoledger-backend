//! Сверка собранных потоков с `tshark -z follow,tcp,raw` (ТЗ 7.3, план тестирования).
//!
//! Тест пропускается, если tshark не установлен; в CI он обязателен (`PL_REQUIRE_TSHARK=1`).
//! Сравниваются записи без дефектов, где результат однозначен: порядок по seq, повторы,
//! неверные суммы (tshark их не проверяет), длинные ответы на десятки сегментов.

use std::path::{Path, PathBuf};
use std::process::Command;

use pl_capture::{Limits, index};
use pl_reassembly::{PieceKind, Policy, Stream, reassemble};

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn tshark_available() -> bool {
    Command::new("tshark")
        .arg("-v")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn tshark(args: &[&str]) -> String {
    let out = Command::new("tshark")
        .args(args)
        .output()
        .expect("tshark запускается");
    assert!(
        out.status.success(),
        "tshark {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Направления одного потока tshark: `(узел 0, узел 1, байты 0→1, байты 1→0)`.
struct Followed {
    nodes: [String; 2],
    data: [Vec<u8>; 2],
}

fn parse_follow(text: &str) -> Followed {
    let mut nodes = [String::new(), String::new()];
    let mut data = [Vec::new(), Vec::new()];
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Node 0: ") {
            nodes[0] = rest.trim().to_owned();
        } else if let Some(rest) = line.strip_prefix("Node 1: ") {
            nodes[1] = rest.trim().to_owned();
        } else if line.starts_with("===")
            || line.starts_with("Follow:")
            || line.starts_with("Filter:")
        {
            continue;
        } else {
            let (side, hex) = match line.strip_prefix('\t') {
                Some(h) => (1, h),
                None => (0, line),
            };
            let hex = hex.trim();
            if hex.is_empty() {
                continue;
            }
            assert!(
                hex.len() % 2 == 0 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
                "не hex: {hex:.40}"
            );
            for pair in hex.as_bytes().chunks(2) {
                let byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
                data[side].push(byte);
            }
        }
    }
    Followed { nodes, data }
}

fn known_bytes(file: &[u8], s: &Stream) -> Vec<u8> {
    let mut out = Vec::new();
    for p in &s.pieces {
        let b = match &p.kind {
            PieceKind::Data(b) => b,
            other => panic!("в сверяемой записи не должно быть дыр и неоднозначностей: {other:?}"),
        };
        let at = b.file_offset as usize;
        out.extend_from_slice(&file[at..at + (p.end - p.start) as usize]);
    }
    out
}

fn compare(path: &Path) {
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    let file = std::fs::read(path).unwrap();
    let idx = index(&file, Limits::default(), &|| false, &mut |_| {}).unwrap();
    let conns = reassemble(&idx, &file, Policy::default(), &|| false).unwrap();

    let file_arg = path.to_str().unwrap();
    let streams: Vec<String> = tshark(&["-r", file_arg, "-T", "fields", "-e", "tcp.stream"])
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_owned)
        .collect();
    let count = streams
        .iter()
        .filter_map(|s| s.trim().parse::<usize>().ok())
        .max()
        .map_or(0, |m| m + 1);
    assert_eq!(count, conns.len(), "{name}: число соединений");

    for (n, conn) in conns.iter().enumerate() {
        let filter = format!("follow,tcp,raw,{n}");
        let followed = parse_follow(&tshark(&[
            "-r",
            file_arg,
            "-o",
            "tcp.reassemble_out_of_order:TRUE",
            "-q",
            "-z",
            &filter,
        ]));
        for (side, node) in followed.nodes.iter().enumerate() {
            // Направление tshark сопоставляем со своим по адресу отправителя.
            let ours = if node == &conn.a.to_string() {
                &conn.streams[0]
            } else {
                &conn.streams[1]
            };
            assert!(
                node == &conn.a.to_string() || node == &conn.b.to_string(),
                "{name} соединение {n}: узел {node} не найден"
            );
            let mine = known_bytes(&file, ours);
            let theirs = &followed.data[side];
            assert!(
                mine == *theirs,
                "{name} соединение {n}, направление от {node}: свои {} байт, tshark {} байт",
                mine.len(),
                theirs.len()
            );
        }
    }
}

#[test]
fn streams_match_tshark_follow() {
    if !tshark_available() {
        assert!(
            std::env::var_os("PL_REQUIRE_TSHARK").is_none(),
            "tshark обязателен (PL_REQUIRE_TSHARK), но не найден"
        );
        eprintln!("tshark не найден: сверка пропущена");
        return;
    }
    for rel in [
        "fixtures/synthetic/normal.pcapng",
        "fixtures/synthetic/normal.pcap",
        "fixtures/synthetic/reorder.pcapng",
        "fixtures/synthetic/duplicates.pcapng",
        "fixtures/synthetic/bad-checksum.pcapng",
        "fixtures/stand/main.pcapng",
        "fixtures/stand/extra.pcapng",
    ] {
        compare(&repo(rel));
    }
}
