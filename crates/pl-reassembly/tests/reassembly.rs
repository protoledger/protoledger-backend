use std::path::PathBuf;

use pl_capture::{Limits, index};
use pl_reassembly::{
    ChecksumPolicy, Close, Connection, Flag, OverlapPolicy, PieceKind, Policy, Stream, reassemble,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const SCENARIOS: &[&str] = &[
    "normal",
    "reorder",
    "duplicates",
    "gap-truncation",
    "overlap-conflict",
    "no-handshake",
    "bad-checksum",
    "port-reuse",
    "background",
    "mixed",
];

fn fixture(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn build(name: &str, policy: Policy) -> (Vec<u8>, Vec<Connection>) {
    let file = fixture(&format!("{name}.pcapng"));
    let idx = index(&file, Limits::default(), &|| false, &mut |_| {}).unwrap();
    let conns = reassemble(&idx, &file, policy, &|| false).unwrap();
    (file, conns)
}

fn known_bytes(file: &[u8], s: &Stream) -> Vec<u8> {
    let mut out = Vec::new();
    for p in &s.pieces {
        let b = match &p.kind {
            PieceKind::Data(b) => b,
            PieceKind::Ambiguous { chosen, variants } => &variants[*chosen],
            PieceKind::Gap => continue,
        };
        let at = b.file_offset as usize;
        out.extend_from_slice(&file[at..at + (p.end - p.start) as usize]);
    }
    out
}

fn ranges(v: &Value) -> Vec<(u64, u64)> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|r| (r["offset"].as_u64().unwrap(), r["length"].as_u64().unwrap()))
        .collect()
}

/// Неоднозначные участки в виде эталона: соседние склеены, кадры — первые кадры вариантов.
fn ambiguous(s: &Stream) -> Vec<(u64, u64, Vec<u32>)> {
    let mut out: Vec<(u64, u64, Vec<u32>)> = Vec::new();
    for p in &s.pieces {
        let PieceKind::Ambiguous { variants, .. } = &p.kind else {
            continue;
        };
        let mut frames: Vec<u32> = variants.iter().map(|v| v.frames[0].frame).collect();
        frames.sort_unstable();
        match out.last_mut() {
            Some(last) if last.0 + last.1 == p.start && last.2 == frames => {
                last.1 += p.end - p.start
            }
            _ => out.push((p.start, p.end - p.start, frames)),
        }
    }
    out
}

fn check_stream(ctx: &str, file: &[u8], got: &Stream, exp: &Value) {
    assert_eq!(
        got.start_available,
        exp["startKnown"].as_bool().unwrap(),
        "{ctx} start"
    );
    assert_eq!(got.length, exp["length"].as_u64().unwrap(), "{ctx} length");
    let bytes = known_bytes(file, got);
    assert_eq!(
        bytes.len() as u64,
        exp["knownBytes"].as_u64().unwrap(),
        "{ctx} known"
    );
    let sha: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(sha, exp["sha256"].as_str().unwrap(), "{ctx} sha256");

    let gaps: Vec<(u64, u64)> = got
        .pieces
        .iter()
        .filter(|p| p.kind == PieceKind::Gap)
        .map(|p| (p.start, p.end - p.start))
        .collect();
    assert_eq!(gaps, ranges(&exp["gaps"]), "{ctx} gaps");

    let exp_amb: Vec<(u64, u64, Vec<u32>)> = exp["ambiguous"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            let frames = a["frames"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f.as_u64().unwrap() as u32);
            (
                a["offset"].as_u64().unwrap(),
                a["length"].as_u64().unwrap(),
                frames.collect(),
            )
        })
        .collect();
    assert_eq!(ambiguous(got), exp_amb, "{ctx} ambiguous");

    let dups: Vec<u32> = got
        .frames
        .iter()
        .filter(|f| f.duplicate)
        .map(|f| f.frame)
        .collect();
    let exp_dups: Vec<u32> = exp["duplicateFrames"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_u64().unwrap() as u32)
        .collect();
    assert_eq!(dups, exp_dups, "{ctx} duplicates");

    let mut pos = 0;
    for p in &got.pieces {
        assert_eq!(p.start, pos, "{ctx}: участки идут подряд");
        assert!(p.end > p.start, "{ctx}: пустой участок");
        pos = p.end;
    }
    assert_eq!(pos, got.length, "{ctx}: участки покрывают поток");
}

#[test]
fn synthetic_streams_match_generator() {
    for name in SCENARIOS {
        let (file, conns) = build(name, Policy::default());
        let exp: Value =
            serde_json::from_slice(&fixture(&format!("{name}.expected.json"))).unwrap();
        let exp_conns = exp["connections"].as_array().unwrap();
        assert_eq!(conns.len(), exp_conns.len(), "{name}: число соединений");
        for (c, e) in conns.iter().zip(exp_conns) {
            let ctx = format!("{name} c{:04}", c.number);
            assert_eq!(
                c.first_frame as u64,
                e["firstFrame"].as_u64().unwrap(),
                "{ctx}"
            );
            assert_eq!(c.roles_known, e["rolesKnown"].as_bool().unwrap(), "{ctx}");
            let (client, server) = (e["client"].as_str().unwrap(), e["server"].as_str().unwrap());
            let (a, b) = (c.a.to_string(), c.b.to_string());
            assert!(
                (a == client && b == server) || (!c.roles_known && a == server && b == client),
                "{ctx}: {a} {b}"
            );
            let (c2s, s2c) = if a == client { (0, 1) } else { (1, 0) };
            check_stream(
                &format!("{ctx} c2s"),
                &file,
                &c.streams[c2s],
                &e["clientToServer"],
            );
            check_stream(
                &format!("{ctx} s2c"),
                &file,
                &c.streams[s2c],
                &e["serverToClient"],
            );
        }
    }
}

#[test]
fn connection_flags_and_close() {
    let (_, c) = build("normal", Policy::default());
    assert_eq!(c[0].close, Close::Fin);
    assert!(c[0].flags.is_empty(), "{:?}", c[0].flags);

    let (_, c) = build("port-reuse", Policy::default());
    assert_eq!(
        c.iter().map(|c| c.close).collect::<Vec<_>>(),
        vec![Close::Fin, Close::Rst, Close::Fin]
    );
    assert!(!c[0].flags.contains(&Flag::ReusedPorts));
    assert!(c[1].flags.contains(&Flag::ReusedPorts) && c[2].flags.contains(&Flag::ReusedPorts));
    assert_eq!(c[0].id("3f5a1c0d99"), "3f5a1c0d:c0001");

    let flags = |n: &str| build(n, Policy::default()).1[0].flags.clone();
    assert!(flags("duplicates").contains(&Flag::Retransmissions));
    assert!(flags("gap-truncation").is_superset(&[Flag::Gaps, Flag::Truncated].into()));
    assert!(flags("overlap-conflict").contains(&Flag::Ambiguous));
    assert!(flags("no-handshake").contains(&Flag::NoSyn));
    assert!(flags("bad-checksum").contains(&Flag::BadChecksum));
}

#[test]
fn overlap_policy_last_picks_later_bytes() {
    let (file, first) = build("overlap-conflict", Policy::default());
    let last_policy = Policy {
        overlap: OverlapPolicy::Last,
        ..Policy::default()
    };
    let (_, last) = build("overlap-conflict", last_policy);
    let a = known_bytes(&file, &first[0].streams[0]);
    let b = known_bytes(&file, &last[0].streams[0]);
    assert_eq!(a.len(), b.len());
    assert_ne!(a, b);
    // [8, 20): последним пришёл конфликтующий кадр; [20, 24): ещё позже — повтор исходных байтов.
    assert!(a[8..20].iter().zip(&b[8..20]).all(|(x, y)| x != y));
    assert_eq!(a[20..24], b[20..24]);
}

#[test]
fn checksum_drop_removes_bad_segments() {
    let policy = Policy {
        checksum: ChecksumPolicy::Drop,
        ..Policy::default()
    };
    let (_, c) = build("bad-checksum", policy);
    // Offloading: все данные клиента с неверной суммой — при `drop` их нет.
    let client = &c[0].streams[0];
    assert_eq!(client.data_bytes(), 0);
    assert_eq!(client.gap_bytes(), client.length);
}

#[test]
fn pieces_in_range() {
    let (_, c) = build("gap-truncation", Policy::default());
    let s = &c[0].streams[1];
    let all = s.pieces_in(0, s.length);
    assert_eq!(all.len(), s.pieces.len());
    let gap = s.pieces.iter().find(|p| p.kind == PieceKind::Gap).unwrap();
    let hit = s.pieces_in(gap.start, gap.start + 1);
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].kind, PieceKind::Gap);
    assert!(s.pieces_in(s.length, s.length + 10).is_empty());
}

/// Свойство из архитектуры (§11): переупорядочивание и повторы сегментов с данными не меняют
/// собранный поток. Без внешних зависимостей — свой простой генератор перестановок.
#[test]
fn reorder_and_duplicates_do_not_change_stream() {
    let file = fixture("normal.pcapng");
    let idx = index(&file, Limits::default(), &|| false, &mut |_| {}).unwrap();
    let reference = reassemble(&idx, &file, Policy::default(), &|| false).unwrap();
    let expect: Vec<Vec<u8>> = reference[0]
        .streams
        .iter()
        .map(|s| known_bytes(&file, s))
        .collect();

    let data_pos: Vec<usize> = (0..idx.segments.len())
        .filter(|&i| idx.segments[i].payload_len > 0)
        .collect();
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut rnd = |n: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed % n as u64) as usize
    };
    for _ in 0..200 {
        let mut shuffled = idx.clone();
        let mut data: Vec<_> = data_pos.iter().map(|&i| idx.segments[i]).collect();
        for i in (1..data.len()).rev() {
            data.swap(i, rnd(i + 1));
        }
        for (slot, seg) in data_pos.iter().zip(data) {
            shuffled.segments[*slot] = seg;
        }
        for _ in 0..3 {
            let dup = shuffled.segments[data_pos[rnd(data_pos.len())]];
            let at = data_pos[0] + rnd(shuffled.segments.len() - data_pos[0]);
            shuffled.segments.insert(at, dup);
        }
        let conns = reassemble(&shuffled, &file, Policy::default(), &|| false).unwrap();
        assert_eq!(conns.len(), 1);
        for (s, want) in conns[0].streams.iter().zip(&expect) {
            assert_eq!(&known_bytes(&file, s), want);
            assert_eq!(s.gap_bytes() + s.ambiguous_bytes(), 0);
        }
    }
}
