use std::path::PathBuf;

use pl_capture::{CaptureError, Checksum, DiagCode, Format, Limits, index, payload_bytes};
use serde_json::Value;

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

fn expected(name: &str) -> Value {
    serde_json::from_slice(&fixture(&format!("{name}.expected.json"))).unwrap()
}

fn run(file: &[u8]) -> Result<pl_capture::CaptureIndex, CaptureError> {
    index(file, Limits::default(), &|| false, &mut |_| {})
}

fn frames_of(v: &Value) -> Vec<u32> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap() as u32)
        .collect()
}

#[test]
fn synthetic_frames_and_diagnostics_match_expected() {
    for name in SCENARIOS {
        let idx = run(&fixture(&format!("{name}.pcapng"))).unwrap();
        let exp = expected(name);
        assert_eq!(idx.format, Format::Pcapng);
        assert_eq!(
            idx.frames.len() as u64,
            exp["frames"].as_u64().unwrap(),
            "{name}"
        );

        let skipped: Vec<(u32, &str)> = exp["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| {
                (
                    s["frame"].as_u64().unwrap() as u32,
                    s["kind"].as_str().unwrap(),
                )
            })
            .collect();
        for (frame, kind) in &skipped {
            let code = match *kind {
                "arp" => DiagCode::NonIp,
                "udp" => DiagCode::NonTcp,
                "ipv6" => DiagCode::Ipv6Skipped,
                "ipv4-fragment" => DiagCode::IpFragment,
                other => panic!("неизвестный вид {other}"),
            };
            assert!(
                idx.diagnostics.frames(code).contains(frame),
                "{name} #{frame} {kind}"
            );
            assert!(
                idx.segments.iter().all(|s| s.frame != *frame),
                "{name} #{frame}"
            );
        }
        assert_eq!(idx.skipped(), skipped.len() as u64, "{name}");

        let bad = frames_of(&exp["badChecksumFrames"]);
        let got_bad: Vec<u32> = idx
            .segments
            .iter()
            .filter(|s| s.checksum == Checksum::Bad)
            .map(|s| s.frame)
            .collect();
        assert_eq!(got_bad, bad, "{name}");
        assert_eq!(
            idx.diagnostics.frames(DiagCode::BadChecksum),
            bad.as_slice(),
            "{name}"
        );
        let offload = frames_of(&exp["offloadFrames"]);
        let got_offload: Vec<u32> = idx
            .segments
            .iter()
            .filter(|s| s.checksum == Checksum::Offload)
            .map(|s| s.frame)
            .collect();
        assert_eq!(got_offload, offload, "{name}");
        assert_eq!(
            idx.diagnostics.frames(DiagCode::ChecksumOffload),
            offload.as_slice(),
            "{name}"
        );
        assert_eq!(idx.diagnostics.count(DiagCode::BadBlock), 0, "{name}");
    }
}

#[test]
fn truncated_payload_is_reported() {
    let file = fixture("gap-truncation.pcapng");
    let idx = run(&file).unwrap();
    let truncated: Vec<_> = idx
        .segments
        .iter()
        .filter(|s| s.captured_len < s.payload_len)
        .collect();
    assert_eq!(truncated.len(), 1);
    let s = truncated[0];
    assert_eq!(s.checksum, Checksum::Unknown);
    assert_eq!(idx.diagnostics.frames(DiagCode::TruncatedFrame), &[s.frame]);
    assert_eq!(
        payload_bytes(&file, s).unwrap().len(),
        s.captured_len as usize
    );
}

#[test]
fn pcap_and_pcapng_give_same_index() {
    let ng = run(&fixture("normal.pcapng")).unwrap();
    let legacy = run(&fixture("normal.pcap")).unwrap();
    assert_eq!(legacy.format, Format::Pcap);
    assert_eq!(ng.segments.len(), legacy.segments.len());
    for (a, b) in ng.segments.iter().zip(&legacy.segments) {
        assert_eq!(
            (a.src, a.dst, a.seq, a.ack, a.flags),
            (b.src, b.dst, b.seq, b.ack, b.flags)
        );
        assert_eq!((a.payload_len, a.checksum), (b.payload_len, b.checksum));
    }
    for (a, b) in ng.frames.iter().zip(&legacy.frames) {
        assert_eq!((a.ts_ns, a.captured_len), (b.ts_ns, b.captured_len));
    }
    // 2026-10-01T00:00:00Z плюс задержки генератора.
    assert!(ng.frames[0].ts_ns > 1_790_812_800_000_000_000);
}

#[test]
fn padding_is_not_payload() {
    let file = fixture("normal.pcapng");
    let idx = run(&file).unwrap();
    let syn = &idx.segments[0];
    assert!(syn.has(pl_capture::tcp_flags::SYN));
    assert_eq!(syn.payload_len, 0);
    assert_eq!(idx.frame(syn.frame).unwrap().captured_len, 60);
}

#[test]
fn not_a_capture() {
    assert_eq!(run(b"").unwrap_err(), CaptureError::NotCapture);
    assert_eq!(run(b"hello, world!").unwrap_err(), CaptureError::NotCapture);
    assert_eq!(
        run(&[0x0A, 0x0D, 0x0D, 0x0A, 1, 2]).unwrap_err(),
        CaptureError::NotCapture
    );
}

#[test]
fn file_size_limit() {
    let file = fixture("normal.pcapng");
    let limits = Limits {
        max_file_bytes: 100,
        ..Limits::default()
    };
    let err = index(&file, limits, &|| false, &mut |_| {}).unwrap_err();
    assert!(matches!(err, CaptureError::LimitExceeded { .. }));
}

#[test]
fn frame_limit() {
    let file = fixture("normal.pcapng");
    let limits = Limits {
        max_frames: 3,
        ..Limits::default()
    };
    let err = index(&file, limits, &|| false, &mut |_| {}).unwrap_err();
    assert!(matches!(
        err,
        CaptureError::LimitExceeded {
            value: 4,
            max: 3,
            ..
        }
    ));
}

#[test]
fn every_prefix_of_a_file_is_handled() {
    for name in ["mixed.pcapng", "normal.pcap"] {
        let file = fixture(name);
        let full = run(&file).unwrap().frames.len();
        let mut damaged = 0;
        for cut in 0..file.len() {
            match run(&file[..cut]) {
                Ok(idx) => {
                    assert!(idx.frames.len() <= full);
                    damaged += usize::from(idx.diagnostics.count(DiagCode::BadBlock) > 0);
                }
                Err(e) => assert_eq!(e, CaptureError::NotCapture, "{name} cut {cut}"),
            }
        }
        // Обрезка посреди блока — почти все срезы; по границе блока файл просто короче.
        assert!(damaged > file.len() / 2, "{name}: {damaged}");
    }
}

#[test]
fn corrupted_bytes_never_panic() {
    let file = fixture("mixed.pcapng");
    let mut seed = 0x1234_5678_9abc_def0u64;
    for _ in 0..3000 {
        let mut f = file.clone();
        for _ in 0..4 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let pos = (seed % f.len() as u64) as usize;
            f[pos] = (seed >> 32) as u8;
        }
        let _ = run(&f);
    }
}

#[test]
fn cancellation_stops_import() {
    let file = fixture("mixed.pcapng");
    let limits = Limits::default();
    // Отмена проверяется раз в 4096 кадров — на маленьком файле импорт успевает.
    assert!(index(&file, limits, &|| true, &mut |_| {}).is_ok());
    let mut last = 0;
    index(&file, limits, &|| false, &mut |p| last = p).unwrap();
    assert_eq!(last, file.len() as u64);
}

/// Та же запись под другим канальным уровнем: заголовок Ethernet каждого кадра заменён на `head`,
/// тип протокола пишется в него по смещению `protocol_at`. Без места для типа (raw IP, loopback)
/// кадры не IPv4 в запись не попадают.
fn relink(pcap: &[u8], linktype: u32, head: &[u8], protocol_at: Option<usize>) -> Vec<u8> {
    let mut out = pcap[..20].to_vec();
    out.extend_from_slice(&linktype.to_le_bytes());
    let mut at = 24;
    while at + 16 <= pcap.len() {
        let field = |i: usize| u32::from_le_bytes(pcap[at + i..at + i + 4].try_into().unwrap());
        let (captured, original) = (field(8) as usize, field(12) as usize);
        let record = at;
        let frame = &pcap[at + 16..at + 16 + captured];
        at += 16 + captured;
        let mut data = head.to_vec();
        match protocol_at {
            Some(i) => data[i..i + 2].copy_from_slice(&frame[12..14]),
            None if frame[12..14] != [0x08, 0x00] => continue,
            None => {}
        }
        data.extend_from_slice(&frame[14..]);
        out.extend_from_slice(&pcap[record..record + 8]);
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&((original + data.len() - captured) as u32).to_le_bytes());
        out.extend_from_slice(&data);
    }
    out
}

#[test]
fn other_link_layers_give_the_same_segments() {
    let ethernet = fixture("normal.pcap");
    let base = run(&ethernet).unwrap();
    assert!(base.segments.len() > 10);
    let sll = [0u8, 0, 0, 1, 0, 6, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0];
    let mut sll2 = [0u8; 20];
    sll2[9] = 1;
    let variants = [
        ("Linux cooked", relink(&ethernet, 113, &sll, Some(14))),
        ("Linux cooked v2", relink(&ethernet, 276, &sll2, Some(0))),
        ("raw IP", relink(&ethernet, 101, &[], None)),
        ("loopback", relink(&ethernet, 0, &[2, 0, 0, 0], None)),
    ];
    for (name, file) in &variants {
        let idx = run(file).unwrap();
        assert_eq!(idx.segments.len(), base.segments.len(), "{name}");
        for (a, b) in idx.segments.iter().zip(&base.segments) {
            assert_eq!(
                (
                    a.src,
                    a.dst,
                    a.seq,
                    a.ack,
                    a.flags,
                    a.payload_len,
                    a.checksum
                ),
                (
                    b.src,
                    b.dst,
                    b.seq,
                    b.ack,
                    b.flags,
                    b.payload_len,
                    b.checksum
                ),
                "{name}"
            );
            assert_eq!(
                payload_bytes(file, a),
                payload_bytes(&ethernet, b),
                "{name}: данные сегмента"
            );
        }
        assert!(
            idx.diagnostics
                .groups
                .keys()
                .all(|c| *c != DiagCode::UnsupportedLinkType),
            "{name}"
        );
    }
}
