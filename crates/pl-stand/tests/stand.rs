use std::net::TcpListener;
use std::path::PathBuf;
use std::thread;

use pl_capture::{Limits, index};
use pl_reassembly::{ChecksumPolicy, OverlapPolicy, PieceKind, Policy, Stream, reassemble};
use pl_stand::log::to_csv;
use pl_stand::proto::{Decoder, Message, kind};
use pl_stand::record::record;
use pl_stand::scenario::{self, Scenario};
use pl_synth::capture::Format;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/stand")
}

fn known_bytes(file: &[u8], s: &Stream) -> Vec<u8> {
    let mut out = Vec::new();
    for p in &s.pieces {
        let b = match &p.kind {
            PieceKind::Data(b) => b,
            _ => panic!("в записи стенда не должно быть дыр и неоднозначностей"),
        };
        let at = b.file_offset as usize;
        out.extend_from_slice(&file[at..at + (p.end - p.start) as usize]);
    }
    out
}

fn decode_all(bytes: &[u8]) -> Vec<Message> {
    Decoder::default()
        .push(bytes)
        .expect("поток стенда разбирается")
}

fn total_messages(s: &Scenario) -> usize {
    s.steps.iter().map(|step| step.acts.len()).sum()
}

#[test]
fn real_tcp_session_gives_same_results_as_recording() {
    for s in scenario::all() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || pl_stand::device::serve(listener));

        let real = pl_stand::client::run(addr, &s, true).unwrap();
        let recorded = record(&s).log;
        let key = |l: &Vec<pl_stand::log::LogEntry>| {
            l.iter()
                .map(|e| (e.action, e.params.clone(), e.result.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(key(&real), key(&recorded), "{}", s.name);
    }
}

#[test]
fn recording_reassembles_into_whole_messages() {
    for s in scenario::all() {
        let rec = record(&s);
        let file = rec.capture.encode(Format::Pcapng);
        let idx = index(&file, Limits::default(), &|| false, &mut |_| {}).unwrap();
        let policy = Policy {
            overlap: OverlapPolicy::First,
            checksum: ChecksumPolicy::Warn,
        };
        let conns = reassemble(&idx, &file, policy, &|| false).unwrap();
        assert_eq!(conns.len(), 1, "{}: одно соединение с устройством", s.name);
        let c = &conns[0];
        assert!(c.roles_known, "{}: виден SYN", s.name);

        let requests = decode_all(&known_bytes(&file, &c.streams[0]));
        let replies = decode_all(&known_bytes(&file, &c.streams[1]));
        assert_eq!(requests.len(), total_messages(&s), "{}", s.name);
        assert_eq!(replies.len(), total_messages(&s), "{}", s.name);
        assert!(requests.iter().all(|m| m.kind < 0x80));
        assert!(replies.iter().all(|m| m.kind >= 0x80));

        // Записи есть не только обмен с устройством: ARP и UDP пропускаются с диагностикой.
        assert!(
            idx.frames.len() > c.frame_count as usize,
            "{}: нет фона",
            s.name
        );
    }
}

#[test]
fn messages_share_segments_and_span_segments() {
    let s = scenario::main_scenario();
    let rec = record(&s);
    let file = rec.capture.encode(Format::Pcapng);
    let idx = index(&file, Limits::default(), &|| false, &mut |_| {}).unwrap();
    let from_device: Vec<_> = idx
        .segments
        .iter()
        .filter(|seg| seg.src.port() == 4710 && seg.payload_len > 0)
        .collect();
    // Канал 3 — ответ около 60 КиБ: он занимает десятки сегментов.
    assert!(from_device.len() > 40, "{}", from_device.len());
    // Пачка запросов уходит одним сегментом: сегментов клиента меньше, чем запросов.
    let from_client = idx
        .segments
        .iter()
        .filter(|seg| seg.dst.port() == 4710 && seg.payload_len > 0)
        .count();
    assert!(from_client < total_messages(&s));
}

#[test]
fn scenarios_cover_the_demo() {
    let main = record(&scenario::main_scenario()).log;
    for v in ["value=21", "value=37", "value=1000"] {
        assert!(
            main.iter().any(|e| e.params.contains(v)),
            "в основной записи нет {v}"
        );
    }
    assert!(main.iter().any(|e| e.result.contains("out_of_range")));
    assert!(main.iter().any(|e| e.result.starts_with("samples=30000")));

    let extra = record(&scenario::extra_scenario()).log;
    assert!(extra.iter().any(|e| e.params.contains("value=70000")));
    assert!(extra.iter().any(|e| e.params.contains("value=-5")));
    assert!(main.iter().all(|e| e.action != "unknown"));
}

#[test]
fn large_replies_are_one_message() {
    let rec = record(&scenario::main_scenario());
    let file = rec.capture.encode(Format::Pcapng);
    let idx = index(&file, Limits::default(), &|| false, &mut |_| {}).unwrap();
    let conns = reassemble(
        &idx,
        &file,
        Policy {
            overlap: OverlapPolicy::First,
            checksum: ChecksumPolicy::Warn,
        },
        &|| false,
    )
    .unwrap();
    let replies = decode_all(&known_bytes(&file, &conns[0].streams[1]));
    let biggest = replies.iter().map(|m| m.body.len()).max().unwrap();
    assert!(biggest > 59_000 && biggest <= 65_535);
    assert!(replies.iter().any(|m| m.kind == kind::SET_RESP));
}

#[test]
fn committed_fixtures_are_up_to_date() {
    for s in scenario::all() {
        let rec = record(&s);
        let dir = fixtures_dir();
        let pcap = std::fs::read(dir.join(format!("{}.pcapng", s.name))).unwrap_or_else(|e| {
            panic!(
                "{}.pcapng: {e} (cargo run -p pl-stand -- record --out fixtures/stand)",
                s.name
            )
        });
        assert!(
            pcap == rec.capture.encode(Format::Pcapng),
            "{}.pcapng устарел: cargo run -p pl-stand -- record --out fixtures/stand",
            s.name
        );
        let csv = std::fs::read_to_string(dir.join(format!("{}.actions.csv", s.name))).unwrap();
        assert!(csv == to_csv(&rec.log), "{}.actions.csv устарел", s.name);
    }
}

#[test]
fn recording_is_deterministic() {
    let a = record(&scenario::main_scenario());
    let b = record(&scenario::main_scenario());
    assert!(a.capture.encode(Format::Pcapng) == b.capture.encode(Format::Pcapng));
    assert_eq!(to_csv(&a.log), to_csv(&b.log));
}
