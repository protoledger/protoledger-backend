use std::path::PathBuf;

use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use pcap_parser::pcapng::Block;
use pcap_parser::{LegacyPcapSlice, PcapBlockOwned, PcapNGSlice};
use pl_synth::{Format, SCENARIOS, generate};
use sha2::{Digest, Sha256};

const SEED: u64 = 1;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/synthetic")
}

struct Pkt {
    caplen: u32,
    origlen: u32,
    ts_us: u64,
    data: Vec<u8>,
}

fn read_pcapng(bytes: &[u8]) -> Vec<Pkt> {
    let mut out = Vec::new();
    for block in PcapNGSlice::from_slice(bytes).expect("заголовок pcapng") {
        if let PcapBlockOwned::NG(Block::EnhancedPacket(epb)) = block.expect("блок pcapng") {
            out.push(Pkt {
                caplen: epb.caplen,
                origlen: epb.origlen,
                ts_us: (u64::from(epb.ts_high) << 32) | u64::from(epb.ts_low),
                data: epb.data[..epb.caplen as usize].to_vec(),
            });
        }
    }
    out
}

fn read_pcap(bytes: &[u8]) -> Vec<Pkt> {
    let mut out = Vec::new();
    for block in LegacyPcapSlice::from_slice(bytes).expect("заголовок pcap") {
        if let PcapBlockOwned::Legacy(b) = block.expect("запись pcap") {
            out.push(Pkt {
                caplen: b.caplen,
                origlen: b.origlen,
                ts_us: u64::from(b.ts_sec) * 1_000_000 + u64::from(b.ts_usec),
                data: b.data.to_vec(),
            });
        }
    }
    out
}

#[test]
fn fixtures_are_up_to_date() {
    let hint = "перегенерируйте: cargo run -p pl-synth -- generate --out fixtures/synthetic \
                && cargo run -p pl-synth -- generate --out fixtures/synthetic --format pcap normal";
    for sc in SCENARIOS {
        let g = generate(sc, SEED);
        let dir = fixtures_dir();
        let capture = std::fs::read(dir.join(format!("{}.pcapng", sc.name))).expect(hint);
        assert!(
            capture == g.capture.to_pcapng(),
            "{}: pcapng устарел; {hint}",
            sc.name
        );
        let json = serde_json::to_string_pretty(&g.expected).unwrap() + "\n";
        let stored =
            std::fs::read_to_string(dir.join(format!("{}.expected.json", sc.name))).expect(hint);
        assert!(stored == json, "{}: эталон устарел; {hint}", sc.name);
    }
    let normal = generate(pl_synth::find("normal").unwrap(), SEED);
    let stored = std::fs::read(fixtures_dir().join("normal.pcap")).expect(hint);
    assert!(
        stored == normal.capture.encode(Format::Pcap),
        "normal.pcap устарел; {hint}"
    );
}

#[test]
fn generation_is_deterministic() {
    for sc in SCENARIOS {
        let a = generate(sc, 42).capture.to_pcapng();
        let b = generate(sc, 42).capture.to_pcapng();
        assert!(a == b, "{}", sc.name);
        assert!(
            a != generate(sc, 43).capture.to_pcapng(),
            "{}: seed не влияет",
            sc.name
        );
    }
}

#[test]
fn files_are_valid_for_independent_parser() {
    for sc in SCENARIOS {
        let g = generate(sc, SEED);
        let ng = read_pcapng(&g.capture.to_pcapng());
        let legacy = read_pcap(&g.capture.to_pcap());
        assert_eq!(ng.len() as u32, g.expected.frames, "{}", sc.name);
        assert_eq!(ng.len(), legacy.len(), "{}", sc.name);
        for (a, b) in ng.iter().zip(&legacy) {
            assert_eq!(
                (a.caplen, a.origlen, a.ts_us),
                (b.caplen, b.origlen, b.ts_us)
            );
            assert!(a.data == b.data);
            assert!(a.caplen <= g.expected.snaplen && a.caplen <= a.origlen);
        }
        assert!(
            ng.windows(2).all(|w| w[0].ts_us < w[1].ts_us),
            "{}: время не растёт",
            sc.name
        );
    }
}

#[test]
fn checksums_match_expected() {
    for sc in SCENARIOS {
        let g = generate(sc, SEED);
        let bad = &g.expected.bad_checksum_frames;
        for (i, p) in read_pcapng(&g.capture.to_pcapng()).iter().enumerate() {
            let frame = i as u32 + 1;
            if p.caplen < p.origlen {
                continue;
            }
            let h = PacketHeaders::from_ethernet_slice(&p.data).expect("разбор кадра");
            let Some(NetHeaders::Ipv4(ip, _)) = &h.net else {
                continue;
            };
            assert_eq!(
                ip.header_checksum,
                ip.calc_header_checksum(),
                "{} #{frame}",
                sc.name
            );
            if let Some(TransportHeader::Tcp(tcp)) = &h.transport {
                let ok = tcp.checksum == tcp.calc_checksum_ipv4(ip, h.payload.slice()).unwrap();
                assert_eq!(ok, !bad.contains(&frame), "{} #{frame}", sc.name);
            }
        }
    }
}

/// Простая сборка «отсортировать по seq и склеить» — годится только для записей без дыр,
/// повторов и перекрытий, зато не зависит от эталона генератора.
#[test]
fn clean_streams_match_independent_reassembly() {
    for name in ["normal", "reorder", "bad-checksum", "background"] {
        let g = generate(pl_synth::find(name).unwrap(), SEED);
        let conn = &g.expected.connections[0];
        let mut isn: [Option<u32>; 2] = [None, None];
        let mut segs: [Vec<(u32, Vec<u8>)>; 2] = [Vec::new(), Vec::new()];
        for p in read_pcapng(&g.capture.to_pcapng()) {
            let h = PacketHeaders::from_ethernet_slice(&p.data).unwrap();
            let (Some(NetHeaders::Ipv4(ip, _)), Some(TransportHeader::Tcp(tcp))) =
                (&h.net, &h.transport)
            else {
                continue;
            };
            if ip.is_fragmenting_payload() {
                continue;
            }
            let src = format!(
                "{}:{}",
                std::net::Ipv4Addr::from(ip.source),
                tcp.source_port
            );
            let d = usize::from(src != conn.client);
            if tcp.syn {
                isn[d] = Some(tcp.sequence_number);
            }
            segs[d].push((tcp.sequence_number, h.payload.slice().to_vec()));
        }
        let streams = [&conn.client_to_server, &conn.server_to_client];
        for d in 0..2 {
            let base = isn[d].unwrap().wrapping_add(1);
            let mut parts: Vec<_> = segs[d]
                .iter()
                .filter(|(_, p)| !p.is_empty())
                .map(|(seq, p)| (seq.wrapping_sub(base), p))
                .collect();
            parts.sort_by_key(|(off, _)| *off);
            let bytes: Vec<u8> = parts.iter().flat_map(|(_, p)| p.iter().copied()).collect();
            let sha: String = Sha256::digest(&bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(bytes.len() as u64, streams[d].length, "{name} dir {d}");
            assert_eq!(sha, streams[d].sha256, "{name} dir {d}");
        }
    }
}

#[test]
fn defects_are_present() {
    let g = |n| generate(pl_synth::find(n).unwrap(), SEED).expected;
    let reorder = g("reorder");
    assert!(
        reorder.connections[0].client_to_server.length > 20,
        "seq не перешёл через 2^32"
    );
    assert!(
        !g("duplicates").connections[0]
            .client_to_server
            .duplicate_frames
            .is_empty()
    );
    let gaps = g("gap-truncation");
    assert!(!gaps.connections[0].client_to_server.gaps.is_empty());
    assert!(!gaps.connections[0].server_to_client.gaps.is_empty());
    assert!(
        !g("overlap-conflict").connections[0]
            .client_to_server
            .ambiguous
            .is_empty()
    );
    let nh = g("no-handshake");
    assert!(!nh.connections[0].roles_known && !nh.connections[0].client_to_server.start_known);
    assert_eq!(
        g("bad-checksum").offloading_host.as_deref(),
        Some("10.0.0.10")
    );
    assert_eq!(g("port-reuse").connections.len(), 3);
    assert_eq!(g("background").skipped.len(), 5);
}
