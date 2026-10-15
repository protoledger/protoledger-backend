//! Профиль для замеров: детерминирован и укладывается в заданные кадры и размер.

use pl_synth::{Format, profile};

#[test]
fn profile_is_deterministic_and_close_to_the_requested_size() {
    let a = profile(20, 400, 200_000, 7).encode(Format::Pcapng);
    let b = profile(20, 400, 200_000, 7).encode(Format::Pcapng);
    assert_eq!(a, b);
    assert_ne!(a, profile(20, 400, 200_000, 8).encode(Format::Pcapng));
    let capture = profile(20, 400, 200_000, 7);
    assert_eq!(capture.frames.len(), 400);
    let size = a.len() as f64;
    assert!((150_000.0..250_000.0).contains(&size), "{size}");
}

#[test]
fn degenerate_parameters_do_not_panic() {
    assert!(!profile(0, 0, 0, 1).frames.is_empty());
    assert!(profile(1, 10, 100, 1).frames.len() >= 6);
}

/// Сообщения каждого направления по порядку кадров: `[A5][тип][длина u16 BE][тело]`.
fn message_lengths(capture: &pl_synth::Capture) -> Vec<usize> {
    use etherparse::{PacketHeaders, TransportHeader};
    use std::collections::BTreeMap;
    let mut streams: BTreeMap<(Vec<u8>, u16), Vec<u8>> = BTreeMap::new();
    for f in &capture.frames {
        let p = PacketHeaders::from_ethernet_slice(&f.data).unwrap();
        let (Some(etherparse::NetHeaders::Ipv4(ip, _)), Some(TransportHeader::Tcp(tcp))) =
            (p.net, p.transport)
        else {
            continue;
        };
        streams
            .entry((ip.source.to_vec(), tcp.source_port))
            .or_default()
            .extend_from_slice(p.payload.slice());
    }
    let mut lengths = Vec::new();
    for bytes in streams.values() {
        let mut pos = 0;
        while pos < bytes.len() {
            assert_eq!(bytes[pos], 0xA5, "поток разбирается целиком");
            let len = 4 + usize::from(u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]));
            lengths.push(len);
            pos += len;
        }
        assert_eq!(pos, bytes.len());
    }
    lengths
}

#[test]
fn profile_has_responses_up_to_64_kib_split_into_frames() {
    // Соотношение кадров и размера — как в профиле ТЗ: около 420 байт на кадр.
    let capture = profile(20, 4_000, 1_700_000, 7);
    let frames = capture.frames.len();
    assert!((3_800..=4_200).contains(&frames), "{frames}");
    let lengths = message_lengths(&capture);
    let large = lengths.iter().filter(|&&l| l > 16 * 1024).count();
    assert!(large >= 3, "крупных ответов {large}");
    assert!(
        lengths
            .iter()
            .all(|&l| l <= pl_synth::scenario::PROFILE_MAX_MESSAGE)
    );
    let size = capture.encode(Format::Pcapng).len() as f64;
    assert!((1_450_000.0..1_950_000.0).contains(&size), "{size}");
}
