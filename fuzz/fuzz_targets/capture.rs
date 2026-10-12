//! Чтение записи (pcap, pcapng) и сборка TCP-потоков при всех политиках.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pl_capture::{Limits, index};
use pl_reassembly::{ChecksumPolicy, OverlapPolicy, Policy, reassemble};

fuzz_target!(|data: &[u8]| {
    let Ok(idx) = index(data, Limits::default(), &|| false, &mut |_| {}) else {
        return;
    };
    for overlap in [OverlapPolicy::First, OverlapPolicy::Last, OverlapPolicy::Flag] {
        for checksum in [ChecksumPolicy::Ignore, ChecksumPolicy::Warn, ChecksumPolicy::Drop] {
            let policy = Policy { overlap, checksum };
            let Ok(connections) = reassemble(&idx, data, policy, &|| false) else {
                continue;
            };
            for c in &connections {
                for s in &c.streams {
                    // Инварианты карты: участки идут подряд и покрывают поток целиком.
                    let mut at = 0u64;
                    for p in s.pieces_in(0, s.length) {
                        assert_eq!(p.start, at);
                        assert!(p.end > p.start);
                        at = p.end;
                    }
                    assert_eq!(at, s.length);
                    assert_eq!(
                        s.data_bytes() + s.gap_bytes() + s.ambiguous_bytes(),
                        s.length
                    );
                }
            }
        }
    }
});
