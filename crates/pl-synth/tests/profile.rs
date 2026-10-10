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
