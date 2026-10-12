//! Угадывание колонок на настоящих журналах и на злых файлах.

use std::path::PathBuf;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

#[test]
fn stand_journals_are_guessed_and_parse_fully() {
    for name in ["main.actions.csv", "extra.actions.csv"] {
        let bytes = std::fs::read(fixtures().join("stand").join(name)).unwrap();
        let g = pl_actions::guess_mapping(&bytes).unwrap();
        assert_eq!(g.mapping.time, "time", "{name}");
        assert_eq!(g.mapping.action, "action", "{name}");
        assert_eq!(g.mapping.params.as_deref(), Some("params"), "{name}");
        assert_eq!(g.skipped, 0, "{name}: {:?}", g.reasons);
        assert!(g.rows > 5, "{name}");
    }
}

#[test]
fn hostile_journals_never_panic() {
    let dir = fixtures().join("hostile").join("journals");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let bytes = std::fs::read(&path).unwrap();
        // Либо догадка, либо понятная ошибка — без паники и зависания.
        match pl_actions::guess_mapping(&bytes) {
            Ok(g) => assert!(!g.mapping.time.is_empty()),
            Err(e) => assert!(!e.to_string().is_empty()),
        }
        seen += 1;
    }
    assert!(seen >= 10, "злые журналы на месте");
}
