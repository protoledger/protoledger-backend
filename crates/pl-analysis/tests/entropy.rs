//! Энтропия участков: случайные данные, текст, заполнение и обычная структура.

use pl_analysis::{ENTROPY_WINDOW, EntropyKind, entropy_map, entropy_millibits};

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u8 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) as u8
    }
}

#[test]
fn entropy_of_known_distributions() {
    assert_eq!(entropy_millibits(&[]), 0);
    assert_eq!(entropy_millibits(&[7u8; 100]), 0);
    // Два значения поровну — ровно один бит; все 256 значений по разу — восемь.
    assert_eq!(entropy_millibits(&[0, 1, 0, 1, 0, 1, 0, 1]), 1000);
    let all: Vec<u8> = (0..=255).collect();
    assert_eq!(entropy_millibits(&all), 8000);
}

#[test]
fn random_text_padding_and_structure_are_told_apart() {
    let mut rng = Lcg(1);
    let random: Vec<u8> = (0..ENTROPY_WINDOW * 4).map(|_| rng.next()).collect();
    let text: Vec<u8> = b"temperature=21.5;mode=auto;label=Line-2
"
    .iter()
    .copied()
    .cycle()
    .take(ENTROPY_WINDOW * 2)
    .collect();
    let padding = vec![0u8; ENTROPY_WINDOW * 2];
    // Обычные двоичные сообщения: счётчик, постоянные байты, немного меняющихся.
    let structured: Vec<u8> = (0..ENTROPY_WINDOW * 2)
        .map(|i| match i % 8 {
            0 => 0xa5,
            1 => (i / 8) as u8,
            2 | 3 => 0x00,
            4 => 0x80 | (rng.next() & 0x0f),
            _ => 0xff,
        })
        .collect();
    let mut data = Vec::new();
    for part in [&structured, &random, &text, &padding] {
        data.extend_from_slice(part);
    }
    let map = entropy_map(&[(1000, &data)]);
    let kinds: Vec<(u64, u64, EntropyKind)> = map
        .regions
        .iter()
        .map(|r| (r.start, r.end, r.kind))
        .collect();
    let w = ENTROPY_WINDOW as u64;
    assert_eq!(
        kinds,
        vec![
            (1000 + 2 * w, 1000 + 6 * w, EntropyKind::High),
            (1000 + 6 * w, 1000 + 8 * w, EntropyKind::Text),
            (1000 + 8 * w, 1000 + 10 * w, EntropyKind::Low),
        ]
    );
    assert!(map.regions[0].entropy_millibits >= 7000);
    assert_eq!(
        (map.bytes, map.high_bytes, map.text_bytes, map.low_bytes),
        (10 * w, 4 * w, 2 * w, 2 * w)
    );
    assert!(!map.truncated);
}

#[test]
fn windows_do_not_cross_gaps_and_short_data_is_not_judged() {
    let mut rng = Lcg(2);
    let random: Vec<u8> = (0..ENTROPY_WINDOW + 100).map(|_| rng.next()).collect();
    // Два куска по 178 байт: вместе больше окна, но между ними дыра.
    let (left, right) = random.split_at(random.len() / 2);
    let map = entropy_map(&[(0, left), (5000, right)]);
    assert_eq!(map.bytes, 0);
    assert!(map.regions.is_empty());
    // Тот же объём одним куском: одно полное окно, хвост не оценивается.
    let map = entropy_map(&[(0, &random)]);
    assert_eq!(map.bytes, ENTROPY_WINDOW as u64);
    assert_eq!(map.regions.len(), 1);
    assert!(entropy_map(&[]).regions.is_empty());
}
