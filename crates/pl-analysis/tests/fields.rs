//! Подсказки полей на синтетических сообщениях одного вида.

use pl_analysis::{FieldHint, FieldHints, FieldKind, FieldSample, find_fields};

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

/// Часы записи: осень 2026 года, в миллисекундах от эпохи.
const CLOCK_MS: u64 = 1_790_000_000_000;

/// Сообщения двух потоков по `count` штук; `build(номер в потоке, время в мс, случайные байты)`.
fn messages(
    count: usize,
    seed: u64,
    build: impl Fn(usize, u64, &mut Lcg) -> Vec<u8>,
) -> Vec<(Vec<u8>, u32, u64)> {
    let mut rng = Lcg(seed);
    let mut out = Vec::new();
    for stream in 0..2u32 {
        let mut ms = 1_000 + u64::from(stream) * 500_000;
        for i in 0..count {
            ms += 40 + u64::from(rng.next());
            out.push((build(i, ms, &mut rng), stream, (CLOCK_MS + ms) * 1_000_000));
        }
    }
    out
}

fn find(messages: &[(Vec<u8>, u32, u64)]) -> FieldHints {
    let samples: Vec<FieldSample<'_>> = messages
        .iter()
        .map(|(data, stream, ts_ns)| FieldSample {
            data,
            stream: *stream,
            ts_ns: *ts_ns,
        })
        .collect();
    find_fields(&samples, &|| false)
}

fn of(found: &FieldHints, kind: FieldKind) -> Vec<&FieldHint> {
    found.hints.iter().filter(|h| h.kind == kind).collect()
}

#[test]
fn a_request_number_is_a_counter_and_narrower_readings_are_equivalent() {
    // `A5 | номер u16be | случайный байт | случайный байт`.
    let msgs = messages(30, 1, |i, _, rng| {
        let n = (i as u16 + 250).to_be_bytes();
        vec![0xa5, n[0], n[1], rng.next(), rng.next()]
    });
    let found = find(&msgs);
    let counters = of(&found, FieldKind::Counter);
    assert_eq!(counters.len(), 1, "{:?}", found.hints);
    let c = counters[0];
    assert_eq!((c.at, c.ty.as_str(), c.size), (1, "u16be", Some(2)));
    assert_eq!((c.matches, c.samples, c.share_permille), (58, 58, 1000));
    assert!(c.first_counterexample.is_none());
    // Младший байт сам растёт на единицу — то же поле, а не второй счётчик.
    assert!(c.equivalent.iter().any(|e| e.at == 2 && e.ty == "u8"));
}

#[test]
fn a_skipped_number_is_the_counterexample() {
    let msgs = messages(30, 2, |i, _, rng| {
        let n = if i >= 20 { i as u16 + 5 } else { i as u16 };
        let n = n.to_le_bytes();
        vec![n[0], n[1], rng.next(), rng.next()]
    });
    let found = find(&msgs);
    let c = of(&found, FieldKind::Counter)[0];
    assert_eq!((c.at, c.ty.as_str()), (0, "u16le"));
    assert_eq!((c.matches, c.samples), (56, 58));
    // Первый скачок — на двадцатом сообщении первого потока.
    assert_eq!(c.first_counterexample, Some(20));
}

#[test]
fn device_uptime_in_milliseconds_and_unix_seconds_are_times() {
    // Время устройства в мс от включения (не от эпохи) и время от эпохи в секундах.
    let uptime = messages(40, 3, |_, ms, rng| {
        let mut m = vec![0x10, rng.next()];
        m.extend_from_slice(&((ms + 7_000_000) as u32).to_be_bytes());
        m.push(rng.next());
        m
    });
    let found = find(&uptime);
    let t = of(&found, FieldKind::Time)[0];
    assert_eq!((t.at, t.ty.as_str(), t.unit), (2, "u32be", Some("ms")));
    assert_eq!(t.epoch, Some(false));
    assert_eq!(t.share_permille, 1000);

    // Запись сделана «сейчас» по её же часам: значение в секундах совпадает с ними.
    let start_s = 1_790_000_000u64;
    let mut rng = Lcg(4);
    let mut unix = Vec::new();
    for i in 0..40u64 {
        let s = start_s + i * 3 + u64::from(rng.next() % 2);
        let mut m = vec![rng.next()];
        m.extend_from_slice(&(s as u32).to_le_bytes());
        unix.push((m, 0u32, s * 1_000_000_000));
    }
    let found = find(&unix);
    let t = of(&found, FieldKind::Time)[0];
    assert_eq!((t.at, t.ty.as_str(), t.unit), (1, "u32le", Some("s")));
    assert_eq!(t.epoch, Some(true));
}

#[test]
fn a_constant_or_random_field_is_neither_a_counter_nor_a_time() {
    let msgs = messages(40, 5, |_, _, rng| {
        vec![
            0,
            0,
            0,
            7,
            rng.next(),
            rng.next(),
            rng.next(),
            rng.next(),
            rng.next(),
        ]
    });
    let found = find(&msgs);
    assert!(found.hints.is_empty(), "{:?}", found.hints);
}

#[test]
fn a_length_prefixed_string_is_found_with_an_example() {
    let names = ["Lab", "Котельная", "Line-2", "A", "Склад №4"];
    let msgs = messages(20, 6, |i, _, rng| {
        let name = names[i % names.len()].as_bytes();
        let mut m = vec![rng.next() | 0x80, 0x00, name.len() as u8];
        m.extend_from_slice(name);
        m
    });
    let found = find(&msgs);
    let strings = of(&found, FieldKind::String);
    assert_eq!(strings.len(), 1, "{:?}", found.hints);
    let s = strings[0];
    assert_eq!((s.at, s.ty.as_str()), (2, "u8"));
    assert_eq!(s.to_end, Some(true));
    assert_eq!(s.example.as_deref(), Some("Lab"));
    assert_eq!(s.share_permille, 1000);
    // Нулевой байт перед длиной делает её неотличимой от u16be со смещения 1.
    assert!(s.equivalent.iter().any(|e| e.at == 1 && e.ty == "u16be"));
    // Сам текст отдельной подсказкой «текст» не дублируется.
    assert!(of(&found, FieldKind::Text).is_empty());
}

#[test]
fn text_at_a_fixed_place_is_found() {
    let msgs = messages(20, 7, |i, _, rng| {
        let mut m = vec![rng.next() | 0x80];
        m.extend_from_slice(if i % 2 == 0 { b"TEMP" } else { b"PRES" });
        m.push(rng.next() | 0x80);
        m
    });
    let found = find(&msgs);
    let texts = of(&found, FieldKind::Text);
    assert_eq!(texts.len(), 1, "{:?}", found.hints);
    assert_eq!((texts[0].at, texts[0].size), (1, Some(4)));
    assert_eq!(texts[0].example.as_deref(), Some("TEMP"));
}

#[test]
fn tag_length_value_records_are_found_from_their_first_byte() {
    // `код | записи: метка, длина, значение…` до конца сообщения.
    let msgs = messages(20, 8, |i, _, rng| {
        let mut m = vec![0x2b];
        for tag in 0..(2 + i % 3) as u8 {
            let len = 1 + rng.next() % 5;
            m.push(tag);
            m.push(len);
            m.extend((0..len).map(|_| rng.next() | 0x80));
        }
        m
    });
    let found = find(&msgs);
    let tlv = of(&found, FieldKind::Tlv);
    assert_eq!(tlv.len(), 1, "{:?}", found.hints);
    assert_eq!((tlv[0].at, tlv[0].ty.as_str()), (1, "u8"));
    assert_eq!(tlv[0].tags, Some(4));
    assert_eq!(tlv[0].to_end, Some(true));
    assert_eq!(tlv[0].share_permille, 1000);
}

#[test]
fn a_single_length_prefixed_blob_is_not_tlv() {
    let msgs = messages(20, 9, |_, _, rng| {
        let len = 2 + rng.next() % 6;
        let mut m = vec![0x01, len];
        m.extend((0..len).map(|_| rng.next() | 0x80));
        m
    });
    assert!(of(&find(&msgs), FieldKind::Tlv).is_empty());
}

#[test]
fn hostile_and_tiny_inputs_are_harmless() {
    assert!(find(&[]).hints.is_empty());
    let tiny: Vec<(Vec<u8>, u32, u64)> = (0..30u64)
        .map(|i| (vec![0xffu8; (i % 3) as usize], 0u32, u64::MAX - i))
        .collect();
    let _ = find(&tiny);
    let full: Vec<(Vec<u8>, u32, u64)> = (0..30u64).map(|i| (vec![0xffu8; 80], 0u32, i)).collect();
    let _ = find(&full);

    let msgs = messages(30, 10, |i, _, _| vec![i as u8, 1, 2, 3]);
    let samples: Vec<FieldSample<'_>> = msgs
        .iter()
        .map(|(data, stream, ts_ns)| FieldSample {
            data,
            stream: *stream,
            ts_ns: *ts_ns,
        })
        .collect();
    let stopped = find_fields(&samples, &|| true);
    assert!(stopped.incomplete);
    assert!(stopped.hints.is_empty());
}
