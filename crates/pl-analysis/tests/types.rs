//! Поиск типов сообщений на синтетических обменах: данные строятся здесь же.

use pl_analysis::{TypeHints, TypeKey, TypeOptions, TypeSample, find_types};

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

fn find(messages: &[(Vec<u8>, u8)], options: &TypeOptions) -> TypeHints {
    let samples: Vec<TypeSample<'_>> = messages
        .iter()
        .map(|(data, side)| TypeSample {
            data,
            side: *side,
            stream: u32::from(*side),
        })
        .collect();
    find_types(&samples, options, &|| false)
}

fn keys(found: &TypeHints) -> Vec<TypeKey> {
    found.keys.iter().map(|k| k.key).collect()
}

/// Обмен вида «номер u16 | код | данные»: запрос — код и адрес (старший байт нулевой), ответ — код,
/// число байт и данные. Байт после кода в ответах точно предсказывает длину, но типом не является.
fn exchange(count: usize, seed: u64) -> Vec<(Vec<u8>, u8)> {
    let mut rng = Lcg(seed);
    let mut out = Vec::new();
    for i in 0..count {
        let number = (i as u16).to_be_bytes();
        let code = [0x03u8, 0x04, 0x10][i % 3];
        let mut request = vec![number[0], number[1], code, 0x00, rng.next()];
        if code == 0x10 {
            request.extend_from_slice(&[rng.next(), rng.next(), rng.next()]);
        }
        out.push((request, 0));
        let size = 2 * (1 + usize::from(rng.next() % 6));
        let mut response = vec![number[0], number[1], code, size as u8];
        response.extend((0..size).map(|_| rng.next()));
        out.push((response, 1));
    }
    out
}

#[test]
fn the_command_code_wins_over_a_byte_that_only_predicts_response_length() {
    let found = find(&exchange(60, 1), &TypeOptions::default());
    assert_eq!(
        keys(&found),
        vec![TypeKey::Side, TypeKey::Byte { at: 2 }],
        "{:?}",
        found.keys
    );
    assert_eq!(found.types.len(), 6);
    assert_eq!(found.rare, 0);
    // У запросов каждого кода своя длина; у ответов она меняется.
    let request = found
        .types
        .iter()
        .find(|t| t.key[0].value == 0 && t.key[1].value == 0x10)
        .unwrap();
    assert_eq!(
        (request.min_len, request.max_len, request.count),
        (8, 8, 20)
    );
    let response = found
        .types
        .iter()
        .find(|t| t.key[0].value == 1 && t.key[1].value == 0x03)
        .unwrap();
    assert!(response.lengths > 1);
    let hint = &found.keys[1];
    assert_eq!(hint.values, 3);
    assert!(hint.score_permille >= 200, "{hint:?}");
}

#[test]
fn a_byte_that_repeats_the_side_replaces_it() {
    // Тот же обмен, но перед кодом стоит байт направления: 0 — запрос, 1 — ответ.
    let messages: Vec<(Vec<u8>, u8)> = exchange(60, 2)
        .into_iter()
        .map(|(mut m, side)| {
            m.insert(2, side);
            (m, side)
        })
        .collect();
    let found = find(&messages, &TypeOptions::default());
    assert_eq!(
        keys(&found),
        vec![TypeKey::Byte { at: 2 }, TypeKey::Byte { at: 3 }]
    );
}

#[test]
fn when_the_side_cannot_be_written_down_only_bytes_are_offered() {
    let options = TypeOptions {
        without_side: true,
        ..TypeOptions::default()
    };
    // Код находится так же, но запрос и ответ с одним кодом остаются одним типом.
    let found = find(&exchange(60, 3), &options);
    assert_eq!(keys(&found), vec![TypeKey::Byte { at: 2 }]);
    assert_eq!(found.types.len(), 3);

    // Байт направления стороны не требует: он есть в самих сообщениях.
    let messages: Vec<(Vec<u8>, u8)> = exchange(60, 3)
        .into_iter()
        .map(|(mut m, side)| {
            m.insert(2, side);
            (m, side)
        })
        .collect();
    let found = find(&messages, &options);
    assert_eq!(
        keys(&found),
        vec![TypeKey::Byte { at: 2 }, TypeKey::Byte { at: 3 }]
    );
}

#[test]
fn length_bytes_and_counters_are_not_types() {
    // «счётчик | длина | случайное тело»: длина объясняет размер полностью, но это не тип.
    let mut rng = Lcg(4);
    let messages: Vec<(Vec<u8>, u8)> = (0..80)
        .map(|i| {
            let size = 3 + usize::from(rng.next() % 5);
            let mut m = vec![i as u8, (size + 2) as u8];
            m.extend((0..size).map(|_| rng.next()));
            (m, 0)
        })
        .collect();
    let found = find(&messages, &TypeOptions::default());
    assert!(found.keys.is_empty(), "{:?}", found.keys);
    assert!(found.types.is_empty());

    // То же поле длины, названное явно: исключается и без проверки на «похоже на длину».
    let excluded = TypeOptions {
        exclude: vec![1],
        ..TypeOptions::default()
    };
    assert!(find(&messages, &excluded).keys.is_empty());
}

#[test]
fn rare_groups_are_listed_but_counted_separately() {
    let mut messages = exchange(60, 5);
    // Один запрос с кодом, которого больше нет.
    messages.push((vec![0xff, 0xff, 0x2b, 1, 2], 0));
    let found = find(&messages, &TypeOptions::default());
    assert_eq!(found.rare, 1);
    let rare = found.types.iter().find(|t| t.key[1].value == 0x2b).unwrap();
    assert_eq!(rare.count, 1);
    assert!(rare.constant.is_empty());
    assert_eq!(found.types.last().unwrap().count, 1);
}

#[test]
fn a_message_of_unusual_length_is_pointed_out() {
    let mut messages = exchange(90, 6);
    // Запрос с кодом 0x03 обычно пять байт; этот — шесть.
    messages.push((vec![0, 200, 0x03, 9, 9, 9], 0));
    let found = find(&messages, &TypeOptions::default());
    let request = found
        .types
        .iter()
        .find(|t| t.key[0].value == 0 && t.key[1].value == 0x03)
        .unwrap();
    assert_eq!(request.length_outlier, Some(messages.len() as u64 - 1));
    assert_eq!((request.min_len, request.max_len), (5, 6));
}

#[test]
fn too_few_messages_and_cancellation() {
    let few = exchange(4, 7);
    assert!(find(&few, &TypeOptions::default()).keys.is_empty());
    assert!(find(&[], &TypeOptions::default()).types.is_empty());

    let messages = exchange(60, 8);
    let samples: Vec<TypeSample<'_>> = messages
        .iter()
        .map(|(data, side)| TypeSample {
            data,
            side: *side,
            stream: u32::from(*side),
        })
        .collect();
    let stopped = find_types(&samples, &TypeOptions::default(), &|| true);
    assert!(stopped.incomplete);
    assert!(stopped.types.is_empty());

    // Пустые и однобайтовые сообщения не ломают поиск.
    let tiny: Vec<(Vec<u8>, u8)> = (0..20)
        .map(|i| (vec![i as u8; i % 2], (i % 2) as u8))
        .collect();
    let _ = find(&tiny, &TypeOptions::default());
}

#[test]
fn a_request_number_that_follows_the_script_is_not_a_type() {
    // Запись по сценарию: запрос номер k всегда одной и той же команды, поэтому младший байт
    // номера «объясняет» длины не хуже кода. Но он растёт на единицу — это счётчик.
    let mut rng = Lcg(9);
    let mut messages = Vec::new();
    for session in 0..6u32 {
        for k in 0..12u8 {
            let code = [0x10u8, 0x20, 0x30][usize::from(k % 3)];
            let mut request = vec![0xa6, k, code];
            request.extend((0..usize::from(k % 3) * 2).map(|_| rng.next()));
            messages.push((request, 0u8, session * 2));
        }
        for k in 0..12u8 {
            let code = [0x10u8, 0x20, 0x30][usize::from(k % 3)];
            let mut response = vec![0xa6, k, code, 0x00];
            response.extend((0..usize::from(k % 3) * 3).map(|_| rng.next()));
            messages.push((response, 1u8, session * 2 + 1));
        }
    }
    let samples: Vec<TypeSample<'_>> = messages
        .iter()
        .map(|(data, side, stream)| TypeSample {
            data,
            side: *side,
            stream: *stream,
        })
        .collect();
    let found = find_types(&samples, &TypeOptions::default(), &|| false);
    assert_eq!(keys(&found), vec![TypeKey::Side, TypeKey::Byte { at: 2 }]);
}
