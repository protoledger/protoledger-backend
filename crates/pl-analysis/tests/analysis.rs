//! Подсказки на синтетических потоках: данные строятся здесь же, о конкретных протоколах библиотека не знает.

use pl_analysis::{
    Certainty, DataRun, Msg, StreamSample, VariabilityOptions, find_framing, pair_exchanges,
    variability,
};

/// Детерминированный «случайный» источник для тестов.
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

fn payload(rng: &mut Lcg, n: usize) -> Vec<u8> {
    (0..n).map(|_| rng.next()).collect()
}

/// Поток из сообщений `build(payload)`; сегменты совпадают с сообщениями.
fn stream(id: &str, count: usize, seed: u64, build: impl Fn(&[u8]) -> Vec<u8>) -> StreamSample {
    let mut rng = Lcg(seed);
    let mut data = Vec::new();
    let mut starts = Vec::new();
    for i in 0..count {
        let len = 3 + (i * 7 + usize::from(rng.next())) % 40;
        starts.push(data.len());
        data.extend(build(&payload(&mut rng, len)));
    }
    StreamSample {
        id: id.to_owned(),
        runs: vec![DataRun {
            data,
            segment_starts: starts,
            starts_at_boundary: true,
        }],
    }
}

fn never() -> bool {
    false
}

/// Сигнатура `A5 5A`, затем u16 длины (big-endian) всего сообщения, затем тело.
fn framed_be(body: &[u8]) -> Vec<u8> {
    let total = 4 + body.len();
    let mut m = vec![0xA5, 0x5A, (total >> 8) as u8, total as u8];
    m.extend_from_slice(body);
    m
}

#[test]
fn finds_a_big_endian_length_field_and_reports_the_equivalent_low_byte() {
    let streams = [
        stream("s:ab", 40, 1, framed_be),
        stream("s:ba", 25, 2, framed_be),
    ];
    let hints = find_framing(&streams, &never);
    let top = hints.length.first().expect("кандидат найден");
    assert_eq!(
        (top.at, top.width, top.big_endian, top.adjust),
        (2, 2, true, 0)
    );
    assert_eq!(top.score_permille, 1000);
    assert_eq!((top.streams_confirmed, top.streams_total), (2, 2));
    assert_eq!(top.streams_ended_exactly, 2);
    assert_eq!(top.messages, 65);
    assert!(top.first_counterexample.is_none());
    // Младший байт того же числа даёт те же границы и не считается отдельным открытием.
    assert!(top.equivalent.iter().any(|f| f.at == 3 && f.ty == "u8"));
    let json = serde_json::to_value(&top.framing).unwrap();
    assert_eq!(json["kind"], "length_prefixed");
    assert_eq!(json["length"]["type"], "u16be");
    assert_eq!(json["status"], "hypothesis");
}

#[test]
fn finds_a_little_endian_field_that_excludes_the_header() {
    // u32le со второго байта: длина тела без пяти байтов заголовка.
    let build = |body: &[u8]| {
        let mut m = vec![0x01];
        m.extend_from_slice(&(body.len() as u32).to_le_bytes());
        m.extend_from_slice(body);
        m
    };
    let hints = find_framing(&[stream("x", 50, 3, build)], &never);
    let top = hints.length.first().unwrap();
    assert_eq!((top.at, top.width, top.big_endian), (1, 4, false));
    assert_eq!(top.adjust, 5);
    assert_eq!(top.score_permille, 1000);
    assert_eq!(
        hints.signatures.first().map(|s| s.bytes.as_str()),
        Some("01")
    );
}

#[test]
fn a_corrupted_length_gives_a_counterexample_and_lower_share() {
    let mut s = stream("bad", 40, 4, framed_be);
    // Портим длину 26-го сообщения: после неё разбор сбивается.
    let start = s.runs[0].segment_starts[25];
    s.runs[0].data[start + 3] = s.runs[0].data[start + 3].wrapping_add(9);
    let hints = find_framing(&[s], &never);
    let top = hints.length.first().expect("кандидат с оговоркой");
    assert!(top.at == 2 || top.at == 3, "{top:?}");
    let c = top.first_counterexample.as_ref().expect("есть контрпример");
    assert_eq!(c.stream, "bad");
    assert_eq!(c.run, 0);
    assert!(
        c.offset >= start as u64,
        "контрпример после порчи или на ней"
    );
    assert!(top.start_coherence_permille < 1000);
}

#[test]
fn fixed_size_messages_are_a_fixed_hint_not_a_length_field() {
    let build = |body: &[u8]| {
        let mut m = body.to_vec();
        m.resize(16, 0x7f);
        m.truncate(16);
        m
    };
    let hints = find_framing(&[stream("f", 30, 5, build)], &never);
    assert_eq!(hints.fixed.first().map(|f| f.size), Some(16));
    assert!(hints.length.is_empty(), "{:?}", hints.length);
}

#[test]
fn delimiters_are_found_at_message_ends_only() {
    let build = |body: &[u8]| {
        let mut m: Vec<u8> = body.iter().map(|b| b'a' + (b % 26)).collect();
        m.extend_from_slice(b"\r\n");
        m
    };
    let hints = find_framing(&[stream("t", 30, 6, build)], &never);
    let d = hints.delimiters.first().unwrap();
    assert_eq!(d.bytes, "0d0a");
    assert_eq!(d.at_ends, 30);
    assert_eq!(d.inside, 0);
    assert_eq!(
        serde_json::to_value(&d.framing).unwrap()["kind"],
        "delimiter"
    );
}

#[test]
fn random_bytes_produce_no_confident_hints() {
    let mut rng = Lcg(99);
    let data = payload(&mut rng, 6000);
    let s = StreamSample {
        id: "noise".to_owned(),
        runs: vec![DataRun {
            data,
            segment_starts: (0..6000).step_by(500).collect(),
            starts_at_boundary: false,
        }],
    };
    let hints = find_framing(&[s], &never);
    assert!(hints.length.is_empty(), "{:?}", hints.length.first());
    assert!(hints.signatures.is_empty());
    assert!(hints.delimiters.is_empty());
}

#[test]
fn a_capture_cut_inside_the_last_message_is_still_confirmed() {
    let mut s = stream("cut", 20, 7, framed_be);
    let new_len = s.runs[0].data.len() - 5;
    s.runs[0].data.truncate(new_len);
    let top = find_framing(&[s], &never).length.remove(0);
    assert_eq!((top.at, top.width), (2, 2));
    assert_eq!(top.score_permille, 1000);
    assert_eq!(
        top.streams_ended_exactly, 0,
        "обрыв не выдаётся за точный конец"
    );
}

#[test]
fn hostile_input_is_harmless_and_cancellation_stops_the_search() {
    let empty = find_framing(&[], &never);
    assert!(empty.length.is_empty() && empty.sampled_bytes == 0);
    let tiny = StreamSample {
        id: "t".to_owned(),
        runs: vec![DataRun {
            data: vec![0xff; 3],
            segment_starts: vec![0, 99, 7],
            starts_at_boundary: false,
        }],
    };
    assert!(find_framing(&[tiny], &never).length.is_empty());
    // Длины, заявленные как «почти 4 ГиБ», не приводят к выделению памяти и не принимаются.
    let huge = StreamSample {
        id: "h".to_owned(),
        runs: vec![DataRun {
            data: [0xffu8; 4096].to_vec(),
            segment_starts: vec![],
            starts_at_boundary: false,
        }],
    };
    assert!(find_framing(&[huge], &never).length.is_empty());
    let cancelled = find_framing(&[stream("c", 30, 8, framed_be)], &|| true);
    assert!(cancelled.length.is_empty());
}

#[test]
fn input_beyond_the_limits_is_cut_and_reported() {
    let big = StreamSample {
        id: "big".to_owned(),
        runs: vec![DataRun {
            data: vec![0u8; pl_analysis::MAX_STREAM_BYTES + 10],
            segment_starts: vec![],
            starts_at_boundary: false,
        }],
    };
    let hints = find_framing(&[big], &never);
    assert!(hints.truncated);
    assert_eq!(hints.sampled_bytes, pl_analysis::MAX_STREAM_BYTES as u64);
}

#[test]
fn variability_separates_constant_varying_and_counter_bytes() {
    // [тип=0x10][счётчик u16be][случайный байт][константы 0xEE 0xEE]
    let mut rng = Lcg(11);
    let messages: Vec<Vec<u8>> = (0..40u16)
        .map(|i| {
            let mut m = vec![0x10, (i >> 8) as u8, i as u8, rng.next()];
            m.extend_from_slice(&[0xEE, 0xEE]);
            m
        })
        .collect();
    let refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
    let v = variability(&refs, &VariabilityOptions::default());
    assert_eq!((v.messages, v.length, v.analysed), (40, 6, 40));
    assert_eq!(v.columns[0].constant, Some(0x10));
    assert_eq!(v.columns[0].entropy_millibits, 0);
    assert!(v.columns[2].distinct > 5);
    assert!(v.columns[3].entropy_millibits > 3000);
    assert_eq!(v.columns[5].constant, Some(0xEE));
    let kinds: Vec<_> = v
        .regions
        .iter()
        .map(|r| (r.start, r.end, serde_json::to_value(r.kind).unwrap()))
        .collect();
    assert_eq!(
        kinds,
        vec![
            (0, 2, "constant".into()),
            (2, 4, "varying".into()),
            (4, 6, "constant".into()),
        ]
        .into_iter()
        .map(|(a, b, k): (u32, u32, serde_json::Value)| (a, b, k))
        .collect::<Vec<_>>()
    );
    assert_eq!(v.regions[2].bytes.as_deref(), Some("eeee"));
    assert!(
        v.counters
            .iter()
            .any(|c| c.at == 1 && c.width == 2 && c.big_endian)
    );
}

#[test]
fn variability_groups_by_length_and_honours_the_requested_one() {
    let a = [1u8, 2, 3];
    let b = [9u8, 9];
    let refs: Vec<&[u8]> = vec![&a, &a, &b];
    let v = variability(&refs, &VariabilityOptions::default());
    assert_eq!(v.length, 3);
    assert_eq!(v.classes.len(), 2);
    let two = variability(&refs, &VariabilityOptions { length: Some(2) });
    assert_eq!((two.length, two.analysed), (2, 1));
    let none = variability(&[], &VariabilityOptions::default());
    assert_eq!((none.messages, none.columns.len()), (0, 0));
}

fn msg(id: usize, from_initiator: bool, ts: u64) -> Msg {
    Msg {
        id,
        from_initiator,
        first_ts_ns: ts,
        last_ts_ns: ts + 1,
    }
}

#[test]
fn exchanges_are_paired_by_alternation_and_ambiguity_is_marked() {
    let msgs = [
        msg(0, true, 100),
        msg(1, false, 200),
        // конвейер: два запроса подряд и два ответа подряд
        msg(2, true, 300),
        msg(3, true, 310),
        msg(4, false, 400),
        msg(5, false, 410),
        // два запроса и один ответ
        msg(6, true, 500),
        msg(7, true, 510),
        msg(8, false, 600),
        // последний запрос без ответа
        msg(9, true, 700),
    ];
    let (ex, stats) = pair_exchanges(&msgs);
    assert_eq!(ex[0].certainty, Certainty::Certain);
    assert_eq!(
        (ex[0].requests.clone(), ex[0].responses.clone()),
        (vec![0], vec![1])
    );
    assert_eq!(ex[0].delay_ns, Some(99));
    assert_eq!(ex[1].certainty, Certainty::Ordered);
    assert_eq!(
        (ex[1].requests.clone(), ex[1].responses.clone()),
        (vec![2], vec![4])
    );
    assert_eq!(
        (ex[2].requests.clone(), ex[2].responses.clone()),
        (vec![3], vec![5])
    );
    assert_eq!(ex[3].certainty, Certainty::Ambiguous);
    assert_eq!(ex[3].requests, vec![6, 7]);
    assert_eq!(ex[4].certainty, Certainty::Unanswered);
    assert_eq!(
        (
            stats.certain,
            stats.ordered,
            stats.ambiguous,
            stats.unanswered
        ),
        (1, 2, 1, 1)
    );
    assert_eq!(stats.min_delay_ns, Some(99));
}

#[test]
fn a_response_without_a_request_is_unsolicited_and_input_order_does_not_matter() {
    let shuffled = [
        msg(2, true, 300),
        msg(0, false, 100),
        msg(1, true, 200),
        msg(3, false, 400),
    ];
    let (ex, stats) = pair_exchanges(&shuffled);
    assert_eq!(ex[0].certainty, Certainty::Unsolicited);
    assert_eq!(ex[0].responses, vec![0]);
    // 1 (запрос) и 2 (запрос) идут подряд, ответ один — неоднозначно.
    assert_eq!(ex[1].certainty, Certainty::Ambiguous);
    assert_eq!(stats.unsolicited, 1);
    let (none, s) = pair_exchanges(&[]);
    assert!(none.is_empty() && s.exchanges == 0);
}

#[test]
fn signature_is_found_even_when_a_segment_holds_several_messages() {
    // Сегменты режут поток посреди сообщений: начала сегментов не совпадают с началами сообщений.
    let mut s = stream("pipe", 60, 12, framed_be);
    let all = s.runs[0].segment_starts.clone();
    s.runs[0].segment_starts = all.into_iter().step_by(3).map(|p| p + 5).collect();
    let hints = find_framing(&[s], &never);
    let sig = hints
        .signatures
        .iter()
        .find(|h| h.bytes.starts_with("a55a"))
        .expect("сигнатура a55a");
    assert_eq!(sig.basis, "length_candidate");
    assert_eq!(sig.at_starts, sig.starts_total);
}
