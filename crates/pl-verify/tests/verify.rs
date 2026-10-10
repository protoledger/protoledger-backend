use pl_interp::schema::Direction;
use pl_interp::{Category, Interpretation, Region, RegionKind, StreamInput, StreamMeta};
use pl_verify::{
    ChangeKind, Current, RunInputs, StaleReason, StreamTarget, VerifyError, diff, digest_of,
    execute, stale_reasons,
};

/// `a5 | тип | всего | данные | сумма`.
fn spec(sum_rule: bool) -> Interpretation {
    let check = if sum_rule {
        "  - { id: C1, kind: structural, expr: \"sum == sum8(0, message.len - 1)\" }\n"
    } else {
        ""
    };
    Interpretation::parse(&format!(
        "format: protoledger/interpretation@1\n\
         framing: {{ kind: length_prefixed, length: {{ at: 2, type: u8 }} }}\n\
         messages:\n\
         \x20 - id: echo\n\
         \x20   when: \"type == 1\"\n\
         \x20   fields:\n\
         \x20     - {{ name: type, at: 1, type: u8, status: rule }}\n\
         \x20     - {{ name: sum, at: end-1, type: u8, status: rule }}\n\
         checks:\n{check}"
    ))
    .unwrap()
}

fn msg(kind: u8, payload: &[u8], good_sum: bool) -> Vec<u8> {
    let mut m = vec![0xa5, kind, (payload.len() + 4) as u8];
    m.extend_from_slice(payload);
    let sum = m.iter().fold(0u8, |a, b| a.wrapping_add(*b));
    m.push(if good_sum { sum } else { sum.wrapping_add(1) });
    m
}

fn input(bytes: &[u8]) -> StreamInput<'_> {
    StreamInput {
        meta: StreamMeta {
            direction: Direction::AToB,
            src_ip: "10.0.0.1".into(),
            dst_ip: "10.0.0.2".into(),
            src_port: 1000,
            dst_port: 2000,
        },
        length: bytes.len() as u64,
        regions: vec![Region {
            start: 0,
            end: bytes.len() as u64,
            kind: RegionKind::Data(bytes),
        }],
    }
}

fn target<'a>(id: &str, bytes: &'a [u8]) -> StreamTarget<'a> {
    StreamTarget {
        id: id.to_owned(),
        source: "a".repeat(64),
        input: input(bytes),
    }
}

fn inputs(it: &Interpretation) -> RunInputs {
    RunInputs {
        revision: Some(1),
        interpretation_digest: it.digest(),
        settings_digest: digest_of(&"settings"),
        sources: vec!["a".repeat(64)],
        corpus: pl_verify::CorpusFilter::default(),
        engine_version: "test".into(),
    }
}

fn run(it: &Interpretation, targets: &[StreamTarget<'_>]) -> pl_verify::Run {
    execute(it, targets, inputs(it), &|| false, &mut |_, _| {}).unwrap()
}

#[test]
fn summary_covers_the_whole_corpus_and_keeps_counterexamples() {
    let good = [msg(1, b"ab", true), msg(1, b"c", true), msg(7, b"zz", true)].concat();
    let bad = [msg(1, b"ab", true), msg(1, b"q", false)].concat();
    let it = spec(true);
    let r = run(
        &it,
        &[target("s:c0001:ab", &good), target("s:c0002:ab", &bad)],
    );

    assert_eq!(r.summary.streams, 2);
    assert_eq!(r.summary.messages, 5);
    assert_eq!(r.summary.counts.get(&Category::Matched), Some(&3));
    assert_eq!(
        r.summary.counts.get(&Category::Unmatched),
        Some(&1),
        "неописанный тип виден в сводке"
    );
    assert_eq!(r.summary.counts.get(&Category::Violated), Some(&1));
    assert_eq!(r.summary.by_message["echo"][&Category::Violated], 1);
    assert_eq!(r.summary.by_message["?"][&Category::Unmatched], 1);

    assert_eq!(r.counterexamples.len(), 1);
    let cx = &r.counterexamples[0];
    assert_eq!(
        (cx.anchor.stream.as_str(), cx.anchor.start, cx.anchor.end),
        ("s:c0002:ab", 6, 11)
    );
    assert_eq!(cx.anchor.sha256.as_ref().map(String::len), Some(64));
    assert_eq!(cx.violations[0].id, "C1");
    assert_eq!(r.streams[0].messages.len(), 3);
    assert!(!r.summary.counterexamples_truncated);
}

#[test]
fn counterexamples_are_capped_but_counted() {
    let bytes: Vec<u8> = (0..1100).flat_map(|_| msg(1, b"x", false)).collect();
    let r = run(&spec(true), &[target("s:c0001:ab", &bytes)]);
    assert_eq!(r.summary.counterexamples, 1100);
    assert_eq!(r.counterexamples.len(), pl_verify::MAX_COUNTEREXAMPLES);
    assert!(r.summary.counterexamples_truncated);
}

#[test]
fn runs_are_deterministic_and_roundtrip_through_json() {
    let bytes = [msg(1, b"a", true), msg(1, b"b", false)].concat();
    let it = spec(true);
    let a = run(&it, &[target("s:c0001:ab", &bytes)]);
    let b = run(&it, &[target("s:c0001:ab", &bytes)]);
    assert_eq!(a, b);
    let json = serde_json::to_string(&a).unwrap();
    assert_eq!(serde_json::from_str::<pl_verify::Run>(&json).unwrap(), a);
    assert!(json.contains("\"outOfScope\""), "поля в camelCase");
}

#[test]
fn out_of_scope_streams_are_counted_not_hidden() {
    let bytes = msg(1, b"a", true);
    let mut t = target("s:c0001:ab", &bytes);
    t.input.meta.direction = Direction::BToA;
    let scoped = Interpretation::parse(
        "format: protoledger/interpretation@1\nscope: { direction: a_to_b }\nframing: { kind: fixed, size: 5 }\n",
    )
    .unwrap();
    let r = run(&scoped, &[t]);
    assert_eq!(r.summary.out_of_scope_streams, 1);
    assert_eq!(r.summary.messages, 0);
    assert!(r.streams[0].out_of_scope);
}

#[test]
fn cancellation_and_progress() {
    let bytes = msg(1, b"a", true);
    let it = spec(false);
    let targets = [
        target("a", &bytes),
        target("b", &bytes),
        target("c", &bytes),
    ];
    let mut seen = Vec::new();
    execute(&it, &targets, inputs(&it), &|| false, &mut |done, total| {
        seen.push((done, total))
    })
    .unwrap();
    assert_eq!(seen.first(), Some(&(0, 3)));
    assert_eq!(seen.last(), Some(&(3, 3)));
    let err = execute(&it, &targets, inputs(&it), &|| true, &mut |_, _| {}).unwrap_err();
    assert_eq!(err, VerifyError::Cancelled);
}

#[test]
fn staleness_follows_the_signature() {
    let it = spec(true);
    let bytes = msg(1, b"a", true);
    let r = run(&it, &[target("s:c0001:ab", &bytes)]);
    let fresh = Current {
        interpretation_digest: Some(it.digest()),
        settings_digest: digest_of(&"settings"),
        sources: vec!["a".repeat(64), "b".repeat(64)],
    };
    assert!(stale_reasons(&r, &fresh).is_empty());

    let changed = Current {
        interpretation_digest: Some(spec(false).digest()),
        ..fresh.clone()
    };
    assert_eq!(stale_reasons(&r, &changed), [StaleReason::Interpretation]);
    let none = Current {
        interpretation_digest: None,
        ..fresh.clone()
    };
    assert_eq!(stale_reasons(&r, &none), [StaleReason::Interpretation]);
    let settings = Current {
        settings_digest: digest_of(&"other"),
        ..fresh.clone()
    };
    assert_eq!(stale_reasons(&r, &settings), [StaleReason::Settings]);
    let gone = Current {
        sources: vec![],
        ..fresh
    };
    assert_eq!(stale_reasons(&r, &gone), [StaleReason::Sources]);
}

#[test]
fn diff_tells_fixed_from_regressed_and_new() {
    // Первый прогон: правило проверки суммы строже, плохая сумма нарушает; второй: правило снято.
    let bytes = [msg(1, b"a", true), msg(1, b"b", false)].concat();
    let strict = spec(true);
    let lax = spec(false);
    let mut a = run(&strict, &[target("s:c0001:ab", &bytes)]);
    let mut b = run(&lax, &[target("s:c0001:ab", &bytes)]);
    a.id = "run-0001".into();
    b.id = "run-0002".into();

    let d = diff(&a, &b);
    assert_eq!((d.a.as_str(), d.b.as_str()), ("run-0001", "run-0002"));
    assert_eq!(d.totals.fixed, 1);
    assert_eq!(d.totals.unchanged, 1);
    assert_eq!(d.changes.len(), 1);
    assert_eq!(
        (d.changes[0].kind, d.changes[0].from, d.changes[0].to),
        (
            ChangeKind::Fixed,
            Some(Category::Violated),
            Some(Category::Matched)
        )
    );
    assert_eq!(d.counts_a[&Category::Violated], 1);

    let back = diff(&b, &a);
    assert_eq!(back.totals.regressed, 1);

    // Другой набор потоков: добавленные и исчезнувшие сообщения.
    let other = run(&lax, &[target("s:c0002:ab", &bytes)]);
    let moved = diff(&a, &other);
    assert_eq!((moved.totals.added, moved.totals.removed), (2, 2));
}
