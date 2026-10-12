//! Поиск контрольных сумм на синтетических сообщениях; функции-кандидаты заданы здесь же.

use pl_analysis::{ChecksumFn, MAX_CHECKSUM_MESSAGE_BYTES, find_checksums};

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

fn sum8(data: &[u8]) -> u64 {
    u64::from(data.iter().fold(0u8, |a, b| a.wrapping_add(*b)))
}

fn xor8(data: &[u8]) -> u64 {
    u64::from(data.iter().fold(0u8, |a, b| a ^ b))
}

fn sum16(data: &[u8]) -> u64 {
    data.iter().map(|b| u64::from(*b)).sum::<u64>() & 0xffff
}

/// CRC-16 с отражением, многочлен 0xA001, начальное значение 0xFFFF.
fn crc16(data: &[u8]) -> u64 {
    let mut c = 0xffffu16;
    for b in data {
        c ^= u16::from(*b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xa001
            } else {
                c >> 1
            };
        }
    }
    u64::from(c)
}

fn functions() -> Vec<ChecksumFn<'static>> {
    vec![
        ChecksumFn {
            name: "sum8",
            title: "сумма",
            width: 1,
            compute: &sum8,
        },
        ChecksumFn {
            name: "xor8",
            title: "XOR",
            width: 1,
            compute: &xor8,
        },
        ChecksumFn {
            name: "sum16",
            title: "сумма 16",
            width: 2,
            compute: &sum16,
        },
        ChecksumFn {
            name: "crc16",
            title: "CRC-16",
            width: 2,
            compute: &crc16,
        },
    ]
}

/// `count` сообщений со случайным телом разной длины, собранных функцией `build`.
fn messages(count: usize, seed: u64, build: impl Fn(&[u8]) -> Vec<u8>) -> Vec<Vec<u8>> {
    let mut rng = Lcg(seed);
    (0..count)
        .map(|i| {
            let len = 4 + (i * 5 + usize::from(rng.next())) % 30;
            let body: Vec<u8> = (0..len).map(|_| rng.next()).collect();
            build(&body)
        })
        .collect()
}

fn find(messages: &[Vec<u8>]) -> pl_analysis::ChecksumHints {
    let refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
    find_checksums(&refs, &functions(), &|| false)
}

#[test]
fn finds_a_trailing_crc_with_its_byte_order() {
    let msgs = messages(40, 1, |body| {
        let mut m = body.to_vec();
        m.extend_from_slice(&(crc16(body) as u16).to_le_bytes());
        m
    });
    let found = find(&msgs);
    assert_eq!(found.messages, 40);
    let top = found.hints.first().unwrap();
    assert_eq!(
        (top.algorithm.as_str(), top.at.as_str(), top.ty.as_str()),
        ("crc16", "end-2", "u16le")
    );
    assert_eq!((top.from, top.to.as_str()), (0, "message.len - 2"));
    assert_eq!(top.expr, "checksum == crc16(0, message.len - 2)");
    assert_eq!(
        (top.matches, top.samples, top.share_permille),
        (40, 40, 1000)
    );
    assert!(top.first_counterexample.is_none());
    assert_eq!(found.hints.len(), 1);
}

#[test]
fn finds_a_sum_that_skips_the_signature_and_precedes_a_terminator() {
    // `A5 5A | тело | сумма тела | 03`: сигнатура в сумму не входит, после суммы — завершающий байт.
    let msgs = messages(30, 2, |body| {
        let mut m = vec![0xa5, 0x5a];
        m.extend_from_slice(body);
        m.push(sum8(body) as u8);
        m.push(0x03);
        m
    });
    let found = find(&msgs);
    let top = found.hints.first().unwrap();
    assert_eq!(
        (top.algorithm.as_str(), top.at.as_str(), top.ty.as_str()),
        ("sum8", "end-2", "u8")
    );
    assert_eq!((top.from, top.to.as_str()), (2, "message.len - 2"));
    assert_eq!(top.share_permille, 1000);
}

#[test]
fn leading_zero_bytes_make_ranges_equivalent() {
    // Нулевой первый байт сумму не меняет: диапазоны с 0 и с 1 неразличимы, первым идёт полный.
    let msgs = messages(30, 3, |body| {
        let mut m = vec![0x00];
        m.extend_from_slice(body);
        m.push(xor8(body) as u8);
        m
    });
    let found = find(&msgs);
    let top = found.hints.first().unwrap();
    assert_eq!((top.algorithm.as_str(), top.from), ("xor8", 0));
    assert!(
        top.equivalent
            .iter()
            .any(|e| e.algorithm == "xor8" && e.from == 1)
    );
}

#[test]
fn finds_a_checksum_in_the_header() {
    // `номер | сумма u16be всего, что дальше | тело`.
    let msgs = messages(30, 4, |body| {
        let mut m = vec![0x07];
        m.extend_from_slice(&(sum16(body) as u16).to_be_bytes());
        m.extend_from_slice(body);
        m
    });
    let found = find(&msgs);
    let top = found.hints.first().unwrap();
    assert_eq!(
        (top.algorithm.as_str(), top.at.as_str(), top.ty.as_str()),
        ("sum16", "1", "u16be")
    );
    assert_eq!(top.expr, "checksum == sum16(3, message.len)");
    // Младший байт той же суммы сходится и как отдельная 8-битная — второй подсказкой он не идёт.
    assert_eq!(found.hints.len(), 1);
}

#[test]
fn a_corrupted_message_becomes_the_counterexample() {
    let mut msgs = messages(50, 5, |body| {
        let mut m = body.to_vec();
        m.extend_from_slice(&(crc16(body) as u16).to_be_bytes());
        m
    });
    msgs[17][1] ^= 0x40;
    let found = find(&msgs);
    let top = found.hints.first().unwrap();
    assert_eq!((top.matches, top.samples), (49, 50));
    assert_eq!(top.share_permille, 980);
    let counter = top.first_counterexample.as_ref().unwrap();
    assert_eq!(counter.index, 17);
    assert_ne!(counter.got, counter.expected);
}

#[test]
fn no_hints_without_a_checksum_or_without_variety() {
    // Случайные байты: ни одна функция не сходится.
    assert!(find(&messages(200, 6, <[u8]>::to_vec)).hints.is_empty());

    // Одно и то же сообщение сорок раз: совпадение есть, но подтверждать его нечем.
    let one = {
        let body = [1u8, 2, 3, 4, 5, 6];
        let mut m = body.to_vec();
        m.push(sum8(&body) as u8);
        m
    };
    assert!(find(&vec![one; 40]).hints.is_empty());

    // Слишком мало сообщений.
    let few = messages(5, 7, |body| {
        let mut m = body.to_vec();
        m.push(sum8(body) as u8);
        m
    });
    assert!(find(&few).hints.is_empty());
    assert!(find(&[]).hints.is_empty());
}

#[test]
fn limits_and_cancellation_are_reported() {
    let mut msgs = messages(20, 8, |body| {
        let mut m = body.to_vec();
        m.push(sum8(body) as u8);
        m
    });
    msgs.push(vec![0u8; MAX_CHECKSUM_MESSAGE_BYTES + 1]);
    let found = find(&msgs);
    assert_eq!((found.messages, found.skipped_long), (20, 1));
    assert_eq!(found.hints.first().unwrap().algorithm, "sum8");

    let refs: Vec<&[u8]> = msgs.iter().map(Vec::as_slice).collect();
    let stopped = find_checksums(&refs, &functions(), &|| true);
    assert!(stopped.incomplete);
    assert!(stopped.hints.is_empty());

    // Короче любого поля: ничего не падает.
    let tiny = vec![vec![], vec![1u8], vec![1u8, 2]];
    assert!(find(&tiny).hints.is_empty());
}
