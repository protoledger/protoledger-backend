//! Угадывание сопоставления колонок журнала по заголовкам и содержимому.
//!
//! Догадка — предложение, а не решение: для каждой колонки возвращается причина, а сама
//! догадка проверяется пробным разбором файла. Пользователь принимает или правит.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::{LogError, MAX_FILE_BYTES, Mapping, PairsFormat, TimeFormat, csv_rows, parse};

/// Сколько строк смотрим, чтобы судить о колонке.
const SAMPLE_ROWS: usize = 200;
const DELIMITERS: [char; 3] = [',', ';', '\t'];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Guess {
    pub mapping: Mapping,
    /// Колонки файла в исходном порядке.
    pub columns: Vec<String>,
    /// Почему выбрана каждая роль: `time`, `action`, `params`, `result`, `source`, `delimiter`.
    pub reasons: BTreeMap<String, String>,
    /// Пробный разбор с этой догадкой.
    pub rows: u64,
    pub skipped: u64,
}

struct Column<'a> {
    name: &'a str,
    lower: String,
    values: Vec<&'a str>,
}

impl Column<'_> {
    fn named(&self, words: &[&str]) -> bool {
        words.iter().any(|w| self.lower.contains(w))
    }

    fn share(&self, ok: impl Fn(&str) -> bool) -> f64 {
        let filled: Vec<&&str> = self
            .values
            .iter()
            .filter(|v| !v.trim().is_empty())
            .collect();
        if filled.is_empty() {
            return 0.0;
        }
        filled.iter().filter(|v| ok(v.trim())).count() as f64 / filled.len() as f64
    }

    fn distinct(&self) -> usize {
        self.values
            .iter()
            .map(|v| v.trim())
            .collect::<BTreeSet<_>>()
            .len()
    }
}

fn is_rfc3339(v: &str) -> bool {
    crate::parse_rfc3339_ns(v).is_some()
}

fn epoch_format(v: &str) -> Option<TimeFormat> {
    let digits = v.split('.').next().unwrap_or(v);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // Метки 2001–2286 годов: число цифр однозначно задаёт единицу.
    match digits.len() {
        10 => Some(TimeFormat::UnixSeconds),
        13 => Some(TimeFormat::UnixMillis),
        16 => Some(TimeFormat::UnixMicros),
        19 => Some(TimeFormat::UnixNanos),
        _ => None,
    }
}

fn is_json_object(v: &str) -> bool {
    matches!(
        serde_json::from_str::<serde_json::Value>(v),
        Ok(serde_json::Value::Object(_))
    )
}

fn is_kv(v: &str) -> bool {
    v.split(';').all(|p| {
        p.split_once('=')
            .is_some_and(|(k, _)| !k.trim().is_empty() && !k.contains(' '))
    })
}

fn looks_like_capture(v: &str) -> bool {
    let l = v.to_ascii_lowercase();
    [".pcap", ".pcapng", ".cap", ".ntar"]
        .iter()
        .any(|ext| l.ends_with(ext))
}

fn percent(x: f64) -> String {
    format!("{:.0} %", x * 100.0)
}

/// Разделитель, при котором у заголовка больше всего колонок и строки с ним согласны.
fn delimiter(text: &str) -> char {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let header = lines.next().unwrap_or("");
    let sample: Vec<&str> = lines.take(20).collect();
    DELIMITERS
        .iter()
        .copied()
        .max_by_key(|d| {
            let cols = header.split(*d).count();
            let agree = sample
                .iter()
                .filter(|l| l.split(*d).count() >= cols)
                .count();
            (cols > 1, agree, cols)
        })
        .unwrap_or(',')
}

/// Предложить сопоставление колонок для файла журнала.
pub fn guess_mapping(bytes: &[u8]) -> Result<Guess, LogError> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(LogError::TooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| LogError::NotUtf8)?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let delim = delimiter(text);
    let rows = csv_rows(text, delim)?;
    let mut it = rows.iter();
    let (_, header) = it.next().ok_or(LogError::Empty)?;
    let sample: Vec<&Vec<String>> = it.take(SAMPLE_ROWS).map(|(_, r)| r).collect();
    let columns: Vec<Column<'_>> = header
        .iter()
        .enumerate()
        .map(|(i, name)| Column {
            name: name.trim(),
            lower: name.trim().to_lowercase(),
            values: sample
                .iter()
                .map(|r| r.get(i).map_or("", String::as_str))
                .collect(),
        })
        .collect();
    let mut reasons = BTreeMap::new();
    reasons.insert(
        "delimiter".to_owned(),
        format!(
            "«{}»: при нём {} колонок и строки с ним согласны",
            if delim == '\t' {
                "табуляция".to_owned()
            } else {
                delim.to_string()
            },
            columns.len()
        ),
    );
    let mut taken: BTreeSet<&str> = BTreeSet::new();

    // Время: формат по содержимому; из нескольких — колонка начала действия.
    let mut time: Option<(&Column<'_>, TimeFormat, f64)> = None;
    for c in &columns {
        let rfc = c.share(is_rfc3339);
        let epoch = epoch_format(
            c.values
                .iter()
                .find(|v| !v.trim().is_empty())
                .unwrap_or(&""),
        );
        let (format, share) = match epoch {
            Some(f) if rfc < 0.9 => (f, c.share(|v| epoch_format(v) == Some(f))),
            _ => (TimeFormat::Rfc3339, rfc),
        };
        if share < 0.9 {
            continue;
        }
        let score = share
            + if c.named(&["start", "begin", "начал"]) {
                0.5
            } else {
                0.0
            }
            + if c.named(&["time", "ts", "date", "врем"]) {
                0.2
            } else {
                0.0
            }
            - if c.named(&["end", "finish", "stop", "конец", "оконч"]) {
                0.5
            } else {
                0.0
            };
        if time.is_none_or(|(_, _, best)| score > best) {
            time = Some((c, format, score));
        }
    }
    let Some((time_col, time_format, _)) = time else {
        return Err(LogError::Mapping(
            "не нашлось колонки со временем (RFC 3339 или Unix-время): укажите сопоставление вручную"
                .to_owned(),
        ));
    };
    taken.insert(time_col.name);
    reasons.insert(
        "time".to_owned(),
        format!(
            "«{}»: {} значений читаются как время ({})",
            time_col.name,
            percent(match time_format {
                TimeFormat::Rfc3339 => time_col.share(is_rfc3339),
                f => time_col.share(|v| epoch_format(v) == Some(f)),
            }),
            time_format.title()
        ),
    );

    // Параметры и результат: JSON-объект или «ключ=значение».
    let structured = |c: &Column<'_>| -> Option<(PairsFormat, f64)> {
        let json = c.share(is_json_object);
        let kv = c.share(is_kv);
        if json >= 0.6 {
            Some((PairsFormat::Json, json))
        } else if kv >= 0.6 {
            Some((PairsFormat::Kv, kv))
        } else {
            None
        }
    };
    let pick_pairs = |names: &[&str], taken: &BTreeSet<&str>| {
        columns
            .iter()
            .filter(|c| !taken.contains(c.name))
            .filter_map(|c| structured(c).map(|(f, s)| (c, f, s)))
            .max_by(|a, b| {
                let score = |(c, _, s): &(&Column<'_>, PairsFormat, f64)| {
                    s + if c.named(names) { 1.0 } else { 0.0 }
                };
                score(a).total_cmp(&score(b))
            })
    };
    let params = pick_pairs(
        &["param", "arg", "input", "request", "параметр", "аргумент"],
        &taken,
    )
    .filter(|(c, _, _)| {
        !c.named(&[
            "result",
            "response",
            "outcome",
            "observ",
            "результат",
            "ответ",
        ])
    });
    if let Some((c, f, s)) = params {
        taken.insert(c.name);
        reasons.insert(
            "params".to_owned(),
            format!("«{}»: {} значений — {}", c.name, percent(s), pairs_name(f)),
        );
    }
    let result = pick_pairs(
        &[
            "result",
            "response",
            "outcome",
            "observ",
            "status",
            "результат",
            "ответ",
        ],
        &taken,
    )
    .or_else(|| {
        // Результат бывает голым статусом («ok»): тогда — по имени колонки.
        columns
            .iter()
            .filter(|c| !taken.contains(c.name))
            .find(|c| {
                c.named(&[
                    "result",
                    "response",
                    "outcome",
                    "observ",
                    "результат",
                    "ответ",
                ])
            })
            .map(|c| (c, PairsFormat::Kv, 0.0))
    });
    if let Some((c, f, s)) = result {
        taken.insert(c.name);
        reasons.insert(
            "result".to_owned(),
            if s > 0.0 {
                format!("«{}»: {} значений — {}", c.name, percent(s), pairs_name(f))
            } else {
                format!("«{}»: по имени колонки", c.name)
            },
        );
    }

    // Запись: имена файлов захвата.
    let source = columns
        .iter()
        .filter(|c| !taken.contains(c.name))
        .map(|c| (c, c.share(looks_like_capture)))
        .filter(|(_, s)| *s >= 0.8)
        .max_by(|a, b| a.1.total_cmp(&b.1));
    if let Some((c, s)) = source {
        taken.insert(c.name);
        reasons.insert(
            "source".to_owned(),
            format!(
                "«{}»: {} значений — имена файлов записей; журнал на несколько записей",
                c.name,
                percent(s)
            ),
        );
    }

    // Действие: короткие повторяющиеся имена, лучше всего — по имени колонки.
    let action = columns
        .iter()
        .filter(|c| !taken.contains(c.name))
        .filter(|c| {
            c.share(|v| !v.contains(' ') && v.len() <= 64 && v.parse::<f64>().is_err()) >= 0.9
        })
        .max_by(|a, b| {
            let score = |c: &&Column<'_>| {
                let repeats = c.values.len().saturating_sub(c.distinct()) as f64
                    / c.values.len().max(1) as f64;
                repeats
                    + if c.named(&[
                        "action",
                        "command",
                        "cmd",
                        "event",
                        "operation",
                        "действ",
                        "команд",
                        "операц",
                    ]) {
                        2.0
                    } else {
                        0.0
                    }
                    - if c.named(&["id", "session", "сесси"]) {
                        1.0
                    } else {
                        0.0
                    }
            };
            score(a).total_cmp(&score(b))
        });
    let Some(action_col) = action else {
        return Err(LogError::Mapping(
            "не нашлось колонки с именами действий: укажите сопоставление вручную".to_owned(),
        ));
    };
    reasons.insert(
        "action".to_owned(),
        format!(
            "«{}»: {} разных действий на {} строк",
            action_col.name,
            action_col.distinct(),
            action_col.values.len()
        ),
    );

    let mapping = Mapping {
        time: time_col.name.to_owned(),
        action: action_col.name.to_owned(),
        params: params.map(|(c, _, _)| c.name.to_owned()),
        result: result.map(|(c, _, _)| c.name.to_owned()),
        time_format,
        params_format: params.map_or(PairsFormat::Kv, |(_, f, _)| f),
        result_format: result.map_or(PairsFormat::Kv, |(_, f, _)| f),
        delimiter: match delim {
            ',' => None,
            '\t' => Some("tab".to_owned()),
            d => Some(d.to_string()),
        },
        utc_offset_minutes: 0,
        clock_offset_ms: 0,
        source: source.map(|(c, _)| c.name.to_owned()),
    };
    let parsed = parse(bytes, &mapping)?;
    Ok(Guess {
        columns: columns.iter().map(|c| c.name.to_owned()).collect(),
        rows: parsed.actions.len() as u64,
        skipped: parsed.skipped,
        mapping,
        reasons,
    })
}

fn pairs_name(f: PairsFormat) -> &'static str {
    match f {
        PairsFormat::Json => "JSON-объект",
        PairsFormat::Kv => "пары «ключ=значение»",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organizers_journal_is_guessed() {
        let csv = concat!(
            "capture,session,action_id,start_utc,end_utc,action,parameters,observed_result\n",
            "research/01_configuration.pcap,s1,01-01-001,2026-10-10T10:30:00.006000Z,2026-10-10T10:30:00.032000Z,read-config,{},\"{\"\"status\"\":\"\"ok\"\"}\"\n",
            "research/01_configuration.pcap,s1,01-01-002,2026-10-10T10:30:00.134000Z,2026-10-10T10:30:00.148000Z,set-config,\"{\"\"enabled\"\":true,\"\"period_ms\"\":1000}\",\"{\"\"status\"\":\"\"ok\"\"}\"\n",
            "research/02_variations.pcapng,s2,02-01-001,2026-10-10T10:31:00.006000Z,2026-10-10T10:31:00.040000Z,read-config,{},\"{\"\"status\"\":\"\"ok\"\"}\"\n",
        );
        let g = guess_mapping(csv.as_bytes()).unwrap();
        assert_eq!(g.mapping.time, "start_utc", "начало, а не конец действия");
        assert_eq!(g.mapping.action, "action");
        assert_eq!(g.mapping.params.as_deref(), Some("parameters"));
        assert_eq!(g.mapping.params_format, PairsFormat::Json);
        assert_eq!(g.mapping.result.as_deref(), Some("observed_result"));
        assert_eq!(g.mapping.result_format, PairsFormat::Json);
        assert_eq!(g.mapping.source.as_deref(), Some("capture"));
        assert_eq!((g.rows, g.skipped), (3, 0));
        assert!(g.reasons["time"].contains("start_utc"));
    }

    #[test]
    fn stand_journal_with_kv_and_bare_result() {
        let csv = concat!(
            "time,action,params,result\n",
            "2026-10-01T00:00:00.356179Z,read_param,param=gain,value=1\n",
            "2026-10-01T00:00:01.000000Z,set_param,param=setpoint;value=21,ok;applied=21\n",
            "2026-10-01T00:00:02.000000Z,set_param,param=setpoint;value=37,ok;applied=37\n",
        );
        let g = guess_mapping(csv.as_bytes()).unwrap();
        assert_eq!(g.mapping.time, "time");
        assert_eq!(g.mapping.action, "action");
        assert_eq!(g.mapping.params.as_deref(), Some("params"));
        assert_eq!(g.mapping.params_format, PairsFormat::Kv);
        assert_eq!(g.mapping.result.as_deref(), Some("result"));
        assert_eq!(g.mapping.source, None);
        assert_eq!((g.rows, g.skipped), (3, 0));
    }

    #[test]
    fn semicolons_and_unix_millis() {
        let csv = concat!(
            "ts;event;args\n",
            "1760000000123;open;{\"x\":1}\n",
            "1760000000456;close;{\"x\":2}\n",
        );
        let g = guess_mapping(csv.as_bytes()).unwrap();
        assert_eq!(g.mapping.delimiter.as_deref(), Some(";"));
        assert_eq!(g.mapping.time_format, TimeFormat::UnixMillis);
        assert_eq!(g.mapping.action, "event");
        assert_eq!(g.mapping.params_format, PairsFormat::Json);
        assert_eq!(g.rows, 2);
    }

    #[test]
    fn no_time_column_is_explained() {
        let err = guess_mapping(b"a,b\nx,y\n").unwrap_err();
        assert!(err.to_string().contains("времен"), "{err}");
    }
}
