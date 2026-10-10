//! Журнал действий клиента: время, действие, параметры, наблюдаемый результат.
//!
//! Формат журнала от организаторов неизвестен, поэтому разбор универсален: CSV с произвольными
//! именами колонок, несколькими форматами времени, поправкой на сдвиг часов и параметрами
//! `ключ=значение;…` или JSON. Файл — недоверенный ввод: размеры и число строк ограничены.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Размер файла журнала (`plan/security.md` §6).
pub const MAX_FILE_BYTES: usize = 256 << 20;
pub const MAX_ROWS: usize = 1_000_000;
const MAX_FIELD_BYTES: usize = 64 << 10;
const MAX_COLUMNS: usize = 256;
/// Сколько ошибок строк показываем подробно.
pub const MAX_REPORTED_ERRORS: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LogError {
    #[error("файл журнала больше {MAX_FILE_BYTES} байт")]
    TooLarge,
    #[error("в журнале больше {MAX_ROWS} строк")]
    TooManyRows,
    #[error("файл журнала не в кодировке UTF-8")]
    NotUtf8,
    #[error("в журнале нет строки заголовка")]
    Empty,
    #[error("нет колонки «{0}» из сопоставления; в файле: {1}")]
    MissingColumn(String, String),
    #[error("строка {line}: {why}")]
    Csv { line: u64, why: String },
    #[error(
        "разобрать удалось меньше половины строк ({parsed} из {total}); первая ошибка — {first}"
    )]
    MostlyBroken {
        parsed: u64,
        total: u64,
        first: String,
    },
    #[error("сопоставление: {0}")]
    Mapping(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TimeFormat {
    /// `2026-10-01T12:00:00.250Z`, `…+03:00`; без пояса — по `utcOffsetMinutes`.
    #[default]
    Rfc3339,
    UnixSeconds,
    UnixMillis,
    UnixMicros,
    UnixNanos,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PairsFormat {
    /// `param=gain;value=5`
    #[default]
    Kv,
    /// `{"param":"gain","value":5}`
    Json,
}

/// Сопоставление колонок файла и настроек разбора.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mapping {
    pub time: String,
    pub action: String,
    #[serde(default)]
    pub params: Option<String>,
    #[serde(default)]
    pub result: Option<String>,
    #[serde(default)]
    pub time_format: TimeFormat,
    #[serde(default)]
    pub params_format: PairsFormat,
    #[serde(default)]
    pub result_format: PairsFormat,
    /// Разделитель; по умолчанию запятая.
    #[serde(default)]
    pub delimiter: Option<String>,
    /// Пояс времени без указания пояса, минуты от UTC.
    #[serde(default)]
    pub utc_offset_minutes: i32,
    /// Поправка на сдвиг часов клиента относительно часов записи, мс: прибавляется ко времени журнала.
    #[serde(default)]
    pub clock_offset_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Param {
    Int(i128),
    Text(String),
}

impl std::fmt::Display for Param {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Param::Int(v) => write!(f, "{v}"),
            Param::Text(v) => write!(f, "{v}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    /// Номер строки файла (с 1; заголовок — строка 1): часть идентичности действия.
    pub line: u64,
    /// Время в наносекундах от эпохи Unix, с учётом поправки.
    pub ts_ns: u64,
    pub action: String,
    pub params: BTreeMap<String, Param>,
    pub result: BTreeMap<String, Param>,
    /// Результат как в файле (если не разбирается на пары).
    pub result_raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowError {
    pub line: u64,
    pub why: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedLog {
    pub actions: Vec<Action>,
    /// Строки, которые не разобрались: показываются пользователю, а не молча теряются.
    pub errors: Vec<RowError>,
    pub skipped: u64,
}

// ------------------------------------------------------------------- CSV

/// Разбирает CSV с кавычками (`""` внутри поля, переводы строк в кавычках). `(номер строки, поля)`.
fn csv_rows(text: &str, delimiter: char) -> Result<Vec<(u64, Vec<String>)>, LogError> {
    let mut rows = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut line = 1u64;
    let mut row_line = 1u64;
    let mut chars = text.chars().peekable();
    let mut field_started = false;
    let end_row = |rows: &mut Vec<(u64, Vec<String>)>,
                   row: &mut Vec<String>,
                   field: &mut String,
                   row_line: u64|
     -> Result<(), LogError> {
        row.push(std::mem::take(field));
        if !(row.len() == 1 && row.first().is_some_and(String::is_empty)) {
            if rows.len() > MAX_ROWS {
                return Err(LogError::TooManyRows);
            }
            rows.push((row_line, std::mem::take(row)));
        } else {
            row.clear();
        }
        Ok(())
    };
    while let Some(c) = chars.next() {
        if field.len() > MAX_FIELD_BYTES {
            return Err(LogError::Csv {
                line,
                why: "поле длиннее 64 КиБ".to_owned(),
            });
        }
        if quoted {
            match c {
                '"' if chars.peek() == Some(&'"') => {
                    field.push('"');
                    chars.next();
                }
                '"' => quoted = false,
                '\n' => {
                    line += 1;
                    field.push('\n');
                }
                other => field.push(other),
            }
        } else if c == '"' && !field_started {
            quoted = true;
            field_started = true;
        } else if c == delimiter {
            row.push(std::mem::take(&mut field));
            if row.len() > MAX_COLUMNS {
                return Err(LogError::Csv {
                    line,
                    why: format!("больше {MAX_COLUMNS} колонок"),
                });
            }
            field_started = false;
        } else if c == '\n' || c == '\r' {
            if c == '\r' && chars.peek() == Some(&'\n') {
                chars.next();
            }
            end_row(&mut rows, &mut row, &mut field, row_line)?;
            field_started = false;
            line += 1;
            row_line = line;
        } else {
            field.push(c);
            field_started = true;
        }
    }
    if quoted {
        return Err(LogError::Csv {
            line,
            why: "кавычка не закрыта".to_owned(),
        });
    }
    if field_started || !row.is_empty() || !field.is_empty() {
        end_row(&mut rows, &mut row, &mut field, row_line)?;
    }
    Ok(rows)
}

// ----------------------------------------------------------------- время

/// День по гражданской дате (алгоритм Говарда Хиннанта), дни от 1970-01-01.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn digits(s: &str, from: usize, len: usize) -> Option<i64> {
    let part = s.get(from..from + len)?;
    part.bytes()
        .all(|b| b.is_ascii_digit())
        .then(|| part.parse().ok())
        .flatten()
}

/// `YYYY-MM-DD[T ]HH:MM:SS[.дробь][Z|±HH:MM]` → наносекунды от эпохи, `None` — не подходит.
fn parse_rfc3339(s: &str, default_offset_min: i32) -> Option<i128> {
    let s = s.trim();
    let (year, month, day) = (digits(s, 0, 4)?, digits(s, 5, 2)?, digits(s, 8, 2)?);
    if s.get(4..5)? != "-" || s.get(7..8)? != "-" || !matches!(s.get(10..11)?, "T" | "t" | " ") {
        return None;
    }
    let (hour, minute, second) = (digits(s, 11, 2)?, digits(s, 14, 2)?, digits(s, 17, 2)?);
    if s.get(13..14)? != ":" || s.get(16..17)? != ":" {
        return None;
    }
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let mut rest = s.get(19..)?;
    let mut nanos: i64 = 0;
    if let Some(frac) = rest.strip_prefix('.') {
        let n = frac.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 {
            return None;
        }
        let kept = frac.get(..n.min(9))?;
        nanos = kept.parse::<i64>().ok()? * 10i64.pow(9 - kept.len() as u32);
        rest = frac.get(n..)?;
    }
    let offset_min: i64 = match rest {
        "" => i64::from(default_offset_min),
        "Z" | "z" => 0,
        zone => {
            let sign = match zone.get(..1)? {
                "+" => 1,
                "-" => -1,
                _ => return None,
            };
            let (h, m) = (
                digits(zone, 1, 2)?,
                if zone.len() >= 6 {
                    digits(zone, 4, 2)?
                } else {
                    0
                },
            );
            if zone.len() != 6 && zone.len() != 3 || h > 23 || m > 59 {
                return None;
            }
            sign * (h * 60 + m)
        }
    };
    let secs = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second
        - offset_min * 60;
    Some(i128::from(secs) * 1_000_000_000 + i128::from(nanos))
}

/// Время RFC 3339 из запроса (фильтры по окну): наносекунды от эпохи; без пояса — UTC.
pub fn parse_rfc3339_ns(raw: &str) -> Option<u64> {
    parse_rfc3339(raw, 0).and_then(|v| u64::try_from(v).ok())
}

fn parse_time(raw: &str, m: &Mapping) -> Option<i128> {
    let raw = raw.trim();
    let scaled = |unit_ns: i128| -> Option<i128> {
        if let Some((int, frac)) = raw.split_once('.') {
            let whole: i128 = int.parse().ok()?;
            let kept = frac.get(..frac.len().min(9))?;
            if kept.is_empty() || !kept.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let fraction: i128 = kept.parse().ok()?;
            let scale = 10i128.pow(kept.len() as u32);
            let sign = if whole < 0 || int.starts_with('-') {
                -1
            } else {
                1
            };
            Some(whole * unit_ns + sign * fraction * unit_ns / scale)
        } else {
            raw.parse::<i128>().ok()?.checked_mul(unit_ns)
        }
    };
    match m.time_format {
        TimeFormat::Rfc3339 => parse_rfc3339(raw, m.utc_offset_minutes),
        TimeFormat::UnixSeconds => scaled(1_000_000_000),
        TimeFormat::UnixMillis => scaled(1_000_000),
        TimeFormat::UnixMicros => scaled(1_000),
        TimeFormat::UnixNanos => scaled(1),
    }
}

// ---------------------------------------------------------------- пары

fn param(v: &str) -> Param {
    let v = v.trim();
    v.parse::<i128>()
        .map_or_else(|_| Param::Text(v.to_owned()), Param::Int)
}

fn pairs(raw: &str, format: PairsFormat, bare_as_status: bool) -> Option<BTreeMap<String, Param>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Some(BTreeMap::new());
    }
    match format {
        PairsFormat::Kv => {
            let mut out = BTreeMap::new();
            for item in raw.split(';').map(str::trim).filter(|i| !i.is_empty()) {
                match item.split_once('=') {
                    Some((key, value)) => {
                        out.insert(key.trim().to_owned(), param(value));
                    }
                    // «ok;applied=21»: слово без значения — статус результата.
                    None if bare_as_status => {
                        out.insert("status".to_owned(), Param::Text(item.to_owned()));
                    }
                    None => return None,
                }
            }
            Some(out)
        }
        PairsFormat::Json => {
            let serde_json::Value::Object(map) = serde_json::from_str(raw).ok()? else {
                return None;
            };
            Some(
                map.into_iter()
                    .map(|(k, v)| {
                        let p = match v {
                            serde_json::Value::Number(n) => n.as_i64().map_or_else(
                                || Param::Text(n.to_string()),
                                |i| Param::Int(i128::from(i)),
                            ),
                            serde_json::Value::String(s) => Param::Text(s),
                            other => Param::Text(other.to_string()),
                        };
                        (k, p)
                    })
                    .collect(),
            )
        }
    }
}

// ---------------------------------------------------------------- разбор

fn delimiter_of(m: &Mapping) -> Result<char, LogError> {
    match m.delimiter.as_deref() {
        None => Ok(','),
        Some("\\t") | Some("tab") => Ok('\t'),
        Some(s) if s.chars().count() == 1 => Ok(s.chars().next().unwrap_or(',')),
        Some(_) => Err(LogError::Mapping(
            "delimiter — один символ или tab".to_owned(),
        )),
    }
}

pub fn parse(bytes: &[u8], mapping: &Mapping) -> Result<ParsedLog, LogError> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(LogError::TooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| LogError::NotUtf8)?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let delimiter = delimiter_of(mapping)?;
    if mapping.time.is_empty() || mapping.action.is_empty() {
        return Err(LogError::Mapping(
            "укажите колонки time и action".to_owned(),
        ));
    }
    let rows = csv_rows(text, delimiter)?;
    let mut it = rows.into_iter();
    let (_, header) = it.next().ok_or(LogError::Empty)?;
    let header: Vec<String> = header.into_iter().map(|h| h.trim().to_owned()).collect();
    let column = |name: &str| -> Result<usize, LogError> {
        header
            .iter()
            .position(|h| h == name)
            .ok_or_else(|| LogError::MissingColumn(name.to_owned(), header.join(", ")))
    };
    let (c_time, c_action) = (column(&mapping.time)?, column(&mapping.action)?);
    let c_params = mapping.params.as_deref().map(column).transpose()?;
    let c_result = mapping.result.as_deref().map(column).transpose()?;
    let offset_ns = i128::from(mapping.clock_offset_ms) * 1_000_000;

    let mut log = ParsedLog {
        actions: Vec::new(),
        errors: Vec::new(),
        skipped: 0,
    };
    let mut total = 0u64;
    for (line, fields) in it {
        total += 1;
        let get = |c: usize| fields.get(c).map_or("", String::as_str);
        let mut fail = |why: String| {
            log.skipped += 1;
            if log.errors.len() < MAX_REPORTED_ERRORS {
                log.errors.push(RowError { line, why });
            }
        };
        let Some(ts) = parse_time(get(c_time), mapping).and_then(|t| t.checked_add(offset_ns))
        else {
            fail(format!(
                "время «{}» не разобрано как {:?}",
                get(c_time),
                mapping.time_format
            ));
            continue;
        };
        let Some(ts_ns) = u64::try_from(ts).ok() else {
            fail("время вне допустимого диапазона".to_owned());
            continue;
        };
        let action = get(c_action).trim();
        if action.is_empty() {
            fail("пустое действие".to_owned());
            continue;
        }
        let Some(params) = c_params.map_or_else(
            || Some(BTreeMap::new()),
            |c| pairs(get(c), mapping.params_format, false),
        ) else {
            fail(format!(
                "параметры «{}» не разобраны",
                get(c_params.unwrap_or(0))
            ));
            continue;
        };
        let result_raw = c_result.map_or("", get).trim().to_owned();
        let result = pairs(&result_raw, mapping.result_format, true).unwrap_or_default();
        log.actions.push(Action {
            line,
            ts_ns,
            action: action.to_owned(),
            params,
            result,
            result_raw,
        });
    }
    if total > 0 && (log.actions.len() as u64) * 2 < total {
        let first = log
            .errors
            .first()
            .map_or_else(String::new, |e| format!("строка {}: {}", e.line, e.why));
        return Err(LogError::MostlyBroken {
            parsed: log.actions.len() as u64,
            total,
            first,
        });
    }
    Ok(log)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping() -> Mapping {
        Mapping {
            time: "time".into(),
            action: "action".into(),
            params: Some("params".into()),
            result: Some("result".into()),
            time_format: TimeFormat::Rfc3339,
            params_format: PairsFormat::Kv,
            result_format: PairsFormat::Kv,
            delimiter: None,
            utc_offset_minutes: 0,
            clock_offset_ms: 0,
        }
    }

    #[test]
    fn parses_the_stand_log_format() {
        let csv = "time,action,params,result\n2026-10-01T00:00:02.768393Z,set_param,param=setpoint;value=21,ok;applied=21\n";
        let log = parse(csv.as_bytes(), &mapping()).unwrap();
        let a = &log.actions[0];
        assert_eq!((a.line, a.action.as_str()), (2, "set_param"));
        assert_eq!(a.params["value"], Param::Int(21));
        assert_eq!(a.params["param"], Param::Text("setpoint".into()));
        assert_eq!(a.result["applied"], Param::Int(21));
        assert_eq!(a.ts_ns, 1_790_812_802_768_393_000);
    }

    #[test]
    fn arbitrary_column_names_and_semicolons() {
        let m = Mapping {
            time: "Дата".into(),
            action: "Операция".into(),
            params: Some("Параметры".into()),
            result: None,
            delimiter: Some(";".into()),
            ..mapping()
        };
        let csv =
            "\u{feff}Дата;Операция;Параметры\r\n2026-10-01 03:00:00+03:00;read;param=gain\r\n";
        let log = parse(csv.as_bytes(), &m).unwrap();
        assert_eq!(log.actions[0].ts_ns, 1_790_812_800_000_000_000);
        assert_eq!(log.actions[0].action, "read");
    }

    #[test]
    fn quoted_fields_with_commas_quotes_and_newlines() {
        let csv = "time,action,params,result\n2026-10-01T00:00:00Z,\"say \"\"hi\"\", ok\",a=1,\"line1\nline2\"\n2026-10-01T00:00:01Z,next,,\n";
        let log = parse(csv.as_bytes(), &mapping()).unwrap();
        assert_eq!(log.actions[0].action, "say \"hi\", ok");
        assert_eq!(log.actions[0].result_raw, "line1\nline2");
        assert_eq!(
            log.actions[1].line, 4,
            "номер строки считает и переводы внутри кавычек"
        );
    }

    #[test]
    fn time_formats() {
        let at = |fmt: TimeFormat, raw: &str, offset: i32| {
            parse_time(
                raw,
                &Mapping {
                    time_format: fmt,
                    utc_offset_minutes: offset,
                    ..mapping()
                },
            )
        };
        let base: i128 = 1_790_812_800_000_000_000;
        assert_eq!(at(TimeFormat::UnixSeconds, "1790812800", 0), Some(base));
        assert_eq!(
            at(TimeFormat::UnixSeconds, "1790812800.5", 0),
            Some(base + 500_000_000)
        );
        assert_eq!(
            at(TimeFormat::UnixMillis, "1790812800250", 0),
            Some(base + 250_000_000)
        );
        assert_eq!(
            at(TimeFormat::UnixMicros, "1790812800000001", 0),
            Some(base + 1_000)
        );
        assert_eq!(
            at(TimeFormat::UnixNanos, "1790812800000000007", 0),
            Some(base + 7)
        );
        assert_eq!(
            at(TimeFormat::Rfc3339, "2026-10-01T03:00:00", 180),
            Some(base),
            "пояс по умолчанию"
        );
        assert_eq!(
            at(TimeFormat::Rfc3339, "2026-10-01T00:00:00.123456789123Z", 0),
            Some(base + 123_456_789)
        );
        for bad in [
            "",
            "вчера",
            "2026-13-01T00:00:00Z",
            "2026-10-01T25:00:00Z",
            "2026-10-01T00:00:00+3",
            "2026-10-01",
        ] {
            assert_eq!(at(TimeFormat::Rfc3339, bad, 0), None, "{bad}");
        }
        assert_eq!(at(TimeFormat::UnixSeconds, "1.x", 0), None);
    }

    #[test]
    fn clock_offset_shifts_times() {
        let m = Mapping {
            clock_offset_ms: -1500,
            ..mapping()
        };
        let log = parse(
            b"time,action\n2026-10-01T00:00:10Z,x\n",
            &Mapping {
                params: None,
                result: None,
                ..m
            },
        )
        .unwrap();
        assert_eq!(log.actions[0].ts_ns, 1_790_812_808_500_000_000);
    }

    #[test]
    fn bad_rows_are_reported_not_hidden() {
        let csv = "time,action,params,result\n2026-10-01T00:00:00Z,a,x=1,\nвчера,b,,\n2026-10-01T00:00:02Z,,,\n2026-10-01T00:00:03Z,c,не пары,\n2026-10-01T00:00:04Z,d,,\n2026-10-01T00:00:05Z,e,,
";
        let log = parse(csv.as_bytes(), &mapping()).unwrap();
        assert_eq!(log.actions.len(), 3);
        assert_eq!(log.skipped, 3);
        let lines: Vec<u64> = log.errors.iter().map(|e| e.line).collect();
        assert_eq!(lines, [3, 4, 5]);
        assert!(log.errors[0].why.contains("вчера"));
    }

    #[test]
    fn mostly_broken_file_is_rejected() {
        let csv = "time,action\nx,a\ny,b\nz,c\n2026-10-01T00:00:00Z,d\n";
        let err = parse(
            csv.as_bytes(),
            &Mapping {
                params: None,
                result: None,
                ..mapping()
            },
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                LogError::MostlyBroken {
                    parsed: 1,
                    total: 4,
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn mapping_and_format_errors() {
        let err = parse(b"t,a\n1,2\n", &mapping()).unwrap_err();
        assert!(matches!(err, LogError::MissingColumn(c, _) if c == "time"));
        assert_eq!(parse(b"", &mapping()), Err(LogError::Empty));
        assert_eq!(parse(&[0xff, 0xfe], &mapping()), Err(LogError::NotUtf8));
        assert!(matches!(
            parse(
                b"time,action\n\"x",
                &Mapping {
                    params: None,
                    result: None,
                    ..mapping()
                }
            ),
            Err(LogError::Csv { .. })
        ));
        let bad = Mapping {
            delimiter: Some("ab".into()),
            ..mapping()
        };
        assert!(matches!(
            parse(b"time,action\n", &bad),
            Err(LogError::Mapping(_))
        ));
    }

    #[test]
    fn json_pairs() {
        let m = Mapping {
            params_format: PairsFormat::Json,
            result: None,
            ..mapping()
        };
        let csv = "time,action,params\n2026-10-01T00:00:00Z,set,\"{\"\"value\"\": 70000, \"\"param\"\": \"\"setpoint\"\"}\"\n";
        let log = parse(csv.as_bytes(), &m).unwrap();
        assert_eq!(log.actions[0].params["value"], Param::Int(70_000));
        assert_eq!(
            log.actions[0].params["param"],
            Param::Text("setpoint".into())
        );
    }

    #[test]
    fn hostile_input_does_not_panic() {
        let long = "x".repeat(MAX_FIELD_BYTES + 10);
        assert!(matches!(
            parse(
                format!("time,action\n{long},a\n").as_bytes(),
                &Mapping {
                    params: None,
                    result: None,
                    ..mapping()
                }
            ),
            Err(LogError::Csv { .. })
        ));
        let wide = (0..300)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        assert!(matches!(
            parse(format!("{wide}\n").as_bytes(), &mapping()),
            Err(LogError::Csv { .. })
        ));
        let mut state = 7u64;
        for _ in 0..300 {
            let bytes: Vec<u8> = (0..64)
                .map(|_| {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    b"a,\"\n\r;=-:0 "[(state >> 33) as usize % 11]
                })
                .collect();
            let _ = parse(&bytes, &mapping());
        }
    }
}
