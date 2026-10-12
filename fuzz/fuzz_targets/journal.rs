//! Журнал действий: CSV, пары «ключ=значение» и JSON в ячейках, все форматы времени.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pl_actions::{Mapping, PairsFormat, TimeFormat, parse};

fuzz_target!(|data: &[u8]| {
    let Some((mode, body)) = data.split_first() else {
        return;
    };
    let pairs = |json: bool| {
        if json {
            PairsFormat::Json
        } else {
            PairsFormat::Kv
        }
    };
    let mapping = Mapping {
        time: "time".to_owned(),
        action: "action".to_owned(),
        params: Some("params".to_owned()),
        result: Some("result".to_owned()),
        time_format: match mode % 5 {
            0 => TimeFormat::Rfc3339,
            1 => TimeFormat::UnixSeconds,
            2 => TimeFormat::UnixMillis,
            3 => TimeFormat::UnixMicros,
            _ => TimeFormat::UnixNanos,
        },
        params_format: pairs(mode & 0x10 != 0),
        result_format: pairs(mode & 0x20 != 0),
        delimiter: (mode & 0x40 != 0).then(|| ";".to_owned()),
        utc_offset_minutes: 0,
        clock_offset_ms: 0,
        source: (mode & 0x80 != 0).then(|| "capture".to_owned()),
    };
    if let Ok(log) = parse(body, &mapping) {
        // Показанных ошибок не больше, чем пропущенных строк.
        assert!(log.errors.len() as u64 <= log.skipped);
    }
});
