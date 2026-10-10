//! Журнал действий клиента (CSV).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// Время начала действия, мкс от эпохи Unix.
    pub ts_us: u64,
    pub action: &'static str,
    pub params: String,
    pub result: String,
}

/// Дата и время UTC `2026-10-01T00:00:00.123456Z` из микросекунд от эпохи.
pub fn rfc3339(ts_us: u64) -> String {
    let secs = ts_us / 1_000_000;
    let micros = ts_us % 1_000_000;
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    // Гражданская дата по дню от эпохи (алгоритм Говарда Хиннанта).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{micros:06}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

pub fn to_csv(entries: &[LogEntry]) -> String {
    let mut out = String::from("time,action,params,result\n");
    for e in entries {
        out.push_str(&format!(
            "{},{},{},{}\n",
            rfc3339(e.ts_us),
            e.action,
            e.params,
            e.result
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_dates() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000000Z");
        assert_eq!(
            rfc3339(1_790_812_800_000_000 + 3_723_000_456),
            "2026-10-01T01:02:03.000456Z"
        );
        assert_eq!(rfc3339(951_782_400_000_000), "2000-02-29T00:00:00.000000Z");
    }
}
