//! Кодирование для ответов API без внешних зависимостей: base64 и время RFC 3339.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64(data: &[u8]) -> String {
    let sym = |v: u32| char::from(ALPHABET[(v & 63) as usize]);
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let n = (b(0) << 16) | (b(1) << 8) | b(2);
        out.push(sym(n >> 18));
        out.push(sym(n >> 12));
        out.push(if chunk.len() > 1 { sym(n >> 6) } else { '=' });
        out.push(if chunk.len() > 2 { sym(n) } else { '=' });
    }
    out
}

/// Наносекунды от эпохи Unix → `YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ` (UTC).
pub fn rfc3339(ns: u64) -> String {
    let secs = ns / 1_000_000_000;
    let frac = ns % 1_000_000_000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{frac:09}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Дата по числу дней от 1970-01-01 (алгоритм Г. Хиннанта).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_rfc4648_vectors() {
        let cases = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (input, want) in cases {
            assert_eq!(base64(input.as_bytes()), want);
        }
        assert_eq!(base64(&[0xFF, 0xFE]), "//4=");
    }

    #[test]
    fn rfc3339_known_dates() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000000000Z");
        assert_eq!(
            rfc3339(1_790_812_800_000_000_000 + 250_000_000),
            "2026-10-01T00:00:00.250000000Z"
        );
        assert_eq!(
            rfc3339(951_782_400_000_000_007),
            "2000-02-29T00:00:00.000000007Z"
        );
    }
}
