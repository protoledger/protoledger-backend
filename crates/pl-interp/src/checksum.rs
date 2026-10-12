//! Контрольные суммы и CRC, доступные в выражениях как функции `имя(от, до)` над байтами сообщения.
//! Параметры CRC — по каталогу «Catalogue of parametrised CRC algorithms»; каждая проверена
//! на эталонной строке `123456789`.

/// Алгоритм: имя функции в выражениях, название для человека и размер результата.
#[derive(Clone, Copy)]
pub struct Algorithm {
    pub name: &'static str,
    pub title: &'static str,
    /// Размер результата в байтах.
    pub width: u8,
    kind: Kind,
}

impl std::fmt::Debug for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name)
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Sum8,
    Lrc8,
    Xor8,
    Sum16,
    Inet16,
    Fletcher16,
    Crc(&'static Crc),
}

/// CRC в модели Rocksoft; отражение входа и выхода у всех алгоритмов каталога совпадает.
struct Crc {
    bits: u32,
    init: u32,
    reflected: bool,
    xorout: u32,
    table: [u32; 256],
}

const fn mask(bits: u32) -> u32 {
    if bits >= 32 {
        u32::MAX
    } else {
        (1 << bits) - 1
    }
}

const fn reflect(value: u32, bits: u32) -> u32 {
    value.reverse_bits() >> (32 - bits)
}

// Индексы таблицы — счётчик цикла до 256, выход за границы невозможен.
#[allow(clippy::indexing_slicing)]
const fn crc(bits: u32, poly: u32, init: u32, reflected: bool, xorout: u32) -> Crc {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = if reflected {
            i as u32
        } else {
            (i as u32) << (bits - 8)
        };
        let mut bit = 0;
        while bit < 8 {
            c = if reflected {
                if c & 1 != 0 {
                    (c >> 1) ^ reflect(poly, bits)
                } else {
                    c >> 1
                }
            } else if c & (1 << (bits - 1)) != 0 {
                (c << 1) ^ poly
            } else {
                c << 1
            };
            bit += 1;
        }
        table[i] = c & mask(bits);
        i += 1;
    }
    Crc {
        bits,
        init: if reflected { reflect(init, bits) } else { init },
        reflected,
        xorout,
        table,
    }
}

impl Crc {
    fn compute(&self, data: &[u8]) -> u32 {
        let entry = |i: u32| {
            self.table
                .get((i & 0xff) as usize)
                .copied()
                .unwrap_or_default()
        };
        let mut c = self.init;
        for b in data {
            c = if self.reflected {
                entry(c ^ u32::from(*b)) ^ (c >> 8)
            } else {
                entry((c >> (self.bits - 8)) ^ u32::from(*b)) ^ (c << 8)
            };
        }
        (c ^ self.xorout) & mask(self.bits)
    }
}

static CRC8: Crc = crc(8, 0x07, 0x00, false, 0x00);
static CRC8_MAXIM: Crc = crc(8, 0x31, 0x00, true, 0x00);
static CRC16_ARC: Crc = crc(16, 0x8005, 0x0000, true, 0x0000);
static CRC16_MODBUS: Crc = crc(16, 0x8005, 0xffff, true, 0x0000);
static CRC16_USB: Crc = crc(16, 0x8005, 0xffff, true, 0xffff);
static CRC16_CCITT: Crc = crc(16, 0x1021, 0xffff, false, 0x0000);
static CRC16_XMODEM: Crc = crc(16, 0x1021, 0x0000, false, 0x0000);
static CRC16_KERMIT: Crc = crc(16, 0x1021, 0x0000, true, 0x0000);
static CRC16_X25: Crc = crc(16, 0x1021, 0xffff, true, 0xffff);
static CRC16_DNP: Crc = crc(16, 0x3d65, 0x0000, true, 0xffff);
static CRC32: Crc = crc(32, 0x04c1_1db7, 0xffff_ffff, true, 0xffff_ffff);
static CRC32C: Crc = crc(32, 0x1edc_6f41, 0xffff_ffff, true, 0xffff_ffff);
static CRC32_BZIP2: Crc = crc(32, 0x04c1_1db7, 0xffff_ffff, false, 0xffff_ffff);
static CRC32_MPEG2: Crc = crc(32, 0x04c1_1db7, 0xffff_ffff, false, 0x0000_0000);

const fn simple(name: &'static str, title: &'static str, width: u8, kind: Kind) -> Algorithm {
    Algorithm {
        name,
        title,
        width,
        kind,
    }
}

const fn named(name: &'static str, title: &'static str, crc: &'static Crc) -> Algorithm {
    Algorithm {
        name,
        title,
        width: (crc.bits / 8) as u8,
        kind: Kind::Crc(crc),
    }
}

/// Все алгоритмы; порядок — от простых к сложным, так же перечисляются равнозначные подсказки.
pub static ALGORITHMS: [Algorithm; 20] = [
    simple("sum8", "сумма байтов по модулю 256", 1, Kind::Sum8),
    simple("lrc8", "LRC: сумма байтов с обратным знаком", 1, Kind::Lrc8),
    simple("xor8", "XOR всех байтов", 1, Kind::Xor8),
    named("crc8", "CRC-8", &CRC8),
    named("crc8_maxim", "CRC-8/MAXIM", &CRC8_MAXIM),
    simple("sum16", "сумма байтов по модулю 65536", 2, Kind::Sum16),
    simple(
        "inet16",
        "контрольная сумма Интернета (RFC 1071)",
        2,
        Kind::Inet16,
    ),
    simple("fletcher16", "Fletcher-16", 2, Kind::Fletcher16),
    named("crc16_modbus", "CRC-16/MODBUS", &CRC16_MODBUS),
    named("crc16_arc", "CRC-16/ARC", &CRC16_ARC),
    named("crc16_usb", "CRC-16/USB", &CRC16_USB),
    named("crc16_ccitt", "CRC-16/CCITT-FALSE", &CRC16_CCITT),
    named("crc16_xmodem", "CRC-16/XMODEM", &CRC16_XMODEM),
    named("crc16_kermit", "CRC-16/KERMIT", &CRC16_KERMIT),
    named("crc16_x25", "CRC-16/X-25", &CRC16_X25),
    named("crc16_dnp", "CRC-16/DNP", &CRC16_DNP),
    named("crc32", "CRC-32", &CRC32),
    named("crc32c", "CRC-32C (Castagnoli)", &CRC32C),
    named("crc32_bzip2", "CRC-32/BZIP2", &CRC32_BZIP2),
    named("crc32_mpeg2", "CRC-32/MPEG-2", &CRC32_MPEG2),
];

impl Algorithm {
    pub fn by_name(name: &str) -> Option<&'static Algorithm> {
        ALGORITHMS.iter().find(|a| a.name == name)
    }

    pub fn compute(&self, data: &[u8]) -> u64 {
        let sum = || {
            data.iter()
                .fold(0u32, |acc, b| acc.wrapping_add(u32::from(*b)))
        };
        u64::from(match self.kind {
            Kind::Sum8 => sum() & 0xff,
            Kind::Lrc8 => sum().wrapping_neg() & 0xff,
            Kind::Xor8 => u32::from(data.iter().fold(0u8, |acc, b| acc ^ b)),
            Kind::Sum16 => sum() & 0xffff,
            Kind::Inet16 => inet16(data),
            Kind::Fletcher16 => fletcher16(data),
            Kind::Crc(crc) => crc.compute(data),
        })
    }
}

/// RFC 1071: дополнение суммы 16-битных слов (старший байт первым) с переносом по кругу.
fn inet16(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    for pair in data.chunks(2) {
        let hi = pair.first().copied().unwrap_or(0);
        let lo = pair.get(1).copied().unwrap_or(0);
        sum += u32::from(u16::from_be_bytes([hi, lo]));
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum & 0xffff
}

fn fletcher16(data: &[u8]) -> u32 {
    let (mut a, mut b) = (0u32, 0u32);
    for byte in data {
        a = (a + u32::from(*byte)) % 255;
        b = (b + a) % 255;
    }
    (b << 8) | a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(name: &str) -> u64 {
        Algorithm::by_name(name).unwrap().compute(b"123456789")
    }

    #[test]
    fn crc_matches_the_catalogue_check_values() {
        let expected: [(&str, u64); 14] = [
            ("crc8", 0xf4),
            ("crc8_maxim", 0xa1),
            ("crc16_arc", 0xbb3d),
            ("crc16_modbus", 0x4b37),
            ("crc16_usb", 0xb4c8),
            ("crc16_ccitt", 0x29b1),
            ("crc16_xmodem", 0x31c3),
            ("crc16_kermit", 0x2189),
            ("crc16_x25", 0x906e),
            ("crc16_dnp", 0xea82),
            ("crc32", 0xcbf4_3926),
            ("crc32c", 0xe306_9283),
            ("crc32_bzip2", 0xfc89_1918),
            ("crc32_mpeg2", 0x0376_e6e7),
        ];
        for (name, value) in expected {
            assert_eq!(check(name), value, "{name}");
        }
    }

    #[test]
    fn sums_match_hand_computed_values() {
        // Сумма кодов «123456789» = 477 = 0x1DD.
        assert_eq!(check("sum8"), 0xdd);
        assert_eq!(check("lrc8"), 0x23);
        assert_eq!(check("xor8"), 0x31);
        assert_eq!(check("sum16"), 0x01dd);
        assert_eq!(check("fletcher16"), 0x1ede);
        // Пример RFC 1071: слова 0001 f203 f4f5 f6f7 дают сумму ddf2, дополнение — 220d.
        let rfc = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(Algorithm::by_name("inet16").unwrap().compute(&rfc), 0x220d);
    }

    #[test]
    fn widths_and_names_are_consistent() {
        for a in &ALGORITHMS {
            assert!(matches!(a.width, 1 | 2 | 4), "{}", a.name);
            assert!(a.compute(&[0xff; 64]) < 1u64 << (u32::from(a.width) * 8));
            assert_eq!(Algorithm::by_name(a.name).map(|x| x.name), Some(a.name));
        }
        assert!(Algorithm::by_name("md5").is_none());
        assert_eq!(Algorithm::by_name("crc32").unwrap().compute(&[]), 0);
    }
}
