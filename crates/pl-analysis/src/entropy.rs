//! Энтропия участков потока: где данные похожи на сжатые или зашифрованные, где на текст,
//! где на заполнение. Подсказка, почему участок не поддаётся разбору на поля, — не вывод.

use serde::Serialize;

/// Размер окна: на меньшем числе байтов случайные данные от структурированных не отличить.
pub const ENTROPY_WINDOW: usize = 256;
/// Столько байтов одного потока просматривается.
pub const MAX_ENTROPY_BYTES: usize = 16 << 20;
/// Случайные 256 байт дают около 7,17 бита на байт; структурированные данные — заметно меньше.
const HIGH_MILLIBITS: u32 = 7_000;
const LOW_MILLIBITS: u32 = 1_000;
/// Доля печатных символов, с которой окно считается текстом.
const TEXT_PERMILLE: usize = 900;
const MAX_REGIONS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntropyKind {
    /// Байты распределены почти равномерно: сжатие или шифрование.
    High,
    /// Почти все байты — печатные символы.
    Text,
    /// Почти одно и то же значение: заполнение.
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntropyRegion {
    pub start: u64,
    pub end: u64,
    pub kind: EntropyKind,
    /// Средняя энтропия окон участка, в тысячных долях бита на байт.
    pub entropy_millibits: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntropyMap {
    /// Сколько байтов просмотрено окнами.
    pub bytes: u64,
    pub high_bytes: u64,
    pub text_bytes: u64,
    pub low_bytes: u64,
    /// Участки с узнаваемым видом; остальное — обычные структурированные данные.
    pub regions: Vec<EntropyRegion>,
    /// Поток длиннее предела или участков слишком много.
    pub truncated: bool,
}

/// Энтропия распределения байтов, в тысячных долях бита на байт.
pub fn entropy_millibits(data: &[u8]) -> u32 {
    if data.is_empty() {
        return 0;
    }
    let mut counts = [0u32; 256];
    for b in data {
        if let Some(c) = counts.get_mut(usize::from(*b)) {
            *c += 1;
        }
    }
    let n = data.len() as f64;
    let bits: f64 = counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = f64::from(*c) / n;
            -p * p.log2()
        })
        .sum();
    (bits * 1000.0).round() as u32
}

fn classify(window: &[u8]) -> (Option<EntropyKind>, u32) {
    let entropy = entropy_millibits(window);
    let printable = window
        .iter()
        .filter(|b| matches!(b, 0x20..=0x7e | b'\r' | b'\n' | b'\t'))
        .count();
    let kind = if entropy >= HIGH_MILLIBITS {
        Some(EntropyKind::High)
    } else if entropy <= LOW_MILLIBITS {
        Some(EntropyKind::Low)
    } else if printable * 1000 >= window.len() * TEXT_PERMILLE {
        Some(EntropyKind::Text)
    } else {
        None
    };
    (kind, entropy)
}

/// Карта энтропии потока. `pieces` — непрерывные участки известных байтов с их смещениями;
/// окна через дыры не перекидываются.
pub fn entropy_map(pieces: &[(u64, &[u8])]) -> EntropyMap {
    let mut out = EntropyMap::default();
    // Участок и число окон в нём: средняя энтропия считается по окнам.
    let mut windows_in_last = 0u64;
    let mut budget = MAX_ENTROPY_BYTES;
    for (start, data) in pieces {
        for (i, window) in data.chunks(ENTROPY_WINDOW).enumerate() {
            // Хвост короче окна не оценивается.
            if window.len() < ENTROPY_WINDOW {
                break;
            }
            if budget < ENTROPY_WINDOW {
                out.truncated = true;
                return out;
            }
            budget -= ENTROPY_WINDOW;
            out.bytes += ENTROPY_WINDOW as u64;
            let (Some(kind), entropy) = classify(window) else {
                continue;
            };
            let from = start + (i * ENTROPY_WINDOW) as u64;
            let to = from + ENTROPY_WINDOW as u64;
            match kind {
                EntropyKind::High => out.high_bytes += ENTROPY_WINDOW as u64,
                EntropyKind::Text => out.text_bytes += ENTROPY_WINDOW as u64,
                EntropyKind::Low => out.low_bytes += ENTROPY_WINDOW as u64,
            }
            let joins = out
                .regions
                .last()
                .is_some_and(|last| last.end == from && last.kind == kind);
            if joins {
                if let Some(last) = out.regions.last_mut() {
                    let total =
                        u64::from(last.entropy_millibits) * windows_in_last + u64::from(entropy);
                    windows_in_last += 1;
                    last.entropy_millibits = (total / windows_in_last) as u32;
                    last.end = to;
                }
            } else if out.regions.len() >= MAX_REGIONS {
                out.truncated = true;
            } else {
                windows_in_last = 1;
                out.regions.push(EntropyRegion {
                    start: from,
                    end: to,
                    kind,
                    entropy_millibits: entropy,
                });
            }
        }
    }
    out
}
