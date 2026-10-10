//! Чтение записей pcap/pcapng: индекс кадров и TCP-сегментов без копирования данных.
//! Запись — недоверенный ввод: ошибка кадра становится диагностикой, а не паникой.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]

mod container;
mod decode;
mod diag;

use std::net::SocketAddrV4;

pub use container::Format;
pub use decode::{
    Checksum, Decoded, EthernetInfo, Ipv4Info, LINKTYPE_ETHERNET, TcpInfo, decode, tcp_flags,
};
pub use diag::{DiagCode, DiagGroup, Diagnostics, MAX_FRAME_NUMBERS, Severity};

/// Предел размера файла записи (`plan/security.md` §6).
pub const MAX_FILE_BYTES: u64 = 1 << 30;
/// Предел числа кадров в одной записи.
pub const MAX_FRAMES: u64 = 10_000_000;
/// Как часто (в кадрах) проверяем отмену и сообщаем прогресс.
const CONTROL_EVERY: u64 = 4096;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_file_bytes: u64,
    pub max_frames: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_bytes: MAX_FILE_BYTES,
            max_frames: MAX_FRAMES,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CaptureError {
    #[error("Файл не является записью pcap или pcapng либо повреждён с самого начала.")]
    NotCapture,
    #[error("Превышен предел «{name}»: {value}, допустимо не больше {max}.")]
    LimitExceeded {
        name: &'static str,
        value: u64,
        max: u64,
    },
    #[error("Импорт отменён.")]
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameRecord {
    /// Номер кадра с 1, как в Wireshark.
    pub no: u32,
    pub ts_ns: u64,
    /// Смещение данных кадра в файле.
    pub file_offset: u64,
    pub captured_len: u32,
    pub original_len: u32,
    /// `None` — блок кадра повреждён.
    pub linktype: Option<i32>,
}

/// TCP-сегмент, пригодный для сборки. Байты payload — в файле по `payload_offset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSegment {
    pub frame: u32,
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub payload_offset: u64,
    /// Длина payload по заголовкам.
    pub payload_len: u32,
    /// Сколько байтов payload записано (меньше `payload_len` при усечении).
    pub captured_len: u32,
    pub checksum: Checksum,
}

impl TcpSegment {
    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureIndex {
    pub format: Format,
    pub frames: Vec<FrameRecord>,
    pub segments: Vec<TcpSegment>,
    pub diagnostics: Diagnostics,
}

impl CaptureIndex {
    pub fn frame(&self, no: u32) -> Option<&FrameRecord> {
        self.frames.get((no as usize).checked_sub(1)?)
    }

    /// Кадры, ставшие TCP-сегментами.
    pub fn parsed(&self) -> u64 {
        self.segments.len() as u64
    }

    pub fn skipped(&self) -> u64 {
        self.frames.len() as u64 - self.parsed()
    }
}

/// Записанные байты кадра.
pub fn frame_bytes<'a>(file: &'a [u8], f: &FrameRecord) -> Option<&'a [u8]> {
    let start = usize::try_from(f.file_offset).ok()?;
    file.get(start..start.checked_add(f.captured_len as usize)?)
}

/// Записанные байты payload сегмента.
pub fn payload_bytes<'a>(file: &'a [u8], s: &TcpSegment) -> Option<&'a [u8]> {
    let start = usize::try_from(s.payload_offset).ok()?;
    file.get(start..start.checked_add(s.captured_len as usize)?)
}

/// Индексирует запись целиком. `cancelled` и `progress(байтов пройдено)` вызываются
/// раз в несколько тысяч кадров.
pub fn index(
    file: &[u8],
    limits: Limits,
    cancelled: &dyn Fn() -> bool,
    progress: &mut dyn FnMut(u64),
) -> Result<CaptureIndex, CaptureError> {
    let size = file.len() as u64;
    if size > limits.max_file_bytes {
        return Err(CaptureError::LimitExceeded {
            name: "размер файла записи, байт",
            value: size,
            max: limits.max_file_bytes,
        });
    }
    let format = container::detect(file).ok_or(CaptureError::NotCapture)?;
    let mut idx = CaptureIndex {
        format,
        frames: Vec::new(),
        segments: Vec::new(),
        diagnostics: Diagnostics::default(),
    };
    let mut diags = Diagnostics::default();
    container::for_each_frame(file, format, &mut diags, &mut |raw| {
        let no = idx.frames.len() as u64 + 1;
        if no > limits.max_frames {
            return Err(CaptureError::LimitExceeded {
                name: "кадров в записи",
                value: no,
                max: limits.max_frames,
            });
        }
        if no.is_multiple_of(CONTROL_EVERY) {
            if cancelled() {
                return Err(CaptureError::Cancelled);
            }
            progress(raw.file_offset);
        }
        let no = no as u32;
        let d = decode(raw.data, raw.original_len, raw.linktype);
        for code in &d.issues {
            idx.diagnostics.add(*code, no);
        }
        if let (Some(ip), Some(tcp)) = (d.ipv4, d.tcp) {
            idx.segments.push(TcpSegment {
                frame: no,
                src: SocketAddrV4::new(ip.src, tcp.src_port),
                dst: SocketAddrV4::new(ip.dst, tcp.dst_port),
                seq: tcp.seq,
                ack: tcp.ack,
                flags: tcp.flags,
                window: tcp.window,
                payload_offset: raw.file_offset + d.payload_offset as u64,
                payload_len: d.payload_len,
                captured_len: d.captured_payload_len,
                checksum: tcp.checksum,
            });
        }
        idx.frames.push(FrameRecord {
            no,
            ts_ns: raw.ts_ns,
            file_offset: raw.file_offset,
            captured_len: raw.data.len() as u32,
            original_len: raw.original_len,
            linktype: raw.linktype,
        });
        Ok(())
    })?;
    for (code, g) in diags.groups {
        for _ in 0..g.count {
            idx.diagnostics.add(code, 0);
        }
    }
    if idx.frames.is_empty() && idx.diagnostics.count(DiagCode::BadBlock) > 0 {
        return Err(CaptureError::NotCapture);
    }
    progress(size);
    Ok(idx)
}
