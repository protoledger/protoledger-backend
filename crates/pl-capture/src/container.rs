use pcap_parser::pcap::{parse_pcap_frame, parse_pcap_frame_be, parse_pcap_header};
use pcap_parser::pcapng::{Block, parse_block_be, parse_block_le};

use crate::diag::{DiagCode, Diagnostics};

const NS_PER_SEC: u128 = 1_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Pcap,
    Pcapng,
}

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Format::Pcap => "pcap",
            Format::Pcapng => "pcapng",
        }
    }
}

pub fn detect(file: &[u8]) -> Option<Format> {
    let magic = u32::from_le_bytes(file.get(..4)?.try_into().ok()?);
    match magic {
        0xA1B2_C3D4 | 0xD4C3_B2A1 | 0xA1B2_3C4D | 0x4D3C_B2A1 => Some(Format::Pcap),
        0x0A0D_0D0A => Some(Format::Pcapng),
        _ => None,
    }
}

/// Кадр из контейнера, ещё не разобранный. `linktype: None` — блок кадра испорчен.
pub struct RawFrame<'a> {
    pub ts_ns: u64,
    pub file_offset: u64,
    pub data: &'a [u8],
    pub original_len: u32,
    pub linktype: Option<i32>,
}

fn offset_in(file: &[u8], part: &[u8]) -> u64 {
    (part.as_ptr() as usize).saturating_sub(file.as_ptr() as usize) as u64
}

/// Проходит кадры по порядку. Сбой контейнера — `bad_block` и остановка: что разобрано, остаётся.
pub fn for_each_frame<E>(
    file: &[u8],
    format: Format,
    diags: &mut Diagnostics,
    f: &mut dyn FnMut(RawFrame<'_>) -> Result<(), E>,
) -> Result<(), E> {
    match format {
        Format::Pcap => pcap(file, diags, f),
        Format::Pcapng => pcapng(file, diags, f),
    }
}

fn pcap<E>(
    file: &[u8],
    diags: &mut Diagnostics,
    f: &mut dyn FnMut(RawFrame<'_>) -> Result<(), E>,
) -> Result<(), E> {
    let Ok((mut rem, header)) = parse_pcap_header(file) else {
        diags.add(DiagCode::BadBlock, 0);
        return Ok(());
    };
    let frac_ns: u128 = if header.is_nanosecond_precision() {
        1
    } else {
        1_000
    };
    let parse = if header.is_bigendian() {
        parse_pcap_frame_be
    } else {
        parse_pcap_frame
    };
    while !rem.is_empty() {
        let Ok((next, rec)) = parse(rem) else {
            diags.add(DiagCode::BadBlock, 0);
            break;
        };
        if next.len() >= rem.len() {
            diags.add(DiagCode::BadBlock, 0);
            break;
        }
        let ts = u128::from(rec.ts_sec) * NS_PER_SEC + u128::from(rec.ts_usec) * frac_ns;
        f(RawFrame {
            ts_ns: u64::try_from(ts).unwrap_or(u64::MAX),
            file_offset: offset_in(file, rec.data),
            data: rec.data,
            original_len: rec.origlen.max(rec.caplen),
            linktype: Some(header.network.0),
        })?;
        rem = next;
    }
    Ok(())
}

struct Iface {
    linktype: i32,
    snaplen: u32,
    /// Единиц времени в секунде; `None` — значение в файле некорректно.
    units_per_sec: Option<u64>,
    offset_sec: i64,
}

fn pcapng_ts(raw: u64, iface: &Iface) -> u64 {
    let Some(units) = iface.units_per_sec.filter(|u| *u > 0) else {
        return 0;
    };
    let ns = i128::from(raw) * NS_PER_SEC as i128 / i128::from(units)
        + i128::from(iface.offset_sec) * NS_PER_SEC as i128;
    u64::try_from(ns.max(0)).unwrap_or(u64::MAX)
}

fn pcapng<E>(
    file: &[u8],
    diags: &mut Diagnostics,
    f: &mut dyn FnMut(RawFrame<'_>) -> Result<(), E>,
) -> Result<(), E> {
    let mut rem = file;
    let mut big_endian = false;
    let mut ifaces: Vec<Iface> = Vec::new();
    while !rem.is_empty() {
        let parse = if big_endian {
            parse_block_be
        } else {
            parse_block_le
        };
        let Ok((next, block)) = parse(rem) else {
            diags.add(DiagCode::BadBlock, 0);
            break;
        };
        if next.len() >= rem.len() {
            diags.add(DiagCode::BadBlock, 0);
            break;
        }
        match block {
            Block::SectionHeader(shb) => {
                big_endian = shb.big_endian();
                ifaces.clear();
            }
            Block::InterfaceDescription(idb) => ifaces.push(Iface {
                linktype: idb.linktype.0,
                snaplen: idb.snaplen,
                units_per_sec: idb.ts_resolution(),
                offset_sec: idb.if_tsoffset,
            }),
            Block::EnhancedPacket(epb) => {
                let iface = usize::try_from(epb.if_id).ok().and_then(|i| ifaces.get(i));
                let data = epb.data.get(..epb.caplen as usize);
                let raw_ts = (u64::from(epb.ts_high) << 32) | u64::from(epb.ts_low);
                let (linktype, ts_ns, data) = match (iface, data) {
                    (Some(i), Some(d)) => (Some(i.linktype), pcapng_ts(raw_ts, i), d),
                    _ => (None, 0, &[][..]),
                };
                f(RawFrame {
                    ts_ns,
                    file_offset: offset_in(file, data),
                    data,
                    original_len: epb.origlen.max(data.len() as u32),
                    linktype,
                })?;
            }
            Block::SimplePacket(spb) => {
                let iface = ifaces.first();
                let captured = iface.map_or(0, |i| {
                    let mut n = spb.origlen as usize;
                    if i.snaplen > 0 {
                        n = n.min(i.snaplen as usize);
                    }
                    n.min(spb.data.len())
                });
                let data = spb.data.get(..captured).unwrap_or_default();
                f(RawFrame {
                    ts_ns: 0,
                    file_offset: offset_in(file, data),
                    data,
                    original_len: spb.origlen.max(data.len() as u32),
                    linktype: iface.map(|i| i.linktype),
                })?;
            }
            _ => {}
        }
        rem = next;
    }
    Ok(())
}
