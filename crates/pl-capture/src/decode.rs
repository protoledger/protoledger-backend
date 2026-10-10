use std::net::Ipv4Addr;

use crate::diag::DiagCode;

pub const LINKTYPE_ETHERNET: i32 = 1;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const VLAN_TAGS: [u16; 3] = [0x8100, 0x88A8, 0x9100];
const MAX_VLAN_TAGS: usize = 2;
const IP_PROTO_TCP: u8 = 6;

pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Checksum {
    Ok,
    Bad,
    /// Кадр усечён — проверить нельзя.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthernetInfo {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    /// Тип после VLAN-меток, если они были.
    pub ether_type: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Info {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub ttl: u8,
    pub protocol: u8,
    pub header_len: u8,
    pub total_len: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub header_len: u8,
    pub checksum: Checksum,
}

/// Разбор одного кадра. `tcp` заполнен, только если сегмент пригоден для сборки потока.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Decoded {
    pub ethernet: Option<EthernetInfo>,
    pub ipv4: Option<Ipv4Info>,
    pub tcp: Option<TcpInfo>,
    /// Смещение payload TCP внутри кадра.
    pub payload_offset: usize,
    /// Длина payload по заголовкам.
    pub payload_len: u32,
    /// Сколько байтов payload реально записано.
    pub captured_payload_len: u32,
    pub issues: Vec<DiagCode>,
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(at)?,
        *b.get(at + 1)?,
        *b.get(at + 2)?,
        *b.get(at + 3)?,
    ]))
}

fn mac(b: &[u8], at: usize) -> Option<[u8; 6]> {
    b.get(at..at + 6)?.try_into().ok()
}

fn sum16(data: &[u8], mut acc: u64) -> u64 {
    for c in data.chunks(2) {
        acc += match c {
            [hi, lo] => u64::from(u16::from_be_bytes([*hi, *lo])),
            [hi] => u64::from(*hi) << 8,
            _ => 0,
        };
    }
    acc
}

fn fold(mut acc: u64) -> u16 {
    while acc > 0xFFFF {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    acc as u16
}

/// Сумма с учётом поля контрольной суммы: для верных данных — 0xFFFF (RFC 1071).
fn verifies(data: &[u8], init: u64) -> bool {
    fold(sum16(data, init)) == 0xFFFF
}

pub fn decode(frame: &[u8], original_len: u32, linktype: Option<i32>) -> Decoded {
    let mut d = Decoded::default();
    let truncated = (frame.len() as u64) < u64::from(original_len);
    let short = |d: &mut Decoded, otherwise: DiagCode| {
        d.issues.push(if truncated {
            DiagCode::TruncatedFrame
        } else {
            otherwise
        });
    };

    match linktype {
        None => {
            d.issues.push(DiagCode::BadBlock);
            return d;
        }
        Some(LINKTYPE_ETHERNET) => {}
        Some(_) => {
            d.issues.push(DiagCode::UnsupportedLinkType);
            return d;
        }
    }

    let (Some(dst), Some(src), Some(mut ether_type)) =
        (mac(frame, 0), mac(frame, 6), be16(frame, 12))
    else {
        short(&mut d, DiagCode::NonIp);
        return d;
    };
    let mut l3 = 14;
    for _ in 0..MAX_VLAN_TAGS {
        if !VLAN_TAGS.contains(&ether_type) {
            break;
        }
        let Some(inner) = be16(frame, l3 + 2) else {
            short(&mut d, DiagCode::NonIp);
            return d;
        };
        ether_type = inner;
        l3 += 4;
    }
    d.ethernet = Some(EthernetInfo {
        dst,
        src,
        ether_type,
    });
    match ether_type {
        ETHERTYPE_IPV4 => {}
        ETHERTYPE_IPV6 => {
            d.issues.push(DiagCode::Ipv6Skipped);
            return d;
        }
        _ => {
            d.issues.push(DiagCode::NonIp);
            return d;
        }
    }

    let ip = frame.get(l3..).unwrap_or_default();
    let (Some(b0), Some(total_len), Some(frag), Some(ttl), Some(protocol), Some(s), Some(t)) = (
        ip.first(),
        be16(ip, 2),
        be16(ip, 6),
        ip.get(8),
        ip.get(9),
        be32(ip, 12),
        be32(ip, 16),
    ) else {
        short(&mut d, DiagCode::BadIpHeader);
        return d;
    };
    let ihl = usize::from(b0 & 0x0F) * 4;
    let on_wire = u64::from(original_len).saturating_sub(l3 as u64);
    if b0 >> 4 != 4 || ihl < 20 || usize::from(total_len) < ihl || u64::from(total_len) > on_wire {
        d.issues.push(DiagCode::BadIpHeader);
        return d;
    }
    let Some(ip_header) = ip.get(..ihl) else {
        short(&mut d, DiagCode::BadIpHeader);
        return d;
    };
    let (src_ip, dst_ip) = (Ipv4Addr::from(s), Ipv4Addr::from(t));
    d.ipv4 = Some(Ipv4Info {
        src: src_ip,
        dst: dst_ip,
        ttl: *ttl,
        protocol: *protocol,
        header_len: ihl as u8,
        total_len,
    });
    if !verifies(ip_header, 0) {
        d.issues.push(DiagCode::BadChecksum);
    }
    let more_fragments = frag & 0x2000 != 0;
    if more_fragments || frag & 0x1FFF != 0 {
        d.issues.push(DiagCode::IpFragment);
        return d;
    }
    if *protocol != IP_PROTO_TCP {
        d.issues.push(DiagCode::NonTcp);
        return d;
    }

    // Байты после total_len — дополнение Ethernet, не данные.
    let datagram = ip.get(..usize::from(total_len)).unwrap_or(ip);
    let tcp_declared = usize::from(total_len) - ihl;
    let seg = datagram.get(ihl..).unwrap_or_default();
    let (Some(sp), Some(dp), Some(seq), Some(ack), Some(off), Some(flags), Some(window)) = (
        be16(seg, 0),
        be16(seg, 2),
        be32(seg, 4),
        be32(seg, 8),
        seg.get(12),
        seg.get(13),
        be16(seg, 14),
    ) else {
        if tcp_declared < 20 {
            d.issues.push(DiagCode::BadTcpHeader);
        } else {
            short(&mut d, DiagCode::BadTcpHeader);
        }
        return d;
    };
    let hl = usize::from(off >> 4) * 4;
    if hl < 20 || hl > tcp_declared {
        d.issues.push(DiagCode::BadTcpHeader);
        return d;
    }
    if seg.len() < hl {
        short(&mut d, DiagCode::BadTcpHeader);
        return d;
    }

    let whole = datagram.len() == usize::from(total_len);
    let checksum = if !whole {
        Checksum::Unknown
    } else {
        let mut ph = Vec::with_capacity(12);
        ph.extend_from_slice(&src_ip.octets());
        ph.extend_from_slice(&dst_ip.octets());
        ph.extend_from_slice(&[0, IP_PROTO_TCP]);
        ph.extend_from_slice(&(tcp_declared as u16).to_be_bytes());
        if verifies(seg, sum16(&ph, 0)) {
            Checksum::Ok
        } else {
            Checksum::Bad
        }
    };
    if checksum == Checksum::Bad && !d.issues.contains(&DiagCode::BadChecksum) {
        d.issues.push(DiagCode::BadChecksum);
    }

    let payload_len = (tcp_declared - hl) as u32;
    let captured = seg.len().saturating_sub(hl) as u32;
    if captured < payload_len {
        d.issues.push(DiagCode::TruncatedFrame);
    }
    d.tcp = Some(TcpInfo {
        src_port: sp,
        dst_port: dp,
        seq,
        ack,
        flags: *flags,
        window,
        header_len: hl as u8,
        checksum,
    });
    d.payload_offset = l3 + ihl + hl;
    d.payload_len = payload_len;
    d.captured_payload_len = captured;
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use pl_synth::net::{self, Fragment, Host, TcpHeader};

    fn tcp_frame(payload: &[u8]) -> Vec<u8> {
        let (a, b) = (Host::new(0, 1), Host::new(1, 1));
        let h = TcpHeader {
            src_port: 1000,
            dst_port: 2000,
            seq: 7,
            ack: 9,
            flags: tcp_flags::PSH | tcp_flags::ACK,
            window: 100,
        };
        let seg = net::tcp(a.ip, b.ip, &h, payload, false);
        let ip = net::ipv4(a.ip, b.ip, 6, 1, Fragment::default(), &seg);
        net::ethernet(b.mac, a.mac, net::ETHERTYPE_IPV4, &ip)
    }

    fn run(f: &[u8]) -> Decoded {
        decode(f, f.len() as u32, Some(LINKTYPE_ETHERNET))
    }

    #[test]
    fn plain_tcp() {
        let d = run(&tcp_frame(b"hello"));
        assert!(d.issues.is_empty(), "{:?}", d.issues);
        assert_eq!(d.tcp.unwrap().checksum, Checksum::Ok);
        assert_eq!((d.payload_offset, d.payload_len), (54, 5));
    }

    #[test]
    fn vlan_tag_is_skipped() {
        let mut f = tcp_frame(b"hello");
        f.splice(12..12, [0x81, 0x00, 0x00, 0x0A]);
        let d = run(&f);
        assert_eq!(d.payload_offset, 58);
        assert_eq!(d.ethernet.unwrap().ether_type, ETHERTYPE_IPV4);
    }

    #[test]
    fn bad_ihl_and_data_offset() {
        let mut f = tcp_frame(b"hello");
        f[14] = 0x44;
        assert_eq!(run(&f).issues, vec![DiagCode::BadIpHeader]);

        let mut f = tcp_frame(b"hello");
        f[14 + 20 + 12] = 0x40;
        assert_eq!(run(&f).issues, vec![DiagCode::BadTcpHeader]);

        let mut f = tcp_frame(b"hello");
        f[14 + 20 + 12] = 0xF0;
        assert_eq!(run(&f).issues, vec![DiagCode::BadTcpHeader]);
    }

    #[test]
    fn total_length_beyond_frame() {
        let mut f = tcp_frame(b"hello");
        f[16] = 0xFF;
        assert_eq!(run(&f).issues, vec![DiagCode::BadIpHeader]);
    }

    #[test]
    fn non_ethernet_and_broken_block() {
        let f = tcp_frame(b"x");
        assert_eq!(
            decode(&f, 60, Some(113)).issues,
            vec![DiagCode::UnsupportedLinkType]
        );
        assert_eq!(decode(&f, 60, None).issues, vec![DiagCode::BadBlock]);
        assert_eq!(run(&f[..10]).issues, vec![DiagCode::NonIp]);
    }
}
