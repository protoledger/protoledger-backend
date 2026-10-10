use std::net::Ipv4Addr;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_UDP: u8 = 17;

/// Кадры короче минимума Ethernet дополняются нулями, как у принимающей стороны:
/// разборщик обязан брать длину из заголовка IPv4, а не из кадра.
const ETH_MIN_FRAME: usize = 60;

pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Host {
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
}

impl Host {
    /// Узел `10.0.<net>.<id>` с локально администрируемым MAC.
    pub fn new(net: u8, id: u8) -> Self {
        Self {
            mac: [0x02, 0, 0, 0, net, id],
            ip: Ipv4Addr::new(10, 0, net, id),
        }
    }
}

fn sum16(data: &[u8], mut acc: u32) -> u32 {
    for c in data.chunks(2) {
        acc += match c {
            [hi, lo] => u32::from(u16::from_be_bytes([*hi, *lo])),
            [hi] => u32::from(*hi) << 8,
            _ => 0,
        };
    }
    acc
}

fn finish(mut acc: u32) -> u16 {
    while acc > 0xFFFF {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    !(acc as u16)
}

/// Контрольная сумма Интернета (RFC 1071).
pub fn checksum(data: &[u8]) -> u16 {
    finish(sum16(data, 0))
}

fn pseudo_header_sum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, len: usize) -> u32 {
    let mut ph = Vec::with_capacity(12);
    ph.extend_from_slice(&src.octets());
    ph.extend_from_slice(&dst.octets());
    ph.extend_from_slice(&[0, proto]);
    ph.extend_from_slice(&(len as u16).to_be_bytes());
    sum16(&ph, 0)
}

pub fn ethernet(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity((14 + payload.len()).max(ETH_MIN_FRAME));
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    if f.len() < ETH_MIN_FRAME {
        f.resize(ETH_MIN_FRAME, 0);
    }
    f
}

/// Поле «флаги + смещение фрагмента» IPv4.
#[derive(Clone, Copy, Debug, Default)]
pub struct Fragment {
    pub more: bool,
    /// Смещение в единицах по 8 байт.
    pub offset8: u16,
}

pub fn ipv4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    ident: u16,
    frag: Fragment,
    payload: &[u8],
) -> Vec<u8> {
    let total = 20 + payload.len();
    let flags_off = if frag.more || frag.offset8 > 0 {
        (u16::from(frag.more) << 13) | (frag.offset8 & 0x1FFF)
    } else {
        0x4000 // DF
    };
    let mut h = Vec::with_capacity(total);
    h.extend_from_slice(&[0x45, 0]);
    h.extend_from_slice(&(total as u16).to_be_bytes());
    h.extend_from_slice(&ident.to_be_bytes());
    h.extend_from_slice(&flags_off.to_be_bytes());
    h.extend_from_slice(&[64, proto, 0, 0]);
    h.extend_from_slice(&src.octets());
    h.extend_from_slice(&dst.octets());
    let cs = checksum(&h);
    h[10..12].copy_from_slice(&cs.to_be_bytes());
    h.extend_from_slice(payload);
    h
}

#[derive(Clone, Copy, Debug)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
}

/// Сегмент TCP с заголовком 20 байт. `bad_checksum` — заведомо неверная сумма.
pub fn tcp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    h: &TcpHeader,
    payload: &[u8],
    bad_checksum: bool,
) -> Vec<u8> {
    let mut s = Vec::with_capacity(20 + payload.len());
    s.extend_from_slice(&h.src_port.to_be_bytes());
    s.extend_from_slice(&h.dst_port.to_be_bytes());
    s.extend_from_slice(&h.seq.to_be_bytes());
    s.extend_from_slice(&h.ack.to_be_bytes());
    s.extend_from_slice(&[5 << 4, h.flags]);
    s.extend_from_slice(&h.window.to_be_bytes());
    s.extend_from_slice(&[0, 0, 0, 0]);
    s.extend_from_slice(payload);
    let mut cs = finish(sum16(
        &s,
        pseudo_header_sum(src, dst, IP_PROTO_TCP, s.len()),
    ));
    if bad_checksum {
        cs = cs.wrapping_add(0x1111);
    }
    s[16..18].copy_from_slice(&cs.to_be_bytes());
    s
}

pub fn udp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut s = Vec::with_capacity(len);
    s.extend_from_slice(&sport.to_be_bytes());
    s.extend_from_slice(&dport.to_be_bytes());
    s.extend_from_slice(&(len as u16).to_be_bytes());
    s.extend_from_slice(&[0, 0]);
    s.extend_from_slice(payload);
    let cs = finish(sum16(&s, pseudo_header_sum(src, dst, IP_PROTO_UDP, len)));
    s[6..8].copy_from_slice(&cs.to_be_bytes());
    s
}

/// ARP-запрос «кто имеет `target`» широковещательным кадром.
pub fn arp_request(sender: Host, target: Ipv4Addr) -> Vec<u8> {
    let mut a = Vec::with_capacity(28);
    a.extend_from_slice(&[0, 1, 0x08, 0, 6, 4, 0, 1]);
    a.extend_from_slice(&sender.mac);
    a.extend_from_slice(&sender.ip.octets());
    a.extend_from_slice(&[0; 6]);
    a.extend_from_slice(&target.octets());
    ethernet([0xFF; 6], sender.mac, ETHERTYPE_ARP, &a)
}

/// IPv6 + UDP между link-local адресами; содержимое для разбора неважно.
pub fn ipv6_udp(src: Host, dst: Host, payload: &[u8]) -> Vec<u8> {
    let link_local = |h: Host| {
        let mut a = [0u8; 16];
        a[0] = 0xFE;
        a[1] = 0x80;
        a[10..16].copy_from_slice(&h.mac);
        a
    };
    let len = 8 + payload.len();
    let mut p = Vec::with_capacity(40 + len);
    p.extend_from_slice(&[0x60, 0, 0, 0]);
    p.extend_from_slice(&(len as u16).to_be_bytes());
    p.extend_from_slice(&[IP_PROTO_UDP, 64]);
    p.extend_from_slice(&link_local(src));
    p.extend_from_slice(&link_local(dst));
    p.extend_from_slice(&5353u16.to_be_bytes());
    p.extend_from_slice(&5353u16.to_be_bytes());
    p.extend_from_slice(&(len as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    ethernet(dst.mac, src.mac, ETHERTYPE_IPV6, &p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_rfc1071_example() {
        let data = [0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7];
        assert_eq!(checksum(&data), !0xDDF2);
    }

    #[test]
    fn ipv4_header_verifies_to_zero() {
        let p = ipv4(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 1, 1),
            IP_PROTO_TCP,
            1,
            Fragment::default(),
            &[1, 2, 3],
        );
        assert_eq!(checksum(&p[..20]), 0);
    }

    #[test]
    fn short_frames_are_padded() {
        let f = ethernet([0; 6], [1; 6], ETHERTYPE_IPV4, &[0; 10]);
        assert_eq!(f.len(), ETH_MIN_FRAME);
    }
}
