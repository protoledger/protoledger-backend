//! Бинарный протокол стенда. Это тестовые данные: продукт ничего о нём не знает.
//!
//! ```text
//! +------+------+------+------+--------+--------+----------+----------+
//! | 5A   | C3   | тип  | сеанс| длина тела u16 LE | тело ... | сумма u8 |
//! +------+------+------+------+--------+--------+----------+----------+
//! ```
//! Сумма — сумма всех предыдущих байтов сообщения по модулю 256. Значения в теле — big-endian
//! (длина в заголовке — little-endian: намеренная «странность» для исследования).

pub const SIGNATURE: [u8; 2] = [0x5A, 0xC3];
pub const HEADER_LEN: usize = 6;
pub const MAX_BODY: usize = 65_535;

pub mod kind {
    pub const READ_REQ: u8 = 0x01;
    pub const SET_REQ: u8 = 0x02;
    pub const MEASURE_REQ: u8 = 0x03;
    pub const READ_RESP: u8 = 0x81;
    pub const SET_RESP: u8 = 0x82;
    pub const MEASURE_RESP: u8 = 0x83;
    pub const ERROR: u8 = 0xFF;
}

pub mod param {
    pub const SETPOINT: u8 = 1;
    pub const GAIN: u8 = 2;
    pub const MODE: u8 = 3;
}

pub const SET_OK: u8 = 0;
pub const SET_OUT_OF_RANGE: u8 = 1;

pub const ERR_UNKNOWN_KIND: u8 = 1;
pub const ERR_UNKNOWN_PARAM: u8 = 2;
pub const ERR_BAD_CHANNEL: u8 = 3;
pub const ERR_MALFORMED: u8 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub kind: u8,
    pub session: u8,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    BadSignature,
    BadChecksum,
}

fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |acc, b| acc.wrapping_add(*b))
}

impl Message {
    pub fn new(kind: u8, session: u8, body: Vec<u8>) -> Self {
        Self {
            kind,
            session,
            body,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let len = u16::try_from(self.body.len()).unwrap_or(u16::MAX);
        let mut out = Vec::with_capacity(HEADER_LEN + self.body.len() + 1);
        out.extend_from_slice(&SIGNATURE);
        out.push(self.kind);
        out.push(self.session);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(self.body.get(..usize::from(len)).unwrap_or_default());
        out.push(checksum(&out));
        out
    }
}

/// Накопитель потока: выделяет сообщения из произвольно нарезанных байтов.
#[derive(Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Message>, ProtoError> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            if self.buf.len() < HEADER_LEN {
                break;
            }
            if self.buf.get(..2) != Some(&SIGNATURE[..]) {
                return Err(ProtoError::BadSignature);
            }
            let len = usize::from(u16::from_le_bytes([
                self.buf.get(4).copied().unwrap_or(0),
                self.buf.get(5).copied().unwrap_or(0),
            ]));
            let total = HEADER_LEN + len + 1;
            if self.buf.len() < total {
                break;
            }
            let frame: Vec<u8> = self.buf.drain(..total).collect();
            let (content, tail) = frame.split_at(total - 1);
            if tail.first().copied() != Some(checksum(content)) {
                return Err(ProtoError::BadChecksum);
            }
            out.push(Message {
                kind: content.get(2).copied().unwrap_or(0),
                session: content.get(3).copied().unwrap_or(0),
                body: content.get(HEADER_LEN..).unwrap_or_default().to_vec(),
            });
        }
        Ok(out)
    }
}

pub fn read_req(session: u8, param: u8) -> Message {
    Message::new(kind::READ_REQ, session, vec![param])
}

pub fn set_req(session: u8, param: u8, value: i32) -> Message {
    let mut body = vec![param];
    body.extend_from_slice(&value.to_be_bytes());
    Message::new(kind::SET_REQ, session, body)
}

pub fn measure_req(session: u8, channel: u8) -> Message {
    Message::new(kind::MEASURE_REQ, session, vec![channel])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_arbitrary_chunking() {
        let a = set_req(7, param::SETPOINT, 21).encode();
        let b = measure_req(8, 2).encode();
        let all = [a.clone(), b.clone()].concat();
        let mut decoder = Decoder::default();
        let mut got = Vec::new();
        for chunk in all.chunks(3) {
            got.extend(decoder.push(chunk).unwrap());
        }
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].kind, kind::SET_REQ);
        assert_eq!(got[0].body, [1, 0, 0, 0, 21]);
        assert_eq!(got[1].session, 8);
        assert_eq!(a.len(), HEADER_LEN + 5 + 1);
    }

    #[test]
    fn corrupted_input_is_rejected() {
        let mut bad = read_req(1, 1).encode();
        bad[0] = 0;
        assert_eq!(Decoder::default().push(&bad), Err(ProtoError::BadSignature));
        let mut bad = read_req(1, 1).encode();
        let last = bad.len() - 1;
        bad[last] ^= 0xFF;
        assert_eq!(Decoder::default().push(&bad), Err(ProtoError::BadChecksum));
    }

    #[test]
    fn length_is_little_endian() {
        let m = Message::new(kind::MEASURE_RESP, 1, vec![0; 300]).encode();
        assert_eq!(&m[4..6], &300u16.to_le_bytes());
    }
}
