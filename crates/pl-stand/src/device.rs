//! Логика устройства и TCP-сервер.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use crate::proto::{self, Decoder, Message, kind, param};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    setpoint: i32,
    gain: i32,
    mode: i32,
}

impl Default for Device {
    fn default() -> Self {
        Self {
            setpoint: 0,
            gain: 1,
            mode: 0,
        }
    }
}

fn error(session: u8, code: u8, text: &str) -> Message {
    let mut body = vec![code];
    body.extend_from_slice(text.as_bytes());
    Message::new(kind::ERROR, session, body)
}

fn be_i32(bytes: &[u8]) -> Option<i32> {
    Some(i32::from_be_bytes(bytes.try_into().ok()?))
}

impl Device {
    fn get(&self, id: u8) -> Option<i32> {
        match id {
            param::SETPOINT => Some(self.setpoint),
            param::GAIN => Some(self.gain),
            param::MODE => Some(self.mode),
            _ => None,
        }
    }

    /// Допустимые значения параметра; уставка — любое число i32.
    fn in_range(id: u8, value: i32) -> bool {
        match id {
            param::GAIN => (0..=255).contains(&value),
            param::MODE => (0..=3).contains(&value),
            _ => true,
        }
    }

    /// Число отсчётов измерения по каналу; канал 3 — ответ около 60 КиБ.
    pub fn channel_samples(channel: u8) -> Option<usize> {
        match channel {
            1 => Some(8),
            2 => Some(300),
            3 => Some(30_000),
            _ => None,
        }
    }

    fn sample(&self, i: usize) -> i16 {
        let wave = i64::try_from((i * 37) % 100).unwrap_or(0) * i64::from(self.gain);
        let value = i64::from(self.setpoint) / 10 + wave - 50 * i64::from(self.mode);
        i16::try_from(value.clamp(i64::from(i16::MIN), i64::from(i16::MAX))).unwrap_or(0)
    }

    pub fn handle(&mut self, request: &Message) -> Message {
        let session = request.session;
        let body = request.body.as_slice();
        match request.kind {
            kind::READ_REQ => {
                let Some(&id) = body.first() else {
                    return error(session, proto::ERR_MALFORMED, "empty body");
                };
                match self.get(id) {
                    Some(value) => {
                        let mut out = vec![id];
                        out.extend_from_slice(&value.to_be_bytes());
                        Message::new(kind::READ_RESP, session, out)
                    }
                    None => error(session, proto::ERR_UNKNOWN_PARAM, "unknown parameter"),
                }
            }
            kind::SET_REQ => {
                let (Some(&id), Some(value)) = (body.first(), body.get(1..).and_then(be_i32))
                else {
                    return error(session, proto::ERR_MALFORMED, "bad set request");
                };
                if self.get(id).is_none() {
                    return error(session, proto::ERR_UNKNOWN_PARAM, "unknown parameter");
                }
                let status = if Self::in_range(id, value) {
                    match id {
                        param::SETPOINT => self.setpoint = value,
                        param::GAIN => self.gain = value,
                        _ => self.mode = value,
                    }
                    proto::SET_OK
                } else {
                    proto::SET_OUT_OF_RANGE
                };
                let applied = self.get(id).unwrap_or(0);
                let mut out = vec![id, status];
                out.extend_from_slice(&applied.to_be_bytes());
                Message::new(kind::SET_RESP, session, out)
            }
            kind::MEASURE_REQ => {
                let channel = body.first().copied().unwrap_or(0);
                let Some(count) = Self::channel_samples(channel) else {
                    return error(session, proto::ERR_BAD_CHANNEL, "bad channel");
                };
                let mut out = vec![channel];
                out.extend_from_slice(&u16::try_from(count).unwrap_or(u16::MAX).to_le_bytes());
                for i in 0..count {
                    out.extend_from_slice(&self.sample(i).to_be_bytes());
                }
                Message::new(kind::MEASURE_RESP, session, out)
            }
            _ => error(session, proto::ERR_UNKNOWN_KIND, "unknown message"),
        }
    }
}

fn serve_connection(mut stream: TcpStream) {
    let mut device = Device::default();
    let mut decoder = Decoder::default();
    let mut buf = [0u8; 4096];
    loop {
        let Ok(n) = stream.read(&mut buf) else { return };
        if n == 0 {
            return;
        }
        let Ok(requests) = decoder.push(buf.get(..n).unwrap_or_default()) else {
            return;
        };
        // Ответы на пачку запросов уходят одной записью: в сети они могут слиться в один сегмент.
        let mut out = Vec::new();
        for request in &requests {
            out.extend_from_slice(&device.handle(request).encode());
        }
        if !out.is_empty() && stream.write_all(&out).is_err() {
            return;
        }
    }
}

/// Принимает соединения, каждое обслуживается отдельным потоком со своим состоянием устройства.
pub fn serve(listener: TcpListener) {
    for stream in listener.incoming().flatten() {
        thread::spawn(move || serve_connection(stream));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{measure_req, read_req, set_req};

    #[test]
    fn set_then_read() {
        let mut d = Device::default();
        let r = d.handle(&set_req(1, param::SETPOINT, 70_000));
        assert_eq!(r.kind, kind::SET_RESP);
        assert_eq!(r.body, [1, 0, 0, 1, 0x11, 0x70]);
        let r = d.handle(&read_req(2, param::SETPOINT));
        assert_eq!(r.body, [1, 0, 1, 0x11, 0x70]);
    }

    #[test]
    fn out_of_range_keeps_value() {
        let mut d = Device::default();
        let r = d.handle(&set_req(1, param::GAIN, 300));
        assert_eq!(r.body[1], proto::SET_OUT_OF_RANGE);
        assert_eq!(i32::from_be_bytes(r.body[2..6].try_into().unwrap()), 1);
    }

    #[test]
    fn errors_for_unknown_input() {
        let mut d = Device::default();
        assert_eq!(d.handle(&read_req(1, 99)).kind, kind::ERROR);
        assert_eq!(d.handle(&measure_req(1, 9)).kind, kind::ERROR);
        assert_eq!(d.handle(&Message::new(0x42, 1, vec![])).kind, kind::ERROR);
        assert_eq!(
            d.handle(&Message::new(kind::SET_REQ, 1, vec![1])).kind,
            kind::ERROR
        );
    }

    #[test]
    fn big_measurement_fits_the_length_field() {
        let mut d = Device::default();
        let r = d.handle(&measure_req(1, 3)).encode();
        assert!(r.len() > 60_000 && r.len() <= proto::MAX_BODY + proto::HEADER_LEN + 1);
    }
}
