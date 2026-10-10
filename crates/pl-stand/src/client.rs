//! Клиент по настоящему TCP: выполняет сценарий и пишет журнал действий по системным часам.
//! Запись трафика при этом снимает tcpdump (см. `README` стенда).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::log::LogEntry;
use crate::proto::{Decoder, Message};
use crate::scenario::Scenario;

fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(0))
}

pub fn run(
    addr: SocketAddr,
    scenario: &Scenario,
    speed_up: bool,
) -> std::io::Result<Vec<LogEntry>> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut decoder = Decoder::default();
    let mut log = Vec::new();
    let mut session = 0u8;
    let mut buf = vec![0u8; 16 * 1024];
    for step in &scenario.steps {
        if !speed_up {
            sleep(Duration::from_millis(step.pause_ms));
        }
        let requests: Vec<Message> = step
            .acts
            .iter()
            .map(|act| {
                session = session.wrapping_add(1);
                act.request(session)
            })
            .collect();
        let started = now_us();
        let bytes: Vec<u8> = requests.iter().flat_map(Message::encode).collect();
        stream.write_all(&bytes)?;

        let mut replies = Vec::new();
        while replies.len() < requests.len() {
            let n = stream.read(&mut buf)?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            let got = decoder
                .push(buf.get(..n).unwrap_or_default())
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            replies.extend(got);
        }
        for (act, reply) in step.acts.iter().zip(&replies) {
            log.push(LogEntry {
                ts_us: started,
                action: act.name(),
                params: act.params(),
                result: act.result(reply),
            });
        }
    }
    Ok(log)
}
