//! Сценарии клиента: что исследователь делает со штатным клиентом устройства.

use crate::device::Device;
use crate::proto::{self, Message, kind, param};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Act {
    Read(u8),
    Set(u8, i32),
    Measure(u8),
}

fn param_name(id: u8) -> &'static str {
    match id {
        param::SETPOINT => "setpoint",
        param::GAIN => "gain",
        param::MODE => "mode",
        _ => "unknown",
    }
}

impl Act {
    /// Название действия в журнале.
    pub fn name(self) -> &'static str {
        match self {
            Act::Read(_) => "read_param",
            Act::Set(..) => "set_param",
            Act::Measure(_) => "get_measurement",
        }
    }

    /// Параметры действия в журнале: `ключ=значение;…`.
    pub fn params(self) -> String {
        match self {
            Act::Read(id) => format!("param={}", param_name(id)),
            Act::Set(id, value) => format!("param={};value={value}", param_name(id)),
            Act::Measure(channel) => format!("channel={channel}"),
        }
    }

    pub fn request(self, session: u8) -> Message {
        match self {
            Act::Read(id) => proto::read_req(session, id),
            Act::Set(id, value) => proto::set_req(session, id, value),
            Act::Measure(channel) => proto::measure_req(session, channel),
        }
    }

    /// Результат действия, как его видит клиент в своём интерфейсе.
    pub fn result(self, response: &Message) -> String {
        let body = response.body.as_slice();
        let i32_at = |at: usize| {
            body.get(at..at + 4)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map(i32::from_be_bytes)
        };
        match (response.kind, self) {
            (kind::READ_RESP, _) => format!("value={}", i32_at(1).unwrap_or_default()),
            (kind::SET_RESP, _) => {
                let applied = i32_at(2).unwrap_or_default();
                if body.get(1) == Some(&proto::SET_OK) {
                    format!("ok;applied={applied}")
                } else {
                    format!("error=out_of_range;kept={applied}")
                }
            }
            (kind::MEASURE_RESP, _) => {
                let samples: Vec<i16> = body
                    .get(3..)
                    .unwrap_or_default()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| i16::from_be_bytes(*c))
                    .collect();
                format!(
                    "samples={};min={};max={}",
                    samples.len(),
                    samples.iter().min().copied().unwrap_or_default(),
                    samples.iter().max().copied().unwrap_or_default()
                )
            }
            (kind::ERROR, _) => format!("error={}", error_name(body.first().copied())),
            _ => "error=unexpected_response".to_owned(),
        }
    }
}

fn error_name(code: Option<u8>) -> &'static str {
    match code {
        Some(proto::ERR_UNKNOWN_KIND) => "unknown_kind",
        Some(proto::ERR_UNKNOWN_PARAM) => "unknown_param",
        Some(proto::ERR_BAD_CHANNEL) => "bad_channel",
        Some(proto::ERR_MALFORMED) => "malformed",
        _ => "unknown",
    }
}

/// Шаг сценария: действия, отправленные клиентом вместе (несколько запросов в одном пакете).
#[derive(Debug, Clone)]
pub struct Step {
    pub acts: Vec<Act>,
    /// Пауза перед шагом.
    pub pause_ms: u64,
}

#[derive(Debug, Clone)]
pub struct Scenario {
    pub name: &'static str,
    pub description: &'static str,
    pub seed: u64,
    /// `(сеть, узел)` клиента и порт клиента.
    pub client: (u8, u8, u16),
    /// `(сеть, узел)` устройства и его порт.
    pub server: (u8, u8, u16),
    pub steps: Vec<Step>,
}

fn step(pause_ms: u64, acts: &[Act]) -> Step {
    Step {
        acts: acts.to_vec(),
        pause_ms,
    }
}

pub fn main_scenario() -> Scenario {
    use Act::{Measure, Read, Set};
    Scenario {
        name: "main",
        description: "Основная запись: параметры 21, 37 и 1000, измерения трёх каналов",
        seed: 11,
        client: (0, 10, 49320),
        server: (1, 1, 4710),
        steps: vec![
            step(200, &[Read(param::GAIN), Read(param::MODE)]),
            step(900, &[Read(param::SETPOINT)]),
            step(1500, &[Set(param::SETPOINT, 21)]),
            step(700, &[Measure(1)]),
            step(2500, &[Set(param::SETPOINT, 37)]),
            step(700, &[Measure(1)]),
            step(2500, &[Set(param::SETPOINT, 1000)]),
            step(700, &[Measure(2)]),
            step(1800, &[Read(param::SETPOINT)]),
            step(2200, &[Set(param::GAIN, 300)]),
            step(1200, &[Set(param::GAIN, 5), Set(param::MODE, 2)]),
            step(900, &[Measure(1), Measure(2)]),
            step(2000, &[Measure(3)]),
        ],
    }
}

pub fn extra_scenario() -> Scenario {
    use Act::{Measure, Read, Set};
    Scenario {
        name: "extra",
        description: "Дополнительная запись: уставка больше 65535 и отрицательная, другой клиент",
        seed: 23,
        client: (2, 21, 51877),
        server: (1, 1, 4710),
        steps: vec![
            step(300, &[Read(param::SETPOINT)]),
            step(1100, &[Set(param::SETPOINT, 70_000)]),
            step(600, &[Measure(1)]),
            step(2400, &[Set(param::SETPOINT, -5)]),
            step(600, &[Measure(1)]),
            step(2400, &[Set(param::SETPOINT, 123_456)]),
            step(800, &[Read(param::SETPOINT), Measure(2)]),
            step(1900, &[Set(param::MODE, 1)]),
            step(700, &[Measure(3)]),
            step(1500, &[Read(param::GAIN)]),
        ],
    }
}

pub fn all() -> Vec<Scenario> {
    vec![main_scenario(), extra_scenario()]
}

pub fn find(name: &str) -> Option<Scenario> {
    all().into_iter().find(|s| s.name == name)
}

/// Что вернёт устройство на шаг: тот же код, что и в реальном сервере.
pub fn responses(device: &mut Device, requests: &[Message]) -> Vec<Message> {
    requests.iter().map(|r| device.handle(r)).collect()
}
