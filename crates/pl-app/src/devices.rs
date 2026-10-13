//! Какие соединения принадлежат устройству: те, что передают данные сразу после действий журнала.
//!
//! Это подсказка для выбора соединения среди фонового трафика, а не вывод о протоколе:
//! для каждого соединения — сколько действий его записи «ответили» в нём данными.

use std::collections::BTreeSet;
use std::sync::Arc;

use pl_core::{Problem, ProblemKind};
use serde::Serialize;

use crate::{LoadedLog, SourceData};

/// Доля действий, начиная с которой соединение считаем соединением устройства.
const DEVICE_SHARE: f64 = 0.5;
/// Сколько соединений отдаётся в ответе: в записи их бывает сто тысяч, а нужны первые — устройство.
pub const MAX_DEVICE_CONNECTIONS: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionRole {
    /// Данные идут сразу после большинства действий записи.
    Device,
    /// С действиями не связано: фон.
    Background,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceConnection {
    pub connection: String,
    pub source: String,
    pub a: String,
    pub b: String,
    pub role: ConnectionRole,
    /// Действий записи, после которых в соединении шли данные.
    pub actions_matched: u64,
    /// Действий журнала, относящихся к записи.
    pub actions_total: u64,
    pub share_permille: u32,
    pub payload_frames: u64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceConnections {
    pub window_ms: u64,
    /// Всего соединений в записях; в `items` — не больше предела.
    pub total: u64,
    /// Соединений с ролью устройства среди всех.
    pub devices: u64,
    /// Устройство — первыми, затем по доле совпадений.
    pub items: Vec<DeviceConnection>,
}

pub fn device_connections(
    sources: &[Arc<SourceData>],
    logs: &[Arc<LoadedLog>],
    window_ms: u64,
) -> Result<DeviceConnections, Problem> {
    if logs.iter().all(|l| l.actions.is_empty()) {
        return Err(Problem::new(
            ProblemKind::Conflict,
            "Нужен журнал действий: соединения устройства определяются по совпадению с действиями.",
        ));
    }
    let window_ns = window_ms.saturating_mul(1_000_000);
    let mut items = Vec::new();
    for data in sources {
        let actions: Vec<u64> = logs
            .iter()
            .flat_map(|l| l.actions.iter())
            .filter(|a| a.belongs_to(&data.name))
            .map(|a| a.ts_ns)
            .collect();
        // (время кадра с данными, номер соединения) — по возрастанию времени.
        let mut frames: Vec<(u64, usize)> = Vec::new();
        let mut payload = vec![0u64; data.connections.len()];
        for (n, connection) in data.connections.iter().enumerate() {
            for stream in &connection.streams {
                for f in stream
                    .frames
                    .iter()
                    .filter(|f| f.end > f.start && !f.duplicate)
                {
                    if let Some(frame) = data.index.frame(f.frame) {
                        frames.push((frame.ts_ns, n));
                        if let Some(p) = payload.get_mut(n) {
                            *p += 1;
                        }
                    }
                }
            }
        }
        frames.sort_unstable();
        let mut matched = vec![0u64; data.connections.len()];
        for ts in &actions {
            let from = ts.saturating_sub(crate::hypothesis::TOLERANCE_NS);
            let to = ts.saturating_add(window_ns);
            let start = frames.partition_point(|(t, _)| *t < from);
            let touched: BTreeSet<usize> = frames
                .get(start..)
                .unwrap_or_default()
                .iter()
                .take_while(|(t, _)| *t <= to)
                .map(|(_, n)| *n)
                .collect();
            for n in touched {
                if let Some(m) = matched.get_mut(n) {
                    *m += 1;
                }
            }
        }
        let total = actions.len() as u64;
        for (n, connection) in data.connections.iter().enumerate() {
            let hits = matched.get(n).copied().unwrap_or(0);
            let frames_n = payload.get(n).copied().unwrap_or(0);
            let share = if total == 0 {
                0.0
            } else {
                hits as f64 / total as f64
            };
            let role = if share >= DEVICE_SHARE && frames_n > 0 {
                ConnectionRole::Device
            } else {
                ConnectionRole::Background
            };
            let reason = if total == 0 {
                "к этой записи в журнале нет действий".to_owned()
            } else {
                format!("данные в течение {window_ms} мс после {hits} из {total} действий записи")
            };
            items.push(DeviceConnection {
                connection: connection.id(&data.sha256),
                source: data.sha256.clone(),
                a: connection.a.to_string(),
                b: connection.b.to_string(),
                role,
                actions_matched: hits,
                actions_total: total,
                share_permille: (share * 1000.0).round() as u32,
                payload_frames: frames_n,
                reason,
            });
        }
    }
    items.sort_by(|x, y| {
        (x.role != ConnectionRole::Device)
            .cmp(&(y.role != ConnectionRole::Device))
            .then(y.share_permille.cmp(&x.share_permille))
            .then(x.connection.cmp(&y.connection))
    });
    let total = items.len() as u64;
    let devices = items
        .iter()
        .filter(|c| c.role == ConnectionRole::Device)
        .count() as u64;
    items.truncate(MAX_DEVICE_CONNECTIONS);
    Ok(DeviceConnections {
        window_ms,
        total,
        devices,
        items,
    })
}
