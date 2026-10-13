//! Сдвиг часов журнала действий относительно записи.
//!
//! Журнал ведёт одна машина, трафик пишет другая, и их часы расходятся — на секунды или на целые
//! часы, если перепутан пояс. Тогда в окне времени после действия нет его данных, и обмены
//! не находятся. Здесь оценивается поправка, при которой данные идут сразу за наибольшим числом
//! действий. Это предложение с основанием: применять его или нет, решает исследователь.

use std::sync::Arc;

use serde::Serialize;

use crate::hypothesis::TOLERANCE_NS;
use crate::{LoadedLog, SourceData};

/// Шаг сетки, на которой сравниваются времена действий и данных.
const BUCKET_NS: u64 = 100_000_000;
/// Наибольшая поправка, которую ищем, в шагах сетки: расхождение поясов бывает до 14 часов.
const MAX_SHIFT: i64 = 14 * 3_600 * 10;
/// Поправка меньше этой не предлагается: такое расхождение покрывает окно поиска.
const MIN_OFFSET_MS: i64 = 100;
/// Действий в оценке и пар «действие — занятый шаг сетки»: предел работы на один запрос.
const MAX_ACTIONS: usize = 2_000;
const MAX_PAIRS: usize = 4_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClockOffset {
    /// Действий журнала, относящихся к записям проекта.
    pub actions: u64,
    /// После скольких из них данные идут в окне времени сейчас.
    pub matched_now: u64,
    /// Предлагаемая поправка: прибавить ко времени журнала. `null` — поправка не нужна
    /// или однозначно не определяется.
    pub offset_ms: Option<i64>,
    /// После скольких действий данные шли бы в окне с этой поправкой.
    pub matched_shifted: u64,
    /// Поправка, уже заданная при импорте журнала.
    pub current_offset_ms: i64,
    pub window_ms: u64,
    pub reason: String,
}

/// Кадры с данными в записи: времена по возрастанию и занятые шаги сетки без повторов.
struct Timeline {
    times: Vec<u64>,
    busy: Vec<i64>,
}

fn timeline(data: &SourceData) -> Timeline {
    let mut times: Vec<u64> = data
        .connections
        .iter()
        .flat_map(|c| c.streams.iter())
        .flat_map(|s| s.frames.iter())
        .filter(|f| f.end > f.start && !f.duplicate)
        .filter_map(|f| data.index.frame(f.frame).map(|frame| frame.ts_ns))
        .collect();
    times.sort_unstable();
    let mut busy: Vec<i64> = times.iter().map(|t| bucket(*t)).collect();
    busy.dedup();
    Timeline { times, busy }
}

fn bucket(ts: u64) -> i64 {
    i64::try_from(ts / BUCKET_NS).unwrap_or(i64::MAX)
}

/// Есть ли кадр с данными в окне после момента `ts`.
fn answered(times: &[u64], ts: u64, window_ns: u64) -> bool {
    let from = ts.saturating_sub(TOLERANCE_NS);
    let start = times.partition_point(|t| *t < from);
    times
        .get(start)
        .is_some_and(|t| *t <= ts.saturating_add(window_ns))
}

fn shifted(ts: u64, offset_ns: i128) -> u64 {
    u64::try_from(i128::from(ts) + offset_ns).unwrap_or(0)
}

pub fn clock_offset(sources: &[Arc<SourceData>], log: &LoadedLog, window_ms: u64) -> ClockOffset {
    let window_ns = window_ms.saturating_mul(1_000_000);
    let per_source: Vec<(&SourceData, Timeline)> =
        sources.iter().map(|d| (d.as_ref(), timeline(d))).collect();
    // Действие и записи, к которым оно относится (у журнала без колонки записи — все).
    let pairs: Vec<(u64, Vec<&Timeline>)> = log
        .actions
        .iter()
        .map(|a| {
            let lines: Vec<&Timeline> = per_source
                .iter()
                .filter(|(d, line)| a.belongs_to(&d.name) && !line.times.is_empty())
                .map(|(_, line)| line)
                .collect();
            (a.ts_ns, lines)
        })
        .filter(|(_, lines)| !lines.is_empty())
        .collect();
    let matched = |offset_ns: i128| -> u64 {
        pairs
            .iter()
            .filter(|(ts, lines)| {
                let at = shifted(*ts, offset_ns);
                lines
                    .iter()
                    .any(|line| answered(&line.times, at, window_ns))
            })
            .count() as u64
    };
    let actions = pairs.len() as u64;
    let matched_now = matched(0);
    let mut out = ClockOffset {
        actions,
        matched_now,
        offset_ms: None,
        matched_shifted: matched_now,
        current_offset_ms: log.record.mapping.clock_offset_ms,
        window_ms,
        reason: String::new(),
    };
    if actions == 0 {
        out.reason = "в журнале нет действий, относящихся к записям проекта".to_owned();
        return out;
    }

    // Голосование на сетке: действие отдаёт голос за каждый сдвиг, при котором на его шаг сетки
    // приходятся данные. Общий сдвиг часов соберёт голоса почти всех действий. Чем плотнее запись,
    // тем меньше действий берётся в оценку: предел — число пар.
    let busiest = per_source
        .iter()
        .map(|(_, line)| line.busy.len())
        .max()
        .unwrap_or(1)
        .max(1);
    let sample = (MAX_PAIRS / busiest).clamp(8, MAX_ACTIONS);
    let stride = pairs.len().div_ceil(sample).max(1);
    let size = usize::try_from(2 * MAX_SHIFT + 1).unwrap_or(1);
    let mut votes = vec![0u32; size];
    // Чтобы действие с двумя записями не голосовало за один сдвиг дважды.
    let mut voted_by = vec![0u32; size];
    for (number, (ts, lines)) in pairs.iter().step_by(stride).enumerate() {
        let own = bucket(*ts);
        let mark = number as u32 + 1;
        for line in lines {
            let from = line.busy.partition_point(|b| *b < own - MAX_SHIFT);
            let to = line.busy.partition_point(|b| *b <= own + MAX_SHIFT);
            for busy in line.busy.get(from..to).unwrap_or_default() {
                let Ok(slot) = usize::try_from(busy - own + MAX_SHIFT) else {
                    continue;
                };
                if let (Some(v), Some(by)) = (votes.get_mut(slot), voted_by.get_mut(slot))
                    && *by != mark
                {
                    *by = mark;
                    *v += 1;
                }
            }
        }
    }
    let shift_of = |slot: usize| slot as i64 - MAX_SHIFT;
    // Лучший сдвиг; при равенстве — ближайший к нулю: без нужды часы не двигаем.
    let Some((best, best_votes)) = votes
        .iter()
        .enumerate()
        .filter(|(_, n)| **n > 0)
        .max_by_key(|(slot, n)| (**n, std::cmp::Reverse(shift_of(*slot).abs())))
        .map(|(slot, n)| (shift_of(slot), *n))
    else {
        out.reason = "рядом с действиями журнала в записях нет данных".to_owned();
        return out;
    };
    // Сдвиг на шаг между действиями тоже совмещает почти все действия с чужими данными, но хотя бы
    // одно крайнее остаётся без пары. Если другой сдвиг совмещает столько же — выбора нет.
    let rival = votes
        .iter()
        .enumerate()
        .filter(|(slot, _)| (shift_of(*slot) - best).abs() > 1)
        .map(|(_, n)| *n)
        .max()
        .unwrap_or(0);

    // Поправка — по ранним задержкам вокруг лучшего сдвига: после неё данные идут вслед за действием.
    let step = i128::from(BUCKET_NS);
    let (low, high) = ((i128::from(best) - 1) * step, (i128::from(best) + 2) * step);
    let mut delays: Vec<i128> = Vec::new();
    for (ts, lines) in pairs.iter().step_by(stride) {
        for line in lines {
            let from = line.times.partition_point(|t| *t < shifted(*ts, low));
            delays.extend(
                line.times
                    .get(from..)
                    .unwrap_or_default()
                    .iter()
                    .map(|t| i128::from(*t) - i128::from(*ts))
                    .take_while(|d| *d < high),
            );
        }
    }
    delays.sort_unstable();
    let early = delays.get(delays.len() / 10).copied().unwrap_or(0);
    let offset_ms = i64::try_from(early.div_euclid(10_000_000) * 10).unwrap_or(0);
    let matched_shifted = matched(i128::from(offset_ms) * 1_000_000);

    let ms = |v: i64| format!("{}{v} мс", if v > 0 { "+" } else { "" });
    if offset_ms.abs() < MIN_OFFSET_MS || matched_shifted <= matched_now {
        out.reason = format!(
            "часы согласованы: данные в окне {window_ms} мс идут после {matched_now} из {actions} действий"
        );
    } else if rival >= best_votes {
        out.reason = format!(
            "поправка не определяется однозначно: столько же действий совпадает с данными и при другом сдвиге (один из них — {}, после {matched_shifted} из {actions} действий)",
            ms(offset_ms)
        );
    } else if matched_shifted * 10 < actions * 6 {
        out.reason = format!(
            "общего сдвига не видно: лучший, {}, даёт данные после {matched_shifted} из {actions} действий",
            ms(offset_ms)
        );
    } else {
        out.offset_ms = Some(offset_ms);
        out.matched_shifted = matched_shifted;
        out.reason = format!(
            "с поправкой {} данные в окне {window_ms} мс идут после {matched_shifted} из {actions} действий, без неё — после {matched_now}",
            ms(offset_ms)
        );
    }
    out
}
