//! Подсказка исправления опровергнутой гипотезы: какая правка описания или теста убирает
//! контрпримеры. Перебираются знак, порядок байтов и ширина полей из теста и масштаб значения
//! из журнала; каждая правка проверяется на записях проекта. Выбирает и применяет исследователь.

use std::collections::BTreeSet;
use std::sync::Arc;

use pl_core::{Problem, ProblemKind};
use pl_interp::schema::{At, FieldType};
use pl_interp::{Expr, Interpretation};
use serde::Serialize;

use crate::field_hints::{HintTest, find, find_mut, refers, same_width, split_name};
use crate::{LoadedLog, SourceData, TestOptions, test_hypothesis};

const MAX_FIXES: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixKind {
    /// Знаковое чтение вместо беззнакового или наоборот.
    Sign,
    /// Другой порядок байтов.
    ByteOrder,
    /// Значение из журнала с другим числом знаков после запятой.
    Scale,
    /// Поле шире или уже.
    Width,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Fix {
    pub kind: FixKind,
    /// Что изменить и что это даёт, одной фразой.
    pub summary: String,
    /// Поле, которое меняется (нет у правки теста).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Сообщения, где поле меняется вместе.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_type: Option<FieldType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_type: Option<FieldType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_at: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_at: Option<u32>,
    /// Новый текст теста (у правки масштаба).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test: Option<String>,
    /// Итог теста гипотезы после правки.
    pub result: HintTest,
    /// Контрпримеры остальных гипотез с этим полем — до и после правки.
    pub other_before: u64,
    pub other_after: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FixHints {
    pub hypothesis: String,
    pub test: String,
    /// Итог теста сейчас.
    pub current: HintTest,
    /// Правки, после которых контрпримеров меньше; лучшая первой. Пусто — простой правки нет.
    pub fixes: Vec<Fix>,
}

fn int_type(size: usize, signed: bool, big_endian: bool) -> Option<FieldType> {
    use FieldType::{I8, I16be, I16le, I32be, I32le, U8, U16be, U16le, U32be, U32le};
    Some(match (size, signed, big_endian) {
        (1, false, _) => U8,
        (1, true, _) => I8,
        (2, false, true) => U16be,
        (2, false, false) => U16le,
        (2, true, true) => I16be,
        (2, true, false) => I16le,
        (4, false, true) => U32be,
        (4, false, false) => U32le,
        (4, true, true) => I32be,
        (4, true, false) => I32le,
        _ => return None,
    })
}

fn type_name(ty: FieldType) -> String {
    serde_json::to_value(ty)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// Тот же тест с другим числом знаков после запятой у значения из журнала: `x == action.params.t`
/// ↔ `x == dec(action.params.t, 2)`.
fn rescaled(test: &str, name: &str) -> Vec<(u32, String)> {
    let is_name_char = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '.';
    let Some(pos) = test.match_indices(name).map(|(i, _)| i).find(|i| {
        let before = test.get(..*i).and_then(|s| s.chars().next_back());
        let after = test.get(i + name.len()..).and_then(|s| s.chars().next());
        !before.is_some_and(is_name_char) && !after.is_some_and(is_name_char)
    }) else {
        return Vec::new();
    };
    let (head, tail) = (
        test.get(..pos).unwrap_or_default(),
        test.get(pos + name.len()..).unwrap_or_default(),
    );
    // Уже внутри `dec(имя, k)`: заменяется вся функция.
    let inside = head.trim_end().strip_suffix("dec(").and_then(|outer| {
        let rest = tail.trim_start().strip_prefix(',')?;
        let (digits, after) = rest.split_once(')')?;
        Some((outer, digits.trim().parse::<u32>().ok()?, after))
    });
    let (outer, current, after) = inside.unwrap_or((head, 0, tail));
    (0..=3u32)
        .filter(|k| *k != current)
        .map(|k| {
            let value = if k == 0 {
                name.to_owned()
            } else {
                format!("dec({name}, {k})")
            };
            (k, format!("{outer}{value}{after}"))
        })
        .collect()
}

fn hint_test(id: &str, e: &crate::Evidence) -> HintTest {
    HintTest {
        id: id.to_owned(),
        verdict: e.verdict,
        applicable: e.applicable,
        held: e.held,
        counterexamples: e.counterexamples_total,
    }
}

/// Правки описания и теста, которые уменьшают число контрпримеров гипотезы `hypothesis`.
pub fn hypothesis_fix_hints(
    sources: &[Arc<SourceData>],
    logs: &[Arc<LoadedLog>],
    interpretation: &Interpretation,
    hypothesis: &str,
    options: &TestOptions,
    cancelled: &dyn Fn() -> bool,
) -> Result<FixHints, Problem> {
    let def = interpretation
        .hypotheses
        .iter()
        .find(|h| h.id == hypothesis)
        .ok_or_else(|| {
            Problem::new(
                ProblemKind::NotFound,
                format!("В описании нет гипотезы {hypothesis}."),
            )
        })?;
    let test = def.test.clone().ok_or_else(|| {
        Problem::new(
            ProblemKind::Unprocessable,
            format!("У гипотезы {hypothesis} нет теста: исправлять нечего."),
        )
    })?;
    let expr = Expr::parse(&test).map_err(|e| {
        Problem::new(
            ProblemKind::Unprocessable,
            format!("Тест гипотезы не разобран: {e}."),
        )
    })?;
    let before = test_hypothesis(sources, interpretation, logs, &test, options)?;
    let mut out = FixHints {
        hypothesis: hypothesis.to_owned(),
        test: test.clone(),
        current: hint_test(hypothesis, &before),
        fixes: Vec::new(),
    };
    if before.counterexamples_total == 0 {
        return Ok(out);
    }
    let stopped = || {
        Problem::new(
            ProblemKind::Conflict,
            "Поиск подсказки прерван: слишком много данных для перебора.",
        )
    };
    let better =
        |e: &crate::Evidence| e.held > 0 && e.counterexamples_total < before.counterexamples_total;

    let names = expr.names();
    // Поля сообщения в тесте: `threshold`, `response.threshold`, `items.0.value` → поле группы.
    let mut fields: BTreeSet<String> = BTreeSet::new();
    for name in &names {
        let name = name.strip_prefix("response.").unwrap_or(name);
        if name.starts_with("action.") || name.starts_with("message.") {
            continue;
        }
        let parts: Vec<&str> = name.split('.').collect();
        fields.insert(match parts.as_slice() {
            [group, _, child] => format!("{group}.{child}"),
            _ => name.to_owned(),
        });
    }

    for field in &fields {
        let (group, name) = split_name(field);
        let Some((current, at)) = interpretation
            .messages
            .iter()
            .find_map(|m| find(&m.fields, group, name))
            .filter(|f| f.mask.is_none() && f.ty.int().is_some())
            .map(|f| (f.ty, f.at.clone()))
        else {
            continue;
        };
        let Some(int) = current.int() else { continue };
        let messages: Vec<String> = interpretation
            .messages
            .iter()
            .filter(|m| find(&m.fields, group, name).is_some_and(|f| f.ty == current))
            .map(|m| m.id.clone())
            .collect();
        // Остальные гипотезы с этим полем: правка типа не должна сломать их.
        let others: Vec<String> = interpretation
            .hypotheses
            .iter()
            .filter(|h| h.id != hypothesis)
            .filter_map(|h| h.test.clone())
            .filter(|t| {
                Expr::parse(t).is_ok_and(|e| e.names().iter().any(|n| refers(n, group, name)))
            })
            .collect();
        let count_others = |it: &Interpretation| -> Result<u64, Problem> {
            let mut total = 0;
            for t in &others {
                total += test_hypothesis(sources, it, logs, t, options)?.counterexamples_total;
            }
            Ok(total)
        };
        let other_before = count_others(interpretation)?;

        let mut variants: Vec<(FixKind, FieldType, Option<u32>)> = Vec::new();
        for ty in same_width(current).unwrap_or_default() {
            let Some(other) = ty.int() else { continue };
            if ty == current {
                continue;
            }
            let kind = if other.big_endian() == int.big_endian() {
                FixKind::Sign
            } else {
                FixKind::ByteOrder
            };
            variants.push((kind, ty, None));
        }
        // Ширина: тот же знак, то же начало; у старшего-первым — ещё и тот же младший байт.
        if let (None, At::Abs(start)) = (group, &at) {
            for size in [1usize, 2, 4] {
                if size == int.size() {
                    continue;
                }
                let orders: &[bool] = if size == 1 { &[true] } else { &[true, false] };
                for &big_endian in orders {
                    let Some(ty) = int_type(size, int.signed(), big_endian) else {
                        continue;
                    };
                    variants.push((FixKind::Width, ty, Some(*start)));
                    let aligned = i64::from(*start) + int.size() as i64 - size as i64;
                    if big_endian
                        && let Ok(moved) = u32::try_from(aligned)
                        && moved != *start
                    {
                        variants.push((FixKind::Width, ty, Some(moved)));
                    }
                }
            }
        }

        for (kind, ty, new_at) in variants {
            if cancelled() {
                return Err(stopped());
            }
            let mut it = interpretation.clone();
            for m in &mut it.messages {
                if messages.contains(&m.id)
                    && let Some(f) = find_mut(&mut m.fields, group, name)
                {
                    f.ty = ty;
                    if let Some(new_at) = new_at {
                        f.at = At::Abs(new_at);
                    }
                }
            }
            let after = test_hypothesis(sources, &it, logs, &test, options)?;
            if !better(&after) {
                continue;
            }
            let (from, to) = (type_name(current), type_name(ty));
            let from_at = match &at {
                At::Abs(n) => Some(*n),
                At::Text(_) => None,
            };
            // Словами, как сказал бы инженер; точные типы — в полях правки.
            let signed = to.starts_with('i');
            let order = if to.ends_with("le") {
                "младший байт первым"
            } else {
                "старший байт первым"
            };
            let width = crate::draft::type_size(&to).unwrap_or(0);
            let what = match (kind, new_at, from_at) {
                (FixKind::Sign, ..) if signed => format!("{field}: читать как число со знаком"),
                (FixKind::Sign, ..) => format!("{field}: читать как число без знака"),
                (FixKind::ByteOrder, ..) => format!("{field}: другой порядок байтов — {order}"),
                (_, Some(b), Some(a)) if a != b => {
                    format!("{field}: поле шире — {width} байта с байта {b}")
                }
                _ => format!("{field}: другая ширина — {width} байта"),
            };
            let _ = &from;
            out.fixes.push(Fix {
                kind,
                summary: format!(
                    "{what} — расхождений {} вместо {}, совпадает в {} из {}",
                    after.counterexamples_total,
                    before.counterexamples_total,
                    after.held,
                    after.applicable
                ),
                field: Some(field.clone()),
                messages: messages.clone(),
                from_type: Some(current),
                to_type: Some(ty),
                from_at: new_at.and(from_at),
                to_at: new_at,
                test: None,
                result: hint_test(hypothesis, &after),
                other_before,
                other_after: count_others(&it)?,
            });
        }
    }

    // Масштаб значения из журнала.
    for name in names.iter().filter(|n| n.starts_with("action.")) {
        for (digits, candidate) in rescaled(&test, name) {
            if cancelled() {
                return Err(stopped());
            }
            let Ok(after) = test_hypothesis(sources, interpretation, logs, &candidate, options)
            else {
                continue;
            };
            if !better(&after) {
                continue;
            }
            out.fixes.push(Fix {
                kind: FixKind::Scale,
                summary: format!(
                    "значение из журнала с {digits} знаками после запятой ({candidate}) — расхождений {} вместо {}, совпадает в {} из {}",
                    after.counterexamples_total,
                    before.counterexamples_total,
                    after.held,
                    after.applicable
                ),
                field: None,
                messages: Vec::new(),
                from_type: None,
                to_type: None,
                from_at: None,
                to_at: None,
                test: Some(candidate),
                result: hint_test(hypothesis, &after),
                other_before: 0,
                other_after: 0,
            });
        }
    }

    // Лучше — меньше контрпримеров и побочных противоречий; при равенстве — более простая правка.
    out.fixes.sort_by_key(|f| {
        (
            f.result.counterexamples,
            f.other_after.saturating_sub(f.other_before),
            f.kind,
            std::cmp::Reverse(f.result.held),
        )
    });
    out.fixes.truncate(MAX_FIXES);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_journal_value_is_rescaled_in_place() {
        let plain = rescaled(
            "threshold == action.params.threshold_c",
            "action.params.threshold_c",
        );
        assert_eq!(
            plain,
            vec![
                (
                    1,
                    "threshold == dec(action.params.threshold_c, 1)".to_owned()
                ),
                (
                    2,
                    "threshold == dec(action.params.threshold_c, 2)".to_owned()
                ),
                (
                    3,
                    "threshold == dec(action.params.threshold_c, 3)".to_owned()
                ),
            ]
        );
        let scaled = rescaled("dec( action.params.t , 1) == x && y > 0", "action.params.t");
        assert_eq!(
            scaled.first(),
            Some(&(0, "action.params.t == x && y > 0".to_owned()))
        );
        assert!(scaled.contains(&(2, "dec(action.params.t, 2) == x && y > 0".to_owned())));
        // Имя — часть более длинного имени: это другое значение.
        assert!(rescaled("x == action.params.total", "action.params.t").is_empty());
    }
}
