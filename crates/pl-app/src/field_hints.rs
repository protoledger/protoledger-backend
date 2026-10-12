//! Подсказка типа поля: какое чтение тех же байтов (знак, порядок байтов) согласуется с тестами
//! гипотез и проверками описания. Это подсказка с основаниями — числом контрпримеров при каждом
//! варианте, — а не вывод: выбирает исследователь.

use std::sync::Arc;

use pl_core::{Problem, ProblemKind};
use pl_interp::schema::{FieldDef, FieldType};
use pl_interp::{Expr, Interpretation, Value};
use serde::Serialize;

use crate::{LoadedLog, SourceData, TestOptions, Verdict, stream_input, test_hypothesis};

/// Итог теста гипотезы при одном варианте типа.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HintTest {
    pub id: String,
    pub verdict: Verdict,
    pub applicable: u64,
    pub held: u64,
    pub counterexamples: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeCandidate {
    #[serde(rename = "type")]
    pub ty: FieldType,
    pub current: bool,
    /// Сколько значений поля прочитано и их границы при этом типе.
    pub values: u64,
    pub min: Option<i128>,
    pub max: Option<i128>,
    pub negative: u64,
    /// Нарушения проверок и ожидаемых значений в сообщениях с этим полем.
    pub violations: u64,
    /// Контрпримеры всех тестов гипотез, где участвует поле.
    pub counterexamples: u64,
    pub tests: Vec<HintTest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldHints {
    pub message_id: String,
    pub field: String,
    pub current_type: FieldType,
    /// Типы сообщений, где есть поле с этим именем и типом: вариант проверяется сразу для всех.
    pub messages: Vec<String>,
    /// Гипотезы, в тестах которых участвует поле.
    pub hypotheses: Vec<String>,
    pub candidates: Vec<TypeCandidate>,
    /// Тип с наименьшим числом противоречий, если он лучше текущего; иначе `null`.
    pub suggested: Option<FieldType>,
}

/// Целочисленные типы той же ширины: замена не сдвигает соседние поля.
fn same_width(ty: FieldType) -> Option<Vec<FieldType>> {
    use FieldType::{
        I8, I16be, I16le, I32be, I32le, I64be, I64le, U8, U16be, U16le, U32be, U32le, U64be, U64le,
    };
    Some(match ty.int()?.size() {
        1 => vec![U8, I8],
        2 => vec![U16be, I16be, U16le, I16le],
        4 => vec![U32be, I32be, U32le, I32le],
        _ => vec![U64be, I64be, U64le, I64le],
    })
}

/// Имя поля в описании: `group.child` для поля повторяющейся группы.
fn split_name(field: &str) -> (Option<&str>, &str) {
    match field.split_once('.') {
        Some((group, child)) => (Some(group), child.rsplit('.').next().unwrap_or(child)),
        None => (None, field),
    }
}

fn find<'a>(fields: &'a [FieldDef], group: Option<&str>, name: &str) -> Option<&'a FieldDef> {
    match group {
        None => fields.iter().find(|f| f.name == name),
        Some(g) => fields
            .iter()
            .find(|f| f.name == g)
            .and_then(|f| f.repeat.as_ref())
            .and_then(|r| r.fields.iter().find(|c| c.name == name)),
    }
}

fn find_mut<'a>(
    fields: &'a mut [FieldDef],
    group: Option<&str>,
    name: &str,
) -> Option<&'a mut FieldDef> {
    match group {
        None => fields.iter_mut().find(|f| f.name == name),
        Some(g) => fields
            .iter_mut()
            .find(|f| f.name == g)
            .and_then(|f| f.repeat.as_mut())
            .and_then(|r| r.fields.iter_mut().find(|c| c.name == name)),
    }
}

/// Относится ли имя из результата или выражения к полю: `value`, `response.value`,
/// `items.3.value` для поля группы `items.value`.
fn refers(name: &str, group: Option<&str>, field: &str) -> bool {
    let name = name.strip_prefix("response.").unwrap_or(name);
    match group {
        None => name == field,
        Some(g) => {
            let mut parts = name.split('.');
            matches!(
                (parts.next(), parts.next(), parts.next(), parts.next()),
                (Some(a), Some(n), Some(c), None)
                    if a == g && c == field && n.bytes().all(|b| b.is_ascii_digit())
            )
        }
    }
}

fn unprocessable(detail: impl Into<String>) -> Problem {
    Problem::new(ProblemKind::Unprocessable, detail)
}

/// Подсказка типа для поля `field` сообщения `message_id` на записях проекта.
pub fn field_type_hints(
    sources: &[Arc<SourceData>],
    logs: &[Arc<LoadedLog>],
    interpretation: &Interpretation,
    message_id: &str,
    field: &str,
    options: &TestOptions,
    cancelled: &dyn Fn() -> bool,
) -> Result<FieldHints, Problem> {
    let (group, name) = split_name(field);
    let message = interpretation
        .messages
        .iter()
        .find(|m| m.id == message_id)
        .ok_or_else(|| {
            Problem::new(
                ProblemKind::NotFound,
                format!("В описании нет сообщения {message_id}."),
            )
        })?;
    let def = find(&message.fields, group, name).ok_or_else(|| {
        Problem::new(
            ProblemKind::NotFound,
            format!("В сообщении {message_id} нет поля {field}."),
        )
    })?;
    let current = def.ty;
    let variants = same_width(current).ok_or_else(|| {
        unprocessable(format!(
            "Поле {field} не целочисленное: подсказка типа есть только для целых."
        ))
    })?;
    // Поле с тем же именем и типом в других сообщениях (запрос и ответ) меняется вместе с этим:
    // их связывает одна гипотеза.
    let messages: Vec<String> = interpretation
        .messages
        .iter()
        .filter(|m| find(&m.fields, group, name).is_some_and(|f| f.ty == current))
        .map(|m| m.id.clone())
        .collect();
    let tests: Vec<(String, String)> = interpretation
        .hypotheses
        .iter()
        .filter_map(|h| Some((h.id.clone(), h.test.clone()?)))
        .filter(|(_, test)| {
            Expr::parse(test).is_ok_and(|e| e.names().iter().any(|n| refers(n, group, name)))
        })
        .collect();

    let mut candidates = Vec::new();
    for ty in variants {
        if cancelled() {
            return Err(Problem::new(
                ProblemKind::Conflict,
                "Поиск подсказки прерван.",
            ));
        }
        let mut it = interpretation.clone();
        for m in &mut it.messages {
            if messages.contains(&m.id)
                && let Some(f) = find_mut(&mut m.fields, group, name)
            {
                f.ty = ty;
            }
        }
        let mut candidate = TypeCandidate {
            ty,
            current: ty == current,
            values: 0,
            min: None,
            max: None,
            negative: 0,
            violations: 0,
            counterexamples: 0,
            tests: Vec::new(),
        };
        for data in sources {
            for connection in &data.connections {
                for (i, stream) in connection.streams.iter().enumerate() {
                    let input = stream_input(&data.file, connection, stream, i);
                    let result = pl_interp::apply(&it, &input, cancelled).map_err(|e| {
                        Problem::new(
                            ProblemKind::LimitExceeded,
                            format!("Разбор остановлен: {e}."),
                        )
                    })?;
                    for m in &result.messages {
                        if !m
                            .message_id
                            .as_ref()
                            .is_some_and(|id| messages.contains(id))
                        {
                            continue;
                        }
                        candidate.violations += m.violations.len() as u64;
                        for f in &m.fields {
                            if !refers(&f.name, group, name) {
                                continue;
                            }
                            if let Some(Value::Int(v)) = f.value {
                                candidate.values += 1;
                                candidate.min = Some(candidate.min.map_or(v, |m| m.min(v)));
                                candidate.max = Some(candidate.max.map_or(v, |m| m.max(v)));
                                candidate.negative += u64::from(v < 0);
                            }
                        }
                    }
                }
            }
        }
        for (id, test) in &tests {
            let evidence = test_hypothesis(sources, &it, logs, test, options)?;
            candidate.counterexamples += evidence.counterexamples_total;
            candidate.tests.push(HintTest {
                id: id.clone(),
                verdict: evidence.verdict,
                applicable: evidence.applicable,
                held: evidence.held,
                counterexamples: evidence.counterexamples_total,
            });
        }
        candidates.push(candidate);
    }

    // Лучше — меньше противоречий; при равенстве — больше подтверждений, затем текущий тип.
    let score = |c: &TypeCandidate| {
        (
            c.counterexamples + c.violations,
            std::cmp::Reverse(c.tests.iter().map(|t| t.held).sum::<u64>()),
            !c.current,
        )
    };
    let best = candidates.iter().min_by_key(|c| score(c));
    let current_score = candidates.iter().find(|c| c.current).map(score);
    let suggested = best
        .filter(|b| !b.current && Some(score(b)) < current_score)
        // Без противоречий у текущего типа и без подтверждений у нового советовать нечего.
        .filter(|b| {
            b.tests.iter().any(|t| t.held > 0) || b.violations < current_violations(&candidates)
        })
        .map(|b| b.ty);

    Ok(FieldHints {
        message_id: message_id.to_owned(),
        field: field.to_owned(),
        current_type: current,
        messages,
        hypotheses: tests.into_iter().map(|(id, _)| id).collect(),
        candidates,
        suggested,
    })
}

fn current_violations(candidates: &[TypeCandidate]) -> u64 {
    candidates
        .iter()
        .find(|c| c.current)
        .map_or(0, |c| c.violations)
}
