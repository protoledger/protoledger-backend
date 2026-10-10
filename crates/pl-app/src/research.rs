//! Документы исследования: наблюдения (якорь + комментарий), гипотезы (утверждение, основания,
//! тест, статус) и открытые вопросы. Хранятся в проекте как YAML, заменяются целиком и атомарно.

use std::collections::BTreeSet;
use std::sync::Arc;

use pl_core::{Problem, ProblemKind};
use pl_interp::{Expr, Read};
use pl_project::DocKind;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Session, SourceData, SourceStore, stream_input};

pub const MAX_ITEMS: usize = 20_000;
const MAX_TEXT: usize = 10_000;
const DIRECTIONS: [&str; 2] = ["ab", "ba"];

/// Стабильная ссылка на байты направленного потока записи.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorRef {
    pub source: String,
    pub stream: String,
    pub start: u64,
    pub end: u64,
    /// sha256 байтов в момент создания; по нему видно, что при другой сборке они изменились.
    #[serde(default)]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observation {
    pub id: String,
    pub anchor: AnchorRef,
    pub comment: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisStatus {
    Proposed,
    /// Поддержана на примерах: не доказана.
    Supported,
    Refuted,
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Hypothesis {
    pub id: String,
    pub statement: String,
    #[serde(default)]
    pub basis: Vec<String>,
    #[serde(default)]
    pub test: Option<String>,
    pub status: HypothesisStatus,
    #[serde(default)]
    pub superseded_by: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionStatus {
    Open,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Question {
    pub id: String,
    pub text: String,
    pub status: QuestionStatus,
    #[serde(default)]
    pub answer: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Doc<T> {
    items: Vec<T>,
}

/// Элемент с идентификатором вида `<префикс>-<номер>`.
pub trait Item: Serialize + DeserializeOwned + Clone {
    const KIND: DocKind;
    const PREFIX: &'static str;
    fn id(&self) -> &str;
    fn set_id(&mut self, id: String);
}

macro_rules! item {
    ($ty:ty, $kind:expr, $prefix:expr) => {
        impl Item for $ty {
            const KIND: DocKind = $kind;
            const PREFIX: &'static str = $prefix;
            fn id(&self) -> &str {
                &self.id
            }
            fn set_id(&mut self, id: String) {
                self.id = id;
            }
        }
    };
}
item!(Observation, DocKind::Observations, "obs");
item!(Hypothesis, DocKind::Hypotheses, "H");
item!(Question, DocKind::Questions, "q");

fn bad(detail: impl Into<String>) -> Problem {
    Problem::new(ProblemKind::BadRequest, detail)
}

fn not_found(what: &str, id: &str) -> Problem {
    Problem::new(ProblemKind::NotFound, format!("{what} {id} не найдено."))
}

fn parse_doc<T: Item>(text: &str) -> Result<Vec<T>, Problem> {
    let mut budget = serde_saphyr::Budget::default();
    budget.max_aliases = 0;
    budget.max_anchors = 0;
    budget.max_depth = 16;
    budget.max_events = 2_000_000;
    budget.max_nodes = 1_000_000;
    let mut options = serde_saphyr::Options::default();
    options.budget = Some(budget);
    let doc: Doc<T> = serde_saphyr::from_str_with_options(text, options).map_err(|e| {
        Problem::new(
            ProblemKind::Unprocessable,
            format!("Документ исследования повреждён: {e}"),
        )
    })?;
    Ok(doc.items)
}

/// Все элементы документа.
pub fn load<T: Item>(session: &Session) -> Result<Vec<T>, Problem> {
    let guard = session.read();
    let project = guard.as_ref().ok_or_else(Session::no_project)?;
    match project.read_doc(T::KIND).map_err(Problem::from)? {
        Some(text) => parse_doc(&text),
        None => Ok(Vec::new()),
    }
}

fn next_id<T: Item>(items: &[T]) -> String {
    let max = items
        .iter()
        .filter_map(|i| {
            i.id()
                .strip_prefix(T::PREFIX)?
                .trim_start_matches('-')
                .parse::<u64>()
                .ok()
        })
        .max()
        .unwrap_or(0);
    let dash = if T::PREFIX == "H" { "" } else { "-" };
    format!("{}{dash}{}", T::PREFIX, max + 1)
}

/// Читает, изменяет и сохраняет документ под одной блокировкой проекта.
pub fn modify<T: Item, R>(
    session: &Session,
    change: impl FnOnce(&mut Vec<T>) -> Result<R, Problem>,
) -> Result<R, Problem> {
    let mut guard = session.write();
    let project = guard.as_mut().ok_or_else(Session::no_project)?;
    let mut items: Vec<T> = match project.read_doc(T::KIND).map_err(Problem::from)? {
        Some(text) => parse_doc(&text)?,
        None => Vec::new(),
    };
    let result = change(&mut items)?;
    if items.len() > MAX_ITEMS {
        return Err(Problem::new(
            ProblemKind::LimitExceeded,
            "Слишком много записей в документе.",
        ));
    }
    let text = serde_saphyr::to_string(&Doc { items })
        .map_err(|e| Problem::new(ProblemKind::Internal, format!("Документ не сохранён: {e}")))?;
    project.write_doc(T::KIND, &text).map_err(Problem::from)?;
    Ok(result)
}

/// Добавляет элемент с новым идентификатором.
pub fn add<T: Item>(session: &Session, mut item: T) -> Result<T, Problem> {
    modify(session, |items: &mut Vec<T>| {
        item.set_id(next_id(items));
        items.push(item.clone());
        Ok(item)
    })
}

pub fn get<T: Item>(session: &Session, id: &str) -> Result<T, Problem> {
    load::<T>(session)?
        .into_iter()
        .find(|i| i.id() == id)
        .ok_or_else(|| not_found("Запись", id))
}

fn check_text(label: &str, text: &str) -> Result<(), Problem> {
    if text.trim().is_empty() || text.len() > MAX_TEXT {
        return Err(bad(format!("{label}: от 1 до {MAX_TEXT} символов.")));
    }
    Ok(())
}

// ---------------------------------------------------------------- якоря

/// Разбор идентификатора потока `<8 hex>:cNNNN:ab|ba`.
pub fn resolve_stream(store: &SourceStore, id: &str) -> Option<(Arc<SourceData>, usize, usize)> {
    let mut parts = id.split(':');
    let (prefix, conn, dir, None) = (parts.next()?, parts.next()?, parts.next()?, parts.next())
    else {
        return None;
    };
    let number: usize = conn.strip_prefix('c')?.parse().ok()?;
    let dir = DIRECTIONS.iter().position(|d| *d == dir)?;
    let data = store.by_prefix(prefix)?;
    let index = number
        .checked_sub(1)
        .filter(|i| *i < data.connections.len())?;
    Some((data, index, dir))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// sha256 байтов якоря; `None`, если в диапазоне дыра или неоднозначность.
pub fn anchor_bytes_sha(store: &SourceStore, a: &AnchorRef) -> Result<Option<String>, Problem> {
    let (data, conn, dir) = resolve_stream(store, &a.stream)
        .filter(|(d, _, _)| d.sha256 == a.source)
        .ok_or_else(|| bad("Якорь указывает на несуществующий поток."))?;
    let connection = data
        .connections
        .get(conn)
        .ok_or_else(|| bad("Нет такого соединения."))?;
    let stream = connection
        .streams
        .get(dir)
        .ok_or_else(|| bad("Нет такого потока."))?;
    if a.start >= a.end || a.end > stream.length {
        return Err(bad(format!(
            "Диапазон якоря [{}, {}) вне потока длиной {}.",
            a.start, a.end, stream.length
        )));
    }
    let input = stream_input(&data.file, connection, stream, dir);
    Ok(match input.read(a.start, a.end - a.start) {
        Read::Bytes(b) => Some(hex(&Sha256::digest(&b))),
        _ => None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorState {
    /// Байты по якорю те же, что при создании.
    Ok,
    /// Байты изменились (другая политика сборки): наблюдение не «переезжает» молча.
    Broken,
    /// Запись или поток не загружены, либо в диапазоне дыра.
    Unavailable,
}

pub fn anchor_state(store: &SourceStore, a: &AnchorRef) -> AnchorState {
    match (anchor_bytes_sha(store, a), &a.sha256) {
        (Ok(Some(now)), Some(then)) => {
            if &now == then {
                AnchorState::Ok
            } else {
                AnchorState::Broken
            }
        }
        (Ok(Some(_)), None) => AnchorState::Ok,
        _ => AnchorState::Unavailable,
    }
}

// ------------------------------------------------------------ наблюдения

pub fn add_observation(
    session: &Session,
    store: &SourceStore,
    mut anchor: AnchorRef,
    comment: String,
) -> Result<Observation, Problem> {
    check_text("comment", &comment)?;
    anchor.sha256 = anchor_bytes_sha(store, &anchor)?;
    add(
        session,
        Observation {
            id: String::new(),
            anchor,
            comment,
        },
    )
}

pub fn update_observation(
    session: &Session,
    id: &str,
    comment: String,
) -> Result<Observation, Problem> {
    check_text("comment", &comment)?;
    modify(session, |items: &mut Vec<Observation>| {
        let item = items
            .iter_mut()
            .find(|o| o.id == id)
            .ok_or_else(|| not_found("Наблюдение", id))?;
        item.comment = comment;
        Ok(item.clone())
    })
}

/// Наблюдение, на которое ссылается гипотеза, не удаляется: основания нельзя терять молча.
pub fn delete_observation(session: &Session, id: &str) -> Result<(), Problem> {
    let hypotheses: Vec<Hypothesis> = load(session)?;
    if let Some(h) = hypotheses.iter().find(|h| h.basis.iter().any(|b| b == id)) {
        return Err(Problem::new(
            ProblemKind::Conflict,
            format!(
                "Наблюдение {id} — основание гипотезы {}: сначала уберите его из оснований.",
                h.id
            ),
        ));
    }
    modify(session, |items: &mut Vec<Observation>| {
        let before = items.len();
        items.retain(|o| o.id != id);
        if items.len() == before {
            Err(not_found("Наблюдение", id))
        } else {
            Ok(())
        }
    })
}

// -------------------------------------------------------------- гипотезы

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HypothesisInput {
    pub statement: Option<String>,
    pub basis: Option<Vec<String>>,
    pub test: Option<String>,
    pub status: Option<HypothesisStatus>,
    pub superseded_by: Option<String>,
    pub note: Option<String>,
}

fn validate_hypothesis(
    h: &Hypothesis,
    all: &[Hypothesis],
    observations: &[Observation],
) -> Result<(), Problem> {
    check_text("statement", &h.statement)?;
    let known: BTreeSet<&str> = observations.iter().map(|o| o.id.as_str()).collect();
    if let Some(missing) = h.basis.iter().find(|b| !known.contains(b.as_str())) {
        return Err(bad(format!("Основание {missing}: такого наблюдения нет.")));
    }
    if let Some(test) = &h.test {
        Expr::parse(test).map_err(|e| {
            Problem::new(
                ProblemKind::Unprocessable,
                format!("Тест гипотезы не разобран: {e}."),
            )
        })?;
    }
    match (h.status, &h.superseded_by) {
        (HypothesisStatus::Superseded, Some(by)) => {
            if by == &h.id || !all.iter().any(|x| &x.id == by) {
                return Err(bad("supersededBy: нужна другая существующая гипотеза."));
            }
        }
        (HypothesisStatus::Superseded, None) => {
            return Err(bad("Для статуса superseded укажите supersededBy."));
        }
        (_, Some(_)) => return Err(bad("supersededBy только при статусе superseded.")),
        _ => {}
    }
    Ok(())
}

pub fn add_hypothesis(session: &Session, input: HypothesisInput) -> Result<Hypothesis, Problem> {
    let statement = input.statement.ok_or_else(|| bad("Нужен statement."))?;
    let observations: Vec<Observation> = load(session)?;
    let item = Hypothesis {
        id: String::new(),
        statement,
        basis: input.basis.unwrap_or_default(),
        test: input.test,
        status: input.status.unwrap_or(HypothesisStatus::Proposed),
        superseded_by: input.superseded_by,
        note: input.note,
    };
    modify(session, |items: &mut Vec<Hypothesis>| {
        let mut item = item;
        item.set_id(next_id(items));
        if item.status == HypothesisStatus::Superseded {
            return Err(bad("Новая гипотеза не может сразу быть superseded."));
        }
        validate_hypothesis(&item, items, &observations)?;
        items.push(item.clone());
        Ok(item)
    })
}

pub fn update_hypothesis(
    session: &Session,
    id: &str,
    input: HypothesisInput,
) -> Result<Hypothesis, Problem> {
    let observations: Vec<Observation> = load(session)?;
    modify(session, |items: &mut Vec<Hypothesis>| {
        let snapshot = items.clone();
        let item = items
            .iter_mut()
            .find(|h| h.id == id)
            .ok_or_else(|| not_found("Гипотеза", id))?;
        if let Some(v) = input.statement {
            item.statement = v;
        }
        if let Some(v) = input.basis {
            item.basis = v;
        }
        if let Some(v) = input.test {
            item.test = if v.trim().is_empty() { None } else { Some(v) };
        }
        if let Some(v) = input.status {
            item.status = v;
            if v != HypothesisStatus::Superseded && input.superseded_by.is_none() {
                item.superseded_by = None;
            }
        }
        if let Some(v) = input.superseded_by {
            item.superseded_by = Some(v);
        }
        if let Some(v) = input.note {
            item.note = Some(v);
        }
        validate_hypothesis(item, &snapshot, &observations)?;
        Ok(item.clone())
    })
}

pub fn delete_hypothesis(session: &Session, id: &str) -> Result<(), Problem> {
    modify(session, |items: &mut Vec<Hypothesis>| {
        if let Some(h) = items
            .iter()
            .find(|h| h.superseded_by.as_deref() == Some(id))
        {
            return Err(Problem::new(
                ProblemKind::Conflict,
                format!("Гипотеза {id} заменяет {}: сначала поправьте её.", h.id),
            ));
        }
        let before = items.len();
        items.retain(|h| h.id != id);
        if items.len() == before {
            Err(not_found("Гипотеза", id))
        } else {
            Ok(())
        }
    })
}

// --------------------------------------------------------------- вопросы

pub fn add_question(session: &Session, text: String) -> Result<Question, Problem> {
    check_text("text", &text)?;
    add(
        session,
        Question {
            id: String::new(),
            text,
            status: QuestionStatus::Open,
            answer: None,
        },
    )
}

pub fn update_question(
    session: &Session,
    id: &str,
    text: Option<String>,
    status: Option<QuestionStatus>,
    answer: Option<String>,
) -> Result<Question, Problem> {
    if let Some(t) = &text {
        check_text("text", t)?;
    }
    modify(session, |items: &mut Vec<Question>| {
        let item = items
            .iter_mut()
            .find(|q| q.id == id)
            .ok_or_else(|| not_found("Вопрос", id))?;
        if let Some(t) = text {
            item.text = t;
        }
        if let Some(s) = status {
            item.status = s;
        }
        if let Some(a) = answer {
            item.answer = Some(a);
        }
        Ok(item.clone())
    })
}

pub fn delete_question(session: &Session, id: &str) -> Result<(), Problem> {
    modify(session, |items: &mut Vec<Question>| {
        let before = items.len();
        items.retain(|q| q.id != id);
        if items.len() == before {
            Err(not_found("Вопрос", id))
        } else {
            Ok(())
        }
    })
}
