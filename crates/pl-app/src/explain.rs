//! «Объясни байт»: всё, что известно о байте потока, одним ответом — из какого он кадра, к какому
//! сообщению и полю относится, на правило или гипотезу опирается, какие наблюдения его касаются
//! и в каких прогонах он проверен. Происхождение любого вывода видно от самого байта.

use pl_core::{Problem, ProblemKind};
use pl_interp::schema::Status;
use pl_interp::{Category, FieldState, Interpretation, Read};
use pl_verify::{Run, ViolationRow};
use serde::Serialize;

use crate::research::{Hypothesis, HypothesisStatus, Observation};
use crate::{Session, SourceStore, resolve_stream, stream_input};

/// Столько последних прогонов просматривается.
const MAX_RUNS: usize = 20;
const MAX_FRAMES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ByteKind {
    /// Байт известен однозначно.
    Data,
    /// Байт не записан: дыра в потоке.
    Gap,
    /// Кадры расходятся в этом байте.
    Ambiguous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ByteFrame {
    /// Номер кадра в записи, с единицы.
    pub frame: u32,
    pub ts_ns: u64,
    /// Какие байты потока принёс кадр.
    pub start: u64,
    pub end: u64,
    /// Кадр повторяет уже полученные байты.
    pub duplicate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ByteMessage {
    pub start: u64,
    pub end: u64,
    pub message_id: Option<String>,
    pub category: Category,
    /// Смещение байта от начала сообщения.
    pub offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ByteHypothesis {
    pub id: String,
    pub statement: String,
    pub test: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ByteField {
    pub name: String,
    pub start: u64,
    pub end: u64,
    pub status: Status,
    pub state: FieldState,
    /// Прочитанное значение, как его показывает разбор.
    pub value: Option<String>,
    /// Гипотеза описания, на которую опирается поле.
    pub hypothesis: Option<ByteHypothesis>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ByteObservation {
    pub id: String,
    pub comment: String,
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ByteProjectHypothesis {
    pub id: String,
    pub statement: String,
    pub status: HypothesisStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ByteRun {
    pub id: String,
    pub revision: Option<u32>,
    /// Прогон выполнен на том же тексте описания, что объясняет байт сейчас.
    pub same_interpretation: bool,
    /// Категория сообщения с этим байтом в прогоне; `null` — байт вне сообщений.
    pub category: Option<Category>,
    pub message_id: Option<String>,
    /// Нарушения в сообщении с этим байтом.
    pub violations: Vec<ViolationRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ByteExplanation {
    pub stream: String,
    pub offset: u64,
    pub kind: ByteKind,
    /// Значение байта; `null` — не записан или неоднозначен без принятого варианта.
    pub value: Option<u8>,
    pub frames: Vec<ByteFrame>,
    /// Сообщение по текущему описанию; `null` — описания нет, поток вне его области или байт
    /// не попал ни в одно сообщение.
    pub message: Option<ByteMessage>,
    /// Поля, в которые входит байт, от внешнего к внутреннему (группа, затем её элемент).
    pub fields: Vec<ByteField>,
    pub observations: Vec<ByteObservation>,
    /// Гипотезы исследователя, основанные на этих наблюдениях.
    pub hypotheses: Vec<ByteProjectHypothesis>,
    /// Прогоны, в корпус которых входил поток, от нового к старому.
    pub runs: Vec<ByteRun>,
}

/// Всё известное о байте `offset` потока `stream_id`. `it` — описание, по которому байт
/// относится к сообщению и полю; без него объясняется только происхождение байта.
pub fn explain_byte(
    session: &Session,
    store: &SourceStore,
    stream_id: &str,
    offset: u64,
    it: Option<&Interpretation>,
    cancelled: &dyn Fn() -> bool,
) -> Result<ByteExplanation, Problem> {
    let missing = || {
        Problem::new(
            ProblemKind::NotFound,
            format!("Потока {stream_id} нет в проекте."),
        )
    };
    let (data, conn, dir) = resolve_stream(store, stream_id).ok_or_else(missing)?;
    let connection = data.connections.get(conn).ok_or_else(missing)?;
    let stream = connection.streams.get(dir).ok_or_else(missing)?;
    if offset >= stream.length {
        return Err(Problem::new(
            ProblemKind::BadRequest,
            format!("В потоке {} байт: смещения {offset} нет.", stream.length),
        ));
    }
    let input = stream_input(&data.file, connection, stream, dir);
    let (kind, value) = match input.read(offset, 1) {
        Read::Bytes(b) => (ByteKind::Data, b.first().copied()),
        Read::Ambiguous => (ByteKind::Ambiguous, None),
        _ => (ByteKind::Gap, None),
    };
    let frames = stream
        .frames
        .iter()
        .filter(|f| f.start <= offset && offset < f.end)
        .take(MAX_FRAMES)
        .map(|f| ByteFrame {
            frame: f.frame,
            ts_ns: data.index.frame(f.frame).map_or(0, |r| r.ts_ns),
            start: f.start,
            end: f.end,
            duplicate: f.duplicate,
        })
        .collect();

    let mut message = None;
    let mut fields = Vec::new();
    if let Some(it) = it {
        let result = pl_interp::apply(it, &input, cancelled).map_err(|e| {
            Problem::new(
                ProblemKind::LimitExceeded,
                format!("Разбор остановлен: {e}."),
            )
        })?;
        if let Some(m) = result
            .messages
            .iter()
            .find(|m| m.start <= offset && offset < m.end)
        {
            message = Some(ByteMessage {
                start: m.start,
                end: m.end,
                message_id: m.message_id.clone(),
                category: m.category,
                offset: offset - m.start,
            });
            fields = m
                .fields
                .iter()
                .filter(|f| {
                    !matches!(f.state, FieldState::OutOfMessage)
                        && f.at <= offset
                        && offset < f.at + f.len
                })
                .map(|f| ByteField {
                    name: f.name.clone(),
                    start: f.at,
                    end: f.at + f.len,
                    status: f.status,
                    state: f.state,
                    value: f.value.as_ref().map(ToString::to_string),
                    hypothesis: f.hypothesis.as_ref().and_then(|id| {
                        it.hypotheses
                            .iter()
                            .find(|h| &h.id == id)
                            .map(|h| ByteHypothesis {
                                id: h.id.clone(),
                                statement: h.statement.clone(),
                                test: h.test.clone(),
                            })
                    }),
                })
                .collect();
        }
    }

    // Наблюдения с якорем на этот байт и гипотезы исследователя, которые на них опираются.
    let observations: Vec<ByteObservation> = crate::research::load::<Observation>(session)?
        .into_iter()
        .filter(|o| {
            o.anchor.stream == stream_id && o.anchor.start <= offset && offset < o.anchor.end
        })
        .map(|o| ByteObservation {
            id: o.id,
            comment: o.comment,
            start: o.anchor.start,
            end: o.anchor.end,
        })
        .collect();
    let hypotheses = crate::research::load::<Hypothesis>(session)?
        .into_iter()
        .filter(|h| {
            h.basis
                .iter()
                .any(|b| observations.iter().any(|o| &o.id == b))
        })
        .map(|h| ByteProjectHypothesis {
            id: h.id,
            statement: h.statement,
            status: h.status,
        })
        .collect();

    // Прогоны читаются с диска: под блокировкой только короткое чтение текста.
    let digest = it.map(Interpretation::digest);
    let texts: Vec<String> = {
        let guard = session.read();
        let project = guard.as_ref().ok_or_else(Session::no_project)?;
        project
            .run_ids()
            .into_iter()
            .rev()
            .take(MAX_RUNS)
            .filter_map(|id| project.read_run(id).ok())
            .collect()
    };
    let mut runs = Vec::new();
    for text in texts {
        let Ok(run) = serde_json::from_str::<Run>(&text) else {
            continue;
        };
        let Some(stream_run) = run.streams.iter().find(|s| s.id == stream_id) else {
            continue;
        };
        let row = stream_run
            .messages
            .iter()
            .find(|m| m.0 <= offset && offset < m.1);
        runs.push(ByteRun {
            same_interpretation: digest.as_ref() == Some(&run.inputs.interpretation_digest),
            revision: run.inputs.revision,
            category: row.map(|m| m.2),
            message_id: row.and_then(|m| m.3.clone()),
            violations: run
                .counterexamples
                .iter()
                .filter(|c| {
                    c.anchor.stream == stream_id
                        && c.anchor.start <= offset
                        && offset < c.anchor.end
                })
                .flat_map(|c| c.violations.iter().cloned())
                .collect(),
            id: run.id,
        });
    }

    Ok(ByteExplanation {
        stream: stream_id.to_owned(),
        offset,
        kind,
        value,
        frames,
        message,
        fields,
        observations,
        hypotheses,
        runs,
    })
}
