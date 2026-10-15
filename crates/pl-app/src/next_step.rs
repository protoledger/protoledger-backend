//! «Что дальше»: по состоянию проекта — следующий шаг исследования и почему именно он.
//! Подсказка ведёт по циклу «записи → границы → описание → гипотезы → проверка → отчёт»
//! и ничего не делает сама.

use pl_core::Problem;
use pl_interp::Interpretation;
use pl_interp::schema::Status;
use pl_verify::{HypothesisVerdict, Run};
use serde::Serialize;

use crate::research::{Hypothesis, HypothesisStatus, Question, QuestionStatus};
use crate::{ActionLogStore, Session, SourceStore};

/// Экран, на котором делается шаг.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Screen {
    Sources,
    Actions,
    Framing,
    Interpretation,
    Hypotheses,
    Verification,
    Questions,
    Report,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NextStep {
    /// Устойчивый идентификатор шага.
    pub id: &'static str,
    pub screen: Screen,
    /// Что сделать.
    pub title: String,
    /// Почему: что в проекте к этому подводит.
    pub detail: String,
}

/// Состояние проекта в числах, по которым выбраны шаги.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectState {
    pub sources: u64,
    pub action_logs: u64,
    pub has_interpretation: bool,
    pub message_types: u64,
    pub hypotheses: u64,
    pub hypotheses_without_test: u64,
    pub unknown_fields: u64,
    pub runs: u64,
    pub last_run: Option<String>,
    pub last_run_stale: bool,
    pub counterexamples: u64,
    pub refuted: Vec<String>,
    pub untested: Vec<String>,
    pub open_questions: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NextSteps {
    /// Шаги по порядку: первый — самый полезный сейчас.
    pub steps: Vec<NextStep>,
    pub state: ProjectState,
}

fn step(id: &'static str, screen: Screen, title: &str, detail: String) -> NextStep {
    NextStep {
        id,
        screen,
        title: title.to_owned(),
        detail,
    }
}

fn list(ids: &[String]) -> String {
    let shown: Vec<&str> = ids.iter().take(5).map(String::as_str).collect();
    let more = ids.len().saturating_sub(shown.len());
    if more > 0 {
        format!("{} и ещё {more}", shown.join(", "))
    } else {
        shown.join(", ")
    }
}

/// Следующие шаги исследования по состоянию открытого проекта.
pub fn next_steps(
    session: &Session,
    sources: &SourceStore,
    logs: &ActionLogStore,
) -> Result<NextSteps, Problem> {
    let mut state = ProjectState {
        sources: sources.list().len() as u64,
        action_logs: logs.list().len() as u64,
        ..ProjectState::default()
    };
    let interpretation = crate::current_interpretation(session);
    if let Some(it) = &interpretation {
        describe(it, &mut state);
    }
    state.has_interpretation = interpretation.is_some();
    state.open_questions = crate::research::load::<Question>(session)?
        .iter()
        .filter(|q| q.status == QuestionStatus::Open)
        .count() as u64;
    let proposed = crate::research::load::<Hypothesis>(session)?
        .iter()
        .filter(|h| h.status == HypothesisStatus::Proposed)
        .count() as u64;

    // Последний прогон: читается с диска, блокировка — только на время чтения текста.
    let last: Option<(String, String)> = {
        let guard = session.read();
        let project = guard.as_ref().ok_or_else(Session::no_project)?;
        let ids = project.run_ids();
        state.runs = ids.len() as u64;
        ids.last()
            .and_then(|id| Some(((*id).to_owned(), project.read_run(id).ok()?)))
    };
    if let Some((id, text)) = last {
        state.last_run = Some(id);
        if let Ok(run) = serde_json::from_str::<Run>(&text) {
            state.last_run_stale = crate::current_signature(session, sources)
                .is_some_and(|c| !pl_verify::stale_reasons(&run, &c).is_empty());
            state.counterexamples = run.summary.counterexamples;
            for h in &run.hypotheses {
                match h.verdict {
                    HypothesisVerdict::Refuted => state.refuted.push(h.id.clone()),
                    HypothesisVerdict::Untested => state.untested.push(h.id.clone()),
                    HypothesisVerdict::NoCounterexample => {}
                }
            }
        }
    }

    let mut steps = Vec::new();
    if state.sources == 0 {
        steps.push(step(
            "import_capture",
            Screen::Sources,
            "Добавьте записи трафика",
            "В проекте нет записей: разбирать пока нечего.".to_owned(),
        ));
        return Ok(NextSteps { steps, state });
    }
    if state.action_logs == 0 {
        steps.push(step(
            "import_journal",
            Screen::Actions,
            "Добавьте журнал действий",
            "Без журнала не связать байты с действиями оператора и не проверить, что означают поля."
                .to_owned(),
        ));
    }
    // Часы журнала расходятся с записью: без поправки действия не находят свои обмены.
    let all = crate::all_sources(sources);
    for log in logs.list() {
        let found = crate::clock_offset(&all, &log, crate::DEFAULT_WINDOW_MS);
        if let Some(offset) = found.offset_ms {
            steps.push(step(
                "fix_journal_clock",
                Screen::Actions,
                "Поправьте время в журнале действий",
                format!(
                    "Журнал {}: {}. Сдвиньте время журнала на {} мс.",
                    log.record.name,
                    found.reason,
                    found.current_offset_ms.saturating_add(offset)
                ),
            ));
        }
    }
    if !state.has_interpretation {
        steps.insert(
            0,
            step(
                "find_framing",
                Screen::Interpretation,
                "Составьте описание протокола",
                "Описания ещё нет. На экране «Протокол» нажмите «Составить описание»: границы сообщений, команды и поля найдутся по записям.".to_owned(),
            ),
        );
        return Ok(NextSteps { steps, state });
    }
    if state.message_types == 0 {
        steps.push(step(
            "describe_types",
            Screen::Interpretation,
            "Опишите сообщения",
            "Границы сообщений известны, но ни одно сообщение не описано. Составьте описание на экране «Протокол»."
                .to_owned(),
        ));
    }
    if state.runs == 0 {
        steps.push(step(
            "first_run",
            Screen::Verification,
            "Проверьте описание на записях",
            "Описание ещё ни разу не проверялось на записях.".to_owned(),
        ));
    } else if state.last_run_stale {
        steps.push(step(
            "rerun",
            Screen::Verification,
            "Проверьте описание ещё раз",
            format!(
                "Проверка {} устарела: после неё изменились описание, настройки или записи.",
                state.last_run.as_deref().unwrap_or_default()
            ),
        ));
    } else {
        if !state.refuted.is_empty() {
            steps.push(step(
                "fix_refuted",
                Screen::Hypotheses,
                "Исправьте поля с расхождениями",
                format!(
                    "В последней проверке есть расхождения: {}. На экране «Протокол» нажмите «Как исправить» у поля.",
                    list(&state.refuted)
                ),
            ));
        }
        if state.counterexamples > 0 {
            steps.push(step(
                "counterexamples",
                Screen::Verification,
                "Разберите нарушения",
                format!(
                    "В последней проверке нарушений: {}. Либо описание неверно, либо в записи дефект захвата.",
                    state.counterexamples
                ),
            ));
        }
        if !state.untested.is_empty() {
            steps.push(step(
                "untested",
                Screen::Hypotheses,
                "Нужны примеры для проверки",
                format!(
                    "Для предположений {} в записях не нашлось подходящих сообщений: нужна запись с таким обменом или журнал действий.",
                    list(&state.untested)
                ),
            ));
        }
    }
    if state.hypotheses_without_test > 0 {
        steps.push(step(
            "add_tests",
            Screen::Hypotheses,
            "Добавьте проверки к предположениям",
            format!(
                "Предположений без проверки: {} из {}. Такое предположение нечем подтвердить на записях.",
                state.hypotheses_without_test, state.hypotheses
            ),
        ));
    }
    if state.unknown_fields > 0 {
        steps.push(step(
            "unknown_fields",
            Screen::Interpretation,
            "Остались неразобранные байты",
            format!(
                "Полей с пометкой «не описано»: {}.",
                state.unknown_fields
            ),
        ));
    }
    if proposed > 0 {
        steps.push(step(
            "review_hypotheses",
            Screen::Hypotheses,
            "Оцените свои предположения",
            format!("Предположений, которые ещё не оценены: {proposed}."),
        ));
    }
    if state.open_questions > 0 {
        steps.push(step(
            "open_questions",
            Screen::Questions,
            "Вернитесь к открытым вопросам",
            format!("Открытых вопросов: {}.", state.open_questions),
        ));
    }
    if steps.is_empty() {
        steps.push(step(
            "report",
            Screen::Report,
            "Сформируйте отчёт",
            "Последняя проверка актуальна, расхождений нет. Отчёт опишет протокол и границы, в которых результат проверен.".to_owned(),
        ));
    }
    Ok(NextSteps { steps, state })
}

fn describe(it: &Interpretation, state: &mut ProjectState) {
    state.message_types = it.messages.len() as u64;
    state.hypotheses = it.hypotheses.len() as u64;
    state.hypotheses_without_test =
        it.hypotheses.iter().filter(|h| h.test.is_none()).count() as u64;
    state.unknown_fields = it
        .messages
        .iter()
        .flat_map(|m| &m.fields)
        .filter(|f| f.status == Status::Unknown)
        .count() as u64;
}
