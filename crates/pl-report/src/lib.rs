//! Отчёт по проекту: основания выводов, примеры, область применимости, контрпримеры, открытые вопросы.
//!
//! Чистая библиотека: данные приходят готовыми, на выходе Markdown или HTML. Данные записей и
//! журналов недоверенные: в HTML всё экранируется, скриптов и внешних ресурсов нет, CSP в `<meta>`.
//! Формулировки осторожные: совпадение на примерах — не доказательство.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]

use std::collections::BTreeMap;
use std::fmt::Write;

use serde::{Deserialize, Serialize};

/// Запись корпуса.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceInfo {
    pub name: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub format: String,
    pub frames: u64,
    pub connections: u64,
    /// Диагностика захвата: код и число кадров.
    pub diagnostics: Vec<(String, u64)>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InterpretationInfo {
    pub rev: u32,
    pub digest: String,
    pub direction: String,
    pub filter: Option<String>,
    pub framing: String,
    pub messages: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CounterexampleInfo {
    pub stream: String,
    pub start: u64,
    pub end: u64,
    pub sha256: Option<String>,
    pub category: String,
    pub message_id: Option<String>,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunInfo {
    pub id: String,
    pub revision: Option<u32>,
    pub interpretation_digest: String,
    pub settings: String,
    pub corpus: String,
    pub engine_version: String,
    pub stale_reasons: Vec<String>,
    pub streams: u64,
    pub out_of_scope_streams: u64,
    pub messages: u64,
    pub unknown_bytes: u64,
    pub counts: BTreeMap<String, u64>,
    pub by_message: BTreeMap<String, BTreeMap<String, u64>>,
    pub counterexamples_total: u64,
    pub counterexamples: Vec<CounterexampleInfo>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObservationInfo {
    pub id: String,
    pub comment: String,
    pub stream: String,
    pub start: u64,
    pub end: u64,
    pub sha256: Option<String>,
    pub anchor_state: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HypothesisTestInfo {
    /// `untested`, `no_counterexample`, `refuted`.
    pub verdict: String,
    pub applicable: u64,
    pub held: u64,
    pub counterexamples_total: u64,
    pub counterexamples: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HypothesisInfo {
    pub id: String,
    pub statement: String,
    /// `proposed`, `supported`, `refuted`, `superseded`.
    pub status: String,
    pub basis: Vec<String>,
    pub test: Option<String>,
    pub superseded_by: Option<String>,
    pub note: Option<String>,
    pub result: Option<HypothesisTestInfo>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuestionInfo {
    pub id: String,
    pub text: String,
    pub open: bool,
    pub answer: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActionLogInfo {
    pub id: String,
    pub name: String,
    pub rows: u64,
    pub skipped: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportData {
    pub project: String,
    pub engine_version: String,
    pub settings: String,
    pub sources: Vec<SourceInfo>,
    pub action_logs: Vec<ActionLogInfo>,
    pub interpretation: Option<InterpretationInfo>,
    pub run: Option<RunInfo>,
    pub observations: Vec<ObservationInfo>,
    pub hypotheses: Vec<HypothesisInfo>,
    pub questions: Vec<QuestionInfo>,
}

/// Максимум контрпримеров в тексте отчёта.
const SHOWN_COUNTEREXAMPLES: usize = 20;

fn category_title(code: &str) -> &str {
    match code {
        "matched" => "совпало",
        "violated" => "нарушено правило",
        "incomplete" => "неполно (дыра или обрыв)",
        "ambiguous" => "неоднозначно",
        "unmatched" => "не охвачено описанием",
        "limit_exceeded" => "предел реализации",
        other => other,
    }
}

fn status_title(code: &str) -> &str {
    match code {
        "proposed" => "предложена",
        "supported" => "поддержана на примерах (не доказана)",
        "refuted" => "опровергнута",
        "superseded" => "заменена другой",
        other => other,
    }
}

fn stale_title(code: &str) -> &str {
    match code {
        "interpretation" => "интерпретацию изменили после прогона",
        "settings" => "изменены настройки сборки потоков",
        "sources" => "записи корпуса пропали из проекта",
        other => other,
    }
}

fn short(hash: &str) -> &str {
    hash.get(..12).unwrap_or(hash)
}

fn hypothesis_result(h: &HypothesisInfo) -> String {
    match &h.result {
        None if h.test.is_some() => "тест не запускался".to_owned(),
        None => "теста нет".to_owned(),
        Some(r) => match r.verdict.as_str() {
            "refuted" => format!(
                "опровергнута тестом: контрпримеров {} из {} применимых",
                r.counterexamples_total, r.applicable
            ),
            "no_counterexample" => format!(
                "выполнилась на {} из {} применимых примеров, контрпримеров нет; это не доказательство вне этих примеров",
                r.held, r.applicable
            ),
            _ => "применимых примеров не нашлось: не проверена".to_owned(),
        },
    }
}

// ----------------------------------------------------------------- модель

/// Документ отчёта: блоки, из которых строятся Markdown и HTML.
enum Block {
    Heading(u8, String),
    Para(String),
    List(Vec<String>),
    Table(Vec<String>, Vec<Vec<String>>),
    Code(String),
}

fn build(d: &ReportData) -> Vec<Block> {
    use Block::{Code, Heading, List, Para, Table};
    let mut out = vec![Heading(1, format!("Отчёт по проекту «{}»", d.project))];
    out.push(Para(format!(
        "Версия движка {}. Политики сборки потоков: {}. Отчёт описывает, что установлено на записях проекта, на чём это основано и чего мы не знаем.",
        d.engine_version, d.settings
    )));

    out.push(Heading(2, "Область применимости".to_owned()));
    out.push(Para("Выводы справедливы для записей ниже и условий их проверки. На других данных они не проверены.".to_owned()));
    out.push(Table(
        vec![
            "Запись".into(),
            "sha256".into(),
            "Размер, байт".into(),
            "Формат".into(),
            "Кадров".into(),
            "Соединений".into(),
        ],
        d.sources
            .iter()
            .map(|s| {
                vec![
                    s.name.clone(),
                    s.sha256.clone(),
                    s.size_bytes.to_string(),
                    s.format.clone(),
                    s.frames.to_string(),
                    s.connections.to_string(),
                ]
            })
            .collect(),
    ));
    let diag: Vec<String> = d
        .sources
        .iter()
        .flat_map(|s| {
            s.diagnostics
                .iter()
                .map(move |(code, n)| format!("{}: {code} — {n} кадров", s.name))
        })
        .collect();
    if !diag.is_empty() {
        out.push(Para(
            "Диагностика захвата (кадры, которые не вошли в потоки или разобраны с оговорками):"
                .to_owned(),
        ));
        out.push(List(diag));
    }
    if !d.action_logs.is_empty() {
        out.push(Para("Журналы действий:".to_owned()));
        out.push(List(
            d.action_logs
                .iter()
                .map(|l| {
                    format!(
                        "{} ({}): разобрано действий {}, строк с ошибками {}",
                        l.name, l.id, l.rows, l.skipped
                    )
                })
                .collect(),
        ));
    }
    match &d.interpretation {
        Some(i) => {
            out.push(Para(format!(
                "Интерпретация: ревизия {}, digest {}. Область: направление {}, условие {}. Фрейминг: {}.",
                i.rev,
                i.digest,
                i.direction,
                i.filter.clone().unwrap_or_else(|| "нет".to_owned()),
                i.framing
            )));
            if !i.messages.is_empty() {
                out.push(Para(format!(
                    "Описанные типы сообщений: {}.",
                    i.messages.join(", ")
                )));
            }
        }
        None => out.push(Para("Интерпретация не сохранена.".to_owned())),
    }

    out.push(Heading(2, "Результат проверки".to_owned()));
    match &d.run {
        None => out.push(Para(
            "Прогонов проверки нет: интерпретация не применялась к корпусу.".to_owned(),
        )),
        Some(r) => {
            out.push(Para(format!(
                "Прогон {} (ревизия {}, фильтры корпуса: {}). Потоков: {}, вне области применимости: {}. Сообщений: {}.",
                r.id,
                r.revision.map_or_else(|| "—".to_owned(), |v| v.to_string()),
                r.corpus,
                r.streams,
                r.out_of_scope_streams,
                r.messages
            )));
            if !r.stale_reasons.is_empty() {
                out.push(Para(format!(
                    "Внимание: прогон устарел — {}. Результат ниже относится к прежним условиям.",
                    r.stale_reasons
                        .iter()
                        .map(|s| stale_title(s))
                        .collect::<Vec<_>>()
                        .join("; ")
                )));
            }
            out.push(Table(
                vec!["Категория".into(), "Сообщений".into()],
                r.counts
                    .iter()
                    .map(|(c, n)| vec![category_title(c).to_owned(), n.to_string()])
                    .collect(),
            ));
            out.push(Para(format!(
                "Байтов в сообщениях вне описанных полей или в зонах «неизвестно»: {}. Это то, чего описание пока не объясняет.",
                r.unknown_bytes
            )));
            if !r.by_message.is_empty() {
                out.push(Table(
                    vec!["Тип сообщения".into(), "Распределение".into()],
                    r.by_message
                        .iter()
                        .map(|(m, c)| {
                            vec![
                                m.clone(),
                                c.iter()
                                    .map(|(k, n)| format!("{}: {n}", category_title(k)))
                                    .collect::<Vec<_>>()
                                    .join(", "),
                            ]
                        })
                        .collect(),
                ));
            }
            out.push(Para(
                "Совпадение описания с сообщениями корпуса не доказывает, что оно верно для других данных: оно показывает лишь, что на этих примерах противоречий не найдено."
                    .to_owned(),
            ));
            out.push(Heading(3, "Контрпримеры".to_owned()));
            if r.counterexamples.is_empty() {
                out.push(Para("Контрпримеров на корпусе не найдено.".to_owned()));
            } else {
                out.push(Para(format!(
                    "Всего контрпримеров: {}; показаны первые {}.",
                    r.counterexamples_total,
                    r.counterexamples.len().min(SHOWN_COUNTEREXAMPLES)
                )));
                out.push(Table(
                    vec![
                        "Поток".into(),
                        "Байты".into(),
                        "sha256 байтов".into(),
                        "Тип".into(),
                        "Что нарушено".into(),
                    ],
                    r.counterexamples
                        .iter()
                        .take(SHOWN_COUNTEREXAMPLES)
                        .map(|c| {
                            vec![
                                c.stream.clone(),
                                format!("[{}, {})", c.start, c.end),
                                c.sha256.clone().map_or_else(
                                    || "нет (в диапазоне дыра)".to_owned(),
                                    |h| short(&h).to_owned(),
                                ),
                                c.message_id
                                    .clone()
                                    .unwrap_or_else(|| "не определён".to_owned()),
                                c.details.join("; "),
                            ]
                        })
                        .collect(),
                ));
            }
        }
    }

    out.push(Heading(2, "Гипотезы".to_owned()));
    if d.hypotheses.is_empty() {
        out.push(Para("Гипотез нет.".to_owned()));
    }
    for h in &d.hypotheses {
        out.push(Heading(3, format!("{}. {}", h.id, h.statement)));
        let mut lines = vec![
            format!("Статус: {}.", status_title(&h.status)),
            format!("Проверка: {}.", hypothesis_result(h)),
        ];
        if let Some(test) = &h.test {
            lines.push(format!("Тест: {test}"));
        }
        if !h.basis.is_empty() {
            let basis: Vec<String> = h
                .basis
                .iter()
                .map(|id| match d.observations.iter().find(|o| &o.id == id) {
                    Some(o) => format!("{id} ({}, [{}, {}))", o.stream, o.start, o.end),
                    None => id.clone(),
                })
                .collect();
            lines.push(format!("Основания: {}.", basis.join("; ")));
        } else {
            lines.push("Оснований (наблюдений) не указано.".to_owned());
        }
        if let Some(by) = &h.superseded_by {
            lines.push(format!("Заменена гипотезой {by}."));
        }
        if let Some(note) = &h.note {
            lines.push(format!("Заметка: {note}"));
        }
        if let Some(r) = &h.result {
            for c in r.counterexamples.iter().take(3) {
                lines.push(format!("Контрпример: {c}"));
            }
        }
        out.push(List(lines));
    }

    out.push(Heading(2, "Наблюдения".to_owned()));
    if d.observations.is_empty() {
        out.push(Para("Наблюдений нет.".to_owned()));
    } else {
        out.push(Table(
            vec![
                "№".into(),
                "Поток".into(),
                "Байты".into(),
                "sha256".into(),
                "Якорь".into(),
                "Комментарий".into(),
            ],
            d.observations
                .iter()
                .map(|o| {
                    vec![
                        o.id.clone(),
                        o.stream.clone(),
                        format!("[{}, {})", o.start, o.end),
                        o.sha256
                            .clone()
                            .map_or_else(|| "—".to_owned(), |h| short(&h).to_owned()),
                        match o.anchor_state.as_str() {
                            "ok" => "байты на месте".to_owned(),
                            "broken" => "байты изменились при другой сборке".to_owned(),
                            _ => "запись недоступна".to_owned(),
                        },
                        o.comment.clone(),
                    ]
                })
                .collect(),
        ));
    }

    out.push(Heading(2, "Открытые вопросы".to_owned()));
    let open: Vec<String> = d
        .questions
        .iter()
        .filter(|q| q.open)
        .map(|q| format!("{}: {}", q.id, q.text))
        .collect();
    if open.is_empty() {
        out.push(Para("Открытых вопросов нет.".to_owned()));
    } else {
        out.push(List(open));
    }
    let closed: Vec<String> = d
        .questions
        .iter()
        .filter(|q| !q.open)
        .map(|q| {
            format!(
                "{}: {} — {}",
                q.id,
                q.text,
                q.answer
                    .clone()
                    .unwrap_or_else(|| "закрыт без ответа".to_owned())
            )
        })
        .collect();
    if !closed.is_empty() {
        out.push(Para("Закрытые вопросы:".to_owned()));
        out.push(List(closed));
    }

    out.push(Heading(2, "Как воспроизвести".to_owned()));
    out.push(Para("Проект переносится копированием папки. Результаты перепроверяются командой (код возврата 0 — совпало, 1 — отличия):".to_owned()));
    out.push(Code("protoledger verify <папка проекта>".to_owned()));
    out.push(Para(
        "Описание применяется к новым записям без проекта:".to_owned(),
    ));
    out.push(Code(
        "protoledger apply --interpretation <файл> --input <запись>".to_owned(),
    ));
    out
}

// ---------------------------------------------------------------- Markdown

fn md_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '|' | '#' => {
                out.push('\\');
                out.push(c);
            }
            '\n' | '\r' => out.push(' '),
            c if c.is_control() => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }
    out
}

pub fn markdown(data: &ReportData) -> String {
    let mut out = String::new();
    for block in build(data) {
        match block {
            Block::Heading(level, text) => {
                let _ = writeln!(
                    out,
                    "{} {}\n",
                    "#".repeat(usize::from(level)),
                    md_escape(&text)
                );
            }
            Block::Para(text) => {
                let _ = writeln!(out, "{}\n", md_escape(&text));
            }
            Block::List(items) => {
                for item in items {
                    let _ = writeln!(out, "- {}", md_escape(&item));
                }
                out.push('\n');
            }
            Block::Table(head, rows) => {
                let _ = writeln!(
                    out,
                    "| {} |",
                    head.iter()
                        .map(|h| md_escape(h))
                        .collect::<Vec<_>>()
                        .join(" | ")
                );
                let _ = writeln!(out, "|{}|", vec!["---"; head.len()].join("|"));
                for row in rows {
                    let _ = writeln!(
                        out,
                        "| {} |",
                        row.iter()
                            .map(|c| md_escape(c))
                            .collect::<Vec<_>>()
                            .join(" | ")
                    );
                }
                out.push('\n');
            }
            Block::Code(text) => {
                let _ = writeln!(out, "```\n{}\n```\n", text.replace("```", "'''"));
            }
        }
    }
    out
}

// -------------------------------------------------------------------- HTML

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() && c != '\n' => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }
    out
}

const STYLE: &str = "body{font:16px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;color:#1b1f24;background:#fff}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #c9d1d9;padding:.35rem .6rem;text-align:left;vertical-align:top;word-break:break-word}th{background:#f1f3f5}pre{background:#f1f3f5;padding:.6rem;overflow:auto}h1,h2,h3{line-height:1.25}";

/// HTML без скриптов и внешних ресурсов; CSP запрещает всё, кроме встроенных стилей.
pub fn html(data: &ReportData) -> String {
    let mut out = String::from(
        "<!doctype html>\n<html lang=\"ru\">\n<head>\n<meta charset=\"utf-8\">\n<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n",
    );
    let _ = writeln!(
        out,
        "<title>Отчёт по проекту «{}»</title>\n<style>{STYLE}</style>\n</head>\n<body>",
        html_escape(&data.project)
    );
    for block in build(data) {
        match block {
            Block::Heading(level, text) => {
                let level = level.clamp(1, 6);
                let _ = writeln!(out, "<h{level}>{}</h{level}>", html_escape(&text));
            }
            Block::Para(text) => {
                let _ = writeln!(out, "<p>{}</p>", html_escape(&text));
            }
            Block::List(items) => {
                out.push_str("<ul>\n");
                for item in items {
                    let _ = writeln!(out, "<li>{}</li>", html_escape(&item));
                }
                out.push_str("</ul>\n");
            }
            Block::Table(head, rows) => {
                out.push_str("<table>\n<thead><tr>");
                for h in &head {
                    let _ = write!(out, "<th>{}</th>", html_escape(h));
                }
                out.push_str("</tr></thead>\n<tbody>\n");
                for row in rows {
                    out.push_str("<tr>");
                    for cell in &row {
                        let _ = write!(out, "<td>{}</td>", html_escape(cell));
                    }
                    out.push_str("</tr>\n");
                }
                out.push_str("</tbody>\n</table>\n");
            }
            Block::Code(text) => {
                let _ = writeln!(out, "<pre>{}</pre>", html_escape(&text));
            }
        }
    }
    out.push_str("</body>\n</html>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hostile() -> ReportData {
        ReportData {
            project: "<img src=x onerror=alert(1)>".to_owned(),
            questions: vec![QuestionInfo {
                id: "q-1".to_owned(),
                text: "a | b\nc `d` <script>".to_owned(),
                open: true,
                answer: None,
            }],
            ..ReportData::default()
        }
    }

    #[test]
    fn html_escapes_everything_from_data() {
        let html = html(&hostile());
        assert!(!html.contains("<img"));
        assert!(!html.contains("<script"));
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(html.contains("default-src 'none'"));
    }

    #[test]
    fn markdown_does_not_break_tables_or_inject_markup() {
        let md = markdown(&hostile());
        assert!(!md.contains("<script>"));
        assert!(md.contains(r"a \| b c \`d\` \<script\>"));
    }

    #[test]
    fn empty_project_reports_absence_honestly() {
        let md = markdown(&ReportData::default());
        assert!(md.contains("Прогонов проверки нет"));
        assert!(md.contains("Гипотез нет."));
        assert!(md.contains("Открытых вопросов нет."));
    }

    #[test]
    fn supported_hypothesis_is_not_called_proven() {
        let data = ReportData {
            hypotheses: vec![HypothesisInfo {
                id: "H1".to_owned(),
                statement: "s".to_owned(),
                status: "supported".to_owned(),
                test: Some("x == 1".to_owned()),
                result: Some(HypothesisTestInfo {
                    verdict: "no_counterexample".to_owned(),
                    applicable: 9,
                    held: 9,
                    ..HypothesisTestInfo::default()
                }),
                ..HypothesisInfo::default()
            }],
            ..ReportData::default()
        };
        let md = markdown(&data);
        assert!(md.contains("не доказана"));
        assert!(md.contains("выполнилась на 9 из 9"));
    }
}
