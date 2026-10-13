//! Черновик описания протокола: подсказки по границам, типам, полям, журналу и контрольной сумме,
//! собранные в один текст интерпретации. Всё найденное — гипотезы с основаниями; черновик не
//! сохраняется, его принимает или правит исследователь.

use std::collections::{BTreeMap, BTreeSet};

use pl_analysis::{FieldKind, TypeKey};
use pl_core::{Problem, ProblemKind};
use pl_interp::schema::Framing;
use pl_interp::{Category, Interpretation};
use serde::Serialize;

use crate::analysis::{
    ChecksumRequest, CorrelationRequest, FieldsRequest, TypesRequest, checksums_on,
    correlations_on, fields_on, framing_hints, types_on,
};
use crate::{ActionLogStore, SourceStore, resolve_stream, stream_input};

/// Для стольких типов (самых частых) ищутся поля и связи с журналом.
const MAX_DETAILED_TYPES: usize = 16;
/// Связь с журналом попадает в черновик, если сошлась почти везде.
const MIN_LINK_SHARE: u32 = 900;

#[derive(Debug, Clone)]
pub struct DraftRequest {
    pub streams: Vec<String>,
    /// Журнал действий; без значения — все журналы проекта.
    pub log_id: Option<String>,
}

/// Шаг сборки: что найдено и на чём основано.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DraftStep {
    pub title: String,
    pub detail: String,
}

/// Что даёт черновик на тех же потоках.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftSummary {
    pub streams: u64,
    pub messages: u64,
    /// Сообщений по категориям результата.
    pub counts: BTreeMap<String, u64>,
    pub unknown_bytes: u64,
    pub types: u64,
    pub hypotheses: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftView {
    /// Текст интерпретации; проходит ту же проверку, что и сохранение.
    pub yaml: String,
    pub steps: Vec<DraftStep>,
    pub summary: DraftSummary,
    /// Часть шагов не успела выполниться: черновик беднее, чем мог бы быть.
    pub incomplete: bool,
}

struct Field {
    name: String,
    at: String,
    ty: String,
    len: Option<String>,
    expect: Option<String>,
    mask: Option<u64>,
    hypothesis: usize,
    /// Байты от начала сообщения, если место и размер известны: по ним отсекаются пересечения.
    span: Option<(u64, u64)>,
}

struct Message {
    id: String,
    when: String,
    count: u64,
    fields: Vec<Field>,
}

#[derive(Default)]
struct Hypotheses {
    items: Vec<(String, Option<String>)>,
    by_key: BTreeMap<String, usize>,
}

impl Hypotheses {
    /// Одна гипотеза на одно утверждение: поле с тем же смыслом в других сообщениях ссылается на неё же.
    fn id(&mut self, key: &str, statement: impl FnOnce() -> String, test: Option<String>) -> usize {
        if let Some(i) = self.by_key.get(key) {
            return *i;
        }
        self.items.push((statement(), test));
        self.by_key.insert(key.to_owned(), self.items.len());
        self.items.len()
    }
}

fn quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            // Управляющие символы и разделители строк Юникода ломают однострочную запись.
            c if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}' | '\u{feff}') => {
                out.push(' ');
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn type_size(ty: &str) -> Option<u64> {
    match ty
        .trim_start_matches(['u', 'i'])
        .trim_end_matches(['b', 'l', 'e'])
    {
        "8" => Some(1),
        "16" => Some(2),
        "32" => Some(4),
        "64" => Some(8),
        _ => None,
    }
}

/// Имя из журнала годится для выражения: буквы, цифры, подчёркивания, части через точку.
fn expression_name(name: &str) -> bool {
    !name.is_empty()
        && name.split('.').all(|part| {
            !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
}

fn field_name(param: &str, taken: &BTreeSet<String>) -> String {
    let clean = |text: &str| -> String {
        text.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect()
    };
    let path = param
        .strip_prefix("params.")
        .or_else(|| param.strip_prefix("result."))
        .unwrap_or(param);
    let last = path.rsplit('.').next().unwrap_or(path);
    // У элемента списка одного последнего слова мало: «measurements.1.alarm» и «measurements.2.alarm».
    let indexed = path
        .split('.')
        .any(|part| part.chars().all(|c| c.is_ascii_digit()));
    let mut name = if indexed { clean(path) } else { clean(last) };
    if !name.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
        name.insert(0, 'f');
    }
    if taken.contains(&name) && !indexed {
        name = clean(path);
    }
    let base = name.clone();
    let mut n = 2;
    while taken.contains(&name) {
        name = format!("{base}_{n}");
        n += 1;
    }
    name
}

/// Самое узкое из равнозначных чтений связи: широкое поле с нулём в старшем байте поглотило бы
/// соседний байт, смысл которого ещё не известен.
fn narrowest(at: u32, ty: &str, equivalent: &[String]) -> (u32, String) {
    let mut best = (at, ty.to_owned());
    for alt in equivalent {
        let Some((alt_ty, alt_at)) = alt.split_once('@') else {
            continue;
        };
        let (Ok(alt_at), Some(size), Some(current)) =
            (alt_at.parse::<u32>(), type_size(alt_ty), type_size(&best.1))
        else {
            continue;
        };
        if size < current {
            best = (alt_at, alt_ty.to_owned());
        }
    }
    best
}

impl Message {
    /// Свободны ли эти байты и имя.
    fn free(&self, name: &str, span: Option<(u64, u64)>) -> bool {
        !self.fields.iter().any(|f| {
            f.name == name
                || matches!((f.span, span), (Some((a, b)), Some((c, d))) if a < d && c < b)
        })
    }

    /// Добавляет поле, если его байты ещё свободны и имя не занято.
    fn add(&mut self, field: Field) -> bool {
        let free = self.free(&field.name, field.span);
        if free {
            self.fields.push(field);
        }
        free
    }

    fn names(&self) -> BTreeSet<String> {
        self.fields.iter().map(|f| f.name.clone()).collect()
    }
}

fn render(
    framing: &Framing,
    messages: &[Message],
    hyps: &Hypotheses,
    checks: &[(String, String)],
) -> String {
    let mut y = String::from(
        "# Черновик описания, собранный по данным. Каждое поле — гипотеза с основанием:\n# проверьте её прогоном и уточните.\nformat: protoledger/interpretation@1\n",
    );
    y.push_str(&format!(
        "framing: {}\n",
        serde_json::to_string(framing).unwrap_or_default()
    ));
    y.push_str("messages:\n");
    for m in messages {
        y.push_str(&format!("  - id: {}\n", m.id));
        y.push_str(&format!(
            "    description: {}\n",
            quoted(&format!("сообщений в данных: {}", m.count))
        ));
        if !m.when.is_empty() {
            y.push_str(&format!("    when: {}\n", quoted(&m.when)));
        }
        y.push_str("    fields:\n");
        let mut fields: Vec<&Field> = m.fields.iter().collect();
        fields.sort_by_key(|f| f.span.map_or((1, 0), |(start, _)| (0, start)));
        for f in fields {
            let at = if f.at.starts_with("end") {
                f.at.clone()
            } else {
                f.at.to_string()
            };
            let mut line = format!("      - {{ name: {}, at: {at}, type: {}", f.name, f.ty);
            if let Some(len) = &f.len {
                line.push_str(&format!(", len: {len}"));
            }
            if let Some(expect) = &f.expect {
                line.push_str(&format!(", expect: {expect}"));
            }
            if let Some(mask) = f.mask {
                line.push_str(&format!(", mask: 0x{mask:02x}"));
            }
            line.push_str(&format!(
                ", status: hypothesis, hypothesis: H{} }}\n",
                f.hypothesis
            ));
            y.push_str(&line);
        }
    }
    y.push_str("hypotheses:\n");
    for (i, (statement, test)) in hyps.items.iter().enumerate() {
        let test = test
            .as_ref()
            .map(|t| format!(", test: {}", quoted(t)))
            .unwrap_or_default();
        y.push_str(&format!(
            "  - {{ id: H{}, statement: {}{test} }}\n",
            i + 1,
            quoted(statement)
        ));
    }
    if !checks.is_empty() {
        y.push_str("checks:\n");
        for (i, (expr, description)) in checks.iter().enumerate() {
            y.push_str(&format!(
                "  - {{ id: C{}, kind: structural, expr: {}, description: {} }}\n",
                i + 1,
                quoted(expr),
                quoted(description)
            ));
        }
    }
    y
}

fn parse(yaml: &str) -> Result<Interpretation, Problem> {
    Interpretation::parse(yaml).map_err(|e| {
        Problem::new(
            ProblemKind::Internal,
            format!("Черновик не прошёл проверку описания: {e}."),
        )
    })
}

/// Собирает черновик описания по указанным потокам (обеих сторон обмена).
pub fn draft_interpretation(
    store: &SourceStore,
    logs: &ActionLogStore,
    request: &DraftRequest,
    cancelled: &dyn Fn() -> bool,
) -> Result<DraftView, Problem> {
    let streams = &request.streams;
    let mut steps: Vec<DraftStep> = Vec::new();
    let mut incomplete = false;
    let mut step = |title: &str, detail: String| {
        steps.push(DraftStep {
            title: title.to_owned(),
            detail,
        });
    };

    // 1. Границы сообщений.
    let hints = framing_hints(store, streams, cancelled)?;
    incomplete |= hints.incomplete;
    let Some(length) = hints.length.first() else {
        return Err(Problem::new(
            ProblemKind::Unprocessable,
            "Границы сообщений по этим потокам не найдены: поля длины с достаточным числом подтверждений нет. Задайте фрейминг вручную.",
        ));
    };
    let mut framing: Framing = serde_json::to_value(&length.framing)
        .and_then(serde_json::from_value)
        .map_err(|e| Problem::new(ProblemKind::Internal, format!("Фрейминг не собран: {e}.")))?;
    let length_at = u64::from(length.at);
    let length_ty = length.framing.length.as_ref().map_or("u8", |l| l.ty);
    let length_size = u64::from(length.width).max(1);
    // Сигнатура — постоянное начало всех сообщений, но не дальше поля длины.
    let signature = hints
        .signatures
        .first()
        .filter(|s| s.at_starts == s.starts_total && s.starts_total > 0)
        .map(|s| {
            let keep = (s.bytes.len() / 2).min(length.at as usize) * 2;
            s.bytes.get(..keep).unwrap_or_default().to_owned()
        })
        .filter(|s| s.len() >= 2);
    if length.at > 0 {
        framing.sync.clone_from(&signature);
    }
    // Как из значения поля получается размер сообщения.
    let rule = if length_ty == "varint" {
        "длина переменного размера, считается от конца самого поля".to_owned()
    } else {
        format!("размер сообщения = значение + {}", length.adjust)
    };
    step(
        "Границы сообщений",
        format!(
            "Поле длины {length_ty} по смещению {}: {rule}. Сообщений: {}, покрыто байтов: {} из {}, {}.{}",
            length.at,
            length.messages,
            length.covered_bytes,
            length.total_bytes,
            match (&length.first_counterexample, length.score_permille) {
                (None, _) => "контрпримеров нет",
                // Разбор прошёл весь поток; отмечено только сообщение, начало которого не похоже на остальные.
                (Some(_), 1000) => "разбор покрывает все байты",
                (Some(_), _) => "есть контрпример",
            },
            signature
                .as_ref()
                .map(|s| format!(" Каждое сообщение начинается с байтов {s}."))
                .unwrap_or_default(),
        ),
    );

    let mut hyps = Hypotheses::default();
    let length_hyp = hyps.id(
        "length",
        || {
            format!(
                "length — длина: {rule}; найдено по {} сообщениям",
                length.messages
            )
        },
        None,
    );
    // `limit` — сколько первых байтов может занять сигнатура: байт-различитель типа внутри
    // «постоянного начала» важнее, иначе условие типа ссылалось бы на поле, которого нет.
    let header = |m: &mut Message, hyps: &mut Hypotheses, limit: u64| {
        m.add(Field {
            name: "length".to_owned(),
            at: length.at.to_string(),
            ty: length_ty.to_owned(),
            len: None,
            expect: None,
            mask: None,
            hypothesis: length_hyp,
            span: Some((length_at, length_at + length_size)),
        });
        let cut = signature.as_ref().and_then(|bytes| {
            let size = ((bytes.len() / 2) as u64).min(limit);
            let hex = bytes.get(..usize::try_from(size).ok()? * 2)?;
            (size > 0).then_some((hex, size))
        });
        if let Some((bytes, size)) = cut {
            let hypothesis = hyps.id(
                "signature",
                || format!("signature — постоянное начало сообщения ({bytes}): стоит в начале каждого сообщения"),
                None,
            );
            m.add(Field {
                name: "signature".to_owned(),
                at: "0".to_owned(),
                ty: "bytes".to_owned(),
                len: Some(size.to_string()),
                expect: Some(quoted(bytes)),
                mask: None,
                hypothesis,
                span: Some((0, size)),
            });
        }
    };

    // 2. Типы сообщений.
    let bare = parse(&render(&framing, &[], &hyps, &[]))?;
    let types = types_on(
        &bare,
        store,
        &TypesRequest {
            streams: streams.clone(),
            framing: None,
        },
        cancelled,
    )?;
    incomplete |= types.incomplete;
    let first_key = types
        .keys
        .iter()
        .filter_map(|k| match k.key {
            TypeKey::Byte { at } => Some(u64::from(at)),
            TypeKey::Side => None,
        })
        .min()
        .unwrap_or(u64::MAX);
    let mut messages: Vec<Message> = Vec::new();
    for t in &types.types {
        let mut m = Message {
            id: t.id.clone(),
            when: t.when.clone(),
            count: t.count,
            fields: Vec::new(),
        };
        header(&mut m, &mut hyps, first_key);
        for (i, k) in types.keys.iter().enumerate() {
            let TypeKey::Byte { at } = k.key else {
                continue;
            };
            let hypothesis = hyps.id(
                &format!("b{at}"),
                || {
                    if i == 0 && k.score_permille == 0 {
                        format!(
                            "b{at} — сторона обмена: у запросов одно значение, у ответов другое"
                        )
                    } else {
                        format!(
                            "b{at} — тип сообщения: значений — {}, объясняет {} % разнообразия длин",
                            k.values,
                            k.length_explained_permille / 10
                        )
                    }
                },
                None,
            );
            m.add(Field {
                name: format!("b{at}"),
                at: at.to_string(),
                ty: "u8".to_owned(),
                len: None,
                expect: None,
                mask: None,
                hypothesis,
                span: Some((u64::from(at), u64::from(at) + 1)),
            });
        }
        messages.push(m);
    }
    if messages.is_empty() {
        // Типов не нашлось: одно сообщение без условия — границы и общий заголовок всё равно описаны.
        let mut m = Message {
            id: "message".to_owned(),
            when: String::new(),
            count: types.messages,
            fields: Vec::new(),
        };
        header(&mut m, &mut hyps, u64::MAX);
        messages.push(m);
        step(
            "Типы сообщений",
            "Байт, который делил бы сообщения на типы, не найден: описано одно сообщение."
                .to_owned(),
        );
    } else {
        let keys: Vec<String> = types
            .keys
            .iter()
            .map(|k| match k.key {
                TypeKey::Byte { at } if k.score_permille == 0 => {
                    format!("байт {at} (сторона обмена)")
                }
                TypeKey::Byte { at } => format!(
                    "байт {at} (значений — {}, объясняет {} % разнообразия длин)",
                    k.values,
                    k.length_explained_permille / 10
                ),
                TypeKey::Side => "сторона обмена (по порту)".to_owned(),
            })
            .collect();
        step(
            "Типы сообщений",
            format!(
                "Различители: {}. Типов: {}; сообщений в группах меньше трёх: {}.",
                keys.join(", "),
                messages.len(),
                types.rare
            ),
        );
    }

    // 3. Поля по поведению и связи с журналом — по каждому типу отдельно.
    let has_logs = match &request.log_id {
        Some(id) => logs.get(id).is_some(),
        None => !logs.list().is_empty(),
    };
    let typed = parse(&render(&framing, &messages, &hyps, &[]))?;
    let mut counter_seen = false;
    let (mut links, mut strings) = (Vec::new(), Vec::new());
    for index in 0..messages.len().min(MAX_DETAILED_TYPES) {
        if cancelled() {
            incomplete = true;
            break;
        }
        let Some(id) = messages.get(index).map(|m| m.id.clone()) else {
            break;
        };
        let filter = (messages.len() > 1).then(|| id.clone());
        let found = fields_on(
            &typed,
            store,
            &FieldsRequest {
                streams: streams.clone(),
                framing: None,
                message_id: filter.clone(),
                matching: Vec::new(),
            },
            cancelled,
        )?;
        incomplete |= found.incomplete;
        for h in &found.hints {
            match h.kind {
                // Счётчик — свойство потока: добавляется во все сообщения, где его байты свободны.
                FieldKind::Counter => {
                    let Some(size) = h.size else { continue };
                    let span = (u64::from(h.at), u64::from(h.at) + u64::from(size));
                    // Байты заняты во всех типах — гипотезе не на что опереться.
                    if !messages.iter().any(|m| m.free("counter", Some(span))) {
                        continue;
                    }
                    let hypothesis = hyps.id(
                        &format!("counter{}", h.at),
                        || {
                            format!(
                                "counter — номер сообщения: растёт на единицу в {} из {} пар соседних сообщений потока",
                                h.matches, h.samples
                            )
                        },
                        None,
                    );
                    let mut added = false;
                    for m in &mut messages {
                        added |= m.add(Field {
                            name: "counter".to_owned(),
                            at: h.at.to_string(),
                            ty: h.ty.clone(),
                            len: None,
                            expect: None,
                            mask: None,
                            hypothesis,
                            span: Some(span),
                        });
                    }
                    if added && !counter_seen {
                        counter_seen = true;
                        step(
                            "Счётчик",
                            format!(
                                "{} по смещению {}: {} ({} из {}).",
                                h.ty, h.at, h.summary, h.matches, h.samples
                            ),
                        );
                    }
                }
                FieldKind::String => {
                    let Some(width) = type_size(&h.ty) else {
                        continue;
                    };
                    let Some(m) = messages.get_mut(index) else {
                        continue;
                    };
                    let at = u64::from(h.at);
                    if !m.free("", Some((at, at + width + 1))) {
                        continue;
                    }
                    let taken = m.names();
                    let len_name = field_name("text_len", &taken);
                    let text_name = field_name("text", &taken);
                    let example = h.example.clone().unwrap_or_default();
                    let hypothesis = hyps.id(
                        &format!("{id}.string{at}"),
                        || {
                            format!(
                                "{text_name} — строка: длина в {len_name}, текст сразу за ней; пример: {example}; сошлось в {} из {} сообщений",
                                h.matches, h.samples
                            )
                        },
                        None,
                    );
                    let added = m.add(Field {
                        name: len_name.clone(),
                        at: at.to_string(),
                        ty: h.ty.clone(),
                        len: None,
                        expect: None,
                        mask: None,
                        hypothesis,
                        span: Some((at, at + width)),
                    });
                    if added {
                        m.add(Field {
                            name: text_name,
                            at: (at + width).to_string(),
                            ty: "string".to_owned(),
                            len: Some(quoted(&len_name)),
                            expect: None,
                            mask: None,
                            hypothesis,
                            span: Some((at + width, at + width + 1)),
                        });
                        strings.push(format!("{id}: смещение {at}, пример «{example}»"));
                    }
                }
                _ => {}
            }
        }

        if !has_logs {
            continue;
        }
        let found = correlations_on(
            &typed,
            store,
            logs,
            &CorrelationRequest {
                streams: streams.clone(),
                framing: None,
                message_id: filter,
                log_id: request.log_id.clone(),
                window_ms: None,
            },
            cancelled,
        )?;
        let Some(m) = messages.get_mut(index) else {
            continue;
        };
        for v in found
            .values
            .iter()
            .filter(|v| v.share_permille >= MIN_LINK_SHARE && expression_name(&v.param))
        {
            // Гипотеза заводится только для поля, которое встаёт на свободное место.
            let plain = v.mask.is_none() && type_size(v.ty).is_some();
            let (at, ty) = if plain {
                narrowest(v.at, v.ty, &v.equivalent)
            } else {
                (v.at, v.ty.to_owned())
            };
            let size = type_size(&ty).unwrap_or(u64::from(v.size));
            let float = ty.starts_with('f');
            let at = u64::from(at);
            if !m.free("", Some((at, at + size))) {
                continue;
            }
            let digits = match v.scale {
                1 => 0,
                10 => 1,
                100 => 2,
                1000 => 3,
                _ => continue,
            };
            let name = field_name(&v.param, &m.names());
            let test = if float {
                // Число с плавающей точкой читается десятичной записью: обе стороны — через dec.
                format!("dec({name}, 3) == dec(action.{}, 3)", v.param)
            } else if digits == 0 {
                format!("{name} == action.{}", v.param)
            } else {
                format!("{name} == dec(action.{}, {digits})", v.param)
            };
            let hypothesis = hyps.id(
                &format!("link.{id}.{name}"),
                || {
                    format!(
                        "{name} — значение «{}» из журнала действий{}: совпало в {} из {} сообщений{}",
                        v.param,
                        if digits == 0 {
                            String::new()
                        } else {
                            format!(" с {digits} знаками после запятой")
                        },
                        v.matches,
                        v.samples,
                        if ty == v.ty {
                            String::new()
                        } else {
                            format!(
                                "; соседние байты всегда нулевые — возможно, поле шире ({} по смещению {})",
                                v.ty, v.at
                            )
                        }
                    )
                },
                Some(test),
            );
            if m.add(Field {
                name: name.clone(),
                at: at.to_string(),
                len: (ty == "bcd").then(|| v.size.to_string()),
                ty,
                expect: None,
                mask: v.mask,
                hypothesis,
                span: Some((at, at + size)),
            }) {
                links.push(format!(
                    "{id}.{name} ← {} ({} из {})",
                    v.param, v.matches, v.samples
                ));
            }
        }
    }
    if !strings.is_empty() {
        step(
            "Строки",
            format!("Длина и текст сразу за ней — {}.", strings.join("; ")),
        );
    }
    if has_logs {
        step(
            "Связи с журналом действий",
            if links.is_empty() {
                "Полей, значения которых совпадают с параметрами действий, не найдено.".to_owned()
            } else {
                format!("Поля, равные значениям из журнала: {}.", links.join("; "))
            },
        );
    }

    // 4. Контрольная сумма — по всем сообщениям сразу.
    let mut checks: Vec<(String, String)> = Vec::new();
    let sums = checksums_on(
        &typed,
        store,
        &ChecksumRequest {
            streams: streams.clone(),
            framing: None,
            message_id: None,
        },
        cancelled,
    )?;
    incomplete |= sums.incomplete;
    match sums.hints.first() {
        Some(h) => {
            let hypothesis = hyps.id(
                "checksum",
                || {
                    format!(
                        "checksum — контрольная сумма ({}) байтов с {} до {}: сошлась в {} из {} сообщений",
                        h.title, h.from, h.to, h.matches, h.samples
                    )
                },
                None,
            );
            for m in &mut messages {
                m.add(Field {
                    name: "checksum".to_owned(),
                    at: h.at.clone(),
                    ty: h.ty.clone(),
                    len: None,
                    expect: None,
                    mask: None,
                    hypothesis,
                    span: h
                        .at
                        .parse::<u64>()
                        .ok()
                        .zip(type_size(&h.ty))
                        .map(|(at, size)| (at, at + size)),
                });
            }
            checks.push((h.expr.clone(), "контрольная сумма не сходится".to_owned()));
            step(
                "Контрольная сумма",
                format!(
                    "{}: поле {} по смещению {}, сошлась в {} из {} сообщений.",
                    h.title, h.ty, h.at, h.matches, h.samples
                ),
            );
        }
        None => step(
            "Контрольная сумма",
            format!(
                "Не найдена: ни одна из {} проверенных функций не сошлась.",
                sums.checked.len()
            ),
        ),
    }

    // 5. Готовый текст и что он даёт на тех же потоках.
    let yaml = render(&framing, &messages, &hyps, &checks);
    let it = parse(&yaml)?;
    let mut summary = DraftSummary {
        types: messages.len() as u64,
        hypotheses: hyps.items.len() as u64,
        ..DraftSummary::default()
    };
    for id in streams {
        let Some((data, conn, dir)) = resolve_stream(store, id) else {
            continue;
        };
        let (Some(connection), Some(stream)) = (
            data.connections.get(conn),
            data.connections.get(conn).and_then(|c| c.streams.get(dir)),
        ) else {
            continue;
        };
        let input = stream_input(&data.file, connection, stream, dir);
        let result = pl_interp::apply(&it, &input, cancelled)
            .map_err(|e| Problem::new(ProblemKind::Unprocessable, format!("Поток {id}: {e}.")))?;
        summary.streams += 1;
        for m in &result.messages {
            summary.messages += 1;
            summary.unknown_bytes += m.unknown_bytes;
            let name = match m.category {
                Category::Matched => "matched",
                Category::Violated => "violated",
                Category::Incomplete => "incomplete",
                Category::Ambiguous => "ambiguous",
                Category::Unmatched => "unmatched",
                _ => "other",
            };
            *summary.counts.entry(name.to_owned()).or_default() += 1;
        }
    }
    let matched = summary.counts.get("matched").copied().unwrap_or(0);
    step(
        "Проверка черновика",
        format!(
            "На этих потоках: сообщений {}, разобрано без замечаний {}, байтов без описания {}. Гипотез: {}.",
            summary.messages, matched, summary.unknown_bytes, summary.hypotheses
        ),
    );
    Ok(DraftView {
        yaml,
        steps,
        summary,
        incomplete,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_from_data_cannot_break_the_yaml_line() {
        let hostile = "a\"b\\c\nd\u{2028}e\u{0}f: #- {x}";
        let line = format!("statement: {}", quoted(hostile));
        assert_eq!(line.lines().count(), 1);
        let parsed: BTreeMap<String, String> = serde_saphyr::from_str(&line).unwrap();
        assert_eq!(parsed["statement"], "a\"b\\c d e f: #- {x}");
    }

    #[test]
    fn journal_names_become_safe_field_names() {
        let mut taken = BTreeSet::new();
        assert_eq!(field_name("params.period_ms", &taken), "period_ms");
        taken.insert("period_ms".to_owned());
        assert_eq!(
            field_name("result.configuration.period_ms", &taken),
            "configuration_period_ms"
        );
        assert_eq!(
            field_name("result.measurements.1.alarm", &taken),
            "measurements_1_alarm"
        );
        assert_eq!(field_name("params.9 lives!", &taken), "f9_lives_");
        assert!(expression_name("params.period_ms"));
        assert!(expression_name("result.values.0"));
        assert!(!expression_name("params.9 lives!"));
        assert!(!expression_name(""));
    }

    #[test]
    fn the_narrowest_equivalent_reading_is_taken() {
        let alts = ["i16be@8".to_owned(), "u8@9".to_owned(), "мусор".to_owned()];
        assert_eq!(narrowest(8, "u16be", &alts), (9, "u8".to_owned()));
        assert_eq!(narrowest(10, "u16be", &[]), (10, "u16be".to_owned()));
    }

    #[test]
    fn fields_in_every_encoding_render_into_an_accepted_description() {
        let framing: Framing = serde_json::from_value(serde_json::json!({
            "kind": "length_prefixed",
            "length": { "at": 0, "type": "u8", "adjust": 0 },
            "status": "hypothesis"
        }))
        .unwrap();
        let mut hyps = Hypotheses::default();
        let hypothesis = hyps.id("all", || "поля разных кодировок".to_owned(), None);
        let field = |name: &str, at: u64, ty: &str, len: Option<&str>, mask: Option<u64>| Field {
            name: name.to_owned(),
            at: at.to_string(),
            ty: ty.to_owned(),
            len: len.map(str::to_owned),
            expect: None,
            mask,
            hypothesis,
            span: None,
        };
        let message = Message {
            id: "m".to_owned(),
            when: String::new(),
            count: 1,
            fields: vec![
                field("flag", 1, "u8", None, Some(0x08)),
                field("serial", 2, "bcd", Some("2"), None),
                field("temperature", 4, "f32le", None, None),
            ],
        };
        let yaml = render(&framing, &[message], &hyps, &[]);
        assert!(yaml.contains("type: u8, mask: 0x08"), "{yaml}");
        assert!(yaml.contains("type: bcd, len: 2"), "{yaml}");
        parse(&yaml).unwrap();
    }
}
