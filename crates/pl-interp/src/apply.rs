//! Применение интерпретации к направленному потоку: сообщения, поля, категории результата
//! (`plan/architecture.md` §4). Свойства протокола и ограничения реализации не смешиваются.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::expr::{Context, Expr, ExprError, Value};
use crate::framing::{self, Frame, FrameError, Problem, Unknown, read_int};
use crate::input::{Read, StreamInput};
use crate::schema::{
    At, Check, Direction, Expect, FieldDef, FieldType, Interpretation, Len, MessageDef, Offset,
    Status, parse_hex,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Сообщение выделено, тип найден, поля декодированы, проверки прошли.
    Matched,
    /// Нарушена проверка `rule` или `expect`.
    Violated,
    /// Сообщение задевает дыру или обрывается в конце потока.
    Incomplete,
    /// Сообщение задевает неоднозначный участок.
    Ambiguous,
    /// Ни одно описание сообщения не подошло.
    Unmatched,
    /// Ограничение реализации: превышен защитный предел.
    LimitExceeded,
}

impl Category {
    pub fn code(self) -> &'static str {
        match self {
            Category::Matched => "matched",
            Category::Violated => "violated",
            Category::Incomplete => "incomplete",
            Category::Ambiguous => "ambiguous",
            Category::Unmatched => "unmatched",
            Category::LimitExceeded => "limit_exceeded",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldState {
    Decoded,
    /// Тип `unknown`: зона отмечена как неизученная.
    Unknown,
    Gap,
    Ambiguous,
    /// Поле не помещается в сообщение.
    OutOfMessage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldResult {
    pub name: String,
    /// Абсолютное смещение в потоке и длина.
    pub at: u64,
    pub len: u64,
    pub status: Status,
    pub hypothesis: Option<String>,
    pub state: FieldState,
    pub value: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind {
    Framing,
    Expect,
    Check,
    FieldRange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub kind: ViolationKind,
    /// Поле или проверка.
    pub id: String,
    pub detail: String,
    /// Статус нарушенного знания: от него зависит, сделает ли нарушение сообщение `violated`.
    pub status: Status,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageResult {
    pub start: u64,
    pub end: u64,
    pub category: Category,
    pub message_id: Option<String>,
    pub fields: Vec<FieldResult>,
    pub violations: Vec<Violation>,
    /// Байты сообщения вне описанных полей и в зонах `unknown`.
    pub unknown_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StreamResult {
    /// Поток вне области применимости (`scope`): сообщения не разбирались.
    pub out_of_scope: bool,
    pub messages: Vec<MessageResult>,
}

impl StreamResult {
    pub fn counts(&self) -> BTreeMap<Category, u64> {
        let mut out = BTreeMap::new();
        for m in &self.messages {
            *out.entry(m.category).or_insert(0) += 1;
        }
        out
    }

    pub fn unknown_bytes(&self) -> u64 {
        self.messages.iter().map(|m| m.unknown_bytes).sum()
    }
}

struct Compiled<'a> {
    it: &'a Interpretation,
    whens: Vec<Option<Expr>>,
    checks: Vec<(&'a Check, Expr)>,
}

fn compile(it: &Interpretation) -> Compiled<'_> {
    Compiled {
        it,
        whens: it
            .messages
            .iter()
            .map(|m| m.when.as_deref().and_then(|w| Expr::parse(w).ok()))
            .collect(),
        checks: it
            .checks
            .iter()
            .filter_map(|c| Expr::parse(&c.expr).ok().map(|e| (c, e)))
            .collect(),
    }
}

struct StreamCtx<'a>(&'a crate::input::StreamMeta);

impl Context for StreamCtx<'_> {
    fn get(&self, name: &str) -> Option<Value> {
        match name {
            "src_port" => Some(Value::Int(i128::from(self.0.src_port))),
            "dst_port" => Some(Value::Int(i128::from(self.0.dst_port))),
            "src_ip" => Some(Value::Str(self.0.src_ip.clone())),
            "dst_ip" => Some(Value::Str(self.0.dst_ip.clone())),
            _ => None,
        }
    }

    fn sum8(&self, _: i128, _: i128) -> Result<i128, ExprError> {
        Err(ExprError::UnknownFunction("sum8".to_owned()))
    }
}

pub fn apply(
    it: &Interpretation,
    input: &StreamInput<'_>,
    cancelled: &dyn Fn() -> bool,
) -> Result<StreamResult, FrameError> {
    let in_dir = match it.scope.direction {
        Direction::Any => true,
        d => d == input.meta.direction,
    };
    let in_filter = match &it.scope.filter {
        None => true,
        Some(f) => Expr::parse(f)
            .and_then(|e| e.eval_bool(&StreamCtx(&input.meta)))
            .unwrap_or(false),
    };
    if !(in_dir && in_filter) {
        return Ok(StreamResult {
            out_of_scope: true,
            messages: Vec::new(),
        });
    }
    let compiled = compile(it);
    let frames = framing::frame(&it.framing, input, cancelled)?;
    let messages = frames
        .iter()
        .map(|f| message(&compiled, input, f))
        .collect();
    Ok(StreamResult {
        out_of_scope: false,
        messages,
    })
}

/// Доступ к байтам сообщения `[start, end)` по смещению внутри него.
struct View<'a, 'b> {
    input: &'a StreamInput<'b>,
    start: u64,
    end: u64,
}

impl View<'_, '_> {
    fn len(&self) -> u64 {
        self.end - self.start
    }

    fn resolve(&self, at: &At) -> Option<u64> {
        match at.offset()? {
            Offset::FromStart(n) => self.start.checked_add(u64::from(n)),
            Offset::FromEnd(n) => self.end.checked_sub(u64::from(n)),
        }
    }
}

fn decode(ty: FieldType, bytes: &[u8]) -> Option<Value> {
    if let Some(int) = ty.int() {
        return read_int(bytes, int).map(Value::Int);
    }
    match ty {
        FieldType::Bytes => Some(Value::Bytes(bytes.to_vec())),
        FieldType::String => Some(Value::Str(String::from_utf8_lossy(bytes).into_owned())),
        _ => None,
    }
}

/// Контекст `when`: поля с известным местом и размером читаются по требованию.
struct WhenCtx<'a, 'b> {
    view: &'a View<'a, 'b>,
    def: &'a MessageDef,
}

impl Context for WhenCtx<'_, '_> {
    fn get(&self, name: &str) -> Option<Value> {
        let field = self.def.fields.iter().find(|f| f.name == name)?;
        let at = self.view.resolve(&field.at)?;
        let len = fixed_len(field)?;
        match self.view.input.read(at, len) {
            Read::Bytes(b) if at + len <= self.view.end => decode(field.ty, &b),
            _ => None,
        }
    }

    fn sum8(&self, _: i128, _: i128) -> Result<i128, ExprError> {
        Err(ExprError::UnknownFunction("sum8".to_owned()))
    }
}

fn fixed_len(f: &FieldDef) -> Option<u64> {
    if let Some(int) = f.ty.int() {
        return Some(int.size() as u64);
    }
    match (&f.len, f.ty) {
        (Some(Len::Fixed(n)), FieldType::Bytes | FieldType::String | FieldType::Unknown) => {
            Some(u64::from(*n))
        }
        _ => None,
    }
}

/// Контекст проверок: значения декодированных полей и сведения о сообщении.
struct CheckCtx<'a, 'b> {
    values: &'a BTreeMap<String, Value>,
    view: &'a View<'a, 'b>,
}

impl Context for CheckCtx<'_, '_> {
    fn get(&self, name: &str) -> Option<Value> {
        match name {
            "message.len" => Some(Value::Int(i128::from(self.view.len()))),
            "message.start" => Some(Value::Int(i128::from(self.view.start))),
            _ => self.values.get(name).cloned(),
        }
    }

    fn sum8(&self, from: i128, to: i128) -> Result<i128, ExprError> {
        let len = i128::from(self.view.len());
        if from < 0 || to < from || to > len {
            return Err(ExprError::Arguments("sum8"));
        }
        let (Ok(from), Ok(span)) = (u64::try_from(from), u64::try_from(to - from)) else {
            return Err(ExprError::Arguments("sum8"));
        };
        match self.view.input.read(self.view.start + from, span) {
            Read::Bytes(b) => Ok(b.iter().fold(0i128, |acc, x| (acc + i128::from(*x)) % 256)),
            _ => Err(ExprError::UnknownName("байты сообщения".to_owned())),
        }
    }
}

fn violation(kind: ViolationKind, id: &str, status: Status, detail: String) -> Violation {
    Violation {
        kind,
        id: id.to_owned(),
        detail,
        status,
    }
}

fn expect_matches(field: &FieldDef, expect: &Expect, value: &Value) -> bool {
    match (expect, value) {
        (Expect::Int(e), Value::Int(v)) => i128::from(*e) == *v,
        (Expect::Text(t), Value::Bytes(b)) => parse_hex(t).is_some_and(|e| &e == b),
        (Expect::Text(t), Value::Str(s)) => t == s,
        (Expect::Text(t), Value::Int(v)) => {
            field.ty.int().is_some()
                && parse_hex(t).is_some_and(|b| {
                    b.iter().try_fold(0i128, |acc, x| {
                        acc.checked_mul(256).map(|a| a + i128::from(*x))
                    }) == Some(*v)
                })
        }
        _ => false,
    }
}

fn message(c: &Compiled<'_>, input: &StreamInput<'_>, frame: &Frame) -> MessageResult {
    let view = View {
        input,
        start: frame.start,
        end: frame.end,
    };
    let mut result = MessageResult {
        start: frame.start,
        end: frame.end,
        category: Category::Matched,
        message_id: None,
        fields: Vec::new(),
        violations: Vec::new(),
        unknown_bytes: view.len(),
    };

    // Ограничения фрейминга и неопределимые границы.
    match frame.problem {
        Some(Problem::TooLarge(n)) => {
            result.category = Category::LimitExceeded;
            result.violations.push(violation(
                ViolationKind::Framing,
                "framing",
                c.it.framing.status,
                format!(
                    "заявленная длина сообщения {n} байт больше предела; разбор потока остановлен"
                ),
            ));
            return result;
        }
        Some(Problem::BadLength(n)) => {
            result.category = Category::Violated;
            result.violations.push(violation(
                ViolationKind::Framing,
                "framing",
                c.it.framing.status,
                format!(
                    "поле длины даёт невозможную длину сообщения {n}; разбор потока остановлен"
                ),
            ));
            return result;
        }
        Some(Problem::Unframed) => {
            result.category = Category::Unmatched;
            return result;
        }
        _ => {}
    }
    let frame_incomplete = matches!(
        frame.problem,
        Some(Problem::EndOfStream | Problem::Unknown(Unknown::Gap))
    );
    let frame_ambiguous = matches!(frame.problem, Some(Problem::Unknown(Unknown::Ambiguous)));

    // Какое описание подходит.
    let mut undecidable = false;
    let mut chosen: Option<(usize, &MessageDef)> = None;
    for (i, def) in c.it.messages.iter().enumerate() {
        let matched = match c.whens.get(i).and_then(Option::as_ref) {
            None if def.when.is_none() => true,
            None => false,
            Some(expr) => match expr.eval_bool(&WhenCtx { view: &view, def }) {
                Ok(b) => b,
                Err(ExprError::UnknownName(_)) => {
                    undecidable = true;
                    false
                }
                Err(_) => false,
            },
        };
        if matched {
            chosen = Some((i, def));
            break;
        }
    }
    let unknown_in_message = input.first_unknown(frame.start, frame.end);
    let Some((_, def)) = chosen else {
        result.category = match (undecidable, unknown_in_message, frame_incomplete) {
            (true, Some((_, _, true)), _) | (_, _, true) => Category::Incomplete,
            (true, Some((_, _, false)), _) => Category::Ambiguous,
            _ => Category::Unmatched,
        };
        if frame_ambiguous {
            result.category = Category::Ambiguous;
        }
        return result;
    };
    result.message_id = Some(def.id.clone());

    // Поля по порядку описания.
    let mut values: BTreeMap<String, Value> = BTreeMap::new();
    let mut covered: Vec<(u64, u64)> = Vec::new();
    for field in &def.fields {
        let mut fr = FieldResult {
            name: field.name.clone(),
            at: 0,
            len: 0,
            status: field.status,
            hypothesis: field.hypothesis.clone(),
            state: FieldState::OutOfMessage,
            value: None,
        };
        let Some(at) = view.resolve(&field.at) else {
            result.fields.push(fr);
            continue;
        };
        fr.at = at;
        let len = match (&field.len, fixed_len(field)) {
            (_, Some(n)) => Some(n),
            (Some(Len::Text(t)), _) if t == "to_end" => Some(view.end.saturating_sub(at)),
            (Some(Len::Text(t)), _) => Expr::parse(t)
                .and_then(|e| {
                    e.eval_int(&CheckCtx {
                        values: &values,
                        view: &view,
                    })
                })
                .ok()
                .and_then(|n| u64::try_from(n).ok()),
            _ => None,
        };
        let Some(len) = len else {
            result.violations.push(violation(
                ViolationKind::FieldRange,
                &field.name,
                field.status,
                "длину поля вычислить не удалось".to_owned(),
            ));
            result.fields.push(fr);
            continue;
        };
        fr.len = len;
        if at < view.start || at.saturating_add(len) > view.end {
            if frame.problem.is_none() && field.status != Status::Unknown {
                result.violations.push(violation(
                    ViolationKind::FieldRange,
                    &field.name,
                    field.status,
                    format!(
                        "поле выходит за границы сообщения длиной {} байт",
                        view.len()
                    ),
                ));
            }
            result.fields.push(fr);
            continue;
        }
        if field.ty == FieldType::Unknown {
            fr.state = FieldState::Unknown;
            result.fields.push(fr);
            continue;
        }
        match input.read(at, len) {
            Read::Bytes(bytes) => {
                fr.state = FieldState::Decoded;
                fr.value = decode(field.ty, &bytes);
                covered.push((at, at + len));
                if let Some(value) = &fr.value {
                    if let Some(expect) = &field.expect
                        && !expect_matches(field, expect, value)
                    {
                        result.violations.push(violation(
                            ViolationKind::Expect,
                            &field.name,
                            field.status,
                            format!("ожидалось {}, в данных {value}", expect_text(expect)),
                        ));
                    }
                    values.insert(field.name.clone(), value.clone());
                }
            }
            Read::Gap => {
                fr.state = FieldState::Gap;
                covered.push((at, at + len));
            }
            Read::Ambiguous => {
                fr.state = FieldState::Ambiguous;
                covered.push((at, at + len));
            }
            Read::OutOfRange => {}
        }
        result.fields.push(fr);
    }

    // Проверки: неприменимые к этим данным (нет значения или байтов) пропускаются, а не проваливаются.
    let ctx = CheckCtx {
        values: &values,
        view: &view,
    };
    for (check, expr) in &c.checks {
        if check.message.as_deref().is_some_and(|m| m != def.id) {
            continue;
        }
        match expr.eval_bool(&ctx) {
            Ok(true) | Err(ExprError::UnknownName(_)) => {}
            Ok(false) => result.violations.push(violation(
                ViolationKind::Check,
                &check.id,
                Status::Rule,
                check
                    .description
                    .clone()
                    .unwrap_or_else(|| format!("не выполнено: {}", check.expr)),
            )),
            Err(e) => result.violations.push(violation(
                ViolationKind::Check,
                &check.id,
                Status::Rule,
                format!("проверка не вычислилась: {e}"),
            )),
        }
    }

    result.unknown_bytes =
        view.len()
            .saturating_sub(covered_bytes(&mut covered, def, &result.fields));

    let rule_broken = result.violations.iter().any(|v| v.status == Status::Rule);
    result.category = if frame_incomplete
        || result.fields.iter().any(|f| f.state == FieldState::Gap)
        || unknown_in_message.is_some_and(|(_, _, gap)| gap)
    {
        Category::Incomplete
    } else if frame_ambiguous
        || unknown_in_message.is_some()
        || result
            .fields
            .iter()
            .any(|f| f.state == FieldState::Ambiguous)
    {
        Category::Ambiguous
    } else if rule_broken {
        Category::Violated
    } else {
        Category::Matched
    };
    result
}

fn expect_text(e: &Expect) -> String {
    match e {
        Expect::Int(v) => v.to_string(),
        Expect::Text(t) => t.clone(),
    }
}

/// Сколько байт сообщения описано полями (кроме зон `unknown`), без двойного счёта перекрытий.
fn covered_bytes(covered: &mut Vec<(u64, u64)>, def: &MessageDef, fields: &[FieldResult]) -> u64 {
    let _ = def;
    covered.retain(|(a, b)| {
        fields.iter().any(|f| {
            f.at == *a
                && f.at + f.len == *b
                && f.status != Status::Unknown
                && f.state != FieldState::Unknown
        })
    });
    covered.sort_unstable();
    let mut total = 0;
    let mut end = 0;
    for (a, b) in covered.iter().copied() {
        let a = a.max(end);
        if b > a {
            total += b - a;
            end = b;
        }
    }
    total
}
