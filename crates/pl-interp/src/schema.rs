//! Схема `protoledger/interpretation@1` (ADR 0005): разбор YAML, проверка, digest.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::expr::Expr;

pub const FORMAT: &str = "protoledger/interpretation@1";
/// Размер файла интерпретации (`plan/security.md` §6).
pub const MAX_FILE_BYTES: usize = 4 << 20;
pub const MAX_MESSAGES: usize = 1_000;
pub const MAX_FIELDS: usize = 1_000;
pub const MAX_ITEMS: usize = 10_000;
/// Предел размера одного сообщения (`plan/security.md` §6).
pub const MAX_MESSAGE_BYTES: u64 = 16 << 20;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SchemaError {
    #[error("файл интерпретации больше {MAX_FILE_BYTES} байт")]
    TooLarge,
    #[error("YAML не разобран: {0}")]
    Yaml(String),
    #[error("{0}")]
    Invalid(String),
}

fn invalid<T>(msg: impl Into<String>) -> Result<T, SchemaError> {
    Err(SchemaError::Invalid(msg.into()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    #[default]
    Any,
    AToB,
    BToA,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    #[serde(default)]
    pub direction: Direction,
    /// Условие на поток: `src_port`, `dst_port`, `src_ip`, `dst_ip`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
}

/// Статус знания (ТЗ 8): правило, гипотеза или неизвестная зона.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Rule,
    Hypothesis,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntType {
    U8,
    U16be,
    U16le,
    U32be,
    U32le,
    U64be,
    U64le,
    I8,
    I16be,
    I16le,
    I32be,
    I32le,
    I64be,
    I64le,
}

impl IntType {
    pub fn size(self) -> usize {
        match self {
            Self::U8 | Self::I8 => 1,
            Self::U16be | Self::U16le | Self::I16be | Self::I16le => 2,
            Self::U32be | Self::U32le | Self::I32be | Self::I32le => 4,
            Self::U64be | Self::U64le | Self::I64be | Self::I64le => 8,
        }
    }

    pub fn big_endian(self) -> bool {
        matches!(
            self,
            Self::U8
                | Self::I8
                | Self::U16be
                | Self::U32be
                | Self::U64be
                | Self::I16be
                | Self::I32be
                | Self::I64be
        )
    }

    pub fn signed(self) -> bool {
        matches!(
            self,
            Self::I8
                | Self::I16be
                | Self::I16le
                | Self::I32be
                | Self::I32le
                | Self::I64be
                | Self::I64le
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    U8,
    U16be,
    U16le,
    U32be,
    U32le,
    U64be,
    U64le,
    I8,
    I16be,
    I16le,
    I32be,
    I32le,
    I64be,
    I64le,
    Bytes,
    String,
    Unknown,
}

impl FieldType {
    pub fn int(self) -> Option<IntType> {
        Some(match self {
            Self::U8 => IntType::U8,
            Self::U16be => IntType::U16be,
            Self::U16le => IntType::U16le,
            Self::U32be => IntType::U32be,
            Self::U32le => IntType::U32le,
            Self::U64be => IntType::U64be,
            Self::U64le => IntType::U64le,
            Self::I8 => IntType::I8,
            Self::I16be => IntType::I16be,
            Self::I16le => IntType::I16le,
            Self::I32be => IntType::I32be,
            Self::I32le => IntType::I32le,
            Self::I64be => IntType::I64be,
            Self::I64le => IntType::I64le,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FramingKind {
    LengthPrefixed,
    Delimiter,
    Fixed,
    Magic,
}

/// Длина полного сообщения = значение поля длины + `adjust`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LengthSpec {
    pub at: u32,
    #[serde(rename = "type")]
    pub ty: IntType,
    #[serde(default)]
    pub adjust: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Framing {
    pub kind: FramingKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<LengthSpec>,
    /// Размер сообщения для `fixed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u32>,
    /// Разделитель (`delimiter`) или начало сообщения (`magic`), hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<String>,
    #[serde(default)]
    pub status: Status,
}

/// Смещение поля: число от начала сообщения или `end-N` — от конца.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum At {
    Abs(u32),
    Text(String),
}

/// Длина поля: число, `to_end` или выражение над ранее объявленными полями.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Len {
    Fixed(u32),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Expect {
    Int(i128),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldDef {
    pub name: String,
    pub at: At,
    #[serde(rename = "type")]
    pub ty: FieldType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub len: Option<Len>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect: Option<Expect>,
    #[serde(default)]
    pub status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hypothesis: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageDef {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub fields: Vec<FieldDef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hypothesis {
    pub id: String,
    pub statement: String,
    /// Наблюдения-основания (`obs-7`).
    #[serde(default)]
    pub basis: Vec<String>,
    /// Тест на корпусе; имена `action.params.*`, `action.result` и `response.*` — из контекста прогона.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CheckKind {
    #[default]
    Structural,
    Semantic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub id: String,
    #[serde(default)]
    pub kind: CheckKind,
    pub expr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// К каким сообщениям применяется; без значения — ко всем.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interpretation {
    pub format: String,
    #[serde(default)]
    pub scope: Scope,
    pub framing: Framing,
    #[serde(default)]
    pub messages: Vec<MessageDef>,
    #[serde(default)]
    pub hypotheses: Vec<Hypothesis>,
    #[serde(default)]
    pub checks: Vec<Check>,
}

/// Разбор `0x…` и десятичных чисел для `expect`.
pub fn parse_hex(text: &str) -> Option<Vec<u8>> {
    let t = text.trim().trim_start_matches("0x");
    if t.is_empty() || !t.len().is_multiple_of(2) || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    t.as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
        .collect()
}

/// Позиция поля после разбора `at`: от начала или от конца сообщения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offset {
    FromStart(u32),
    FromEnd(u32),
}

impl At {
    pub fn offset(&self) -> Option<Offset> {
        match self {
            At::Abs(n) => Some(Offset::FromStart(*n)),
            At::Text(t) => t
                .trim()
                .strip_prefix("end-")
                .and_then(|n| n.trim().parse().ok())
                .map(Offset::FromEnd),
        }
    }
}

impl Interpretation {
    /// Разбирает и проверяет файл. Ошибки — понятные пользователю, с именами полей.
    pub fn parse(text: &str) -> Result<Self, SchemaError> {
        if text.len() > MAX_FILE_BYTES {
            return Err(SchemaError::TooLarge);
        }
        // T12: ни якорей, ни алиасов, небольшая глубина.
        let mut budget = serde_saphyr::Budget::default();
        budget.max_aliases = 0;
        budget.max_anchors = 0;
        budget.max_depth = 24;
        budget.max_events = 500_000;
        budget.max_nodes = 200_000;
        let mut options = serde_saphyr::Options::default();
        options.budget = Some(budget);
        let it: Interpretation = serde_saphyr::from_str_with_options(text, options)
            .map_err(|e| SchemaError::Yaml(e.to_string()))?;
        it.validate()?;
        Ok(it)
    }

    /// Каноническая форма (JSON с фиксированным порядком полей) и её sha256.
    pub fn digest(&self) -> String {
        let canonical = serde_json::to_string(self).unwrap_or_default();
        Sha256::digest(canonical.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    pub fn to_yaml(&self) -> Result<String, SchemaError> {
        serde_saphyr::to_string(self).map_err(|e| SchemaError::Yaml(e.to_string()))
    }

    fn validate(&self) -> Result<(), SchemaError> {
        if self.format != FORMAT {
            return invalid(format!(
                "format должен быть «{FORMAT}», а не «{}»",
                self.format
            ));
        }
        if self.messages.len() > MAX_MESSAGES
            || self.hypotheses.len() > MAX_ITEMS
            || self.checks.len() > MAX_ITEMS
        {
            return invalid("слишком много описаний");
        }
        if let Some(filter) = &self.scope.filter {
            let allowed = ["src_port", "dst_port", "src_ip", "dst_ip"];
            self.check_expr("scope.filter", filter, |n| allowed.contains(&n))?;
        }
        self.validate_framing()?;
        self.validate_hypotheses()?;

        let mut ids = BTreeSet::new();
        for m in &self.messages {
            if !ids.insert(m.id.as_str()) {
                return invalid(format!("сообщение «{}» описано дважды", m.id));
            }
            self.validate_message(m)?;
        }
        let mut checks = BTreeSet::new();
        for c in &self.checks {
            if !checks.insert(c.id.as_str()) {
                return invalid(format!("проверка «{}» описана дважды", c.id));
            }
            if let Some(target) = &c.message
                && !self.messages.iter().any(|m| &m.id == target)
            {
                return invalid(format!("проверка «{}»: нет сообщения «{target}»", c.id));
            }
            // Имена полей — любые: какие есть, зависит от сообщения; проверяется при применении.
            Expr::parse(&c.expr)
                .map_err(|e| SchemaError::Invalid(format!("проверка «{}»: {e}", c.id)))?;
        }
        Ok(())
    }

    fn check_expr(
        &self,
        ctx: &str,
        src: &str,
        known: impl Fn(&str) -> bool,
    ) -> Result<Expr, SchemaError> {
        let expr = Expr::parse(src).map_err(|e| SchemaError::Invalid(format!("{ctx}: {e}")))?;
        if let Some(name) = expr.names().iter().find(|n| !known(n)) {
            return invalid(format!("{ctx}: неизвестное имя «{name}»"));
        }
        Ok(expr)
    }

    fn validate_framing(&self) -> Result<(), SchemaError> {
        let f = &self.framing;
        match f.kind {
            FramingKind::LengthPrefixed => {
                let Some(length) = &f.length else {
                    return invalid("framing.length_prefixed: нужно поле length {at, type}");
                };
                let _ = length;
            }
            FramingKind::Fixed => match f.size {
                Some(n) if n > 0 && u64::from(n) <= MAX_MESSAGE_BYTES => {}
                _ => return invalid("framing.fixed: size должен быть от 1 до 16 МиБ"),
            },
            FramingKind::Delimiter | FramingKind::Magic => {
                let ok = f
                    .bytes
                    .as_deref()
                    .and_then(parse_hex)
                    .is_some_and(|b| !b.is_empty());
                if !ok {
                    return invalid("framing: bytes — непустая hex-строка («0d0a»)");
                }
            }
        }
        Ok(())
    }

    fn validate_hypotheses(&self) -> Result<(), SchemaError> {
        let mut ids = BTreeSet::new();
        for h in &self.hypotheses {
            if !ids.insert(h.id.as_str()) {
                return invalid(format!("гипотеза «{}» описана дважды", h.id));
            }
            if let Some(test) = &h.test {
                Expr::parse(test)
                    .map_err(|e| SchemaError::Invalid(format!("гипотеза «{}»: {e}", h.id)))?;
            }
        }
        Ok(())
    }

    fn validate_message(&self, m: &MessageDef) -> Result<(), SchemaError> {
        if m.fields.len() > MAX_FIELDS {
            return invalid(format!("сообщение «{}»: слишком много полей", m.id));
        }
        let mut names = BTreeSet::new();
        for field in &m.fields {
            let ctx = format!("сообщение «{}», поле «{}»", m.id, field.name);
            if field.name.is_empty()
                || !field.name.chars().all(|c| c.is_alphanumeric() || c == '_')
                || field
                    .name
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_digit())
            {
                return invalid(format!("{ctx}: имя — буквы, цифры и «_», не с цифры"));
            }
            if !names.insert(field.name.as_str()) {
                return invalid(format!("{ctx}: имя повторяется"));
            }
            if field.at.offset().is_none() {
                return invalid(format!("{ctx}: at — число или «end-N»"));
            }
            self.validate_field(m, field, &ctx, &names)?;
        }
        if let Some(when) = &m.when {
            // `when` вычисляется до разбора: только поля с известным местом и размером.
            let fixed: BTreeSet<&str> = m
                .fields
                .iter()
                .filter(|f| matches!(f.at, At::Abs(_)) && is_fixed_size(f))
                .map(|f| f.name.as_str())
                .collect();
            self.check_expr(
                &format!("сообщение «{}», when", m.id),
                when,
                |n| fixed.contains(n),
            )?;
        }
        Ok(())
    }

    fn validate_field(
        &self,
        m: &MessageDef,
        f: &FieldDef,
        ctx: &str,
        earlier: &BTreeSet<&str>,
    ) -> Result<(), SchemaError> {
        match f.ty {
            FieldType::Unknown => {
                if f.status != Status::Unknown {
                    return invalid(format!(
                        "{ctx}: type unknown допускает только status unknown"
                    ));
                }
            }
            FieldType::Bytes | FieldType::String => {
                if f.len.is_none() {
                    return invalid(format!("{ctx}: для bytes и string нужна len"));
                }
            }
            _ if f.len.is_some() => {
                return invalid(format!("{ctx}: len только у bytes, string и unknown"));
            }
            _ => {}
        }
        if let Some(Len::Text(text)) = &f.len
            && text != "to_end"
        {
            // Длина считается по полям, объявленным раньше.
            let earlier: BTreeSet<String> = earlier.iter().map(|s| (*s).to_owned()).collect();
            self.check_expr(&format!("{ctx}, len"), text, |n| {
                earlier.contains(n) && n != f.name
            })?;
        }
        match f.status {
            Status::Hypothesis => match &f.hypothesis {
                Some(id) if self.hypotheses.iter().any(|h| &h.id == id) => {}
                Some(id) => return invalid(format!("{ctx}: гипотезы «{id}» нет в hypotheses")),
                None => return invalid(format!("{ctx}: для status hypothesis укажите hypothesis")),
            },
            _ if f.hypothesis.is_some() => {
                return invalid(format!("{ctx}: hypothesis только при status hypothesis"));
            }
            _ => {}
        }
        if let Some(expect) = &f.expect {
            let ok = match (f.ty, expect) {
                (FieldType::Bytes, Expect::Text(t)) => parse_hex(t).is_some(),
                (FieldType::String, Expect::Text(_)) => true,
                (t, Expect::Int(_)) => t.int().is_some(),
                (t, Expect::Text(s)) => t.int().is_some() && parse_hex(s).is_some(),
            };
            if !ok {
                return invalid(format!(
                    "{ctx}: expect не подходит к типу (для bytes — hex-строка в кавычках, для чисел — число)"
                ));
            }
        }
        let _ = m;
        Ok(())
    }
}

/// Поле с известным размером: целое или bytes/string с числовой длиной.
pub fn is_fixed_size(f: &FieldDef) -> bool {
    f.ty.int().is_some()
        || (matches!(f.ty, FieldType::Bytes | FieldType::String)
            && matches!(f.len, Some(Len::Fixed(_))))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) const STAND: &str = r#"
format: protoledger/interpretation@1
scope:
  direction: any
  filter: "dst_port == 4710 || src_port == 4710"
framing:
  kind: length_prefixed
  length: { at: 4, type: u16le, adjust: 7 }
  status: rule
messages:
  - id: set_param_req
    when: "type == 0x02"
    fields:
      - { name: signature, at: 0, type: bytes, len: 2, expect: "5ac3", status: rule }
      - { name: type,      at: 2, type: u8, status: rule }
      - { name: session,   at: 3, type: u8, status: rule }
      - { name: length,    at: 4, type: u16le, status: rule }
      - { name: param,     at: 6, type: u8, status: hypothesis, hypothesis: H1 }
      - { name: value,     at: 7, type: i32be, status: hypothesis, hypothesis: H2 }
      - { name: checksum,  at: end-1, type: u8, status: rule }
hypotheses:
  - { id: H1, statement: "param — идентификатор параметра", basis: [obs-1] }
  - { id: H2, statement: "value — устанавливаемое значение", basis: [obs-2], test: "value == action.params.value" }
checks:
  - { id: C1, kind: structural, expr: "length + 7 == message.len" }
  - { id: C2, kind: structural, expr: "checksum == sum8(0, message.len - 1)" }
"#;

    #[test]
    fn parses_the_adr_example() {
        let it = Interpretation::parse(STAND).unwrap();
        assert_eq!(it.messages.len(), 1);
        assert_eq!(it.framing.kind, FramingKind::LengthPrefixed);
        assert_eq!(
            it.messages[0].fields[6].at.offset(),
            Some(Offset::FromEnd(1))
        );
        assert_eq!(it.digest().len(), 64);
    }

    #[test]
    fn digest_is_stable_and_ignores_formatting() {
        let a = Interpretation::parse(STAND).unwrap();
        let reformatted = a.to_yaml().unwrap();
        let b = Interpretation::parse(&reformatted).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.digest(), b.digest());
        let changed = STAND.replace("adjust: 7", "adjust: 8");
        assert_ne!(
            Interpretation::parse(&changed).unwrap().digest(),
            a.digest()
        );
    }

    fn rejected(text: &str) -> String {
        match Interpretation::parse(text) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("ожидалась ошибка"),
        }
    }

    #[test]
    fn validation_messages_name_the_problem() {
        let cases = [
            (STAND.replace("@1", "@2"), "format должен быть"),
            (
                STAND.replace("kind: length_prefixed", "kind: bogus"),
                "bogus",
            ),
            (
                STAND.replace(
                    "type: u8, status: rule }\n      - { name: session",
                    "type: u9, status: rule }\n      - { name: session",
                ),
                "u9",
            ),
            (STAND.replace("hypothesis: H2", "hypothesis: H9"), "H9"),
            (
                STAND.replace("when: \"type == 0x02\"", "when: \"nope == 1\""),
                "nope",
            ),
            (
                STAND.replace("expect: \"5ac3\"", "expect: \"5ac\""),
                "expect",
            ),
            (STAND.replace("name: param,", "name: type,"), "повторяется"),
            (STAND.replace("at: end-1", "at: sometimes"), "at"),
            (STAND.replace("len: 2,", "len: 2, bogus: 1,"), "bogus"),
            (
                STAND.replace(
                    "filter: \"dst_port == 4710 || src_port == 4710\"",
                    "filter: \"foo == 1\"",
                ),
                "foo",
            ),
            (
                STAND.replace("{ at: 4, type: u16le, adjust: 7 }", "{ at: 4 }"),
                "type",
            ),
        ];
        for (text, needle) in cases {
            let msg = rejected(&text);
            assert!(msg.contains(needle), "«{needle}» нет в «{msg}»");
        }
    }

    #[test]
    fn unknown_fields_and_status_rules() {
        let unknown_with_rule = "format: protoledger/interpretation@1\nframing: { kind: fixed, size: 4 }\nmessages:\n  - id: m\n    fields:\n      - { name: x, at: 0, type: unknown, len: 4, status: rule }\n";
        assert!(rejected(unknown_with_rule).contains("unknown"));
        let hypothesis_without_id = "format: protoledger/interpretation@1\nframing: { kind: fixed, size: 4 }\nmessages:\n  - id: m\n    fields:\n      - { name: x, at: 0, type: u8, status: hypothesis }\n";
        assert!(rejected(hypothesis_without_id).contains("hypothesis"));
        let ok = "format: protoledger/interpretation@1\nframing: { kind: fixed, size: 4 }\nmessages:\n  - id: m\n    fields:\n      - { name: x, at: 0, type: unknown, len: to_end }\n";
        assert!(Interpretation::parse(ok).is_ok());
    }

    #[test]
    fn hostile_yaml_is_limited() {
        let bomb = "format: protoledger/interpretation@1\na: &a [x, x, x, x]\nb: &b [*a, *a, *a, *a]\nframing: {kind: fixed, size: 1}\n";
        assert!(matches!(
            Interpretation::parse(bomb),
            Err(SchemaError::Yaml(_))
        ));
        let deep = format!(
            "format: x\nframing: {}1{}\n",
            "[".repeat(100),
            "]".repeat(100)
        );
        assert!(Interpretation::parse(&deep).is_err());
        let huge = "x".repeat(MAX_FILE_BYTES + 1);
        assert_eq!(Interpretation::parse(&huge), Err(SchemaError::TooLarge));
        assert!(Interpretation::parse("").is_err());
        assert!(Interpretation::parse("- 1\n- 2").is_err());
    }

    #[test]
    fn framing_requirements() {
        let base = "format: protoledger/interpretation@1\n";
        assert!(Interpretation::parse(&format!("{base}framing: {{ kind: fixed }}")).is_err());
        assert!(
            Interpretation::parse(&format!(
                "{base}framing: {{ kind: delimiter, bytes: '0d0a' }}"
            ))
            .is_ok()
        );
        assert!(
            Interpretation::parse(&format!("{base}framing: {{ kind: magic, bytes: 'zz' }}"))
                .is_err()
        );
        assert!(
            Interpretation::parse(&format!("{base}framing: {{ kind: length_prefixed }}")).is_err()
        );
    }
}
