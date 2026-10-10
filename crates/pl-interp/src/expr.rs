//! Язык выражений для условий `when`, проверок и тестов гипотез.
//!
//! Свой интерпретатор без доступа к файлам, сети и процессам (`plan/security.md` T13): число шагов
//! и глубина ограничены, арифметика проверяемая, неизвестное имя — отдельная ошибка, а не ноль.

use std::collections::BTreeSet;
use std::fmt;

/// Предел шагов вычисления выражения.
pub const MAX_STEPS: u32 = 10_000;
/// Предел вложенности выражения.
pub const MAX_DEPTH: u32 = 32;
/// Предел длины текста выражения.
pub const MAX_EXPR_LEN: usize = 1_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExprError {
    #[error("выражение разобрать не удалось (позиция {pos}): {why}")]
    Parse { pos: usize, why: String },
    #[error("выражение слишком длинное или слишком вложенное")]
    TooComplex,
    #[error("неизвестное имя «{0}»")]
    UnknownName(String),
    #[error("неизвестная функция «{0}»")]
    UnknownFunction(String),
    #[error("несовместимые типы в «{0}»")]
    Type(&'static str),
    #[error("деление на ноль")]
    DivisionByZero,
    #[error("переполнение при вычислении")]
    Overflow,
    #[error("превышен предел шагов вычисления ({MAX_STEPS})")]
    StepLimit,
    #[error("неверные аргументы функции «{0}»")]
    Arguments(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Int(i128),
    Bool(bool),
    Str(String),
    Bytes(Vec<u8>),
}

impl Value {
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Int(_) => "число",
            Value::Bool(_) => "логическое",
            Value::Str(_) => "строка",
            Value::Bytes(_) => "байты",
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Int(v) => write!(f, "{v}"),
            Value::Bool(v) => write!(f, "{v}"),
            Value::Str(v) => write!(f, "{v}"),
            Value::Bytes(v) => {
                for b in v {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Add,
    Sub,
    Mul,
    Div,
    Rem,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Int(i128),
    Bool(bool),
    Str(String),
    Name(String),
    Not(Box<Node>),
    Neg(Box<Node>),
    Bin(Op, Box<Node>, Box<Node>),
    Call(String, Vec<Node>),
}

/// Разобранное выражение.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expr {
    root: Node,
}

/// Откуда берутся значения имён и функции над сообщением.
pub trait Context {
    /// `None` — имени нет: выражение к этим данным неприменимо.
    fn get(&self, name: &str) -> Option<Value>;
    /// Сумма байтов сообщения `[from, to)` по модулю 256.
    fn sum8(&self, from: i128, to: i128) -> Result<i128, ExprError>;
}

// ---------------------------------------------------------------- разбор

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Int(i128),
    Str(String),
    Name(String),
    Sym(&'static str),
}

fn lex(src: &str) -> Result<Vec<(usize, Tok)>, ExprError> {
    let chars: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let err = |pos: usize, why: &str| ExprError::Parse {
        pos,
        why: why.to_owned(),
    };
    while let Some(&c) = chars.get(i) {
        let start = i;
        if c.is_whitespace() {
            i += 1;
        } else if c.is_ascii_digit() {
            let hex = c == '0' && matches!(chars.get(i + 1), Some('x' | 'X'));
            if hex {
                i += 2;
            }
            let from = i;
            while chars.get(i).is_some_and(|d| {
                if hex {
                    d.is_ascii_hexdigit()
                } else {
                    d.is_ascii_digit()
                }
            }) {
                i += 1;
            }
            let digits: String = chars.get(from..i).unwrap_or_default().iter().collect();
            let value = i128::from_str_radix(&digits, if hex { 16 } else { 10 })
                .map_err(|_| err(start, "некорректное число"))?;
            out.push((start, Tok::Int(value)));
        } else if c.is_alphabetic() || c == '_' {
            while chars
                .get(i)
                .is_some_and(|d| d.is_alphanumeric() || *d == '_' || *d == '.')
            {
                i += 1;
            }
            out.push((
                start,
                Tok::Name(chars.get(start..i).unwrap_or_default().iter().collect()),
            ));
        } else if c == '"' || c == '\'' {
            i += 1;
            let from = i;
            while chars.get(i).is_some_and(|d| *d != c) {
                i += 1;
            }
            if chars.get(i).is_none() {
                return Err(err(start, "строка не закрыта"));
            }
            out.push((
                start,
                Tok::Str(chars.get(from..i).unwrap_or_default().iter().collect()),
            ));
            i += 1;
        } else {
            let two: String = chars
                .get(i..(i + 2).min(chars.len()))
                .unwrap_or_default()
                .iter()
                .collect();
            let sym: &'static str = match two.as_str() {
                "==" => "==",
                "!=" => "!=",
                "<=" => "<=",
                ">=" => ">=",
                "&&" => "&&",
                "||" => "||",
                _ => match c {
                    '<' => "<",
                    '>' => ">",
                    '+' => "+",
                    '-' => "-",
                    '*' => "*",
                    '/' => "/",
                    '%' => "%",
                    '!' => "!",
                    '(' => "(",
                    ')' => ")",
                    ',' => ",",
                    _ => return Err(err(start, "неожиданный символ")),
                },
            };
            i += sym.len();
            out.push((start, Tok::Sym(sym)));
        }
    }
    Ok(out)
}

struct Parser {
    toks: Vec<(usize, Tok)>,
    at: usize,
    depth: u32,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.at).map(|(_, t)| t)
    }

    fn pos(&self) -> usize {
        self.toks.get(self.at).map_or(usize::MAX, |(p, _)| *p)
    }

    fn eat(&mut self, sym: &str) -> bool {
        if matches!(self.peek(), Some(Tok::Sym(s)) if *s == sym) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn fail<T>(&self, why: &str) -> Result<T, ExprError> {
        Err(ExprError::Parse {
            pos: self.pos(),
            why: why.to_owned(),
        })
    }

    fn enter(&mut self) -> Result<(), ExprError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(ExprError::TooComplex);
        }
        Ok(())
    }

    fn binary(&mut self, level: usize) -> Result<Node, ExprError> {
        const LEVELS: [&[(&str, Op)]; 6] = [
            &[("||", Op::Or)],
            &[("&&", Op::And)],
            &[("==", Op::Eq), ("!=", Op::Ne)],
            &[("<=", Op::Le), (">=", Op::Ge), ("<", Op::Lt), (">", Op::Gt)],
            &[("+", Op::Add), ("-", Op::Sub)],
            &[("*", Op::Mul), ("/", Op::Div), ("%", Op::Rem)],
        ];
        let Some(ops) = LEVELS.get(level) else {
            return self.unary();
        };
        self.enter()?;
        let mut left = self.binary(level + 1)?;
        'outer: loop {
            for (sym, op) in *ops {
                if self.eat(sym) {
                    let right = self.binary(level + 1)?;
                    left = Node::Bin(*op, Box::new(left), Box::new(right));
                    continue 'outer;
                }
            }
            break;
        }
        self.depth -= 1;
        Ok(left)
    }

    fn unary(&mut self) -> Result<Node, ExprError> {
        self.enter()?;
        let node = if self.eat("!") {
            Node::Not(Box::new(self.unary()?))
        } else if self.eat("-") {
            Node::Neg(Box::new(self.unary()?))
        } else {
            self.primary()?
        };
        self.depth -= 1;
        Ok(node)
    }

    fn primary(&mut self) -> Result<Node, ExprError> {
        let Some(tok) = self.peek().cloned() else {
            return self.fail("выражение оборвано");
        };
        self.at += 1;
        match tok {
            Tok::Int(v) => Ok(Node::Int(v)),
            Tok::Str(s) => Ok(Node::Str(s)),
            Tok::Name(n) if n == "true" => Ok(Node::Bool(true)),
            Tok::Name(n) if n == "false" => Ok(Node::Bool(false)),
            Tok::Name(n) => {
                if self.eat("(") {
                    let mut args = Vec::new();
                    if !self.eat(")") {
                        loop {
                            args.push(self.binary(0)?);
                            if self.eat(")") {
                                break;
                            }
                            if !self.eat(",") {
                                return self.fail("ожидалась запятая или «)»");
                            }
                        }
                    }
                    Ok(Node::Call(n, args))
                } else {
                    Ok(Node::Name(n))
                }
            }
            Tok::Sym("(") => {
                let inner = self.binary(0)?;
                if !self.eat(")") {
                    return self.fail("ожидалась «)»");
                }
                Ok(inner)
            }
            Tok::Sym(_) => {
                self.at -= 1;
                self.fail("неожиданный знак")
            }
        }
    }
}

impl Expr {
    pub fn parse(src: &str) -> Result<Self, ExprError> {
        if src.chars().count() > MAX_EXPR_LEN {
            return Err(ExprError::TooComplex);
        }
        let toks = lex(src)?;
        if toks.is_empty() {
            return Err(ExprError::Parse {
                pos: 0,
                why: "выражение пустое".to_owned(),
            });
        }
        let mut parser = Parser {
            toks,
            at: 0,
            depth: 0,
        };
        let root = parser.binary(0)?;
        if parser.at != parser.toks.len() {
            return parser.fail("лишние символы после выражения");
        }
        Ok(Self { root })
    }

    /// Все имена, на которые ссылается выражение (для проверки схемы).
    pub fn names(&self) -> BTreeSet<String> {
        fn walk(n: &Node, out: &mut BTreeSet<String>) {
            match n {
                Node::Name(name) => {
                    out.insert(name.clone());
                }
                Node::Not(a) | Node::Neg(a) => walk(a, out),
                Node::Bin(_, a, b) => {
                    walk(a, out);
                    walk(b, out);
                }
                Node::Call(_, args) => args.iter().for_each(|a| walk(a, out)),
                Node::Int(_) | Node::Bool(_) | Node::Str(_) => {}
            }
        }
        let mut out = BTreeSet::new();
        walk(&self.root, &mut out);
        out
    }

    pub fn eval(&self, ctx: &dyn Context) -> Result<Value, ExprError> {
        self.eval_with_limit(ctx, MAX_STEPS)
    }

    fn eval_with_limit(&self, ctx: &dyn Context, limit: u32) -> Result<Value, ExprError> {
        let mut steps = Steps { used: 0, limit };
        eval(&self.root, ctx, &mut steps)
    }

    /// Выражение как условие: должно давать логическое значение.
    pub fn eval_bool(&self, ctx: &dyn Context) -> Result<bool, ExprError> {
        match self.eval(ctx)? {
            Value::Bool(b) => Ok(b),
            _ => Err(ExprError::Type("условие должно быть логическим")),
        }
    }

    pub fn eval_int(&self, ctx: &dyn Context) -> Result<i128, ExprError> {
        match self.eval(ctx)? {
            Value::Int(v) => Ok(v),
            _ => Err(ExprError::Type("ожидалось число")),
        }
    }
}

// ------------------------------------------------------------ вычисление

struct Steps {
    used: u32,
    limit: u32,
}

fn eval(n: &Node, ctx: &dyn Context, steps: &mut Steps) -> Result<Value, ExprError> {
    steps.used += 1;
    if steps.used > steps.limit {
        return Err(ExprError::StepLimit);
    }
    match n {
        Node::Int(v) => Ok(Value::Int(*v)),
        Node::Bool(v) => Ok(Value::Bool(*v)),
        Node::Str(v) => Ok(Value::Str(v.clone())),
        Node::Name(name) => ctx
            .get(name)
            .ok_or_else(|| ExprError::UnknownName(name.clone())),
        Node::Not(a) => match eval(a, ctx, steps)? {
            Value::Bool(b) => Ok(Value::Bool(!b)),
            _ => Err(ExprError::Type("!")),
        },
        Node::Neg(a) => match eval(a, ctx, steps)? {
            Value::Int(v) => v.checked_neg().map(Value::Int).ok_or(ExprError::Overflow),
            _ => Err(ExprError::Type("-")),
        },
        Node::Bin(Op::And, a, b) => match eval(a, ctx, steps)? {
            Value::Bool(false) => Ok(Value::Bool(false)),
            Value::Bool(true) => match eval(b, ctx, steps)? {
                Value::Bool(v) => Ok(Value::Bool(v)),
                _ => Err(ExprError::Type("&&")),
            },
            _ => Err(ExprError::Type("&&")),
        },
        Node::Bin(Op::Or, a, b) => match eval(a, ctx, steps)? {
            Value::Bool(true) => Ok(Value::Bool(true)),
            Value::Bool(false) => match eval(b, ctx, steps)? {
                Value::Bool(v) => Ok(Value::Bool(v)),
                _ => Err(ExprError::Type("||")),
            },
            _ => Err(ExprError::Type("||")),
        },
        Node::Bin(op, a, b) => {
            let (l, r) = (eval(a, ctx, steps)?, eval(b, ctx, steps)?);
            binary(*op, l, r)
        }
        Node::Call(name, args) => call(name, args, ctx, steps),
    }
}

fn int(v: &Value, what: &'static str) -> Result<i128, ExprError> {
    match v {
        Value::Int(i) => Ok(*i),
        _ => Err(ExprError::Type(what)),
    }
}

fn binary(op: Op, l: Value, r: Value) -> Result<Value, ExprError> {
    match op {
        Op::Eq | Op::Ne => {
            let eq = match (&l, &r) {
                (Value::Int(a), Value::Int(b)) => a == b,
                (Value::Bool(a), Value::Bool(b)) => a == b,
                (Value::Str(a), Value::Str(b)) => a == b,
                (Value::Bytes(a), Value::Bytes(b)) => a == b,
                // Байты сравниваются с hex-строкой: `signature == "5ac3"`.
                (Value::Bytes(_), Value::Str(s)) | (Value::Str(s), Value::Bytes(_)) => {
                    let bytes = if let Value::Bytes(b) = &l {
                        b
                    } else if let Value::Bytes(b) = &r {
                        b
                    } else {
                        return Err(ExprError::Type("=="));
                    };
                    Value::Bytes(bytes.clone()).to_string()
                        == s.trim_start_matches("0x").to_ascii_lowercase()
                }
                _ => return Err(ExprError::Type("==")),
            };
            Ok(Value::Bool(if op == Op::Eq { eq } else { !eq }))
        }
        Op::Lt | Op::Le | Op::Gt | Op::Ge => {
            let (a, b) = (int(&l, "сравнение")?, int(&r, "сравнение")?);
            Ok(Value::Bool(match op {
                Op::Lt => a < b,
                Op::Le => a <= b,
                Op::Gt => a > b,
                _ => a >= b,
            }))
        }
        Op::Add | Op::Sub | Op::Mul | Op::Div | Op::Rem => {
            let (a, b) = (int(&l, "арифметика")?, int(&r, "арифметика")?);
            let result = match op {
                Op::Add => a.checked_add(b),
                Op::Sub => a.checked_sub(b),
                Op::Mul => a.checked_mul(b),
                _ if b == 0 => return Err(ExprError::DivisionByZero),
                Op::Div => a.checked_div(b),
                _ => a.checked_rem(b),
            };
            result.map(Value::Int).ok_or(ExprError::Overflow)
        }
        Op::And | Op::Or => Err(ExprError::Type("логическая операция")),
    }
}

fn call(
    name: &str,
    args: &[Node],
    ctx: &dyn Context,
    steps: &mut Steps,
) -> Result<Value, ExprError> {
    match name {
        "sum8" => {
            let [from, to] = args else {
                return Err(ExprError::Arguments("sum8"));
            };
            let from = int(&eval(from, ctx, steps)?, "sum8")?;
            let to = int(&eval(to, ctx, steps)?, "sum8")?;
            ctx.sum8(from, to).map(Value::Int)
        }
        _ => Err(ExprError::UnknownFunction(name.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    struct Env(BTreeMap<&'static str, Value>);

    impl Context for Env {
        fn get(&self, name: &str) -> Option<Value> {
            self.0.get(name).cloned()
        }

        fn sum8(&self, from: i128, to: i128) -> Result<i128, ExprError> {
            Ok((from + to) % 256)
        }
    }

    fn env() -> Env {
        Env(BTreeMap::from([
            ("type", Value::Int(2)),
            ("length", Value::Int(300)),
            ("sig", Value::Bytes(vec![0x5a, 0xc3])),
            ("action.params.value", Value::Int(21)),
            ("proto", Value::Str("tcp".to_owned())),
        ]))
    }

    fn run(src: &str) -> Result<Value, ExprError> {
        Expr::parse(src)?.eval(&env())
    }

    #[test]
    fn arithmetic_and_logic() {
        assert_eq!(
            run("type == 0x02 && length + 4 > 300"),
            Ok(Value::Bool(true))
        );
        assert_eq!(run("(1 + 2) * 3 - 4 / 2 % 3"), Ok(Value::Int(7)));
        assert_eq!(run("!(type == 3) || false"), Ok(Value::Bool(true)));
        assert_eq!(run("-length + 300 == 0"), Ok(Value::Bool(true)));
        assert_eq!(run("action.params.value == 21"), Ok(Value::Bool(true)));
        assert_eq!(run("proto == 'tcp'"), Ok(Value::Bool(true)));
    }

    #[test]
    fn bytes_compare_with_hex_strings() {
        assert_eq!(run("sig == '5ac3'"), Ok(Value::Bool(true)));
        assert_eq!(run("sig == \"0x5AC3\""), Ok(Value::Bool(true)));
        assert_eq!(run("sig != '5ac4'"), Ok(Value::Bool(true)));
    }

    #[test]
    fn short_circuit_skips_unknown_names() {
        assert_eq!(run("false && nope == 1"), Ok(Value::Bool(false)));
        assert_eq!(run("true || nope == 1"), Ok(Value::Bool(true)));
        assert_eq!(
            run("nope == 1"),
            Err(ExprError::UnknownName("nope".to_owned()))
        );
    }

    #[test]
    fn errors_are_reported_not_hidden() {
        assert_eq!(run("1 / 0"), Err(ExprError::DivisionByZero));
        assert_eq!(run("1 % 0"), Err(ExprError::DivisionByZero));
        assert_eq!(run("type == 'x'"), Err(ExprError::Type("==")));
        assert_eq!(run("1 && 2"), Err(ExprError::Type("&&")));
        assert_eq!(
            run("pow(2, 3)"),
            Err(ExprError::UnknownFunction("pow".to_owned()))
        );
        assert_eq!(run("sum8(1)"), Err(ExprError::Arguments("sum8")));
        let huge = "9999999999999999999999999999999999999999";
        assert!(
            matches!(Expr::parse(huge), Err(ExprError::Parse { .. })),
            "{huge}"
        );
        assert_eq!(
            run("170141183460469231731687303715884105727 + 1"),
            Err(ExprError::Overflow)
        );
    }

    #[test]
    fn parse_errors_have_positions() {
        for bad in [
            "", "1 +", "(1", "1 2", "a == ", "== 1", "'x", "1 $ 2", "f(1,", "f(,)",
        ] {
            assert!(
                matches!(Expr::parse(bad), Err(ExprError::Parse { .. })),
                "{bad}"
            );
        }
        let Err(ExprError::Parse { pos, .. }) = Expr::parse("1 + $") else {
            panic!("ожидалась ошибка разбора");
        };
        assert_eq!(pos, 4);
    }

    #[test]
    fn complexity_is_limited() {
        let deep = format!("{}1{}", "(".repeat(100), ")".repeat(100));
        assert_eq!(Expr::parse(&deep), Err(ExprError::TooComplex));
        let nots = format!("{}true", "!".repeat(100));
        assert_eq!(Expr::parse(&nots), Err(ExprError::TooComplex));
        let long = "1+".repeat(600) + "1";
        assert_eq!(Expr::parse(&long), Err(ExprError::TooComplex));
        // 2000 слагаемых укладываются в длину, но не в предел шагов.
        let wide = vec!["1"; 4000].join("+");
        assert!(Expr::parse(&wide).is_err());
    }

    #[test]
    fn step_limit_stops_heavy_expressions() {
        let src = vec!["(1+1)"; 150].join("+");
        let expr = Expr::parse(&src).unwrap();
        assert_eq!(expr.eval_with_limit(&env(), 100), Err(ExprError::StepLimit));
        assert!(expr.eval(&env()).is_ok());
    }

    #[test]
    fn names_are_collected() {
        let e = Expr::parse("a.b + c * sum8(d, 1) > 0 && !e").unwrap();
        let names: Vec<_> = e.names().into_iter().collect();
        assert_eq!(names, ["a.b", "c", "d", "e"]);
    }
}
