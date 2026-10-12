//! Язык выражений: разбор и вычисление с пределами шагов и вложенности.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pl_interp::{Context, Expr, ExprError, Value};

struct Names;

impl Context for Names {
    fn get(&self, name: &str) -> Option<Value> {
        match name {
            "a" => Some(Value::Int(1)),
            "b" => Some(Value::Int(i128::MAX)),
            "c" => Some(Value::Int(i128::MIN)),
            "s" => Some(Value::Str("-2.5".to_owned())),
            "raw" => Some(Value::Bytes(vec![0xA5, 0x5A])),
            "flag" => Some(Value::Bool(true)),
            "message.len" => Some(Value::Int(64)),
            _ => None,
        }
    }

    fn sum8(&self, from: i128, to: i128) -> Result<i128, ExprError> {
        if from < 0 || to < from || to > 64 {
            return Err(ExprError::Arguments("sum8"));
        }
        Ok((to - from) % 256)
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(expr) = Expr::parse(text) {
        let _ = expr.names();
        let _ = expr.eval(&Names);
        let _ = expr.eval_bool(&Names);
    }
});
