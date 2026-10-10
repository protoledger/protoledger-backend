//! Интерпретация протокола (ADR 0005): схема DSL, язык выражений, фрейминг и применение к потокам.
//! Чистая библиотека: без HTTP, проекта и ввода-вывода. Описания и данные — недоверенный ввод.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]

pub mod expr;
pub mod schema;

pub use expr::{Context, Expr, ExprError, Value};
pub use schema::{Interpretation, SchemaError};
