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

pub mod apply;
pub mod expr;
pub mod framing;
pub mod input;
pub mod schema;

pub use apply::{
    Category, FieldResult, FieldState, MessageResult, StreamResult, Violation, ViolationKind, apply,
};
pub use expr::{Context, Expr, ExprError, Value};
pub use input::{Read, Region, RegionKind, StreamInput, StreamMeta};
pub use schema::{Interpretation, SchemaError};
