//! Интерпретация протокола: схема DSL, язык выражений, фрейминг и применение к потокам.
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
pub mod checksum;
pub mod export;
pub mod expr;
pub mod framing;
pub mod input;
pub mod schema;
mod yaml_error;

pub use apply::{
    Category, FieldResult, FieldState, MessageResult, StreamResult, Violation, ViolationKind, apply,
};
pub use checksum::Algorithm;
pub use expr::{Context, Expr, ExprError, Value};
pub use input::{Read, Region, RegionKind, StreamInput, StreamMeta};
pub use schema::{Interpretation, SchemaError};
