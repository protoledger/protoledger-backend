//! Общие типы движка: пока — ошибки API в формате Problem Details.

mod problem;

pub use problem::{Limit, Problem, ProblemKind};
