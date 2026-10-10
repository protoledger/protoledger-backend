//! Детерминированный генератор синтетических записей трафика с дефектами захвата (ТЗ 7.3)
//! и эталоном сборки для каждой записи. Только для тестов и замеров, в продукт не входит.

pub mod capture;
pub mod expected;
pub mod net;
pub mod rng;
pub mod scenario;
pub mod tcp;

pub use capture::{Capture, Format};
pub use scenario::{Generated, SCENARIOS, Scenario, find, generate, profile};
