//! Подсказки для исследователя: где проходят границы сообщений, какие байты постоянны, кто кому отвечает.
//!
//! Чистая библиотека: данные приходят готовыми, ничего не читается с диска. Всё здесь — гипотезы с
//! основаниями (доля подтверждений, первый контрпример), а не выводы, и ничего не знает о конкретном
//! протоколе. Результат детерминирован: стабильные сортировки, без времени и случайности.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]

mod exchanges;
mod framing;
mod variability;

pub use exchanges::{Certainty, Exchange, ExchangeStats, Msg, pair_exchanges};
pub use framing::{
    Counter, CounterReason, DelimiterHint, FieldRef, FixedHint, FramingHints, FramingSpec,
    LengthHint, LengthSpecHint, SignatureHint, find_framing,
};
pub use variability::{
    Column, CounterHint, LengthClass, Region, RegionKind, TopValue, Variability,
    VariabilityOptions, variability,
};

/// Непрерывный участок известных байтов потока. `segment_starts` — смещения (внутри участка), с которых
/// начинались TCP-сегменты: часто с них же начинаются и сообщения.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DataRun {
    pub data: Vec<u8>,
    pub segment_starts: Vec<usize>,
    /// Участок начинается ровно с начала сообщения (виден начало потока); иначе начало могло прийтись на середину.
    pub starts_at_boundary: bool,
}

/// Направленный поток для анализа: идентификатор и участки без дыр.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamSample {
    pub id: String,
    pub runs: Vec<DataRun>,
}

/// Сколько байтов одного потока анализируется (остальное отбрасывается, об этом сказано в результате).
pub const MAX_STREAM_BYTES: usize = 1 << 20;
/// Сколько байтов анализируется за один запрос на все потоки.
pub const MAX_TOTAL_BYTES: usize = 16 << 20;
/// Сколько потоков анализируется за раз.
pub const MAX_STREAMS: usize = 64;
/// Сколько сообщений проходится по каждому участку при проверке кандидата.
pub const MAX_WALK_MESSAGES: usize = 2_000;
/// Сколько первых байтов сообщения просматривается при поиске изменчивости.
pub const MAX_COLUMNS: usize = 4_096;
/// Сколько сообщений участвует в анализе изменчивости.
pub const MAX_MESSAGES: usize = 100_000;
