//! Мост между собранным потоком и интерпретацией: участки потока → вход `pl-interp`.

use pl_interp::schema::Direction;
use pl_interp::{Region, RegionKind, StreamInput, StreamMeta};
use pl_reassembly::{Connection, PieceKind, Stream};

use crate::SourceData;

fn slice(file: &[u8], at: u64, len: u64) -> &[u8] {
    usize::try_from(at)
        .ok()
        .and_then(|a| file.get(a..a.checked_add(usize::try_from(len).ok()?)?))
        .unwrap_or_default()
}

/// Входной поток для интерпретации: байты берутся из файла записи без копирования.
/// `direction_index`: 0 — от `a` к `b`, 1 — от `b` к `a`.
pub fn stream_input<'a>(
    file: &'a [u8],
    connection: &Connection,
    stream: &Stream,
    direction_index: usize,
) -> StreamInput<'a> {
    let (src, dst) = if direction_index == 0 {
        (connection.a, connection.b)
    } else {
        (connection.b, connection.a)
    };
    let regions = stream
        .pieces
        .iter()
        .map(|p| {
            let len = p.end - p.start;
            let kind = match &p.kind {
                PieceKind::Data(b) => RegionKind::Data(slice(file, b.file_offset, len)),
                PieceKind::Gap => RegionKind::Gap,
                PieceKind::Ambiguous { chosen, variants } => RegionKind::Ambiguous(
                    chosen
                        .and_then(|c| variants.get(c))
                        .map(|b| slice(file, b.file_offset, len)),
                ),
            };
            Region {
                start: p.start,
                end: p.end,
                kind,
            }
        })
        .collect();
    StreamInput {
        meta: StreamMeta {
            direction: if direction_index == 0 {
                Direction::AToB
            } else {
                Direction::BToA
            },
            src_ip: src.ip().to_string(),
            dst_ip: dst.ip().to_string(),
            src_port: src.port(),
            dst_port: dst.port(),
        },
        length: stream.length,
        regions,
    }
}

/// Результат применения к одному направленному потоку записи.
pub struct StreamApplied {
    pub connection: u32,
    pub direction_index: usize,
    pub result: pl_interp::StreamResult,
}

/// Применяет интерпретацию ко всем потокам записи.
pub fn apply_to_source(
    it: &pl_interp::Interpretation,
    data: &SourceData,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<StreamApplied>, pl_interp::framing::FrameError> {
    let mut out = Vec::new();
    for connection in &data.connections {
        for (i, stream) in connection.streams.iter().enumerate() {
            let input = stream_input(&data.file, connection, stream, i);
            out.push(StreamApplied {
                connection: connection.number,
                direction_index: i,
                result: pl_interp::apply(it, &input, cancelled)?,
            });
        }
    }
    Ok(out)
}
