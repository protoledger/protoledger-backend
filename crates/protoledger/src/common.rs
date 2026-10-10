//! Общее для команд: коды возврата и чтение файлов.

use std::path::Path;

use pl_core::Problem;

/// Коды возврата CLI: 0 — всё совпало, 1 — есть отличия, 2 — ошибка.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Ok,
    Differences,
}

impl Exit {
    pub fn code(self) -> u8 {
        match self {
            Exit::Ok => 0,
            Exit::Differences => 1,
        }
    }
}

/// Размер текстовых входов CLI (интерпретация, сопоставление): те же пределы, что у API.
const MAX_TEXT: u64 = 4 << 20;

pub fn read_text(path: &Path) -> Result<String, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() || meta.len() > MAX_TEXT {
        return Err(format!(
            "{}: нужен обычный файл не больше 4 МиБ",
            path.display()
        ));
    }
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Ошибка движка в виде строки для пользователя: файл и причина.
pub fn fail(path: &Path, problem: &Problem) -> String {
    format!(
        "{}: {}",
        path.display(),
        problem
            .detail
            .clone()
            .unwrap_or_else(|| problem.title.to_owned())
    )
}
