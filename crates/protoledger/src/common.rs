//! Общее для команд: коды возврата и чтение файлов.

use std::path::{Component, Path, PathBuf};

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

/// Путь к проекту из командной строки: «..» и «.» раскрываются от текущего каталога.
/// Внутри проекта «..» запрещены, но свой путь пользователь вправе написать как угодно.
pub fn project_path(path: &Path) -> PathBuf {
    if !path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return path.to_path_buf();
    }
    let mut out = if path.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir().unwrap_or_default()
    };
    for part in path.components() {
        match part {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

/// Записи из аргументов: файл берётся как есть, из каталога — его `.pcap` и `.pcapng` по имени,
/// без вложенных каталогов.
pub fn capture_files(paths: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    for p in paths {
        let meta = std::fs::metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
        if meta.is_dir() {
            let mut found: Vec<PathBuf> = std::fs::read_dir(p)
                .map_err(|e| format!("{}: {e}", p.display()))?
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|f| {
                    f.is_file()
                        && f.extension()
                            .and_then(|e| e.to_str())
                            .is_some_and(|e| matches!(e, "pcap" | "pcapng"))
                })
                .collect();
            found.sort();
            out.extend(found);
        } else {
            out.push(p.clone());
        }
    }
    if out.is_empty() {
        return Err("Записей .pcap и .pcapng не найдено.".to_owned());
    }
    Ok(out)
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
    std::fs::read_to_string(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::InvalidData => {
            format!("{}: файл не в кодировке UTF-8", path.display())
        }
        _ => format!("{}: {e}", path.display()),
    })
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
