//! Загрузка записи из браузера (`multipart/form-data`, поле `file`).
//!
//! Файл пишется потоком во временную папку внутри проекта (`.cache/uploads/…`), не копится в памяти
//! и не попадает в системные временные папки (T46). Дальше обычный импорт по пути.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use axum::extract::Multipart;
use axum::extract::multipart::Field;
use pl_core::{Limit, Problem, ProblemKind};
use tokio::io::AsyncWriteExt;

use crate::{ApiError, AppState};

static UPLOAD_COUNTER: AtomicU64 = AtomicU64::new(0);
const MAX_NAME_CHARS: usize = 100;

/// Загруженный файл и папка, которую нужно удалить после импорта.
pub struct Upload {
    pub dir: PathBuf,
    pub file: PathBuf,
}

/// Имя файла только для показа: без путей и управляющих символов.
fn display_name(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or(raw);
    let cleaned: String = base
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME_CHARS)
        .collect();
    // Имя станет частью пути во временной папке: точки и пустое имя не годятся.
    let cleaned = cleaned.trim().trim_start_matches('.').to_owned();
    if cleaned.is_empty() {
        "upload.pcap".to_owned()
    } else {
        cleaned
    }
}

fn bad(detail: impl Into<String>) -> ApiError {
    ApiError::new(ProblemKind::BadRequest, detail)
}

fn too_large(max: u64) -> ApiError {
    ApiError(
        Problem::new(
            ProblemKind::LimitExceeded,
            format!("Файл больше защитного предела {max} байт."),
        )
        .with_limit(Limit {
            name: "max_source_size",
            value: max,
            unit: "bytes",
        }),
    )
}

fn io_failed() -> ApiError {
    ApiError::new(
        ProblemKind::Internal,
        "Не удалось сохранить загруженный файл. Проверьте свободное место и права на папку проекта.",
    )
}

async fn write_field(field: &mut Field<'_>, path: &Path, max: u64) -> Result<(), ApiError> {
    let mut out = tokio::fs::File::create(path)
        .await
        .map_err(|_| io_failed())?;
    let mut total = 0u64;
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|_| bad("Загрузка прервана или повреждена."))?
    {
        total += chunk.len() as u64;
        if total > max {
            return Err(too_large(max));
        }
        out.write_all(&chunk).await.map_err(|_| io_failed())?;
    }
    out.flush().await.map_err(|_| io_failed())?;
    Ok(())
}

/// Сохраняет поле `file`; при любой ошибке временная папка удаляется.
pub async fn save(state: &AppState, mut multipart: Multipart) -> Result<Upload, ApiError> {
    let cache = state
        .session
        .read()
        .as_ref()
        .map(|p| p.cache_dir())
        .ok_or_else(|| ApiError(pl_app::Session::no_project()))?;
    let n = UPLOAD_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = cache
        .join("uploads")
        .join(format!("{}-{n}", std::process::id()));
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|_| io_failed())?;

    let result = async {
        while let Some(mut field) = multipart
            .next_field()
            .await
            .map_err(|_| bad("Тело запроса не похоже на multipart/form-data."))?
        {
            if field.name() != Some("file") {
                continue;
            }
            let name = display_name(field.file_name().unwrap_or_default());
            let file = dir.join(name);
            write_field(&mut field, &file, state.max_upload).await?;
            return Ok(file);
        }
        Err(bad("В запросе нет поля file с файлом записи."))
    }
    .await;

    match result {
        Ok(file) => Ok(Upload { dir, file }),
        Err(error) => {
            let _ = tokio::fs::remove_dir_all(&dir).await;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::display_name;

    #[test]
    fn names_are_safe() {
        assert_eq!(display_name("session.pcap"), "session.pcap");
        assert_eq!(display_name("C:\\dir\\..\\x.pcapng"), "x.pcapng");
        assert_eq!(display_name("../../etc/passwd"), "passwd");
        assert_eq!(display_name(".."), "upload.pcap");
        assert_eq!(display_name(""), "upload.pcap");
        assert_eq!(display_name("a\u{0}b\nc.pcap"), "abc.pcap");
        assert_eq!(display_name(&"x".repeat(500)).chars().count(), 100);
    }
}
