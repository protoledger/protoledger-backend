use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

use crate::error::ProjectError;
use crate::manifest::{FORMAT_VERSION, ImportRecord, Manifest, Settings, SourceFormat};

/// Размер файла записи, `plan/security.md` §6.
pub const MAX_SOURCE_SIZE: u64 = 1 << 30;
/// Размер `project.yaml`: манифест — небольшой текст, больше — признак подмены.
pub const MAX_MANIFEST_SIZE: u64 = 4 << 20;
const MAX_IMPORTS: usize = 100_000;
const MAX_NAME_CHARS: usize = 255;

const MANIFEST_FILE: &str = "project.yaml";
const SOURCES_DIR: &str = "sources";
const CACHE_DIR: &str = ".cache";
const PROJECT_SUFFIX: &str = ".protoledger";
const COPY_BUFFER: usize = 64 * 1024;

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn is_valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Запись проекта: один файл по sha256, может быть импортирована несколько раз.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub sha256: String,
    pub name: String,
    pub format: SourceFormat,
    pub size_bytes: u64,
    /// Последний импорт.
    pub import_id: String,
    pub import_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceStatus {
    Ready,
    Missing,
    Damaged,
}

#[derive(Debug)]
pub struct Project {
    root: PathBuf,
    manifest: Manifest,
}

/// Временный файл рядом с целью; удаляется, если не закреплён переименованием.
struct TempFile {
    path: PathBuf,
    keep: bool,
}

impl TempFile {
    fn new(dir: &Path, prefix: &str) -> Self {
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        Self {
            path: dir.join(format!(".{prefix}-{}-{n}.tmp", std::process::id())),
            keep: false,
        }
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn validate_path(path: &Path) -> Result<(), ProjectError> {
    if path.as_os_str().is_empty() {
        return Err(ProjectError::InvalidPath("путь пустой"));
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(ProjectError::InvalidPath("«..» в пути не допускается"));
    }
    Ok(())
}

fn sanitize_name(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '/' | '\\') {
                '_'
            } else {
                c
            }
        })
        .take(MAX_NAME_CHARS)
        .collect();
    cleaned.trim().to_owned()
}

fn detect_format(magic: &[u8]) -> Option<SourceFormat> {
    match magic {
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xd4, 0xc3, 0xb2, 0xa1] => Some(SourceFormat::Pcap),
        // Вариант pcap с наносекундными метками времени.
        [0xa1, 0xb2, 0x3c, 0x4d] | [0x4d, 0x3c, 0xb2, 0xa1] => Some(SourceFormat::Pcap),
        [0x0a, 0x0d, 0x0d, 0x0a] => Some(SourceFormat::Pcapng),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(unix)]
fn restrict_dir(path: &Path) -> Result<(), ProjectError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(ProjectError::io("права папки"))
}

#[cfg(not(unix))]
fn restrict_dir(_path: &Path) -> Result<(), ProjectError> {
    // Windows: папка в профиле пользователя, права наследуются (plan/security.md T31).
    Ok(())
}

#[cfg(unix)]
fn create_private_file(path: &Path, mode: u32) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
}

#[cfg(not(unix))]
fn create_private_file(path: &Path, _mode: u32) -> std::io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

fn make_readonly(path: &Path) -> Result<(), ProjectError> {
    let mut perms = fs::metadata(path)
        .map_err(ProjectError::io("права файла"))?
        .permissions();
    perms.set_readonly(true);
    fs::set_permissions(path, perms).map_err(ProjectError::io("права файла"))
}

fn save_manifest(root: &Path, manifest: &Manifest) -> Result<(), ProjectError> {
    let text = serde_saphyr::to_string(manifest)
        .map_err(|e| ProjectError::InvalidManifest(e.to_string()))?;
    let mut tmp = TempFile::new(root, "project");
    let mut file =
        create_private_file(&tmp.path, 0o600).map_err(ProjectError::io("запись манифеста"))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(ProjectError::io("запись манифеста"))?;
    drop(file);
    // Атомарная замена: либо старый манифест, либо новый целиком.
    fs::rename(&tmp.path, root.join(MANIFEST_FILE))
        .map_err(ProjectError::io("замена манифеста"))?;
    tmp.keep = true;
    Ok(())
}

fn load_manifest(root: &Path) -> Result<Manifest, ProjectError> {
    let path = root.join(MANIFEST_FILE);
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ProjectError::NotAProject);
        }
        Err(e) => {
            return Err(ProjectError::Io {
                op: "чтение манифеста",
                source: e,
            });
        }
    };
    // T9: ссылки внутри папки проекта не следуем.
    if !meta.is_file() {
        return Err(ProjectError::NotAProject);
    }
    if meta.len() > MAX_MANIFEST_SIZE {
        return Err(ProjectError::LimitExceeded {
            name: "max_manifest_size",
            value: MAX_MANIFEST_SIZE,
            unit: "bytes",
        });
    }
    let mut text = String::new();
    File::open(&path)
        .and_then(|f| f.take(MAX_MANIFEST_SIZE + 1).read_to_string(&mut text))
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::InvalidData => {
                ProjectError::InvalidManifest("файл не в кодировке UTF-8".to_owned())
            }
            _ => ProjectError::Io {
                op: "чтение манифеста",
                source: e,
            },
        })?;
    if text.len() as u64 > MAX_MANIFEST_SIZE {
        return Err(ProjectError::LimitExceeded {
            name: "max_manifest_size",
            value: MAX_MANIFEST_SIZE,
            unit: "bytes",
        });
    }

    // T12: в манифесте нет якорей и алиасов, вложенность небольшая.
    let mut budget = serde_saphyr::Budget::default();
    budget.max_aliases = 0;
    budget.max_anchors = 0;
    budget.max_depth = 16;
    budget.max_events = 500_000;
    budget.max_nodes = 200_000;
    let mut options = serde_saphyr::Options::default();
    options.budget = Some(budget);
    let manifest: Manifest = serde_saphyr::from_str_with_options(&text, options)
        .map_err(|e| ProjectError::InvalidManifest(e.to_string()))?;

    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn validate_manifest(manifest: &Manifest) -> Result<(), ProjectError> {
    if manifest.format_version > FORMAT_VERSION {
        return Err(ProjectError::UnsupportedVersion {
            found: manifest.format_version,
            supported: FORMAT_VERSION,
        });
    }
    if manifest.format_version == 0 {
        return Err(ProjectError::InvalidManifest(
            "formatVersion должен быть не меньше 1".to_owned(),
        ));
    }
    if manifest.imports.len() > MAX_IMPORTS {
        return Err(ProjectError::InvalidManifest(
            "слишком много импортов".to_owned(),
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for record in &manifest.imports {
        if !is_valid_sha256(&record.sha256) {
            return Err(ProjectError::InvalidManifest(format!(
                "импорт {}: sha256 должен быть 64 строчные hex-цифры",
                record.id
            )));
        }
        if import_number(&record.id).is_none() {
            return Err(ProjectError::InvalidManifest(format!(
                "импорт {}: идентификатор должен быть вида imp-0001",
                record.id
            )));
        }
        if !seen.insert(record.id.as_str()) {
            return Err(ProjectError::InvalidManifest(format!(
                "импорт {} встречается дважды",
                record.id
            )));
        }
    }
    Ok(())
}

fn import_number(id: &str) -> Option<u64> {
    let digits = id.strip_prefix("imp-")?;
    if digits.is_empty() || digits.len() > 9 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

impl Project {
    /// Создаёт проект в новой или пустой папке; родительская папка должна существовать.
    pub fn create(path: &Path) -> Result<Self, ProjectError> {
        validate_path(path)?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .map(|n| n.strip_suffix(PROJECT_SUFFIX).unwrap_or(&n).to_owned())
            .map(|n| sanitize_name(&n))
            .filter(|n| !n.is_empty())
            .ok_or(ProjectError::InvalidPath("у папки нет имени"))?;

        match fs::symlink_metadata(path) {
            Ok(meta) if meta.is_dir() => {
                let mut entries = fs::read_dir(path).map_err(ProjectError::io("чтение папки"))?;
                if entries.next().is_some() {
                    return Err(ProjectError::AlreadyExists);
                }
            }
            Ok(_) => return Err(ProjectError::AlreadyExists),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(path).map_err(|e| match e.kind() {
                    std::io::ErrorKind::NotFound => {
                        ProjectError::InvalidPath("родительская папка не существует")
                    }
                    _ => ProjectError::Io {
                        op: "создание папки проекта",
                        source: e,
                    },
                })?;
            }
            Err(e) => {
                return Err(ProjectError::Io {
                    op: "создание папки проекта",
                    source: e,
                });
            }
        }

        restrict_dir(path)?;
        for dir in [SOURCES_DIR, CACHE_DIR] {
            let dir = path.join(dir);
            fs::create_dir(&dir).map_err(ProjectError::io("создание папки проекта"))?;
            restrict_dir(&dir)?;
        }
        let manifest = Manifest {
            format_version: FORMAT_VERSION,
            engine_version: env!("CARGO_PKG_VERSION").to_owned(),
            name,
            settings: Settings::default(),
            imports: Vec::new(),
        };
        save_manifest(path, &manifest)?;
        Ok(Self {
            root: path.to_path_buf(),
            manifest,
        })
    }

    pub fn open(path: &Path) -> Result<Self, ProjectError> {
        validate_path(path)?;
        match fs::metadata(path) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => return Err(ProjectError::NotAProject),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ProjectError::Missing);
            }
            Err(e) => {
                return Err(ProjectError::Io {
                    op: "открытие проекта",
                    source: e,
                });
            }
        }
        let manifest = load_manifest(path)?;
        Ok(Self {
            root: path.to_path_buf(),
            manifest,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn name(&self) -> &str {
        &self.manifest.name
    }

    /// Папка для пересобираемых индексов; её содержимое можно удалять.
    pub fn cache_dir(&self) -> PathBuf {
        self.root.join(CACHE_DIR)
    }

    pub fn imports(&self) -> &[ImportRecord] {
        &self.manifest.imports
    }

    /// Записи в порядке первого импорта.
    pub fn sources(&self) -> Vec<Source> {
        let mut order: Vec<Source> = Vec::new();
        for record in &self.manifest.imports {
            match order.iter_mut().find(|s| s.sha256 == record.sha256) {
                Some(source) => {
                    source.name.clone_from(&record.name);
                    source.import_id.clone_from(&record.id);
                    source.import_count += 1;
                }
                None => order.push(Source {
                    sha256: record.sha256.clone(),
                    name: record.name.clone(),
                    format: record.format,
                    size_bytes: record.size_bytes,
                    import_id: record.id.clone(),
                    import_count: 1,
                }),
            }
        }
        order
    }

    fn find_import(&self, sha256: &str) -> Result<&ImportRecord, ProjectError> {
        self.manifest
            .imports
            .iter()
            .find(|r| r.sha256 == sha256)
            .ok_or_else(|| ProjectError::UnknownSource(sha256.chars().take(64).collect()))
    }

    /// Путь к неизменной копии записи. Имя строится из sha256 и формата, а не из манифеста.
    pub fn source_path(&self, sha256: &str) -> Result<PathBuf, ProjectError> {
        if !is_valid_sha256(sha256) {
            return Err(ProjectError::UnknownSource(
                sha256.chars().take(64).collect(),
            ));
        }
        let record = self.find_import(sha256)?;
        Ok(self
            .root
            .join(SOURCES_DIR)
            .join(format!("{sha256}.{}", record.format.extension())))
    }

    /// Копирует запись в `sources/<sha256>.<ext>` и регистрирует импорт.
    pub fn add_source(
        &mut self,
        path: &Path,
        cancelled: &dyn Fn() -> bool,
        progress: &mut dyn FnMut(u64),
    ) -> Result<ImportRecord, ProjectError> {
        self.add_source_limited(path, MAX_SOURCE_SIZE, cancelled, progress)
    }

    fn add_source_limited(
        &mut self,
        path: &Path,
        max_size: u64,
        cancelled: &dyn Fn() -> bool,
        progress: &mut dyn FnMut(u64),
    ) -> Result<ImportRecord, ProjectError> {
        // Путь к записи выбирает пользователь, «..» допустим; защита — токен API и проверка «обычный файл».
        if path.as_os_str().is_empty() {
            return Err(ProjectError::InvalidPath("путь пустой"));
        }
        let meta = match fs::metadata(path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ProjectError::Missing);
            }
            Err(e) => {
                return Err(ProjectError::Io {
                    op: "чтение записи",
                    source: e,
                });
            }
        };
        if !meta.is_file() {
            return Err(ProjectError::NotRegularFile);
        }
        let too_large = ProjectError::LimitExceeded {
            name: "max_source_size",
            value: max_size,
            unit: "bytes",
        };
        if meta.len() > max_size {
            return Err(too_large);
        }

        let mut input = File::open(path).map_err(ProjectError::io("чтение записи"))?;
        let mut magic = [0u8; 4];
        let format = match input.read_exact(&mut magic) {
            Ok(()) => detect_format(&magic).ok_or(ProjectError::NotCapture)?,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(ProjectError::NotCapture);
            }
            Err(e) => {
                return Err(ProjectError::Io {
                    op: "чтение записи",
                    source: e,
                });
            }
        };

        let sources_dir = self.root.join(SOURCES_DIR);
        let mut tmp = TempFile::new(&sources_dir, "import");
        let mut output = create_private_file(&tmp.path, 0o600)
            .map_err(ProjectError::io("копирование записи"))?;
        let mut hasher = Sha256::new();
        let mut total = 0u64;
        let mut buffer = vec![0u8; COPY_BUFFER];
        let mut chunk = magic.to_vec();
        loop {
            hasher.update(&chunk);
            output
                .write_all(&chunk)
                .map_err(ProjectError::io("копирование записи"))?;
            total += chunk.len() as u64;
            // Файл мог вырасти после проверки размера.
            if total > max_size {
                return Err(too_large);
            }
            progress(total);
            if cancelled() {
                return Err(ProjectError::Cancelled);
            }
            let read = input
                .read(&mut buffer)
                .map_err(ProjectError::io("чтение записи"))?;
            if read == 0 {
                break;
            }
            chunk.clear();
            chunk.extend_from_slice(buffer.get(..read).unwrap_or_default());
        }
        output
            .sync_all()
            .map_err(ProjectError::io("копирование записи"))?;
        drop(output);

        let sha256 = hex(&hasher.finalize());
        let final_path = sources_dir.join(format!("{sha256}.{}", format.extension()));
        if fs::symlink_metadata(&final_path).is_err() {
            fs::rename(&tmp.path, &final_path).map_err(ProjectError::io("сохранение записи"))?;
            tmp.keep = true;
            make_readonly(&final_path)?;
        }
        // Иначе такая копия уже есть: временный файл удалится сам.

        let next = self
            .manifest
            .imports
            .iter()
            .filter_map(|r| import_number(&r.id))
            .max()
            .unwrap_or(0)
            + 1;
        let record = ImportRecord {
            id: format!("imp-{next:04}"),
            sha256,
            name: path
                .file_name()
                .map(|n| sanitize_name(&n.to_string_lossy()))
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| "запись".to_owned()),
            format,
            size_bytes: total,
        };
        let mut updated = self.manifest.clone();
        updated.imports.push(record.clone());
        save_manifest(&self.root, &updated)?;
        self.manifest = updated;
        Ok(record)
    }

    /// Сверяет копию записи с её sha256 (T11): подмена или удаление не должны быть незаметны.
    pub fn check_source(
        &self,
        sha256: &str,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<SourceStatus, ProjectError> {
        let path = self.source_path(sha256)?;
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(SourceStatus::Missing),
            Err(e) => {
                return Err(ProjectError::Io {
                    op: "проверка записи",
                    source: e,
                });
            }
        };
        let expected = self.find_import(sha256)?.size_bytes;
        if !meta.is_file() || meta.len() != expected {
            return Ok(SourceStatus::Damaged);
        }
        let mut file = File::open(&path).map_err(ProjectError::io("проверка записи"))?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; COPY_BUFFER];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(ProjectError::io("проверка записи"))?;
            if read == 0 {
                break;
            }
            hasher.update(buffer.get(..read).unwrap_or_default());
            if cancelled() {
                return Err(ProjectError::Cancelled);
            }
        }
        Ok(if hex(&hasher.finalize()) == sha256 {
            SourceStatus::Ready
        } else {
            SourceStatus::Damaged
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("pl-project-test-{}-{n}", std::process::id()));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }

        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.path(name);
            fs::write(&path, bytes).unwrap();
            path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn pcap_bytes(extra: u8) -> Vec<u8> {
        let mut bytes = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
        bytes.extend_from_slice(&[0; 16]);
        bytes.push(extra);
        bytes
    }

    fn never() -> bool {
        false
    }

    fn add(project: &mut Project, path: &Path) -> Result<ImportRecord, ProjectError> {
        project.add_source(path, &never, &mut |_| {})
    }

    fn new_project(dir: &TestDir) -> Project {
        Project::create(&dir.path("demo.protoledger")).unwrap()
    }

    #[test]
    fn create_then_open_roundtrip() {
        let dir = TestDir::new();
        let created = new_project(&dir);
        assert_eq!(created.name(), "demo");
        assert!(dir.path("demo.protoledger/sources").is_dir());
        let opened = Project::open(&dir.path("demo.protoledger")).unwrap();
        assert_eq!(opened.manifest(), created.manifest());
    }

    #[test]
    fn create_requires_new_or_empty_folder() {
        let dir = TestDir::new();
        fs::create_dir(dir.path("empty")).unwrap();
        assert!(Project::create(&dir.path("empty")).is_ok());

        fs::create_dir(dir.path("busy")).unwrap();
        dir.write("busy/file.txt", b"x");
        assert!(matches!(
            Project::create(&dir.path("busy")),
            Err(ProjectError::AlreadyExists)
        ));
        assert!(matches!(
            Project::create(&dir.path("no-parent/demo")),
            Err(ProjectError::InvalidPath(_))
        ));
    }

    #[test]
    fn parent_dir_in_path_is_rejected() {
        let dir = TestDir::new();
        let path = dir.path("a").join("..").join("b");
        assert!(matches!(
            Project::create(&path),
            Err(ProjectError::InvalidPath(_))
        ));
        assert!(matches!(
            Project::open(&path),
            Err(ProjectError::InvalidPath(_))
        ));
    }

    #[test]
    fn open_rejects_non_projects() {
        let dir = TestDir::new();
        assert!(matches!(
            Project::open(&dir.path("nope")),
            Err(ProjectError::Missing)
        ));
        assert!(matches!(
            Project::open(&dir.0),
            Err(ProjectError::NotAProject)
        ));
        let file = dir.write("file.txt", b"x");
        assert!(matches!(
            Project::open(&file),
            Err(ProjectError::NotAProject)
        ));
    }

    #[test]
    fn add_source_copies_and_registers() {
        let dir = TestDir::new();
        let mut project = new_project(&dir);
        let bytes = pcap_bytes(1);
        let src = dir.write("session.pcap", &bytes);

        let mut seen = 0;
        let record = project.add_source(&src, &never, &mut |n| seen = n).unwrap();
        assert_eq!(record.id, "imp-0001");
        assert_eq!(record.format, SourceFormat::Pcap);
        assert_eq!(record.size_bytes, bytes.len() as u64);
        assert_eq!(seen, bytes.len() as u64);
        assert!(is_valid_sha256(&record.sha256));

        let copy = project.source_path(&record.sha256).unwrap();
        assert_eq!(fs::read(&copy).unwrap(), bytes);
        assert!(fs::metadata(&copy).unwrap().permissions().readonly());
        assert_eq!(
            project.check_source(&record.sha256, &never).unwrap(),
            SourceStatus::Ready
        );

        let reopened = Project::open(project.root()).unwrap();
        assert_eq!(reopened.imports(), project.imports());
    }

    #[test]
    fn reimport_is_a_new_import_without_new_copy() {
        let dir = TestDir::new();
        let mut project = new_project(&dir);
        let src = dir.write("session.pcap", &pcap_bytes(1));
        let first = add(&mut project, &src).unwrap();
        let second = add(&mut project, &src).unwrap();

        assert_eq!(second.id, "imp-0002");
        assert_eq!(first.sha256, second.sha256);
        let sources = project.sources();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].import_count, 2);
        assert_eq!(sources[0].import_id, "imp-0002");
        let copies = fs::read_dir(dir.path("demo.protoledger/sources"))
            .unwrap()
            .count();
        assert_eq!(copies, 1);
    }

    #[test]
    fn rejects_non_capture_and_leaves_no_temp_files() {
        let dir = TestDir::new();
        let mut project = new_project(&dir);
        let text = dir.write("notes.txt", b"hello world");
        assert!(matches!(
            add(&mut project, &text),
            Err(ProjectError::NotCapture)
        ));
        let empty = dir.write("empty.pcap", b"");
        assert!(matches!(
            add(&mut project, &empty),
            Err(ProjectError::NotCapture)
        ));
        assert!(matches!(
            add(&mut project, &dir.0),
            Err(ProjectError::NotRegularFile)
        ));
        assert!(matches!(
            add(&mut project, &dir.path("missing.pcap")),
            Err(ProjectError::Missing)
        ));
        assert_eq!(
            fs::read_dir(dir.path("demo.protoledger/sources"))
                .unwrap()
                .count(),
            0
        );
        assert!(project.imports().is_empty());
    }

    #[test]
    fn size_limit_is_enforced_without_leftovers() {
        let dir = TestDir::new();
        let mut project = new_project(&dir);
        let src = dir.write("big.pcap", &pcap_bytes(1));
        let err = project
            .add_source_limited(&src, 10, &never, &mut |_| {})
            .unwrap_err();
        assert!(matches!(
            err,
            ProjectError::LimitExceeded {
                name: "max_source_size",
                ..
            }
        ));
        assert_eq!(
            fs::read_dir(dir.path("demo.protoledger/sources"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn cancellation_stops_copy_and_cleans_up() {
        let dir = TestDir::new();
        let mut project = new_project(&dir);
        let src = dir.write("session.pcap", &pcap_bytes(1));
        let err = project.add_source(&src, &|| true, &mut |_| {}).unwrap_err();
        assert!(matches!(err, ProjectError::Cancelled));
        assert_eq!(
            fs::read_dir(dir.path("demo.protoledger/sources"))
                .unwrap()
                .count(),
            0
        );
        assert!(project.imports().is_empty());
    }

    #[test]
    fn tampered_or_removed_copy_is_detected() {
        let dir = TestDir::new();
        let mut project = new_project(&dir);
        let src = dir.write("session.pcap", &pcap_bytes(1));
        let sha = add(&mut project, &src).unwrap().sha256;
        let copy = project.source_path(&sha).unwrap();

        let mut perms = fs::metadata(&copy).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        fs::set_permissions(&copy, perms).unwrap();
        let mut tampered = pcap_bytes(1);
        if let Some(last) = tampered.last_mut() {
            *last = 99;
        }
        fs::write(&copy, tampered).unwrap();
        assert_eq!(
            project.check_source(&sha, &never).unwrap(),
            SourceStatus::Damaged
        );

        fs::remove_file(&copy).unwrap();
        assert_eq!(
            project.check_source(&sha, &never).unwrap(),
            SourceStatus::Missing
        );
    }

    #[test]
    fn unknown_or_malformed_sha_is_not_found() {
        let dir = TestDir::new();
        let project = new_project(&dir);
        for sha in ["", "../../etc/passwd", &"a".repeat(64), &"A".repeat(64)] {
            assert!(matches!(
                project.source_path(sha),
                Err(ProjectError::UnknownSource(_))
            ));
        }
    }

    fn write_manifest(dir: &TestDir, text: &str) -> PathBuf {
        let root = dir.path("p.protoledger");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(MANIFEST_FILE), text).unwrap();
        root
    }

    #[test]
    fn newer_format_is_refused() {
        let dir = TestDir::new();
        let root = write_manifest(&dir, "formatVersion: 99\nengineVersion: 9.0.0\nname: x\n");
        assert!(matches!(
            Project::open(&root),
            Err(ProjectError::UnsupportedVersion { found: 99, .. })
        ));
    }

    #[test]
    fn broken_manifest_is_invalid() {
        let dir = TestDir::new();
        for text in [
            "not: [valid",
            "formatVersion: 1\nname: x\n",
            "formatVersion: 1\nengineVersion: 1\nname: x\nimports:\n  - {id: imp-0001, sha256: ../../x, name: a, format: pcap, sizeBytes: 1}\n",
            "formatVersion: 1\nengineVersion: 1\nname: x\nimports:\n  - {id: bad, sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, name: a, format: pcap, sizeBytes: 1}\n",
        ] {
            let root = write_manifest(&dir, text);
            assert!(
                matches!(Project::open(&root), Err(ProjectError::InvalidManifest(_))),
                "{text}"
            );
        }
    }

    #[test]
    fn yaml_bomb_and_huge_manifest_are_limited() {
        let dir = TestDir::new();
        let bomb = "a: &a [x, x, x, x]\nb: &b [*a, *a, *a, *a]\nc: &c [*b, *b, *b, *b]\nd: [*c, *c, *c, *c]\n";
        let root = write_manifest(&dir, bomb);
        assert!(matches!(
            Project::open(&root),
            Err(ProjectError::InvalidManifest(_))
        ));

        let huge = "x".repeat(MAX_MANIFEST_SIZE as usize + 1);
        let root = write_manifest(&dir, &huge);
        assert!(matches!(
            Project::open(&root),
            Err(ProjectError::LimitExceeded {
                name: "max_manifest_size",
                ..
            })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_manifest_is_not_followed() {
        let dir = TestDir::new();
        let real = dir.write(
            "real.yaml",
            b"formatVersion: 1\nengineVersion: 1\nname: x\n",
        );
        let root = dir.path("p.protoledger");
        fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(real, root.join(MANIFEST_FILE)).unwrap();
        assert!(matches!(
            Project::open(&root),
            Err(ProjectError::NotAProject)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn project_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new();
        let project = new_project(&dir);
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(project.root()), 0o700);
        assert_eq!(mode(&project.root().join(MANIFEST_FILE)), 0o600);
    }
}
