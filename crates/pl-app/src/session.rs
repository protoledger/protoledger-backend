use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use pl_core::{Problem, ProblemKind};
use pl_project::{Project, Settings};
use serde::{Deserialize, Serialize};

use crate::JobRegistry;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OpenMode {
    Open,
    Create,
}

/// Частичное изменение настроек сборки потоков.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettingsPatch {
    pub overlap_policy: Option<pl_project::OverlapPolicy>,
    pub checksum_policy: Option<pl_project::ChecksumPolicy>,
}

/// Описание открытого проекта для API.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectInfo {
    pub name: String,
    pub path: String,
    pub format_version: u32,
    pub engine_version: String,
    pub settings: Settings,
    pub source_count: usize,
}

impl ProjectInfo {
    fn of(project: &Project) -> Self {
        let manifest = project.manifest();
        Self {
            name: manifest.name.clone(),
            path: project.root().display().to_string(),
            format_version: manifest.format_version,
            engine_version: manifest.engine_version.clone(),
            settings: manifest.settings,
            source_count: project.sources().len(),
        }
    }
}

/// Сессия движка: каталог проектов и открытый проект (один на сессию).
#[derive(Clone)]
pub struct Session {
    workspace: PathBuf,
    project: Arc<RwLock<Option<Project>>>,
}

impl Session {
    pub fn new(workspace: PathBuf) -> Self {
        Self {
            workspace,
            project: Arc::default(),
        }
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    /// Чтение проекта; `None` — проект не открыт.
    pub fn read(&self) -> RwLockReadGuard<'_, Option<Project>> {
        // Отравление возможно только при панике в короткой секции; данные проекта целы.
        self.project.read().unwrap_or_else(|p| p.into_inner())
    }

    pub fn write(&self) -> RwLockWriteGuard<'_, Option<Project>> {
        self.project.write().unwrap_or_else(|p| p.into_inner())
    }

    pub fn no_project() -> Problem {
        Problem::new(
            ProblemKind::NoProject,
            "Сначала создайте или откройте проект (POST /api/project).",
        )
    }

    pub fn current(&self) -> Result<ProjectInfo, Problem> {
        self.read()
            .as_ref()
            .map(ProjectInfo::of)
            .ok_or_else(Self::no_project)
    }

    /// Меняет настройки сборки. Возвращает проект и признак «настройки изменились»:
    /// только тогда записи нужно собрать заново.
    pub fn update_settings(
        &self,
        jobs: &JobRegistry,
        patch: SettingsPatch,
    ) -> Result<(ProjectInfo, bool), Problem> {
        if jobs.has_active() {
            return Err(Problem::new(
                ProblemKind::Conflict,
                "Пока идут задачи, настройки менять нельзя: дождитесь завершения или отмените их.",
            ));
        }
        let mut guard = self.write();
        let project = guard.as_mut().ok_or_else(Self::no_project)?;
        let mut settings = project.manifest().settings;
        if let Some(policy) = patch.overlap_policy {
            settings.overlap_policy = policy;
        }
        if let Some(policy) = patch.checksum_policy {
            settings.checksum_policy = policy;
        }
        let changed = settings != project.manifest().settings;
        if changed {
            project.set_settings(settings).map_err(Problem::from)?;
        }
        Ok((ProjectInfo::of(project), changed))
    }

    /// Относительные пути считаются от каталога проектов (`--workspace`).
    pub fn open(
        &self,
        jobs: &JobRegistry,
        path: &str,
        mode: OpenMode,
    ) -> Result<ProjectInfo, Problem> {
        if jobs.has_active() {
            return Err(Problem::new(
                ProblemKind::Conflict,
                "Пока идут задачи, проект сменить нельзя: дождитесь завершения или отмените их.",
            ));
        }
        let path = self.workspace.join(path);
        let project = match mode {
            OpenMode::Open => Project::open(&path),
            OpenMode::Create => Project::create(&path),
        }
        .map_err(Problem::from)?;
        let info = ProjectInfo::of(&project);
        *self.write() = Some(project);
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_workspace() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pl-app-session-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn create_open_and_current() {
        let workspace = temp_workspace().join("a");
        std::fs::create_dir_all(&workspace).unwrap();
        let session = Session::new(workspace.clone());
        let jobs = JobRegistry::new();

        assert_eq!(session.current().unwrap_err().status, 409);
        let created = session
            .open(&jobs, "demo.protoledger", OpenMode::Create)
            .unwrap();
        assert_eq!(created.name, "demo");
        assert_eq!(session.current().unwrap(), created);

        let other = Session::new(workspace.clone());
        assert_eq!(
            other
                .open(&jobs, "demo.protoledger", OpenMode::Open)
                .unwrap()
                .name,
            "demo"
        );
        assert_eq!(
            other
                .open(&jobs, "nope.protoledger", OpenMode::Open)
                .unwrap_err()
                .status,
            400
        );
        assert_eq!(
            other
                .open(&jobs, "demo.protoledger", OpenMode::Create)
                .unwrap_err()
                .status,
            409
        );
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[tokio::test]
    async fn open_is_refused_while_jobs_run() {
        let workspace = temp_workspace().join("b");
        std::fs::create_dir_all(&workspace).unwrap();
        let session = Session::new(workspace.clone());
        let jobs = JobRegistry::new();
        let id = jobs
            .spawn(crate::JobKind::Import, |ctx| async move {
                ctx.cancel_token().cancelled().await;
                Ok(serde_json::Value::Null)
            })
            .unwrap();
        let err = session
            .open(&jobs, "p.protoledger", OpenMode::Create)
            .unwrap_err();
        assert_eq!(err.status, 409);
        jobs.cancel(&id).unwrap();
        let _ = std::fs::remove_dir_all(workspace);
    }
}
