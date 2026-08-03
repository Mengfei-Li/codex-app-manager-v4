//! Durable AppX child-worker artifact for support and crash diagnosis.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use codex_win_engine::AppxWorkerEvent;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::app::atomic_file::write_atomic;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkerStatus {
    Prepared,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppxWorkerArtifact {
    pub schema_version: u32,
    pub worker_id: String,
    pub package_moniker: String,
    pub status: WorkerStatus,
    pub pid: Option<u32>,
    pub started_unix: u64,
    pub heartbeat_unix: u64,
    pub elapsed_ms: u64,
    pub exit_code: Option<i32>,
    pub hresult: Option<String>,
    pub stdout: String,
    pub stderr: String,
    pub last_error: Option<String>,
    pub system_events: Vec<String>,
}

#[derive(Clone)]
pub struct AppxWorkerArtifactHandle {
    path: PathBuf,
    artifact: Arc<Mutex<AppxWorkerArtifact>>,
}

impl AppxWorkerArtifactHandle {
    pub fn start(package_moniker: &str) -> Result<Self, String> {
        let root = crate::app::paths::data_dir()
            .ok_or_else(|| "manager data directory unavailable".to_string())?
            .join("appx-workers");
        Self::start_in(root, package_moniker)
    }

    fn start_in(root: PathBuf, package_moniker: &str) -> Result<Self, String> {
        std::fs::create_dir_all(&root)
            .map_err(|error| format!("create AppX worker artifact directory: {error}"))?;
        let worker_id = Uuid::new_v4().to_string();
        let now = now_unix();
        let artifact = AppxWorkerArtifact {
            schema_version: 1,
            worker_id: worker_id.clone(),
            package_moniker: package_moniker.to_string(),
            status: WorkerStatus::Prepared,
            pid: None,
            started_unix: now,
            heartbeat_unix: now,
            elapsed_ms: 0,
            exit_code: None,
            hresult: None,
            stdout: String::new(),
            stderr: String::new(),
            last_error: None,
            system_events: Vec::new(),
        };
        let handle = Self {
            path: root.join(format!("appx-worker-{worker_id}.json")),
            artifact: Arc::new(Mutex::new(artifact)),
        };
        handle.persist()?;
        Ok(handle)
    }

    pub fn observe(&self, event: AppxWorkerEvent) {
        let Ok(mut artifact) = self.artifact.lock() else {
            log::error!("AppX worker artifact mutex poisoned");
            return;
        };
        artifact.heartbeat_unix = now_unix();
        match event {
            AppxWorkerEvent::Started { pid } => {
                artifact.status = WorkerStatus::Running;
                artifact.pid = Some(pid);
                artifact
                    .system_events
                    .push(format!("worker process started pid={pid}"));
            }
            AppxWorkerEvent::Heartbeat { elapsed_ms } => {
                artifact.elapsed_ms = elapsed_ms;
            }
            AppxWorkerEvent::Completed {
                exit_code,
                stdout,
                stderr,
            } => {
                artifact.status = if exit_code == Some(0) {
                    WorkerStatus::Completed
                } else {
                    WorkerStatus::Failed
                };
                artifact.exit_code = exit_code;
                artifact.hresult = extract_hresult(&format!("{stdout}\n{stderr}"));
                artifact.stdout = stdout;
                artifact.stderr = stderr;
                artifact.system_events.push(format!(
                    "worker process completed exit_code={}",
                    exit_code
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "signal".to_string())
                ));
            }
            AppxWorkerEvent::Failed { error } => {
                artifact.status = WorkerStatus::Failed;
                artifact.hresult = extract_hresult(&error);
                artifact.last_error = Some(error.clone());
                artifact
                    .system_events
                    .push(format!("worker runner failed: {error}"));
            }
        }
        drop(artifact);
        if let Err(error) = self.persist() {
            log::error!(
                "failed to persist AppX worker artifact path={} error={error}",
                self.path.display()
            );
        }
    }

    fn persist(&self) -> Result<(), String> {
        let artifact = self
            .artifact
            .lock()
            .map_err(|_| "AppX worker artifact mutex poisoned".to_string())?
            .clone();
        let bytes = serde_json::to_vec_pretty(&artifact)
            .map_err(|error| format!("serialize AppX worker artifact: {error}"))?;
        write_atomic(&self.path, &bytes)
            .map_err(|error| format!("write AppX worker artifact: {error}"))
    }

    #[cfg(test)]
    fn read_for_test(&self) -> AppxWorkerArtifact {
        serde_json::from_slice(&std::fs::read(&self.path).unwrap()).unwrap()
    }
}

fn extract_hresult(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    for index in 0..bytes.len().saturating_sub(9) {
        if bytes[index] == b'0'
            && matches!(bytes[index + 1], b'x' | b'X')
            && bytes[index + 2..index + 10]
                .iter()
                .all(u8::is_ascii_hexdigit)
        {
            return Some(text[index..index + 10].to_ascii_uppercase());
        }
    }
    None
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_pid_heartbeat_complete_output_and_hresult() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-data")
            .join(format!("appx-worker-test-{}", Uuid::new_v4()));
        let handle = AppxWorkerArtifactHandle::start_in(root.clone(), "Codex_x64.msix").unwrap();
        handle.observe(AppxWorkerEvent::Started { pid: 77 });
        handle.observe(AppxWorkerEvent::Heartbeat { elapsed_ms: 1500 });
        handle.observe(AppxWorkerEvent::Completed {
            exit_code: Some(1),
            stdout: "json output".to_string(),
            stderr: "deployment failed HRESULT=0x80073D02".to_string(),
        });
        let artifact = handle.read_for_test();
        assert_eq!(artifact.pid, Some(77));
        assert_eq!(artifact.elapsed_ms, 1500);
        assert_eq!(artifact.status, WorkerStatus::Failed);
        assert_eq!(artifact.hresult.as_deref(), Some("0X80073D02"));
        assert_eq!(artifact.stdout, "json output");
        assert!(artifact.stderr.contains("HRESULT"));
        let _ = std::fs::remove_dir_all(root);
    }
}
