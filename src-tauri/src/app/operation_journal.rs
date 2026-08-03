//! Durable, cross-platform operation state.
//!
//! The in-memory lease drives concurrency, while this journal is the crash and
//! support boundary: every phase/progress/evidence transition is atomically
//! replaced on disk. A process crash therefore leaves an `active` record that
//! startup recovery and diagnostics can distinguish from a clean terminal run.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::app::atomic_file::{read_with_recovery, write_atomic, LoadOutcome};

pub const OPERATION_JOURNAL_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JournalStatus {
    Active,
    Succeeded,
    FailedBeforeCommit,
    RolledBack,
    OutcomeUnknown,
    Released,
    Abandoned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JournalProgress {
    pub downloaded: u64,
    pub total: u64,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationUiState {
    pub step_index: u16,
    pub step_total: u16,
    pub step_key: String,
    pub component: String,
    pub system_action: String,
    pub attempt_current: u32,
    pub attempt_total: u32,
    pub source_label: Option<String>,
    pub bytes_per_second: Option<u64>,
    pub eta_seconds: Option<u64>,
    pub last_activity_unix: u64,
    pub stall_after_seconds: u64,
    pub point_of_no_return: bool,
}

impl OperationUiState {
    pub fn initial(started_unix: u64) -> Self {
        Self {
            step_index: 1,
            step_total: 6,
            step_key: "preparing".to_string(),
            component: "codex-desktop".to_string(),
            system_action: "preflight".to_string(),
            attempt_current: 1,
            attempt_total: 3,
            source_label: None,
            bytes_per_second: None,
            eta_seconds: None,
            last_activity_unix: started_unix,
            stall_after_seconds: 30,
            point_of_no_return: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationDiagnosticState {
    pub report_id: String,
    pub local_bundle_path: String,
    pub upload_status: String,
    pub support_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationPartialOutcome {
    pub primary: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JournalEvidence {
    pub mutation_started: bool,
    pub mutation_rolled_back: bool,
    pub outcome_ambiguous: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationJournal {
    pub schema_version: u32,
    pub sequence: u64,
    pub operation_id: String,
    pub kind: String,
    pub status: JournalStatus,
    pub phase: String,
    pub started_unix: u64,
    pub heartbeat_unix: u64,
    pub attempt: u32,
    pub pid: u32,
    pub progress: Option<JournalProgress>,
    pub paused: bool,
    #[serde(default)]
    pub ui: Option<OperationUiState>,
    #[serde(default)]
    pub diagnostics: Option<OperationDiagnosticState>,
    #[serde(default)]
    pub partial_outcome: Option<OperationPartialOutcome>,
    pub evidence: JournalEvidence,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OperationJournalStore {
    path: PathBuf,
}

impl OperationJournalStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> (Option<OperationJournal>, LoadOutcome) {
        read_with_recovery(&self.path)
    }

    pub fn write(&self, journal: &OperationJournal) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(journal)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        write_atomic(&self.path, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

    fn test_store(name: &str) -> OperationJournalStore {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-data")
            .join(format!(
                "operation-journal-{name}-{}-{id}",
                std::process::id()
            ));
        let _ = fs::remove_dir_all(&root);
        OperationJournalStore::new(root.join("operation-journal.json"))
    }

    fn journal(sequence: u64, status: JournalStatus) -> OperationJournal {
        OperationJournal {
            schema_version: OPERATION_JOURNAL_SCHEMA_VERSION,
            sequence,
            operation_id: "op-1".to_string(),
            kind: "install".to_string(),
            status,
            phase: "downloading".to_string(),
            started_unix: 100,
            heartbeat_unix: 101,
            attempt: 2,
            pid: 42,
            progress: Some(JournalProgress {
                downloaded: 7,
                total: 11,
                source: "mirror.example".to_string(),
            }),
            paused: false,
            ui: Some(OperationUiState::initial(100)),
            diagnostics: None,
            partial_outcome: None,
            evidence: JournalEvidence::default(),
            last_error: None,
        }
    }

    #[test]
    fn atomically_replaces_state_and_preserves_last_good_backup() {
        let store = test_store("replace");
        store.write(&journal(1, JournalStatus::Active)).unwrap();
        store.write(&journal(2, JournalStatus::Succeeded)).unwrap();
        let (loaded, outcome) = store.load();
        assert_eq!(outcome, LoadOutcome::Ok);
        assert_eq!(loaded.unwrap(), journal(2, JournalStatus::Succeeded));
        assert!(store.path().with_extension("json.bak").exists());
    }

    #[test]
    fn recovers_last_good_state_after_torn_main_write() {
        let store = test_store("recover");
        store.write(&journal(1, JournalStatus::Active)).unwrap();
        store.write(&journal(2, JournalStatus::RolledBack)).unwrap();
        fs::write(store.path(), b"{").unwrap();
        let (loaded, outcome) = store.load();
        assert_eq!(outcome, LoadOutcome::RecoveredFromBak);
        assert_eq!(loaded.unwrap(), journal(1, JournalStatus::Active));
    }
}
