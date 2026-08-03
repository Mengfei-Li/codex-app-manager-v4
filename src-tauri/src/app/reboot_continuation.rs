//! One-shot Windows reboot continuation.
//!
//! A receipt contains no customer credential. It is SHA-256 bound and signed
//! with a random local key, expires after a short window, and is consumed before
//! the resumed operation starts. A failed resumed attempt is terminal, so the
//! installer can never create a reboot loop.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::app::atomic_file::{read_with_recovery, write_atomic};

const SCHEMA_VERSION: u32 = 1;
const DEFAULT_EXPIRY: Duration = Duration::from_secs(24 * 60 * 60);
const SIGNING_DOMAIN: &[u8] = b"codex-app-manager-v4/reboot-continuation/v1";
const RUN_ONCE_VALUE: &str = "CodexAppManagerV4Resume";
static RESUME_ATTEMPT_ACTIVE: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptStatus {
    Pending,
    Attempted,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RebootPayload {
    pub schema_version: u32,
    pub receipt_id: String,
    pub created_unix: u64,
    pub expires_unix: u64,
    pub attempt: u32,
    pub max_attempts: u32,
    pub status: ReceiptStatus,
    pub reason: String,
    pub install_mode: String,
    pub package_moniker: String,
    pub latest_version: String,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignedReceipt {
    payload: RebootPayload,
    payload_sha256: String,
    signature_sha256: String,
}

#[derive(Debug, Clone)]
pub struct RebootContinuationStore {
    receipt_path: PathBuf,
    key_path: PathBuf,
}

impl RebootContinuationStore {
    pub fn in_data_dir(data_dir: &Path) -> Self {
        Self {
            receipt_path: data_dir.join("reboot-continuation.json"),
            key_path: data_dir.join("reboot-continuation.key"),
        }
    }

    fn key(&self) -> Result<Vec<u8>, String> {
        if let Ok(bytes) = std::fs::read(&self.key_path) {
            if bytes.len() == 32 {
                return Ok(bytes);
            }
            return Err("reboot continuation key has invalid length".to_string());
        }
        let mut key = Vec::with_capacity(32);
        key.extend_from_slice(Uuid::new_v4().as_bytes());
        key.extend_from_slice(Uuid::new_v4().as_bytes());
        write_atomic(&self.key_path, &key)
            .map_err(|error| format!("write reboot continuation key: {error}"))?;
        Ok(key)
    }

    fn sign(&self, payload: &RebootPayload) -> Result<SignedReceipt, String> {
        let payload_bytes = serde_json::to_vec(payload)
            .map_err(|error| format!("serialize reboot payload: {error}"))?;
        let payload_sha256 = sha256_hex(&payload_bytes);
        let key = self.key()?;
        let mut signer = Sha256::new();
        signer.update(&key);
        signer.update(SIGNING_DOMAIN);
        signer.update(&payload_bytes);
        signer.update(&key);
        let signature_sha256 = hex(signer.finalize());
        Ok(SignedReceipt {
            payload: payload.clone(),
            payload_sha256,
            signature_sha256,
        })
    }

    fn write_payload(&self, payload: &RebootPayload) -> Result<(), String> {
        let signed = self.sign(payload)?;
        let bytes = serde_json::to_vec_pretty(&signed)
            .map_err(|error| format!("serialize signed reboot receipt: {error}"))?;
        write_atomic(&self.receipt_path, &bytes)
            .map_err(|error| format!("write reboot receipt: {error}"))
    }

    fn read_verified(&self) -> Result<Option<RebootPayload>, String> {
        if !self.receipt_path.exists() {
            return Ok(None);
        }
        let (signed, _) = read_with_recovery::<SignedReceipt>(&self.receipt_path);
        let signed =
            signed.ok_or_else(|| "reboot receipt and backup are unreadable".to_string())?;
        if signed.payload.schema_version != SCHEMA_VERSION {
            return Err("reboot receipt schema is unsupported".to_string());
        }
        let expected = self.sign(&signed.payload)?;
        if signed.payload_sha256 != expected.payload_sha256
            || signed.signature_sha256 != expected.signature_sha256
        {
            return Err("reboot receipt integrity/signature verification failed".to_string());
        }
        Ok(Some(signed.payload))
    }

    pub fn create(
        &self,
        reason: String,
        install_mode: String,
        package_moniker: String,
        latest_version: String,
        now_unix: u64,
    ) -> Result<RebootPayload, String> {
        let payload = RebootPayload {
            schema_version: SCHEMA_VERSION,
            receipt_id: Uuid::new_v4().to_string(),
            created_unix: now_unix,
            expires_unix: now_unix.saturating_add(DEFAULT_EXPIRY.as_secs()),
            attempt: 0,
            max_attempts: 1,
            status: ReceiptStatus::Pending,
            reason,
            install_mode,
            package_moniker,
            latest_version,
            last_error: None,
        };
        self.write_payload(&payload)?;
        Ok(payload)
    }

    /// Verify and consume the sole attempt before any installation call runs.
    pub fn take_pending(&self, now_unix: u64) -> Result<Option<RebootPayload>, String> {
        let Some(mut payload) = self.read_verified()? else {
            return Ok(None);
        };
        if payload.status != ReceiptStatus::Pending {
            return Ok(None);
        }
        if now_unix > payload.expires_unix {
            payload.status = ReceiptStatus::Failed;
            payload.last_error = Some("reboot continuation expired before login".to_string());
            self.write_payload(&payload)?;
            return Ok(None);
        }
        if payload.attempt >= payload.max_attempts {
            payload.status = ReceiptStatus::Failed;
            payload.last_error = Some("reboot continuation attempt limit reached".to_string());
            self.write_payload(&payload)?;
            return Ok(None);
        }
        payload.attempt = payload.attempt.saturating_add(1);
        payload.status = ReceiptStatus::Attempted;
        self.write_payload(&payload)?;
        Ok(Some(payload))
    }

    pub fn finish(&self, succeeded: bool, error: Option<String>) -> Result<(), String> {
        let Some(mut payload) = self.read_verified()? else {
            return Err("reboot receipt disappeared before completion".to_string());
        };
        payload.status = if succeeded {
            ReceiptStatus::Succeeded
        } else {
            ReceiptStatus::Failed
        };
        payload.last_error = error;
        self.write_payload(&payload)
    }
}

pub struct ResumeAttemptGuard;

impl ResumeAttemptGuard {
    pub fn enter() -> Self {
        RESUME_ATTEMPT_ACTIVE.store(true, Ordering::SeqCst);
        Self
    }
}

impl Drop for ResumeAttemptGuard {
    fn drop(&mut self) {
        RESUME_ATTEMPT_ACTIVE.store(false, Ordering::SeqCst);
    }
}

pub fn resume_attempt_active() -> bool {
    RESUME_ATTEMPT_ACTIVE.load(Ordering::SeqCst)
}

pub fn default_store() -> Option<RebootContinuationStore> {
    crate::app::paths::data_dir().map(|dir| RebootContinuationStore::in_data_dir(&dir))
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub fn schedule_run_once(receipt_id: &str) -> Result<(), String> {
    #[cfg(not(windows))]
    {
        let _ = receipt_id;
        return Err("Windows RunOnce is unavailable on this platform".to_string());
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};
        use std::time::Instant;

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let executable = std::env::current_exe()
            .map_err(|error| format!("resolve manager executable: {error}"))?;
        let launch = format!(
            "\"{}\" --v4-resume-after-reboot {}",
            executable.display(),
            receipt_id
        );
        let mut child = Command::new("reg.exe")
            .args([
                "ADD",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                "/v",
                RUN_ONCE_VALUE,
                "/t",
                "REG_SZ",
                "/d",
                &launch,
                "/f",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("start reg.exe: {error}"))?;
        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(status)) => {
                    return Err(format!("reg.exe RunOnce registration failed: {status}"));
                }
                Ok(None) if started.elapsed() >= Duration::from_secs(30) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("reg.exe RunOnce registration timed out".to_string());
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("wait for reg.exe: {error}"));
                }
            }
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(Sha256::digest(bytes))
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

    fn store(name: &str) -> RebootContinuationStore {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-data")
            .join(format!("reboot-{name}-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        RebootContinuationStore::in_data_dir(&root)
    }

    #[test]
    fn pending_receipt_is_signed_and_consumed_exactly_once() {
        let store = store("once");
        let created = store
            .create(
                "AppX service busy".to_string(),
                "msix".to_string(),
                "Codex_x64.msix".to_string(),
                "26.1".to_string(),
                100,
            )
            .unwrap();
        let taken = store.take_pending(101).unwrap().unwrap();
        assert_eq!(taken.receipt_id, created.receipt_id);
        assert_eq!(taken.attempt, 1);
        assert_eq!(taken.status, ReceiptStatus::Attempted);
        assert!(store.take_pending(102).unwrap().is_none());
    }

    #[test]
    fn tampered_receipt_is_rejected() {
        let store = store("tamper");
        store
            .create(
                "AppX timeout".to_string(),
                "msix".to_string(),
                "Codex_x64.msix".to_string(),
                "26.1".to_string(),
                100,
            )
            .unwrap();
        let mut text = fs::read_to_string(&store.receipt_path).unwrap();
        text = text.replace("AppX timeout", "AppX success");
        fs::write(&store.receipt_path, text).unwrap();
        assert!(store.take_pending(101).is_err());
    }

    #[test]
    fn expired_receipt_becomes_terminal_without_attempt() {
        let store = store("expired");
        let created = store
            .create(
                "AppX timeout".to_string(),
                "msix".to_string(),
                "Codex_x64.msix".to_string(),
                "26.1".to_string(),
                100,
            )
            .unwrap();
        assert!(store
            .take_pending(created.expires_unix.saturating_add(1))
            .unwrap()
            .is_none());
        let payload = store.read_verified().unwrap().unwrap();
        assert_eq!(payload.status, ReceiptStatus::Failed);
        assert_eq!(payload.attempt, 0);
    }
}
