use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::contract::{normalize_locale, LocaleContract, LocaleMode};
use crate::locale::{LocaleInitError, LocaleInitializer};

const PINNED_WORKER_SHA256: &str =
    "758005ee4b9ea13993b7dc739f195eecfcd935e94e7d66fe015e86480b0d63ec";

pub struct NativeLocaleInitializer {
    worker_path: Option<PathBuf>,
    operation_root: PathBuf,
    timeout: Duration,
}

impl NativeLocaleInitializer {
    pub fn new(worker_path: Option<PathBuf>, operation_root: PathBuf) -> Self {
        Self {
            worker_path,
            operation_root,
            timeout: Duration::from_secs(4 * 60),
        }
    }

    #[cfg(test)]
    fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl LocaleInitializer for NativeLocaleInitializer {
    fn initialize(
        &mut self,
        contract: &LocaleContract,
        relay_bundle: Option<&[u8]>,
    ) -> Result<(), LocaleInitError> {
        let _ = (&self.worker_path, &self.operation_root, self.timeout);
        match contract.mode {
            LocaleMode::NativeSystem => Ok(()),
            LocaleMode::ShortLivedRelay => {
                #[cfg(target_os = "windows")]
                {
                    self.initialize_windows_relay(contract, relay_bundle)
                }
                #[cfg(not(target_os = "windows"))]
                {
                    let _ = relay_bundle;
                    Err(locale_error("locale-relay-platform-unsupported", false))
                }
            }
        }
    }
}

#[cfg(target_os = "windows")]
impl NativeLocaleInitializer {
    fn initialize_windows_relay(
        &mut self,
        contract: &LocaleContract,
        relay_bundle: Option<&[u8]>,
    ) -> Result<(), LocaleInitError> {
        use std::fs::{self, File, OpenOptions};
        use std::io::Write as _;
        use std::os::windows::process::CommandExt as _;
        use std::process::{Command, Stdio};
        use std::thread;
        use std::time::Instant;

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let worker = self
            .worker_path
            .as_ref()
            .ok_or_else(|| locale_error("locale-worker-missing", false))?;
        let worker_bytes =
            fs::read(worker).map_err(|_| locale_error("locale-worker-missing", false))?;
        if worker_bytes.len() > 64 * 1024
            || crate::contract::sha256_hex(&worker_bytes) != PINNED_WORKER_SHA256
        {
            return Err(locale_error("locale-worker-integrity", false));
        }
        let material = extract_relay_material(contract, relay_bundle)?;
        fs::create_dir_all(&self.operation_root)
            .map_err(|_| locale_error("locale-artifact-directory", false))?;
        crate::config::owner_only_permissions(&self.operation_root, true)
            .map_err(|_| locale_error("locale-artifact-permissions", false))?;
        let material_path = self.operation_root.join(format!(
            "relay-material-{}.json",
            uuid::Uuid::new_v4().simple()
        ));
        let material_bytes = Zeroizing::new(
            serde_json::to_vec(&material)
                .map_err(|_| locale_error("locale-material-encode", false))?,
        );
        let mut material_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&material_path)
            .map_err(|_| locale_error("locale-material-create", false))?;
        let material_guard = SensitiveMaterialFile(material_path.clone());
        material_file
            .write_all(&material_bytes)
            .and_then(|()| material_file.flush())
            .and_then(|()| material_file.sync_all())
            .map_err(|_| locale_error("locale-material-write", false))?;
        crate::config::owner_only_permissions(&material_path, false)
            .map_err(|_| locale_error("locale-material-permissions", false))?;

        let stdout_path = self.operation_root.join("locale-worker.stdout.log");
        let stderr_path = self.operation_root.join("locale-worker.stderr.log");
        let stdout = File::create(&stdout_path)
            .map_err(|_| locale_error("locale-worker-log-create", false))?;
        let stderr = File::create(&stderr_path)
            .map_err(|_| locale_error("locale-worker-log-create", false))?;
        crate::config::owner_only_permissions(&stdout_path, false)
            .and_then(|()| crate::config::owner_only_permissions(&stderr_path, false))
            .map_err(|_| locale_error("locale-worker-log-permissions", false))?;

        let system_root = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .ok_or_else(|| locale_error("powershell-unavailable", false))?;
        let powershell = system_root
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        if !powershell.is_file() {
            return Err(locale_error("powershell-unavailable", false));
        }
        let mut child = Command::new(powershell)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(worker)
            .arg("-RelayMaterialPath")
            .arg(&material_path)
            .arg("-TargetLocale")
            .arg(&contract.target_locale)
            .arg("-EmbeddedMode")
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|_| locale_error("locale-worker-start", true))?;
        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => break,
                Ok(Some(_)) => return Err(locale_error("locale-worker-failed", true)),
                Ok(None) if started.elapsed() < self.timeout => {
                    thread::sleep(Duration::from_millis(250));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(locale_error("locale-worker-timeout", true));
                }
                Err(_) => return Err(locale_error("locale-worker-wait", true)),
            }
        }
        drop(material_guard);
        if material_path.exists() {
            return Err(locale_error("locale-material-not-deleted", false));
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayWrapper {
    schema_version: u32,
    target_locale: String,
    issued_at_unix: i64,
    expires_at_unix: i64,
    payload: RelayMaterial,
}

#[cfg(target_os = "windows")]
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct RelayMaterial {
    schema_version: u32,
    relay_host: String,
    relay_port: u16,
    relay_user: String,
    expires_at: String,
    private_key_base64: String,
    known_hosts_line: String,
}

#[cfg(target_os = "windows")]
fn extract_relay_material(
    contract: &LocaleContract,
    relay_bundle: Option<&[u8]>,
) -> Result<RelayMaterial, LocaleInitError> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    let wrapper: RelayWrapper = serde_json::from_slice(
        relay_bundle.ok_or_else(|| locale_error("locale-relay-missing", false))?,
    )
    .map_err(|_| locale_error("locale-relay-contract", false))?;
    if wrapper.schema_version != 1
        || normalize_locale(&wrapper.target_locale) != normalize_locale(&contract.target_locale)
        || wrapper.issued_at_unix != contract.issued_at_unix
        || wrapper.expires_at_unix != contract.expires_at_unix
    {
        return Err(locale_error("locale-relay-contract", false));
    }
    let material = wrapper.payload;
    let host_valid = !material.relay_host.is_empty()
        && material.relay_host.len() <= 253
        && !material.relay_host.starts_with('.')
        && !material.relay_host.ends_with('.')
        && material
            .relay_host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'));
    let user_valid = !material.relay_user.is_empty()
        && material.relay_user.len() <= 32
        && material
            .relay_user
            .bytes()
            .enumerate()
            .all(|(index, byte)| {
                if index == 0 {
                    byte.is_ascii_alphabetic() || byte == b'_'
                } else {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
                }
            });
    let host_key_parts: Vec<&str> = material.known_hosts_line.split_whitespace().collect();
    let host_key_valid = !material
        .known_hosts_line
        .bytes()
        .any(|byte| matches!(byte, b'\r' | b'\n'))
        && host_key_parts.len() == 3
        && (matches!(host_key_parts[1], "ssh-ed25519" | "ssh-rsa")
            || host_key_parts[1].starts_with("ecdsa-sha2-"));
    let private_key = Zeroizing::new(
        STANDARD
            .decode(&material.private_key_base64)
            .map_err(|_| locale_error("locale-relay-private-key", false))?,
    );
    let expires = OffsetDateTime::parse(&material.expires_at, &Rfc3339)
        .map_err(|_| locale_error("locale-relay-expiry", false))?
        .unix_timestamp();
    if material.schema_version != 1
        || !host_valid
        || material.relay_port == 0
        || !user_valid
        || !host_key_valid
        || !(64..=16_384).contains(&private_key.len())
        || expires <= contract.issued_at_unix
        || expires > contract.issued_at_unix + 6 * 60 * 60
    {
        return Err(locale_error("locale-relay-material", false));
    }
    Ok(material)
}

#[cfg(target_os = "windows")]
struct SensitiveMaterialFile(PathBuf);

#[cfg(target_os = "windows")]
impl Drop for SensitiveMaterialFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn locale_error(code: &str, retryable: bool) -> LocaleInitError {
    LocaleInitError {
        code: code.to_string(),
        retryable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "windows")]
    use base64::Engine as _;

    fn contract(mode: LocaleMode) -> LocaleContract {
        LocaleContract {
            schema_version: 1,
            target_locale: "zh-CN".to_string(),
            required: true,
            mode,
            issued_at_unix: 1_786_000_000,
            expires_at_unix: 1_786_000_600,
        }
    }

    #[test]
    fn native_system_does_not_require_a_worker_or_relay() {
        let temp = tempfile::tempdir().unwrap();
        let mut initializer = NativeLocaleInitializer::new(None, temp.path().to_path_buf())
            .with_timeout(Duration::from_millis(1));
        initializer
            .initialize(&contract(LocaleMode::NativeSystem), None)
            .unwrap();
    }

    #[test]
    fn packaged_windows_worker_is_present_pinned_and_declared_as_a_resource() {
        let worker = include_bytes!("../../../src-tauri/resources/i18n-relay-worker.ps1");
        assert_eq!(crate::contract::sha256_hex(worker), PINNED_WORKER_SHA256);
        let tauri: serde_json::Value =
            serde_json::from_str(include_str!("../../../src-tauri/tauri.conf.json")).unwrap();
        assert!(tauri["bundle"]["resources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some("resources/*")));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn relay_material_is_strictly_extracted_without_persisting_wrapper_fields() {
        let wrapper = serde_json::json!({
            "schema_version": 1,
            "target_locale": "zh-CN",
            "issued_at_unix": 1_786_000_000,
            "expires_at_unix": 1_786_000_600,
            "payload": {
                "schema_version": 1,
                "relay_host": "relay.example.com",
                "relay_port": 22,
                "relay_user": "locale_relay",
                "expires_at": "2026-08-06T08:06:40Z",
                "private_key_base64": base64::engine::general_purpose::STANDARD.encode([7_u8; 64]),
                "known_hosts_line": "relay.example.com ssh-ed25519 AAAATEST"
            }
        });
        let bytes = serde_json::to_vec(&wrapper).unwrap();
        let material =
            extract_relay_material(&contract(LocaleMode::ShortLivedRelay), Some(&bytes)).unwrap();
        let serialized = serde_json::to_string(&material).unwrap();
        assert!(serialized.contains("relay_host"));
        assert!(!serialized.contains("target_locale"));

        let mut invalid = wrapper;
        invalid["payload"]["unexpected"] = serde_json::json!(true);
        assert!(extract_relay_material(
            &contract(LocaleMode::ShortLivedRelay),
            Some(&serde_json::to_vec(&invalid).unwrap()),
        )
        .is_err());
    }
}
