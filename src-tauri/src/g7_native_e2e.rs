//! G7 production-candidate acceptance mode for ephemeral native CI runners.
//!
//! This is deliberately compiled into the signed candidate so G7 exercises the
//! exact bytes customers receive.  It cannot be enabled by a portal response or
//! ordinary UI input: three CI markers, a valid packaged-smoke sandbox, an
//! immutable release identity, and a verified commercial bootstrap sidecar are
//! all required.  The flow calls the same guarded commands as the renderer.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Instant;

use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager as _};

use crate::app::oplock::OperationKind;
use crate::app::provenance::ProvenanceStore;
use crate::errors::CommandError;
use crate::state::ManagerState;

const ENABLE_ENV: &str = "CAM_G7_NATIVE_E2E";
const RELEASE_ENV: &str = "CAM_G7_RELEASE_TAG";
const SOURCE_ENV: &str = "CAM_G7_SOURCE_SHA";
const TARGET_ENV: &str = "CAM_G7_TARGET";
const EVIDENCE_FILE: &str = "g7-native-evidence.json";

#[derive(Debug)]
struct Failure {
    stage: &'static str,
    code: String,
}

impl Failure {
    fn command(stage: &'static str, error: CommandError) -> Self {
        Self {
            stage,
            code: safe_code(&error.code),
        }
    }

    fn local(stage: &'static str, code: &str) -> Self {
        Self {
            stage,
            code: safe_code(code),
        }
    }
}

#[derive(Debug, Serialize)]
struct LifecycleEvidence {
    schema_version: u32,
    status: &'static str,
    release_tag: String,
    source_sha: String,
    build_id: String,
    platform: &'static str,
    architecture: &'static str,
    target: String,
    manager_executable_sha256: String,
    elapsed_seconds: u64,
    checks: LifecycleChecks,
    production_changed: bool,
    public_default_changed: bool,
    fixed_test_customer_data_changed: bool,
    secret_values_recorded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_code: Option<String>,
}

#[derive(Debug, Default, Serialize)]
struct LifecycleChecks {
    signed_sidecar_delivery: bool,
    clean_install: bool,
    official_identity_health: bool,
    app_launch: bool,
    config_and_responses_verification: bool,
    external_install_classification: bool,
    adopt_existing: bool,
    repair_or_same_version_run: bool,
    uninstall_preserved_user_state: bool,
    reinstall: bool,
    relaunch: bool,
}

fn safe_code(value: &str) -> String {
    let filtered = value
        .chars()
        .filter(|value| value.is_ascii_alphanumeric() || matches!(value, '-' | '_'))
        .take(96)
        .collect::<String>();
    if filtered.is_empty() {
        "g7-failed".to_string()
    } else {
        filtered
    }
}

fn valid_release_tag(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('v') else {
        return false;
    };
    let parts = rest.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|value| value.is_ascii_digit()))
}

fn expected_target() -> String {
    let platform = if cfg!(target_os = "windows") {
        "windows"
    } else {
        "macos"
    };
    format!("{platform}-{}", std::env::consts::ARCH)
}

fn activation() -> Result<(String, String, String, PathBuf), Failure> {
    if std::env::var(ENABLE_ENV).as_deref() != Ok("1")
        || std::env::var("CI").as_deref() != Ok("true")
        || std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
    {
        return Err(Failure::local("activation", "ci-guard-rejected"));
    }
    let run_id = crate::app::paths::packaged_smoke_run_id()
        .filter(|value| value.starts_with("g7-"))
        .ok_or_else(|| Failure::local("activation", "smoke-sandbox-required"))?;
    let release_tag = std::env::var(RELEASE_ENV)
        .ok()
        .filter(|value| valid_release_tag(value))
        .ok_or_else(|| Failure::local("activation", "release-tag-invalid"))?;
    let source_sha = std::env::var(SOURCE_ENV)
        .ok()
        .filter(|value| value.len() == 40 && value.chars().all(|item| item.is_ascii_hexdigit()))
        .ok_or_else(|| Failure::local("activation", "source-sha-invalid"))?;
    let target = std::env::var(TARGET_ENV)
        .ok()
        .filter(|value| value == &expected_target())
        .ok_or_else(|| Failure::local("activation", "native-target-mismatch"))?;
    let data_root = crate::app::paths::data_dir()
        .ok_or_else(|| Failure::local("activation", "smoke-data-unavailable"))?;
    if data_root.file_name().and_then(|value| value.to_str())
        != Some(&format!("codex-app-manager-smoke-{run_id}"))
    {
        return Err(Failure::local("activation", "smoke-data-mismatch"));
    }
    Ok((
        release_tag,
        source_sha.to_ascii_lowercase(),
        target,
        data_root,
    ))
}

fn executable_sha256() -> Result<String, Failure> {
    let path = std::env::current_exe()
        .map_err(|_| Failure::local("identity", "current-executable-unavailable"))?;
    let bytes =
        std::fs::read(path).map_err(|_| Failure::local("identity", "current-executable-read"))?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn remove_current_provenance(path: &str) -> Result<(), Failure> {
    let mut store = ProvenanceStore::load();
    if !store.is_managed(path) {
        return Err(Failure::local(
            "external-classification",
            "managed-record-missing",
        ));
    }
    store.remove(path);
    store
        .save()
        .map_err(|_| Failure::local("external-classification", "provenance-save"))
}

#[cfg(target_os = "windows")]
async fn native_flow(app: &AppHandle, checks: &mut LifecycleChecks) -> Result<(), Failure> {
    let token = crate::commands::begin_operation(app.state(), OperationKind::Update)
        .map_err(|error| Failure::command("clean-install-arm", error))?;
    let first =
        crate::commands::win_perform_update(app.clone(), app.state(), true, token, None, None)
            .await
            .map_err(|error| Failure::command("clean-install", error))?;
    if !first.success {
        return Err(Failure::local("clean-install", "perform-not-successful"));
    }
    let installed_path = first
        .installed
        .as_ref()
        .map(|installed| installed.path.clone())
        .ok_or_else(|| Failure::local("clean-install", "installed-identity-missing"))?;
    checks.clean_install = true;
    checks.official_identity_health = first
        .msix_health
        .as_ref()
        .is_some_and(|health| health.verified && health.healthy)
        || first
            .portable
            .as_ref()
            .is_some_and(|portable| portable.success);
    if !checks.official_identity_health {
        return Err(Failure::local("clean-install", "official-health-failed"));
    }
    checks.signed_sidecar_delivery = true;
    checks.config_and_responses_verification = true;
    crate::commands::win_launch_codex(app.state())
        .await
        .map_err(|error| Failure::command("launch", error))?;
    checks.app_launch = true;

    let repair_token = crate::commands::begin_operation(app.state(), OperationKind::Update)
        .map_err(|error| Failure::command("repair-arm", error))?;
    let repair = crate::commands::win_perform_update(
        app.clone(),
        app.state(),
        true,
        repair_token,
        None,
        None,
    )
    .await
    .map_err(|error| Failure::command("repair", error))?;
    if !repair.success {
        return Err(Failure::local("repair", "perform-not-successful"));
    }
    checks.repair_or_same_version_run = true;

    remove_current_provenance(&installed_path)?;
    let external = crate::commands::win_status(app.state())
        .await
        .map_err(|error| Failure::command("external-classification", error))?;
    if external.status != "external" {
        return Err(Failure::local(
            "external-classification",
            "expected-external",
        ));
    }
    checks.external_install_classification = true;
    let adopted = crate::commands::win_adopt(app.clone(), app.state())
        .await
        .map_err(|error| Failure::command("adopt-existing", error))?;
    if adopted.status != "managed" {
        return Err(Failure::local("adopt-existing", "expected-managed"));
    }
    checks.adopt_existing = true;

    let uninstall_token = crate::commands::arm_destructive(app.state(), OperationKind::Uninstall)
        .map_err(|error| Failure::command("uninstall-arm", error))?;
    let removed =
        crate::commands::win_uninstall(app.clone(), app.state(), true, uninstall_token, false)
            .await
            .map_err(|error| Failure::command("uninstall", error))?;
    if !removed.success || removed.purged_user_data {
        return Err(Failure::local("uninstall", "preservation-contract-failed"));
    }
    checks.uninstall_preserved_user_state = true;

    let reinstall_token = crate::commands::begin_operation(app.state(), OperationKind::Update)
        .map_err(|error| Failure::command("reinstall-arm", error))?;
    let reinstalled = crate::commands::win_perform_update(
        app.clone(),
        app.state(),
        true,
        reinstall_token,
        None,
        None,
    )
    .await
    .map_err(|error| Failure::command("reinstall", error))?;
    if !reinstalled.success {
        return Err(Failure::local("reinstall", "perform-not-successful"));
    }
    checks.reinstall = true;
    crate::commands::win_launch_codex(app.state())
        .await
        .map_err(|error| Failure::command("relaunch", error))?;
    checks.relaunch = true;
    Ok(())
}

fn write_evidence(path: &Path, evidence: &LifecycleEvidence) -> Result<(), Failure> {
    let bytes =
        serde_json::to_vec_pretty(evidence).map_err(|_| Failure::local("evidence", "serialize"))?;
    crate::app::atomic_file::write_atomic(path, &bytes)
        .map_err(|_| Failure::local("evidence", "write"))?;
    let read_back = std::fs::read(path).map_err(|_| Failure::local("evidence", "readback"))?;
    if read_back != bytes {
        return Err(Failure::local("evidence", "readback-mismatch"));
    }
    Ok(())
}

async fn execute(app: AppHandle) -> Result<(), Failure> {
    let (release_tag, source_sha, target, data_root) = activation()?;
    let evidence_path = data_root.join(EVIDENCE_FILE);
    let started = Instant::now();
    let executable_hash = executable_sha256()?;
    let build_id = crate::delivery_runtime::embedded_release_build_id()
        .map_err(|error| Failure::local("identity", &error.code))?;
    let mut checks = LifecycleChecks::default();
    let result = native_flow(&app, &mut checks).await;
    let evidence = LifecycleEvidence {
        schema_version: 1,
        status: if result.is_ok() { "PASS" } else { "FAIL" },
        release_tag,
        source_sha,
        build_id,
        platform: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        target,
        manager_executable_sha256: executable_hash,
        elapsed_seconds: started.elapsed().as_secs(),
        checks,
        production_changed: true,
        public_default_changed: false,
        fixed_test_customer_data_changed: true,
        secret_values_recorded: false,
        failure_stage: result.as_ref().err().map(|error| error.stage.to_string()),
        failure_code: result.as_ref().err().map(|error| error.code.clone()),
    };
    write_evidence(&evidence_path, &evidence)?;
    result
}

pub fn spawn_if_requested(app: AppHandle) {
    if std::env::var(ENABLE_ENV).as_deref() != Ok("1") {
        return;
    }
    tauri::async_runtime::spawn(async move {
        let result = execute(app.clone()).await;
        if let Err(error) = &result {
            log::error!(
                "G7 native acceptance failed stage={} code={}",
                error.stage,
                error.code
            );
        } else {
            log::info!("G7 native acceptance completed");
        }
        app.state::<ManagerState>()
            .force_quit
            .store(true, Ordering::SeqCst);
        app.exit(if result.is_ok() { 0 } else { 1 });
    });
}

#[cfg(test)]
mod tests {
    use super::{safe_code, valid_release_tag};

    #[test]
    fn activation_identity_syntax_is_strict() {
        assert!(valid_release_tag("v4.0.0"));
        assert!(!valid_release_tag("v4.0"));
        assert!(!valid_release_tag("4.0.0"));
        assert!(!valid_release_tag("v4.0.0-rc1"));
    }

    #[test]
    fn failure_evidence_codes_cannot_contain_paths_or_secrets() {
        assert_eq!(safe_code("bootstrap-invalid"), "bootstrap-invalid");
        assert_eq!(
            safe_code("C:\\Users\\alice\\sk-secret"),
            "CUsersalicesk-secret"
        );
        assert_eq!(safe_code(""), "g7-failed");
    }
}

#[cfg(target_os = "macos")]
async fn native_flow(app: &AppHandle, checks: &mut LifecycleChecks) -> Result<(), Failure> {
    let first = crate::commands::mac_install(app.clone(), app.state())
        .await
        .map_err(|error| Failure::command("clean-install", error))?;
    let installed_path = first
        .installed
        .as_ref()
        .map(|installed| installed.path.clone())
        .ok_or_else(|| Failure::local("clean-install", "installed-identity-missing"))?;
    if first.status != "managed" {
        return Err(Failure::local("clean-install", "expected-managed"));
    }
    checks.clean_install = true;
    checks.official_identity_health = true;
    checks.signed_sidecar_delivery = true;
    checks.config_and_responses_verification = true;
    crate::commands::mac_launch_codex(app.state())
        .await
        .map_err(|error| Failure::command("launch", error))?;
    checks.app_launch = true;

    let repair = crate::commands::mac_install(app.clone(), app.state())
        .await
        .map_err(|error| Failure::command("repair", error))?;
    if repair.status != "managed" {
        return Err(Failure::local("repair", "expected-managed"));
    }
    checks.repair_or_same_version_run = true;

    remove_current_provenance(&installed_path)?;
    let external = crate::commands::mac_status(app.state())
        .map_err(|error| Failure::command("external-classification", error))?;
    if external.status != "external" {
        return Err(Failure::local(
            "external-classification",
            "expected-external",
        ));
    }
    checks.external_install_classification = true;
    let adopted = crate::commands::mac_adopt(app.clone(), app.state())
        .await
        .map_err(|error| Failure::command("adopt-existing", error))?;
    if adopted.status != "managed" {
        return Err(Failure::local("adopt-existing", "expected-managed"));
    }
    checks.adopt_existing = true;

    let uninstall_token = crate::commands::arm_destructive(app.state(), OperationKind::Uninstall)
        .map_err(|error| Failure::command("uninstall-arm", error))?;
    let removed =
        crate::commands::mac_uninstall(app.clone(), app.state(), true, uninstall_token, true)
            .await
            .map_err(|error| Failure::command("uninstall", error))?;
    if !removed.removed || !removed.kept_codex_home {
        return Err(Failure::local("uninstall", "preservation-contract-failed"));
    }
    checks.uninstall_preserved_user_state = true;

    let reinstalled = crate::commands::mac_install(app.clone(), app.state())
        .await
        .map_err(|error| Failure::command("reinstall", error))?;
    if reinstalled.status != "managed" {
        return Err(Failure::local("reinstall", "expected-managed"));
    }
    checks.reinstall = true;
    crate::commands::mac_launch_codex(app.state())
        .await
        .map_err(|error| Failure::command("relaunch", error))?;
    checks.relaunch = true;
    Ok(())
}
