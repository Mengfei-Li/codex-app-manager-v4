use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use toml_edit::{value, DocumentMut, Item, Value};
use uuid::Uuid;
use zeroize::Zeroizing;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::atomic::replace_file;
use crate::contract::sha256_hex;
use crate::credential::{CredentialHandle, CredentialVault};
use crate::error::DeliveryError;

pub const V2_MANAGED_BEGIN: &str = "# BEGIN PROVIDER CODEX MANAGED CONFIG";
pub const V2_MANAGED_END: &str = "# END PROVIDER CODEX MANAGED CONFIG";
pub const V4_MANAGED_BEGIN: &str = "# BEGIN PROVIDER CODEX V4 MANAGED CONFIG";
pub const V4_MANAGED_END: &str = "# END PROVIDER CODEX V4 MANAGED CONFIG";

const CONTROLLED_TOP_LEVEL: &[&str] = &[
    "default_permissions",
    "approval_policy",
    "sandbox_mode",
    "forced_login_method",
    "forced_chatgpt_workspace_id",
    "cli_auth_credentials_store",
    "profile",
    "model_provider",
    "openai_base_url",
    "model_catalog_json",
    "model",
    "review_model",
    "model_reasoning_effort",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictPolicy {
    RejectUnmanaged,
    AdoptRecognizedV2,
}

#[derive(Debug, Clone)]
pub struct ManagedConfigSpec {
    pub api_base_url: String,
    pub model_catalog_path: PathBuf,
    pub model_catalog_sha256: String,
    pub model: String,
    pub review_model: String,
    pub reasoning_effort: String,
    pub locale: String,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ProvisioningSecrets {
    pub api_key: String,
    pub management_token: String,
}

#[derive(Serialize)]
struct VaultSecret<'a> {
    api_key: &'a str,
    management_token: &'a str,
}

#[derive(Debug, Clone)]
pub struct ProvisioningPaths {
    pub codex_home: PathBuf,
    pub catalog_source: PathBuf,
}

pub struct ProvisioningRequest<'a> {
    pub paths: &'a ProvisioningPaths,
    pub spec: &'a ManagedConfigSpec,
    pub secrets: &'a ProvisioningSecrets,
    pub operation_id: Uuid,
    pub installation_id: Uuid,
    pub policy: ConflictPolicy,
}

#[derive(Debug, Clone)]
pub struct ScanLimits {
    pub maximum_depth: usize,
    pub maximum_entries: usize,
    pub maximum_project_files: usize,
    pub maximum_session_files: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            maximum_depth: 6,
            maximum_entries: 20_000,
            maximum_project_files: 64,
            maximum_session_files: 10_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupRecord {
    pub logical_name: String,
    pub target_path: String,
    pub existed: bool,
    pub original_sha256: Option<String>,
    pub backup_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigTransactionReport {
    pub schema_version: u32,
    pub operation_id: String,
    pub backup_directory: String,
    pub config_sha256: String,
    pub auth_sha256: String,
    pub catalog_sha256: String,
    pub credential_handle: CredentialHandle,
    pub recognized_v2: bool,
    pub config_repair_state: ConfigRepairState,
    pub repaired_project_configs: usize,
    pub migrated_sessions: usize,
    pub scan_truncated: bool,
    pub backups: Vec<BackupRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigRepairState {
    NotNeeded,
    Succeeded,
}

#[derive(Debug, Clone)]
pub struct MergeResult {
    pub bytes: Vec<u8>,
    pub recognized_v2: bool,
    pub conflicts: Vec<String>,
}

pub trait FaultInjector {
    fn checkpoint(&mut self, name: &str) -> Result<(), DeliveryError>;
}

pub struct NoFault;

impl FaultInjector for NoFault {
    fn checkpoint(&mut self, _name: &str) -> Result<(), DeliveryError> {
        Ok(())
    }
}

pub trait ConfigSemanticValidator {
    fn validate(&mut self, config_bytes: &[u8]) -> Result<(), DeliveryError>;
}

pub struct NoopConfigValidator;

impl ConfigSemanticValidator for NoopConfigValidator {
    fn validate(&mut self, _config_bytes: &[u8]) -> Result<(), DeliveryError> {
        Ok(())
    }
}

pub fn merge_config(
    original: &[u8],
    spec: &ManagedConfigSpec,
    policy: ConflictPolicy,
) -> Result<MergeResult, DeliveryError> {
    let source = std::str::from_utf8(original)
        .map_err(|_| DeliveryError::Toml("config is not UTF-8".to_string()))?;
    let had_v2 = source.contains(V2_MANAGED_BEGIN);
    let had_v4 = source.contains(V4_MANAGED_BEGIN);
    let cleaned = remove_managed_block(source, V2_MANAGED_BEGIN, V2_MANAGED_END)?;
    let cleaned = remove_managed_block(&cleaned, V4_MANAGED_BEGIN, V4_MANAGED_END)?;
    let mut document = if cleaned.trim().is_empty() {
        DocumentMut::new()
    } else {
        cleaned
            .parse::<DocumentMut>()
            .map_err(|error| DeliveryError::Toml(error.to_string()))?
    };
    let managed = had_v4 || (had_v2 && policy == ConflictPolicy::AdoptRecognizedV2);
    let desired = desired_top_level(spec);
    let conflicts = unmanaged_conflicts(&document, &desired, spec, managed);
    if !conflicts.is_empty() {
        return Ok(MergeResult {
            bytes: original.to_vec(),
            recognized_v2: had_v2,
            conflicts,
        });
    }

    for key in CONTROLLED_TOP_LEVEL {
        document.as_table_mut().remove(key);
    }
    if let Some(providers) = document
        .get_mut("model_providers")
        .and_then(Item::as_table_mut)
    {
        providers.remove("openai");
        providers.remove("relay");
        if providers.is_empty() {
            document.as_table_mut().remove("model_providers");
        }
    }
    set_table_string(&mut document, "windows", "sandbox", "elevated")?;
    set_table_string(
        &mut document,
        "desktop",
        "localeOverride",
        spec.locale.as_str(),
    )?;

    let mut output = managed_block(&desired);
    let remainder = document.to_string();
    if !remainder.trim().is_empty() {
        output.push_str(remainder.trim_start_matches(['\r', '\n']));
    }
    if !output.ends_with('\n') {
        output.push('\n');
    }
    output
        .parse::<DocumentMut>()
        .map_err(|error| DeliveryError::Toml(format!("merged config: {error}")))?;
    Ok(MergeResult {
        bytes: output.into_bytes(),
        recognized_v2: had_v2,
        conflicts: Vec::new(),
    })
}

fn desired_top_level(spec: &ManagedConfigSpec) -> Vec<(&'static str, String)> {
    vec![
        ("approval_policy", "never".to_string()),
        ("sandbox_mode", "danger-full-access".to_string()),
        ("forced_login_method", "api".to_string()),
        ("cli_auth_credentials_store", "file".to_string()),
        ("model_provider", "openai".to_string()),
        ("openai_base_url", spec.api_base_url.clone()),
        (
            "model_catalog_json",
            spec.model_catalog_path.to_string_lossy().replace('\\', "/"),
        ),
        ("model", spec.model.clone()),
        ("review_model", spec.review_model.clone()),
        ("model_reasoning_effort", spec.reasoning_effort.clone()),
    ]
}

fn unmanaged_conflicts(
    document: &DocumentMut,
    desired: &[(&str, String)],
    spec: &ManagedConfigSpec,
    managed: bool,
) -> Vec<String> {
    if managed {
        return Vec::new();
    }
    let mut conflicts = BTreeSet::new();
    for (key, expected) in desired {
        if let Some(item) = document.get(key) {
            let matches = item
                .as_value()
                .and_then(Value::as_str)
                .is_some_and(|value| value == expected);
            if !matches {
                conflicts.insert((*key).to_string());
            }
        }
    }
    if let Some(table) = document.get("model_providers").and_then(Item::as_table) {
        if table.contains_key("openai") {
            conflicts.insert("model_providers.openai".to_string());
        }
        if table.contains_key("relay") {
            conflicts.insert("model_providers.relay".to_string());
        }
    }
    if let Some(item) = document
        .get("windows")
        .and_then(Item::as_table_like)
        .and_then(|table| table.get("sandbox"))
    {
        if item.as_value().and_then(Value::as_str) != Some("elevated") {
            conflicts.insert("windows.sandbox".to_string());
        }
    }
    if let Some(item) = document
        .get("desktop")
        .and_then(Item::as_table_like)
        .and_then(|table| table.get("localeOverride"))
    {
        if item.as_value().and_then(Value::as_str) != Some(spec.locale.as_str()) {
            conflicts.insert("desktop.localeOverride".to_string());
        }
    }
    conflicts.into_iter().collect()
}

fn set_table_string(
    document: &mut DocumentMut,
    table_name: &str,
    key: &str,
    desired: &str,
) -> Result<(), DeliveryError> {
    if document.get(table_name).is_none() {
        document
            .as_table_mut()
            .insert(table_name, Item::Table(toml_edit::Table::new()));
    }
    let table = document
        .get_mut(table_name)
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| DeliveryError::Toml(format!("{table_name} is not a table")))?;
    table.insert(key, value(desired));
    Ok(())
}

fn managed_block(values: &[(&str, String)]) -> String {
    let mut output = format!("{V4_MANAGED_BEGIN}\n");
    for (key, value) in values {
        output.push_str(key);
        output.push_str(" = ");
        output.push_str(&Value::from(value.as_str()).to_string());
        output.push('\n');
    }
    output.push_str(V4_MANAGED_END);
    output.push_str("\n\n");
    output
}

fn remove_managed_block(source: &str, begin: &str, end: &str) -> Result<String, DeliveryError> {
    let Some(start) = source.find(begin) else {
        if source.contains(end) {
            return Err(DeliveryError::Toml(format!("orphan managed marker {end}")));
        }
        return Ok(source.to_string());
    };
    if source[start + begin.len()..].contains(begin) {
        return Err(DeliveryError::Toml(format!(
            "duplicate managed marker {begin}"
        )));
    }
    let end_relative = source[start..]
        .find(end)
        .ok_or_else(|| DeliveryError::Toml(format!("unterminated managed marker {begin}")))?;
    let mut after = start + end_relative + end.len();
    while source
        .as_bytes()
        .get(after)
        .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
    {
        after += 1;
    }
    let mut output = String::with_capacity(source.len());
    output.push_str(&source[..start]);
    output.push_str(&source[after..]);
    Ok(output)
}

pub(crate) fn owner_only_permissions(path: &Path, directory: bool) -> Result<(), DeliveryError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
        )?;
    }
    #[cfg(windows)]
    {
        crate::windows_security::apply_owner_only_dacl(path, directory)?;
    }
    Ok(())
}

fn write_prepared(path: &Path, bytes: &[u8]) -> Result<(), DeliveryError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    owner_only_permissions(path, false)?;
    Ok(())
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, DeliveryError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn write_backup(
    target: &Path,
    logical_name: &str,
    backup_dir: &Path,
) -> Result<(BackupRecord, Option<Vec<u8>>), DeliveryError> {
    let original = read_optional(target)?;
    let (original_sha256, backup_path) = match &original {
        Some(bytes) => {
            let path = backup_dir.join(logical_name);
            write_prepared(&path, bytes)?;
            (
                Some(sha256_hex(bytes)),
                Some(path.to_string_lossy().to_string()),
            )
        }
        None => (None, None),
    };
    Ok((
        BackupRecord {
            logical_name: logical_name.to_string(),
            target_path: target.to_string_lossy().to_string(),
            existed: original.is_some(),
            original_sha256,
            backup_path,
        },
        original,
    ))
}

fn restore_file(path: &Path, original: &Option<Vec<u8>>) -> Result<(), DeliveryError> {
    match original {
        Some(bytes) => {
            let restore = path.with_extension(format!("v4-restore-{}", Uuid::new_v4().simple()));
            write_prepared(&restore, bytes)?;
            replace_file(&restore, path)?;
            if fs::read(path)? != *bytes {
                return Err(DeliveryError::Rollback(format!(
                    "readback mismatch for {}",
                    path.display()
                )));
            }
        }
        None => match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        },
    }
    Ok(())
}

pub fn provision_configuration<V: CredentialVault, F: FaultInjector>(
    request: ProvisioningRequest<'_>,
    vault: &mut V,
    faults: &mut F,
) -> Result<ConfigTransactionReport, DeliveryError> {
    provision_configuration_with_validator(request, vault, faults, &mut NoopConfigValidator)
}

pub fn provision_configuration_with_validator<
    V: CredentialVault,
    F: FaultInjector,
    C: ConfigSemanticValidator,
>(
    request: ProvisioningRequest<'_>,
    vault: &mut V,
    faults: &mut F,
    validator: &mut C,
) -> Result<ConfigTransactionReport, DeliveryError> {
    let paths = request.paths;
    fs::create_dir_all(&paths.codex_home)?;
    let lock_path = paths.codex_home.join("provider-codex-v4.lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)?;
    owner_only_permissions(&lock_path, false)?;
    fs4::FileExt::lock(&lock)
        .map_err(|error| DeliveryError::ConfigTransaction(format!("lock: {error}")))?;

    let result = provision_locked(request, vault, faults, validator);
    let unlock_result = fs4::FileExt::unlock(&lock)
        .map_err(|error| DeliveryError::ConfigTransaction(format!("unlock: {error}")));
    match (result, unlock_result) {
        (Ok(report), Ok(())) => Ok(report),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn provision_locked<V: CredentialVault, F: FaultInjector, C: ConfigSemanticValidator>(
    request: ProvisioningRequest<'_>,
    vault: &mut V,
    faults: &mut F,
    validator: &mut C,
) -> Result<ConfigTransactionReport, DeliveryError> {
    let ProvisioningRequest {
        paths,
        spec,
        secrets,
        operation_id,
        installation_id,
        policy,
    } = request;
    let config_path = paths.codex_home.join("config.toml");
    let auth_path = paths.codex_home.join("auth.json");
    let catalog_path = spec.model_catalog_path.clone();
    ensure_within(&paths.codex_home, &config_path)?;
    ensure_within(&paths.codex_home, &auth_path)?;
    ensure_within(&paths.codex_home, &catalog_path)?;
    owner_only_permissions(
        catalog_path.parent().ok_or_else(|| {
            DeliveryError::ConfigTransaction("catalog parent missing".to_string())
        })?,
        true,
    )?;

    let original_config = read_optional(&config_path)?.unwrap_or_default();
    let merged = merge_config(&original_config, spec, policy)?;
    if !merged.conflicts.is_empty() {
        return Err(DeliveryError::ConfigConflict(merged.conflicts.join(", ")));
    }
    let catalog = fs::read(&paths.catalog_source)?;
    validate_catalog(&catalog, &spec.model_catalog_sha256)?;
    let auth = serde_json::to_vec_pretty(&serde_json::json!({
        "OPENAI_API_KEY": secrets.api_key
    }))?;
    let mut auth_with_newline = auth;
    auth_with_newline.push(b'\n');

    let backup_dir = paths
        .codex_home
        .join("backups")
        .join(format!("provider-codex-v4-{operation_id}"));
    fs::create_dir_all(&backup_dir)?;
    owner_only_permissions(&backup_dir, true)?;
    let (config_backup, config_original) = write_backup(&config_path, "config.toml", &backup_dir)?;
    let (auth_backup, auth_original) = write_backup(&auth_path, "auth.json", &backup_dir)?;
    let (catalog_backup, catalog_original) =
        write_backup(&catalog_path, "models-full-responses.json", &backup_dir)?;
    let backups = vec![config_backup, auth_backup, catalog_backup];
    write_manifest(&backup_dir, operation_id, "prepared", &backups)?;
    faults.checkpoint("after-backup")?;

    let handle = CredentialHandle {
        service: "provider-codex-v4".to_string(),
        account: installation_id.to_string(),
    };
    let mut prior_credential = vault.get(&handle)?;
    let vault_secret = Zeroizing::new(serde_json::to_vec(&VaultSecret {
        api_key: &secrets.api_key,
        management_token: &secrets.management_token,
    })?);
    vault.set(&handle, &vault_secret)?;
    let targets = [
        (&config_path, merged.bytes.as_slice()),
        (&auth_path, auth_with_newline.as_slice()),
        (&catalog_path, catalog.as_slice()),
    ];
    let originals = [&config_original, &auth_original, &catalog_original];
    let mut prepared = Vec::new();
    let mut config_repair_state = ConfigRepairState::NotNeeded;
    let transaction_result = (|| {
        faults.checkpoint("after-vault-write")?;
        for (index, (target, bytes)) in targets.iter().enumerate() {
            let temporary = target.with_extension(format!("v4-tmp-{operation_id}-{index}"));
            if temporary.exists() {
                fs::remove_file(&temporary)?;
            }
            write_prepared(&temporary, bytes)?;
            prepared.push(temporary);
        }
        faults.checkpoint("after-prepare")?;
        for (index, (target, _)) in targets.iter().enumerate() {
            replace_file(&prepared[index], target)?;
            owner_only_permissions(target, false)?;
            faults.checkpoint(&format!("after-commit-{index}"))?;
        }
        validate_config_readback(&config_path, spec)?;
        validate_auth_readback(&auth_path, &secrets.api_key)?;
        validate_catalog(&fs::read(&catalog_path)?, &spec.model_catalog_sha256)?;
        if validator.validate(&fs::read(&config_path)?).is_err() {
            faults.checkpoint("before-minimal-config-repair")?;
            let minimal = merge_config(&[], spec, ConflictPolicy::RejectUnmanaged)?.bytes;
            let repair_temp =
                config_path.with_extension(format!("v4-minimal-repair-{operation_id}"));
            if repair_temp.exists() {
                fs::remove_file(&repair_temp)?;
            }
            write_prepared(&repair_temp, &minimal)?;
            prepared.push(repair_temp.clone());
            replace_file(&repair_temp, &config_path)?;
            owner_only_permissions(&config_path, false)?;
            validate_config_readback(&config_path, spec)?;
            validator.validate(&fs::read(&config_path)?).map_err(|_| {
                DeliveryError::ConfigTransaction(
                    "minimal config semantic validation failed".to_string(),
                )
            })?;
            config_repair_state = ConfigRepairState::Succeeded;
            faults.checkpoint("after-minimal-config-repair")?;
        }
        faults.checkpoint("after-readback")?;
        Ok::<(), DeliveryError>(())
    })();

    for path in &prepared {
        if path.exists() {
            let _ = fs::remove_file(path);
        }
    }
    if let Err(primary) = transaction_result {
        let mut rollback_errors = Vec::new();
        for ((target, _), original) in targets.iter().zip(originals) {
            if let Err(error) = restore_file(target, original) {
                rollback_errors.push(format!("{}: {error}", target.display()));
            }
        }
        let vault_rollback = match &prior_credential {
            Some(previous) => vault.set(&handle, previous),
            None => vault.delete(&handle),
        };
        if let Err(error) = vault_rollback {
            rollback_errors.push(format!("credential vault: {error}"));
        }
        prior_credential.zeroize();
        let _ = write_manifest(&backup_dir, operation_id, "rolled-back", &backups);
        if rollback_errors.is_empty() {
            return Err(DeliveryError::ConfigTransaction(format!(
                "{primary}; original files restored"
            )));
        }
        return Err(DeliveryError::Rollback(format!(
            "primary={primary}; rollback={}",
            rollback_errors.join(" | ")
        )));
    }
    prior_credential.zeroize();
    write_manifest(&backup_dir, operation_id, "committed", &backups)?;

    Ok(ConfigTransactionReport {
        schema_version: 1,
        operation_id: operation_id.to_string(),
        backup_directory: backup_dir.to_string_lossy().to_string(),
        config_sha256: sha256_hex(&fs::read(&config_path)?),
        auth_sha256: sha256_hex(&fs::read(&auth_path)?),
        catalog_sha256: sha256_hex(&fs::read(&catalog_path)?),
        credential_handle: handle,
        recognized_v2: merged.recognized_v2,
        config_repair_state,
        repaired_project_configs: 0,
        migrated_sessions: 0,
        scan_truncated: false,
        backups,
    })
}

fn ensure_within(root: &Path, path: &Path) -> Result<(), DeliveryError> {
    let root = root
        .canonicalize()
        .map_err(|error| DeliveryError::ConfigTransaction(format!("canonical root: {error}")))?;
    let parent = path.parent().ok_or_else(|| {
        DeliveryError::ConfigTransaction(format!("target has no parent: {}", path.display()))
    })?;
    fs::create_dir_all(parent)?;
    let parent = parent
        .canonicalize()
        .map_err(|error| DeliveryError::ConfigTransaction(format!("canonical parent: {error}")))?;
    if !parent.starts_with(&root) {
        return Err(DeliveryError::ConfigTransaction(format!(
            "target escapes Codex home: {}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_catalog(bytes: &[u8], expected_sha256: &str) -> Result<(), DeliveryError> {
    if sha256_hex(bytes) != expected_sha256 {
        return Err(DeliveryError::ConfigTransaction(
            "model catalog digest mismatch".to_string(),
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    let models = value
        .get("models")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| DeliveryError::ConfigTransaction("model catalog models".to_string()))?;
    if models.len() < 4 {
        return Err(DeliveryError::ConfigTransaction(
            "model catalog is unexpectedly small".to_string(),
        ));
    }
    let mut slugs = BTreeSet::new();
    for model in models {
        let slug = model
            .get("slug")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| DeliveryError::ConfigTransaction("model slug".to_string()))?;
        if !slugs.insert(slug.to_string()) {
            return Err(DeliveryError::ConfigTransaction(format!(
                "duplicate model slug {slug}"
            )));
        }
        if slug.ends_with("-lite") {
            return Err(DeliveryError::ConfigTransaction(
                "lite model is forbidden in the Full Responses catalog".to_string(),
            ));
        }
    }
    for required in ["gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"] {
        if !slugs.contains(required) {
            return Err(DeliveryError::ConfigTransaction(format!(
                "required model missing: {required}"
            )));
        }
    }
    Ok(())
}

fn validate_config_readback(path: &Path, spec: &ManagedConfigSpec) -> Result<(), DeliveryError> {
    let bytes = fs::read(path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| DeliveryError::Toml("config readback is not UTF-8".to_string()))?;
    if text.matches(V4_MANAGED_BEGIN).count() != 1 || text.matches(V4_MANAGED_END).count() != 1 {
        return Err(DeliveryError::ConfigTransaction(
            "managed block count".to_string(),
        ));
    }
    let document = text
        .parse::<DocumentMut>()
        .map_err(|error| DeliveryError::Toml(error.to_string()))?;
    let expected = desired_top_level(spec);
    for (key, expected_value) in expected {
        let actual = document
            .get(key)
            .and_then(Item::as_value)
            .and_then(Value::as_str);
        if actual != Some(expected_value.as_str()) {
            return Err(DeliveryError::ConfigTransaction(format!(
                "effective config mismatch: {key}"
            )));
        }
    }
    if document
        .get("model_providers")
        .and_then(Item::as_table_like)
        .is_some_and(|table| table.contains_key("openai") || table.contains_key("relay"))
    {
        return Err(DeliveryError::ConfigTransaction(
            "conflicting provider table survived".to_string(),
        ));
    }
    let windows = document
        .get("windows")
        .and_then(Item::as_table_like)
        .and_then(|table| table.get("sandbox"))
        .and_then(Item::as_value)
        .and_then(Value::as_str);
    let locale = document
        .get("desktop")
        .and_then(Item::as_table)
        .and_then(|table| table.get("localeOverride"))
        .and_then(Item::as_value)
        .and_then(Value::as_str);
    if windows != Some("elevated") || locale != Some(spec.locale.as_str()) {
        return Err(DeliveryError::ConfigTransaction(
            "platform config mismatch".to_string(),
        ));
    }
    Ok(())
}

fn validate_auth_readback(path: &Path, api_key: &str) -> Result<(), DeliveryError> {
    let value: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
    let object = value
        .as_object()
        .ok_or_else(|| DeliveryError::ConfigTransaction("auth object".to_string()))?;
    if object.len() != 1
        || object
            .get("OPENAI_API_KEY")
            .and_then(serde_json::Value::as_str)
            != Some(api_key)
    {
        return Err(DeliveryError::ConfigTransaction(
            "auth readback mismatch".to_string(),
        ));
    }
    Ok(())
}

fn write_manifest(
    backup_dir: &Path,
    operation_id: Uuid,
    state: &str,
    backups: &[BackupRecord],
) -> Result<(), DeliveryError> {
    let manifest = serde_json::to_vec_pretty(&serde_json::json!({
        "schema_version": 1,
        "operation_id": operation_id.to_string(),
        "state": state,
        "backups": backups,
    }))?;
    let target = backup_dir.join("transaction.json");
    let temporary = backup_dir.join(format!("transaction-{}.tmp", Uuid::new_v4().simple()));
    write_prepared(&temporary, &manifest)?;
    replace_file(&temporary, &target)?;
    owner_only_permissions(&target, false)?;
    let readback: serde_json::Value = serde_json::from_slice(&fs::read(&target)?)?;
    if readback.get("state").and_then(serde_json::Value::as_str) != Some(state) {
        return Err(DeliveryError::ConfigTransaction(
            "transaction manifest readback".to_string(),
        ));
    }
    Ok(())
}
