use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;

pub const BUNDLE_SCHEMA_VERSION: u32 = 1;
pub const MAX_ARTIFACTS: usize = 64;
pub const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_BUNDLE_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum DiagnosticError {
    #[error("invalid diagnostic input: {0}")]
    Invalid(&'static str),
    #[error("diagnostic I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("diagnostic serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("diagnostic archive failed: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("diagnostic bundle exceeded the size limit")]
    SizeLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactType {
    ParentLog,
    ChildWorkerLog,
    Transaction,
    SystemProbe,
    Verification,
    StructuredEvents,
    OperationJournal,
    OtherText,
    SafeBinary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RedactionPolicy {
    Text,
    Json,
    SafeBinary,
    Exclude,
}

#[derive(Debug, Clone)]
pub struct ArtifactDeclaration {
    pub producer: String,
    pub logical_name: String,
    pub source_path: PathBuf,
    pub artifact_type: ArtifactType,
    pub redaction_policy: RedactionPolicy,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactState {
    Included,
    Missing,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRecord {
    pub producer: String,
    pub logical_name: String,
    pub artifact_type: ArtifactType,
    pub redaction_policy: RedactionPolicy,
    pub required: bool,
    pub state: ArtifactState,
    pub created_at_unix: Option<u64>,
    pub sha256: Option<String>,
    pub size_in_bytes: Option<u64>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredFailure {
    pub domain: String,
    pub code: String,
    pub stage: String,
    pub retryable: bool,
    pub reboot_required: bool,
    pub root_cause: String,
    pub next_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticIdentity {
    pub report_id: String,
    pub operation_id: String,
    pub public_customer_id: Option<String>,
    pub order_id: Option<String>,
    pub device_hash: Option<String>,
    pub installation_id: Option<String>,
    pub build_id: String,
    pub os: String,
    pub architecture: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticManifest {
    pub schema_version: u32,
    pub generated_at_unix: u64,
    pub identity: DiagnosticIdentity,
    pub outcome: String,
    pub failure: Option<StructuredFailure>,
    pub artifacts: Vec<ArtifactRecord>,
    pub required_missing: Vec<String>,
    pub redaction_applied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizedBundle {
    pub report_id: String,
    pub operation_id: String,
    pub path: PathBuf,
    pub sha256: String,
    pub size_in_bytes: u64,
    pub manifest: DiagnosticManifest,
}

#[derive(Debug, Clone, Default)]
pub struct RedactionContext {
    secrets: Vec<Vec<u8>>,
    home_paths: Vec<String>,
}

impl RedactionContext {
    pub fn add_secret(&mut self, secret: impl AsRef<[u8]>) {
        let value = secret.as_ref();
        if value.len() >= 4 && !self.secrets.iter().any(|existing| existing == value) {
            self.secrets.push(value.to_vec());
        }
    }

    pub fn add_home_path(&mut self, path: impl Into<String>) {
        let path = path.into();
        if !path.is_empty() && !self.home_paths.contains(&path) {
            self.home_paths.push(path);
        }
    }
}

impl Drop for RedactionContext {
    fn drop(&mut self) {
        for secret in &mut self.secrets {
            secret.fill(0);
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArtifactRegistry {
    declarations: Vec<ArtifactDeclaration>,
}

impl ArtifactRegistry {
    pub fn new() -> Self {
        Self {
            declarations: Vec::new(),
        }
    }

    pub fn register(&mut self, declaration: ArtifactDeclaration) -> Result<(), DiagnosticError> {
        if self.declarations.len() >= MAX_ARTIFACTS {
            return Err(DiagnosticError::Invalid("too many artifacts"));
        }
        validate_component(&declaration.producer)?;
        validate_logical_name(&declaration.logical_name)?;
        if self
            .declarations
            .iter()
            .any(|item| item.logical_name == declaration.logical_name)
        {
            return Err(DiagnosticError::Invalid("duplicate logical name"));
        }
        self.declarations.push(declaration);
        Ok(())
    }

    pub fn declarations(&self) -> &[ArtifactDeclaration] {
        &self.declarations
    }
}

impl Default for ArtifactRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub struct BundleBuilder {
    pub identity: DiagnosticIdentity,
    pub outcome: String,
    pub failure: Option<StructuredFailure>,
    pub registry: ArtifactRegistry,
    pub redaction: RedactionContext,
    pub producer_wait: Duration,
}

impl BundleBuilder {
    pub fn finalize(self, output_root: &Path) -> Result<FinalizedBundle, DiagnosticError> {
        validate_identity(&self.identity)?;
        ensure_private_directory(output_root)?;
        wait_for_registered_producers(self.registry.declarations(), self.producer_wait);

        let final_path = output_root.join(format!("{}.zip", self.identity.report_id));
        if final_path.exists() {
            return load_existing_bundle(&final_path, &self.identity);
        }
        let temporary_path = output_root.join(format!(
            ".{}.{}.tmp",
            self.identity.report_id,
            uuid::Uuid::new_v4()
        ));
        let result = self.write_temporary_bundle(&temporary_path);
        match result {
            Ok((manifest, sha256, size_in_bytes)) => {
                fs::rename(&temporary_path, &final_path)?;
                sync_parent(output_root)?;
                set_owner_only_permissions(&final_path, false)?;
                Ok(FinalizedBundle {
                    report_id: self.identity.report_id,
                    operation_id: self.identity.operation_id,
                    path: final_path,
                    sha256,
                    size_in_bytes,
                    manifest,
                })
            }
            Err(error) => {
                let _ = fs::remove_file(&temporary_path);
                Err(error)
            }
        }
    }

    fn write_temporary_bundle(
        &self,
        temporary_path: &Path,
    ) -> Result<(DiagnosticManifest, String, u64), DiagnosticError> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temporary_path)?;
        set_owner_only_permissions(temporary_path, false)?;
        let mut archive = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o600);
        let mut records = Vec::with_capacity(self.registry.declarations().len());
        let mut logical_total = 0_u64;

        for declaration in self.registry.declarations() {
            let (record, bytes) = collect_artifact(declaration, &self.redaction)?;
            if let Some(bytes) = bytes {
                logical_total = logical_total.saturating_add(bytes.len() as u64);
                if logical_total > MAX_BUNDLE_BYTES {
                    return Err(DiagnosticError::SizeLimit);
                }
                archive.start_file(format!("artifacts/{}", declaration.logical_name), options)?;
                archive.write_all(&bytes)?;
            }
            records.push(record);
        }

        let required_missing = records
            .iter()
            .filter(|record| record.required && record.state != ArtifactState::Included)
            .map(|record| record.logical_name.clone())
            .collect::<Vec<_>>();
        let manifest = DiagnosticManifest {
            schema_version: BUNDLE_SCHEMA_VERSION,
            generated_at_unix: now_unix(),
            identity: self.identity.clone(),
            outcome: self.outcome.clone(),
            failure: self.failure.clone(),
            artifacts: records,
            required_missing,
            redaction_applied: true,
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        archive.start_file("manifest.json", options)?;
        archive.write_all(&manifest_bytes)?;
        let mut file = archive.finish()?;
        file.flush()?;
        file.sync_all()?;
        let size = file.metadata()?.len();
        drop(file);
        if size > MAX_BUNDLE_BYTES {
            return Err(DiagnosticError::SizeLimit);
        }
        Ok((manifest, sha256_file(temporary_path)?, size))
    }
}

fn collect_artifact(
    declaration: &ArtifactDeclaration,
    redaction: &RedactionContext,
) -> Result<(ArtifactRecord, Option<Vec<u8>>), DiagnosticError> {
    let base = ArtifactRecord {
        producer: declaration.producer.clone(),
        logical_name: declaration.logical_name.clone(),
        artifact_type: declaration.artifact_type,
        redaction_policy: declaration.redaction_policy,
        required: declaration.required,
        state: ArtifactState::Missing,
        created_at_unix: None,
        sha256: None,
        size_in_bytes: None,
        note: None,
    };
    if declaration.redaction_policy == RedactionPolicy::Exclude {
        return Ok((
            ArtifactRecord {
                state: ArtifactState::Rejected,
                note: Some("excluded-by-policy".to_string()),
                ..base
            },
            None,
        ));
    }
    let metadata = match fs::symlink_metadata(&declaration.source_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((
                ArtifactRecord {
                    note: Some("producer-did-not-create-file".to_string()),
                    ..base
                },
                None,
            ));
        }
        Err(error) => {
            return Ok((
                ArtifactRecord {
                    state: ArtifactState::Rejected,
                    note: Some(format!("metadata-{}", io_kind_code(error.kind()))),
                    ..base
                },
                None,
            ));
        }
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Ok((
            ArtifactRecord {
                state: ArtifactState::Rejected,
                note: Some("not-a-regular-file".to_string()),
                ..base
            },
            None,
        ));
    }
    if metadata.len() > MAX_ARTIFACT_BYTES {
        return Ok((
            ArtifactRecord {
                state: ArtifactState::Rejected,
                size_in_bytes: Some(metadata.len()),
                note: Some("artifact-size-limit".to_string()),
                ..base
            },
            None,
        ));
    }
    let file = match File::open(&declaration.source_path) {
        Ok(file) => file,
        Err(error) => {
            return Ok((
                ArtifactRecord {
                    state: ArtifactState::Rejected,
                    note: Some(format!("open-{}", io_kind_code(error.kind()))),
                    ..base
                },
                None,
            ));
        }
    };
    let mut raw = Vec::with_capacity(metadata.len() as usize);
    if let Err(error) = file.take(MAX_ARTIFACT_BYTES + 1).read_to_end(&mut raw) {
        return Ok((
            ArtifactRecord {
                state: ArtifactState::Rejected,
                note: Some(format!("read-{}", io_kind_code(error.kind()))),
                ..base
            },
            None,
        ));
    }
    if raw.len() as u64 > MAX_ARTIFACT_BYTES {
        return Err(DiagnosticError::SizeLimit);
    }
    let bytes = match declaration.redaction_policy {
        RedactionPolicy::Text => redact_text(&raw, redaction)?,
        RedactionPolicy::Json => redact_json(&raw, redaction)?,
        RedactionPolicy::SafeBinary => raw,
        RedactionPolicy::Exclude => unreachable!(),
    };
    let size = bytes.len() as u64;
    let hash = sha256_bytes(&bytes);
    let created_at_unix = metadata
        .created()
        .or_else(|_| metadata.modified())
        .ok()
        .and_then(system_time_unix);
    Ok((
        ArtifactRecord {
            state: ArtifactState::Included,
            created_at_unix,
            sha256: Some(hash),
            size_in_bytes: Some(size),
            note: None,
            ..base
        },
        Some(bytes),
    ))
}

fn io_kind_code(kind: std::io::ErrorKind) -> &'static str {
    match kind {
        std::io::ErrorKind::NotFound => "not-found",
        std::io::ErrorKind::PermissionDenied => "permission-denied",
        std::io::ErrorKind::TimedOut => "timed-out",
        std::io::ErrorKind::WouldBlock => "would-block",
        std::io::ErrorKind::InvalidData => "invalid-data",
        _ => "io-error",
    }
}

fn redact_text(raw: &[u8], context: &RedactionContext) -> Result<Vec<u8>, DiagnosticError> {
    let mut text = String::from_utf8(raw.to_vec())
        .map_err(|_| DiagnosticError::Invalid("text artifact is not UTF-8"))?;
    for secret in &context.secrets {
        if let Ok(secret) = std::str::from_utf8(secret) {
            text = text.replace(secret, "<redacted-secret>");
        }
    }
    for home in &context.home_paths {
        text = replace_case_insensitive(&text, home, "<user-home>");
    }
    let redacted = text
        .lines()
        .map(redact_sensitive_line)
        .collect::<Vec<_>>()
        .join("\n");
    Ok(if text.ends_with('\n') {
        format!("{redacted}\n").into_bytes()
    } else {
        redacted.into_bytes()
    })
}

fn redact_sensitive_line(line: &str) -> String {
    const SENSITIVE_KEYS: &[&str] = &[
        "api_key",
        "apikey",
        "authorization",
        "bootstrap_token",
        "management_token",
        "password",
        "secret",
        "token",
    ];
    let lower = line.to_ascii_lowercase();
    let sensitive = SENSITIVE_KEYS.iter().any(|key| lower.contains(key));
    if !sensitive {
        return line.to_string();
    }
    for delimiter in [':', '='] {
        if let Some(index) = line.find(delimiter) {
            let prefix = &line[..=index];
            return format!("{prefix} <redacted-secret>");
        }
    }
    "<redacted-sensitive-line>".to_string()
}

fn redact_json(raw: &[u8], context: &RedactionContext) -> Result<Vec<u8>, DiagnosticError> {
    let mut value: Value = serde_json::from_slice(raw)?;
    redact_json_value(&mut value, context);
    Ok(serde_json::to_vec_pretty(&value)?)
}

fn redact_json_value(value: &mut Value, context: &RedactionContext) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let lower = key.to_ascii_lowercase();
                if [
                    "api_key",
                    "authorization",
                    "bootstrap_token",
                    "management_token",
                    "password",
                    "secret",
                    "token",
                ]
                .iter()
                .any(|candidate| lower.contains(candidate))
                {
                    *value = Value::String("<redacted-secret>".to_string());
                } else {
                    redact_json_value(value, context);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                redact_json_value(value, context);
            }
        }
        Value::String(text) => {
            for secret in &context.secrets {
                if let Ok(secret) = std::str::from_utf8(secret) {
                    *text = text.replace(secret, "<redacted-secret>");
                }
            }
            for home in &context.home_paths {
                *text = replace_case_insensitive(text, home, "<user-home>");
            }
        }
        _ => {}
    }
}

fn replace_case_insensitive(input: &str, needle: &str, replacement: &str) -> String {
    if needle.is_empty() {
        return input.to_string();
    }
    let lower_input = input.to_ascii_lowercase();
    let lower_needle = needle.to_ascii_lowercase();
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;
    while let Some(offset) = lower_input[cursor..].find(&lower_needle) {
        let start = cursor + offset;
        let end = start + needle.len();
        if !input.is_char_boundary(start) || !input.is_char_boundary(end) {
            break;
        }
        output.push_str(&input[cursor..start]);
        output.push_str(replacement);
        cursor = end;
    }
    output.push_str(&input[cursor..]);
    output
}

fn wait_for_registered_producers(declarations: &[ArtifactDeclaration], timeout: Duration) {
    if timeout.is_zero() {
        return;
    }
    let deadline = Instant::now() + timeout;
    loop {
        let all_required_exist = declarations
            .iter()
            .filter(|item| item.required)
            .all(|item| item.source_path.is_file());
        if all_required_exist || Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn load_existing_bundle(
    path: &Path,
    expected: &DiagnosticIdentity,
) -> Result<FinalizedBundle, DiagnosticError> {
    let file = File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    let manifest: DiagnosticManifest = {
        let mut entry = archive.by_name("manifest.json")?;
        if entry.size() > 1024 * 1024 {
            return Err(DiagnosticError::SizeLimit);
        }
        let mut bytes = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut bytes)?;
        serde_json::from_slice(&bytes)?
    };
    if manifest.identity != *expected {
        return Err(DiagnosticError::Invalid(
            "existing bundle identity mismatch",
        ));
    }
    let size = fs::metadata(path)?.len();
    Ok(FinalizedBundle {
        report_id: expected.report_id.clone(),
        operation_id: expected.operation_id.clone(),
        path: path.to_path_buf(),
        sha256: sha256_file(path)?,
        size_in_bytes: size,
        manifest,
    })
}

/// Re-open a previously finalized bundle for manual retransmission or deletion.
/// The archive manifest, filename, size and digest are revalidated; callers do
/// not need to trust mutable sidecar state.
pub fn load_finalized_bundle(path: &Path) -> Result<FinalizedBundle, DiagnosticError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(DiagnosticError::Invalid("bundle is not a regular file"));
    }
    if metadata.len() == 0 || metadata.len() > MAX_BUNDLE_BYTES {
        return Err(DiagnosticError::SizeLimit);
    }
    let file = File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    let manifest: DiagnosticManifest = {
        let mut entry = archive.by_name("manifest.json")?;
        if entry.size() > 1024 * 1024 {
            return Err(DiagnosticError::SizeLimit);
        }
        let mut bytes = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut bytes)?;
        serde_json::from_slice(&bytes)?
    };
    validate_identity(&manifest.identity)?;
    let expected_name = format!("{}.zip", manifest.identity.report_id);
    if path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
        return Err(DiagnosticError::Invalid("bundle filename mismatch"));
    }
    Ok(FinalizedBundle {
        report_id: manifest.identity.report_id.clone(),
        operation_id: manifest.identity.operation_id.clone(),
        path: path.to_path_buf(),
        sha256: sha256_file(path)?,
        size_in_bytes: metadata.len(),
        manifest,
    })
}

fn validate_identity(identity: &DiagnosticIdentity) -> Result<(), DiagnosticError> {
    validate_component(&identity.report_id)?;
    validate_component(&identity.operation_id)?;
    validate_component(&identity.build_id)?;
    validate_component(&identity.os)?;
    validate_component(&identity.architecture)?;
    for value in [
        identity.public_customer_id.as_deref(),
        identity.order_id.as_deref(),
        identity.device_hash.as_deref(),
        identity.installation_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_component(value)?;
    }
    Ok(())
}

fn validate_component(value: &str) -> Result<(), DiagnosticError> {
    if value.is_empty()
        || value.len() > 160
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(DiagnosticError::Invalid("unsafe identifier"));
    }
    Ok(())
}

fn validate_logical_name(value: &str) -> Result<(), DiagnosticError> {
    if value.is_empty() || value.len() > 200 || value.contains('\\') {
        return Err(DiagnosticError::Invalid("unsafe logical name"));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(DiagnosticError::Invalid("unsafe logical name"));
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/'))
    {
        return Err(DiagnosticError::Invalid("unsafe logical name"));
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), DiagnosticError> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(DiagnosticError::Invalid(
            "bundle root is not a safe directory",
        ));
    }
    set_owner_only_permissions(path, true)?;
    Ok(())
}

fn set_owner_only_permissions(path: &Path, directory: bool) -> Result<(), DiagnosticError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
        )?;
    }
    #[cfg(not(unix))]
    let _ = (path, directory);
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), DiagnosticError> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_digest(hasher.finalize().as_slice())
}

fn sha256_file(path: &Path) -> Result<String, DiagnosticError> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex_digest(hasher.finalize().as_slice()))
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn system_time_unix(value: SystemTime) -> Option<u64> {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UploadStatus {
    Pending,
    Uploaded,
    FailedRetained,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadReceipt {
    pub report_id: String,
    pub server_receipt_id: String,
    pub received_sha256: String,
    pub identity_linked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadState {
    pub schema_version: u32,
    pub report_id: String,
    pub bundle_sha256: String,
    pub status: UploadStatus,
    pub attempts: u32,
    pub last_error_code: Option<String>,
    pub receipt: Option<UploadReceipt>,
    pub updated_at_unix: u64,
}

pub trait BundleTransport {
    fn upload(
        &mut self,
        bundle: &FinalizedBundle,
        idempotency_key: &str,
    ) -> Result<UploadReceipt, String>;
}

pub fn upload_with_retry<T: BundleTransport>(
    bundle: &FinalizedBundle,
    state_root: &Path,
    max_attempts: u32,
    transport: &mut T,
) -> Result<UploadState, DiagnosticError> {
    if max_attempts == 0 || max_attempts > 5 {
        return Err(DiagnosticError::Invalid("invalid upload attempt budget"));
    }
    ensure_private_directory(state_root)?;
    let state_path = state_root.join(format!("{}.upload.json", bundle.report_id));
    if let Ok(existing) = load_upload_state(&state_path) {
        if existing.bundle_sha256 != bundle.sha256 {
            return Err(DiagnosticError::Invalid("upload state digest mismatch"));
        }
        if existing.status == UploadStatus::Uploaded {
            return Ok(existing);
        }
    }
    let mut state = UploadState {
        schema_version: 1,
        report_id: bundle.report_id.clone(),
        bundle_sha256: bundle.sha256.clone(),
        status: UploadStatus::Pending,
        attempts: 0,
        last_error_code: None,
        receipt: None,
        updated_at_unix: now_unix(),
    };
    persist_upload_state(&state_path, &state)?;
    for _ in 0..max_attempts {
        state.attempts += 1;
        match transport.upload(bundle, &bundle.report_id) {
            Ok(receipt)
                if receipt.report_id == bundle.report_id
                    && receipt.received_sha256 == bundle.sha256 =>
            {
                state.status = UploadStatus::Uploaded;
                state.last_error_code = None;
                state.receipt = Some(receipt);
                state.updated_at_unix = now_unix();
                persist_upload_state(&state_path, &state)?;
                return Ok(state);
            }
            Ok(_) => state.last_error_code = Some("receipt-mismatch".to_string()),
            Err(code) => state.last_error_code = Some(safe_error_code(&code)),
        }
        state.status = UploadStatus::FailedRetained;
        state.updated_at_unix = now_unix();
        persist_upload_state(&state_path, &state)?;
    }
    Ok(state)
}

pub fn load_upload_state(path: &Path) -> Result<UploadState, DiagnosticError> {
    let bytes = fs::read(path)?;
    if bytes.len() > 128 * 1024 {
        return Err(DiagnosticError::SizeLimit);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn persist_upload_state(path: &Path, state: &UploadState) -> Result<(), DiagnosticError> {
    let parent = path
        .parent()
        .ok_or(DiagnosticError::Invalid("upload state parent"))?;
    let temporary = parent.join(format!(".upload-state-{}.tmp", uuid::Uuid::new_v4()));
    let bytes = serde_json::to_vec_pretty(state)?;
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        set_owner_only_permissions(&temporary, false)?;
        file.write_all(&bytes)?;
        file.flush()?;
        file.sync_all()?;
    }
    fs::rename(&temporary, path)?;
    sync_parent(parent)?;
    set_owner_only_permissions(path, false)?;
    Ok(())
}

fn safe_error_code(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    if lower.contains("timeout") || lower.contains("timed out") {
        "upload-timeout"
    } else if lower.contains("offline")
        || lower.contains("network")
        || lower.contains("connect")
        || lower.contains("dns")
    {
        "network-unavailable"
    } else if lower.contains("unauthorized") || lower.contains("forbidden") {
        "upload-unauthorized"
    } else if lower.contains("too large") || lower.contains("size") {
        "upload-size-limit"
    } else {
        "upload-failed"
    }
    .to_string()
}

pub fn remove_local_bundle(bundle: &FinalizedBundle, root: &Path) -> Result<(), DiagnosticError> {
    let root = root.canonicalize()?;
    let path = bundle.path.canonicalize()?;
    if path.parent() != Some(root.as_path())
        || path.file_name().and_then(|name| name.to_str())
            != Some(format!("{}.zip", bundle.report_id).as_str())
    {
        return Err(DiagnosticError::Invalid("bundle delete escaped root"));
    }
    fs::remove_file(path)?;
    Ok(())
}

pub fn report_id() -> String {
    format!("IR-V4-{}", uuid::Uuid::new_v4())
}

pub fn included_artifact_names(manifest: &DiagnosticManifest) -> BTreeSet<&str> {
    manifest
        .artifacts
        .iter()
        .filter(|record| record.state == ArtifactState::Included)
        .map(|record| record.logical_name.as_str())
        .collect()
}
