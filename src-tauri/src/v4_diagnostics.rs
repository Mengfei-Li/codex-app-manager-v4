//! V4 failure diagnostics integration.
//!
//! This module is deliberately backend-only.  It finalizes a complete local
//! bundle before attempting any upload, never exposes the management token to
//! the renderer, and keeps an idempotent upload state for later retransmission.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(any(target_os = "windows", target_os = "macos"))]
use codex_delivery_engine::NativeCredentialVault;
use codex_delivery_engine::{CredentialHandle, CredentialVault};
use codex_diagnostics_engine::{
    load_finalized_bundle, remove_local_bundle, report_id, upload_with_retry, ArtifactDeclaration,
    ArtifactRegistry, ArtifactType, BundleBuilder, BundleTransport, DiagnosticIdentity,
    FinalizedBundle, RedactionContext, RedactionPolicy, StructuredFailure, UploadReceipt,
    UploadState, UploadStatus,
};
use reqwest::blocking::{Body, Client};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::app::logging::logs_dir;
use crate::app::operation_journal::OperationDiagnosticState;
use crate::app::oplock::{OperationManager, OperationSnapshot, OperationToken};
use crate::errors::CommandError;

const CONTEXT_SCHEMA_VERSION: u32 = 1;
const LATEST_SCHEMA_VERSION: u32 = 1;
const MAX_CONTEXT_BYTES: u64 = 128 * 1024;
const MAX_RECEIPT_BYTES: u64 = 1024 * 1024;
const PRODUCER_WAIT: Duration = Duration::from_millis(500);
const UPLOAD_ATTEMPTS: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticBusinessContext {
    pub schema_version: u32,
    pub public_customer_id: Option<String>,
    pub order_id: Option<String>,
    pub device_hash: Option<String>,
    pub installation_id: String,
    pub credential_service: String,
    pub credential_account: String,
    pub diagnostic_endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LatestDiagnosticReport {
    pub schema_version: u32,
    pub report_id: String,
    pub operation_id: String,
    pub local_bundle_path: String,
    pub bundle_sha256: String,
    pub upload_status: String,
    pub upload_attempts: u32,
    pub server_receipt_id: Option<String>,
    pub support_summary: String,
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone)]
pub struct FailureDescriptor {
    pub domain: String,
    pub code: String,
    pub stage: String,
    pub retryable: bool,
    pub reboot_required: bool,
}

impl FailureDescriptor {
    pub fn from_command(error: &CommandError, stage: &str) -> Self {
        Self {
            domain: "manager".to_string(),
            code: safe_identifier(&error.code, "operation-failed"),
            stage: safe_identifier(stage, "unknown"),
            retryable: matches!(
                error.code.as_str(),
                "network"
                    | "timeout"
                    | "disk_space"
                    | "disk_write"
                    | "permission"
                    | "artifact"
                    | "install"
                    | "operation_busy"
                    | "internal_error"
                    | "engine_error"
            ),
            reboot_required: false,
        }
    }

    pub fn generic(stage: &str) -> Self {
        Self {
            domain: "manager".to_string(),
            code: "operation-failed".to_string(),
            stage: safe_identifier(stage, "unknown"),
            retryable: true,
            reboot_required: false,
        }
    }

    fn structured(&self) -> StructuredFailure {
        StructuredFailure {
            domain: self.domain.clone(),
            code: self.code.clone(),
            stage: self.stage.clone(),
            retryable: self.retryable,
            reboot_required: self.reboot_required,
            root_cause: root_cause_for(&self.code).to_string(),
            next_action: next_action_for(&self.code).to_string(),
        }
    }
}

/// P5 writes this immediately after a verified claim/config transaction.  The
/// context contains only identifiers and a native-vault handle, never secrets.
#[allow(dead_code)]
pub fn persist_business_context(context: &DiagnosticBusinessContext) -> Result<(), String> {
    validate_context(context)?;
    let path = context_path().ok_or_else(|| "diagnostic-data-dir-unavailable".to_string())?;
    let bytes =
        serde_json::to_vec_pretty(context).map_err(|_| "diagnostic-context-encode".to_string())?;
    write_private_atomic(&path, &bytes).map_err(|_| "diagnostic-context-write".to_string())
}

pub fn load_business_context() -> Option<DiagnosticBusinessContext> {
    let path = context_path()?;
    let metadata = fs::symlink_metadata(&path).ok()?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_CONTEXT_BYTES
    {
        return None;
    }
    let context: DiagnosticBusinessContext = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    validate_context(&context).ok()?;
    Some(context)
}

pub fn latest_report() -> Option<LatestDiagnosticReport> {
    let path = latest_path()?;
    let metadata = fs::symlink_metadata(&path).ok()?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_CONTEXT_BYTES
    {
        return None;
    }
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}

pub fn retry_latest_upload() -> Result<LatestDiagnosticReport, String> {
    let current = latest_report().ok_or_else(|| "diagnostic-report-missing".to_string())?;
    if current.local_bundle_path.is_empty() {
        return Err("diagnostic-bundle-deleted".to_string());
    }
    let bundle = load_finalized_bundle(Path::new(&current.local_bundle_path))
        .map_err(|_| "diagnostic-bundle-invalid".to_string())?;
    if bundle.report_id != current.report_id || bundle.sha256 != current.bundle_sha256 {
        return Err("diagnostic-bundle-state-mismatch".to_string());
    }
    let context = load_business_context();
    let authorization = diagnostic_authorization(context.as_ref());
    let mut transport = HttpBundleTransport::new(authorization.endpoint, authorization.token);
    let state_root = crate::app::paths::data_dir()
        .ok_or_else(|| "diagnostic-data-dir-unavailable".to_string())?
        .join("diagnostics")
        .join("upload-state");
    let state = upload_with_retry(&bundle, &state_root, UPLOAD_ATTEMPTS, &mut transport)
        .map_err(|_| "diagnostic-upload-state-failed".to_string())?;
    let latest = latest_from_upload(&bundle, &current.support_summary, Some(&state));
    persist_latest(&latest).map_err(|_| "diagnostic-latest-write".to_string())?;
    Ok(latest)
}

pub fn delete_latest_bundle() -> Result<LatestDiagnosticReport, String> {
    let mut current = latest_report().ok_or_else(|| "diagnostic-report-missing".to_string())?;
    if current.local_bundle_path.is_empty() {
        return Ok(current);
    }
    let bundle = load_finalized_bundle(Path::new(&current.local_bundle_path))
        .map_err(|_| "diagnostic-bundle-invalid".to_string())?;
    let root = crate::app::paths::data_dir()
        .ok_or_else(|| "diagnostic-data-dir-unavailable".to_string())?
        .join("diagnostics")
        .join("bundles");
    remove_local_bundle(&bundle, &root).map_err(|_| "diagnostic-delete-rejected".to_string())?;
    current.local_bundle_path.clear();
    current.upload_status = "deleted".to_string();
    current.updated_at_unix = now_unix();
    persist_latest(&current).map_err(|_| "diagnostic-latest-write".to_string())?;
    Ok(current)
}

/// Finalize the local bundle synchronously so a process exit cannot erase the
/// evidence.  Network upload is spawned only after the local state is durable.
pub fn finalize_failure(
    app: &tauri::AppHandle,
    operations: &OperationManager,
    token: &OperationToken,
    failure: FailureDescriptor,
) -> Option<OperationDiagnosticState> {
    let data_root = crate::app::paths::data_dir()?;
    finalize_failure_at(
        app,
        operations,
        token,
        failure,
        data_root,
        load_business_context(),
    )
}

fn finalize_failure_at<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    operations: &OperationManager,
    token: &OperationToken,
    failure: FailureDescriptor,
    data_root: PathBuf,
    context: Option<DiagnosticBusinessContext>,
) -> Option<OperationDiagnosticState> {
    let snapshot = operations.snapshot().filter(|item| item.id == token.0)?;
    let diagnostic_root = data_root.join("diagnostics");
    let bundles_root = diagnostic_root.join("bundles");
    let state_root = diagnostic_root.join("upload-state");
    let working_root = diagnostic_root.join("working");
    let report_id = report_id();
    let work = working_root.join(&report_id);
    if fs::create_dir_all(&work).is_err() {
        return None;
    }

    let mut authorization = diagnostic_authorization(context.as_ref());
    let structured = failure.structured();
    let failure_path = work.join("failure.json");
    let system_path = work.join("system.json");
    let events_path = work.join("structured-events.jsonl");
    let failure_bytes = serde_json::to_vec_pretty(&structured).ok()?;
    let system_bytes = system_probe_bytes(app, &snapshot).ok()?;
    let events_bytes = structured_event_bytes(&snapshot, &structured).ok()?;
    if write_private_atomic(&failure_path, &failure_bytes).is_err()
        || write_private_atomic(&system_path, &system_bytes).is_err()
        || write_private_atomic(&events_path, &events_bytes).is_err()
    {
        authorization.token.zeroize();
        return None;
    }

    let mut registry = ArtifactRegistry::new();
    register(
        &mut registry,
        "manager",
        "failure.json",
        failure_path,
        ArtifactType::Verification,
        RedactionPolicy::Json,
        true,
    )?;
    register(
        &mut registry,
        "manager",
        "system.json",
        system_path,
        ArtifactType::SystemProbe,
        RedactionPolicy::Json,
        true,
    )?;
    register(
        &mut registry,
        "manager",
        "structured-events.jsonl",
        events_path,
        ArtifactType::StructuredEvents,
        RedactionPolicy::Text,
        true,
    )?;
    register(
        &mut registry,
        "operation-manager",
        "operation-journal.json",
        operations
            .journal_path()
            .unwrap_or_else(|| work.join("missing-operation-journal.json")),
        ArtifactType::OperationJournal,
        RedactionPolicy::Json,
        true,
    )?;
    register(
        &mut registry,
        "manager-log",
        "manager.log",
        logs_dir(app)
            .as_deref()
            .and_then(latest_file)
            .unwrap_or_else(|| work.join("missing-manager.log")),
        ArtifactType::ParentLog,
        RedactionPolicy::Text,
        true,
    )?;
    register(
        &mut registry,
        "appx-worker",
        "child-worker.json",
        latest_file(&data_root.join("appx-workers"))
            .unwrap_or_else(|| work.join("missing-child-worker.json")),
        ArtifactType::ChildWorkerLog,
        RedactionPolicy::Json,
        false,
    )?;
    register(
        &mut registry,
        "platform-transaction",
        "install-transaction.json",
        latest_file(&data_root.join("install-transactions"))
            .unwrap_or_else(|| work.join("missing-install-transaction.json")),
        ArtifactType::Transaction,
        RedactionPolicy::Json,
        false,
    )?;
    register(
        &mut registry,
        "delivery",
        "config-transaction.json",
        crate::app::paths::codex_home_dir()
            .and_then(|root| latest_file_recursive(&root.join("backups"), "transaction.json", 512))
            .unwrap_or_else(|| work.join("missing-config-transaction.json")),
        ArtifactType::Transaction,
        RedactionPolicy::Json,
        false,
    )?;
    register(
        &mut registry,
        "verifier",
        "verification.json",
        latest_file(&data_root.join("verification"))
            .unwrap_or_else(|| work.join("missing-verification.json")),
        ArtifactType::Verification,
        RedactionPolicy::Json,
        false,
    )?;

    let mut redaction = RedactionContext::default();
    if let Some(home) = directories::UserDirs::new() {
        redaction.add_home_path(home.home_dir().to_string_lossy().into_owned());
    }
    if !authorization.token.is_empty() {
        redaction.add_secret(authorization.token.as_bytes());
    }
    let identity = DiagnosticIdentity {
        report_id: report_id.clone(),
        operation_id: token.0.clone(),
        public_customer_id: context
            .as_ref()
            .and_then(|value| value.public_customer_id.clone()),
        order_id: context.as_ref().and_then(|value| value.order_id.clone()),
        device_hash: context
            .as_ref()
            .and_then(|value| value.device_hash.clone())
            .or_else(|| authorization.device_hash.clone()),
        installation_id: context.as_ref().map(|value| value.installation_id.clone()),
        build_id: safe_identifier(&app.package_info().version.to_string(), "unknown-build"),
        os: safe_identifier(std::env::consts::OS, "unknown-os"),
        architecture: safe_identifier(std::env::consts::ARCH, "unknown-arch"),
    };
    let bundle = BundleBuilder {
        identity,
        outcome: "failed".to_string(),
        failure: Some(structured.clone()),
        registry,
        redaction,
        producer_wait: PRODUCER_WAIT,
    }
    .finalize(&bundles_root)
    .ok()?;

    let support_summary = format!(
        "{} | {} | {} | {} | {}/{}",
        bundle.report_id,
        structured.stage,
        structured.code,
        snapshot.kind.as_str(),
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    let pending = LatestDiagnosticReport {
        schema_version: LATEST_SCHEMA_VERSION,
        report_id: bundle.report_id.clone(),
        operation_id: bundle.operation_id.clone(),
        local_bundle_path: bundle.path.to_string_lossy().into_owned(),
        bundle_sha256: bundle.sha256.clone(),
        upload_status: "pending".to_string(),
        upload_attempts: 0,
        server_receipt_id: None,
        support_summary: support_summary.clone(),
        updated_at_unix: now_unix(),
    };
    let latest_path = diagnostic_root.join("latest.json");
    let _ = persist_latest_at(&pending, &latest_path);
    let operation_state = OperationDiagnosticState {
        report_id: bundle.report_id.clone(),
        local_bundle_path: bundle.path.to_string_lossy().into_owned(),
        upload_status: "pending".to_string(),
        support_summary,
    };
    let _ = operations.set_diagnostic_state(token, operation_state.clone());

    let endpoint_for_upload = authorization.endpoint;
    let token_for_upload = authorization.token;
    let support_summary_for_upload = operation_state.support_summary.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut transport = HttpBundleTransport::new(endpoint_for_upload, token_for_upload);
        let state = upload_with_retry(&bundle, &state_root, UPLOAD_ATTEMPTS, &mut transport);
        let latest = latest_from_upload(&bundle, &support_summary_for_upload, state.as_ref().ok());
        let _ = persist_latest_at(&latest, &latest_path);
    });
    Some(operation_state)
}

fn latest_from_upload(
    bundle: &FinalizedBundle,
    support_summary: &str,
    state: Option<&UploadState>,
) -> LatestDiagnosticReport {
    let (status, attempts, receipt) = match state {
        Some(state) => (
            match state.status {
                UploadStatus::Pending => "pending",
                UploadStatus::Uploaded => "uploaded",
                UploadStatus::FailedRetained => "failed-retained",
            },
            state.attempts,
            state
                .receipt
                .as_ref()
                .map(|value| value.server_receipt_id.clone()),
        ),
        None => ("failed-retained", 0, None),
    };
    LatestDiagnosticReport {
        schema_version: LATEST_SCHEMA_VERSION,
        report_id: bundle.report_id.clone(),
        operation_id: bundle.operation_id.clone(),
        local_bundle_path: bundle.path.to_string_lossy().into_owned(),
        bundle_sha256: bundle.sha256.clone(),
        upload_status: status.to_string(),
        upload_attempts: attempts,
        server_receipt_id: receipt,
        support_summary: support_summary.to_string(),
        updated_at_unix: now_unix(),
    }
}

struct DiagnosticAuthorization {
    endpoint: Option<Url>,
    token: Zeroizing<String>,
    device_hash: Option<String>,
}

fn diagnostic_authorization(
    context: Option<&DiagnosticBusinessContext>,
) -> DiagnosticAuthorization {
    if let Some(context) = context {
        if let Some(token) = load_management_token(context) {
            return DiagnosticAuthorization {
                endpoint: runtime_diagnostic_endpoint(context),
                token,
                device_hash: context.device_hash.clone(),
            };
        }
    }
    match crate::delivery_runtime::bootstrap_diagnostic_authorization() {
        Ok(Some(authorization)) => DiagnosticAuthorization {
            endpoint: runtime_diagnostic_endpoint_url(authorization.diagnostic_endpoint),
            token: authorization.token,
            device_hash: authorization.device_hash,
        },
        Ok(None) => DiagnosticAuthorization {
            endpoint: None,
            token: Zeroizing::new(String::new()),
            device_hash: None,
        },
        Err(error) => {
            log::warn!(
                "V4 bootstrap diagnostic authorization unavailable code={} stage={}",
                error.code,
                error.stage
            );
            DiagnosticAuthorization {
                endpoint: None,
                token: Zeroizing::new(String::new()),
                device_hash: None,
            }
        }
    }
}

struct HttpBundleTransport {
    client: Option<Client>,
    endpoint: Option<Url>,
    authorization_secret: Zeroizing<String>,
}

impl HttpBundleTransport {
    fn new(endpoint: Option<Url>, authorization_secret: Zeroizing<String>) -> Self {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .redirect(Policy::none())
            .build()
            .ok();
        Self {
            client,
            endpoint,
            authorization_secret,
        }
    }
}

fn runtime_diagnostic_endpoint(context: &DiagnosticBusinessContext) -> Option<Url> {
    let endpoint = Url::parse(&context.diagnostic_endpoint).ok()?;
    runtime_diagnostic_endpoint_url(endpoint)
}

fn runtime_diagnostic_endpoint_url(endpoint: Url) -> Option<Url> {
    let smoke = crate::app::paths::packaged_smoke_run_id().is_some();
    let explicit = std::env::var("CAM_DIAGNOSTIC_TEST_ENDPOINT").ok();
    select_runtime_diagnostic_endpoint_url(endpoint, smoke, explicit.as_deref())
}

#[cfg(test)]
fn select_runtime_diagnostic_endpoint(
    context: &DiagnosticBusinessContext,
    smoke: bool,
    explicit_test_endpoint: Option<&str>,
) -> Option<Url> {
    let endpoint = Url::parse(&context.diagnostic_endpoint)
        .ok()
        .filter(valid_endpoint)?;
    select_runtime_diagnostic_endpoint_url(endpoint, smoke, explicit_test_endpoint)
}

fn select_runtime_diagnostic_endpoint_url(
    endpoint: Url,
    smoke: bool,
    explicit_test_endpoint: Option<&str>,
) -> Option<Url> {
    if !valid_endpoint(&endpoint) {
        return None;
    }
    if !smoke {
        return Some(endpoint);
    }
    if endpoint
        .host_str()
        .is_some_and(|host| matches!(host, "127.0.0.1" | "localhost" | "::1"))
    {
        return Some(endpoint);
    }
    let explicitly_allowed = explicit_test_endpoint.is_some_and(|value| value == endpoint.as_str());
    explicitly_allowed.then_some(endpoint)
}

#[derive(Deserialize)]
struct PortalUploadResponse {
    ok: bool,
    data: Option<UploadReceipt>,
}

impl BundleTransport for HttpBundleTransport {
    fn upload(
        &mut self,
        bundle: &FinalizedBundle,
        idempotency_key: &str,
    ) -> Result<UploadReceipt, String> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| "network-client".to_string())?;
        let endpoint = self
            .endpoint
            .clone()
            .ok_or_else(|| "unauthorized-context".to_string())?;
        if self.authorization_secret.is_empty() {
            return Err("unauthorized-token".to_string());
        }
        let file = File::open(&bundle.path).map_err(|_| "bundle-open".to_string())?;
        let response = client
            .post(endpoint)
            .bearer_auth(self.authorization_secret.as_str())
            .header("content-type", "application/zip")
            .header("x-diagnostic-report-id", &bundle.report_id)
            .header("x-bundle-sha256", &bundle.sha256)
            .header("x-idempotency-key", idempotency_key)
            .body(Body::sized(file, bundle.size_in_bytes))
            .send()
            .map_err(|error| {
                if error.is_timeout() {
                    "upload-timeout".to_string()
                } else {
                    "network-unavailable".to_string()
                }
            })?;
        let status = response.status();
        if !status.is_success() {
            return Err(if matches!(status.as_u16(), 401 | 403) {
                "upload-unauthorized".to_string()
            } else if status.as_u16() == 413 {
                "upload-size-limit".to_string()
            } else {
                format!("http-{}", status.as_u16())
            });
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RECEIPT_BYTES)
        {
            return Err("receipt-size".to_string());
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_RECEIPT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "receipt-read".to_string())?;
        if bytes.len() as u64 > MAX_RECEIPT_BYTES {
            return Err("receipt-size".to_string());
        }
        let response: PortalUploadResponse =
            serde_json::from_slice(&bytes).map_err(|_| "receipt-invalid".to_string())?;
        if !response.ok {
            return Err("receipt-rejected".to_string());
        }
        response.data.ok_or_else(|| "receipt-missing".to_string())
    }
}

fn register(
    registry: &mut ArtifactRegistry,
    producer: &str,
    logical_name: &str,
    source_path: PathBuf,
    artifact_type: ArtifactType,
    redaction_policy: RedactionPolicy,
    required: bool,
) -> Option<()> {
    registry
        .register(ArtifactDeclaration {
            producer: producer.to_string(),
            logical_name: logical_name.to_string(),
            source_path,
            artifact_type,
            redaction_policy,
            required,
        })
        .ok()
}

fn validate_context(context: &DiagnosticBusinessContext) -> Result<(), String> {
    if context.schema_version != CONTEXT_SCHEMA_VERSION
        || context.installation_id.is_empty()
        || context.credential_service.is_empty()
        || context.credential_account.is_empty()
        || context.device_hash.as_deref().is_some_and(|value| {
            value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return Err("diagnostic-context-invalid".to_string());
    }
    let endpoint = Url::parse(&context.diagnostic_endpoint)
        .map_err(|_| "diagnostic-endpoint-invalid".to_string())?;
    if !valid_endpoint(&endpoint) {
        return Err("diagnostic-endpoint-invalid".to_string());
    }
    Ok(())
}

fn valid_endpoint(endpoint: &Url) -> bool {
    endpoint.scheme() == "https"
        || (endpoint.scheme() == "http"
            && endpoint
                .host_str()
                .is_some_and(|host| matches!(host, "127.0.0.1" | "localhost" | "::1")))
}

fn load_management_token(context: &DiagnosticBusinessContext) -> Option<Zeroizing<String>> {
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        let vault = NativeCredentialVault;
        let handle = CredentialHandle {
            service: context.credential_service.clone(),
            account: context.credential_account.clone(),
        };
        let secret = Zeroizing::new(vault.get(&handle).ok()??);
        let value: serde_json::Value = serde_json::from_slice(secret.as_slice()).ok()?;
        let token = value.get("management_token")?.as_str()?.to_string();
        if token.len() < 24 {
            return None;
        }
        Some(Zeroizing::new(token))
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = context;
        None
    }
}

fn system_probe_bytes<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    snapshot: &OperationSnapshot,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec_pretty(&serde_json::json!({
        "schema_version": 1,
        "app_version": app.package_info().version.to_string(),
        "os": std::env::consts::OS,
        "architecture": std::env::consts::ARCH,
        "process_id": std::process::id(),
        "operation_id": snapshot.id,
        "operation_kind": snapshot.kind.as_str(),
        "phase": snapshot.phase.as_str(),
        "point_of_no_return": snapshot.ui.state.point_of_no_return,
        "generated_at_unix": now_unix(),
    }))
}

fn structured_event_bytes(
    snapshot: &OperationSnapshot,
    failure: &StructuredFailure,
) -> Result<Vec<u8>, serde_json::Error> {
    let event = serde_json::json!({
        "schema_version": 1,
        "event": "operation-failed",
        "operation_id": snapshot.id,
        "kind": snapshot.kind.as_str(),
        "phase": snapshot.phase.as_str(),
        "step": snapshot.ui.state.step_key,
        "component": snapshot.ui.state.component,
        "system_action": snapshot.ui.state.system_action,
        "failure": failure,
        "created_at_unix": now_unix(),
    });
    let mut bytes = serde_json::to_vec(&event)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn latest_file(root: &Path) -> Option<PathBuf> {
    let mut candidates = fs::read_dir(root)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file()))
        .filter_map(|path| {
            let modified = fs::metadata(&path).ok()?.modified().ok()?;
            Some((modified, path))
        })
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.pop().map(|(_, path)| path)
}

fn latest_file_recursive(root: &Path, file_name: &str, limit: usize) -> Option<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut seen = 0_usize;
    let mut candidates = Vec::new();
    while let Some(dir) = pending.pop() {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            seen += 1;
            if seen > limit {
                break;
            }
            let path = entry.path();
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                continue;
            };
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file()
                && path.file_name().and_then(|value| value.to_str()) == Some(file_name)
            {
                let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                candidates.push((modified, path));
            }
        }
        if seen > limit {
            break;
        }
    }
    candidates.sort();
    candidates.pop().map(|(_, path)| path)
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing parent"))?;
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    crate::app::atomic_file::write_atomic(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn persist_latest(report: &LatestDiagnosticReport) -> std::io::Result<()> {
    let path = latest_path()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "data dir"))?;
    persist_latest_at(report, &path)
}

fn persist_latest_at(report: &LatestDiagnosticReport, path: &Path) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(report)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    write_private_atomic(path, &bytes)
}

fn context_path() -> Option<PathBuf> {
    crate::app::paths::data_dir().map(|root| root.join("delivery-context.json"))
}

fn latest_path() -> Option<PathBuf> {
    crate::app::paths::data_dir().map(|root| root.join("diagnostics").join("latest.json"))
}

fn safe_identifier(value: &str, fallback: &str) -> String {
    if !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        value.to_string()
    } else {
        fallback.to_string()
    }
}

fn root_cause_for(code: &str) -> &'static str {
    match code {
        "network" | "timeout" => "required endpoint was unavailable within the bounded attempt",
        "disk_space" => "the destination did not have enough free space",
        "disk_write" => "the operating system rejected a required local write",
        "permission" => "the operating system denied the requested action",
        "signature" => "the downloaded artifact did not pass publisher verification",
        "artifact" => "the downloaded artifact did not match its release contract",
        "incompatible" => "the selected platform installation path is not available",
        "install" => "the operating-system installation service did not complete",
        _ => "the operation ended without a verified successful outcome",
    }
}

fn next_action_for(code: &str) -> &'static str {
    match code {
        "network" | "timeout" => "keep the bundle and retry after connectivity is restored",
        "disk_space" => "free disk space and retry",
        "permission" => "close blocking applications and retry with the current user",
        "signature" | "artifact" => "do not install the artifact; refresh release metadata",
        "incompatible" => "use the alternate verified installation path",
        _ => "send the report identifier to support before retrying destructive work",
    }
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
    fn endpoint_requires_https_except_loopback() {
        assert!(valid_endpoint(
            &Url::parse("https://portal.example/v4").unwrap()
        ));
        assert!(valid_endpoint(
            &Url::parse("http://127.0.0.1:8123/v4").unwrap()
        ));
        assert!(!valid_endpoint(
            &Url::parse("http://portal.example/v4").unwrap()
        ));
        assert!(!valid_endpoint(&Url::parse("file:///tmp/report").unwrap()));
    }

    #[test]
    fn command_failure_maps_to_safe_structured_fields() {
        let failure = FailureDescriptor::from_command(
            &CommandError {
                code: "network".to_string(),
                message: "secret raw detail".to_string(),
            },
            "downloading",
        );
        let structured = failure.structured();
        assert_eq!(structured.code, "network");
        assert_eq!(structured.stage, "downloading");
        assert!(structured.retryable);
        assert!(!serde_json::to_string(&structured)
            .unwrap()
            .contains("secret raw detail"));
    }

    #[test]
    fn packaged_smoke_never_uses_production_diagnostics_without_exact_opt_in() {
        let context = DiagnosticBusinessContext {
            schema_version: 1,
            public_customer_id: None,
            order_id: None,
            device_hash: None,
            installation_id: "installation".to_string(),
            credential_service: "service".to_string(),
            credential_account: "account".to_string(),
            diagnostic_endpoint: "https://portal.example/api/installer/v4/diagnostics/bundles"
                .to_string(),
        };
        assert!(select_runtime_diagnostic_endpoint(&context, true, None).is_none());
        assert!(select_runtime_diagnostic_endpoint(
            &context,
            true,
            Some("https://other.example/api/installer/v4/diagnostics/bundles")
        )
        .is_none());
        assert!(select_runtime_diagnostic_endpoint(
            &context,
            true,
            Some("https://portal.example/api/installer/v4/diagnostics/bundles")
        )
        .is_some());
        assert!(select_runtime_diagnostic_endpoint(&context, false, None).is_some());
    }

    #[test]
    fn packaged_smoke_allows_loopback_diagnostics_without_external_side_effects() {
        let context = DiagnosticBusinessContext {
            schema_version: 1,
            public_customer_id: None,
            order_id: None,
            device_hash: None,
            installation_id: "installation".to_string(),
            credential_service: "service".to_string(),
            credential_account: "account".to_string(),
            diagnostic_endpoint: "http://127.0.0.1:48081/api/installer/v4/diagnostics/bundles"
                .to_string(),
        };
        assert!(select_runtime_diagnostic_endpoint(&context, true, None).is_some());
    }
}
