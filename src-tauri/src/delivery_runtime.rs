//! Production bridge between the platform installer and the V4 delivery kernel.
//!
//! The platform engines deliberately know nothing about customer credentials.
//! This module runs only after their health gate succeeds.  It consumes the
//! externally signed bootstrap sidecar, claims on the bound device, commits the
//! Codex configuration transaction, initializes locale independently, performs
//! real HTTP/SSE/WebSocket verification, and finally retires the one-time
//! sidecar.  Secret-bearing values never cross the Tauri command boundary.

use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use codex_delivery_engine::{
    native_device_hash, run_delivery_pipeline, AppProof, CliPolicy, CliProof, ConfigProof,
    ConflictPolicy, CredentialVault, DeliveryPipelineInput, DeliveryPipelineState, ModelsProof,
    NativeCredentialVault, NativeLocaleInitializer, ProbeError, ProvisioningPaths, ResponseProof,
    ScanLimits, StreamProof, UsageProof, VerificationPolicy, VerificationProbe,
    VerificationRequest,
};
use reqwest::blocking::{Client, Response};
use reqwest::redirect::Policy as RedirectPolicy;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tauri::Manager as _;
use toml_edit::DocumentMut;
use tungstenite::client::IntoClientRequest as _;
use tungstenite::client_tls_with_config;
use tungstenite::http::HeaderValue;
use tungstenite::Message;
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::app::settings_store::{AppSettings, ProxyMode};
use crate::app::url_guard::validate_custom_proxy;
use crate::delivery::{load_bootstrap_sidecar, HttpClaimTransport};
use crate::v4_diagnostics::{persist_business_context, DiagnosticBusinessContext};

const RELEASE_POLICY_JSON: &str = include_str!("../resources/v4-release-policy.json");
const MODEL_CATALOG: &[u8] = include_bytes!("../../assets/models-full-responses.json");
const BOOTSTRAP_FILE_NAME: &str = "bootstrap.v4.json";
const MAX_SIDECAR_SEARCH_ENTRIES: usize = 2_000;
const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const NETWORK_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const WEBSOCKET_EVENT_LIMIT: usize = 2_000;

pub fn embedded_release_build_id() -> Result<String, DeliveryRuntimeError> {
    release_policy(RELEASE_POLICY_JSON, false).map(|policy| policy.build_id)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleasePolicy {
    schema_version: u32,
    state: String,
    public_key_b64: String,
    issuer: String,
    audience: String,
    build_id: String,
    claim_endpoint_id: String,
    claim_endpoint_url: String,
    diagnostic_endpoint: String,
    allowed_api_origins: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DeliveryRuntimeError {
    pub code: String,
    pub stage: String,
    pub retryable: bool,
}

impl DeliveryRuntimeError {
    fn new(code: &str, stage: &str, retryable: bool) -> Self {
        Self {
            code: safe_code(code, "delivery-failed"),
            stage: safe_code(stage, "delivery"),
            retryable,
        }
    }
}

impl std::fmt::Display for DeliveryRuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}:{}", self.stage, self.code)
    }
}

#[derive(Debug, Clone)]
pub enum DeliveryRunOutcome {
    ExistingConfiguration,
    Delivered,
}

#[derive(Debug)]
struct VerifiedSidecarCandidate {
    path: PathBuf,
    issued_at_unix: i64,
    signature_b64: String,
}

pub struct BootstrapDiagnosticAuthorization {
    pub token: Zeroizing<String>,
    pub diagnostic_endpoint: Url,
    pub device_hash: Option<String>,
}

/// Resolve a narrowly scoped pre-claim diagnostic credential directly from a
/// verified sidecar.  Nothing is persisted or exposed to the renderer, and a
/// tampered/expired sidecar fails closed.
pub fn bootstrap_diagnostic_authorization(
) -> Result<Option<BootstrapDiagnosticAuthorization>, DeliveryRuntimeError> {
    let policy = release_policy(RELEASE_POLICY_JSON, false)?;
    let verification_policy = policy.verification_policy(None)?;
    let Some(sidecar_path) = locate_signed_sidecar(&verification_policy, now_unix())? else {
        return Ok(None);
    };
    let loaded = load_bootstrap_sidecar(&sidecar_path, &verification_policy, now_unix())
        .map_err(|error| DeliveryRuntimeError::new(&error.code, "bootstrap", false))?;
    bootstrap_diagnostic_authorization_from_loaded(&policy, &loaded, false)
}

fn bootstrap_diagnostic_authorization_from_loaded(
    policy: &ReleasePolicy,
    loaded: &crate::delivery::LoadedBootstrapSidecar,
    allow_loopback: bool,
) -> Result<Option<BootstrapDiagnosticAuthorization>, DeliveryRuntimeError> {
    let token = loaded.bootstrap_token();
    if !token.starts_with("boot_") || token.len() < 24 {
        return Err(DeliveryRuntimeError::new(
            "bootstrap-token-invalid",
            "bootstrap",
            false,
        ));
    }
    Ok(Some(BootstrapDiagnosticAuthorization {
        token,
        diagnostic_endpoint: policy.diagnostic_endpoint(allow_loopback)?,
        device_hash: native_device_hash().ok(),
    }))
}

/// Complete the commercial V4 delivery after the OS-level app transaction has
/// passed its own health gate.  A missing sidecar is allowed only when a prior
/// V4 managed configuration already exists (normal manager/app update).
pub fn run_after_platform_install<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    operation_id: &str,
    app_health_verified: bool,
) -> Result<DeliveryRunOutcome, DeliveryRuntimeError> {
    if !app_health_verified {
        return Err(DeliveryRuntimeError::new(
            "app-health-required",
            "platform-health",
            true,
        ));
    }
    let codex_home = crate::app::paths::codex_home_dir().ok_or_else(|| {
        DeliveryRuntimeError::new("codex-home-unavailable", "delivery-prepare", false)
    })?;
    let existing_v4 = has_v4_managed_configuration(&codex_home);
    let policy = release_policy(RELEASE_POLICY_JSON, false)?;
    let verification_policy = policy.verification_policy(None)?;
    let sidecar_path = match locate_signed_sidecar(&verification_policy, now_unix()) {
        Ok(path) => path,
        Err(error) if existing_v4 => {
            log::warn!(
                "ignored invalid V4 bootstrap because managed configuration already exists code={}",
                error.code
            );
            return Ok(DeliveryRunOutcome::ExistingConfiguration);
        }
        Err(error) => return Err(error),
    };
    let Some(sidecar_path) = sidecar_path else {
        return if existing_v4 {
            Ok(DeliveryRunOutcome::ExistingConfiguration)
        } else {
            Err(DeliveryRuntimeError::new(
                "bootstrap-sidecar-missing",
                "bootstrap",
                false,
            ))
        };
    };
    run_with_policy_and_sidecar(
        app,
        operation_id,
        codex_home,
        app_health_verified,
        policy,
        sidecar_path,
    )
}

fn run_with_policy_and_sidecar<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    operation_id: &str,
    codex_home: PathBuf,
    app_health_verified: bool,
    policy: ReleasePolicy,
    sidecar_path: PathBuf,
) -> Result<DeliveryRunOutcome, DeliveryRuntimeError> {
    let operation_id = Uuid::parse_str(operation_id).map_err(|_| {
        DeliveryRuntimeError::new("operation-id-invalid", "delivery-prepare", false)
    })?;
    let now = now_unix();
    let device_hash = native_device_hash()
        .map_err(|_| DeliveryRuntimeError::new("device-id-unavailable", "device-binding", false))?;
    let verification_policy = policy.verification_policy(Some(device_hash.clone()))?;
    let loaded = load_bootstrap_sidecar(&sidecar_path, &verification_policy, now)
        .map_err(|error| DeliveryRuntimeError::new(&error.code, "bootstrap", false))?;
    let claim_endpoint = policy.claim_endpoint(false)?;
    let mut claim_transport = HttpClaimTransport::new(claim_endpoint).map_err(|error| {
        DeliveryRuntimeError::new(&error.server_code, "claim-transport", error.retryable)
    })?;
    let data_root = crate::app::paths::data_dir().ok_or_else(|| {
        DeliveryRuntimeError::new("manager-data-unavailable", "delivery-prepare", false)
    })?;
    let operation_root = data_root
        .join("delivery")
        .join("operations")
        .join(operation_id.to_string());
    fs::create_dir_all(&operation_root).map_err(|_| {
        DeliveryRuntimeError::new("operation-directory-create", "delivery-prepare", false)
    })?;
    let catalog_source = materialize_catalog(&data_root)?;
    let worker_path = resolve_locale_worker(app);
    let mut locale = NativeLocaleInitializer::new(worker_path, operation_root.join("locale"));
    let mut vault = NativeCredentialVault;
    NativeCredentialVault::available().map_err(|_| {
        DeliveryRuntimeError::new("native-vault-unavailable", "delivery-prepare", false)
    })?;
    let mut probe = ProductionVerificationProbe::new(codex_home.clone(), app_health_verified)?;
    let platform = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        return Err(DeliveryRuntimeError::new(
            "platform-unsupported",
            "delivery-prepare",
            false,
        ));
    };
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => other,
    };
    let system_locale = sys_locale::get_locale().unwrap_or_else(|| "en-US".to_string());
    let marker = format!("provider-v4-verify-{}", Uuid::new_v4().simple());
    let paths = ProvisioningPaths {
        codex_home: codex_home.clone(),
        catalog_source,
    };
    let result = run_delivery_pipeline(
        DeliveryPipelineInput {
            operation_id,
            envelope: loaded.envelope(),
            verification_policy,
            device_hash: &device_hash,
            platform,
            architecture,
            system_locale: &system_locale,
            app_health_verified,
            now_unix: now,
            provisioning_paths: paths,
            project_roots: project_roots(),
            sessions_root: codex_home.join("sessions"),
            migration_backup_root: operation_root.join("migration-backups"),
            scan_limits: ScanLimits::default(),
            conflict_policy: ConflictPolicy::AdoptRecognizedV2,
            cli_policy: CliPolicy::NotApplicable,
            require_usage_lifecycle: false,
            verification_marker: marker,
        },
        &mut claim_transport,
        &mut vault,
        &mut locale,
        &mut probe,
    );
    let report = result.map_err(|failure| {
        DeliveryRuntimeError::new(&failure.code, &failure.stage, failure.retryable)
    })?;
    let context = DiagnosticBusinessContext {
        schema_version: 1,
        public_customer_id: None,
        order_id: None,
        device_hash: Some(device_hash),
        installation_id: report.installation_id.clone(),
        credential_service: report.config.credential_handle.service.clone(),
        credential_account: report.config.credential_handle.account.clone(),
        diagnostic_endpoint: policy.diagnostic_endpoint(false)?.to_string(),
    };
    persist_business_context(&context)
        .map_err(|code| DeliveryRuntimeError::new(&code, "diagnostic-context", false))?;
    if report.state == DeliveryPipelineState::VerificationFailed {
        let code = report
            .verification
            .stages
            .iter()
            .find(|stage| stage.state == codex_delivery_engine::VerificationState::Failed)
            .map(|stage| stage.code.as_str())
            .unwrap_or("verification-failed");
        return Err(DeliveryRuntimeError::new(code, "verification", true));
    }
    loaded
        .retire()
        .map_err(|error| DeliveryRuntimeError::new(&error.code, "bootstrap-retire", true))?;
    Ok(DeliveryRunOutcome::Delivered)
}

impl ReleasePolicy {
    fn verification_policy(
        &self,
        expected_device_hash: Option<String>,
    ) -> Result<VerificationPolicy, DeliveryRuntimeError> {
        let public_key: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&self.public_key_b64)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| {
                DeliveryRuntimeError::new("release-public-key-invalid", "release-policy", false)
            })?;
        Ok(VerificationPolicy {
            public_key,
            expected_issuer: self.issuer.clone(),
            expected_audience: self.audience.clone(),
            expected_build_id: self.build_id.clone(),
            expected_claim_endpoint_id: self.claim_endpoint_id.clone(),
            expected_device_hash,
            allowed_api_origins: self.allowed_api_origins.clone(),
            allow_loopback_http: false,
        })
    }

    fn claim_endpoint(&self, allow_loopback: bool) -> Result<Url, DeliveryRuntimeError> {
        checked_endpoint(
            &self.claim_endpoint_url,
            "/api/bootstrap/v4/claim",
            allow_loopback,
            "claim-endpoint-invalid",
        )
    }

    fn diagnostic_endpoint(&self, allow_loopback: bool) -> Result<Url, DeliveryRuntimeError> {
        checked_endpoint(
            &self.diagnostic_endpoint,
            "/api/installer/v4/diagnostics/bundles",
            allow_loopback,
            "diagnostic-endpoint-invalid",
        )
    }
}

fn release_policy(raw: &str, allow_test: bool) -> Result<ReleasePolicy, DeliveryRuntimeError> {
    let policy: ReleasePolicy = serde_json::from_str(raw).map_err(|_| {
        DeliveryRuntimeError::new("release-policy-invalid", "release-policy", false)
    })?;
    if policy.schema_version != 1
        || (policy.state != "release" && !(allow_test && policy.state == "test"))
        || !safe_identifier(&policy.issuer)
        || !safe_identifier(&policy.audience)
        || !safe_identifier(&policy.build_id)
        || !safe_identifier(&policy.claim_endpoint_id)
        || policy.allowed_api_origins.is_empty()
    {
        return Err(DeliveryRuntimeError::new(
            if policy.state == "unpublished" {
                "v4-release-policy-unpublished"
            } else {
                "release-policy-invalid"
            },
            "release-policy",
            false,
        ));
    }
    policy.verification_policy(None)?;
    policy.claim_endpoint(allow_test)?;
    policy.diagnostic_endpoint(allow_test)?;
    for origin in &policy.allowed_api_origins {
        checked_api_origin(origin, allow_test)?;
    }
    Ok(policy)
}

fn checked_endpoint(
    value: &str,
    required_path: &str,
    allow_loopback: bool,
    code: &str,
) -> Result<Url, DeliveryRuntimeError> {
    let url =
        Url::parse(value).map_err(|_| DeliveryRuntimeError::new(code, "release-policy", false))?;
    let loopback = url
        .host_str()
        .is_some_and(|host| matches!(host, "127.0.0.1" | "localhost" | "::1"));
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != required_path
        || (url.scheme() != "https" && !(allow_loopback && loopback && url.scheme() == "http"))
    {
        return Err(DeliveryRuntimeError::new(code, "release-policy", false));
    }
    Ok(url)
}

fn checked_api_origin(value: &str, allow_loopback: bool) -> Result<Url, DeliveryRuntimeError> {
    let url = Url::parse(value)
        .map_err(|_| DeliveryRuntimeError::new("api-origin-invalid", "release-policy", false))?;
    let loopback = url
        .host_str()
        .is_some_and(|host| matches!(host, "127.0.0.1" | "localhost" | "::1"));
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (url.scheme() != "https" && !(allow_loopback && loopback && url.scheme() == "http"))
    {
        return Err(DeliveryRuntimeError::new(
            "api-origin-invalid",
            "release-policy",
            false,
        ));
    }
    Ok(url)
}

fn locate_signed_sidecar(
    policy: &VerificationPolicy,
    now: i64,
) -> Result<Option<PathBuf>, DeliveryRuntimeError> {
    for tier in sidecar_candidate_tiers() {
        let mut found_file = false;
        let mut verified = Vec::new();
        let mut rejected_code = None;
        for path in tier {
            if !path.is_file() {
                continue;
            }
            found_file = true;
            match load_bootstrap_sidecar(&path, policy, now) {
                Ok(loaded) => verified.push(VerifiedSidecarCandidate {
                    path,
                    issued_at_unix: loaded.envelope().payload.issued_at_unix,
                    signature_b64: loaded.envelope().signature_b64.clone(),
                }),
                Err(error) => {
                    log::warn!("rejected V4 bootstrap candidate code={}", error.code);
                    rejected_code = Some(error.code);
                }
            }
        }
        if let Some(path) = select_latest_verified_sidecar(verified)? {
            return Ok(Some(path));
        }
        if found_file {
            return Err(DeliveryRuntimeError::new(
                rejected_code
                    .as_deref()
                    .unwrap_or("bootstrap-sidecar-no-valid-candidate"),
                "bootstrap",
                false,
            ));
        }
    }
    Ok(None)
}

fn select_latest_verified_sidecar(
    mut candidates: Vec<VerifiedSidecarCandidate>,
) -> Result<Option<PathBuf>, DeliveryRuntimeError> {
    let Some(latest_issued_at) = candidates.iter().map(|item| item.issued_at_unix).max() else {
        return Ok(None);
    };
    candidates.retain(|item| item.issued_at_unix == latest_issued_at);
    let signatures = candidates
        .iter()
        .map(|item| item.signature_b64.as_str())
        .collect::<BTreeSet<_>>();
    if signatures.len() != 1 {
        return Err(DeliveryRuntimeError::new(
            "bootstrap-sidecar-ambiguous",
            "bootstrap",
            false,
        ));
    }
    candidates.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(candidates.into_iter().next().map(|item| item.path))
}

fn sidecar_candidate_tiers() -> Vec<Vec<PathBuf>> {
    let mut colocated = Vec::new();
    if let Ok(executable) = std::env::current_exe() {
        for parent in executable.ancestors().take(6).filter_map(Path::parent) {
            colocated.push(parent.join(BOOTSTRAP_FILE_NAME));
        }
    }
    if let Ok(current) = std::env::current_dir() {
        colocated.push(current.join(BOOTSTRAP_FILE_NAME));
    }
    let mut managed = Vec::new();
    if let Some(root) = crate::app::paths::data_dir() {
        managed.push(root.join("bootstrap").join(BOOTSTRAP_FILE_NAME));
    }
    let mut downloads = Vec::new();
    if let Some(users) = directories::UserDirs::new() {
        if let Some(root) = users.download_dir() {
            downloads.extend(find_named_files_bounded(
                root,
                BOOTSTRAP_FILE_NAME,
                3,
                MAX_SIDECAR_SEARCH_ENTRIES,
            ));
        }
    }
    let mut seen = BTreeSet::new();
    [colocated, managed, downloads]
        .into_iter()
        .map(|tier| {
            tier.into_iter()
                .filter(|path| seen.insert(path.clone()))
                .collect::<Vec<_>>()
        })
        .filter(|tier| !tier.is_empty())
        .collect()
}

fn find_named_files_bounded(
    root: &Path,
    file_name: &str,
    max_depth: usize,
    max_entries: usize,
) -> Vec<PathBuf> {
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    let mut seen = 0_usize;
    let mut matches = Vec::new();
    while let Some((directory, depth)) = pending.pop() {
        let Ok(entries) = fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            seen += 1;
            if seen > max_entries {
                return matches;
            }
            let path = entry.path();
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                continue;
            };
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_file()
                && path.file_name().and_then(|value| value.to_str()) == Some(file_name)
            {
                matches.push(path);
            } else if metadata.is_dir() && depth < max_depth {
                pending.push((path, depth + 1));
            }
        }
    }
    matches.sort_by_key(|path| {
        fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH)
    });
    matches.reverse();
    matches
}

fn materialize_catalog(data_root: &Path) -> Result<PathBuf, DeliveryRuntimeError> {
    let digest = hex_sha256(MODEL_CATALOG);
    let root = data_root.join("delivery").join("assets");
    let path = root.join(format!("models-full-responses-{digest}.json"));
    if path.is_file() && fs::read(&path).is_ok_and(|bytes| bytes == MODEL_CATALOG) {
        return Ok(path);
    }
    fs::create_dir_all(&root).map_err(|_| {
        DeliveryRuntimeError::new("catalog-directory-create", "delivery-prepare", false)
    })?;
    crate::app::atomic_file::write_atomic(&path, MODEL_CATALOG)
        .map_err(|_| DeliveryRuntimeError::new("catalog-materialize", "delivery-prepare", false))?;
    if !fs::read(&path).is_ok_and(|bytes| bytes == MODEL_CATALOG) {
        return Err(DeliveryRuntimeError::new(
            "catalog-readback",
            "delivery-prepare",
            false,
        ));
    }
    Ok(path)
}

fn resolve_locale_worker<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> Option<PathBuf> {
    ["resources/i18n-relay-worker.ps1", "i18n-relay-worker.ps1"]
        .into_iter()
        .filter_map(|relative| {
            app.path()
                .resolve(relative, tauri::path::BaseDirectory::Resource)
                .ok()
        })
        .find(|path| path.is_file())
}

fn project_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(users) = directories::UserDirs::new() {
        for candidate in [
            users.desktop_dir(),
            users.document_dir(),
            users.download_dir(),
        ]
        .into_iter()
        .flatten()
        {
            roots.push(candidate.to_path_buf());
        }
    }
    if let Ok(current) = std::env::current_dir() {
        roots.push(current);
    }
    let mut seen = BTreeSet::new();
    roots
        .into_iter()
        .filter(|path| path.is_dir() && seen.insert(path.clone()))
        .collect()
}

fn has_v4_managed_configuration(codex_home: &Path) -> bool {
    fs::read_to_string(codex_home.join("config.toml")).is_ok_and(|value| {
        value.contains(codex_delivery_engine::config::V4_MANAGED_BEGIN)
            && value.contains(codex_delivery_engine::config::V4_MANAGED_END)
    })
}

#[derive(Debug, Clone)]
enum VerificationProxy {
    System,
    Direct,
    Custom(Url),
}

impl VerificationProxy {
    fn from_settings() -> Result<Self, DeliveryRuntimeError> {
        let settings = AppSettings::load();
        match settings.proxy_mode {
            ProxyMode::System => Ok(Self::System),
            ProxyMode::Direct => Ok(Self::Direct),
            ProxyMode::Custom => {
                let normalized =
                    validate_custom_proxy(&settings.custom_proxy_url).map_err(|_| {
                        DeliveryRuntimeError::new(
                            "verification-proxy-invalid",
                            "verification",
                            false,
                        )
                    })?;
                let url = Url::parse(&normalized).map_err(|_| {
                    DeliveryRuntimeError::new("verification-proxy-invalid", "verification", false)
                })?;
                Ok(Self::Custom(url))
            }
        }
    }

    fn build_http_client(&self) -> Result<Client, DeliveryRuntimeError> {
        let mut builder = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(NETWORK_TIMEOUT)
            .redirect(RedirectPolicy::none());
        match self {
            Self::System => {}
            Self::Direct => builder = builder.no_proxy(),
            Self::Custom(url) => {
                let proxy = reqwest::Proxy::all(url.as_str()).map_err(|_| {
                    DeliveryRuntimeError::new("verification-proxy-invalid", "verification", false)
                })?;
                builder = builder.proxy(proxy);
            }
        }
        builder.build().map_err(|_| {
            DeliveryRuntimeError::new("verification-client-build", "verification", false)
        })
    }
}

struct ProductionVerificationProbe {
    client: Client,
    proxy: VerificationProxy,
    codex_home: PathBuf,
    app_health_verified: bool,
    #[cfg(test)]
    api_key_override: Option<Zeroizing<String>>,
}

impl ProductionVerificationProbe {
    fn new(codex_home: PathBuf, app_health_verified: bool) -> Result<Self, DeliveryRuntimeError> {
        let proxy = VerificationProxy::from_settings()?;
        let client = proxy.build_http_client()?;
        Ok(Self {
            client,
            proxy,
            codex_home,
            app_health_verified,
            #[cfg(test)]
            api_key_override: None,
        })
    }

    #[cfg(test)]
    fn with_api_key_override(mut self, api_key: &str) -> Self {
        self.api_key_override = Some(Zeroizing::new(api_key.to_string()));
        self
    }

    #[cfg(test)]
    fn loopback_for_test(codex_home: PathBuf, api_key: &str) -> Result<Self, DeliveryRuntimeError> {
        let proxy = VerificationProxy::Direct;
        let client = proxy.build_http_client()?;
        Ok(Self {
            client,
            proxy,
            codex_home,
            app_health_verified: true,
            api_key_override: None,
        }
        .with_api_key_override(api_key))
    }

    fn api_key(&self, request: &VerificationRequest) -> Result<Zeroizing<String>, ProbeError> {
        #[cfg(test)]
        if let Some(value) = self.api_key_override.as_ref() {
            return Ok(Zeroizing::new(value.as_str().to_string()));
        }
        let vault = NativeCredentialVault;
        let secret = Zeroizing::new(
            vault
                .get(&request.credential)
                .map_err(|_| probe_error("verification-vault-read", false))?
                .ok_or_else(|| probe_error("verification-vault-missing", false))?,
        );
        let value: Value = serde_json::from_slice(secret.as_slice())
            .map_err(|_| probe_error("verification-vault-contract", false))?;
        let key = value
            .get("api_key")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| probe_error("verification-api-key-missing", false))?
            .to_string();
        Ok(Zeroizing::new(key))
    }

    fn endpoint(&self, base: &str, leaf: &str) -> Result<Url, ProbeError> {
        let mut value = base.trim_end_matches('/').to_string();
        value.push('/');
        let base = Url::parse(&value).map_err(|_| probe_error("verification-api-origin", false))?;
        base.join(leaf)
            .map_err(|_| probe_error("verification-api-origin", false))
    }

    fn post_response(
        &self,
        request: &VerificationRequest,
        stream: bool,
    ) -> Result<Response, ProbeError> {
        let mut key = self.api_key(request)?;
        let endpoint = self.endpoint(&request.expected_api_origin, "responses")?;
        let result = self
            .client
            .post(endpoint)
            .bearer_auth(key.as_str())
            .header(
                "accept",
                if stream {
                    "text/event-stream"
                } else {
                    "application/json"
                },
            )
            .json(&response_request_json(request, stream))
            .send()
            .map_err(map_reqwest_error);
        key.zeroize();
        let response = result?;
        if !response.status().is_success() {
            return Err(probe_error(
                &format!("verification-http-{}", response.status().as_u16()),
                response.status().is_server_error() || response.status().as_u16() == 429,
            ));
        }
        Ok(response)
    }
}

impl VerificationProbe for ProductionVerificationProbe {
    fn app(&mut self, _request: &VerificationRequest) -> Result<AppProof, ProbeError> {
        Ok(AppProof {
            process_alive: self.app_health_verified,
            surface_ready: self.app_health_verified,
        })
    }

    fn config(&mut self, request: &VerificationRequest) -> Result<ConfigProof, ProbeError> {
        let raw = fs::read_to_string(self.codex_home.join("config.toml"))
            .map_err(|_| probe_error("verification-config-read", false))?;
        let document = raw
            .parse::<DocumentMut>()
            .map_err(|_| probe_error("verification-config-parse", false))?;
        let string = |key: &str| {
            document
                .get(key)
                .and_then(|item| item.as_value())
                .and_then(|value| value.as_str())
                .map(str::to_string)
        };
        let vault = NativeCredentialVault;
        let credential_native = vault
            .get(&request.credential)
            .ok()
            .flatten()
            .is_some_and(|value| !value.is_empty());
        Ok(ConfigProof {
            api_origin: string("openai_base_url").unwrap_or_default(),
            model: string("model").unwrap_or_default(),
            review_model: string("review_model").unwrap_or_default(),
            credential_native,
            unknown_fields_preserved: raw.contains(codex_delivery_engine::config::V4_MANAGED_BEGIN),
        })
    }

    fn models(&mut self, request: &VerificationRequest) -> Result<ModelsProof, ProbeError> {
        let mut key = self.api_key(request)?;
        let endpoint = self.endpoint(&request.expected_api_origin, "models")?;
        let result = self
            .client
            .get(endpoint)
            .bearer_auth(key.as_str())
            .header("accept", "application/json")
            .send()
            .map_err(map_reqwest_error);
        key.zeroize();
        let response = result?;
        if !response.status().is_success() {
            return Err(probe_error(
                &format!("verification-models-http-{}", response.status().as_u16()),
                response.status().is_server_error() || response.status().as_u16() == 429,
            ));
        }
        let value = bounded_json(response)?;
        let model_ids = value
            .get("data")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|item| item.get("id").and_then(Value::as_str))
            .map(str::to_string)
            .collect();
        Ok(ModelsProof { model_ids })
    }

    fn response(&mut self, request: &VerificationRequest) -> Result<ResponseProof, ProbeError> {
        let value = bounded_json(self.post_response(request, false)?)?;
        Ok(ResponseProof {
            request_id: value
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            model: value
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            output_text: response_output_text(&value),
        })
    }

    fn sse(&mut self, request: &VerificationRequest) -> Result<StreamProof, ProbeError> {
        parse_sse(self.post_response(request, true)?)
    }

    fn websocket(&mut self, request: &VerificationRequest) -> Result<StreamProof, ProbeError> {
        let mut key = self.api_key(request)?;
        let result = websocket_probe(request, key.as_str(), &self.proxy);
        key.zeroize();
        result
    }

    fn cli(&mut self, _request: &VerificationRequest) -> Result<CliProof, ProbeError> {
        Err(probe_error("verification-cli-not-applicable", false))
    }

    fn usage(&mut self, _request: &VerificationRequest) -> Result<UsageProof, ProbeError> {
        Err(probe_error("verification-usage-test-only", false))
    }
}

fn response_request_json(request: &VerificationRequest, stream: bool) -> Value {
    serde_json::json!({
        "model": request.expected_model,
        "input": [{
            "role": "user",
            "content": [{
                "type": "input_text",
                "text": format!("Reply with exactly this marker and nothing else: {}", request.expected_marker)
            }]
        }],
        "stream": stream,
        "max_output_tokens": 128
    })
}

fn bounded_json(response: Response) -> Result<Value, ProbeError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES)
    {
        return Err(probe_error("verification-response-too-large", false));
    }
    let bytes = response.bytes().map_err(map_reqwest_error)?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(probe_error("verification-response-too-large", false));
    }
    serde_json::from_slice(&bytes).map_err(|_| probe_error("verification-response-json", false))
}

fn response_output_text(value: &Value) -> String {
    if let Some(text) = value.get("output_text").and_then(Value::as_str) {
        return text.to_string();
    }
    value
        .get("output")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|item| {
            item.get("content")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter_map(|content| content.get("text").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("")
}

fn parse_sse(response: Response) -> Result<StreamProof, ProbeError> {
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !content_type.starts_with("text/event-stream") {
        return Err(probe_error("verification-sse-content-type", false));
    }
    let reader = BufReader::new(response.take(MAX_RESPONSE_BYTES + 1));
    let mut bytes_read = 0_u64;
    let mut event_types = Vec::new();
    let mut model = String::new();
    let mut output_text = String::new();
    let mut completed = false;
    for line in reader.lines() {
        let line = line.map_err(|_| probe_error("verification-sse-read", true))?;
        bytes_read = bytes_read.saturating_add(line.len() as u64 + 1);
        if bytes_read > MAX_RESPONSE_BYTES {
            return Err(probe_error("verification-response-too-large", false));
        }
        let Some(data) = line.strip_prefix("data:").map(str::trim) else {
            continue;
        };
        if data == "[DONE]" {
            continue;
        }
        let value: Value =
            serde_json::from_str(data).map_err(|_| probe_error("verification-sse-json", false))?;
        absorb_stream_event(
            &value,
            &mut event_types,
            &mut model,
            &mut output_text,
            &mut completed,
        );
    }
    Ok(StreamProof {
        event_types,
        model,
        output_text,
        completed,
    })
}

trait BlockingNetworkStream: Read + Write {}
impl<T: Read + Write> BlockingNetworkStream for T {}

struct ResolvedWebSocketProxy {
    endpoint: Url,
    basic_authorization: Option<Zeroizing<String>>,
    username: Option<Zeroizing<String>>,
    password: Option<Zeroizing<String>>,
}

fn resolve_websocket_proxy(
    mode: &VerificationProxy,
    endpoint: &Url,
) -> Result<Option<ResolvedWebSocketProxy>, ProbeError> {
    match mode {
        VerificationProxy::Direct => Ok(None),
        VerificationProxy::Custom(url) => Ok(Some(ResolvedWebSocketProxy {
            endpoint: url.clone(),
            basic_authorization: None,
            username: None,
            password: None,
        })),
        VerificationProxy::System => {
            let mut proxy_target = endpoint.clone();
            proxy_target
                .set_scheme(if endpoint.scheme() == "wss" {
                    "https"
                } else {
                    "http"
                })
                .map_err(|_| probe_error("verification-websocket-origin", false))?;
            let target_uri = proxy_target
                .as_str()
                .parse::<tungstenite::http::Uri>()
                .map_err(|_| probe_error("verification-websocket-origin", false))?;
            let matcher = hyper_util::client::proxy::matcher::Matcher::from_system();
            let Some(intercept) = matcher.intercept(&target_uri) else {
                return Ok(None);
            };
            let proxy_url = Url::parse(&intercept.uri().to_string())
                .map_err(|_| probe_error("verification-websocket-proxy", false))?;
            let basic_authorization = intercept
                .basic_auth()
                .and_then(|value| value.to_str().ok())
                .map(|value| Zeroizing::new(value.to_string()));
            let (username, password) = intercept
                .raw_auth()
                .map(|(username, password)| {
                    (
                        Some(Zeroizing::new(username.to_string())),
                        Some(Zeroizing::new(password.to_string())),
                    )
                })
                .unwrap_or((None, None));
            Ok(Some(ResolvedWebSocketProxy {
                endpoint: proxy_url,
                basic_authorization,
                username,
                password,
            }))
        }
    }
}

fn connect_tcp(host: &str, port: u16, error_code: &str) -> Result<TcpStream, ProbeError> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|_| probe_error("verification-websocket-dns", true))?;
    let mut last_error = None;
    for address in addresses.take(8) {
        match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(NETWORK_TIMEOUT))
                    .and_then(|()| stream.set_write_timeout(Some(NETWORK_TIMEOUT)))
                    .map_err(|_| probe_error("verification-websocket-timeout", true))?;
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    let _ = last_error;
    Err(probe_error(error_code, true))
}

fn endpoint_host_port(endpoint: &Url, default_port: u16) -> Result<(&str, u16), ProbeError> {
    let host = endpoint
        .host_str()
        .ok_or_else(|| probe_error("verification-websocket-origin", false))?;
    Ok((host, endpoint.port().unwrap_or(default_port)))
}

fn connect_http_proxy(
    proxy: &ResolvedWebSocketProxy,
    target: &Url,
) -> Result<Box<dyn BlockingNetworkStream + Send>, ProbeError> {
    let default_port = if proxy.endpoint.scheme() == "https" {
        443
    } else {
        80
    };
    let (proxy_host, proxy_port) = endpoint_host_port(&proxy.endpoint, default_port)?;
    let tcp = connect_tcp(
        proxy_host,
        proxy_port,
        "verification-websocket-proxy-connect",
    )?;
    let mut stream: Box<dyn BlockingNetworkStream + Send> = if proxy.endpoint.scheme() == "https" {
        let connector = native_tls::TlsConnector::builder()
            .build()
            .map_err(|_| probe_error("verification-websocket-proxy-tls", true))?;
        let tls = connector
            .connect(proxy_host, tcp)
            .map_err(|_| probe_error("verification-websocket-proxy-tls", true))?;
        Box::new(tls)
    } else {
        Box::new(tcp)
    };
    let (target_host, target_port) =
        endpoint_host_port(target, if target.scheme() == "wss" { 443 } else { 80 })?;
    let authority = if target_host.contains(':') {
        format!("[{target_host}]:{target_port}")
    } else {
        format!("{target_host}:{target_port}")
    };
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n"
    );
    if let Some(authorization) = proxy.basic_authorization.as_ref() {
        request.push_str("Proxy-Authorization: ");
        request.push_str(authorization.as_str());
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|_| probe_error("verification-websocket-proxy-write", true))?;
    let mut response = Vec::with_capacity(1024);
    let mut byte = [0_u8; 1];
    while response.len() < 32 * 1024 && !response.ends_with(b"\r\n\r\n") {
        stream
            .read_exact(&mut byte)
            .map_err(|_| probe_error("verification-websocket-proxy-read", true))?;
        response.push(byte[0]);
    }
    if !response.ends_with(b"\r\n\r\n") {
        return Err(probe_error("verification-websocket-proxy-response", false));
    }
    let status_line = response
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .unwrap_or_default();
    if status_line.split_ascii_whitespace().nth(1) != Some("200") {
        return Err(probe_error("verification-websocket-proxy-rejected", true));
    }
    Ok(stream)
}

fn socks5_destination(target: &Url, remote_dns: bool) -> Result<Vec<u8>, ProbeError> {
    let (host, port) = endpoint_host_port(target, if target.scheme() == "wss" { 443 } else { 80 })?;
    let mut destination = Vec::new();
    if remote_dns {
        let bytes = host.as_bytes();
        if bytes.is_empty() || bytes.len() > u8::MAX as usize {
            return Err(probe_error("verification-websocket-proxy-host", false));
        }
        destination.push(3);
        destination.push(bytes.len() as u8);
        destination.extend_from_slice(bytes);
    } else {
        let address = (host, port)
            .to_socket_addrs()
            .map_err(|_| probe_error("verification-websocket-dns", true))?
            .next()
            .ok_or_else(|| probe_error("verification-websocket-dns", true))?;
        match address.ip() {
            std::net::IpAddr::V4(ip) => {
                destination.push(1);
                destination.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                destination.push(4);
                destination.extend_from_slice(&ip.octets());
            }
        }
    }
    destination.extend_from_slice(&port.to_be_bytes());
    Ok(destination)
}

fn connect_socks5_proxy(
    proxy: &ResolvedWebSocketProxy,
    target: &Url,
    remote_dns: bool,
) -> Result<Box<dyn BlockingNetworkStream + Send>, ProbeError> {
    let (proxy_host, proxy_port) = endpoint_host_port(&proxy.endpoint, 1080)?;
    let mut stream = connect_tcp(
        proxy_host,
        proxy_port,
        "verification-websocket-proxy-connect",
    )?;
    let has_credentials = proxy.username.is_some();
    let greeting: &[u8] = if has_credentials {
        &[5, 2, 0, 2]
    } else {
        &[5, 1, 0]
    };
    stream
        .write_all(greeting)
        .map_err(|_| probe_error("verification-websocket-proxy-write", true))?;
    let mut method = [0_u8; 2];
    stream
        .read_exact(&mut method)
        .map_err(|_| probe_error("verification-websocket-proxy-read", true))?;
    if method[0] != 5 || method[1] == 0xff {
        return Err(probe_error("verification-websocket-proxy-auth", false));
    }
    if method[1] == 2 {
        let username = proxy
            .username
            .as_ref()
            .map(|value| value.as_str())
            .unwrap_or_default()
            .as_bytes();
        let password = proxy
            .password
            .as_ref()
            .map(|value| value.as_str())
            .unwrap_or_default()
            .as_bytes();
        if username.is_empty() || username.len() > 255 || password.len() > 255 {
            return Err(probe_error("verification-websocket-proxy-auth", false));
        }
        let mut auth = Vec::with_capacity(username.len() + password.len() + 3);
        auth.extend_from_slice(&[1, username.len() as u8]);
        auth.extend_from_slice(username);
        auth.push(password.len() as u8);
        auth.extend_from_slice(password);
        stream
            .write_all(&auth)
            .map_err(|_| probe_error("verification-websocket-proxy-write", true))?;
        let mut reply = [0_u8; 2];
        stream
            .read_exact(&mut reply)
            .map_err(|_| probe_error("verification-websocket-proxy-read", true))?;
        if reply != [1, 0] {
            return Err(probe_error("verification-websocket-proxy-auth", false));
        }
    } else if method[1] != 0 {
        return Err(probe_error("verification-websocket-proxy-auth", false));
    }
    let mut connect = vec![5, 1, 0];
    connect.extend_from_slice(&socks5_destination(target, remote_dns)?);
    stream
        .write_all(&connect)
        .map_err(|_| probe_error("verification-websocket-proxy-write", true))?;
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|_| probe_error("verification-websocket-proxy-read", true))?;
    if header[0] != 5 || header[1] != 0 {
        return Err(probe_error("verification-websocket-proxy-rejected", true));
    }
    let address_length = match header[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut length = [0_u8; 1];
            stream
                .read_exact(&mut length)
                .map_err(|_| probe_error("verification-websocket-proxy-read", true))?;
            length[0] as usize
        }
        _ => return Err(probe_error("verification-websocket-proxy-response", false)),
    };
    let mut address_and_port = vec![0_u8; address_length + 2];
    stream
        .read_exact(&mut address_and_port)
        .map_err(|_| probe_error("verification-websocket-proxy-read", true))?;
    Ok(Box::new(stream))
}

fn websocket_transport(
    endpoint: &Url,
    mode: &VerificationProxy,
) -> Result<Box<dyn BlockingNetworkStream + Send>, ProbeError> {
    let Some(proxy) = resolve_websocket_proxy(mode, endpoint)? else {
        let (host, port) =
            endpoint_host_port(endpoint, if endpoint.scheme() == "wss" { 443 } else { 80 })?;
        return connect_tcp(host, port, "verification-websocket-connect")
            .map(|stream| Box::new(stream) as Box<dyn BlockingNetworkStream + Send>);
    };
    match proxy.endpoint.scheme() {
        "http" | "https" => connect_http_proxy(&proxy, endpoint),
        "socks5" => connect_socks5_proxy(&proxy, endpoint, false),
        "socks5h" => connect_socks5_proxy(&proxy, endpoint, true),
        _ => Err(probe_error("verification-websocket-proxy-scheme", false)),
    }
}

fn websocket_probe(
    request: &VerificationRequest,
    api_key: &str,
    proxy: &VerificationProxy,
) -> Result<StreamProof, ProbeError> {
    let mut endpoint = Url::parse(request.expected_api_origin.trim_end_matches('/'))
        .map_err(|_| probe_error("verification-websocket-origin", false))?;
    endpoint
        .set_scheme(if endpoint.scheme() == "https" {
            "wss"
        } else {
            "ws"
        })
        .map_err(|_| probe_error("verification-websocket-origin", false))?;
    endpoint.set_path(&format!(
        "{}/responses",
        endpoint.path().trim_end_matches('/')
    ));
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    let stream = websocket_transport(&endpoint, proxy)?;
    let mut ws_request = endpoint
        .as_str()
        .into_client_request()
        .map_err(|_| probe_error("verification-websocket-request", false))?;
    ws_request.headers_mut().insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {api_key}"))
            .map_err(|_| probe_error("verification-websocket-request", false))?,
    );
    ws_request.headers_mut().insert(
        "OpenAI-Beta",
        HeaderValue::from_static("responses=experimental"),
    );
    ws_request.headers_mut().insert(
        "x-codex-beta-features",
        HeaderValue::from_static("responses_websockets_v2"),
    );
    let (mut socket, _) = client_tls_with_config(ws_request, stream, None, None)
        .map_err(|_| probe_error("verification-websocket-handshake", true))?;
    let mut payload = response_request_json(request, true);
    payload["type"] = Value::String("response.create".to_string());
    socket
        .send(Message::Text(payload.to_string().into()))
        .map_err(|_| probe_error("verification-websocket-send", true))?;
    let mut event_types = Vec::new();
    let mut model = String::new();
    let mut output_text = String::new();
    let mut completed = false;
    for _ in 0..WEBSOCKET_EVENT_LIMIT {
        let message = socket
            .read()
            .map_err(|_| probe_error("verification-websocket-read", true))?;
        match message {
            Message::Text(text) => {
                let value: Value = serde_json::from_str(text.as_str())
                    .map_err(|_| probe_error("verification-websocket-json", false))?;
                absorb_stream_event(
                    &value,
                    &mut event_types,
                    &mut model,
                    &mut output_text,
                    &mut completed,
                );
                if completed {
                    break;
                }
            }
            Message::Ping(payload) => {
                socket
                    .send(Message::Pong(payload))
                    .map_err(|_| probe_error("verification-websocket-pong", true))?;
            }
            Message::Close(_) => break,
            Message::Binary(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
    }
    let _ = socket.close(None);
    Ok(StreamProof {
        event_types,
        model,
        output_text,
        completed,
    })
}

fn absorb_stream_event(
    value: &Value,
    event_types: &mut Vec<String>,
    model: &mut String,
    output_text: &mut String,
    completed: &mut bool,
) {
    let event_type = value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !event_type.is_empty() {
        event_types.push(event_type.to_string());
    }
    if event_type == "response.output_text.delta" {
        if let Some(delta) = value.get("delta").and_then(Value::as_str) {
            output_text.push_str(delta);
        }
    }
    if let Some(response) = value.get("response") {
        if let Some(value) = response.get("model").and_then(Value::as_str) {
            *model = value.to_string();
        }
        if output_text.is_empty() {
            output_text.push_str(&response_output_text(response));
        }
    }
    if event_type == "response.completed" {
        *completed = true;
    }
}

fn map_reqwest_error(error: reqwest::Error) -> ProbeError {
    probe_error(
        if error.is_timeout() {
            "verification-timeout"
        } else if error.is_connect() {
            "verification-connect"
        } else {
            "verification-network"
        },
        true,
    )
}

fn probe_error(code: &str, retryable: bool) -> ProbeError {
    ProbeError {
        code: safe_code(code, "verification-probe-error"),
        retryable,
    }
}

fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn safe_code(value: &str, fallback: &str) -> String {
    if !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        value.to_string()
    } else {
        fallback.to_string()
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    use codex_delivery_engine::CredentialHandle;

    fn test_policy_json(claim: &str, diagnostic: &str, api: &str) -> String {
        serde_json::json!({
            "schema_version": 1,
            "state": "test",
            "public_key_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "issuer": "provider-codex-v4",
            "audience": "codex-app-manager",
            "build_id": "v4-test-build",
            "claim_endpoint_id": "customer-portal-v4-claim",
            "claim_endpoint_url": claim,
            "diagnostic_endpoint": diagnostic,
            "allowed_api_origins": [api]
        })
        .to_string()
    }

    #[test]
    fn embedded_policy_fails_closed_until_release_injection() {
        let error = release_policy(RELEASE_POLICY_JSON, false).unwrap_err();
        assert_eq!(error.code, "v4-release-policy-unpublished");
    }

    #[test]
    fn test_policy_allows_only_exact_loopback_contract_paths() {
        let valid = test_policy_json(
            "http://127.0.0.1:8011/api/bootstrap/v4/claim",
            "http://127.0.0.1:8011/api/installer/v4/diagnostics/bundles",
            "http://127.0.0.1:8012/v1",
        );
        assert!(release_policy(&valid, true).is_ok());
        let wrong = test_policy_json(
            "http://127.0.0.1:8011/api/bootstrap/claim",
            "http://127.0.0.1:8011/api/installer/v4/diagnostics/bundles",
            "http://127.0.0.1:8012/v1",
        );
        assert_eq!(
            release_policy(&wrong, true).unwrap_err().code,
            "claim-endpoint-invalid"
        );
        assert!(release_policy(&valid, false).is_err());
    }

    #[test]
    fn verified_preclaim_sidecar_supplies_only_bootstrap_diagnostic_authorization() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../crates/codex-delivery-engine/tests/fixtures/portal-v4-claim.json"
        ))
        .unwrap();
        let verification = &fixture["verification_policy"];
        let policy = ReleasePolicy {
            schema_version: 1,
            state: "test".to_string(),
            public_key_b64: verification["public_key_b64"].as_str().unwrap().to_string(),
            issuer: verification["expected_issuer"]
                .as_str()
                .unwrap()
                .to_string(),
            audience: verification["expected_audience"]
                .as_str()
                .unwrap()
                .to_string(),
            build_id: verification["expected_build_id"]
                .as_str()
                .unwrap()
                .to_string(),
            claim_endpoint_id: verification["expected_claim_endpoint_id"]
                .as_str()
                .unwrap()
                .to_string(),
            claim_endpoint_url: "http://127.0.0.1:48080/api/bootstrap/v4/claim".to_string(),
            diagnostic_endpoint: "http://127.0.0.1:48080/api/installer/v4/diagnostics/bundles"
                .to_string(),
            allowed_api_origins: vec!["https://api.2466335.xyz".to_string()],
        };
        let path = std::env::temp_dir().join(format!(
            "codex-v4-diagnostic-sidecar-{}.json",
            Uuid::new_v4().simple()
        ));
        fs::write(
            &path,
            serde_json::to_vec(&fixture["bootstrap_envelope"]).unwrap(),
        )
        .unwrap();
        let loaded = load_bootstrap_sidecar(
            &path,
            &policy.verification_policy(None).unwrap(),
            fixture["now_unix"].as_i64().unwrap(),
        )
        .unwrap();
        let authorization = bootstrap_diagnostic_authorization_from_loaded(&policy, &loaded, true)
            .unwrap()
            .unwrap();
        assert!(authorization.token.starts_with("boot_"));
        assert_eq!(
            authorization.diagnostic_endpoint.path(),
            "/api/installer/v4/diagnostics/bundles"
        );
        assert_ne!(
            authorization.diagnostic_endpoint.path(),
            "/api/bootstrap/v4/claim"
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn bounded_sidecar_search_does_not_follow_symlinks_or_cross_depth() {
        let root = std::env::temp_dir().join(format!(
            "codex-v4-sidecar-search-{}",
            Uuid::new_v4().simple()
        ));
        let accepted = root.join("one/two").join(BOOTSTRAP_FILE_NAME);
        let rejected = root.join("one/two/three/four").join(BOOTSTRAP_FILE_NAME);
        fs::create_dir_all(accepted.parent().unwrap()).unwrap();
        fs::create_dir_all(rejected.parent().unwrap()).unwrap();
        fs::write(&accepted, b"accepted").unwrap();
        fs::write(&rejected, b"rejected").unwrap();
        let found = find_named_files_bounded(&root, BOOTSTRAP_FILE_NAME, 2, 100);
        assert_eq!(found, vec![accepted]);
        fs::remove_dir_all(root).unwrap();
    }

    fn verified_candidate(
        path: &str,
        issued_at_unix: i64,
        signature: &str,
    ) -> VerifiedSidecarCandidate {
        VerifiedSidecarCandidate {
            path: PathBuf::from(path),
            issued_at_unix,
            signature_b64: signature.to_string(),
        }
    }

    #[test]
    fn signed_sidecar_selection_uses_newest_envelope_not_filesystem_order() {
        let selected = select_latest_verified_sidecar(vec![
            verified_candidate("z/old/bootstrap.v4.json", 100, "old-signature"),
            verified_candidate("a/new/bootstrap.v4.json", 200, "new-signature"),
        ])
        .unwrap();
        assert_eq!(selected, Some(PathBuf::from("a/new/bootstrap.v4.json")));
    }

    #[test]
    fn signed_sidecar_selection_is_deterministic_for_identical_duplicates() {
        let selected = select_latest_verified_sidecar(vec![
            verified_candidate("z/bootstrap.v4.json", 200, "same-signature"),
            verified_candidate("a/bootstrap.v4.json", 200, "same-signature"),
        ])
        .unwrap();
        assert_eq!(selected, Some(PathBuf::from("a/bootstrap.v4.json")));
    }

    #[test]
    fn signed_sidecar_selection_rejects_same_time_customer_ambiguity() {
        let error = select_latest_verified_sidecar(vec![
            verified_candidate("a/bootstrap.v4.json", 200, "customer-a-signature"),
            verified_candidate("b/bootstrap.v4.json", 200, "customer-b-signature"),
        ])
        .unwrap_err();
        assert_eq!(error.code, "bootstrap-sidecar-ambiguous");
    }

    #[test]
    fn response_text_parser_handles_responses_api_nested_content() {
        let value = serde_json::json!({
            "output": [{
                "content": [
                    {"type": "output_text", "text": "provider-"},
                    {"type": "output_text", "text": "marker"}
                ]
            }]
        });
        assert_eq!(response_output_text(&value), "provider-marker");
    }

    #[test]
    fn stream_absorber_requires_real_event_semantics_not_final_text_only() {
        let mut events = Vec::new();
        let mut model = String::new();
        let mut text = String::new();
        let mut completed = false;
        for value in [
            serde_json::json!({"type":"response.created","response":{"model":"gpt-test"}}),
            serde_json::json!({"type":"response.output_text.delta","delta":"marker"}),
            serde_json::json!({"type":"response.completed","response":{"model":"gpt-test"}}),
        ] {
            absorb_stream_event(&value, &mut events, &mut model, &mut text, &mut completed);
        }
        assert_eq!(model, "gpt-test");
        assert_eq!(text, "marker");
        assert!(completed);
        assert_eq!(
            events,
            vec![
                "response.created",
                "response.output_text.delta",
                "response.completed"
            ]
        );
    }

    fn verification_request(api_origin: String) -> VerificationRequest {
        VerificationRequest {
            operation_id: Uuid::new_v4().to_string(),
            expected_api_origin: api_origin,
            expected_model: "gpt-test".to_string(),
            expected_review_model: "gpt-review".to_string(),
            expected_marker: "provider-v4-marker".to_string(),
            credential: CredentialHandle {
                service: "test".to_string(),
                account: "test".to_string(),
            },
            cli_policy: CliPolicy::NotApplicable,
            require_usage_lifecycle: false,
        }
    }

    #[test]
    fn loopback_http_verifier_proves_models_json_response_and_sse() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let responses = [
                (
                    "application/json",
                    serde_json::json!({
                        "data": [{"id":"gpt-test"},{"id":"gpt-review"}]
                    })
                    .to_string(),
                ),
                (
                    "application/json",
                    serde_json::json!({
                        "id":"resp_test",
                        "model":"gpt-test",
                        "output_text":"provider-v4-marker"
                    })
                    .to_string(),
                ),
                (
                    "text/event-stream",
                    [
                        "data: {\"type\":\"response.created\",\"response\":{\"model\":\"gpt-test\"}}\n\n",
                        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"provider-v4-marker\"}\n\n",
                        "data: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-test\"}}\n\n",
                    ]
                    .concat(),
                ),
            ];
            for (content_type, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = vec![0_u8; 64 * 1024];
                let read = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..read]).to_ascii_lowercase();
                assert!(request.contains("authorization: bearer test-api-key"));
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        let root =
            std::env::temp_dir().join(format!("codex-v4-verifier-{}", Uuid::new_v4().simple()));
        fs::create_dir_all(&root).unwrap();
        let mut probe =
            ProductionVerificationProbe::loopback_for_test(root.clone(), "test-api-key").unwrap();
        let request = verification_request(format!("http://{address}/v1"));
        let models = probe.models(&request).unwrap();
        assert_eq!(models.model_ids, vec!["gpt-test", "gpt-review"]);
        let response = probe.response(&request).unwrap();
        assert_eq!(response.request_id, "resp_test");
        assert_eq!(response.output_text, "provider-v4-marker");
        let stream = probe.sse(&request).unwrap();
        assert!(stream.completed);
        assert_eq!(stream.output_text, "provider-v4-marker");
        server.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn loopback_api_outage_is_retryable_and_never_claims_success() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = vec![0_u8; 64 * 1024];
            let read = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..read]).to_ascii_lowercase();
            assert!(request.contains("authorization: bearer test-api-key"));
            let body = r#"{"error":{"message":"temporarily unavailable"}}"#;
            let response = format!(
                "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        let root =
            std::env::temp_dir().join(format!("codex-v4-api-outage-{}", Uuid::new_v4().simple()));
        fs::create_dir_all(&root).unwrap();
        let mut probe =
            ProductionVerificationProbe::loopback_for_test(root.clone(), "test-api-key").unwrap();
        let request = verification_request(format!("http://{address}/v1"));
        let error = probe.models(&request).unwrap_err();
        assert_eq!(error.code, "verification-models-http-503");
        assert!(error.retryable);
        server.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn loopback_websocket_verifier_uses_authorization_and_v2_feature_signal() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut socket = tungstenite::accept_hdr(
                stream,
                |request: &tungstenite::handshake::server::Request, response| {
                    assert_eq!(
                        request
                            .headers()
                            .get("authorization")
                            .and_then(|value| value.to_str().ok()),
                        Some("Bearer test-api-key")
                    );
                    assert_eq!(
                        request
                            .headers()
                            .get("x-codex-beta-features")
                            .and_then(|value| value.to_str().ok()),
                        Some("responses_websockets_v2")
                    );
                    Ok(response)
                },
            )
            .unwrap();
            let request = socket.read().unwrap();
            let Message::Text(request) = request else {
                panic!("expected text request")
            };
            let request: Value = serde_json::from_str(request.as_str()).unwrap();
            assert_eq!(request["type"], "response.create");
            assert_eq!(request["model"], "gpt-test");
            for event in [
                serde_json::json!({"type":"response.created","response":{"model":"gpt-test"}}),
                serde_json::json!({"type":"response.output_text.delta","delta":"provider-v4-marker"}),
                serde_json::json!({"type":"response.completed","response":{"model":"gpt-test"}}),
            ] {
                socket
                    .send(Message::Text(event.to_string().into()))
                    .unwrap();
            }
            let _ = socket.close(None);
        });
        let request = verification_request(format!("http://{address}/v1"));
        let proof = websocket_probe(&request, "test-api-key", &VerificationProxy::Direct).unwrap();
        assert!(proof.completed);
        assert_eq!(proof.model, "gpt-test");
        assert_eq!(proof.output_text, "provider-v4-marker");
        server.join().unwrap();
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn loopback_websocket_verifier_tunnels_through_custom_http_proxy() {
        let destination_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let destination_address = destination_listener.local_addr().unwrap();
        let destination = thread::spawn(move || {
            let (stream, _) = destination_listener.accept().unwrap();
            let mut socket = tungstenite::accept_hdr(
                stream,
                |request: &tungstenite::handshake::server::Request, response| {
                    assert_eq!(
                        request
                            .headers()
                            .get("authorization")
                            .and_then(|value| value.to_str().ok()),
                        Some("Bearer test-api-key")
                    );
                    Ok(response)
                },
            )
            .unwrap();
            let request = socket.read().unwrap();
            let Message::Text(request) = request else {
                panic!("expected text request")
            };
            assert_eq!(
                serde_json::from_str::<Value>(request.as_str()).unwrap()["type"],
                "response.create"
            );
            for event in [
                serde_json::json!({"type":"response.created","response":{"model":"gpt-test"}}),
                serde_json::json!({"type":"response.output_text.delta","delta":"provider-v4-marker"}),
                serde_json::json!({"type":"response.completed","response":{"model":"gpt-test"}}),
            ] {
                socket
                    .send(Message::Text(event.to_string().into()))
                    .unwrap();
            }
            let _ = socket.close(None);
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_address = proxy_listener.local_addr().unwrap();
        let proxy = thread::spawn(move || {
            let (mut client, _) = proxy_listener.accept().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut connect_request = Vec::new();
            let mut byte = [0_u8; 1];
            while connect_request.len() < 32 * 1024 && !connect_request.ends_with(b"\r\n\r\n") {
                client.read_exact(&mut byte).unwrap();
                connect_request.push(byte[0]);
            }
            let connect_request = String::from_utf8(connect_request).unwrap();
            assert!(
                connect_request.starts_with(&format!("CONNECT {destination_address} HTTP/1.1\r\n"))
            );
            let mut upstream = TcpStream::connect(destination_address).unwrap();
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            let mut client_reader = client.try_clone().unwrap();
            let mut upstream_writer = upstream.try_clone().unwrap();
            let outbound = thread::spawn(move || {
                let _ = std::io::copy(&mut client_reader, &mut upstream_writer);
            });
            let _ = std::io::copy(&mut upstream, &mut client);
            outbound.join().unwrap();
        });

        let request = verification_request(format!("http://{destination_address}/v1"));
        let proxy_mode = VerificationProxy::Custom(
            Url::parse(&format!("http://{proxy_address}")).expect("loopback proxy URL must parse"),
        );
        let proof = websocket_probe(&request, "test-api-key", &proxy_mode).unwrap();
        assert!(proof.completed);
        assert_eq!(proof.output_text, "provider-v4-marker");
        proxy.join().unwrap();
        destination.join().unwrap();
    }
}
