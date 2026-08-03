use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::claim::{
    ClaimCoordinator, ClaimExecution, ClaimRecoveryAction, ClaimTransport, RetryPolicy,
};
use crate::config::{
    provision_configuration_with_validator, ConfigRepairState, ConfigSemanticValidator,
    ConflictPolicy, ManagedConfigSpec, NoFault, NoopConfigValidator, ProvisioningPaths,
    ProvisioningSecrets, ScanLimits,
};
use crate::contract::{SignedBootstrapEnvelope, VerificationPolicy};
use crate::credential::{CredentialHandle, CredentialVault};
use crate::error::DeliveryError;
use crate::locale::{run_locale_task, LocaleInitializer, LocaleTaskReport, LocaleTaskState};
use crate::migration::migrate_project_and_session_overrides;
use crate::verifier::{
    run_verification, CliPolicy, VerificationProbe, VerificationReport, VerificationRequest,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DeliveryPipelineState {
    Completed,
    CompletedWithWarnings,
    VerificationFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSummary {
    pub config_sha256: String,
    pub auth_sha256: String,
    pub catalog_sha256: String,
    pub credential_handle: CredentialHandle,
    pub recognized_v2: bool,
    pub config_repair_state: ConfigRepairState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationSummary {
    pub project_configs_changed: usize,
    pub sessions_changed: usize,
    pub issues: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryPipelineReport {
    pub schema_version: u32,
    pub operation_id: String,
    pub installation_id: String,
    pub state: DeliveryPipelineState,
    pub claim_attempts: u8,
    pub config: ConfigSummary,
    pub migration: MigrationSummary,
    pub locale: LocaleTaskReport,
    pub verification: VerificationReport,
    pub warning_codes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryPipelineFailure {
    pub schema_version: u32,
    pub operation_id: String,
    pub stage: String,
    pub code: String,
    pub retryable: bool,
    pub recovery: ClaimRecoveryAction,
    pub claim_config_failure_disposition: Option<String>,
}

pub struct DeliveryPipelineInput<'a> {
    pub operation_id: Uuid,
    pub envelope: &'a SignedBootstrapEnvelope,
    pub verification_policy: VerificationPolicy,
    pub device_hash: &'a str,
    pub platform: &'a str,
    pub architecture: &'a str,
    pub system_locale: &'a str,
    pub app_health_verified: bool,
    pub now_unix: i64,
    pub provisioning_paths: ProvisioningPaths,
    pub project_roots: Vec<PathBuf>,
    pub sessions_root: PathBuf,
    pub migration_backup_root: PathBuf,
    pub scan_limits: ScanLimits,
    pub conflict_policy: ConflictPolicy,
    pub cli_policy: CliPolicy,
    pub require_usage_lifecycle: bool,
    pub verification_marker: String,
}

pub fn run_delivery_pipeline<T, V, L, P>(
    input: DeliveryPipelineInput<'_>,
    claim_transport: &mut T,
    vault: &mut V,
    locale_initializer: &mut L,
    verification_probe: &mut P,
) -> Result<DeliveryPipelineReport, DeliveryPipelineFailure>
where
    T: ClaimTransport,
    V: CredentialVault,
    L: LocaleInitializer,
    P: VerificationProbe,
{
    run_delivery_pipeline_with_validator(
        input,
        claim_transport,
        vault,
        locale_initializer,
        verification_probe,
        &mut NoopConfigValidator,
    )
}

pub fn run_delivery_pipeline_with_validator<T, V, L, P, C>(
    input: DeliveryPipelineInput<'_>,
    claim_transport: &mut T,
    vault: &mut V,
    locale_initializer: &mut L,
    verification_probe: &mut P,
    config_validator: &mut C,
) -> Result<DeliveryPipelineReport, DeliveryPipelineFailure>
where
    T: ClaimTransport,
    V: CredentialVault,
    L: LocaleInitializer,
    P: VerificationProbe,
    C: ConfigSemanticValidator,
{
    let operation_id = input.operation_id.to_string();
    let claim = ClaimCoordinator::new(input.verification_policy, RetryPolicy::default())
        .execute(
            ClaimExecution {
                envelope: input.envelope,
                device_hash: input.device_hash,
                platform: input.platform,
                architecture: input.architecture,
                system_locale: input.system_locale,
                operation_id: &operation_id,
                app_health_verified: input.app_health_verified,
                now_unix: input.now_unix,
            },
            claim_transport,
        )
        .map_err(|failure| DeliveryPipelineFailure {
            schema_version: 1,
            operation_id: operation_id.clone(),
            stage: "claim".to_string(),
            code: safe_code(&failure.server_code, "claim-failed"),
            retryable: failure.recovery == ClaimRecoveryAction::Retry,
            recovery: failure.recovery,
            claim_config_failure_disposition: None,
        })?;

    let claim_attempts = claim.attempts;
    let receipt = claim.receipt.payload;
    let config_failure_disposition = receipt.config_failure_disposition.clone();
    let installation_id = Uuid::parse_str(&receipt.installation_id).map_err(|_| {
        pipeline_failure(
            &operation_id,
            "claim",
            "installation-id-invalid",
            ClaimRecoveryAction::Redownload,
            None,
        )
    })?;
    let mut delivery = claim.delivery;
    let api_key = std::mem::take(&mut delivery.api_key);
    let management_token = std::mem::take(&mut delivery.management_token);
    let locale_relay_bundle_b64 =
        Zeroizing::new(std::mem::take(&mut delivery.locale_relay_bundle_b64));
    let model_catalog_path = input
        .provisioning_paths
        .codex_home
        .join("models-full-responses.json");
    let spec = ManagedConfigSpec {
        api_base_url: receipt.api_base_url.clone(),
        model_catalog_path,
        model_catalog_sha256: receipt.model_catalog_sha256.clone(),
        model: receipt.model.clone(),
        review_model: receipt.review_model.clone(),
        reasoning_effort: receipt.reasoning_effort.clone(),
        locale: receipt.locale.target_locale.clone(),
    };
    let secrets = ProvisioningSecrets {
        api_key,
        management_token,
    };
    let config = provision_configuration_with_validator(
        crate::config::ProvisioningRequest {
            paths: &input.provisioning_paths,
            spec: &spec,
            secrets: &secrets,
            operation_id: input.operation_id,
            installation_id,
            policy: input.conflict_policy,
        },
        vault,
        &mut NoFault,
        config_validator,
    )
    .map_err(|error| config_failure(&operation_id, error, &config_failure_disposition))?;

    let migration = migrate_project_and_session_overrides(
        &input.project_roots,
        &input.sessions_root,
        &input.migration_backup_root,
        input.operation_id,
        &input.scan_limits,
    )
    .map_err(|_| {
        pipeline_failure(
            &operation_id,
            "migration",
            "migration-transaction-failed",
            ClaimRecoveryAction::Support,
            Some(config_failure_disposition.clone()),
        )
    })?;

    let locale = run_locale_task(
        &receipt.locale,
        input.system_locale,
        locale_relay_bundle_b64.as_deref(),
        input.now_unix,
        locale_initializer,
    );
    let verification = run_verification(
        &VerificationRequest {
            operation_id: operation_id.clone(),
            expected_api_origin: receipt.api_base_url,
            expected_model: receipt.model,
            expected_review_model: receipt.review_model,
            expected_marker: input.verification_marker,
            credential: config.credential_handle.clone(),
            cli_policy: input.cli_policy,
            require_usage_lifecycle: input.require_usage_lifecycle,
        },
        verification_probe,
    );

    let mut warning_codes = Vec::new();
    if !matches!(
        locale.state,
        LocaleTaskState::Succeeded | LocaleTaskState::Skipped
    ) {
        warning_codes.push(
            locale
                .error_code
                .clone()
                .unwrap_or_else(|| "locale-initialization-warning".to_string()),
        );
    }
    if !migration.issues.is_empty() {
        warning_codes.push("migration-partial-warning".to_string());
    }
    if migration.truncated {
        warning_codes.push("migration-scan-truncated".to_string());
    }
    let state = if !verification.succeeded {
        DeliveryPipelineState::VerificationFailed
    } else if warning_codes.is_empty() {
        DeliveryPipelineState::Completed
    } else {
        DeliveryPipelineState::CompletedWithWarnings
    };

    Ok(DeliveryPipelineReport {
        schema_version: 1,
        operation_id,
        installation_id: installation_id.to_string(),
        state,
        claim_attempts,
        config: ConfigSummary {
            config_sha256: config.config_sha256,
            auth_sha256: config.auth_sha256,
            catalog_sha256: config.catalog_sha256,
            credential_handle: config.credential_handle,
            recognized_v2: config.recognized_v2,
            config_repair_state: config.config_repair_state,
        },
        migration: MigrationSummary {
            project_configs_changed: migration.project_configs_changed,
            sessions_changed: migration.sessions_changed,
            issues: migration.issues.len(),
            truncated: migration.truncated,
        },
        locale,
        verification,
        warning_codes,
    })
}

fn config_failure(
    operation_id: &str,
    error: DeliveryError,
    disposition: &str,
) -> DeliveryPipelineFailure {
    let code = match error {
        DeliveryError::ConfigConflict(_) => "config-conflict",
        DeliveryError::Rollback(_) => "config-rollback-failed",
        _ => "config-transaction-failed",
    };
    pipeline_failure(
        operation_id,
        "config",
        code,
        ClaimRecoveryAction::Support,
        Some(disposition.to_string()),
    )
}

fn pipeline_failure(
    operation_id: &str,
    stage: &str,
    code: &str,
    recovery: ClaimRecoveryAction,
    disposition: Option<String>,
) -> DeliveryPipelineFailure {
    DeliveryPipelineFailure {
        schema_version: 1,
        operation_id: operation_id.to_string(),
        stage: stage.to_string(),
        code: code.to_string(),
        retryable: recovery == ClaimRecoveryAction::Retry,
        recovery,
        claim_config_failure_disposition: disposition,
    }
}

fn safe_code(value: &str, fallback: &str) -> String {
    if !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        value.to_string()
    } else {
        fallback.to_string()
    }
}
