//! V4 business-delivery kernel.
//!
//! The crate deliberately has no UI dependency. Secret-bearing claim material
//! stays in the native backend, while callers receive only redacted outcomes.

mod atomic;
pub mod claim;
pub mod config;
pub mod contract;
pub mod credential;
pub mod device;
pub mod error;
pub mod locale;
pub mod migration;
pub mod native_locale;
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub mod native_vault;
pub mod pipeline;
pub mod runtime;
pub mod security;
pub mod verifier;
#[cfg(target_os = "windows")]
mod windows_security;

pub use claim::{
    ClaimCoordinator, ClaimExecution, ClaimFailure, ClaimOutcome, ClaimRecoveryAction,
    ClaimTransport, ClaimTransportError, ManualClaimDecision, ManualRetryBudget, RetryPolicy,
};
pub use config::{
    merge_config, provision_configuration, provision_configuration_with_validator, BackupRecord,
    ConfigRepairState, ConfigSemanticValidator, ConfigTransactionReport, ConflictPolicy,
    FaultInjector, ManagedConfigSpec, MergeResult, NoFault, NoopConfigValidator, ProvisioningPaths,
    ProvisioningRequest, ProvisioningSecrets, ScanLimits,
};
pub use contract::{
    canonical_json, hash_device_material, verify_claim_response, verify_envelope,
    BootstrapEnvelopePayload, ClaimDelivery, ClaimReceiptPayload, ClaimRequest, ClaimResponse,
    LocaleContract, LocaleMode, SignedBootstrapEnvelope, SignedClaimReceipt, VerificationPolicy,
};
pub use credential::{CredentialHandle, CredentialVault, MemoryCredentialVault};
pub use device::native_device_hash;
pub use error::DeliveryError;
pub use locale::{
    run_locale_task, LocaleInitError, LocaleInitializer, LocaleTaskReport, LocaleTaskState,
};
pub use migration::{
    migrate_project_and_session_overrides, restore_migration, MigrationChange, MigrationIssue,
    MigrationReport, RestoreReport,
};
pub use native_locale::NativeLocaleInitializer;
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub use native_vault::NativeCredentialVault;
pub use pipeline::{
    run_delivery_pipeline, run_delivery_pipeline_with_validator, ConfigSummary,
    DeliveryPipelineFailure, DeliveryPipelineInput, DeliveryPipelineReport, DeliveryPipelineState,
    MigrationSummary,
};
pub use runtime::{EndpointPolicy, RuntimeMode};
pub use verifier::{
    run_verification, AppProof, CliPolicy, CliProof, ConfigProof, ModelsProof, ProbeError,
    ResponseProof, StreamProof, UsageProof, VerificationProbe, VerificationReport,
    VerificationRequest, VerificationStageReport, VerificationState,
};
