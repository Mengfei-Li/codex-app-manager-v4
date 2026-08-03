use std::fs;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use codex_delivery_engine::contract::sha256_hex;
use codex_delivery_engine::*;
use ed25519_dalek::{Signer, SigningKey};
use tempfile::TempDir;
use uuid::Uuid;

const NOW: i64 = 1_900_000_000;
const DEVICE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BUILD: &str = "v4-pipeline-fixture";

fn catalog() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "client_version": "fixture",
        "models": [
            {"slug":"gpt-5.6-sol","supported_in_api":true},
            {"slug":"gpt-5.6-terra","supported_in_api":true},
            {"slug":"gpt-5.6-luna","supported_in_api":true},
            {"slug":"gpt-5.5","supported_in_api":true}
        ]
    }))
    .unwrap()
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn sign<T: serde::Serialize>(payload: &T) -> String {
    URL_SAFE_NO_PAD.encode(
        signing_key()
            .sign(&canonical_json(payload).unwrap())
            .to_bytes(),
    )
}

fn envelope() -> SignedBootstrapEnvelope {
    let payload = BootstrapEnvelopePayload {
        schema_version: 1,
        issuer: "provider-codex-v4".to_string(),
        audience: "codex-app-manager".to_string(),
        build_id: BUILD.to_string(),
        bootstrap_token: format!("boot_{}", "b".repeat(48)),
        claim_endpoint_id: "fixture-v4-claim".to_string(),
        issued_at_unix: NOW - 60,
        expires_at_unix: NOW + 600,
        nonce: "fixture-nonce-1234567890".to_string(),
    };
    SignedBootstrapEnvelope {
        signature_b64: sign(&payload),
        payload,
    }
}

fn claim_response(catalog_hash: &str) -> ClaimResponse {
    let delivery = ClaimDelivery {
        api_key: "fixture-api-key-never-log".to_string(),
        management_token: "fixture-management-never-log".to_string(),
        locale_relay_bundle_b64: None,
    };
    let payload = ClaimReceiptPayload {
        schema_version: 1,
        issuer: "provider-codex-v4".to_string(),
        audience: "codex-app-manager".to_string(),
        build_id: BUILD.to_string(),
        installation_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        device_hash: DEVICE.to_string(),
        claim_disposition: "claimed".to_string(),
        config_failure_disposition: "retain-same-device-resume".to_string(),
        already_claimed: false,
        issued_at_unix: NOW - 30,
        expires_at_unix: NOW + 600,
        api_base_url: "https://api.fixture.invalid/v1".to_string(),
        model: "gpt-5.6-sol".to_string(),
        review_model: "gpt-5.6-terra".to_string(),
        reasoning_effort: "high".to_string(),
        model_catalog_sha256: catalog_hash.to_string(),
        locale: LocaleContract {
            schema_version: 1,
            target_locale: "en-US".to_string(),
            required: true,
            mode: LocaleMode::NativeSystem,
            issued_at_unix: NOW - 30,
            expires_at_unix: NOW + 600,
        },
        delivery_sha256: sha256_hex(&canonical_json(&delivery).unwrap()),
    };
    ClaimResponse {
        receipt: SignedClaimReceipt {
            signature_b64: sign(&payload),
            payload,
        },
        delivery,
    }
}

struct Transport {
    response: Option<ClaimResponse>,
    calls: usize,
}

impl ClaimTransport for Transport {
    fn claim(&mut self, _request: &ClaimRequest) -> Result<ClaimResponse, ClaimTransportError> {
        self.calls += 1;
        Ok(self.response.take().unwrap())
    }
}

struct LocaleFixture {
    failure: bool,
}

impl LocaleInitializer for LocaleFixture {
    fn initialize(
        &mut self,
        _contract: &LocaleContract,
        _relay_bundle: Option<&[u8]>,
    ) -> Result<(), LocaleInitError> {
        if self.failure {
            Err(LocaleInitError {
                code: "locale-fixture-warning".to_string(),
                retryable: true,
            })
        } else {
            Ok(())
        }
    }
}

struct Probe;

struct FailMergedConfigOnce {
    calls: usize,
}

impl ConfigSemanticValidator for FailMergedConfigOnce {
    fn validate(&mut self, config_bytes: &[u8]) -> Result<(), DeliveryError> {
        self.calls += 1;
        if self.calls == 1 && config_bytes.windows(7).any(|window| window == b"unknown") {
            return Err(DeliveryError::ConfigTransaction(
                "fixture semantic rejection".to_string(),
            ));
        }
        Ok(())
    }
}

impl VerificationProbe for Probe {
    fn app(&mut self, _request: &VerificationRequest) -> Result<AppProof, ProbeError> {
        Ok(AppProof {
            process_alive: true,
            surface_ready: true,
        })
    }

    fn config(&mut self, request: &VerificationRequest) -> Result<ConfigProof, ProbeError> {
        Ok(ConfigProof {
            api_origin: request.expected_api_origin.clone(),
            model: request.expected_model.clone(),
            review_model: request.expected_review_model.clone(),
            credential_native: true,
            unknown_fields_preserved: true,
        })
    }

    fn models(&mut self, request: &VerificationRequest) -> Result<ModelsProof, ProbeError> {
        Ok(ModelsProof {
            model_ids: vec![
                request.expected_model.clone(),
                request.expected_review_model.clone(),
            ],
        })
    }

    fn response(&mut self, request: &VerificationRequest) -> Result<ResponseProof, ProbeError> {
        Ok(ResponseProof {
            request_id: "response-fixture".to_string(),
            model: request.expected_model.clone(),
            output_text: request.expected_marker.clone(),
        })
    }

    fn sse(&mut self, request: &VerificationRequest) -> Result<StreamProof, ProbeError> {
        Ok(stream(request))
    }

    fn websocket(&mut self, request: &VerificationRequest) -> Result<StreamProof, ProbeError> {
        Ok(stream(request))
    }

    fn cli(&mut self, request: &VerificationRequest) -> Result<CliProof, ProbeError> {
        Ok(CliProof {
            found: true,
            version_ok: true,
            auth_ok: true,
            output_text: request.expected_marker.clone(),
        })
    }

    fn usage(&mut self, _request: &VerificationRequest) -> Result<UsageProof, ProbeError> {
        Ok(UsageProof {
            isolated_customer: true,
            records_before: 1,
            records_after: 2,
            claim_released_or_revoked: true,
        })
    }
}

fn stream(request: &VerificationRequest) -> StreamProof {
    StreamProof {
        event_types: vec![
            "response.created".to_string(),
            "response.output_text.delta".to_string(),
            "response.completed".to_string(),
        ],
        model: request.expected_model.clone(),
        output_text: request.expected_marker.clone(),
        completed: true,
    }
}

struct Fixture {
    _temp: TempDir,
    input_envelope: SignedBootstrapEnvelope,
    paths: ProvisioningPaths,
    project_root: std::path::PathBuf,
    sessions_root: std::path::PathBuf,
    backup_root: std::path::PathBuf,
    catalog_hash: String,
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let codex_home = temp.path().join("codex-home");
    let catalog_source = temp.path().join("catalog.json");
    let catalog = catalog();
    fs::write(&catalog_source, &catalog).unwrap();
    fs::create_dir_all(&codex_home).unwrap();
    fs::write(
        codex_home.join("config.toml"),
        b"unknown = 'preserved'\n# BEGIN PROVIDER CODEX MANAGED CONFIG\nmodel_provider = 'relay'\n# END PROVIDER CODEX MANAGED CONFIG\n",
    )
    .unwrap();
    let project_root = temp.path().join("projects");
    fs::create_dir_all(project_root.join("a/.codex")).unwrap();
    fs::write(
        project_root.join("a/.codex/config.toml"),
        b"unknown = 1\nmodel_provider = 'relay'\n",
    )
    .unwrap();
    let sessions_root = temp.path().join("sessions");
    fs::create_dir_all(&sessions_root).unwrap();
    fs::write(
        sessions_root.join("one.jsonl"),
        b"{\"payload\":{\"model_provider\":\"relay\",\"body\":\"keep\"}}\n",
    )
    .unwrap();
    Fixture {
        paths: ProvisioningPaths {
            codex_home,
            catalog_source,
        },
        project_root,
        sessions_root,
        backup_root: temp.path().join("migration-backups"),
        input_envelope: envelope(),
        catalog_hash: sha256_hex(&catalog),
        _temp: temp,
    }
}

fn policy() -> VerificationPolicy {
    VerificationPolicy {
        public_key: signing_key().verifying_key().to_bytes(),
        expected_issuer: "provider-codex-v4".to_string(),
        expected_audience: "codex-app-manager".to_string(),
        expected_build_id: BUILD.to_string(),
        expected_claim_endpoint_id: "fixture-v4-claim".to_string(),
        expected_device_hash: Some(DEVICE.to_string()),
        allowed_api_origins: vec!["https://api.fixture.invalid".to_string()],
        allow_loopback_http: false,
    }
}

fn input(fixture: &Fixture, app_health_verified: bool) -> DeliveryPipelineInput<'_> {
    DeliveryPipelineInput {
        operation_id: Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap(),
        envelope: &fixture.input_envelope,
        verification_policy: policy(),
        device_hash: DEVICE,
        platform: "windows",
        architecture: "x64",
        system_locale: "en-US",
        app_health_verified,
        now_unix: NOW,
        provisioning_paths: fixture.paths.clone(),
        project_roots: vec![fixture.project_root.clone()],
        sessions_root: fixture.sessions_root.clone(),
        migration_backup_root: fixture.backup_root.clone(),
        scan_limits: ScanLimits::default(),
        conflict_policy: ConflictPolicy::AdoptRecognizedV2,
        cli_policy: CliPolicy::Required,
        require_usage_lifecycle: true,
        verification_marker: "pipeline-marker".to_string(),
    }
}

#[test]
fn full_pipeline_claims_then_commits_migrates_localizes_and_verifies() {
    let fixture = fixture();
    let mut transport = Transport {
        response: Some(claim_response(&fixture.catalog_hash)),
        calls: 0,
    };
    let mut vault = MemoryCredentialVault::default();
    let report = run_delivery_pipeline(
        input(&fixture, true),
        &mut transport,
        &mut vault,
        &mut LocaleFixture { failure: false },
        &mut Probe,
    )
    .unwrap();

    assert_eq!(transport.calls, 1);
    assert_eq!(report.state, DeliveryPipelineState::Completed);
    assert_eq!(report.migration.project_configs_changed, 1);
    assert_eq!(report.migration.sessions_changed, 1);
    assert!(report.verification.succeeded);
    let config = fs::read_to_string(fixture.paths.codex_home.join("config.toml")).unwrap();
    assert!(config.contains("unknown = 'preserved'"));
    assert!(config.contains("BEGIN PROVIDER CODEX V4"));
    let secure: serde_json::Value = serde_json::from_slice(
        &vault
            .get(&report.config.credential_handle)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(secure["api_key"], "fixture-api-key-never-log");
    assert_eq!(secure["management_token"], "fixture-management-never-log");
    let public_report = serde_json::to_string(&report).unwrap();
    assert!(!public_report.contains("fixture-api-key"));
    assert!(!public_report.contains("fixture-management"));
    assert!(!public_report.contains(fixture._temp.path().to_string_lossy().as_ref()));
}

#[test]
fn full_pipeline_runs_one_semantic_repair_before_migration_and_verification() {
    let fixture = fixture();
    let mut transport = Transport {
        response: Some(claim_response(&fixture.catalog_hash)),
        calls: 0,
    };
    let mut vault = MemoryCredentialVault::default();
    let mut validator = FailMergedConfigOnce { calls: 0 };
    let report = run_delivery_pipeline_with_validator(
        input(&fixture, true),
        &mut transport,
        &mut vault,
        &mut LocaleFixture { failure: false },
        &mut Probe,
        &mut validator,
    )
    .unwrap();

    assert_eq!(validator.calls, 2);
    assert_eq!(
        report.config.config_repair_state,
        ConfigRepairState::Succeeded
    );
    assert_eq!(report.state, DeliveryPipelineState::Completed);
    let config = fs::read_to_string(fixture.paths.codex_home.join("config.toml")).unwrap();
    assert!(!config.contains("unknown = 'preserved'"));
    assert!(report.verification.succeeded);
}

#[test]
fn locale_failure_becomes_warning_and_does_not_rollback_app_or_config() {
    let fixture = fixture();
    let mut transport = Transport {
        response: Some(claim_response(&fixture.catalog_hash)),
        calls: 0,
    };
    let mut vault = MemoryCredentialVault::default();
    let report = run_delivery_pipeline(
        input(&fixture, true),
        &mut transport,
        &mut vault,
        &mut LocaleFixture { failure: true },
        &mut Probe,
    )
    .unwrap();

    assert_eq!(report.state, DeliveryPipelineState::CompletedWithWarnings);
    assert_eq!(report.locale.state, LocaleTaskState::FailedRetryable);
    assert!(!report.locale.config_rollback_required);
    assert!(!report.locale.app_rollback_required);
    assert!(fixture.paths.codex_home.join("config.toml").exists());
    assert!(vault.contains(&report.config.credential_handle));
}

#[test]
fn app_health_failure_never_calls_claim_transport() {
    let fixture = fixture();
    let mut transport = Transport {
        response: Some(claim_response(&fixture.catalog_hash)),
        calls: 0,
    };
    let failure = run_delivery_pipeline(
        input(&fixture, false),
        &mut transport,
        &mut MemoryCredentialVault::default(),
        &mut LocaleFixture { failure: false },
        &mut Probe,
    )
    .unwrap_err();

    assert_eq!(failure.stage, "claim");
    assert_eq!(failure.code, "app_health_required");
    assert_eq!(transport.calls, 0);
}

#[test]
fn user_owned_config_conflict_is_not_overwritten_and_claim_policy_is_explicit() {
    let fixture = fixture();
    let original = b"model = 'user-owned'\nunknown = 'keep'\n".to_vec();
    fs::write(fixture.paths.codex_home.join("config.toml"), &original).unwrap();
    let mut pipeline_input = input(&fixture, true);
    pipeline_input.conflict_policy = ConflictPolicy::RejectUnmanaged;
    let mut transport = Transport {
        response: Some(claim_response(&fixture.catalog_hash)),
        calls: 0,
    };
    let mut vault = MemoryCredentialVault::default();
    let failure = run_delivery_pipeline(
        pipeline_input,
        &mut transport,
        &mut vault,
        &mut LocaleFixture { failure: false },
        &mut Probe,
    )
    .unwrap_err();

    assert_eq!(transport.calls, 1);
    assert_eq!(failure.stage, "config");
    assert_eq!(failure.code, "config-conflict");
    assert_eq!(
        failure.claim_config_failure_disposition.as_deref(),
        Some("retain-same-device-resume")
    );
    assert_eq!(
        fs::read(fixture.paths.codex_home.join("config.toml")).unwrap(),
        original
    );
    assert!(!vault.contains(&CredentialHandle {
        service: "provider-codex-v4".to_string(),
        account: "550e8400-e29b-41d4-a716-446655440000".to_string(),
    }));
}
