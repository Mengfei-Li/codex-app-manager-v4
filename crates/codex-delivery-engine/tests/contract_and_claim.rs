use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use codex_delivery_engine::contract::{sha256_hex, LocaleContract, LocaleMode};
use codex_delivery_engine::{
    canonical_json, hash_device_material, verify_claim_response, verify_envelope,
    BootstrapEnvelopePayload, ClaimCoordinator, ClaimDelivery, ClaimExecution, ClaimFailure,
    ClaimOutcome, ClaimReceiptPayload, ClaimRecoveryAction, ClaimRequest, ClaimResponse,
    ClaimTransport, ClaimTransportError, ManualClaimDecision, ManualRetryBudget, RetryPolicy,
    SignedBootstrapEnvelope, SignedClaimReceipt, VerificationPolicy,
};
use ed25519_dalek::{Signer, SigningKey};

const NOW: i64 = 1_786_000_000;
const BUILD: &str = "v4-g3-test-20260804";
const DEVICE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn policy() -> VerificationPolicy {
    VerificationPolicy {
        public_key: signing_key().verifying_key().to_bytes(),
        expected_issuer: "provider-codex-v4".to_string(),
        expected_audience: "codex-app-manager".to_string(),
        expected_build_id: BUILD.to_string(),
        expected_claim_endpoint_id: "portal-v4".to_string(),
        expected_device_hash: Some(DEVICE.to_string()),
        allowed_api_origins: vec!["https://api.2466335.xyz".to_string()],
        allow_loopback_http: false,
    }
}

fn sign<T: serde::Serialize>(value: &T) -> String {
    let bytes = canonical_json(value).unwrap();
    URL_SAFE_NO_PAD.encode(signing_key().sign(&bytes).to_bytes())
}

fn envelope() -> SignedBootstrapEnvelope {
    let payload = BootstrapEnvelopePayload {
        schema_version: 1,
        issuer: "provider-codex-v4".to_string(),
        audience: "codex-app-manager".to_string(),
        build_id: BUILD.to_string(),
        bootstrap_token: format!("boot_{}", "A".repeat(48)),
        claim_endpoint_id: "portal-v4".to_string(),
        issued_at_unix: NOW - 30,
        expires_at_unix: NOW + 600,
        nonce: "nonce_0123456789abcdef".to_string(),
    };
    let signature_b64 = sign(&payload);
    SignedBootstrapEnvelope {
        payload,
        signature_b64,
    }
}

fn response() -> ClaimResponse {
    let delivery = ClaimDelivery {
        api_key: "sk-test-secret-never-log".to_string(),
        management_token: "mgmt_test_secret_never_log".to_string(),
        locale_relay_bundle_b64: None,
    };
    let delivery_sha256 = sha256_hex(&canonical_json(&delivery).unwrap());
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
        issued_at_unix: NOW - 10,
        expires_at_unix: NOW + 600,
        api_base_url: "https://api.2466335.xyz/v1".to_string(),
        model: "gpt-5.6-sol".to_string(),
        review_model: "gpt-5.6-sol".to_string(),
        reasoning_effort: "high".to_string(),
        model_catalog_sha256: "b".repeat(64),
        locale: LocaleContract {
            schema_version: 1,
            target_locale: "zh-CN".to_string(),
            required: true,
            mode: LocaleMode::NativeSystem,
            issued_at_unix: NOW - 10,
            expires_at_unix: NOW + 300,
        },
        delivery_sha256,
    };
    let signature_b64 = sign(&payload);
    ClaimResponse {
        receipt: SignedClaimReceipt {
            payload,
            signature_b64,
        },
        delivery,
    }
}

fn execution<'a>(envelope: &'a SignedBootstrapEnvelope) -> ClaimExecution<'a> {
    ClaimExecution {
        envelope,
        device_hash: DEVICE,
        platform: "windows",
        architecture: "x64",
        system_locale: "zh_cn",
        operation_id: "28d596c6-4c43-4f8a-8826-b0aa306f1234",
        app_health_verified: true,
        now_unix: NOW,
    }
}

fn expect_failure(result: Result<ClaimOutcome, ClaimFailure>) -> ClaimFailure {
    match result {
        Ok(_) => panic!("expected claim failure"),
        Err(error) => error,
    }
}

#[test]
fn signed_envelope_and_receipt_are_bound_to_build_device_and_delivery() {
    let envelope = envelope();
    verify_envelope(&envelope, &policy(), NOW).unwrap();
    verify_claim_response(&response(), &policy(), NOW).unwrap();

    let mut tampered = response();
    tampered.receipt.payload.model = "unexpected".to_string();
    assert!(verify_claim_response(&tampered, &policy(), NOW).is_err());

    let mut tampered_delivery = response();
    tampered_delivery.delivery.api_key.push_str("-changed");
    assert!(verify_claim_response(&tampered_delivery, &policy(), NOW).is_err());
}

#[test]
fn envelope_time_build_and_endpoint_are_fail_closed() {
    let mut stale = envelope();
    stale.payload.expires_at_unix = NOW - 1_000;
    stale.signature_b64 = sign(&stale.payload);
    assert!(verify_envelope(&stale, &policy(), NOW).is_err());

    let mut wrong_build = envelope();
    wrong_build.payload.build_id = "other-build".to_string();
    wrong_build.signature_b64 = sign(&wrong_build.payload);
    assert!(verify_envelope(&wrong_build, &policy(), NOW).is_err());

    let mut wrong_endpoint = envelope();
    wrong_endpoint.payload.claim_endpoint_id = "untrusted".to_string();
    wrong_endpoint.signature_b64 = sign(&wrong_endpoint.payload);
    assert!(verify_envelope(&wrong_endpoint, &policy(), NOW).is_err());
}

#[test]
fn api_origin_and_locale_relay_contract_are_enforced() {
    let mut wrong_origin = response();
    wrong_origin.receipt.payload.api_base_url = "https://evil.example/v1".to_string();
    wrong_origin.receipt.signature_b64 = sign(&wrong_origin.receipt.payload);
    assert!(verify_claim_response(&wrong_origin, &policy(), NOW).is_err());

    let mut missing_relay = response();
    missing_relay.receipt.payload.locale.mode = LocaleMode::ShortLivedRelay;
    missing_relay.receipt.signature_b64 = sign(&missing_relay.receipt.payload);
    assert!(verify_claim_response(&missing_relay, &policy(), NOW).is_err());
}

#[test]
fn device_hash_is_order_independent_but_field_sensitive() {
    let left = hash_device_material(
        "windows",
        &[("user-sid", "S-1-5-21-test"), ("machine-guid", "machine-a")],
    )
    .unwrap();
    let right = hash_device_material(
        "windows",
        &[("machine-guid", "machine-a"), ("user-sid", "S-1-5-21-test")],
    )
    .unwrap();
    let changed = hash_device_material(
        "windows",
        &[("machine-guid", "machine-b"), ("user-sid", "S-1-5-21-test")],
    )
    .unwrap();
    assert_eq!(left, right);
    assert_ne!(left, changed);
    assert_eq!(left.len(), 64);
}

struct MockTransport {
    failures: Vec<ClaimTransportError>,
    response: Option<ClaimResponse>,
    idempotency_keys: Vec<String>,
    locales: Vec<String>,
}

impl ClaimTransport for MockTransport {
    fn claim(&mut self, request: &ClaimRequest) -> Result<ClaimResponse, ClaimTransportError> {
        self.idempotency_keys.push(request.idempotency_key.clone());
        self.locales.push(request.system_locale.clone());
        if !self.failures.is_empty() {
            return Err(self.failures.remove(0));
        }
        Ok(self.response.take().expect("one success response"))
    }
}

#[test]
fn claim_retries_are_bounded_and_reuse_the_same_idempotency_key() {
    let envelope = envelope();
    let coordinator = ClaimCoordinator::new(
        policy(),
        RetryPolicy {
            maximum_attempts: 4,
            initial_backoff_ms: 0,
            maximum_backoff_ms: 1,
        },
    );
    let mut transport = MockTransport {
        failures: vec![
            ClaimTransportError::temporary("database_busy"),
            ClaimTransportError::temporary("upstream_timeout"),
        ],
        response: Some(response()),
        idempotency_keys: Vec::new(),
        locales: Vec::new(),
    };
    let result = coordinator
        .execute(execution(&envelope), &mut transport)
        .unwrap();
    assert_eq!(result.attempts, 3);
    assert_eq!(transport.idempotency_keys.len(), 3);
    assert!(transport
        .idempotency_keys
        .windows(2)
        .all(|pair| pair[0] == pair[1]));
    assert!(transport.locales.iter().all(|locale| locale == "zh-CN"));
}

#[test]
fn permanent_errors_get_stable_distinct_recovery_actions() {
    let cases = [
        (
            409,
            "bootstrap_device_mismatch",
            ClaimRecoveryAction::OtherDevice,
        ),
        (410, "bootstrap_expired", ClaimRecoveryAction::Redownload),
        (401, "credential_invalid", ClaimRecoveryAction::SignIn),
        (422, "claim_contract_invalid", ClaimRecoveryAction::Support),
    ];
    for (status, code, expected) in cases {
        let envelope = envelope();
        let mut transport = MockTransport {
            failures: vec![ClaimTransportError {
                http_status: Some(status),
                server_code: code.to_string(),
                safe_message: "safe".to_string(),
                retry_after_ms: None,
                retryable: false,
            }],
            response: None,
            idempotency_keys: Vec::new(),
            locales: Vec::new(),
        };
        let failure = expect_failure(
            ClaimCoordinator::new(policy(), RetryPolicy::default())
                .execute(execution(&envelope), &mut transport),
        );
        assert_eq!(failure.recovery, expected);
        assert_eq!(failure.attempts, 1);
    }
}

#[test]
fn interactive_claim_retry_is_bounded_to_three_rounds_and_cancel_is_terminal() {
    let mut budget = ManualRetryBudget::default();
    assert_eq!(budget.rounds_remaining(), 3);
    assert_eq!(budget.authorize(ManualClaimDecision::Retry).unwrap(), 1);
    assert_eq!(budget.authorize(ManualClaimDecision::Retry).unwrap(), 2);
    assert_eq!(budget.authorize(ManualClaimDecision::Retry).unwrap(), 3);
    assert_eq!(budget.rounds_remaining(), 0);
    let exhausted = budget.authorize(ManualClaimDecision::Retry).unwrap_err();
    assert_eq!(exhausted.server_code, "manual_retry_exhausted");
    assert_eq!(exhausted.recovery, ClaimRecoveryAction::Support);

    let mut cancelled = ManualRetryBudget::default();
    let failure = cancelled
        .authorize(ManualClaimDecision::Cancel)
        .unwrap_err();
    assert_eq!(failure.recovery, ClaimRecoveryAction::Cancelled);
    assert_eq!(cancelled.rounds_remaining(), 0);
    assert!(cancelled.authorize(ManualClaimDecision::Retry).is_err());
}

#[test]
fn claim_is_not_consumed_before_platform_health() {
    let envelope = envelope();
    let mut execution = execution(&envelope);
    execution.app_health_verified = false;
    let mut transport = MockTransport {
        failures: Vec::new(),
        response: Some(response()),
        idempotency_keys: Vec::new(),
        locales: Vec::new(),
    };
    let failure = expect_failure(
        ClaimCoordinator::new(policy(), RetryPolicy::default()).execute(execution, &mut transport),
    );
    assert_eq!(failure.server_code, "app_health_required");
    assert!(transport.idempotency_keys.is_empty());
}

#[test]
fn transient_failure_stops_at_four_attempts() {
    let envelope = envelope();
    let mut transport = MockTransport {
        failures: (0..8)
            .map(|_| ClaimTransportError::temporary("temporary"))
            .collect(),
        response: None,
        idempotency_keys: Vec::new(),
        locales: Vec::new(),
    };
    let failure = expect_failure(
        ClaimCoordinator::new(
            policy(),
            RetryPolicy {
                maximum_attempts: 99,
                initial_backoff_ms: 0,
                maximum_backoff_ms: 1,
            },
        )
        .execute(execution(&envelope), &mut transport),
    );
    assert_eq!(failure.attempts, 4);
    assert_eq!(transport.idempotency_keys.len(), 4);
    assert_eq!(failure.recovery, ClaimRecoveryAction::Retry);
}
