use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use codex_delivery_engine::{
    verify_claim_response, verify_envelope, ClaimResponse, SignedBootstrapEnvelope,
    VerificationPolicy,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PortalFixture {
    fixture_schema_version: u32,
    generated_by: String,
    now_unix: i64,
    verification_policy: FixturePolicy,
    bootstrap_envelope: SignedBootstrapEnvelope,
    claim_response: ClaimResponse,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixturePolicy {
    public_key_b64: String,
    expected_issuer: String,
    expected_audience: String,
    expected_build_id: String,
    expected_claim_endpoint_id: String,
    expected_device_hash: String,
    allowed_api_origins: Vec<String>,
    allow_loopback_http: bool,
}

fn fixture() -> PortalFixture {
    serde_json::from_str(include_str!("fixtures/portal-v4-claim.json"))
        .expect("Portal fixture must remain valid JSON")
}

fn policy(value: &FixturePolicy) -> VerificationPolicy {
    let public_key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&value.public_key_b64)
        .expect("fixture public key must be base64url")
        .try_into()
        .expect("fixture public key must be Ed25519 length");
    VerificationPolicy {
        public_key,
        expected_issuer: value.expected_issuer.clone(),
        expected_audience: value.expected_audience.clone(),
        expected_build_id: value.expected_build_id.clone(),
        expected_claim_endpoint_id: value.expected_claim_endpoint_id.clone(),
        expected_device_hash: Some(value.expected_device_hash.clone()),
        allowed_api_origins: value.allowed_api_origins.clone(),
        allow_loopback_http: value.allow_loopback_http,
    }
}

#[test]
fn python_portal_signature_and_canonical_json_verify_in_rust() {
    let fixture = fixture();
    assert_eq!(fixture.fixture_schema_version, 1);
    assert_eq!(
        fixture.generated_by,
        "sub2api-customer-portal/scripts/generate_v4_contract_fixture.py"
    );
    verify_claim_response(
        &fixture.claim_response,
        &policy(&fixture.verification_policy),
        fixture.now_unix,
    )
    .expect("Python Portal claim must verify byte-for-byte in Rust Manager");
    verify_envelope(
        &fixture.bootstrap_envelope,
        &policy(&fixture.verification_policy),
        fixture.now_unix,
    )
    .expect("Python Portal bootstrap envelope must verify byte-for-byte in Rust Manager");
}

#[test]
fn cross_language_bootstrap_fails_closed_after_build_tamper() {
    let mut fixture = fixture();
    fixture.bootstrap_envelope.payload.build_id.push('x');
    assert!(verify_envelope(
        &fixture.bootstrap_envelope,
        &policy(&fixture.verification_policy),
        fixture.now_unix,
    )
    .is_err());
}

#[test]
fn cross_language_fixture_fails_closed_after_delivery_tamper() {
    let mut fixture = fixture();
    fixture.claim_response.delivery.api_key.push('x');
    assert!(verify_claim_response(
        &fixture.claim_response,
        &policy(&fixture.verification_policy),
        fixture.now_unix,
    )
    .is_err());
}
