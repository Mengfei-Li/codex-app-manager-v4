use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::DeliveryError;

pub const BOOTSTRAP_SCHEMA_VERSION: u32 = 1;
pub const RECEIPT_SCHEMA_VERSION: u32 = 1;
const MAX_CLOCK_SKEW_SECONDS: i64 = 300;
const MAX_BOOTSTRAP_LIFETIME_SECONDS: i64 = 24 * 60 * 60;
const MAX_RECEIPT_LIFETIME_SECONDS: i64 = 24 * 60 * 60;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapEnvelopePayload {
    pub schema_version: u32,
    pub issuer: String,
    pub audience: String,
    pub build_id: String,
    pub bootstrap_token: String,
    pub claim_endpoint_id: String,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    pub nonce: String,
}

impl Drop for BootstrapEnvelopePayload {
    fn drop(&mut self) {
        self.bootstrap_token.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedBootstrapEnvelope {
    pub payload: BootstrapEnvelopePayload,
    pub signature_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum LocaleMode {
    NativeSystem,
    ShortLivedRelay,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocaleContract {
    pub schema_version: u32,
    pub target_locale: String,
    pub required: bool,
    pub mode: LocaleMode,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct ClaimDelivery {
    pub api_key: String,
    pub management_token: String,
    pub locale_relay_bundle_b64: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClaimReceiptPayload {
    pub schema_version: u32,
    pub issuer: String,
    pub audience: String,
    pub build_id: String,
    pub installation_id: String,
    pub device_hash: String,
    pub claim_disposition: String,
    pub config_failure_disposition: String,
    pub already_claimed: bool,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    pub api_base_url: String,
    pub model: String,
    pub review_model: String,
    pub reasoning_effort: String,
    pub model_catalog_sha256: String,
    pub locale: LocaleContract,
    pub delivery_sha256: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedClaimReceipt {
    pub payload: ClaimReceiptPayload,
    pub signature_b64: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimResponse {
    pub receipt: SignedClaimReceipt,
    pub delivery: ClaimDelivery,
}

#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
pub struct ClaimRequest {
    pub schema_version: u32,
    pub bootstrap_token: String,
    pub device_hash: String,
    pub platform: String,
    pub architecture: String,
    pub system_locale: String,
    pub installer_build: String,
    pub idempotency_key: String,
    pub operation_id: String,
    pub app_health_verified: bool,
}

#[derive(Clone)]
pub struct VerificationPolicy {
    pub public_key: [u8; 32],
    pub expected_issuer: String,
    pub expected_audience: String,
    pub expected_build_id: String,
    pub expected_claim_endpoint_id: String,
    pub expected_device_hash: Option<String>,
    pub allowed_api_origins: Vec<String>,
    pub allow_loopback_http: bool,
}

pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, DeliveryError> {
    let value = serde_json::to_value(value)?;
    let sorted = sort_json(value);
    Ok(serde_json::to_vec(&sorted)?)
}

fn sort_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(sort_json).collect()),
        Value::Object(values) => {
            let ordered: BTreeMap<_, _> = values
                .into_iter()
                .map(|(key, value)| (key, sort_json(value)))
                .collect();
            Value::Object(ordered.into_iter().collect())
        }
        primitive => primitive,
    }
}

fn decode_signature(value: &str) -> Result<Signature, DeliveryError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| DeliveryError::InvalidEnvelope("signature encoding".to_string()))?;
    Signature::try_from(bytes.as_slice())
        .map_err(|_| DeliveryError::InvalidEnvelope("signature length".to_string()))
}

fn verifying_key(policy: &VerificationPolicy) -> Result<VerifyingKey, DeliveryError> {
    VerifyingKey::from_bytes(&policy.public_key)
        .map_err(|_| DeliveryError::InvalidEnvelope("public key".to_string()))
}

pub fn verify_envelope(
    envelope: &SignedBootstrapEnvelope,
    policy: &VerificationPolicy,
    now_unix: i64,
) -> Result<(), DeliveryError> {
    let payload = &envelope.payload;
    if payload.schema_version != BOOTSTRAP_SCHEMA_VERSION {
        return Err(DeliveryError::InvalidEnvelope("schema_version".to_string()));
    }
    if payload.issuer != policy.expected_issuer
        || payload.audience != policy.expected_audience
        || payload.build_id != policy.expected_build_id
        || payload.claim_endpoint_id != policy.expected_claim_endpoint_id
    {
        return Err(DeliveryError::InvalidEnvelope(
            "issuer, audience, build, or endpoint binding".to_string(),
        ));
    }
    if !valid_identifier(&payload.build_id, 3, 128)
        || !valid_identifier(&payload.nonce, 16, 128)
        || !valid_bootstrap_token(&payload.bootstrap_token)
    {
        return Err(DeliveryError::InvalidEnvelope(
            "identifier or token format".to_string(),
        ));
    }
    validate_time_window(
        payload.issued_at_unix,
        payload.expires_at_unix,
        now_unix,
        MAX_BOOTSTRAP_LIFETIME_SECONDS,
    )
    .map_err(|_| DeliveryError::EnvelopeTime)?;

    let bytes = canonical_json(payload)?;
    let signature = decode_signature(&envelope.signature_b64)?;
    verifying_key(policy)?
        .verify(&bytes, &signature)
        .map_err(|_| DeliveryError::EnvelopeSignature)
}

pub fn verify_claim_response(
    response: &ClaimResponse,
    policy: &VerificationPolicy,
    now_unix: i64,
) -> Result<(), DeliveryError> {
    let receipt = &response.receipt.payload;
    if receipt.schema_version != RECEIPT_SCHEMA_VERSION {
        return Err(DeliveryError::InvalidClaim("schema_version".to_string()));
    }
    if receipt.issuer != policy.expected_issuer
        || receipt.audience != policy.expected_audience
        || receipt.build_id != policy.expected_build_id
    {
        return Err(DeliveryError::InvalidClaim(
            "issuer, audience, or build binding".to_string(),
        ));
    }
    if let Some(expected) = &policy.expected_device_hash {
        if receipt.device_hash != *expected {
            return Err(DeliveryError::InvalidClaim("device binding".to_string()));
        }
    }
    if !valid_hex_sha256(&receipt.device_hash)
        || !valid_hex_sha256(&receipt.model_catalog_sha256)
        || !valid_hex_sha256(&receipt.delivery_sha256)
        || uuid::Uuid::parse_str(&receipt.installation_id).is_err()
        || !matches!(
            receipt.claim_disposition.as_str(),
            "claimed" | "same-device-resume"
        )
        || !matches!(
            receipt.config_failure_disposition.as_str(),
            "retain-same-device-resume" | "release"
        )
        || receipt.model.trim().is_empty()
        || receipt.review_model.trim().is_empty()
        || receipt.reasoning_effort.trim().is_empty()
    {
        return Err(DeliveryError::InvalidClaim(
            "required receipt fields".to_string(),
        ));
    }
    validate_time_window(
        receipt.issued_at_unix,
        receipt.expires_at_unix,
        now_unix,
        MAX_RECEIPT_LIFETIME_SECONDS,
    )
    .map_err(|_| DeliveryError::InvalidClaim("receipt time window".to_string()))?;
    validate_locale_contract(&receipt.locale, now_unix)?;
    validate_api_base(&receipt.api_base_url, policy)?;

    let signature = decode_signature(&response.receipt.signature_b64)
        .map_err(|_| DeliveryError::ReceiptSignature)?;
    let receipt_bytes = canonical_json(receipt)?;
    verifying_key(policy)?
        .verify(&receipt_bytes, &signature)
        .map_err(|_| DeliveryError::ReceiptSignature)?;

    let delivery_bytes = canonical_json(&response.delivery)?;
    if sha256_hex(&delivery_bytes) != receipt.delivery_sha256 {
        return Err(DeliveryError::DeliveryDigest);
    }
    if response.delivery.api_key.trim().is_empty()
        || response.delivery.management_token.trim().is_empty()
    {
        return Err(DeliveryError::InvalidClaim(
            "empty secret delivery".to_string(),
        ));
    }
    if receipt.locale.mode == LocaleMode::ShortLivedRelay
        && response
            .delivery
            .locale_relay_bundle_b64
            .as_deref()
            .unwrap_or_default()
            .is_empty()
    {
        return Err(DeliveryError::InvalidClaim(
            "relay locale delivery missing".to_string(),
        ));
    }
    Ok(())
}

fn validate_locale_contract(locale: &LocaleContract, now_unix: i64) -> Result<(), DeliveryError> {
    if locale.schema_version != 1 || normalize_locale(&locale.target_locale).is_none() {
        return Err(DeliveryError::Locale("schema or target locale".to_string()));
    }
    validate_time_window(
        locale.issued_at_unix,
        locale.expires_at_unix,
        now_unix,
        15 * 60,
    )
    .map_err(|_| DeliveryError::Locale("time window".to_string()))
}

fn validate_time_window(
    issued_at: i64,
    expires_at: i64,
    now_unix: i64,
    maximum_lifetime: i64,
) -> Result<(), ()> {
    if issued_at <= 0
        || expires_at <= issued_at
        || expires_at - issued_at > maximum_lifetime
        || now_unix + MAX_CLOCK_SKEW_SECONDS < issued_at
        || now_unix - MAX_CLOCK_SKEW_SECONDS > expires_at
    {
        return Err(());
    }
    Ok(())
}

fn validate_api_base(value: &str, policy: &VerificationPolicy) -> Result<(), DeliveryError> {
    let url =
        Url::parse(value).map_err(|_| DeliveryError::InvalidClaim("api_base_url".to_string()))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(DeliveryError::InvalidClaim(
            "api_base_url components".to_string(),
        ));
    }
    let loopback = url
        .host_str()
        .map(|host| matches!(host, "127.0.0.1" | "localhost" | "::1"))
        .unwrap_or(false);
    if url.scheme() == "http" && policy.allow_loopback_http && loopback {
        return Ok(());
    }
    if url.scheme() != "https" {
        return Err(DeliveryError::InvalidClaim(
            "api_base_url scheme".to_string(),
        ));
    }
    let origin = url.origin().ascii_serialization();
    if !policy
        .allowed_api_origins
        .iter()
        .any(|allowed| allowed == &origin)
    {
        return Err(DeliveryError::InvalidClaim(
            "api_base_url origin".to_string(),
        ));
    }
    Ok(())
}

pub fn hash_device_material(
    platform: &str,
    fields: &[(&str, &str)],
) -> Result<String, DeliveryError> {
    if !matches!(platform, "windows" | "macos") || fields.is_empty() || fields.len() > 8 {
        return Err(DeliveryError::InvalidEnvelope(
            "device material".to_string(),
        ));
    }
    let mut sorted = fields.to_vec();
    sorted.sort_unstable_by(|left, right| left.0.cmp(right.0));
    let mut digest = Sha256::new();
    digest.update(b"provider-codex-v4-device\0");
    digest.update(platform.as_bytes());
    for (name, value) in sorted {
        if !valid_identifier(name, 1, 64) || value.is_empty() || value.len() > 512 {
            return Err(DeliveryError::InvalidEnvelope("device field".to_string()));
        }
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name.as_bytes());
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    Ok(hex_lower(&digest.finalize()))
}

pub fn normalize_locale(raw: &str) -> Option<String> {
    let normalized = raw.trim().replace('_', "-");
    if normalized.is_empty() || normalized.len() > 35 {
        return None;
    }
    let parts: Vec<&str> = normalized.split('-').collect();
    let language = *parts.first()?;
    if !(2..=3).contains(&language.len())
        || !language.bytes().all(|byte| byte.is_ascii_alphabetic())
    {
        return None;
    }
    let mut output = vec![language.to_ascii_lowercase()];
    let mut script_seen = false;
    let mut region_seen = false;
    for part in parts.iter().skip(1) {
        if !(2..=8).contains(&part.len()) || !part.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return None;
        }
        if !script_seen
            && !region_seen
            && part.len() == 4
            && part.bytes().all(|byte| byte.is_ascii_alphabetic())
        {
            let mut script = part.to_ascii_lowercase();
            script[0..1].make_ascii_uppercase();
            output.push(script);
            script_seen = true;
        } else if !region_seen
            && ((part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_alphabetic()))
                || (part.len() == 3 && part.bytes().all(|byte| byte.is_ascii_digit())))
        {
            output.push(part.to_ascii_uppercase());
            region_seen = true;
        } else if (4..=8).contains(&part.len()) {
            output.push(part.to_ascii_lowercase());
        } else {
            return None;
        }
    }
    Some(output.join("-"))
}

fn valid_identifier(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_bootstrap_token(value: &str) -> bool {
    value.len() == 53
        && value.starts_with("boot_")
        && value[5..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
