use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::contract::{normalize_locale, LocaleContract, LocaleMode};
use crate::error::DeliveryError;

const MAX_RELAY_BUNDLE_BYTES: usize = 64 * 1024;
const MAX_RELAY_LIFETIME_SECONDS: i64 = 15 * 60;
const CLOCK_SKEW_SECONDS: i64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LocaleTaskState {
    Succeeded,
    Skipped,
    FailedRetryable,
    FailedPermanent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocaleTaskReport {
    pub schema_version: u32,
    pub target_locale: String,
    pub mode: LocaleMode,
    pub state: LocaleTaskState,
    pub attempts: u8,
    pub error_code: Option<String>,
    pub config_rollback_required: bool,
    pub app_rollback_required: bool,
}

#[derive(Debug, Clone)]
pub struct LocaleInitError {
    pub code: String,
    pub retryable: bool,
}

pub trait LocaleInitializer {
    fn initialize(
        &mut self,
        contract: &LocaleContract,
        relay_bundle: Option<&[u8]>,
    ) -> Result<(), LocaleInitError>;
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayBundle {
    schema_version: u32,
    target_locale: String,
    issued_at_unix: i64,
    expires_at_unix: i64,
    payload: serde_json::Value,
}

pub fn run_locale_task<I: LocaleInitializer>(
    contract: &LocaleContract,
    expected_locale: &str,
    relay_bundle_b64: Option<&str>,
    now_unix: i64,
    initializer: &mut I,
) -> LocaleTaskReport {
    let target =
        normalize_locale(&contract.target_locale).unwrap_or_else(|| contract.target_locale.clone());
    let mut report = LocaleTaskReport {
        schema_version: 1,
        target_locale: target,
        mode: contract.mode.clone(),
        state: LocaleTaskState::FailedPermanent,
        attempts: 0,
        error_code: None,
        config_rollback_required: false,
        app_rollback_required: false,
    };
    if let Err(error) = validate_contract(contract, expected_locale, now_unix) {
        report.error_code = Some(locale_error_code(error));
        return report;
    }
    if !contract.required {
        report.state = LocaleTaskState::Skipped;
        return report;
    }

    let decoded = match contract.mode {
        LocaleMode::NativeSystem => None,
        LocaleMode::ShortLivedRelay => {
            match decode_relay(relay_bundle_b64, &contract.target_locale, now_unix) {
                Ok(bytes) => Some(bytes),
                Err(error) => {
                    report.error_code = Some(locale_error_code(error));
                    return report;
                }
            }
        }
    };
    report.attempts = 1;
    match initializer.initialize(contract, decoded.as_deref().map(Vec::as_slice)) {
        Ok(()) => report.state = LocaleTaskState::Succeeded,
        Err(error) => {
            report.error_code = Some(error.code);
            report.state = if error.retryable {
                LocaleTaskState::FailedRetryable
            } else {
                LocaleTaskState::FailedPermanent
            };
        }
    }
    report
}

fn locale_error_code(error: DeliveryError) -> String {
    match error {
        DeliveryError::Locale(code) => code,
        _ => "locale-internal-error".to_string(),
    }
}

fn validate_contract(
    contract: &LocaleContract,
    expected_locale: &str,
    now_unix: i64,
) -> Result<(), DeliveryError> {
    let target = normalize_locale(&contract.target_locale)
        .ok_or_else(|| DeliveryError::Locale("target-locale-invalid".to_string()))?;
    let expected = normalize_locale(expected_locale)
        .ok_or_else(|| DeliveryError::Locale("expected-locale-invalid".to_string()))?;
    if contract.schema_version != 1 || target != expected {
        return Err(DeliveryError::Locale(
            "locale-contract-mismatch".to_string(),
        ));
    }
    validate_time(contract.issued_at_unix, contract.expires_at_unix, now_unix)
}

fn decode_relay(
    value: Option<&str>,
    expected_locale: &str,
    now_unix: i64,
) -> Result<Zeroizing<Vec<u8>>, DeliveryError> {
    let encoded = value.ok_or_else(|| DeliveryError::Locale("relay-missing".to_string()))?;
    let bytes = Zeroizing::new(
        STANDARD
            .decode(encoded)
            .map_err(|_| DeliveryError::Locale("relay-base64-invalid".to_string()))?,
    );
    if bytes.is_empty() || bytes.len() > MAX_RELAY_BUNDLE_BYTES {
        return Err(DeliveryError::Locale("relay-size-invalid".to_string()));
    }
    let bundle: RelayBundle = serde_json::from_slice(&bytes)
        .map_err(|_| DeliveryError::Locale("relay-json-invalid".to_string()))?;
    if bundle.schema_version != 1
        || normalize_locale(&bundle.target_locale) != normalize_locale(expected_locale)
        || !bundle.payload.is_object()
    {
        return Err(DeliveryError::Locale("relay-contract-invalid".to_string()));
    }
    validate_time(bundle.issued_at_unix, bundle.expires_at_unix, now_unix)?;
    Ok(bytes)
}

fn validate_time(issued: i64, expires: i64, now: i64) -> Result<(), DeliveryError> {
    if issued <= 0
        || expires <= issued
        || expires - issued > MAX_RELAY_LIFETIME_SECONDS
        || now + CLOCK_SKEW_SECONDS < issued
        || now - CLOCK_SKEW_SECONDS > expires
    {
        return Err(DeliveryError::Locale("locale-time-invalid".to_string()));
    }
    Ok(())
}
