use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::contract::{
    normalize_locale, sha256_hex, verify_claim_response, verify_envelope, ClaimDelivery,
    ClaimRequest, ClaimResponse, SignedBootstrapEnvelope, SignedClaimReceipt, VerificationPolicy,
};
use crate::error::DeliveryError;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimRecoveryAction {
    Retry,
    Redownload,
    OtherDevice,
    SignIn,
    Support,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualClaimDecision {
    Retry,
    Cancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManualRetryBudget {
    rounds_consumed: u8,
    maximum_rounds: u8,
    cancelled: bool,
}

impl Default for ManualRetryBudget {
    fn default() -> Self {
        Self {
            rounds_consumed: 0,
            maximum_rounds: 3,
            cancelled: false,
        }
    }
}

impl ManualRetryBudget {
    pub fn authorize(&mut self, decision: ManualClaimDecision) -> Result<u8, ClaimFailure> {
        if self.cancelled || decision == ManualClaimDecision::Cancel {
            self.cancelled = true;
            return Err(manual_failure(
                "claim_cancelled",
                ClaimRecoveryAction::Cancelled,
                self.rounds_consumed,
            ));
        }
        if self.rounds_consumed >= self.maximum_rounds {
            return Err(manual_failure(
                "manual_retry_exhausted",
                ClaimRecoveryAction::Support,
                self.rounds_consumed,
            ));
        }
        self.rounds_consumed += 1;
        Ok(self.rounds_consumed)
    }

    pub fn rounds_remaining(&self) -> u8 {
        if self.cancelled {
            0
        } else {
            self.maximum_rounds.saturating_sub(self.rounds_consumed)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaimTransportError {
    pub http_status: Option<u16>,
    pub server_code: String,
    pub safe_message: String,
    pub retry_after_ms: Option<u64>,
    pub retryable: bool,
}

impl ClaimTransportError {
    pub fn temporary(code: impl Into<String>) -> Self {
        Self {
            http_status: Some(503),
            server_code: code.into(),
            safe_message: "The claim service is temporarily unavailable.".to_string(),
            retry_after_ms: None,
            retryable: true,
        }
    }
}

pub trait ClaimTransport {
    fn claim(&mut self, request: &ClaimRequest) -> Result<ClaimResponse, ClaimTransportError>;
}

#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    pub maximum_attempts: u8,
    pub initial_backoff_ms: u64,
    pub maximum_backoff_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            maximum_attempts: 4,
            initial_backoff_ms: 250,
            maximum_backoff_ms: 4_000,
        }
    }
}

impl RetryPolicy {
    fn normalized(self) -> Self {
        Self {
            maximum_attempts: self.maximum_attempts.clamp(1, 4),
            initial_backoff_ms: self.initial_backoff_ms.min(10_000),
            maximum_backoff_ms: self.maximum_backoff_ms.clamp(1, 10_000),
        }
    }

    fn delay_ms(self, attempt: u8, server_delay: Option<u64>) -> u64 {
        let exponent = u32::from(attempt.saturating_sub(1)).min(8);
        let local = self
            .initial_backoff_ms
            .saturating_mul(2u64.saturating_pow(exponent))
            .min(self.maximum_backoff_ms);
        server_delay.unwrap_or(local).min(self.maximum_backoff_ms)
    }
}

pub struct ClaimOutcome {
    pub receipt: SignedClaimReceipt,
    pub delivery: ClaimDelivery,
    pub attempts: u8,
}

#[derive(Debug, Error)]
#[error("claim failed ({server_code}); recovery={recovery:?}")]
pub struct ClaimFailure {
    pub server_code: String,
    pub safe_message: String,
    pub http_status: Option<u16>,
    pub attempts: u8,
    pub recovery: ClaimRecoveryAction,
}

pub struct ClaimExecution<'a> {
    pub envelope: &'a SignedBootstrapEnvelope,
    pub device_hash: &'a str,
    pub platform: &'a str,
    pub architecture: &'a str,
    pub system_locale: &'a str,
    pub operation_id: &'a str,
    pub app_health_verified: bool,
    pub now_unix: i64,
}

pub struct ClaimCoordinator {
    policy: VerificationPolicy,
    retry: RetryPolicy,
}

impl ClaimCoordinator {
    pub fn new(policy: VerificationPolicy, retry: RetryPolicy) -> Self {
        Self {
            policy,
            retry: retry.normalized(),
        }
    }

    pub fn execute<T: ClaimTransport>(
        &self,
        execution: ClaimExecution<'_>,
        transport: &mut T,
    ) -> Result<ClaimOutcome, ClaimFailure> {
        verify_envelope(execution.envelope, &self.policy, execution.now_unix)
            .map_err(|error| local_failure(error, "bootstrap_envelope_invalid"))?;
        if !execution.app_health_verified {
            return Err(local_failure(
                DeliveryError::InvalidClaim("app health must precede claim".to_string()),
                "app_health_required",
            ));
        }
        if !matches!(execution.platform, "windows" | "macos")
            || !matches!(execution.architecture, "x64" | "arm64")
            || !is_sha256(execution.device_hash)
            || uuid::Uuid::parse_str(execution.operation_id).is_err()
        {
            return Err(local_failure(
                DeliveryError::InvalidClaim("claim context".to_string()),
                "claim_context_invalid",
            ));
        }
        let locale = normalize_locale(execution.system_locale).ok_or_else(|| {
            local_failure(
                DeliveryError::Locale("system locale".to_string()),
                "locale_invalid",
            )
        })?;
        let request = ClaimRequest {
            schema_version: 1,
            bootstrap_token: execution.envelope.payload.bootstrap_token.clone(),
            device_hash: execution.device_hash.to_string(),
            platform: execution.platform.to_string(),
            architecture: execution.architecture.to_string(),
            system_locale: locale,
            installer_build: execution.envelope.payload.build_id.clone(),
            idempotency_key: idempotency_key(
                &execution.envelope.payload.nonce,
                execution.device_hash,
                &execution.envelope.payload.build_id,
            ),
            operation_id: execution.operation_id.to_string(),
            app_health_verified: true,
        };

        for attempt in 1..=self.retry.maximum_attempts {
            match transport.claim(&request) {
                Ok(response) => {
                    verify_claim_response(&response, &self.policy, execution.now_unix)
                        .map_err(|error| local_failure(error, "claim_receipt_invalid"))?;
                    return Ok(ClaimOutcome {
                        receipt: response.receipt,
                        delivery: response.delivery,
                        attempts: attempt,
                    });
                }
                Err(error) if error.retryable && attempt < self.retry.maximum_attempts => {
                    let delay = self.retry.delay_ms(attempt, error.retry_after_ms);
                    if delay > 0 {
                        std::thread::sleep(Duration::from_millis(delay));
                    }
                }
                Err(error) => return Err(transport_failure(error, attempt)),
            }
        }
        unreachable!("bounded retry loop always returns")
    }
}

fn idempotency_key(nonce: &str, device_hash: &str, build_id: &str) -> String {
    let mut material = Vec::with_capacity(nonce.len() + device_hash.len() + build_id.len() + 25);
    material.extend_from_slice(b"provider-codex-v4-claim\0");
    material.extend_from_slice(nonce.as_bytes());
    material.extend_from_slice(device_hash.as_bytes());
    material.extend_from_slice(build_id.as_bytes());
    sha256_hex(&material)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn local_failure(error: DeliveryError, code: &str) -> ClaimFailure {
    ClaimFailure {
        server_code: code.to_string(),
        safe_message: error.to_string(),
        http_status: None,
        attempts: 0,
        recovery: ClaimRecoveryAction::Redownload,
    }
}

fn transport_failure(error: ClaimTransportError, attempts: u8) -> ClaimFailure {
    let recovery = match (error.http_status, error.server_code.as_str()) {
        (_, "bootstrap_device_mismatch" | "device_occupied") => ClaimRecoveryAction::OtherDevice,
        (_, "stale_installer" | "bootstrap_expired" | "bootstrap_unavailable")
        | (Some(404 | 410), _) => ClaimRecoveryAction::Redownload,
        (Some(401), _) => ClaimRecoveryAction::SignIn,
        (Some(429 | 500..=599), _) if error.retryable => ClaimRecoveryAction::Retry,
        _ => ClaimRecoveryAction::Support,
    };
    ClaimFailure {
        server_code: error.server_code,
        safe_message: error.safe_message,
        http_status: error.http_status,
        attempts,
        recovery,
    }
}

fn manual_failure(code: &str, recovery: ClaimRecoveryAction, rounds: u8) -> ClaimFailure {
    ClaimFailure {
        server_code: code.to_string(),
        safe_message: code.to_string(),
        http_status: None,
        attempts: rounds,
        recovery,
    }
}
