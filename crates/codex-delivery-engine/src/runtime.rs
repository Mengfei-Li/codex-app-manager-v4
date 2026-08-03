use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::error::DeliveryError;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeMode {
    Interactive,
    NonInteractive,
    Test,
    EndToEnd,
    RealSandbox,
}

#[derive(Debug, Clone)]
pub struct EndpointPolicy {
    pub production_claim: Url,
    pub sandbox_claim: Url,
}

impl EndpointPolicy {
    pub fn select_claim_endpoint(
        &self,
        mode: RuntimeMode,
        requested_override: Option<&Url>,
    ) -> Result<Url, DeliveryError> {
        match mode {
            RuntimeMode::Interactive | RuntimeMode::NonInteractive => {
                reject_different_override(requested_override, &self.production_claim)?;
                Ok(self.production_claim.clone())
            }
            RuntimeMode::EndToEnd | RuntimeMode::RealSandbox => {
                reject_different_override(requested_override, &self.sandbox_claim)?;
                Ok(self.sandbox_claim.clone())
            }
            RuntimeMode::Test => {
                let requested = requested_override.ok_or_else(|| {
                    DeliveryError::InvalidEnvelope("test-endpoint-required".to_string())
                })?;
                let is_loopback = match requested.host() {
                    Some(Host::Ipv4(ip)) => ip.is_loopback(),
                    Some(Host::Ipv6(ip)) => ip.is_loopback(),
                    _ => false,
                };
                if !is_loopback || !matches!(requested.scheme(), "http" | "https") {
                    return Err(DeliveryError::InvalidEnvelope(
                        "test-endpoint-must-be-loopback".to_string(),
                    ));
                }
                Ok(requested.clone())
            }
        }
    }

    pub fn requires_usage_lifecycle(mode: RuntimeMode) -> bool {
        matches!(mode, RuntimeMode::EndToEnd | RuntimeMode::RealSandbox)
    }
}

fn reject_different_override(requested: Option<&Url>, pinned: &Url) -> Result<(), DeliveryError> {
    if requested.is_some_and(|value| value != pinned) {
        return Err(DeliveryError::InvalidEnvelope(
            "endpoint-override-forbidden".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{EndpointPolicy, RuntimeMode};
    use url::Url;

    fn policy() -> EndpointPolicy {
        EndpointPolicy {
            production_claim: Url::parse("https://claim.example.invalid/v4").unwrap(),
            sandbox_claim: Url::parse("https://sandbox.example.invalid/v4").unwrap(),
        }
    }

    #[test]
    fn production_and_sandbox_modes_are_pinned() {
        let policy = policy();
        assert_eq!(
            policy
                .select_claim_endpoint(RuntimeMode::Interactive, None)
                .unwrap(),
            policy.production_claim
        );
        assert!(policy
            .select_claim_endpoint(
                RuntimeMode::NonInteractive,
                Some(&Url::parse("https://attacker.invalid").unwrap())
            )
            .is_err());
        assert_eq!(
            policy
                .select_claim_endpoint(RuntimeMode::EndToEnd, None)
                .unwrap(),
            policy.sandbox_claim
        );
    }

    #[test]
    fn test_mode_accepts_only_ip_loopback() {
        let policy = policy();
        for value in ["http://127.0.0.1:1234/v4", "http://[::1]:1234/v4"] {
            assert!(policy
                .select_claim_endpoint(RuntimeMode::Test, Some(&Url::parse(value).unwrap()))
                .is_ok());
        }
        for value in ["https://example.invalid/v4", "http://localhost:1234/v4"] {
            assert!(policy
                .select_claim_endpoint(RuntimeMode::Test, Some(&Url::parse(value).unwrap()))
                .is_err());
        }
    }
}
