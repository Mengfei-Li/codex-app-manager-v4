use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use codex_delivery_engine::{
    verify_envelope, ClaimRequest, ClaimResponse, ClaimTransport, ClaimTransportError,
    SignedBootstrapEnvelope, VerificationPolicy,
};
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

const MAX_CLAIM_RESPONSE_BYTES: u64 = 1024 * 1024;
const MAX_BOOTSTRAP_SIDECAR_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BootstrapSidecarError {
    pub code: String,
}

pub struct LoadedBootstrapSidecar {
    path: PathBuf,
    envelope: SignedBootstrapEnvelope,
}

impl LoadedBootstrapSidecar {
    pub fn envelope(&self) -> &SignedBootstrapEnvelope {
        &self.envelope
    }

    pub fn bootstrap_token(&self) -> Zeroizing<String> {
        Zeroizing::new(self.envelope.payload.bootstrap_token.clone())
    }

    pub fn retire(self) -> Result<(), BootstrapSidecarError> {
        let path = self.path.clone();
        drop(self);
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(sidecar_error("bootstrap-sidecar-retire-failed")),
        }
    }
}

pub fn load_bootstrap_sidecar(
    path: &Path,
    policy: &VerificationPolicy,
    now_unix: i64,
) -> Result<LoadedBootstrapSidecar, BootstrapSidecarError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| sidecar_error("bootstrap-sidecar-missing"))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_BOOTSTRAP_SIDECAR_BYTES
    {
        return Err(sidecar_error("bootstrap-sidecar-invalid"));
    }
    codex_delivery_engine::security::harden_control_path(path, false)
        .map_err(|_| sidecar_error("bootstrap-sidecar-permissions"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(|_| sidecar_error("bootstrap-sidecar-open"))?
        .take(MAX_BOOTSTRAP_SIDECAR_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| sidecar_error("bootstrap-sidecar-read"))?;
    if bytes.len() as u64 > MAX_BOOTSTRAP_SIDECAR_BYTES {
        return Err(sidecar_error("bootstrap-sidecar-invalid"));
    }
    let envelope: SignedBootstrapEnvelope =
        serde_json::from_slice(&bytes).map_err(|_| sidecar_error("bootstrap-sidecar-contract"))?;
    verify_envelope(&envelope, policy, now_unix)
        .map_err(|_| sidecar_error("bootstrap-sidecar-verification"))?;
    Ok(LoadedBootstrapSidecar {
        path: path.to_path_buf(),
        envelope,
    })
}

fn sidecar_error(code: &str) -> BootstrapSidecarError {
    BootstrapSidecarError {
        code: code.to_string(),
    }
}

pub struct HttpClaimTransport {
    client: Client,
    endpoint: Url,
}

impl HttpClaimTransport {
    pub fn new(endpoint: Url) -> Result<Self, ClaimTransportError> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .redirect(Policy::none())
            .build()
            .map_err(|_| transport_error(None, "claim-client-build", false, None))?;
        Ok(Self { client, endpoint })
    }
}

#[derive(Deserialize)]
struct PortalClaimResponse {
    ok: bool,
    data: Option<ClaimResponse>,
    error: Option<String>,
    message: Option<String>,
}

impl ClaimTransport for HttpClaimTransport {
    fn claim(&mut self, request: &ClaimRequest) -> Result<ClaimResponse, ClaimTransportError> {
        let body = serde_json::to_vec(request)
            .map_err(|_| transport_error(None, "claim-request-encode", false, None))?;
        let response = self
            .client
            .post(self.endpoint.clone())
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .body(body)
            .send()
            .map_err(|error| {
                transport_error(
                    None,
                    if error.is_timeout() {
                        "claim-timeout"
                    } else {
                        "claim-network"
                    },
                    true,
                    None,
                )
            })?;
        let status = response.status().as_u16();
        let retry_after_ms = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .map(|seconds| seconds.saturating_mul(1000).min(30_000));
        if response
            .content_length()
            .is_some_and(|length| length > MAX_CLAIM_RESPONSE_BYTES)
        {
            return Err(transport_error(
                Some(status),
                "claim-response-too-large",
                false,
                None,
            ));
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_CLAIM_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| transport_error(Some(status), "claim-response-read", true, None))?;
        if bytes.len() as u64 > MAX_CLAIM_RESPONSE_BYTES {
            return Err(transport_error(
                Some(status),
                "claim-response-too-large",
                false,
                None,
            ));
        }
        let portal: PortalClaimResponse = serde_json::from_slice(&bytes).map_err(|_| {
            transport_error(
                Some(status),
                "claim-response-invalid",
                false,
                retry_after_ms,
            )
        })?;
        if (200..300).contains(&status) && portal.ok {
            return portal.data.ok_or_else(|| {
                transport_error(Some(status), "claim-response-missing", false, None)
            });
        }
        let code = portal
            .error
            .as_deref()
            .filter(|value| safe_code(value))
            .unwrap_or("claim-server-error");
        let retryable = status == 429 || status >= 500;
        let _safe_public_message = portal.message;
        Err(transport_error(
            Some(status),
            code,
            retryable,
            retry_after_ms,
        ))
    }
}

fn safe_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn transport_error(
    status: Option<u16>,
    code: &str,
    retryable: bool,
    retry_after_ms: Option<u64>,
) -> ClaimTransportError {
    ClaimTransportError {
        http_status: status,
        server_code: code.to_string(),
        safe_message: code.to_string(),
        retryable,
        retry_after_ms,
    }
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    fn contract_fixture() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../crates/codex-delivery-engine/tests/fixtures/portal-v4-claim.json"
        ))
        .expect("fixture JSON")
    }

    fn fixture_policy() -> VerificationPolicy {
        let fixture = contract_fixture();
        let policy = &fixture["verification_policy"];
        let public_key: [u8; 32] = URL_SAFE_NO_PAD
            .decode(policy["public_key_b64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        VerificationPolicy {
            public_key,
            expected_issuer: policy["expected_issuer"].as_str().unwrap().to_string(),
            expected_audience: policy["expected_audience"].as_str().unwrap().to_string(),
            expected_build_id: policy["expected_build_id"].as_str().unwrap().to_string(),
            expected_claim_endpoint_id: policy["expected_claim_endpoint_id"]
                .as_str()
                .unwrap()
                .to_string(),
            expected_device_hash: None,
            allowed_api_origins: policy["allowed_api_origins"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_string())
                .collect(),
            allow_loopback_http: false,
        }
    }

    fn request() -> ClaimRequest {
        ClaimRequest {
            schema_version: 1,
            bootstrap_token: format!("boot_{}", "a".repeat(48)),
            device_hash: "a".repeat(64),
            platform: "windows".to_string(),
            architecture: "x64".to_string(),
            system_locale: "en-US".to_string(),
            installer_build: "v4-g3-test-20260804".to_string(),
            idempotency_key: "b".repeat(64),
            operation_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            app_health_verified: true,
        }
    }

    fn serve_once(status: &str, headers: &[(&str, &str)], body: Vec<u8>) -> Url {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let address = listener.local_addr().expect("loopback address");
        let status = status.to_string();
        let headers: Vec<(String, String)> = headers
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            let mut request_bytes = vec![0_u8; 64 * 1024];
            let read = stream.read(&mut request_bytes).expect("read request");
            assert!(request_bytes[..read].starts_with(b"POST /api/bootstrap/v4/claim "));
            let mut response = format!("HTTP/1.1 {status}\r\nConnection: close\r\n");
            for (name, value) in headers {
                response.push_str(&format!("{name}: {value}\r\n"));
            }
            if !response.to_ascii_lowercase().contains("content-length:") {
                response.push_str(&format!("Content-Length: {}\r\n", body.len()));
            }
            response.push_str("Content-Type: application/json\r\n\r\n");
            stream
                .write_all(response.as_bytes())
                .expect("write headers");
            stream.write_all(&body).expect("write body");
        });
        Url::parse(&format!("http://{address}/api/bootstrap/v4/claim")).expect("loopback endpoint")
    }

    #[test]
    fn loopback_portal_success_is_deserialized_without_renderer_secret_handoff() {
        let fixture = contract_fixture();
        let body = serde_json::to_vec(&serde_json::json!({
            "ok": true,
            "data": fixture["claim_response"].clone()
        }))
        .expect("response JSON");
        let endpoint = serve_once("200 OK", &[], body);
        let mut transport = HttpClaimTransport::new(endpoint).expect("transport");
        let response = transport.claim(&request()).expect("claim response");
        assert_eq!(
            response.receipt.payload.installation_id,
            "a4e02441-a329-500d-8440-c976a7328b79"
        );
    }

    #[test]
    fn loopback_portal_error_preserves_only_bounded_code_retry_and_status() {
        let body =
            br#"{"ok":false,"error":"service_busy","message":"do not trust this text"}"#.to_vec();
        let endpoint = serve_once("503 Service Unavailable", &[("Retry-After", "120")], body);
        let mut transport = HttpClaimTransport::new(endpoint).expect("transport");
        let error = match transport.claim(&request()) {
            Ok(_) => panic!("expected failure"),
            Err(error) => error,
        };
        assert_eq!(error.http_status, Some(503));
        assert_eq!(error.server_code, "service_busy");
        assert_eq!(error.safe_message, "service_busy");
        assert_eq!(error.retry_after_ms, Some(30_000));
        assert!(error.retryable);
    }

    #[test]
    fn loopback_portal_oversized_content_length_is_rejected_before_body_read() {
        let endpoint = serve_once("200 OK", &[("Content-Length", "1048577")], Vec::new());
        let mut transport = HttpClaimTransport::new(endpoint).expect("transport");
        let error = match transport.claim(&request()) {
            Ok(_) => panic!("expected failure"),
            Err(error) => error,
        };
        assert_eq!(error.server_code, "claim-response-too-large");
        assert!(!error.retryable);
    }

    #[test]
    fn signed_external_sidecar_is_hardened_loaded_and_retired_without_public_secret() {
        let fixture = contract_fixture();
        let path = std::env::temp_dir().join(format!(
            "codex-v4-bootstrap-{}.json",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::write(
            &path,
            serde_json::to_vec(&fixture["bootstrap_envelope"]).unwrap(),
        )
        .unwrap();
        let loaded = load_bootstrap_sidecar(
            &path,
            &fixture_policy(),
            fixture["now_unix"].as_i64().unwrap(),
        )
        .unwrap();
        assert_eq!(loaded.envelope().payload.build_id, "v4-g3-test-20260804");
        loaded.retire().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn tampered_sidecar_fails_closed_with_only_a_stable_public_code() {
        let fixture = contract_fixture();
        let path = std::env::temp_dir().join(format!(
            "codex-v4-bootstrap-tampered-{}.json",
            uuid::Uuid::new_v4().simple()
        ));
        let mut envelope = fixture["bootstrap_envelope"].clone();
        envelope["payload"]["build_id"] = serde_json::json!("tampered-build");
        std::fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        let error = match load_bootstrap_sidecar(
            &path,
            &fixture_policy(),
            fixture["now_unix"].as_i64().unwrap(),
        ) {
            Ok(_) => panic!("expected verification failure"),
            Err(error) => error,
        };
        let public = serde_json::to_string(&error).unwrap();
        assert_eq!(error.code, "bootstrap-sidecar-verification");
        assert!(!public.contains("boot_"));
        let _ = std::fs::remove_file(path);
    }
}
