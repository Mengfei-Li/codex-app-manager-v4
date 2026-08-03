use serde::{Deserialize, Serialize};

use crate::credential::CredentialHandle;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CliPolicy {
    Required,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum VerificationState {
    Succeeded,
    Failed,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationStageReport {
    pub stage: String,
    pub state: VerificationState,
    pub code: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationReport {
    pub schema_version: u32,
    pub operation_id: String,
    pub succeeded: bool,
    pub stages: Vec<VerificationStageReport>,
}

#[derive(Clone)]
pub struct VerificationRequest {
    pub operation_id: String,
    pub expected_api_origin: String,
    pub expected_model: String,
    pub expected_review_model: String,
    pub expected_marker: String,
    pub credential: CredentialHandle,
    pub cli_policy: CliPolicy,
    pub require_usage_lifecycle: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeError {
    pub code: String,
    pub retryable: bool,
}

#[derive(Debug, Clone)]
pub struct AppProof {
    pub process_alive: bool,
    pub surface_ready: bool,
}

#[derive(Debug, Clone)]
pub struct ConfigProof {
    pub api_origin: String,
    pub model: String,
    pub review_model: String,
    pub credential_native: bool,
    pub unknown_fields_preserved: bool,
}

#[derive(Debug, Clone)]
pub struct ModelsProof {
    pub model_ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ResponseProof {
    pub request_id: String,
    pub model: String,
    pub output_text: String,
}

#[derive(Debug, Clone)]
pub struct StreamProof {
    pub event_types: Vec<String>,
    pub model: String,
    pub output_text: String,
    pub completed: bool,
}

#[derive(Debug, Clone)]
pub struct CliProof {
    pub found: bool,
    pub version_ok: bool,
    pub auth_ok: bool,
    pub output_text: String,
}

#[derive(Debug, Clone)]
pub struct UsageProof {
    pub isolated_customer: bool,
    pub records_before: u64,
    pub records_after: u64,
    pub claim_released_or_revoked: bool,
}

pub trait VerificationProbe {
    fn app(&mut self, request: &VerificationRequest) -> Result<AppProof, ProbeError>;
    fn config(&mut self, request: &VerificationRequest) -> Result<ConfigProof, ProbeError>;
    fn models(&mut self, request: &VerificationRequest) -> Result<ModelsProof, ProbeError>;
    fn response(&mut self, request: &VerificationRequest) -> Result<ResponseProof, ProbeError>;
    fn sse(&mut self, request: &VerificationRequest) -> Result<StreamProof, ProbeError>;
    fn websocket(&mut self, request: &VerificationRequest) -> Result<StreamProof, ProbeError>;
    fn cli(&mut self, request: &VerificationRequest) -> Result<CliProof, ProbeError>;
    fn usage(&mut self, request: &VerificationRequest) -> Result<UsageProof, ProbeError>;
}

pub fn run_verification<P: VerificationProbe>(
    request: &VerificationRequest,
    probe: &mut P,
) -> VerificationReport {
    let mut stages = Vec::with_capacity(8);
    stages.push(stage("app", probe.app(request), |proof| {
        proof.process_alive && proof.surface_ready
    }));
    stages.push(stage("config", probe.config(request), |proof| {
        proof.api_origin == request.expected_api_origin
            && proof.model == request.expected_model
            && proof.review_model == request.expected_review_model
            && proof.credential_native
            && proof.unknown_fields_preserved
    }));
    stages.push(stage("models", probe.models(request), |proof| {
        proof
            .model_ids
            .iter()
            .any(|id| id == &request.expected_model)
            && proof
                .model_ids
                .iter()
                .any(|id| id == &request.expected_review_model)
            && proof.model_ids.iter().all(|id| !id.ends_with("-lite"))
    }));
    stages.push(stage("responses", probe.response(request), |proof| {
        response_is_valid(proof, request)
    }));
    stages.push(stage("sse", probe.sse(request), |proof| {
        stream_is_valid(proof, request)
    }));
    stages.push(stage("websocket", probe.websocket(request), |proof| {
        stream_is_valid(proof, request)
    }));
    stages.push(match request.cli_policy {
        CliPolicy::Required => stage("cli", probe.cli(request), |proof| {
            proof.found
                && proof.version_ok
                && proof.auth_ok
                && proof.output_text.contains(&request.expected_marker)
        }),
        CliPolicy::NotApplicable => VerificationStageReport {
            stage: "cli".to_string(),
            state: VerificationState::NotApplicable,
            code: "cli-not-required-by-product".to_string(),
            retryable: false,
        },
    });
    stages.push(if request.require_usage_lifecycle {
        stage("usage", probe.usage(request), |proof| {
            proof.isolated_customer
                && proof.records_after > proof.records_before
                && proof.claim_released_or_revoked
        })
    } else {
        VerificationStageReport {
            stage: "usage".to_string(),
            state: VerificationState::NotApplicable,
            code: "usage-lifecycle-not-required-in-production".to_string(),
            retryable: false,
        }
    });

    let succeeded = stages
        .iter()
        .all(|item| item.state != VerificationState::Failed);
    VerificationReport {
        schema_version: 1,
        operation_id: request.operation_id.clone(),
        succeeded,
        stages,
    }
}

fn stage<T, F>(name: &str, result: Result<T, ProbeError>, validate: F) -> VerificationStageReport
where
    F: FnOnce(&T) -> bool,
{
    match result {
        Ok(proof) if validate(&proof) => VerificationStageReport {
            stage: name.to_string(),
            state: VerificationState::Succeeded,
            code: format!("{name}-verified"),
            retryable: false,
        },
        Ok(_) => VerificationStageReport {
            stage: name.to_string(),
            state: VerificationState::Failed,
            code: format!("{name}-semantic-mismatch"),
            retryable: false,
        },
        Err(error) => VerificationStageReport {
            stage: name.to_string(),
            state: VerificationState::Failed,
            code: sanitize_code(&error.code),
            retryable: error.retryable,
        },
    }
}

fn response_is_valid(proof: &ResponseProof, request: &VerificationRequest) -> bool {
    !proof.request_id.is_empty()
        && proof.model == request.expected_model
        && proof.output_text.contains(&request.expected_marker)
}

fn stream_is_valid(proof: &StreamProof, request: &VerificationRequest) -> bool {
    let created = proof
        .event_types
        .iter()
        .position(|event| event == "response.created");
    let completed = proof
        .event_types
        .iter()
        .rposition(|event| event == "response.completed");
    proof.completed
        && proof.model == request.expected_model
        && proof.output_text.contains(&request.expected_marker)
        && created
            .zip(completed)
            .is_some_and(|(start, end)| start < end)
        && proof
            .event_types
            .iter()
            .any(|event| event == "response.output_text.delta")
}

fn sanitize_code(code: &str) -> String {
    if !code.is_empty()
        && code.len() <= 80
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        code.to_string()
    } else {
        "verification-probe-error".to_string()
    }
}
