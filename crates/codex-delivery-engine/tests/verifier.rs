use codex_delivery_engine::{
    run_verification, AppProof, CliPolicy, CliProof, ConfigProof, CredentialHandle, ModelsProof,
    ProbeError, ResponseProof, StreamProof, UsageProof, VerificationProbe, VerificationRequest,
    VerificationState,
};

struct FixtureProbe {
    corrupt_sse: bool,
    websocket_error: Option<ProbeError>,
    cli_calls: usize,
    usage_calls: usize,
}

impl FixtureProbe {
    fn healthy() -> Self {
        Self {
            corrupt_sse: false,
            websocket_error: None,
            cli_calls: 0,
            usage_calls: 0,
        }
    }
}

impl VerificationProbe for FixtureProbe {
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
                "gpt-5.6-luna".to_string(),
            ],
        })
    }

    fn response(&mut self, request: &VerificationRequest) -> Result<ResponseProof, ProbeError> {
        Ok(ResponseProof {
            request_id: "resp_fixture".to_string(),
            model: request.expected_model.clone(),
            output_text: format!("ok {}", request.expected_marker),
        })
    }

    fn sse(&mut self, request: &VerificationRequest) -> Result<StreamProof, ProbeError> {
        let events = if self.corrupt_sse {
            vec!["response.completed".to_string()]
        } else {
            stream_events()
        };
        Ok(StreamProof {
            event_types: events,
            model: request.expected_model.clone(),
            output_text: request.expected_marker.clone(),
            completed: true,
        })
    }

    fn websocket(&mut self, request: &VerificationRequest) -> Result<StreamProof, ProbeError> {
        if let Some(error) = self.websocket_error.take() {
            return Err(error);
        }
        Ok(StreamProof {
            event_types: stream_events(),
            model: request.expected_model.clone(),
            output_text: request.expected_marker.clone(),
            completed: true,
        })
    }

    fn cli(&mut self, request: &VerificationRequest) -> Result<CliProof, ProbeError> {
        self.cli_calls += 1;
        Ok(CliProof {
            found: true,
            version_ok: true,
            auth_ok: true,
            output_text: request.expected_marker.clone(),
        })
    }

    fn usage(&mut self, _request: &VerificationRequest) -> Result<UsageProof, ProbeError> {
        self.usage_calls += 1;
        Ok(UsageProof {
            isolated_customer: true,
            records_before: 4,
            records_after: 5,
            claim_released_or_revoked: true,
        })
    }
}

fn stream_events() -> Vec<String> {
    vec![
        "response.created".to_string(),
        "response.output_text.delta".to_string(),
        "response.completed".to_string(),
    ]
}

fn request(cli_policy: CliPolicy, usage: bool) -> VerificationRequest {
    VerificationRequest {
        operation_id: "op-fixture".to_string(),
        expected_api_origin: "https://api.fixture.invalid".to_string(),
        expected_model: "gpt-5.6-sol".to_string(),
        expected_review_model: "gpt-5.6-terra".to_string(),
        expected_marker: "v4-verification-marker".to_string(),
        credential: CredentialHandle {
            service: "provider-codex-v4".to_string(),
            account: "install-fixture".to_string(),
        },
        cli_policy,
        require_usage_lifecycle: usage,
    }
}

#[test]
fn complete_fixture_proves_app_config_all_transports_cli_and_usage() {
    let mut probe = FixtureProbe::healthy();
    let report = run_verification(&request(CliPolicy::Required, true), &mut probe);

    assert!(report.succeeded);
    assert_eq!(report.stages.len(), 8);
    assert!(report
        .stages
        .iter()
        .all(|stage| stage.state == VerificationState::Succeeded));
    assert_eq!(probe.cli_calls, 1);
    assert_eq!(probe.usage_calls, 1);
    let serialized = serde_json::to_string(&report).unwrap();
    assert!(!serialized.contains("OPENAI_API_KEY"));
    assert!(!serialized.contains("sk-"));
}

#[test]
fn http_success_without_required_sse_semantics_is_a_failure() {
    let mut probe = FixtureProbe {
        corrupt_sse: true,
        ..FixtureProbe::healthy()
    };
    let report = run_verification(&request(CliPolicy::Required, true), &mut probe);

    assert!(!report.succeeded);
    let sse = report
        .stages
        .iter()
        .find(|stage| stage.stage == "sse")
        .unwrap();
    assert_eq!(sse.state, VerificationState::Failed);
    assert_eq!(sse.code, "sse-semantic-mismatch");
}

#[test]
fn probe_failure_is_redacted_to_a_bounded_code_and_other_stages_continue() {
    let mut probe = FixtureProbe {
        websocket_error: Some(ProbeError {
            code: "secret-bearing invalid error !".to_string(),
            retryable: true,
        }),
        ..FixtureProbe::healthy()
    };
    let report = run_verification(&request(CliPolicy::Required, true), &mut probe);

    assert!(!report.succeeded);
    let websocket = report
        .stages
        .iter()
        .find(|stage| stage.stage == "websocket")
        .unwrap();
    assert_eq!(websocket.code, "verification-probe-error");
    assert!(websocket.retryable);
    assert_eq!(probe.cli_calls, 1);
    assert_eq!(probe.usage_calls, 1);
}

#[test]
fn explicit_not_applicable_is_reported_and_never_silently_skipped() {
    let mut probe = FixtureProbe::healthy();
    let report = run_verification(&request(CliPolicy::NotApplicable, false), &mut probe);

    assert!(report.succeeded);
    assert_eq!(probe.cli_calls, 0);
    assert_eq!(probe.usage_calls, 0);
    for name in ["cli", "usage"] {
        let stage = report
            .stages
            .iter()
            .find(|stage| stage.stage == name)
            .unwrap();
        assert_eq!(stage.state, VerificationState::NotApplicable);
        assert!(stage.code.contains("not-required"));
    }
}
