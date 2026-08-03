use std::collections::VecDeque;
use std::fs;
use std::time::Duration;

use codex_diagnostics_engine::{
    load_upload_state, remove_local_bundle, report_id, upload_with_retry, ArtifactDeclaration,
    ArtifactRegistry, ArtifactType, BundleBuilder, BundleTransport, DiagnosticIdentity,
    RedactionContext, RedactionPolicy, UploadReceipt, UploadStatus,
};

struct FakeTransport {
    results: VecDeque<Result<UploadReceipt, String>>,
    calls: usize,
}

impl BundleTransport for FakeTransport {
    fn upload(
        &mut self,
        bundle: &codex_diagnostics_engine::FinalizedBundle,
        idempotency_key: &str,
    ) -> Result<UploadReceipt, String> {
        self.calls += 1;
        assert_eq!(idempotency_key, bundle.report_id);
        self.results.pop_front().unwrap()
    }
}

fn bundle(temp: &tempfile::TempDir) -> codex_diagnostics_engine::FinalizedBundle {
    let log = temp.path().join("manager.log");
    fs::write(&log, b"safe log\n").unwrap();
    let mut registry = ArtifactRegistry::new();
    registry
        .register(ArtifactDeclaration {
            producer: "manager".to_string(),
            logical_name: "manager.log".to_string(),
            source_path: log,
            artifact_type: ArtifactType::ParentLog,
            redaction_policy: RedactionPolicy::Text,
            required: true,
        })
        .unwrap();
    BundleBuilder {
        identity: DiagnosticIdentity {
            report_id: report_id(),
            operation_id: "5e996f27-f818-4c68-8df6-28ca702d8032".to_string(),
            public_customer_id: None,
            order_id: None,
            device_hash: None,
            installation_id: None,
            build_id: "build-1".to_string(),
            os: "macos".to_string(),
            architecture: "aarch64".to_string(),
        },
        outcome: "failed".to_string(),
        failure: None,
        registry,
        redaction: RedactionContext::default(),
        producer_wait: Duration::ZERO,
    }
    .finalize(&temp.path().join("bundles"))
    .unwrap()
}

#[test]
fn offline_failure_retains_complete_bundle_and_reupload_is_idempotent() {
    let temp = tempfile::tempdir().unwrap();
    let bundle = bundle(&temp);
    let state_root = temp.path().join("state");
    let mut offline = FakeTransport {
        results: VecDeque::from([
            Err("network offline: token=secret".to_string()),
            Err("network offline: token=secret".to_string()),
            Err("network offline: token=secret".to_string()),
        ]),
        calls: 0,
    };
    let failed = upload_with_retry(&bundle, &state_root, 3, &mut offline).unwrap();
    assert_eq!(failed.status, UploadStatus::FailedRetained);
    assert_eq!(failed.attempts, 3);
    assert_eq!(
        failed.last_error_code.as_deref(),
        Some("network-unavailable")
    );
    assert!(bundle.path.is_file());
    let state_path = state_root.join(format!("{}.upload.json", bundle.report_id));
    assert_eq!(load_upload_state(&state_path).unwrap(), failed);
    assert!(!fs::read_to_string(&state_path)
        .unwrap()
        .contains("token=secret"));

    let receipt = UploadReceipt {
        report_id: bundle.report_id.clone(),
        server_receipt_id: "server-1".to_string(),
        received_sha256: bundle.sha256.clone(),
        identity_linked: true,
    };
    let mut online = FakeTransport {
        results: VecDeque::from([Ok(receipt.clone())]),
        calls: 0,
    };
    let uploaded = upload_with_retry(&bundle, &state_root, 3, &mut online).unwrap();
    assert_eq!(uploaded.status, UploadStatus::Uploaded);
    assert_eq!(uploaded.receipt, Some(receipt));
    assert_eq!(online.calls, 1);

    let mut must_not_call = FakeTransport {
        results: VecDeque::new(),
        calls: 0,
    };
    let already = upload_with_retry(&bundle, &state_root, 3, &mut must_not_call).unwrap();
    assert_eq!(already.status, UploadStatus::Uploaded);
    assert_eq!(must_not_call.calls, 0);
}

#[test]
fn mismatched_receipt_never_marks_bundle_uploaded() {
    let temp = tempfile::tempdir().unwrap();
    let bundle = bundle(&temp);
    let mut transport = FakeTransport {
        results: VecDeque::from([Ok(UploadReceipt {
            report_id: "wrong-report".to_string(),
            server_receipt_id: "server-2".to_string(),
            received_sha256: "0".repeat(64),
            identity_linked: false,
        })]),
        calls: 0,
    };
    let state = upload_with_retry(&bundle, &temp.path().join("state"), 1, &mut transport).unwrap();
    assert_eq!(state.status, UploadStatus::FailedRetained);
    assert_eq!(state.last_error_code.as_deref(), Some("receipt-mismatch"));
    assert!(bundle.path.is_file());
}

#[test]
fn local_delete_is_confined_to_the_exact_bundle_root() {
    let temp = tempfile::tempdir().unwrap();
    let bundle = bundle(&temp);
    let wrong_root = temp.path().join("wrong");
    fs::create_dir(&wrong_root).unwrap();
    assert!(remove_local_bundle(&bundle, &wrong_root).is_err());
    assert!(bundle.path.exists());
    remove_local_bundle(&bundle, &temp.path().join("bundles")).unwrap();
    assert!(!bundle.path.exists());
}
