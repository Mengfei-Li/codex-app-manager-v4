use std::fs;
use std::io::Read as _;
use std::path::Path;
use std::time::Duration;

use codex_diagnostics_engine::{
    included_artifact_names, report_id, ArtifactDeclaration, ArtifactRegistry, ArtifactState,
    ArtifactType, BundleBuilder, DiagnosticIdentity, RedactionContext, RedactionPolicy,
    StructuredFailure,
};

fn identity(report_id: String) -> DiagnosticIdentity {
    DiagnosticIdentity {
        report_id,
        operation_id: "70b50f26-56be-454c-b1fd-6ab0cae4091f".to_string(),
        public_customer_id: Some("customer-2466335".to_string()),
        order_id: Some("order-42".to_string()),
        device_hash: Some("a".repeat(64)),
        installation_id: Some("d49c8c71-ff39-43f7-8fe5-4b2ea1aca2e1".to_string()),
        build_id: "v4-test-build".to_string(),
        os: "windows".to_string(),
        architecture: "x86_64".to_string(),
    }
}

fn register(
    registry: &mut ArtifactRegistry,
    source: &Path,
    logical_name: &str,
    artifact_type: ArtifactType,
    policy: RedactionPolicy,
    required: bool,
) {
    registry
        .register(ArtifactDeclaration {
            producer: "test-producer".to_string(),
            logical_name: logical_name.to_string(),
            source_path: source.to_path_buf(),
            artifact_type,
            redaction_policy: policy,
            required,
        })
        .unwrap();
}

fn read_entry(bundle: &Path, name: &str) -> Vec<u8> {
    let file = fs::File::open(bundle).unwrap();
    let mut archive = zip::ZipArchive::new(file).unwrap();
    let mut entry = archive.by_name(name).unwrap();
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes).unwrap();
    bytes
}

#[test]
fn failure_bundle_includes_parent_child_journal_and_explicit_missing_artifact() {
    let temp = tempfile::tempdir().unwrap();
    let parent = temp.path().join("parent.log");
    let child = temp.path().join("worker.log");
    let journal = temp.path().join("journal.json");
    let missing = temp.path().join("transaction.json");
    fs::write(&parent, b"stage=apply\napi_key=sk-super-secret\n").unwrap();
    fs::write(&child, b"worker failed token=mgmt-hidden-value\n").unwrap();
    fs::write(
        &journal,
        br#"{"operation":"70b50f26-56be-454c-b1fd-6ab0cae4091f","password":"bad"}"#,
    )
    .unwrap();

    let mut registry = ArtifactRegistry::new();
    register(
        &mut registry,
        &parent,
        "manager/parent.log",
        ArtifactType::ParentLog,
        RedactionPolicy::Text,
        true,
    );
    register(
        &mut registry,
        &child,
        "worker/locale.stderr.log",
        ArtifactType::ChildWorkerLog,
        RedactionPolicy::Text,
        true,
    );
    register(
        &mut registry,
        &journal,
        "operation/journal.json",
        ArtifactType::OperationJournal,
        RedactionPolicy::Json,
        true,
    );
    register(
        &mut registry,
        &missing,
        "config/transaction.json",
        ArtifactType::Transaction,
        RedactionPolicy::Json,
        true,
    );
    let mut redaction = RedactionContext::default();
    redaction.add_secret("sk-super-secret");
    redaction.add_secret("mgmt-hidden-value");
    redaction.add_home_path("C:\\Users\\private-user");
    let builder = BundleBuilder {
        identity: identity(report_id()),
        outcome: "failed".to_string(),
        failure: Some(StructuredFailure {
            domain: "locale".to_string(),
            code: "worker-exit".to_string(),
            stage: "locale-initialize".to_string(),
            retryable: true,
            reboot_required: false,
            root_cause: "child worker returned a non-zero exit code".to_string(),
            next_action: "retry locale initialization".to_string(),
        }),
        registry,
        redaction,
        producer_wait: Duration::from_millis(10),
    };

    let bundle = builder.finalize(&temp.path().join("bundles")).unwrap();
    assert!(bundle.path.is_file());
    assert_eq!(
        bundle.manifest.required_missing,
        ["config/transaction.json"]
    );
    assert_eq!(
        included_artifact_names(&bundle.manifest),
        [
            "manager/parent.log",
            "operation/journal.json",
            "worker/locale.stderr.log"
        ]
        .into_iter()
        .collect()
    );
    let parent_bytes = read_entry(&bundle.path, "artifacts/manager/parent.log");
    let child_bytes = read_entry(&bundle.path, "artifacts/worker/locale.stderr.log");
    let journal_bytes = read_entry(&bundle.path, "artifacts/operation/journal.json");
    for bytes in [&parent_bytes, &child_bytes, &journal_bytes] {
        assert!(!bytes.windows(3).any(|window| window == b"sk-"));
        assert!(!bytes.windows(5).any(|window| window == b"mgmt-"));
        assert!(!bytes.windows(3).any(|window| window == b"bad"));
    }
    assert!(String::from_utf8(parent_bytes)
        .unwrap()
        .contains("<redacted-secret>"));
    let manifest_from_zip: serde_json::Value =
        serde_json::from_slice(&read_entry(&bundle.path, "manifest.json")).unwrap();
    assert_eq!(manifest_from_zip["identity"]["report_id"], bundle.report_id);
    assert_eq!(manifest_from_zip["failure"]["code"], "worker-exit");
}

#[test]
fn finalization_is_idempotent_for_the_same_identity_and_rejects_mismatch() {
    let temp = tempfile::tempdir().unwrap();
    let log = temp.path().join("parent.log");
    fs::write(&log, b"ok\n").unwrap();
    let report = report_id();
    let make = |operation_id: &str| {
        let mut registry = ArtifactRegistry::new();
        register(
            &mut registry,
            &log,
            "parent.log",
            ArtifactType::ParentLog,
            RedactionPolicy::Text,
            true,
        );
        let mut id = identity(report.clone());
        id.operation_id = operation_id.to_string();
        BundleBuilder {
            identity: id,
            outcome: "success".to_string(),
            failure: None,
            registry,
            redaction: RedactionContext::default(),
            producer_wait: Duration::ZERO,
        }
    };
    let root = temp.path().join("bundles");
    let first = make("70b50f26-56be-454c-b1fd-6ab0cae4091f")
        .finalize(&root)
        .unwrap();
    let second = make("70b50f26-56be-454c-b1fd-6ab0cae4091f")
        .finalize(&root)
        .unwrap();
    assert_eq!(first.sha256, second.sha256);
    assert!(make("a120a66d-7011-4cbc-9fd2-a87d90298d7e")
        .finalize(&root)
        .is_err());
}

#[test]
fn registry_rejects_path_traversal_duplicate_names_and_unsafe_producers() {
    let mut registry = ArtifactRegistry::new();
    let source = Path::new("unused");
    for name in ["../escape.log", "/absolute.log", "bad\\path.log"] {
        assert!(registry
            .register(ArtifactDeclaration {
                producer: "safe".to_string(),
                logical_name: name.to_string(),
                source_path: source.to_path_buf(),
                artifact_type: ArtifactType::OtherText,
                redaction_policy: RedactionPolicy::Text,
                required: false,
            })
            .is_err());
    }
    register(
        &mut registry,
        source,
        "safe.log",
        ArtifactType::OtherText,
        RedactionPolicy::Text,
        false,
    );
    assert!(registry
        .register(ArtifactDeclaration {
            producer: "safe".to_string(),
            logical_name: "safe.log".to_string(),
            source_path: source.to_path_buf(),
            artifact_type: ArtifactType::OtherText,
            redaction_policy: RedactionPolicy::Text,
            required: false,
        })
        .is_err());
    assert!(registry
        .register(ArtifactDeclaration {
            producer: "bad producer".to_string(),
            logical_name: "other.log".to_string(),
            source_path: source.to_path_buf(),
            artifact_type: ArtifactType::OtherText,
            redaction_policy: RedactionPolicy::Text,
            required: false,
        })
        .is_err());
}

#[test]
fn excluded_and_oversized_artifacts_are_manifested_without_entering_the_archive() {
    let temp = tempfile::tempdir().unwrap();
    let excluded = temp.path().join("chat.txt");
    let oversized = temp.path().join("oversized.log");
    fs::write(&excluded, b"private conversation").unwrap();
    let file = fs::File::create(&oversized).unwrap();
    file.set_len(codex_diagnostics_engine::MAX_ARTIFACT_BYTES + 1)
        .unwrap();
    let mut registry = ArtifactRegistry::new();
    register(
        &mut registry,
        &excluded,
        "excluded.txt",
        ArtifactType::OtherText,
        RedactionPolicy::Exclude,
        false,
    );
    register(
        &mut registry,
        &oversized,
        "oversized.log",
        ArtifactType::OtherText,
        RedactionPolicy::Text,
        false,
    );
    let bundle = BundleBuilder {
        identity: identity(report_id()),
        outcome: "failed".to_string(),
        failure: None,
        registry,
        redaction: RedactionContext::default(),
        producer_wait: Duration::ZERO,
    }
    .finalize(&temp.path().join("bundles"))
    .unwrap();
    assert!(bundle
        .manifest
        .artifacts
        .iter()
        .all(|item| item.state == ArtifactState::Rejected));
    let file = fs::File::open(bundle.path).unwrap();
    let mut archive = zip::ZipArchive::new(file).unwrap();
    assert_eq!(archive.len(), 1);
    assert_eq!(archive.by_index(0).unwrap().name(), "manifest.json");
}
