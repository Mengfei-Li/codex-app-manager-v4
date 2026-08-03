use std::fs;
use std::path::PathBuf;

use codex_delivery_engine::contract::sha256_hex;
use codex_delivery_engine::{
    merge_config, provision_configuration, provision_configuration_with_validator,
    ConfigRepairState, ConfigSemanticValidator, ConflictPolicy, CredentialHandle, CredentialVault,
    DeliveryError, FaultInjector, ManagedConfigSpec, MemoryCredentialVault, NoFault,
    ProvisioningPaths, ProvisioningRequest, ProvisioningSecrets,
};
use tempfile::TempDir;
use uuid::Uuid;

const API_KEY: &str = "sk-fixture-secret-not-for-logs";
const MANAGEMENT_TOKEN: &str = "mgmt_fixture_secret_not_for_logs";
const FULL_RESPONSES_CATALOG: &[u8] = include_bytes!("../../../assets/models-full-responses.json");

fn catalog_bytes() -> Vec<u8> {
    serde_json::to_vec_pretty(&serde_json::json!({
        "client_version": "test",
        "models": [
            {"slug": "gpt-5.6-sol", "supported_in_api": true},
            {"slug": "gpt-5.6-terra", "supported_in_api": true},
            {"slug": "gpt-5.6-luna", "supported_in_api": true},
            {"slug": "gpt-5.5", "supported_in_api": true}
        ]
    }))
    .unwrap()
}

#[test]
fn published_full_responses_catalog_has_pinned_bytes_and_semantics() {
    let text = std::str::from_utf8(FULL_RESPONSES_CATALOG).unwrap();
    let canonical = text.replace("\r\n", "\n");
    assert_eq!(canonical.len(), 326_974);
    assert_eq!(
        sha256_hex(canonical.as_bytes()),
        "a61fbe6d2a5bed953fb0e08e9f9e22b78715e5f8802fe2c2c0dcb41ad6a9acda"
    );
    let value: serde_json::Value = serde_json::from_str(&canonical).unwrap();
    let models = value["models"].as_array().unwrap();
    assert_eq!(models.len(), 8);
    let slugs: Vec<&str> = models
        .iter()
        .map(|model| model["slug"].as_str().unwrap())
        .collect();
    for required in ["gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"] {
        assert_eq!(slugs.iter().filter(|slug| **slug == required).count(), 1);
    }
    assert!(slugs.iter().all(|slug| !slug.ends_with("-lite")));
}

fn fixture() -> (TempDir, ProvisioningPaths, ManagedConfigSpec) {
    let temp = tempfile::tempdir().unwrap();
    let codex_home = temp.path().join("codex-home");
    fs::create_dir_all(&codex_home).unwrap();
    let catalog_source = temp.path().join("catalog.json");
    let catalog = catalog_bytes();
    fs::write(&catalog_source, &catalog).unwrap();
    let catalog_path = codex_home
        .join("managed")
        .join("relay-models-full-responses.json");
    let paths = ProvisioningPaths {
        codex_home,
        catalog_source,
    };
    let spec = ManagedConfigSpec {
        api_base_url: "https://api.2466335.xyz/v1".to_string(),
        model_catalog_path: catalog_path,
        model_catalog_sha256: sha256_hex(&catalog),
        model: "gpt-5.6-sol".to_string(),
        review_model: "gpt-5.6-sol".to_string(),
        reasoning_effort: "high".to_string(),
        locale: "zh-CN".to_string(),
    };
    (temp, paths, spec)
}

fn secrets() -> ProvisioningSecrets {
    ProvisioningSecrets {
        api_key: API_KEY.to_string(),
        management_token: MANAGEMENT_TOKEN.to_string(),
    }
}

struct FailFirstSemanticValidation {
    calls: usize,
}

impl ConfigSemanticValidator for FailFirstSemanticValidation {
    fn validate(&mut self, config_bytes: &[u8]) -> Result<(), DeliveryError> {
        self.calls += 1;
        if self.calls == 1 {
            return Err(DeliveryError::ConfigTransaction(
                "injected merged-config rejection".to_string(),
            ));
        }
        if config_bytes
            .windows(b"unknown_setting".len())
            .any(|window| window == b"unknown_setting")
        {
            return Err(DeliveryError::ConfigTransaction(
                "minimal config retained unknown setting".to_string(),
            ));
        }
        Ok(())
    }
}

struct AlwaysFailSemanticValidation;

impl ConfigSemanticValidator for AlwaysFailSemanticValidation {
    fn validate(&mut self, _config_bytes: &[u8]) -> Result<(), DeliveryError> {
        Err(DeliveryError::ConfigTransaction(
            "injected semantic rejection".to_string(),
        ))
    }
}

#[test]
fn merge_preserves_unknown_fields_and_adopts_the_recognized_v2_block() {
    let (_temp, _paths, spec) = fixture();
    let source = br#"# user comment
unknown_setting = "keep-me"
# BEGIN PROVIDER CODEX MANAGED CONFIG
model_provider = "relay"
openai_base_url = "https://old.invalid/v1"
# END PROVIDER CODEX MANAGED CONFIG

[history]
persistence = "save-all"

[model_providers.relay]
name = "legacy"
"#;
    let merged = merge_config(source, &spec, ConflictPolicy::AdoptRecognizedV2).unwrap();
    assert!(merged.conflicts.is_empty());
    assert!(merged.recognized_v2);
    let output = String::from_utf8(merged.bytes).unwrap();
    assert!(output.contains("# user comment"));
    assert!(output.contains("unknown_setting = \"keep-me\""));
    assert!(output.contains("persistence = \"save-all\""));
    assert!(!output.contains("model_providers.relay"));
    assert!(!output.contains("https://old.invalid"));
    assert!(output.contains("model_provider = \"openai\""));
    assert!(output.contains("localeOverride = \"zh-CN\""));
    assert_eq!(output.matches("BEGIN PROVIDER CODEX V4").count(), 1);
}

#[test]
fn unmanaged_conflicts_are_reported_without_rewriting_bytes() {
    let (_temp, _paths, spec) = fixture();
    let source = b"model = \"user-model\"\nunknown = 7\n";
    let merged = merge_config(source, &spec, ConflictPolicy::RejectUnmanaged).unwrap();
    assert_eq!(merged.bytes, source);
    assert_eq!(merged.conflicts, vec!["model"]);
}

#[test]
fn every_priority_override_and_provider_table_conflict_is_reported() {
    let (_temp, _paths, spec) = fixture();
    let source = br#"approval_policy = "on-request"
sandbox_mode = "read-only"
openai_base_url = "https://user.example/v1"

[model_providers.openai]
name = "user-openai"

[model_providers.relay]
name = "legacy-relay"

[windows]
sandbox = "unelevated"

[desktop]
localeOverride = "en-US"
"#;
    let merged = merge_config(source, &spec, ConflictPolicy::RejectUnmanaged).unwrap();
    assert_eq!(merged.bytes, source);
    assert_eq!(
        merged.conflicts,
        vec![
            "approval_policy",
            "desktop.localeOverride",
            "model_providers.openai",
            "model_providers.relay",
            "openai_base_url",
            "sandbox_mode",
            "windows.sandbox",
        ]
    );
}

#[test]
fn successful_transaction_commits_three_files_vault_and_hash_manifest() {
    let (_temp, paths, spec) = fixture();
    let original_config = b"# keep\nunknown_setting = \"yes\"\n";
    fs::write(paths.codex_home.join("config.toml"), original_config).unwrap();
    fs::write(paths.codex_home.join("auth.json"), b"{\"OLD\":true}\n").unwrap();
    let operation_id = Uuid::new_v4();
    let installation_id = Uuid::new_v4();
    let mut vault = MemoryCredentialVault::default();
    let request_secrets = secrets();
    let report = provision_configuration(
        ProvisioningRequest {
            paths: &paths,
            spec: &spec,
            secrets: &request_secrets,
            operation_id,
            installation_id,
            policy: ConflictPolicy::RejectUnmanaged,
        },
        &mut vault,
        &mut NoFault,
    )
    .unwrap();
    let handle = CredentialHandle {
        service: "provider-codex-v4".to_string(),
        account: installation_id.to_string(),
    };
    assert!(vault.contains(&handle));
    let vault_value: serde_json::Value =
        serde_json::from_slice(&vault.get(&handle).unwrap().unwrap()).unwrap();
    assert_eq!(vault_value["api_key"], API_KEY);
    assert_eq!(vault_value["management_token"], MANAGEMENT_TOKEN);
    let config = fs::read_to_string(paths.codex_home.join("config.toml")).unwrap();
    assert!(config.contains("unknown_setting = \"yes\""));
    assert!(config.contains("model_provider = \"openai\""));
    let auth: serde_json::Value =
        serde_json::from_slice(&fs::read(paths.codex_home.join("auth.json")).unwrap()).unwrap();
    assert_eq!(auth.as_object().unwrap().len(), 1);
    assert_eq!(auth["OPENAI_API_KEY"], API_KEY);
    assert_eq!(fs::read(&spec.model_catalog_path).unwrap(), catalog_bytes());
    assert_eq!(report.backups.len(), 3);
    assert_eq!(report.credential_handle, handle);
    assert_eq!(report.config_repair_state, ConfigRepairState::NotNeeded);
    let report_json = serde_json::to_string(&report).unwrap();
    assert!(!report_json.contains(API_KEY));
    assert!(!report_json.contains(MANAGEMENT_TOKEN));
    let manifest = PathBuf::from(&report.backup_directory).join("transaction.json");
    let manifest_json: serde_json::Value =
        serde_json::from_slice(&fs::read(manifest).unwrap()).unwrap();
    assert_eq!(manifest_json["state"], "committed");
    for entry in fs::read_dir(&report.backup_directory).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        assert!(!bytes
            .windows(API_KEY.len())
            .any(|window| window == API_KEY.as_bytes()));
        assert!(!bytes
            .windows(MANAGEMENT_TOKEN.len())
            .any(|window| window == MANAGEMENT_TOKEN.as_bytes()));
    }
}

#[cfg(unix)]
#[test]
fn successful_transaction_enforces_owner_only_unix_permissions() {
    use std::os::unix::fs::PermissionsExt as _;

    let (_temp, paths, spec) = fixture();
    fs::write(paths.codex_home.join("config.toml"), b"# existing\n").unwrap();
    fs::write(paths.codex_home.join("auth.json"), b"{\"OLD\":true}\n").unwrap();
    let mut vault = MemoryCredentialVault::default();
    let request_secrets = secrets();
    let report = provision_configuration(
        ProvisioningRequest {
            paths: &paths,
            spec: &spec,
            secrets: &request_secrets,
            operation_id: Uuid::new_v4(),
            installation_id: Uuid::new_v4(),
            policy: ConflictPolicy::RejectUnmanaged,
        },
        &mut vault,
        &mut NoFault,
    )
    .unwrap();

    for path in [
        paths.codex_home.join("config.toml"),
        paths.codex_home.join("auth.json"),
        spec.model_catalog_path.clone(),
        PathBuf::from(&report.backup_directory).join("transaction.json"),
    ] {
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "{} must be owner-readable and owner-writable only",
            path.display()
        );
    }
    assert_eq!(
        fs::metadata(&report.backup_directory)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700,
        "backup directory must be owner-accessible only"
    );
}

struct FailAt {
    checkpoint: String,
}

impl FaultInjector for FailAt {
    fn checkpoint(&mut self, name: &str) -> Result<(), DeliveryError> {
        if name == self.checkpoint {
            return Err(DeliveryError::ConfigTransaction(format!(
                "injected at {name}"
            )));
        }
        Ok(())
    }
}

#[test]
fn every_partial_commit_is_rolled_back_with_original_bytes_and_vault_value() {
    for checkpoint in [
        "after-vault-write",
        "after-prepare",
        "after-commit-0",
        "after-commit-1",
        "after-commit-2",
        "after-readback",
    ] {
        let (_temp, paths, spec) = fixture();
        let original_config = b"unknown_setting = \"original\"\n".to_vec();
        let original_auth = b"{\"OLD\":\"original\"}\n".to_vec();
        let original_catalog = b"{\"old\":true}\n".to_vec();
        fs::write(paths.codex_home.join("config.toml"), &original_config).unwrap();
        fs::write(paths.codex_home.join("auth.json"), &original_auth).unwrap();
        fs::create_dir_all(spec.model_catalog_path.parent().unwrap()).unwrap();
        fs::write(&spec.model_catalog_path, &original_catalog).unwrap();
        let operation_id = Uuid::new_v4();
        let installation_id = Uuid::new_v4();
        let handle = CredentialHandle {
            service: "provider-codex-v4".to_string(),
            account: installation_id.to_string(),
        };
        let mut vault = MemoryCredentialVault::default();
        vault.set(&handle, b"prior-secret").unwrap();
        let request_secrets = secrets();
        let result = provision_configuration(
            ProvisioningRequest {
                paths: &paths,
                spec: &spec,
                secrets: &request_secrets,
                operation_id,
                installation_id,
                policy: ConflictPolicy::RejectUnmanaged,
            },
            &mut vault,
            &mut FailAt {
                checkpoint: checkpoint.to_string(),
            },
        );
        assert!(result.is_err(), "checkpoint {checkpoint}");
        assert_eq!(
            fs::read(paths.codex_home.join("config.toml")).unwrap(),
            original_config,
            "checkpoint {checkpoint}"
        );
        assert_eq!(
            fs::read(paths.codex_home.join("auth.json")).unwrap(),
            original_auth,
            "checkpoint {checkpoint}"
        );
        assert_eq!(
            fs::read(&spec.model_catalog_path).unwrap(),
            original_catalog,
            "checkpoint {checkpoint}"
        );
        assert_eq!(vault.get(&handle).unwrap().unwrap(), b"prior-secret");
    }
}

#[test]
fn failure_for_new_install_removes_partial_targets_and_new_vault_entry() {
    let (_temp, paths, spec) = fixture();
    let installation_id = Uuid::new_v4();
    let handle = CredentialHandle {
        service: "provider-codex-v4".to_string(),
        account: installation_id.to_string(),
    };
    let mut vault = MemoryCredentialVault::default();
    let request_secrets = secrets();
    let result = provision_configuration(
        ProvisioningRequest {
            paths: &paths,
            spec: &spec,
            secrets: &request_secrets,
            operation_id: Uuid::new_v4(),
            installation_id,
            policy: ConflictPolicy::RejectUnmanaged,
        },
        &mut vault,
        &mut FailAt {
            checkpoint: "after-commit-1".to_string(),
        },
    );
    assert!(result.is_err());
    assert!(!paths.codex_home.join("config.toml").exists());
    assert!(!paths.codex_home.join("auth.json").exists());
    assert!(!spec.model_catalog_path.exists());
    assert!(!vault.contains(&handle));
}

#[test]
fn invalid_catalog_fails_before_backup_vault_or_target_mutation() {
    let (_temp, paths, mut spec) = fixture();
    spec.model_catalog_sha256 = "0".repeat(64);
    fs::write(paths.codex_home.join("config.toml"), b"unknown = true\n").unwrap();
    let installation_id = Uuid::new_v4();
    let handle = CredentialHandle {
        service: "provider-codex-v4".to_string(),
        account: installation_id.to_string(),
    };
    let mut vault = MemoryCredentialVault::default();
    let request_secrets = secrets();
    let result = provision_configuration(
        ProvisioningRequest {
            paths: &paths,
            spec: &spec,
            secrets: &request_secrets,
            operation_id: Uuid::new_v4(),
            installation_id,
            policy: ConflictPolicy::RejectUnmanaged,
        },
        &mut vault,
        &mut NoFault,
    );
    assert!(result.is_err());
    assert_eq!(
        fs::read(paths.codex_home.join("config.toml")).unwrap(),
        b"unknown = true\n"
    );
    assert!(!vault.contains(&handle));
    assert!(!paths.codex_home.join("backups").exists());
}

#[test]
fn failed_merged_config_validation_gets_one_minimal_repair_attempt() {
    let (_temp, paths, spec) = fixture();
    fs::write(
        paths.codex_home.join("config.toml"),
        b"# keep if normal\nunknown_setting = true\n",
    )
    .unwrap();
    let request_secrets = secrets();
    let mut validator = FailFirstSemanticValidation { calls: 0 };
    let mut vault = MemoryCredentialVault::default();
    let report = provision_configuration_with_validator(
        ProvisioningRequest {
            paths: &paths,
            spec: &spec,
            secrets: &request_secrets,
            operation_id: Uuid::new_v4(),
            installation_id: Uuid::new_v4(),
            policy: ConflictPolicy::RejectUnmanaged,
        },
        &mut vault,
        &mut NoFault,
        &mut validator,
    )
    .unwrap();
    assert_eq!(validator.calls, 2);
    assert_eq!(report.config_repair_state, ConfigRepairState::Succeeded);
    let config = fs::read_to_string(paths.codex_home.join("config.toml")).unwrap();
    assert!(!config.contains("unknown_setting"));
    assert!(config.contains("model_provider = \"openai\""));
}

#[test]
fn failed_minimal_repair_restores_every_original_and_vault_state() {
    let (_temp, paths, spec) = fixture();
    let original_config = b"unknown_setting = true\n";
    let original_auth = b"{\"OLD\":true}\n";
    fs::write(paths.codex_home.join("config.toml"), original_config).unwrap();
    fs::write(paths.codex_home.join("auth.json"), original_auth).unwrap();
    let installation_id = Uuid::new_v4();
    let request_secrets = secrets();
    let mut validator = AlwaysFailSemanticValidation;
    let mut vault = MemoryCredentialVault::default();
    let result = provision_configuration_with_validator(
        ProvisioningRequest {
            paths: &paths,
            spec: &spec,
            secrets: &request_secrets,
            operation_id: Uuid::new_v4(),
            installation_id,
            policy: ConflictPolicy::RejectUnmanaged,
        },
        &mut vault,
        &mut NoFault,
        &mut validator,
    );
    assert!(result.is_err());
    assert_eq!(
        fs::read(paths.codex_home.join("config.toml")).unwrap(),
        original_config
    );
    assert_eq!(
        fs::read(paths.codex_home.join("auth.json")).unwrap(),
        original_auth
    );
    assert!(!spec.model_catalog_path.exists());
    assert!(!vault.contains(&CredentialHandle {
        service: "provider-codex-v4".to_string(),
        account: installation_id.to_string(),
    }));
}
