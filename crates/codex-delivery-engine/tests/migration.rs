use std::fs;
use std::path::PathBuf;

use codex_delivery_engine::{migrate_project_and_session_overrides, restore_migration, ScanLimits};
use uuid::Uuid;

fn limits() -> ScanLimits {
    ScanLimits {
        maximum_depth: 6,
        maximum_entries: 100,
        maximum_project_files: 8,
        maximum_session_files: 8,
    }
}

#[test]
fn project_and_session_migration_is_bounded_and_preserves_unrelated_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let projects = temp.path().join("projects");
    let project_config = projects.join("alpha").join(".codex").join("config.toml");
    fs::create_dir_all(project_config.parent().unwrap()).unwrap();
    fs::write(
        &project_config,
        b"# keep comment\nmodel_provider = \"relay\"\nopenai_base_url = \"https://old.invalid\"\nunknown = \"keep\"\n",
    )
    .unwrap();
    let untouched = projects.join("beta").join(".codex").join("config.toml");
    fs::create_dir_all(untouched.parent().unwrap()).unwrap();
    fs::write(&untouched, b"unknown = \"untouched\"\n").unwrap();

    let sessions = temp.path().join("sessions");
    fs::create_dir_all(&sessions).unwrap();
    let session = sessions.join("one.jsonl");
    let before_line = r#"{"timestamp":"same","payload":{"model_provider":"relay","body":"relay must stay in body"},"other":7}"#;
    fs::write(&session, format!("{before_line}\r\n")).unwrap();
    let backup = temp.path().join("backup");
    let report = migrate_project_and_session_overrides(
        std::slice::from_ref(&projects),
        &sessions,
        &backup,
        Uuid::new_v4(),
        &limits(),
    )
    .unwrap();

    assert_eq!(report.project_configs_discovered, 2);
    assert_eq!(report.session_files_discovered, 1);
    assert_eq!(report.project_configs_changed, 1);
    assert_eq!(report.sessions_changed, 1);
    assert!(report.issues.is_empty());
    let repaired = fs::read_to_string(&project_config).unwrap();
    assert!(repaired.contains("# keep comment"));
    assert!(repaired.contains("unknown = \"keep\""));
    assert!(!repaired.contains("model_provider"));
    assert!(!repaired.contains("openai_base_url"));
    assert_eq!(fs::read(&untouched).unwrap(), b"unknown = \"untouched\"\n");
    let after = fs::read_to_string(&session).unwrap();
    assert_eq!(
        after,
        before_line.replacen(
            "\"model_provider\":\"relay\"",
            "\"model_provider\":\"openai\"",
            1
        ) + "\r\n"
    );
    assert!(after.contains("relay must stay in body"));
}

#[test]
fn corrupt_file_does_not_short_circuit_other_files() {
    let temp = tempfile::tempdir().unwrap();
    let projects = temp.path().join("projects");
    let bad = projects.join("bad").join(".codex").join("config.toml");
    let good = projects.join("good").join(".codex").join("config.toml");
    fs::create_dir_all(bad.parent().unwrap()).unwrap();
    fs::create_dir_all(good.parent().unwrap()).unwrap();
    fs::write(&bad, b"this = [invalid\n").unwrap();
    fs::write(&good, b"model = \"old\"\nkeep = true\n").unwrap();
    let report = migrate_project_and_session_overrides(
        std::slice::from_ref(&projects),
        &temp.path().join("sessions"),
        &temp.path().join("backup"),
        Uuid::new_v4(),
        &limits(),
    )
    .unwrap();
    assert_eq!(report.project_configs_changed, 1);
    assert_eq!(report.issues.len(), 1);
    assert!(fs::read_to_string(&good).unwrap().contains("keep = true"));
    assert!(!fs::read_to_string(&good).unwrap().contains("model ="));
    assert_eq!(fs::read(&bad).unwrap(), b"this = [invalid\n");
}

#[test]
fn scan_budgets_are_reported_instead_of_unbounded_traversal() {
    let temp = tempfile::tempdir().unwrap();
    let projects = temp.path().join("projects");
    for index in 0..10 {
        let path = projects
            .join(format!("p{index}"))
            .join(".codex")
            .join("config.toml");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"model = \"old\"\n").unwrap();
    }
    let constrained = ScanLimits {
        maximum_depth: 6,
        maximum_entries: 12,
        maximum_project_files: 2,
        maximum_session_files: 1,
    };
    let report = migrate_project_and_session_overrides(
        std::slice::from_ref(&projects),
        &temp.path().join("sessions"),
        &temp.path().join("backup"),
        Uuid::new_v4(),
        &constrained,
    )
    .unwrap();
    assert!(report.truncated);
    assert!(report.entries_scanned <= constrained.maximum_entries);
    assert!(report.project_configs_discovered <= constrained.maximum_project_files);
}

#[test]
fn restore_continues_when_one_backup_is_missing() {
    let temp = tempfile::tempdir().unwrap();
    let projects = temp.path().join("projects");
    let first = projects.join("first").join(".codex").join("config.toml");
    let second = projects.join("second").join(".codex").join("config.toml");
    for path in [&first, &second] {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"model = \"old\"\nkeep = true\n").unwrap();
    }
    let report = migrate_project_and_session_overrides(
        std::slice::from_ref(&projects),
        &temp.path().join("sessions"),
        &temp.path().join("backup"),
        Uuid::new_v4(),
        &limits(),
    )
    .unwrap();
    assert_eq!(report.changes.len(), 2);
    fs::remove_file(&report.changes[0].backup_path).unwrap();
    let restored = restore_migration(PathBuf::from(report.manifest_path).as_path()).unwrap();
    assert_eq!(restored.restored, 1);
    assert_eq!(restored.failed.len(), 1);
}
