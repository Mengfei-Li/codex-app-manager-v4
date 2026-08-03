use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use toml_edit::DocumentMut;
use uuid::Uuid;

use crate::atomic::replace_file;
use crate::config::{owner_only_permissions, ScanLimits};
use crate::contract::sha256_hex;
use crate::error::DeliveryError;

const OVERRIDE_KEYS: &[&str] = &[
    "model_provider",
    "openai_base_url",
    "model_catalog_json",
    "model",
    "review_model",
    "model_reasoning_effort",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationChange {
    pub target_path: String,
    pub backup_path: String,
    pub original_sha256: String,
    pub updated_sha256: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationIssue {
    pub target_path: String,
    pub stage: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationReport {
    pub schema_version: u32,
    pub operation_id: String,
    pub entries_scanned: usize,
    pub project_configs_discovered: usize,
    pub session_files_discovered: usize,
    pub project_configs_changed: usize,
    pub sessions_changed: usize,
    pub truncated: bool,
    pub changes: Vec<MigrationChange>,
    pub issues: Vec<MigrationIssue>,
    pub manifest_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreReport {
    pub restored: usize,
    pub failed: Vec<MigrationIssue>,
}

struct Discovery {
    project_configs: Vec<PathBuf>,
    session_files: Vec<PathBuf>,
    entries_scanned: usize,
    truncated: bool,
}

pub fn migrate_project_and_session_overrides(
    project_roots: &[PathBuf],
    sessions_root: &Path,
    backup_root: &Path,
    operation_id: Uuid,
    limits: &ScanLimits,
) -> Result<MigrationReport, DeliveryError> {
    fs::create_dir_all(backup_root)?;
    owner_only_permissions(backup_root, true)?;
    let mut discovery = discover_project_configs(project_roots, limits)?;
    let sessions = discover_session_files(sessions_root, limits)?;
    discovery.entries_scanned = discovery
        .entries_scanned
        .saturating_add(sessions.entries_scanned);
    discovery.truncated |= sessions.truncated;
    discovery.session_files = sessions.session_files;

    let project_configs_discovered = discovery.project_configs.len();
    let session_files_discovered = discovery.session_files.len();
    let mut report = MigrationReport {
        schema_version: 1,
        operation_id: operation_id.to_string(),
        entries_scanned: discovery.entries_scanned,
        project_configs_discovered,
        session_files_discovered,
        project_configs_changed: 0,
        sessions_changed: 0,
        truncated: discovery.truncated,
        changes: Vec::new(),
        issues: Vec::new(),
        manifest_path: backup_root
            .join("migration.json")
            .to_string_lossy()
            .to_string(),
    };

    for (index, path) in discovery.project_configs.iter().enumerate() {
        match repair_project_config(path, backup_root, index) {
            Ok(Some(change)) => {
                report.project_configs_changed += 1;
                report.changes.push(change);
            }
            Ok(None) => {}
            Err(error) => report.issues.push(issue(path, "project-config", error)),
        }
    }
    let offset = discovery.project_configs.len();
    for (index, path) in discovery.session_files.iter().enumerate() {
        match migrate_session_file(path, backup_root, offset + index) {
            Ok(Some(change)) => {
                report.sessions_changed += 1;
                report.changes.push(change);
            }
            Ok(None) => {}
            Err(error) => report.issues.push(issue(path, "session", error)),
        }
    }
    write_manifest(&report)?;
    Ok(report)
}

fn discover_project_configs(
    roots: &[PathBuf],
    limits: &ScanLimits,
) -> Result<Discovery, DeliveryError> {
    let mut queue = VecDeque::new();
    for root in roots {
        if root.is_dir() {
            queue.push_back((root.clone(), 0usize));
        }
    }
    let mut result = Discovery {
        project_configs: Vec::new(),
        session_files: Vec::new(),
        entries_scanned: 0,
        truncated: false,
    };
    while let Some((directory, depth)) = queue.pop_front() {
        if depth > limits.maximum_depth || result.entries_scanned >= limits.maximum_entries {
            result.truncated = true;
            continue;
        }
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries {
            if result.entries_scanned >= limits.maximum_entries {
                result.truncated = true;
                break;
            }
            result.entries_scanned += 1;
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            let path = entry.path();
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            if is_reparse_or_symlink(&metadata) {
                continue;
            }
            if metadata.is_dir() {
                queue.push_back((path, depth + 1));
            } else if metadata.is_file()
                && path.file_name().and_then(|name| name.to_str()) == Some("config.toml")
                && path
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|name| name.to_str())
                    == Some(".codex")
            {
                if result.project_configs.len() >= limits.maximum_project_files {
                    result.truncated = true;
                } else {
                    result.project_configs.push(path);
                }
            }
        }
    }
    Ok(result)
}

fn discover_session_files(root: &Path, limits: &ScanLimits) -> Result<Discovery, DeliveryError> {
    let mut result = Discovery {
        project_configs: Vec::new(),
        session_files: Vec::new(),
        entries_scanned: 0,
        truncated: false,
    };
    if !root.is_dir() {
        return Ok(result);
    }
    let mut queue = VecDeque::from([(root.to_path_buf(), 0usize)]);
    while let Some((directory, depth)) = queue.pop_front() {
        if depth > limits.maximum_depth || result.entries_scanned >= limits.maximum_entries {
            result.truncated = true;
            continue;
        }
        for entry in match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(_) => continue,
        } {
            if result.entries_scanned >= limits.maximum_entries {
                result.truncated = true;
                break;
            }
            result.entries_scanned += 1;
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            let path = entry.path();
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            if is_reparse_or_symlink(&metadata) {
                continue;
            }
            if metadata.is_dir() {
                queue.push_back((path, depth + 1));
            } else if metadata.is_file()
                && path.extension().and_then(|value| value.to_str()) == Some("jsonl")
            {
                if result.session_files.len() >= limits.maximum_session_files {
                    result.truncated = true;
                } else {
                    result.session_files.push(path);
                }
            }
        }
    }
    Ok(result)
}

fn repair_project_config(
    path: &Path,
    backup_root: &Path,
    index: usize,
) -> Result<Option<MigrationChange>, DeliveryError> {
    let original = fs::read(path)?;
    let text = std::str::from_utf8(&original)
        .map_err(|_| DeliveryError::Toml("project config is not UTF-8".to_string()))?;
    text.parse::<DocumentMut>()
        .map_err(|error| DeliveryError::Toml(error.to_string()))?;
    let (updated_text, changed) = strip_project_overrides_preserving(text);
    if !changed {
        return Ok(None);
    }
    updated_text
        .parse::<DocumentMut>()
        .map_err(|error| DeliveryError::Toml(format!("repaired project config: {error}")))?;
    let updated = updated_text.into_bytes();
    let backup = backup_root.join(format!("{index:05}-project-config.toml"));
    fs::write(&backup, &original)?;
    owner_only_permissions(&backup, false)?;
    atomic_replace(path, &updated)?;
    let readback = fs::read(path)?;
    std::str::from_utf8(&readback)
        .map_err(|_| DeliveryError::Toml("project readback is not UTF-8".to_string()))?
        .parse::<DocumentMut>()
        .map_err(|error| DeliveryError::Toml(error.to_string()))?;
    Ok(Some(MigrationChange {
        target_path: path.to_string_lossy().to_string(),
        backup_path: backup.to_string_lossy().to_string(),
        original_sha256: sha256_hex(&original),
        updated_sha256: sha256_hex(&readback),
        kind: "project-config".to_string(),
    }))
}

fn strip_project_overrides_preserving(source: &str) -> (String, bool) {
    let mut output = String::with_capacity(source.len());
    let mut changed = false;
    let mut skip_table = false;
    for line in source.split_inclusive('\n') {
        let trimmed = line.trim();
        if let Some(table_name) = toml_table_header(trimmed) {
            skip_table = matches!(
                table_name,
                "model_providers.openai" | "model_providers.relay"
            );
            if skip_table {
                changed = true;
                continue;
            }
        } else if skip_table {
            continue;
        }
        if !trimmed.starts_with('#') && !trimmed.starts_with('[') {
            if let Some((raw_key, _)) = trimmed.split_once('=') {
                let key = raw_key.trim();
                if OVERRIDE_KEYS.contains(&key)
                    || matches!(key, "model_providers.openai" | "model_providers.relay")
                {
                    changed = true;
                    continue;
                }
            }
        }
        output.push_str(line);
    }
    (output, changed)
}

fn toml_table_header(trimmed: &str) -> Option<&str> {
    if !trimmed.starts_with('[') || trimmed.starts_with("[[") {
        return None;
    }
    let end = trimmed.find(']')?;
    Some(trimmed[1..end].trim())
}

fn migrate_session_file(
    path: &Path,
    backup_root: &Path,
    index: usize,
) -> Result<Option<MigrationChange>, DeliveryError> {
    let original = fs::read(path)?;
    let text = std::str::from_utf8(&original).map_err(|_| {
        DeliveryError::Json(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "session is not UTF-8",
        )))
    })?;
    let mut changed = false;
    let mut output = String::with_capacity(text.len());
    for line_with_ending in text.split_inclusive('\n') {
        let (line, ending) = line_with_ending
            .strip_suffix("\r\n")
            .map(|line| (line, "\r\n"))
            .or_else(|| line_with_ending.strip_suffix('\n').map(|line| (line, "\n")))
            .unwrap_or((line_with_ending, ""));
        if line.trim().is_empty() {
            output.push_str(line);
            output.push_str(ending);
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line)?;
        let provider = value
            .get("payload")
            .and_then(|payload| payload.get("model_provider"))
            .and_then(serde_json::Value::as_str);
        if provider == Some("relay") {
            output.push_str(&replace_unique_json_string_field(
                line,
                "model_provider",
                "relay",
                "openai",
            )?);
            changed = true;
        } else {
            output.push_str(line);
        }
        output.push_str(ending);
    }
    if !changed {
        return Ok(None);
    }
    let updated = output.into_bytes();
    let backup = backup_root.join(format!("{index:05}-session.jsonl"));
    fs::write(&backup, &original)?;
    owner_only_permissions(&backup, false)?;
    atomic_replace(path, &updated)?;
    let readback = fs::read(path)?;
    if readback == original {
        return Err(DeliveryError::ConfigTransaction(
            "session migration made no durable change".to_string(),
        ));
    }
    Ok(Some(MigrationChange {
        target_path: path.to_string_lossy().to_string(),
        backup_path: backup.to_string_lossy().to_string(),
        original_sha256: sha256_hex(&original),
        updated_sha256: sha256_hex(&readback),
        kind: "session".to_string(),
    }))
}

fn replace_unique_json_string_field(
    line: &str,
    field: &str,
    old_value: &str,
    new_value: &str,
) -> Result<String, DeliveryError> {
    let needle = serde_json::to_string(field)?;
    let expected = serde_json::to_string(old_value)?;
    let replacement = serde_json::to_string(new_value)?;
    let mut matches = Vec::new();
    let mut offset = 0;
    while let Some(relative) = line[offset..].find(&needle) {
        let field_start = offset + relative;
        let mut cursor = field_start + needle.len();
        while line
            .as_bytes()
            .get(cursor)
            .is_some_and(u8::is_ascii_whitespace)
        {
            cursor += 1;
        }
        if line.as_bytes().get(cursor) != Some(&b':') {
            offset = field_start + needle.len();
            continue;
        }
        cursor += 1;
        while line
            .as_bytes()
            .get(cursor)
            .is_some_and(u8::is_ascii_whitespace)
        {
            cursor += 1;
        }
        if line[cursor..].starts_with(&expected) {
            matches.push((cursor, cursor + expected.len()));
        }
        offset = field_start + needle.len();
    }
    if matches.len() != 1 {
        return Err(DeliveryError::ConfigTransaction(format!(
            "expected exactly one {field} field, found {}",
            matches.len()
        )));
    }
    let (start, end) = matches[0];
    let mut output = String::with_capacity(line.len() + replacement.len());
    output.push_str(&line[..start]);
    output.push_str(&replacement);
    output.push_str(&line[end..]);
    Ok(output)
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), DeliveryError> {
    let temporary = path.with_extension(format!("v4-migrate-{}", Uuid::new_v4().simple()));
    fs::write(&temporary, bytes)?;
    if path.exists() {
        preserve_target_permissions(path, &temporary)?;
    } else {
        owner_only_permissions(&temporary, false)?;
    }
    fs::OpenOptions::new()
        .write(true)
        .open(&temporary)?
        .sync_all()?;
    replace_file(&temporary, path)?;
    if fs::read(path)? != bytes {
        return Err(DeliveryError::ConfigTransaction(format!(
            "migration readback mismatch: {}",
            path.display()
        )));
    }
    Ok(())
}

fn preserve_target_permissions(source: &Path, target: &Path) -> Result<(), DeliveryError> {
    #[cfg(unix)]
    fs::set_permissions(target, fs::metadata(source)?.permissions())?;
    #[cfg(windows)]
    crate::windows_security::copy_dacl(source, target)?;
    Ok(())
}

fn issue(path: &Path, stage: &str, error: DeliveryError) -> MigrationIssue {
    MigrationIssue {
        target_path: path.to_string_lossy().to_string(),
        stage: stage.to_string(),
        error: error.to_string(),
    }
}

fn write_manifest(report: &MigrationReport) -> Result<(), DeliveryError> {
    let bytes = serde_json::to_vec_pretty(report)?;
    atomic_replace(Path::new(&report.manifest_path), &bytes)
}

pub fn restore_migration(manifest_path: &Path) -> Result<RestoreReport, DeliveryError> {
    let report: MigrationReport = serde_json::from_slice(&fs::read(manifest_path)?)?;
    let mut restored = 0;
    let mut failed = Vec::new();
    for change in report.changes {
        let target = PathBuf::from(&change.target_path);
        let backup = PathBuf::from(&change.backup_path);
        match fs::read(&backup)
            .map_err(DeliveryError::from)
            .and_then(|bytes| atomic_replace(&target, &bytes))
        {
            Ok(()) => restored += 1,
            Err(error) => failed.push(issue(&target, "restore", error)),
        }
    }
    Ok(RestoreReport { restored, failed })
}

fn is_reparse_or_symlink(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    false
}
