//! Official Microsoft Store Web Installer route for Codex.
//!
//! This route is attempted before the verified offline MSIX fallback. Both the
//! download and installer process have hard wall-clock bounds; the downloaded
//! executable is accepted only when Windows reports a valid signature with the
//! exact Microsoft Corporation publisher subject.

use std::path::Path;
#[cfg(windows)]
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[cfg(windows)]
use crate::authenticode::verify_microsoft_web_installer_authenticode;
use crate::authenticode::AuthenticodeReport;
use crate::network::NetworkConfig;
#[cfg(windows)]
use crate::network::SchannelRevocationCheck;
#[cfg(windows)]
use crate::process::{curl_exe, hidden_command, run_capturing, run_with_progress, RunLimits};
use crate::EngineError;

pub const OFFICIAL_CODEX_WEB_INSTALLER_URL: &str =
    "https://get.microsoft.com/installer/download/9PLM9XGG6VKS?cid=website_cta_psi";
pub const WEB_INSTALLER_MAX_BYTES: u64 = 128 * 1024 * 1024;
pub const WEB_INSTALLER_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(90);
pub const WEB_INSTALLER_STALL_TIMEOUT: Duration = Duration::from_secs(30);
pub const WEB_INSTALLER_EXECUTION_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebInstallerExecution {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub message: String,
    pub stdout: String,
    pub stderr: String,
}

pub fn download_and_verify_official_web_installer(
    destination: &Path,
    network: &NetworkConfig,
    on_progress: &dyn Fn(u64),
) -> Result<AuthenticodeReport, EngineError> {
    #[cfg(not(windows))]
    {
        let _ = (destination, network, on_progress);
        Err(EngineError::Install(
            "official Web Installer is only available on Windows".to_string(),
        ))
    }

    #[cfg(windows)]
    {
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| EngineError::Io(format!("create Web Installer cache: {error}")))?;
        }
        let _ = std::fs::remove_file(destination);
        let mut command = hidden_command(curl_exe());
        command.args(network.curl_args_with_schannel_revocation(SchannelRevocationCheck::Strict));
        command.args([
            "-fL",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--no-progress-meter",
            "--connect-timeout",
            "20",
            "--max-time",
            "90",
            "--max-filesize",
            &WEB_INSTALLER_MAX_BYTES.to_string(),
            "--retry",
            "1",
            "-o",
            &destination.to_string_lossy(),
            OFFICIAL_CODEX_WEB_INSTALLER_URL,
        ]);
        let output = run_with_progress(
            command,
            RunLimits::with_stall(WEB_INSTALLER_DOWNLOAD_TIMEOUT, WEB_INSTALLER_STALL_TIMEOUT),
            None,
            &|| {
                std::fs::metadata(destination)
                    .map(|meta| meta.len())
                    .unwrap_or(0)
            },
            on_progress,
        )
        .map_err(|error| EngineError::Io(format!("Web Installer download: {}", error.message())))?;
        if !output.status.success() {
            return Err(EngineError::Io(format!(
                "Web Installer download failed exit={}: {}",
                output
                    .status
                    .code()
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "signal".to_string()),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let size = std::fs::metadata(destination)
            .map_err(|error| EngineError::Io(format!("stat Web Installer: {error}")))?
            .len();
        if size == 0 || size > WEB_INSTALLER_MAX_BYTES {
            let _ = std::fs::remove_file(destination);
            return Err(EngineError::Io(format!(
                "Web Installer size outside accepted range: {size}"
            )));
        }
        on_progress(size);
        match verify_microsoft_web_installer_authenticode(destination) {
            Ok(report) => Ok(report),
            Err(error) => {
                let _ = std::fs::remove_file(destination);
                Err(error)
            }
        }
    }
}

pub fn execute_official_web_installer(
    installer: &Path,
) -> Result<WebInstallerExecution, EngineError> {
    #[cfg(not(windows))]
    {
        let _ = installer;
        Err(EngineError::Install(
            "official Web Installer is only available on Windows".to_string(),
        ))
    }

    #[cfg(windows)]
    {
        // Deliberately use Command::new rather than CREATE_NO_WINDOW: this is a
        // signed GUI installer and may need to show a Windows-native prompt.
        let command = Command::new(installer);
        let output = run_capturing(
            command,
            RunLimits::total(WEB_INSTALLER_EXECUTION_TIMEOUT),
            None,
        )
        .map_err(|error| EngineError::Install(format!("Web Installer: {}", error.message())))?;
        let success = output.status.success();
        Ok(WebInstallerExecution {
            success,
            exit_code: output.status.code(),
            message: if success {
                "Microsoft Web Installer completed.".to_string()
            } else {
                format!("Microsoft Web Installer exited with {}.", output.status)
            },
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_installer_contract_is_pinned_and_bounded() {
        assert!(OFFICIAL_CODEX_WEB_INSTALLER_URL.starts_with("https://get.microsoft.com/"));
        assert!(OFFICIAL_CODEX_WEB_INSTALLER_URL.contains("9PLM9XGG6VKS"));
        assert!(WEB_INSTALLER_DOWNLOAD_TIMEOUT < WEB_INSTALLER_EXECUTION_TIMEOUT);
        const {
            assert!(WEB_INSTALLER_MAX_BYTES <= 128 * 1024 * 1024);
        }
    }
}
