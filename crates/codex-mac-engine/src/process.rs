//! Bounded child-process execution for the macOS engine.
//!
//! Every platform command is put in its own process group, stdout/stderr are
//! drained concurrently for the whole lifetime, and timeout/cancel kills the
//! complete group. This prevents BinaryDelta, codesign, Gatekeeper, curl, or
//! AppleScript helpers from leaving the installer stuck indefinitely.

use std::io::Read;
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_millis(50);
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(60);
pub const DEFAULT_MUTATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);
pub const DEFAULT_DELTA_TIMEOUT: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, Copy)]
pub struct RunLimits {
    pub total: Duration,
}

impl RunLimits {
    pub fn total(total: Duration) -> Self {
        Self { total }
    }

    pub fn probe() -> Self {
        Self::total(DEFAULT_PROBE_TIMEOUT)
    }

    pub fn mutation() -> Self {
        Self::total(DEFAULT_MUTATION_TIMEOUT)
    }

    pub fn delta() -> Self {
        Self::total(DEFAULT_DELTA_TIMEOUT)
    }
}

#[derive(Debug)]
pub enum RunError {
    Spawn(String),
    Timeout { partial_stderr: String },
    Cancelled { partial_stderr: String },
    Wait(String),
}

impl RunError {
    pub fn message(&self) -> String {
        match self {
            Self::Spawn(message) => format!("spawn failed: {message}"),
            Self::Timeout { partial_stderr } => format!(
                "process exceeded total deadline{}",
                stderr_suffix(partial_stderr)
            ),
            Self::Cancelled { partial_stderr } => {
                format!("process cancelled{}", stderr_suffix(partial_stderr))
            }
            Self::Wait(message) => format!("process wait failed: {message}"),
        }
    }
}

fn stderr_suffix(stderr: &str) -> String {
    let trimmed = stderr.trim();
    if trimmed.is_empty() {
        String::new()
    } else {
        format!(": {trimmed}")
    }
}

fn cancelled(flag: Option<&AtomicBool>) -> bool {
    flag.map(|value| value.load(Ordering::SeqCst))
        .unwrap_or(false)
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    // SAFETY: pre_exec invokes only async-signal-safe setpgid and constructs an
    // io::Error from errno. No allocator-backed application state is touched.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

fn terminate_group(child: &mut Child) {
    #[cfg(unix)]
    unsafe {
        // Child is the process-group leader configured immediately before exec.
        // Negative pid addresses the entire group, including grandchildren.
        let _ = libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn drain_stdout(mut pipe: ChildStdout) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    pipe.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn drain_stderr(mut pipe: ChildStderr) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    pipe.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Run a command with a hard deadline and optional cancellation.
/// Exit status is returned unchanged; callers retain domain-specific handling.
pub fn run_capturing(
    mut command: Command,
    limits: RunLimits,
    cancel: Option<&AtomicBool>,
) -> Result<Output, RunError> {
    configure_process_group(&mut command);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| RunError::Spawn(error.to_string()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| RunError::Wait("stdout pipe was not created".to_string()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| RunError::Wait("stderr pipe was not created".to_string()))?;
    let stdout_reader = thread::spawn(move || drain_stdout(stdout));
    let stderr_reader = thread::spawn(move || drain_stderr(stderr));

    let started = Instant::now();
    let status: Result<ExitStatus, RunError> = loop {
        if cancelled(cancel) {
            terminate_group(&mut child);
            break Err(RunError::Cancelled {
                partial_stderr: String::new(),
            });
        }
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if started.elapsed() >= limits.total => {
                terminate_group(&mut child);
                break Err(RunError::Timeout {
                    partial_stderr: String::new(),
                });
            }
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(error) => {
                terminate_group(&mut child);
                break Err(RunError::Wait(error.to_string()));
            }
        }
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| RunError::Wait("stdout reader panicked".to_string()))?
        .map_err(|error| RunError::Wait(format!("stdout read failed: {error}")))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| RunError::Wait("stderr reader panicked".to_string()))?
        .map_err(|error| RunError::Wait(format!("stderr read failed: {error}")))?;

    match status {
        Ok(status) => Ok(Output {
            status,
            stdout,
            stderr,
        }),
        Err(RunError::Timeout { .. }) => Err(RunError::Timeout {
            partial_stderr: String::from_utf8_lossy(&stderr).into_owned(),
        }),
        Err(RunError::Cancelled { .. }) => Err(RunError::Cancelled {
            partial_stderr: String::from_utf8_lossy(&stderr).into_owned(),
        }),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn sleep_command(seconds: u64) -> Command {
        #[cfg(windows)]
        {
            let mut command = Command::new("powershell.exe");
            command.args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!("Start-Sleep -Seconds {seconds}"),
            ]);
            command
        }
        #[cfg(not(windows))]
        {
            let mut command = Command::new("sleep");
            command.arg(seconds.to_string());
            command
        }
    }

    fn large_output_command(bytes_per_stream: usize) -> Command {
        #[cfg(windows)]
        {
            let mut command = Command::new("powershell.exe");
            command.args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "$s='m' * {bytes_per_stream}; [Console]::Out.Write($s); [Console]::Error.Write($s)"
                ),
            ]);
            command
        }
        #[cfg(not(windows))]
        {
            let mut command = Command::new("sh");
            command.args([
                "-c",
                &format!(
                    "head -c {bytes_per_stream} /dev/zero | tr '\\0' m; head -c {bytes_per_stream} /dev/zero | tr '\\0' m >&2"
                ),
            ]);
            command
        }
    }

    #[test]
    fn timeout_terminates_hung_child() {
        let error = run_capturing(
            sleep_command(60),
            RunLimits::total(Duration::from_millis(300)),
            None,
        )
        .expect_err("hung command must be terminated");
        assert!(matches!(error, RunError::Timeout { .. }));
    }

    #[test]
    fn cancellation_terminates_hung_child() {
        let flag = Arc::new(AtomicBool::new(false));
        let trigger = Arc::clone(&flag);
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            trigger.store(true, Ordering::SeqCst);
        });
        let error = run_capturing(
            sleep_command(60),
            RunLimits::total(Duration::from_secs(30)),
            Some(&flag),
        )
        .expect_err("cancelled command must be terminated");
        assert!(matches!(error, RunError::Cancelled { .. }));
        handle.join().unwrap();
    }

    #[test]
    fn drains_large_stdout_and_stderr_without_deadlock() {
        const BYTES: usize = 4 * 1024 * 1024;
        let output = run_capturing(
            large_output_command(BYTES),
            RunLimits::total(Duration::from_secs(30)),
            None,
        )
        .expect("large output must complete");
        assert!(output.status.success());
        assert_eq!(output.stdout.len(), BYTES);
        assert_eq!(output.stderr.len(), BYTES);
    }
}
