use tokio::process::Command;

/// Check if a program is available on PATH.
pub async fn is_available(program: &str) -> bool {
    Command::new("which")
        .arg(program)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Standard error JSON when a binary is not found.
pub fn binary_not_found(program: &str, fallback: Option<&str>) -> String {
    let msg = match fallback {
        Some(fb) => format!(
            "Neither '{program}' nor '{fb}' found on PATH. Install the tool to use this feature."
        ),
        None => format!("'{program}' not found on PATH. Install the tool to use this feature."),
    };
    serde_json::json!({
        "error": msg,
        "tool_available": false,
    })
    .to_string()
}

/// Result of running a shell command.
pub struct CmdResult {
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
    pub exit_code: Option<i32>,
}

impl CmdResult {
    pub fn error_json(&self) -> String {
        serde_json::json!({
            "error": self.stderr.trim(),
            "exit_code": self.exit_code,
        })
        .to_string()
    }
}

/// Run a command with timeout. Returns structured result.
pub async fn run(program: &str, args: &[&str], timeout_secs: u64) -> CmdResult {
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        Command::new(program).args(args).output(),
    )
    .await;

    match result {
        Ok(Ok(output)) => CmdResult {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            success: output.status.success(),
            exit_code: output.status.code(),
        },
        Ok(Err(e)) => CmdResult {
            stdout: String::new(),
            stderr: format!("{program}: {e}"),
            success: false,
            exit_code: None,
        },
        Err(_) => CmdResult {
            stdout: String::new(),
            stderr: format!("{program}: timed out after {timeout_secs}s"),
            success: false,
            exit_code: None,
        },
    }
}

/// Run a command with custom environment variables.
pub async fn run_with_env(
    program: &str,
    args: &[&str],
    env: &[(&str, &str)],
    timeout_secs: u64,
) -> CmdResult {
    let mut cmd = Command::new(program);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        cmd.output(),
    )
    .await;

    match result {
        Ok(Ok(output)) => CmdResult {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            success: output.status.success(),
            exit_code: output.status.code(),
        },
        Ok(Err(e)) => CmdResult {
            stdout: String::new(),
            stderr: format!("{program}: {e}"),
            success: false,
            exit_code: None,
        },
        Err(_) => CmdResult {
            stdout: String::new(),
            stderr: format!("{program}: timed out after {timeout_secs}s"),
            success: false,
            exit_code: None,
        },
    }
}

/// Run a command with stdin input.
pub async fn run_with_stdin(
    program: &str,
    args: &[&str],
    stdin_data: &str,
    timeout_secs: u64,
) -> CmdResult {
    use tokio::io::AsyncWriteExt;

    let child = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            return CmdResult {
                stdout: String::new(),
                stderr: format!("{program}: {e}"),
                success: false,
                exit_code: None,
            };
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(stdin_data.as_bytes()).await;
        drop(stdin);
    }

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        child.wait_with_output(),
    )
    .await;

    match result {
        Ok(Ok(output)) => CmdResult {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            success: output.status.success(),
            exit_code: output.status.code(),
        },
        Ok(Err(e)) => CmdResult {
            stdout: String::new(),
            stderr: format!("{program}: {e}"),
            success: false,
            exit_code: None,
        },
        Err(_) => {
            // child was consumed by wait_with_output, nothing to kill
            CmdResult {
                stdout: String::new(),
                stderr: format!("{program}: timed out after {timeout_secs}s"),
                success: false,
                exit_code: None,
            }
        }
    }
}
