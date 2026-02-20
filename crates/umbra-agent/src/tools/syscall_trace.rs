use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct SyscallSummary {
    syscall: String,
    calls: u64,
    errors: u64,
    time_percent: f64,
}

#[derive(Serialize)]
struct StraceResult {
    pid: u32,
    duration_secs: u64,
    syscall_filter: Option<String>,
    summary: Vec<SyscallSummary>,
    raw_lines: Vec<String>,
    success: bool,
    error: Option<String>,
}

pub async fn trace(pid: u32, duration_secs: Option<u64>, syscall_filter: Option<&str>) -> String {
    let duration = duration_secs.unwrap_or(5).min(30); // cap at 30s
    let pid_str = pid.to_string();

    let mut strace_args: Vec<String> = vec![
        "-p".to_string(), pid_str.clone(),
        "-c".to_string(),
        "-S".to_string(), "calls".to_string(),
    ];

    if let Some(filter) = syscall_filter {
        strace_args.push("-e".to_string());
        strace_args.push(filter.to_string());
    }

    let duration_str = duration.to_string();
    let mut timeout_args = vec!["timeout", &duration_str, "strace"];
    let strace_refs: Vec<&str> = strace_args.iter().map(|s| s.as_str()).collect();
    timeout_args.extend_from_slice(&strace_refs);

    // strace outputs to stderr
    let result = cmd::run("env", &timeout_args, duration + 5).await;

    // strace -c summary is in stderr
    let output = &result.stderr;

    let summary: Vec<SyscallSummary> = output
        .lines()
        .filter(|l| {
            let trimmed = l.trim();
            !trimmed.is_empty()
                && !trimmed.starts_with('%')
                && !trimmed.starts_with("---")
                && !trimmed.contains("total")
                && !trimmed.contains("strace:")
        })
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let time_percent = parts[0].parse().unwrap_or(0.0);
                let calls = parts[2].parse().unwrap_or(0);
                let errors = parts[3].parse().unwrap_or(0);
                let syscall = parts.last().unwrap_or(&"?").to_string();
                Some(SyscallSummary {
                    syscall,
                    calls,
                    errors,
                    time_percent,
                })
            } else {
                None
            }
        })
        .collect();

    serde_json::to_string_pretty(&StraceResult {
        pid,
        duration_secs: duration,
        syscall_filter: syscall_filter.map(|f| f.to_string()),
        summary,
        raw_lines: output.lines().map(|l| l.to_string()).collect(),
        success: true,
        error: None,
    })
    .unwrap()
}
