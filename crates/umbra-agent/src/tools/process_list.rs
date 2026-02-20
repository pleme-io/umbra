use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
struct ProcessInfo {
    pid: u32,
    ppid: Option<u32>,
    name: String,
    state: String,
    user: Option<String>,
    cpu_percent: Option<f64>,
    mem_rss_kb: Option<u64>,
    mem_vms_kb: Option<u64>,
    threads: Option<u32>,
    cmdline: String,
}

#[derive(Serialize)]
struct ProcessListResult {
    processes: Vec<ProcessInfo>,
    total: usize,
    success: bool,
    error: Option<String>,
}

pub async fn list() -> String {
    // Read from /proc for structured data (Linux)
    if Path::new("/proc").exists() {
        return list_from_proc();
    }

    serde_json::to_string_pretty(&ProcessListResult {
        processes: vec![],
        total: 0,
        success: false,
        error: Some("/proc not available".to_string()),
    })
    .unwrap()
}

fn list_from_proc() -> String {
    let mut processes = Vec::new();

    let entries = match std::fs::read_dir("/proc") {
        Ok(e) => e,
        Err(e) => {
            return serde_json::to_string_pretty(&ProcessListResult {
                processes: vec![],
                total: 0,
                success: false,
                error: Some(format!("Cannot read /proc: {e}")),
            })
            .unwrap();
        }
    };

    let clock_ticks = 100u64; // sysconf(_SC_CLK_TCK) is typically 100
    let uptime = read_uptime().unwrap_or(0.0);

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if let Ok(pid) = name_str.parse::<u32>() {
            if let Some(info) = read_process(pid, uptime, clock_ticks) {
                processes.push(info);
            }
        }
    }

    processes.sort_by_key(|p| p.pid);
    let total = processes.len();

    serde_json::to_string_pretty(&ProcessListResult {
        processes,
        total,
        success: true,
        error: None,
    })
    .unwrap()
}

fn read_process(pid: u32, uptime: f64, clock_ticks: u64) -> Option<ProcessInfo> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
        .ok()
        .map(|s| s.replace('\0', " ").trim().to_string())
        .unwrap_or_default();

    // Parse /proc/PID/stat: pid (comm) state ppid ...
    let comm_start = stat.find('(')?;
    let comm_end = stat.rfind(')')?;
    let name = stat[comm_start + 1..comm_end].to_string();
    let after_comm: Vec<&str> = stat[comm_end + 2..].split_whitespace().collect();

    let state = after_comm.first().unwrap_or(&"?").to_string();
    let ppid: Option<u32> = after_comm.get(1).and_then(|s| s.parse().ok());
    let utime: u64 = after_comm.get(11).and_then(|s| s.parse().ok()).unwrap_or(0);
    let stime: u64 = after_comm.get(12).and_then(|s| s.parse().ok()).unwrap_or(0);
    let starttime: u64 = after_comm.get(19).and_then(|s| s.parse().ok()).unwrap_or(0);
    let threads: Option<u32> = after_comm.get(17).and_then(|s| s.parse().ok());

    // CPU percentage estimate
    let total_time = utime + stime;
    let seconds = uptime - (starttime as f64 / clock_ticks as f64);
    let cpu_percent = if seconds > 0.0 {
        Some((total_time as f64 / clock_ticks as f64 / seconds) * 100.0)
    } else {
        None
    };

    // Memory from /proc/PID/status
    let mut mem_rss_kb = None;
    let mut mem_vms_kb = None;
    let mut user = None;
    for line in status.lines() {
        if let Some(val) = line.strip_prefix("VmRSS:") {
            mem_rss_kb = val.trim().strip_suffix(" kB").and_then(|v| v.trim().parse().ok());
        } else if let Some(val) = line.strip_prefix("VmSize:") {
            mem_vms_kb = val.trim().strip_suffix(" kB").and_then(|v| v.trim().parse().ok());
        } else if let Some(val) = line.strip_prefix("Uid:") {
            let uid: u32 = val.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
            user = Some(format!("{uid}"));
        }
    }

    Some(ProcessInfo {
        pid,
        ppid,
        name,
        state: decode_state(&state),
        user,
        cpu_percent: cpu_percent.map(|c| (c * 100.0).round() / 100.0),
        mem_rss_kb,
        mem_vms_kb,
        threads,
        cmdline,
    })
}

fn decode_state(s: &str) -> String {
    match s {
        "R" => "running".to_string(),
        "S" => "sleeping".to_string(),
        "D" => "disk_sleep".to_string(),
        "Z" => "zombie".to_string(),
        "T" => "stopped".to_string(),
        "t" => "tracing_stop".to_string(),
        "X" | "x" => "dead".to_string(),
        other => other.to_string(),
    }
}

fn read_uptime() -> Option<f64> {
    let content = std::fs::read_to_string("/proc/uptime").ok()?;
    content.split_whitespace().next()?.parse().ok()
}
