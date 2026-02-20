use serde::Serialize;

#[derive(Serialize)]
struct ResourceUsage {
    cpu: CpuInfo,
    memory: MemoryInfo,
    cgroup: CgroupInfo,
    oom: OomInfo,
    load_average: Option<[f64; 3]>,
    uptime_seconds: Option<f64>,
    success: bool,
    errors: Vec<String>,
}

#[derive(Serialize, Default)]
struct CpuInfo {
    /// Number of CPUs available (from nproc or cgroup)
    available_cpus: Option<f64>,
    /// cgroup CPU quota (e.g. "500m" = 0.5 cores)
    cpu_quota: Option<String>,
    /// CPU usage from /proc/stat
    usage_percent: Option<f64>,
    /// Per-process CPU from /proc/[pid]/stat
    top_processes: Vec<ProcessCpu>,
}

#[derive(Serialize)]
struct ProcessCpu {
    pid: i64,
    name: String,
    cpu_percent: f64,
    threads: i64,
}

#[derive(Serialize, Default)]
struct MemoryInfo {
    total_bytes: Option<i64>,
    used_bytes: Option<i64>,
    available_bytes: Option<i64>,
    usage_percent: Option<f64>,
    swap_total_bytes: Option<i64>,
    swap_used_bytes: Option<i64>,
    /// Per-process memory
    top_processes: Vec<ProcessMemory>,
}

#[derive(Serialize)]
struct ProcessMemory {
    pid: i64,
    name: String,
    rss_bytes: i64,
    percent: f64,
}

#[derive(Serialize, Default)]
struct CgroupInfo {
    version: Option<String>,
    memory_limit: Option<i64>,
    memory_usage: Option<i64>,
    memory_max_usage: Option<i64>,
    memory_percent: Option<f64>,
    cpu_quota_us: Option<i64>,
    cpu_period_us: Option<i64>,
    cpu_shares: Option<i64>,
    pids_current: Option<i64>,
    pids_limit: Option<i64>,
}

#[derive(Serialize, Default)]
struct OomInfo {
    oom_kill_count: i64,
    processes_near_limit: Vec<String>,
}

pub async fn check() -> String {
    let mut usage = ResourceUsage {
        cpu: CpuInfo::default(),
        memory: MemoryInfo::default(),
        cgroup: CgroupInfo::default(),
        oom: OomInfo::default(),
        load_average: None,
        uptime_seconds: None,
        success: true,
        errors: Vec::new(),
    };

    // Read load average and uptime
    if let Ok(content) = std::fs::read_to_string("/proc/loadavg") {
        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() >= 3 {
            let load: Vec<f64> = parts[..3]
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect();
            if load.len() == 3 {
                usage.load_average = Some([load[0], load[1], load[2]]);
            }
        }
    }

    if let Ok(content) = std::fs::read_to_string("/proc/uptime") {
        usage.uptime_seconds = content
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok());
    }

    // Memory from /proc/meminfo
    if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
        let mut total: i64 = 0;
        let mut available: i64 = 0;
        let mut free: i64 = 0;
        let mut buffers: i64 = 0;
        let mut cached: i64 = 0;
        let mut swap_total: i64 = 0;
        let mut swap_free: i64 = 0;

        for line in content.lines() {
            if let Some((key, val)) = line.split_once(':') {
                let val_kb: i64 = val
                    .trim()
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                match key.trim() {
                    "MemTotal" => total = val_kb * 1024,
                    "MemAvailable" => available = val_kb * 1024,
                    "MemFree" => free = val_kb * 1024,
                    "Buffers" => buffers = val_kb * 1024,
                    "Cached" => cached = val_kb * 1024,
                    "SwapTotal" => swap_total = val_kb * 1024,
                    "SwapFree" => swap_free = val_kb * 1024,
                    _ => {}
                }
            }
        }

        if available == 0 {
            available = free + buffers + cached;
        }
        let used = total - available;

        usage.memory.total_bytes = Some(total);
        usage.memory.used_bytes = Some(used);
        usage.memory.available_bytes = Some(available);
        usage.memory.swap_total_bytes = if swap_total > 0 { Some(swap_total) } else { None };
        usage.memory.swap_used_bytes = if swap_total > 0 {
            Some(swap_total - swap_free)
        } else {
            None
        };
        if total > 0 {
            usage.memory.usage_percent =
                Some(((used as f64 / total as f64) * 10000.0).round() / 100.0);
        }
    }

    // cgroup v2 detection
    let cgroup_v2 = std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
    if cgroup_v2 {
        usage.cgroup.version = Some("v2".into());
        parse_cgroup_v2(&mut usage.cgroup);
    } else if std::path::Path::new("/sys/fs/cgroup/memory").exists() {
        usage.cgroup.version = Some("v1".into());
        parse_cgroup_v1(&mut usage.cgroup);
    }

    // Compute cgroup memory percent
    if let (Some(limit), Some(current)) = (usage.cgroup.memory_limit, usage.cgroup.memory_usage) {
        if limit > 0 {
            usage.cgroup.memory_percent =
                Some(((current as f64 / limit as f64) * 10000.0).round() / 100.0);
        }
    }

    // CPU info
    if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
        let cpus = content.matches("processor\t").count();
        if cpus > 0 {
            usage.cpu.available_cpus = Some(cpus as f64);
        }
    }

    // CPU quota from cgroup
    if let (Some(quota), Some(period)) =
        (usage.cgroup.cpu_quota_us, usage.cgroup.cpu_period_us)
    {
        if quota > 0 && period > 0 {
            let cores = quota as f64 / period as f64;
            usage.cpu.cpu_quota = Some(format!("{:.2} cores", cores));
        }
    }

    // Top processes by memory (from /proc)
    parse_top_processes(&mut usage);

    // OOM detection
    if cgroup_v2 {
        if let Ok(content) = std::fs::read_to_string("/sys/fs/cgroup/memory.events") {
            for line in content.lines() {
                if let Some(val) = line.strip_prefix("oom_kill ") {
                    usage.oom.oom_kill_count = val.trim().parse().unwrap_or(0);
                }
            }
        }
    } else if let Ok(content) =
        std::fs::read_to_string("/sys/fs/cgroup/memory/memory.oom_control")
    {
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("oom_kill ") {
                usage.oom.oom_kill_count = val.trim().parse().unwrap_or(0);
            }
        }
    }

    // Check if any process is near limit
    if let Some(limit) = usage.cgroup.memory_limit {
        if let Some(current) = usage.cgroup.memory_usage {
            let threshold = (limit as f64 * 0.9) as i64;
            if current > threshold {
                usage.oom.processes_near_limit.push(format!(
                    "Container using {:.1}% of memory limit ({} / {})",
                    (current as f64 / limit as f64) * 100.0,
                    human_bytes(current),
                    human_bytes(limit)
                ));
            }
        }
    }

    serde_json::to_string_pretty(&usage).unwrap()
}

fn parse_cgroup_v2(cg: &mut CgroupInfo) {
    if let Ok(content) = std::fs::read_to_string("/sys/fs/cgroup/memory.max") {
        let val = content.trim();
        if val != "max" {
            cg.memory_limit = val.parse().ok();
        }
    }
    if let Ok(content) = std::fs::read_to_string("/sys/fs/cgroup/memory.current") {
        cg.memory_usage = content.trim().parse().ok();
    }
    if let Ok(content) = std::fs::read_to_string("/sys/fs/cgroup/memory.peak") {
        cg.memory_max_usage = content.trim().parse().ok();
    }
    if let Ok(content) = std::fs::read_to_string("/sys/fs/cgroup/cpu.max") {
        let parts: Vec<&str> = content.trim().split_whitespace().collect();
        if parts.len() >= 2 {
            cg.cpu_quota_us = if parts[0] == "max" {
                None
            } else {
                parts[0].parse().ok()
            };
            cg.cpu_period_us = parts[1].parse().ok();
        }
    }
    if let Ok(content) = std::fs::read_to_string("/sys/fs/cgroup/cpu.weight") {
        cg.cpu_shares = content.trim().parse().ok();
    }
    if let Ok(content) = std::fs::read_to_string("/sys/fs/cgroup/pids.current") {
        cg.pids_current = content.trim().parse().ok();
    }
    if let Ok(content) = std::fs::read_to_string("/sys/fs/cgroup/pids.max") {
        let val = content.trim();
        if val != "max" {
            cg.pids_limit = val.parse().ok();
        }
    }
}

fn parse_cgroup_v1(cg: &mut CgroupInfo) {
    if let Ok(content) =
        std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes")
    {
        let val: i64 = content.trim().parse().unwrap_or(0);
        // 2^63 -1 means no limit
        if val > 0 && val < (1i64 << 62) {
            cg.memory_limit = Some(val);
        }
    }
    if let Ok(content) =
        std::fs::read_to_string("/sys/fs/cgroup/memory/memory.usage_in_bytes")
    {
        cg.memory_usage = content.trim().parse().ok();
    }
    if let Ok(content) =
        std::fs::read_to_string("/sys/fs/cgroup/memory/memory.max_usage_in_bytes")
    {
        cg.memory_max_usage = content.trim().parse().ok();
    }
    if let Ok(content) = std::fs::read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_quota_us") {
        let val: i64 = content.trim().parse().unwrap_or(-1);
        if val > 0 {
            cg.cpu_quota_us = Some(val);
        }
    }
    if let Ok(content) = std::fs::read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_period_us") {
        cg.cpu_period_us = content.trim().parse().ok();
    }
    if let Ok(content) = std::fs::read_to_string("/sys/fs/cgroup/cpu/cpu.shares") {
        cg.cpu_shares = content.trim().parse().ok();
    }
    if let Ok(content) = std::fs::read_to_string("/sys/fs/cgroup/pids/pids.current") {
        cg.pids_current = content.trim().parse().ok();
    }
    if let Ok(content) = std::fs::read_to_string("/sys/fs/cgroup/pids/pids.max") {
        let val = content.trim();
        if val != "max" {
            cg.pids_limit = val.parse().ok();
        }
    }
}

fn parse_top_processes(usage: &mut ResourceUsage) {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return;
    };

    let mut procs: Vec<(i64, String, i64)> = Vec::new(); // pid, name, rss_bytes

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let pid: i64 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let status_path = format!("/proc/{pid}/status");
        let Ok(status) = std::fs::read_to_string(&status_path) else {
            continue;
        };

        let mut proc_name = String::new();
        let mut rss_kb: i64 = 0;

        for line in status.lines() {
            if let Some(val) = line.strip_prefix("Name:\t") {
                proc_name = val.trim().to_string();
            } else if let Some(val) = line.strip_prefix("VmRSS:\t") {
                rss_kb = val
                    .trim()
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            }
        }

        if !proc_name.is_empty() && rss_kb > 0 {
            procs.push((pid, proc_name, rss_kb * 1024));
        }
    }

    procs.sort_by(|a, b| b.2.cmp(&a.2));

    let total_mem = usage.memory.total_bytes.unwrap_or(1);
    usage.memory.top_processes = procs
        .iter()
        .take(10)
        .map(|(pid, name, rss)| ProcessMemory {
            pid: *pid,
            name: name.clone(),
            rss_bytes: *rss,
            percent: ((*rss as f64 / total_mem as f64) * 10000.0).round() / 100.0,
        })
        .collect();
}

fn human_bytes(bytes: i64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1}Gi", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1}Mi", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1}Ki", bytes as f64 / 1024.0)
    } else {
        format!("{bytes}B")
    }
}
