use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct DiskUsage {
    filesystems: Vec<FilesystemInfo>,
    mounts: Vec<MountInfo>,
    io_stats: Vec<DiskIoStats>,
    large_dirs: Vec<DirSize>,
    temp_usage: Option<DirSize>,
    warnings: Vec<String>,
    success: bool,
    errors: Vec<String>,
}

#[derive(Serialize)]
struct FilesystemInfo {
    filesystem: String,
    mount_point: String,
    fs_type: String,
    total_bytes: i64,
    used_bytes: i64,
    available_bytes: i64,
    usage_percent: f64,
    inodes_total: i64,
    inodes_used: i64,
    inodes_percent: f64,
}

#[derive(Serialize)]
struct MountInfo {
    device: String,
    mount_point: String,
    fs_type: String,
    options: String,
    is_readonly: bool,
    is_tmpfs: bool,
    is_secret: bool,
    is_configmap: bool,
}

#[derive(Serialize, Default)]
struct DiskIoStats {
    device: String,
    reads_completed: i64,
    reads_merged: i64,
    sectors_read: i64,
    read_time_ms: i64,
    writes_completed: i64,
    writes_merged: i64,
    sectors_written: i64,
    write_time_ms: i64,
    io_in_progress: i64,
    io_time_ms: i64,
}

#[derive(Serialize)]
struct DirSize {
    path: String,
    size_bytes: i64,
    size_human: String,
}

pub async fn check() -> String {
    let mut usage = DiskUsage {
        filesystems: Vec::new(),
        mounts: Vec::new(),
        io_stats: Vec::new(),
        large_dirs: Vec::new(),
        temp_usage: None,
        warnings: Vec::new(),
        success: true,
        errors: Vec::new(),
    };

    let (df, df_inodes, mounts, iostat, du_tmp) = tokio::join!(
        cmd::run("df", &["-B1", "--output=source,target,fstype,size,used,avail,pcent"], 10),
        cmd::run("df", &["-i", "--output=source,target,itotal,iused,ipcent"], 10),
        read_mounts(),
        read_diskstats(),
        cmd::run("du", &["-sb", "/tmp"], 10),
    );

    // Parse df output
    if df.success {
        parse_df(&df.stdout, &df_inodes, &mut usage.filesystems);
    } else {
        usage.errors.push(format!("df: {}", df.stderr.trim()));
    }

    // Mounts from /proc/mounts
    usage.mounts = mounts;

    // IO stats
    usage.io_stats = iostat;

    // Temp usage
    if du_tmp.success {
        let parts: Vec<&str> = du_tmp.stdout.trim().split_whitespace().collect();
        if let Some(size) = parts.first().and_then(|s| s.parse::<i64>().ok()) {
            usage.temp_usage = Some(DirSize {
                path: "/tmp".into(),
                size_bytes: size,
                size_human: human_bytes(size),
            });
        }
    }

    // Check for important directories
    let important_dirs = ["/var/log", "/var/lib", "/var/data", "/data"];
    for dir in &important_dirs {
        if std::path::Path::new(dir).exists() {
            let result = cmd::run("du", &["-sb", dir], 10).await;
            if result.success {
                let parts: Vec<&str> = result.stdout.trim().split_whitespace().collect();
                if let Some(size) = parts.first().and_then(|s| s.parse::<i64>().ok()) {
                    if size > 10_000_000 {
                        // Only report dirs > 10MB
                        usage.large_dirs.push(DirSize {
                            path: dir.to_string(),
                            size_bytes: size,
                            size_human: human_bytes(size),
                        });
                    }
                }
            }
        }
    }

    // Generate warnings
    for fs in &usage.filesystems {
        if fs.usage_percent > 90.0 {
            usage.warnings.push(format!(
                "{} is {:.1}% full ({} used of {})",
                fs.mount_point,
                fs.usage_percent,
                human_bytes(fs.used_bytes),
                human_bytes(fs.total_bytes)
            ));
        }
        if fs.inodes_total > 0 && fs.inodes_percent > 90.0 {
            usage.warnings.push(format!(
                "{} inode usage: {:.1}% ({} of {})",
                fs.mount_point, fs.inodes_percent, fs.inodes_used, fs.inodes_total
            ));
        }
    }

    serde_json::to_string_pretty(&usage).unwrap()
}

fn parse_df(
    df_out: &str,
    df_inodes: &crate::cmd::CmdResult,
    filesystems: &mut Vec<FilesystemInfo>,
) {
    // Build inode map from df -i output
    let mut inode_map: std::collections::HashMap<String, (i64, i64, f64)> =
        std::collections::HashMap::new();

    if df_inodes.success {
        for line in df_inodes.stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                let mount = parts[1].to_string();
                let itotal: i64 = parts[2].parse().unwrap_or(0);
                let iused: i64 = parts[3].parse().unwrap_or(0);
                let ipct: f64 = parts[4]
                    .trim_end_matches('%')
                    .parse()
                    .unwrap_or(0.0);
                inode_map.insert(mount, (itotal, iused, ipct));
            }
        }
    }

    for line in df_out.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 7 {
            continue;
        }

        let mount = parts[1];
        // Skip pseudo-filesystems
        if mount == "/dev" || mount == "/dev/shm" || mount == "/proc" || mount == "/sys" {
            continue;
        }

        let total: i64 = parts[3].parse().unwrap_or(0);
        let used: i64 = parts[4].parse().unwrap_or(0);
        let avail: i64 = parts[5].parse().unwrap_or(0);
        let pct: f64 = parts[6].trim_end_matches('%').parse().unwrap_or(0.0);

        let (itotal, iused, ipct) = inode_map
            .get(mount)
            .copied()
            .unwrap_or((0, 0, 0.0));

        if total > 0 {
            filesystems.push(FilesystemInfo {
                filesystem: parts[0].to_string(),
                mount_point: mount.to_string(),
                fs_type: parts[2].to_string(),
                total_bytes: total,
                used_bytes: used,
                available_bytes: avail,
                usage_percent: pct,
                inodes_total: itotal,
                inodes_used: iused,
                inodes_percent: ipct,
            });
        }
    }
}

async fn read_mounts() -> Vec<MountInfo> {
    let Ok(content) = std::fs::read_to_string("/proc/mounts") else {
        return Vec::new();
    };

    content
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                return None;
            }

            let device = parts[0];
            let mount = parts[1];
            let fstype = parts[2];
            let opts = parts[3];

            // Skip kernel pseudo-filesystems
            if fstype == "proc"
                || fstype == "sysfs"
                || fstype == "devpts"
                || fstype == "cgroup"
                || fstype == "cgroup2"
                || fstype == "mqueue"
            {
                return None;
            }

            Some(MountInfo {
                device: device.to_string(),
                mount_point: mount.to_string(),
                fs_type: fstype.to_string(),
                options: opts.to_string(),
                is_readonly: opts.contains("ro,") || opts.starts_with("ro,") || opts == "ro",
                is_tmpfs: fstype == "tmpfs",
                is_secret: mount.contains("secret") || mount.contains("serviceaccount"),
                is_configmap: mount.contains("configmap") || mount.contains("config-map"),
            })
        })
        .collect()
}

async fn read_diskstats() -> Vec<DiskIoStats> {
    let Ok(content) = std::fs::read_to_string("/proc/diskstats") else {
        return Vec::new();
    };

    content
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 14 {
                return None;
            }

            let device = parts[2];
            // Only report real devices (not partitions and loop devices)
            if device.starts_with("loop")
                || device.starts_with("ram")
                || device.starts_with("dm-")
            {
                return None;
            }

            let reads: i64 = parts[3].parse().unwrap_or(0);
            let writes: i64 = parts[7].parse().unwrap_or(0);

            // Skip devices with zero IO
            if reads == 0 && writes == 0 {
                return None;
            }

            Some(DiskIoStats {
                device: device.to_string(),
                reads_completed: reads,
                reads_merged: parts[4].parse().unwrap_or(0),
                sectors_read: parts[5].parse().unwrap_or(0),
                read_time_ms: parts[6].parse().unwrap_or(0),
                writes_completed: writes,
                writes_merged: parts[8].parse().unwrap_or(0),
                sectors_written: parts[9].parse().unwrap_or(0),
                write_time_ms: parts[10].parse().unwrap_or(0),
                io_in_progress: parts[11].parse().unwrap_or(0),
                io_time_ms: parts[12].parse().unwrap_or(0),
            })
        })
        .collect()
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
