use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct NginxHealth {
    version: Option<String>,
    stub_status: Option<NginxStubStatus>,
    config: NginxConfig,
    processes: Vec<NginxProcess>,
    error_log_tail: Vec<String>,
    access_log_tail: Vec<String>,
    warnings: Vec<String>,
    success: bool,
    errors: Vec<String>,
}

#[derive(Serialize)]
struct NginxStubStatus {
    active_connections: i64,
    accepts: i64,
    handled: i64,
    requests: i64,
    reading: i64,
    writing: i64,
    waiting: i64,
    dropped: i64,
}

#[derive(Serialize, Default)]
struct NginxConfig {
    worker_processes: Option<String>,
    worker_connections: Option<String>,
    upstream_count: i64,
    server_count: i64,
    ssl_enabled: bool,
    gzip_enabled: bool,
    proxy_buffering: Option<String>,
    keepalive_timeout: Option<String>,
    client_max_body_size: Option<String>,
    upstreams: Vec<NginxUpstream>,
    includes: Vec<String>,
}

#[derive(Serialize)]
struct NginxUpstream {
    name: String,
    servers: Vec<String>,
}

#[derive(Serialize)]
struct NginxProcess {
    pid: i64,
    process_type: String,
    cpu: f64,
    memory_rss_kb: i64,
    connections: i64,
}

pub async fn check(target: Option<&str>) -> String {
    let status_url = resolve_status_url(target);
    let mut health = NginxHealth {
        version: None,
        stub_status: None,
        config: NginxConfig::default(),
        processes: Vec::new(),
        error_log_tail: Vec::new(),
        access_log_tail: Vec::new(),
        warnings: Vec::new(),
        success: true,
        errors: Vec::new(),
    };

    let curl_args = ["-sf", "--max-time", "5", status_url.as_str()];
    let (stub, version, config_test, config_dump, procs, error_log, access_log) = tokio::join!(
        cmd::run("curl", &curl_args, 10),
        cmd::run("nginx", &["-v"], 5),
        cmd::run("nginx", &["-t"], 5),
        cmd::run("nginx", &["-T"], 10),
        cmd::run("sh", &["-c", "ps aux | grep '[n]ginx'"], 5),
        cmd::run("sh", &["-c", "tail -50 /var/log/nginx/error.log 2>/dev/null || tail -50 /var/log/error.log 2>/dev/null"], 5),
        cmd::run("sh", &["-c", "tail -20 /var/log/nginx/access.log 2>/dev/null || tail -20 /var/log/access.log 2>/dev/null"], 5),
    );

    // Parse stub_status
    if stub.success {
        health.stub_status = parse_stub_status(&stub.stdout);
    } else if !stub.stderr.contains("Connection refused") {
        health.errors.push(format!("stub_status: {}", stub.stderr.trim()));
    }

    // Parse version (nginx -v writes to stderr)
    let version_output = if version.success {
        &version.stderr
    } else {
        &version.stdout
    };
    if let Some(ver) = version_output.lines().next() {
        let ver = ver.trim();
        if ver.contains("nginx/") {
            health.version = Some(
                ver.split("nginx/")
                    .nth(1)
                    .unwrap_or(ver)
                    .split_whitespace()
                    .next()
                    .unwrap_or(ver)
                    .to_string(),
            );
        }
    }

    // Config test
    if !config_test.success {
        health.warnings.push(format!(
            "Config test failed: {}",
            config_test.stderr.trim()
        ));
    }

    // Parse full config dump
    if config_dump.success {
        parse_config(&config_dump.stdout, &mut health.config);
    }

    // Parse processes
    if procs.success {
        for line in procs.stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 11 {
                let cmd_str = parts[10..].join(" ");
                let process_type = if cmd_str.contains("master") {
                    "master"
                } else if cmd_str.contains("worker") {
                    "worker"
                } else if cmd_str.contains("cache") {
                    "cache"
                } else {
                    "other"
                };
                health.processes.push(NginxProcess {
                    pid: parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0),
                    process_type: process_type.to_string(),
                    cpu: parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0.0),
                    memory_rss_kb: parts.get(5).and_then(|s| s.parse().ok()).unwrap_or(0),
                    connections: 0,
                });
            }
        }
    }

    // Error log
    if error_log.success {
        let recent_errors: Vec<String> = error_log
            .stdout
            .lines()
            .filter(|l| {
                l.contains("[error]")
                    || l.contains("[crit]")
                    || l.contains("[alert]")
                    || l.contains("[emerg]")
            })
            .rev()
            .take(20)
            .map(|s| s.to_string())
            .collect();
        health.error_log_tail = recent_errors;
    }

    // Access log (last 20 lines)
    if access_log.success {
        health.access_log_tail = access_log
            .stdout
            .lines()
            .rev()
            .take(20)
            .map(|s| s.to_string())
            .collect();
    }

    // Generate warnings
    if let Some(ref status) = health.stub_status {
        if status.dropped > 0 {
            health.warnings.push(format!(
                "{} dropped connections (accepts - handled)",
                status.dropped
            ));
        }
        if status.waiting > status.active_connections / 2 && status.active_connections > 10 {
            health.warnings.push(format!(
                "High waiting connections: {} of {} active",
                status.waiting, status.active_connections
            ));
        }
    }
    if !health.error_log_tail.is_empty() {
        health.warnings.push(format!(
            "{} recent error/crit/alert/emerg entries in error log",
            health.error_log_tail.len()
        ));
    }

    if health.version.is_none() && health.stub_status.is_none() {
        health.success = false;
    }

    serde_json::to_string_pretty(&health).unwrap()
}

fn resolve_status_url(target: Option<&str>) -> String {
    if let Some(t) = target {
        if t.starts_with("http") {
            return t.to_string();
        }
        return format!("http://{t}/nginx_status");
    }
    std::env::var("NGINX_STATUS_URL")
        .unwrap_or_else(|_| "http://localhost/nginx_status".into())
}

fn parse_stub_status(output: &str) -> Option<NginxStubStatus> {
    // Format:
    // Active connections: 43
    //  server accepts handled requests
    //  7368 7368 10993
    //  Reading: 0 Writing: 5 Waiting: 38
    let lines: Vec<&str> = output.lines().collect();
    if lines.len() < 4 {
        return None;
    }

    let active = lines[0]
        .split(':')
        .nth(1)?
        .trim()
        .parse::<i64>()
        .ok()?;

    let stats: Vec<i64> = lines[2]
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect();

    if stats.len() < 3 {
        return None;
    }

    let mut reading = 0i64;
    let mut writing = 0i64;
    let mut waiting = 0i64;

    let parts: Vec<&str> = lines[3].split_whitespace().collect();
    for (i, part) in parts.iter().enumerate() {
        match *part {
            "Reading:" => reading = parts.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(0),
            "Writing:" => writing = parts.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(0),
            "Waiting:" => waiting = parts.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(0),
            _ => {}
        }
    }

    Some(NginxStubStatus {
        active_connections: active,
        accepts: stats[0],
        handled: stats[1],
        requests: stats[2],
        reading,
        writing,
        waiting,
        dropped: stats[0] - stats[1],
    })
}

fn parse_config(config: &str, result: &mut NginxConfig) {
    let mut current_upstream: Option<(String, Vec<String>)> = None;

    for line in config.lines() {
        let trimmed = line.trim();

        // Track directive values
        if trimmed.starts_with("worker_processes") {
            result.worker_processes = extract_directive_value(trimmed);
        } else if trimmed.starts_with("worker_connections") {
            result.worker_connections = extract_directive_value(trimmed);
        } else if trimmed.starts_with("keepalive_timeout") {
            result.keepalive_timeout = extract_directive_value(trimmed);
        } else if trimmed.starts_with("client_max_body_size") {
            result.client_max_body_size = extract_directive_value(trimmed);
        } else if trimmed.starts_with("proxy_buffering") {
            result.proxy_buffering = extract_directive_value(trimmed);
        } else if trimmed.starts_with("gzip ") && trimmed.contains("on") {
            result.gzip_enabled = true;
        } else if trimmed.starts_with("ssl_certificate") && !trimmed.starts_with("ssl_certificate_key") {
            result.ssl_enabled = true;
        } else if trimmed.starts_with("server {") || trimmed == "server {" {
            result.server_count += 1;
        } else if trimmed.starts_with("upstream ") {
            let name = trimmed
                .strip_prefix("upstream ")
                .and_then(|s| s.strip_suffix('{'))
                .unwrap_or(trimmed)
                .trim()
                .to_string();
            current_upstream = Some((name, Vec::new()));
        } else if trimmed == "}" {
            if let Some((name, servers)) = current_upstream.take() {
                result.upstream_count += 1;
                result.upstreams.push(NginxUpstream { name, servers });
            }
        } else if trimmed.starts_with("server ") && current_upstream.is_some() {
            if let Some((_, ref mut servers)) = current_upstream {
                servers.push(
                    trimmed
                        .strip_prefix("server ")
                        .unwrap_or(trimmed)
                        .trim_end_matches(';')
                        .trim()
                        .to_string(),
                );
            }
        } else if trimmed.starts_with("include ") {
            if let Some(path) = extract_directive_value(trimmed) {
                result.includes.push(path);
            }
        }
    }
}

fn extract_directive_value(line: &str) -> Option<String> {
    line.split_whitespace()
        .nth(1)
        .map(|s| s.trim_end_matches(';').to_string())
}
