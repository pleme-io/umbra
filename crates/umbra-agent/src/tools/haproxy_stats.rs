use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct HaproxyHealth {
    version: Option<String>,
    uptime: Option<String>,
    frontends: Vec<HaproxyFrontend>,
    backends: Vec<HaproxyBackend>,
    servers: Vec<HaproxyServer>,
    connections: HaproxyConnections,
    error_rates: HaproxyErrors,
    warnings: Vec<String>,
    success: bool,
    errors: Vec<String>,
}

#[derive(Serialize)]
struct HaproxyFrontend {
    name: String,
    status: String,
    current_sessions: i64,
    max_sessions: i64,
    session_limit: i64,
    bytes_in: i64,
    bytes_out: i64,
    denied_req: i64,
    request_rate: i64,
    request_total: i64,
}

#[derive(Serialize)]
struct HaproxyBackend {
    name: String,
    status: String,
    current_sessions: i64,
    server_count: i64,
    active_servers: i64,
    backup_servers: i64,
    queue_current: i64,
    queue_max: i64,
    connect_time_avg: i64,
    response_time_avg: i64,
    bytes_in: i64,
    bytes_out: i64,
    error_resp: i64,
    retry_warnings: i64,
    redispatch_warnings: i64,
}

#[derive(Serialize)]
struct HaproxyServer {
    backend: String,
    name: String,
    status: String,
    weight: i64,
    current_sessions: i64,
    max_sessions: i64,
    queue_current: i64,
    check_status: String,
    check_duration: i64,
    downtime: i64,
    last_status_change: i64,
    connect_time_avg: i64,
    response_time_avg: i64,
    bytes_in: i64,
    bytes_out: i64,
}

#[derive(Serialize, Default)]
struct HaproxyConnections {
    current: i64,
    max: i64,
    total: i64,
    rate: i64,
    rate_max: i64,
}

#[derive(Serialize, Default)]
struct HaproxyErrors {
    connection_errors: i64,
    response_errors: i64,
    denied_requests: i64,
    denied_responses: i64,
    failed_checks: i64,
}

pub async fn check(target: Option<&str>) -> String {
    let url = resolve_stats_url(target);
    let mut health = HaproxyHealth {
        version: None,
        uptime: None,
        frontends: Vec::new(),
        backends: Vec::new(),
        servers: Vec::new(),
        connections: HaproxyConnections::default(),
        error_rates: HaproxyErrors::default(),
        warnings: Vec::new(),
        success: true,
        errors: Vec::new(),
    };

    // Try CSV stats endpoint first (most reliable)
    let csv_url = if url.contains('?') {
        format!("{url};csv")
    } else {
        format!("{url}?stats;csv")
    };

    let result = cmd::run(
        "curl",
        &["-sf", "--max-time", "10", &csv_url],
        15,
    )
    .await;

    if !result.success {
        // Try socket if curl fails
        let socket_result = try_socket_stats().await;
        if let Some(csv) = socket_result {
            parse_csv(&csv, &mut health);
        } else {
            health.success = false;
            health.errors.push(format!(
                "Cannot reach HAProxy stats at {csv_url}: {}",
                result.stderr.trim()
            ));
        }
    } else {
        parse_csv(&result.stdout, &mut health);
    }

    // Try to get version via show info on socket
    if health.version.is_none() {
        if let Some(info) = try_socket_info().await {
            for line in info.lines() {
                if let Some((key, val)) = line.split_once(':') {
                    let key = key.trim();
                    let val = val.trim();
                    match key {
                        "Version" => health.version = Some(val.to_string()),
                        "Uptime" => health.uptime = Some(val.to_string()),
                        "CurrConns" => health.connections.current = val.parse().unwrap_or(0),
                        "MaxConn" => health.connections.max = val.parse().unwrap_or(0),
                        "CumConns" => health.connections.total = val.parse().unwrap_or(0),
                        "ConnRate" => health.connections.rate = val.parse().unwrap_or(0),
                        "MaxConnRate" => health.connections.rate_max = val.parse().unwrap_or(0),
                        _ => {}
                    }
                }
            }
        }
    }

    // Generate warnings
    for srv in &health.servers {
        if srv.status != "UP" && srv.status != "no check" {
            health.warnings.push(format!(
                "Server {}/{} is {} (down {}s)",
                srv.backend, srv.name, srv.status, srv.downtime
            ));
        }
    }
    for be in &health.backends {
        if be.queue_current > 0 {
            health.warnings.push(format!(
                "Backend {} has {} queued connections",
                be.name, be.queue_current
            ));
        }
        if be.active_servers == 0 {
            health.warnings.push(format!(
                "Backend {} has no active servers!",
                be.name
            ));
        }
    }

    serde_json::to_string_pretty(&health).unwrap()
}

fn resolve_stats_url(target: Option<&str>) -> String {
    if let Some(t) = target {
        if t.starts_with("http") {
            return t.to_string();
        }
        return format!("http://{t}/haproxy?stats");
    }
    std::env::var("HAPROXY_STATS_URL")
        .unwrap_or_else(|_| "http://localhost:8404/stats".into())
}

async fn try_socket_stats() -> Option<String> {
    let sockets = [
        "/var/run/haproxy/admin.sock",
        "/var/run/haproxy.sock",
        "/tmp/haproxy.sock",
    ];

    for sock in &sockets {
        if std::path::Path::new(sock).exists() {
            let result = cmd::run(
                "sh",
                &["-c", &format!("echo 'show stat' | socat - UNIX-CONNECT:{sock}")],
                10,
            )
            .await;
            if result.success {
                return Some(result.stdout);
            }
        }
    }
    None
}

async fn try_socket_info() -> Option<String> {
    let sockets = [
        "/var/run/haproxy/admin.sock",
        "/var/run/haproxy.sock",
        "/tmp/haproxy.sock",
    ];

    for sock in &sockets {
        if std::path::Path::new(sock).exists() {
            let result = cmd::run(
                "sh",
                &["-c", &format!("echo 'show info' | socat - UNIX-CONNECT:{sock}")],
                10,
            )
            .await;
            if result.success {
                return Some(result.stdout);
            }
        }
    }
    None
}

fn parse_csv(csv: &str, health: &mut HaproxyHealth) {
    let lines: Vec<&str> = csv.lines().collect();
    if lines.is_empty() {
        return;
    }

    // First line is header (starts with # or pxname)
    let header_line = lines[0].trim_start_matches("# ");
    let headers: Vec<&str> = header_line.split(',').collect();

    for line in &lines[1..] {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let fields: Vec<&str> = line.split(',').collect();
        let get = |name: &str| -> &str {
            headers
                .iter()
                .position(|h| h.trim() == name)
                .and_then(|i| fields.get(i).copied())
                .unwrap_or("")
        };
        let get_i64 = |name: &str| -> i64 {
            get(name).parse().unwrap_or(0)
        };

        let svname = get("svname");

        match svname {
            "FRONTEND" => {
                health.frontends.push(HaproxyFrontend {
                    name: get("pxname").to_string(),
                    status: get("status").to_string(),
                    current_sessions: get_i64("scur"),
                    max_sessions: get_i64("smax"),
                    session_limit: get_i64("slim"),
                    bytes_in: get_i64("bin"),
                    bytes_out: get_i64("bout"),
                    denied_req: get_i64("dreq"),
                    request_rate: get_i64("req_rate"),
                    request_total: get_i64("req_tot"),
                });
                health.error_rates.denied_requests += get_i64("dreq");
            }
            "BACKEND" => {
                health.backends.push(HaproxyBackend {
                    name: get("pxname").to_string(),
                    status: get("status").to_string(),
                    current_sessions: get_i64("scur"),
                    server_count: get_i64("srv"),
                    active_servers: get_i64("act"),
                    backup_servers: get_i64("bck"),
                    queue_current: get_i64("qcur"),
                    queue_max: get_i64("qmax"),
                    connect_time_avg: get_i64("ctime"),
                    response_time_avg: get_i64("rtime"),
                    bytes_in: get_i64("bin"),
                    bytes_out: get_i64("bout"),
                    error_resp: get_i64("eresp"),
                    retry_warnings: get_i64("wrew"),
                    redispatch_warnings: get_i64("wredis"),
                });
                health.error_rates.response_errors += get_i64("eresp");
                health.error_rates.connection_errors += get_i64("econ");
            }
            _ => {
                // Server entry
                health.servers.push(HaproxyServer {
                    backend: get("pxname").to_string(),
                    name: svname.to_string(),
                    status: get("status").to_string(),
                    weight: get_i64("weight"),
                    current_sessions: get_i64("scur"),
                    max_sessions: get_i64("smax"),
                    queue_current: get_i64("qcur"),
                    check_status: get("check_status").to_string(),
                    check_duration: get_i64("check_duration"),
                    downtime: get_i64("downtime"),
                    last_status_change: get_i64("lastchg"),
                    connect_time_avg: get_i64("ctime"),
                    response_time_avg: get_i64("rtime"),
                    bytes_in: get_i64("bin"),
                    bytes_out: get_i64("bout"),
                });
                health.error_rates.failed_checks += if get("check_status").contains("ERR") { 1 } else { 0 };
            }
        }
    }
}
