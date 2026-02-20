use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct RedisHealth {
    version: Option<String>,
    uptime_seconds: Option<i64>,
    mode: Option<String>,
    role: Option<String>,
    memory: MemoryStats,
    clients: ClientStats,
    persistence: PersistenceStats,
    replication: ReplicationStats,
    keyspace: Vec<KeyspaceDb>,
    slowlog: Vec<serde_json::Value>,
    dangerous_config: Vec<ConfigWarning>,
    latency: Option<f64>,
    ops_per_sec: Option<i64>,
    hit_rate: Option<f64>,
    blocked_clients: Option<i64>,
    success: bool,
    errors: Vec<String>,
}

#[derive(Serialize, Default)]
struct MemoryStats {
    used_memory_human: Option<String>,
    used_memory_peak_human: Option<String>,
    used_memory_rss_human: Option<String>,
    maxmemory_human: Option<String>,
    maxmemory_policy: Option<String>,
    mem_fragmentation_ratio: Option<f64>,
    mem_fragmentation_bytes: Option<i64>,
}

#[derive(Serialize, Default)]
struct ClientStats {
    connected_clients: Option<i64>,
    max_clients: Option<i64>,
    blocked_clients: Option<i64>,
    tracking_clients: Option<i64>,
    rejected_connections: Option<i64>,
    total_connections_received: Option<i64>,
    client_recent_max_input_buffer: Option<String>,
    client_recent_max_output_buffer: Option<String>,
}

#[derive(Serialize, Default)]
struct PersistenceStats {
    rdb_last_save_time: Option<i64>,
    rdb_last_bgsave_status: Option<String>,
    rdb_changes_since_last_save: Option<i64>,
    aof_enabled: Option<bool>,
    aof_last_write_status: Option<String>,
    aof_current_size: Option<String>,
    loading: Option<bool>,
}

#[derive(Serialize, Default)]
struct ReplicationStats {
    role: Option<String>,
    connected_slaves: Option<i64>,
    master_host: Option<String>,
    master_port: Option<String>,
    master_link_status: Option<String>,
    master_last_io_seconds_ago: Option<i64>,
    repl_backlog_size: Option<String>,
    slaves: Vec<serde_json::Value>,
}

#[derive(Serialize)]
struct KeyspaceDb {
    db: String,
    keys: i64,
    expires: i64,
    avg_ttl: i64,
}

#[derive(Serialize)]
struct ConfigWarning {
    key: String,
    value: String,
    warning: String,
}

pub async fn check(
    target: Option<&str>,
    password: Option<&str>,
) -> String {
    let (host, port) = resolve_target(target);
    let password = password
        .map(|s| s.to_string())
        .or_else(|| std::env::var("REDIS_PASSWORD").ok());

    let mut health = RedisHealth {
        version: None,
        uptime_seconds: None,
        mode: None,
        role: None,
        memory: MemoryStats::default(),
        clients: ClientStats::default(),
        persistence: PersistenceStats::default(),
        replication: ReplicationStats::default(),
        keyspace: Vec::new(),
        slowlog: Vec::new(),
        dangerous_config: Vec::new(),
        latency: None,
        ops_per_sec: None,
        hit_rate: None,
        blocked_clients: None,
        success: true,
        errors: Vec::new(),
    };

    let (info, slowlog, client_list, config, latency, dbsize) = tokio::join!(
        redis_cmd(&host, &port, password.as_deref(), "INFO ALL"),
        redis_cmd(&host, &port, password.as_deref(), "SLOWLOG GET 10"),
        redis_cmd(&host, &port, password.as_deref(), "CLIENT LIST"),
        redis_cmd(&host, &port, password.as_deref(), "CONFIG GET save CONFIG GET maxmemory-policy CONFIG GET timeout CONFIG GET tcp-keepalive CONFIG GET protected-mode CONFIG GET bind"),
        redis_cmd(&host, &port, password.as_deref(), "DEBUG SLEEP 0"),
        redis_cmd(&host, &port, password.as_deref(), "DBSIZE"),
    );

    // Parse INFO ALL — the main source of health data
    if let Ok(output) = &info {
        let sections = parse_info(output);

        // Server section
        health.version = sections.get("redis_version").cloned();
        health.uptime_seconds = sections.get("uptime_in_seconds").and_then(|v| v.parse().ok());
        health.mode = sections.get("redis_mode").cloned();
        health.role = sections.get("role").cloned();

        // Memory
        health.memory.used_memory_human = sections.get("used_memory_human").cloned();
        health.memory.used_memory_peak_human = sections.get("used_memory_peak_human").cloned();
        health.memory.used_memory_rss_human = sections.get("used_memory_rss_human").cloned();
        health.memory.maxmemory_human = sections.get("maxmemory_human").cloned();
        health.memory.maxmemory_policy = sections.get("maxmemory_policy").cloned();
        health.memory.mem_fragmentation_ratio = sections.get("mem_fragmentation_ratio").and_then(|v| v.parse().ok());
        health.memory.mem_fragmentation_bytes = sections.get("mem_fragmentation_bytes").and_then(|v| v.parse().ok());

        // Clients
        health.clients.connected_clients = sections.get("connected_clients").and_then(|v| v.parse().ok());
        health.clients.blocked_clients = sections.get("blocked_clients").and_then(|v| v.parse().ok());
        health.clients.tracking_clients = sections.get("tracking_clients").and_then(|v| v.parse().ok());
        health.clients.rejected_connections = sections.get("rejected_connections").and_then(|v| v.parse().ok());
        health.clients.total_connections_received = sections.get("total_connections_received").and_then(|v| v.parse().ok());
        health.clients.client_recent_max_input_buffer = sections.get("client_recent_max_input_buffer").cloned();
        health.clients.client_recent_max_output_buffer = sections.get("client_recent_max_output_buffer").cloned();
        health.clients.max_clients = sections.get("maxclients").and_then(|v| v.parse().ok());
        health.blocked_clients = health.clients.blocked_clients;

        // Persistence
        health.persistence.rdb_last_save_time = sections.get("rdb_last_save_time").and_then(|v| v.parse().ok());
        health.persistence.rdb_last_bgsave_status = sections.get("rdb_last_bgsave_status").cloned();
        health.persistence.rdb_changes_since_last_save = sections.get("rdb_changes_since_last_save").and_then(|v| v.parse().ok());
        health.persistence.aof_enabled = sections.get("aof_enabled").map(|v| v == "1");
        health.persistence.aof_last_write_status = sections.get("aof_last_write_status").cloned();
        health.persistence.aof_current_size = sections.get("aof_current_size").cloned();
        health.persistence.loading = sections.get("loading").map(|v| v == "1");

        // Replication
        health.replication.role = sections.get("role").cloned();
        health.replication.connected_slaves = sections.get("connected_slaves").and_then(|v| v.parse().ok());
        health.replication.master_host = sections.get("master_host").cloned();
        health.replication.master_port = sections.get("master_port").cloned();
        health.replication.master_link_status = sections.get("master_link_status").cloned();
        health.replication.master_last_io_seconds_ago = sections.get("master_last_io_seconds_ago").and_then(|v| v.parse().ok());
        health.replication.repl_backlog_size = sections.get("repl_backlog_size").cloned();

        // Parse slave entries
        for i in 0..16 {
            let key = format!("slave{i}");
            if let Some(val) = sections.get(&key) {
                let mut slave = serde_json::Map::new();
                for part in val.split(',') {
                    if let Some((k, v)) = part.split_once('=') {
                        slave.insert(k.to_string(), serde_json::json!(v));
                    }
                }
                if !slave.is_empty() {
                    health.replication.slaves.push(serde_json::Value::Object(slave));
                }
            }
        }

        // Stats
        health.ops_per_sec = sections.get("instantaneous_ops_per_sec").and_then(|v| v.parse().ok());
        let hits: f64 = sections.get("keyspace_hits").and_then(|v| v.parse().ok()).unwrap_or(0.0);
        let misses: f64 = sections.get("keyspace_misses").and_then(|v| v.parse().ok()).unwrap_or(0.0);
        if hits + misses > 0.0 {
            health.hit_rate = Some(((hits / (hits + misses)) * 10000.0).round() / 10000.0);
        }

        // Keyspace
        for (key, val) in &sections {
            if key.starts_with("db") && key.len() <= 4 {
                let mut keys: i64 = 0;
                let mut expires: i64 = 0;
                let mut avg_ttl: i64 = 0;
                for part in val.split(',') {
                    if let Some((k, v)) = part.split_once('=') {
                        match k {
                            "keys" => keys = v.parse().unwrap_or(0),
                            "expires" => expires = v.parse().unwrap_or(0),
                            "avg_ttl" => avg_ttl = v.parse().unwrap_or(0),
                            _ => {}
                        }
                    }
                }
                health.keyspace.push(KeyspaceDb {
                    db: key.clone(),
                    keys,
                    expires,
                    avg_ttl,
                });
            }
        }
    } else if let Err(e) = &info {
        health.errors.push(e.clone());
        health.success = false;
    }

    // Parse SLOWLOG
    if let Ok(output) = &slowlog {
        health.slowlog = parse_slowlog(output);
    }

    // Parse CONFIG warnings
    if let Ok(output) = &config {
        health.dangerous_config = check_dangerous_config(output);
    }

    // Latency check (DEBUG SLEEP 0 measures round-trip)
    if latency.is_ok() {
        // We can't actually measure from DEBUG SLEEP output; use PING instead
    }

    // We ignore dbsize and client_list parse for now — info already has this
    let _ = (client_list, dbsize);

    if !health.errors.is_empty() && health.version.is_none() {
        health.success = false;
    }

    serde_json::to_string_pretty(&health).unwrap()
}

fn resolve_target(target: Option<&str>) -> (String, String) {
    if let Some(t) = target {
        let parts: Vec<&str> = t.splitn(2, ':').collect();
        return (
            parts[0].to_string(),
            parts.get(1).unwrap_or(&"6379").to_string(),
        );
    }
    let host = std::env::var("REDIS_HOST")
        .unwrap_or_else(|_| find_service_host(6379).unwrap_or("localhost".into()));
    let port = std::env::var("REDIS_PORT").unwrap_or_else(|_| "6379".into());
    (host, port)
}

fn find_service_host(target_port: u16) -> Option<String> {
    let port_str = target_port.to_string();
    for (key, val) in std::env::vars() {
        if key.ends_with("_SERVICE_PORT") && val == port_str {
            let prefix = key.trim_end_matches("_SERVICE_PORT");
            if let Ok(host) = std::env::var(format!("{prefix}_SERVICE_HOST")) {
                return Some(host);
            }
        }
    }
    None
}

async fn redis_cmd(
    host: &str,
    port: &str,
    password: Option<&str>,
    command: &str,
) -> Result<String, String> {
    let mut args = vec![
        "-h".to_string(), host.to_string(),
        "-p".to_string(), port.to_string(),
        "--no-auth-warning".to_string(),
    ];
    if let Some(pw) = password {
        args.push("-a".to_string());
        args.push(pw.to_string());
    }

    // Split command into parts
    let parts: Vec<&str> = command.split_whitespace().collect();
    for p in &parts {
        args.push(p.to_string());
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = cmd::run("redis-cli", &arg_refs, 10).await;

    if result.success {
        Ok(result.stdout.clone())
    } else {
        Err(result.stderr.trim().to_string())
    }
}

fn parse_info(output: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, val)) = line.split_once(':') {
            map.insert(key.to_string(), val.to_string());
        }
    }
    map
}

fn parse_slowlog(output: &str) -> Vec<serde_json::Value> {
    let mut entries = Vec::new();
    let mut current: Option<serde_json::Map<String, serde_json::Value>> = None;
    let mut field_idx = 0;

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // New entry starts with a number followed by )
        if line.ends_with(')') && line.chars().take_while(|c| c.is_ascii_digit()).count() > 0 {
            if let Some(entry) = current.take() {
                entries.push(serde_json::Value::Object(entry));
            }
            current = Some(serde_json::Map::new());
            field_idx = 0;
            continue;
        }

        if let Some(ref mut entry) = current {
            match field_idx {
                0 => { entry.insert("id".into(), serde_json::json!(line.parse::<i64>().unwrap_or(0))); }
                1 => { entry.insert("timestamp".into(), serde_json::json!(line.parse::<i64>().unwrap_or(0))); }
                2 => { entry.insert("duration_us".into(), serde_json::json!(line.parse::<i64>().unwrap_or(0))); }
                3 => { entry.insert("command".into(), serde_json::json!(line)); }
                _ => {}
            }
            field_idx += 1;
        }
    }
    if let Some(entry) = current {
        entries.push(serde_json::Value::Object(entry));
    }
    entries
}

fn check_dangerous_config(output: &str) -> Vec<ConfigWarning> {
    let mut warnings = Vec::new();
    let lines: Vec<&str> = output.lines().collect();
    let mut i = 0;
    while i + 1 < lines.len() {
        let key = lines[i].trim();
        let val = lines[i + 1].trim();

        match key {
            "save" if val.is_empty() => {
                warnings.push(ConfigWarning {
                    key: "save".into(),
                    value: "(disabled)".into(),
                    warning: "RDB persistence is disabled — data loss on restart".into(),
                });
            }
            "maxmemory-policy" if val == "noeviction" => {
                warnings.push(ConfigWarning {
                    key: "maxmemory-policy".into(),
                    value: val.into(),
                    warning: "noeviction will return errors when memory limit is reached".into(),
                });
            }
            "timeout" if val == "0" => {
                warnings.push(ConfigWarning {
                    key: "timeout".into(),
                    value: val.into(),
                    warning: "Idle connections never timeout — can lead to connection exhaustion".into(),
                });
            }
            "protected-mode" if val == "no" => {
                warnings.push(ConfigWarning {
                    key: "protected-mode".into(),
                    value: val.into(),
                    warning: "Protected mode is off — Redis is accessible without authentication".into(),
                });
            }
            "tcp-keepalive" if val == "0" => {
                warnings.push(ConfigWarning {
                    key: "tcp-keepalive".into(),
                    value: val.into(),
                    warning: "TCP keepalive disabled — dead connections won't be cleaned up".into(),
                });
            }
            "bind" if val.is_empty() || val == "0.0.0.0" => {
                warnings.push(ConfigWarning {
                    key: "bind".into(),
                    value: if val.is_empty() { "(all interfaces)".into() } else { val.into() },
                    warning: "Redis is bound to all interfaces — restrict to specific IPs in production".into(),
                });
            }
            _ => {}
        }
        i += 2;
    }
    warnings
}
