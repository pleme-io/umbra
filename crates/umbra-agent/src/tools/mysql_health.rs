use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct MysqlHealth {
    version: Option<String>,
    connections: MysqlConnections,
    replication: Option<serde_json::Value>,
    innodb: InnodbStats,
    databases: Vec<serde_json::Value>,
    locked_tables: Vec<serde_json::Value>,
    processlist: Vec<serde_json::Value>,
    variables: Vec<serde_json::Value>,
    success: bool,
    errors: Vec<String>,
}

#[derive(Serialize, Default)]
struct MysqlConnections {
    max_connections: Option<i64>,
    current_threads: i64,
    running_threads: i64,
    connected_threads: i64,
    max_used_connections: Option<i64>,
    aborted_clients: Option<i64>,
    aborted_connects: Option<i64>,
}

#[derive(Serialize, Default)]
struct InnodbStats {
    buffer_pool_size: Option<String>,
    buffer_pool_hit_ratio: Option<f64>,
    buffer_pool_read_requests: i64,
    buffer_pool_reads: i64,
    row_lock_waits: Option<i64>,
    row_lock_time_avg: Option<i64>,
    deadlocks: Option<i64>,
}

pub async fn check(
    target: Option<&str>,
    user: Option<&str>,
    password: Option<&str>,
    database: Option<&str>,
) -> String {
    let (host, port) = resolve_target(target);
    let user = user
        .map(|s| s.to_string())
        .or_else(|| std::env::var("MYSQL_USER").ok())
        .unwrap_or_else(|| "root".into());
    let password = password
        .map(|s| s.to_string())
        .or_else(|| std::env::var("MYSQL_PASSWORD").ok())
        .or_else(|| std::env::var("MYSQL_ROOT_PASSWORD").ok());
    let database = database
        .map(|s| s.to_string())
        .or_else(|| std::env::var("MYSQL_DATABASE").ok());

    let mut health = MysqlHealth {
        version: None,
        connections: MysqlConnections::default(),
        replication: None,
        innodb: InnodbStats::default(),
        databases: Vec::new(),
        locked_tables: Vec::new(),
        processlist: Vec::new(),
        variables: Vec::new(),
        success: true,
        errors: Vec::new(),
    };

    let (version, threads, max_conn, max_used, aborted, repl, innodb_bp, innodb_locks, dbs, locks, procs, vars) =
        tokio::join!(
            mysql_query(&host, &port, &user, password.as_deref(), database.as_deref(), "SELECT VERSION() as version"),
            mysql_query(&host, &port, &user, password.as_deref(), database.as_deref(),
                "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_status \
                 WHERE VARIABLE_NAME IN ('Threads_connected','Threads_running','Threads_created','Threads_cached')"),
            mysql_query(&host, &port, &user, password.as_deref(), database.as_deref(),
                "SELECT VARIABLE_VALUE as val FROM performance_schema.global_variables WHERE VARIABLE_NAME = 'max_connections'"),
            mysql_query(&host, &port, &user, password.as_deref(), database.as_deref(),
                "SELECT VARIABLE_VALUE as val FROM performance_schema.global_status WHERE VARIABLE_NAME = 'Max_used_connections'"),
            mysql_query(&host, &port, &user, password.as_deref(), database.as_deref(),
                "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_status \
                 WHERE VARIABLE_NAME IN ('Aborted_clients','Aborted_connects')"),
            mysql_query(&host, &port, &user, password.as_deref(), database.as_deref(),
                "SHOW REPLICA STATUS"),
            mysql_query(&host, &port, &user, password.as_deref(), database.as_deref(),
                "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_status \
                 WHERE VARIABLE_NAME IN ('Innodb_buffer_pool_read_requests','Innodb_buffer_pool_reads', \
                 'Innodb_buffer_pool_pages_total','Innodb_buffer_pool_pages_free')"),
            mysql_query(&host, &port, &user, password.as_deref(), database.as_deref(),
                "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_status \
                 WHERE VARIABLE_NAME IN ('Innodb_row_lock_waits','Innodb_row_lock_time_avg','Innodb_deadlocks')"),
            mysql_query(&host, &port, &user, password.as_deref(), database.as_deref(),
                "SELECT table_schema as db, \
                 ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) as size_mb, \
                 SUM(table_rows) as total_rows, COUNT(*) as table_count \
                 FROM information_schema.tables WHERE table_schema NOT IN ('information_schema','mysql','performance_schema','sys') \
                 GROUP BY table_schema ORDER BY size_mb DESC"),
            mysql_query(&host, &port, &user, password.as_deref(), database.as_deref(),
                "SELECT * FROM information_schema.INNODB_LOCK_WAITS LIMIT 20"),
            mysql_query(&host, &port, &user, password.as_deref(), database.as_deref(),
                "SELECT id, user, host, db, command, time, state, LEFT(info, 200) as query \
                 FROM information_schema.processlist WHERE command != 'Sleep' ORDER BY time DESC LIMIT 20"),
            mysql_query(&host, &port, &user, password.as_deref(), database.as_deref(),
                "SELECT VARIABLE_NAME as name, VARIABLE_VALUE as value FROM performance_schema.global_variables \
                 WHERE VARIABLE_NAME IN ('innodb_buffer_pool_size','innodb_log_file_size','innodb_flush_method', \
                 'max_connections','wait_timeout','interactive_timeout','slow_query_log','long_query_time', \
                 'log_bin','server_id','gtid_mode','read_only','super_read_only')"),
        );

    // Parse version
    if let Some(rows) = parse(&version, &mut health.errors) {
        health.version = rows.first()
            .and_then(|r| r.get("version"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
    }

    // Parse thread stats
    if let Some(rows) = parse(&threads, &mut health.errors) {
        for row in &rows {
            let name = row.get("VARIABLE_NAME").and_then(|v| v.as_str()).unwrap_or("");
            let val = row.get("VARIABLE_VALUE").and_then(|v| v.as_str()).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
            match name {
                "Threads_connected" => health.connections.connected_threads = val,
                "Threads_running" => health.connections.running_threads = val,
                _ => {}
            }
            health.connections.current_threads = health.connections.connected_threads;
        }
    }

    // Parse max_connections
    if let Some(rows) = parse(&max_conn, &mut health.errors) {
        health.connections.max_connections = rows.first()
            .and_then(|r| r.get("val")).and_then(|v| v.as_str()).and_then(|s| s.parse().ok());
    }

    // Parse max_used_connections
    if let Some(rows) = parse(&max_used, &mut health.errors) {
        health.connections.max_used_connections = rows.first()
            .and_then(|r| r.get("val")).and_then(|v| v.as_str()).and_then(|s| s.parse().ok());
    }

    // Parse aborted stats
    if let Some(rows) = parse(&aborted, &mut health.errors) {
        for row in &rows {
            let name = row.get("VARIABLE_NAME").and_then(|v| v.as_str()).unwrap_or("");
            let val = row.get("VARIABLE_VALUE").and_then(|v| v.as_str()).and_then(|s| s.parse().ok());
            match name {
                "Aborted_clients" => health.connections.aborted_clients = val,
                "Aborted_connects" => health.connections.aborted_connects = val,
                _ => {}
            }
        }
    }

    // Parse replication
    if let Some(rows) = parse(&repl, &mut health.errors) {
        health.replication = rows.first().cloned();
    }

    // Parse InnoDB buffer pool
    if let Some(rows) = parse(&innodb_bp, &mut health.errors) {
        let mut requests: i64 = 0;
        let mut reads: i64 = 0;
        for row in &rows {
            let name = row.get("VARIABLE_NAME").and_then(|v| v.as_str()).unwrap_or("");
            let val = row.get("VARIABLE_VALUE").and_then(|v| v.as_str()).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
            match name {
                "Innodb_buffer_pool_read_requests" => requests = val,
                "Innodb_buffer_pool_reads" => reads = val,
                _ => {}
            }
        }
        health.innodb.buffer_pool_read_requests = requests;
        health.innodb.buffer_pool_reads = reads;
        if requests > 0 {
            health.innodb.buffer_pool_hit_ratio =
                Some(((requests - reads) as f64 / requests as f64 * 10000.0).round() / 10000.0);
        }
    }

    // Parse InnoDB lock stats
    if let Some(rows) = parse(&innodb_locks, &mut health.errors) {
        for row in &rows {
            let name = row.get("VARIABLE_NAME").and_then(|v| v.as_str()).unwrap_or("");
            let val = row.get("VARIABLE_VALUE").and_then(|v| v.as_str()).and_then(|s| s.parse().ok());
            match name {
                "Innodb_row_lock_waits" => health.innodb.row_lock_waits = val,
                "Innodb_row_lock_time_avg" => health.innodb.row_lock_time_avg = val,
                "Innodb_deadlocks" => health.innodb.deadlocks = val,
                _ => {}
            }
        }
    }

    // Parse databases
    if let Some(rows) = parse(&dbs, &mut health.errors) { health.databases = rows; }
    if let Some(rows) = parse(&locks, &mut health.errors) { health.locked_tables = rows; }
    if let Some(rows) = parse(&procs, &mut health.errors) { health.processlist = rows; }
    if let Some(rows) = parse(&vars, &mut health.errors) { health.variables = rows; }

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
            parts.get(1).unwrap_or(&"3306").to_string(),
        );
    }
    let host = std::env::var("MYSQL_HOST")
        .unwrap_or_else(|_| find_service_host(3306).unwrap_or("localhost".into()));
    let port = std::env::var("MYSQL_PORT").unwrap_or_else(|_| "3306".into());
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

async fn mysql_query(
    host: &str,
    port: &str,
    user: &str,
    password: Option<&str>,
    database: Option<&str>,
    query: &str,
) -> Result<String, String> {
    let mut args = vec![
        "-h".to_string(), host.to_string(),
        "-P".to_string(), port.to_string(),
        "-u".to_string(), user.to_string(),
        "--batch".to_string(),
        "--raw".to_string(),
        "-e".to_string(), format!("{query};"),
    ];
    if let Some(pw) = password {
        args.insert(6, format!("-p{pw}"));
    }
    if let Some(db) = database {
        args.push(db.to_string());
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = cmd::run("mysql", &arg_refs, 15).await;

    if result.success {
        Ok(result.stdout.clone())
    } else {
        Err(result.stderr.trim().to_string())
    }
}

fn parse(result: &Result<String, String>, errors: &mut Vec<String>) -> Option<Vec<serde_json::Value>> {
    match result {
        Ok(output) => Some(parse_tsv(output)),
        Err(e) => {
            if !e.is_empty() && !e.contains("doesn't exist") {
                errors.push(e.clone());
            }
            None
        }
    }
}

/// Parse MySQL --batch TSV output into JSON array.
fn parse_tsv(output: &str) -> Vec<serde_json::Value> {
    let lines: Vec<&str> = output.trim().lines().collect();
    if lines.is_empty() {
        return Vec::new();
    }
    let headers: Vec<&str> = lines[0].split('\t').collect();
    lines[1..]
        .iter()
        .map(|line| {
            let values: Vec<&str> = line.split('\t').collect();
            let mut obj = serde_json::Map::new();
            for (i, header) in headers.iter().enumerate() {
                let val = values.get(i).unwrap_or(&"");
                obj.insert(header.to_string(), serde_json::json!(val));
            }
            serde_json::Value::Object(obj)
        })
        .collect()
}
