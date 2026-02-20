use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct PostgresHealth {
    version: Option<String>,
    connections: ConnectionStats,
    replication: Vec<serde_json::Value>,
    locks: LockInfo,
    long_running_queries: Vec<serde_json::Value>,
    cache: CacheStats,
    databases: Vec<serde_json::Value>,
    table_health: Vec<serde_json::Value>,
    settings: Vec<serde_json::Value>,
    success: bool,
    errors: Vec<String>,
}

#[derive(Serialize, Default)]
struct ConnectionStats {
    max_connections: Option<i64>,
    total: i64,
    active: i64,
    idle: i64,
    idle_in_transaction: i64,
    waiting: i64,
    by_state: Vec<serde_json::Value>,
}

#[derive(Serialize, Default)]
struct LockInfo {
    total_locks: i64,
    blocked_queries: Vec<serde_json::Value>,
}

#[derive(Serialize, Default)]
struct CacheStats {
    hit_ratio: Option<f64>,
    blks_hit: i64,
    blks_read: i64,
}

pub async fn check(
    target: Option<&str>,
    user: Option<&str>,
    password: Option<&str>,
    database: Option<&str>,
) -> String {
    let conn = build_connection_string(target, user, password, database);
    let mut health = PostgresHealth {
        version: None,
        connections: ConnectionStats::default(),
        replication: Vec::new(),
        locks: LockInfo::default(),
        long_running_queries: Vec::new(),
        cache: CacheStats::default(),
        databases: Vec::new(),
        table_health: Vec::new(),
        settings: Vec::new(),
        success: true,
        errors: Vec::new(),
    };

    // Run all diagnostic queries in parallel
    let (version, conns, max_conns, repl, locks, long_q, cache, dbs, tables, settings) =
        tokio::join!(
            psql(&conn, "SELECT version()"),
            psql(
                &conn,
                "SELECT state, count(*) as count FROM pg_stat_activity GROUP BY state ORDER BY count DESC"
            ),
            psql(&conn, "SELECT setting::int FROM pg_settings WHERE name = 'max_connections'"),
            psql(
                &conn,
                "SELECT pid, client_addr, state, sent_lsn, write_lsn, flush_lsn, replay_lsn, \
                 extract(epoch from replay_lag)::numeric(10,3) as replay_lag_sec \
                 FROM pg_stat_replication"
            ),
            psql(
                &conn,
                "SELECT blocked.pid AS blocked_pid, blocked.query AS blocked_query, \
                 blocking.pid AS blocking_pid, blocking.query AS blocking_query, \
                 blocked.wait_event_type, blocked.wait_event \
                 FROM pg_stat_activity blocked \
                 JOIN pg_locks bl ON bl.pid = blocked.pid AND NOT bl.granted \
                 JOIN pg_locks gl ON gl.locktype = bl.locktype AND gl.database IS NOT DISTINCT FROM bl.database \
                   AND gl.relation IS NOT DISTINCT FROM bl.relation AND gl.page IS NOT DISTINCT FROM bl.page \
                   AND gl.tuple IS NOT DISTINCT FROM bl.tuple AND gl.transactionid IS NOT DISTINCT FROM bl.transactionid \
                   AND gl.classid IS NOT DISTINCT FROM bl.classid AND gl.objid IS NOT DISTINCT FROM bl.objid \
                   AND gl.objsubid IS NOT DISTINCT FROM bl.objsubid AND gl.pid != bl.pid AND gl.granted \
                 JOIN pg_stat_activity blocking ON blocking.pid = gl.pid \
                 LIMIT 20"
            ),
            psql(
                &conn,
                "SELECT pid, now() - query_start as duration, state, left(query, 200) as query \
                 FROM pg_stat_activity \
                 WHERE state = 'active' AND query NOT ILIKE '%pg_stat_activity%' \
                   AND query_start < now() - interval '5 seconds' \
                 ORDER BY query_start LIMIT 20"
            ),
            psql(
                &conn,
                "SELECT sum(blks_hit) as blks_hit, sum(blks_read) as blks_read, \
                 CASE WHEN sum(blks_hit) + sum(blks_read) > 0 \
                   THEN round(sum(blks_hit)::numeric / (sum(blks_hit) + sum(blks_read)), 4) \
                   ELSE 0 END as hit_ratio \
                 FROM pg_stat_database"
            ),
            psql(
                &conn,
                "SELECT datname, pg_size_pretty(pg_database_size(datname)) as size, \
                 pg_database_size(datname) as size_bytes, numbackends \
                 FROM pg_database WHERE datistemplate = false ORDER BY pg_database_size(datname) DESC"
            ),
            psql(
                &conn,
                "SELECT schemaname, relname, n_live_tup, n_dead_tup, \
                 CASE WHEN n_live_tup > 0 THEN round(n_dead_tup::numeric / n_live_tup, 4) ELSE 0 END as dead_ratio, \
                 pg_size_pretty(pg_total_relation_size(schemaname || '.' || relname)) as total_size, \
                 last_vacuum::text, last_autovacuum::text, last_analyze::text, last_autoanalyze::text, \
                 seq_scan, idx_scan \
                 FROM pg_stat_user_tables ORDER BY n_dead_tup DESC LIMIT 30"
            ),
            psql(
                &conn,
                "SELECT name, setting, unit, short_desc FROM pg_settings \
                 WHERE name IN ('shared_buffers','effective_cache_size','work_mem','maintenance_work_mem', \
                 'max_connections','max_wal_size','min_wal_size','checkpoint_completion_target', \
                 'wal_level','max_worker_processes','max_parallel_workers', \
                 'random_page_cost','effective_io_concurrency','autovacuum', \
                 'log_min_duration_statement','statement_timeout','idle_in_transaction_session_timeout') \
                 ORDER BY name"
            ),
        );

    // Parse version
    if let Some(rows) = parse_or_err(&version, &mut health.errors) {
        health.version = rows
            .first()
            .and_then(|r| r.get("version"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
    }

    // Parse connection stats
    if let Some(rows) = parse_or_err(&conns, &mut health.errors) {
        health.connections.by_state = rows.clone();
        for row in &rows {
            let state = row.get("state").and_then(|v| v.as_str()).unwrap_or("");
            let count = row
                .get("count")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            health.connections.total += count;
            match state {
                "active" => health.connections.active = count,
                "idle" => health.connections.idle = count,
                "idle in transaction" => health.connections.idle_in_transaction = count,
                _ if state.contains("waiting") => health.connections.waiting = count,
                _ => {}
            }
        }
    }

    // Parse max_connections
    if let Some(rows) = parse_or_err(&max_conns, &mut health.errors) {
        health.connections.max_connections = rows
            .first()
            .and_then(|r| r.get("setting"))
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok());
    }

    // Parse replication
    if let Some(rows) = parse_or_err(&repl, &mut health.errors) {
        health.replication = rows;
    }

    // Parse locks
    if let Some(rows) = parse_or_err(&locks, &mut health.errors) {
        health.locks.total_locks = rows.len() as i64;
        health.locks.blocked_queries = rows;
    }

    // Parse long-running queries
    if let Some(rows) = parse_or_err(&long_q, &mut health.errors) {
        health.long_running_queries = rows;
    }

    // Parse cache stats
    if let Some(rows) = parse_or_err(&cache, &mut health.errors) {
        if let Some(row) = rows.first() {
            health.cache.hit_ratio = row
                .get("hit_ratio")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok());
            health.cache.blks_hit = row
                .get("blks_hit")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            health.cache.blks_read = row
                .get("blks_read")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        }
    }

    // Parse databases
    if let Some(rows) = parse_or_err(&dbs, &mut health.errors) {
        health.databases = rows;
    }

    // Parse table health
    if let Some(rows) = parse_or_err(&tables, &mut health.errors) {
        health.table_health = rows;
    }

    // Parse settings
    if let Some(rows) = parse_or_err(&settings, &mut health.errors) {
        health.settings = rows;
    }

    if !health.errors.is_empty() && health.version.is_none() {
        health.success = false;
    }

    serde_json::to_string_pretty(&health).unwrap()
}

fn build_connection_string(
    target: Option<&str>,
    user: Option<&str>,
    password: Option<&str>,
    database: Option<&str>,
) -> String {
    // If explicit connection string provided, use it
    if let Some(t) = target {
        if t.starts_with("postgres://") || t.starts_with("postgresql://") {
            return t.to_string();
        }
    }

    // Try DATABASE_URL env
    if let Ok(url) = std::env::var("DATABASE_URL") {
        if target.is_none() {
            return url;
        }
    }

    // Build from components
    let host;
    let port;
    if let Some(t) = target {
        let parts: Vec<&str> = t.splitn(2, ':').collect();
        host = parts[0].to_string();
        port = parts.get(1).unwrap_or(&"5432").to_string();
    } else {
        host = std::env::var("PGHOST")
            .or_else(|_| std::env::var("POSTGRES_HOST"))
            .unwrap_or_else(|_| find_service_host(5432).unwrap_or("localhost".into()));
        port = std::env::var("PGPORT")
            .or_else(|_| std::env::var("POSTGRES_PORT"))
            .unwrap_or_else(|_| "5432".into());
    }

    let user = user
        .map(|s| s.to_string())
        .or_else(|| std::env::var("PGUSER").ok())
        .or_else(|| std::env::var("POSTGRES_USER").ok())
        .unwrap_or_else(|| "postgres".into());

    let db = database
        .map(|s| s.to_string())
        .or_else(|| std::env::var("PGDATABASE").ok())
        .or_else(|| std::env::var("POSTGRES_DB").ok())
        .unwrap_or_else(|| "postgres".into());

    let mut conn = format!("postgresql://{user}");
    if let Some(pw) = password.or(std::env::var("PGPASSWORD").ok().as_deref()) {
        conn.push(':');
        conn.push_str(pw);
    }
    conn.push('@');
    conn.push_str(&host);
    conn.push(':');
    conn.push_str(&port);
    conn.push('/');
    conn.push_str(&db);
    conn
}

/// Find a K8s service host by port from env vars.
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

async fn psql(conn: &str, query: &str) -> Result<String, String> {
    let wrapped = format!(
        "SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM ({}) t",
        query.trim_end_matches(';')
    );

    let result = cmd::run_with_env(
        "psql",
        &[conn, "-t", "-A", "-c", &wrapped],
        &[("PGCONNECT_TIMEOUT", "5")],
        15,
    )
    .await;

    if result.success {
        Ok(result.stdout.trim().to_string())
    } else {
        Err(result.stderr.trim().to_string())
    }
}

fn parse_or_err(
    result: &Result<String, String>,
    errors: &mut Vec<String>,
) -> Option<Vec<serde_json::Value>> {
    match result {
        Ok(json) => match serde_json::from_str(json) {
            Ok(rows) => Some(rows),
            Err(e) => {
                errors.push(format!("JSON parse: {e}"));
                None
            }
        },
        Err(e) => {
            if !e.is_empty() {
                errors.push(e.clone());
            }
            None
        }
    }
}
