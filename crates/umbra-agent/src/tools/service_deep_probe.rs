use crate::cmd;
use crate::probe;
use umbra_core::assessment::{
    DatabaseType, DeepProbeReport, MqType, SecurityFinding, ServiceHealthResult, ServiceType,
    Severity, UnauthenticatedAccess,
};
use umbra_core::targets::{ServiceCredentials, TargetConfig};

/// Deep probe all discovered services — unauthenticated recon + credentialed health check.
/// If `configured_targets` is provided, those targets are probed with their credentials
/// in addition to (or overriding) auto-discovered services.
pub async fn probe_all(configured_targets: Option<Vec<TargetConfig>>) -> String {
    let services = umbra_core::services::discover_services();
    let configured = configured_targets.unwrap_or_default();

    // Build probe list: start with auto-discovered services
    let mut probe_list: Vec<(String, String, u16, ServiceType, ServiceCredentials)> = Vec::new();

    for svc in &services {
        let service_type = detect_type(svc.port);

        // Check if we have configured credentials for this host:port
        let creds = find_credentials(&configured, &svc.host, svc.port);

        probe_list.push((
            svc.name.clone(),
            svc.host.clone(),
            svc.port,
            service_type,
            creds,
        ));
    }

    // Add configured targets that weren't auto-discovered
    for target in &configured {
        let already_listed = probe_list
            .iter()
            .any(|(_, h, p, _, _)| h == &target.host && *p == target.port);

        if !already_listed {
            let service_type = target
                .service_type
                .as_deref()
                .and_then(parse_service_type)
                .unwrap_or_else(|| detect_type(target.port));

            probe_list.push((
                target
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("{}:{}", target.host, target.port)),
                target.host.clone(),
                target.port,
                service_type,
                target.credentials.clone(),
            ));
        }
    }

    // Probe each service in parallel
    let mut handles = Vec::new();
    for (name, host, port, service_type, creds) in probe_list {
        handles.push(tokio::spawn(async move {
            probe_service(&name, &host, port, &service_type, &creds).await
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }

    let authenticated_count = results.iter().filter(|r| r.authenticated).count();
    let anonymous_count = results
        .iter()
        .filter(|r| r.unauthenticated_access.allows_anonymous)
        .count();

    let report = DeepProbeReport {
        total_probed: results.len(),
        authenticated_count,
        anonymous_access_count: anonymous_count,
        services: results,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    serde_json::to_string_pretty(&report).unwrap()
}

/// Probe a single target with explicit type and optional credentials.
pub async fn probe_target(
    target: &str,
    service_type: Option<&str>,
    credentials: Option<ServiceCredentials>,
) -> String {
    let (host, port) = match parse_target(target) {
        Some(hp) => hp,
        None => {
            return serde_json::json!({
                "error": format!("Invalid target '{target}'. Use 'host:port' format.")
            })
            .to_string();
        }
    };

    let st = service_type
        .and_then(parse_service_type)
        .unwrap_or_else(|| detect_type(port));

    let creds = credentials.unwrap_or_default();
    let result = probe_service("", &host, port, &st, &creds).await;
    serde_json::to_string_pretty(&result).unwrap()
}

/// Find configured credentials for a host:port pair.
fn find_credentials(
    configured: &[TargetConfig],
    host: &str,
    port: u16,
) -> ServiceCredentials {
    configured
        .iter()
        .find(|t| t.host == host && t.port == port)
        .map(|t| t.credentials.clone())
        .unwrap_or_default()
}

async fn probe_service(
    name: &str,
    host: &str,
    port: u16,
    service_type: &ServiceType,
    credentials: &ServiceCredentials,
) -> ServiceHealthResult {
    // Step 1: Unauthenticated reconnaissance
    let unauth = unauthenticated_probe(host, port, service_type).await;

    // Step 2: Check if we have credentials — from config, env, or anonymous access
    let has_creds = has_configured_credentials(credentials)
        || has_env_credentials(service_type);

    // Step 3: Run full health check if we have credentials OR anonymous access works
    let health = if has_creds || unauth.allows_anonymous {
        run_health_check(host, port, service_type, credentials).await
    } else {
        None
    };

    // Step 4: Generate security findings
    let findings = generate_findings(name, host, port, service_type, &unauth, &health);

    ServiceHealthResult {
        name: name.to_string(),
        host: host.to_string(),
        port,
        service_type: service_type.clone(),
        authenticated: has_creds,
        unauthenticated_access: unauth,
        health,
        findings,
    }
}

/// Check if ServiceCredentials has any non-empty credential.
fn has_configured_credentials(creds: &ServiceCredentials) -> bool {
    creds.password.is_some()
        || creds.connection_string.is_some()
        || creds.user.is_some()
}

// === Unauthenticated probing ===

async fn unauthenticated_probe(
    host: &str,
    port: u16,
    service_type: &ServiceType,
) -> UnauthenticatedAccess {
    match service_type {
        ServiceType::Database(DatabaseType::PostgreSQL) => probe_postgres_unauth(host, port).await,
        ServiceType::Database(DatabaseType::MySQL) => probe_mysql_unauth(host, port).await,
        ServiceType::Database(DatabaseType::Redis) => probe_redis_unauth(host, port).await,
        ServiceType::Rest | ServiceType::GraphQL | ServiceType::StaticFiles => {
            probe_http_unauth(host, port).await
        }
        _ => probe_generic_unauth(host, port).await,
    }
}

/// PostgreSQL: connect without credentials, extract version from error, check trust auth.
async fn probe_postgres_unauth(host: &str, port: u16) -> UnauthenticatedAccess {
    let mut access = UnauthenticatedAccess {
        version: None,
        banner: None,
        allows_anonymous: false,
        accessible_data: Vec::new(),
        auth_mechanism: None,
        tls_required: None,
        evidence: Vec::new(),
    };

    // pg_isready doesn't need auth — checks if server is accepting connections
    let ready = cmd::run(
        "pg_isready",
        &["-h", host, "-p", &port.to_string(), "-t", "3"],
        5,
    )
    .await;

    if ready.success {
        access
            .evidence
            .push("pg_isready: accepting connections".into());
    } else {
        access.evidence.push(format!(
            "pg_isready: {}",
            ready.stderr.trim()
        ));
    }

    // Try connecting without password — will reveal version and auth method
    let conn = format!("postgresql://probe@{host}:{port}/postgres");
    let result = cmd::run_with_env(
        "psql",
        &[&conn, "-c", "SELECT version()"],
        &[("PGCONNECT_TIMEOUT", "3")],
        5,
    )
    .await;

    if result.success {
        // Trust auth! No password needed — this is a security finding
        access.allows_anonymous = true;
        access.auth_mechanism = Some("trust (no password required)".into());
        access
            .evidence
            .push("Connected WITHOUT password (trust auth)".into());

        // Extract version
        let version = result
            .stdout
            .lines()
            .find(|l| l.contains("PostgreSQL"))
            .map(|l| l.trim().to_string());
        access.version = version.clone();
        if let Some(ref v) = version {
            access.accessible_data.push(format!("version: {v}"));
        }

        // Try to list databases
        let dbs = cmd::run_with_env(
            "psql",
            &[&conn, "-t", "-A", "-c", "SELECT datname FROM pg_database WHERE datistemplate = false"],
            &[("PGCONNECT_TIMEOUT", "3")],
            5,
        )
        .await;
        if dbs.success {
            let db_list: Vec<&str> = dbs.stdout.trim().lines().collect();
            access
                .accessible_data
                .push(format!("databases: {}", db_list.join(", ")));
        }
    } else {
        let stderr = result.stderr.trim();
        if stderr.contains("password authentication failed") {
            access.auth_mechanism = Some("password".into());
            access
                .evidence
                .push("Password authentication required".into());
        } else if stderr.contains("no pg_hba.conf entry") {
            access.auth_mechanism = Some("pg_hba reject".into());
            access.evidence.push(format!("pg_hba.conf: {stderr}"));
        } else if stderr.contains("SSL") {
            access.tls_required = Some(true);
            access.evidence.push("SSL required for connections".into());
        }

        if let Some(ver) = extract_pg_version_from_error(stderr) {
            access.version = Some(ver);
        }
    }

    access
}

/// MySQL: greeting packet reveals version before authentication.
async fn probe_mysql_unauth(host: &str, port: u16) -> UnauthenticatedAccess {
    let mut access = UnauthenticatedAccess {
        version: None,
        banner: None,
        allows_anonymous: false,
        accessible_data: Vec::new(),
        auth_mechanism: None,
        tls_required: None,
        evidence: Vec::new(),
    };

    let port_str = port.to_string();
    let result = cmd::run(
        "mysql",
        &[
            "-h",
            host,
            "-P",
            &port_str,
            "-u",
            "probe",
            "--connect-timeout=3",
            "--batch",
            "-e",
            "SELECT VERSION();",
        ],
        5,
    )
    .await;

    if result.success {
        access.allows_anonymous = true;
        access.auth_mechanism = Some("no password for user 'probe'".into());
        access
            .evidence
            .push("Connected WITHOUT password".into());

        let version = result
            .stdout
            .lines()
            .nth(1)
            .map(|l| l.trim().to_string());
        access.version = version;
    } else {
        let stderr = result.stderr.trim();
        if stderr.contains("Access denied") {
            access.auth_mechanism = Some("password".into());
            access
                .evidence
                .push("Password authentication required".into());
        }

        let banner = cmd::run(
            "sh",
            &[
                "-c",
                &format!(
                    "echo '' | timeout 3 nc -w 2 {host} {port} 2>/dev/null | strings | head -1"
                ),
            ],
            5,
        )
        .await;

        if banner.success && !banner.stdout.trim().is_empty() {
            let raw = banner.stdout.trim().to_string();
            access.banner = Some(raw.clone());
            if let Some(ver) = extract_mysql_version(&raw) {
                access.version = Some(ver);
            }
        }
    }

    // Try anonymous root login (common misconfiguration)
    let root_result = cmd::run(
        "mysql",
        &[
            "-h",
            host,
            "-P",
            &port_str,
            "-u",
            "root",
            "--connect-timeout=3",
            "--batch",
            "-e",
            "SELECT VERSION();",
        ],
        5,
    )
    .await;

    if root_result.success {
        access.allows_anonymous = true;
        access.auth_mechanism = Some("root with no password".into());
        access
            .evidence
            .push("ROOT ACCESS WITHOUT PASSWORD".into());

        let dbs = cmd::run(
            "mysql",
            &[
                "-h",
                host,
                "-P",
                &port_str,
                "-u",
                "root",
                "--connect-timeout=3",
                "--batch",
                "-e",
                "SHOW DATABASES;",
            ],
            5,
        )
        .await;
        if dbs.success {
            let db_list: Vec<&str> = dbs
                .stdout
                .lines()
                .skip(1)
                .filter(|l| !l.is_empty())
                .collect();
            access
                .accessible_data
                .push(format!("databases: {}", db_list.join(", ")));
        }
    }

    access
}

/// Redis: PING and INFO often work without auth. AUTH error confirms Redis.
async fn probe_redis_unauth(host: &str, port: u16) -> UnauthenticatedAccess {
    let mut access = UnauthenticatedAccess {
        version: None,
        banner: None,
        allows_anonymous: false,
        accessible_data: Vec::new(),
        auth_mechanism: None,
        tls_required: None,
        evidence: Vec::new(),
    };

    let port_str = port.to_string();

    let ping = cmd::run(
        "redis-cli",
        &["-h", host, "-p", &port_str, "--no-auth-warning", "PING"],
        5,
    )
    .await;

    let ping_output = ping.stdout.trim().to_string();
    if ping.success && ping_output == "PONG" {
        access.allows_anonymous = true;
        access
            .evidence
            .push("PING → PONG (no auth required)".into());

        let info = cmd::run(
            "redis-cli",
            &[
                "-h",
                host,
                "-p",
                &port_str,
                "--no-auth-warning",
                "INFO",
                "server",
            ],
            5,
        )
        .await;

        if info.success {
            for line in info.stdout.lines() {
                if let Some(ver) = line.strip_prefix("redis_version:") {
                    access.version = Some(ver.trim().to_string());
                }
            }
            access
                .accessible_data
                .push("INFO server accessible".into());
        }

        let dbsize = cmd::run(
            "redis-cli",
            &[
                "-h",
                host,
                "-p",
                &port_str,
                "--no-auth-warning",
                "DBSIZE",
            ],
            5,
        )
        .await;
        if dbsize.success {
            access
                .accessible_data
                .push(format!("DBSIZE: {}", dbsize.stdout.trim()));
        }

        let config = cmd::run(
            "redis-cli",
            &[
                "-h",
                host,
                "-p",
                &port_str,
                "--no-auth-warning",
                "CONFIG",
                "GET",
                "requirepass",
            ],
            5,
        )
        .await;
        if config.success && !config.stdout.contains("NOAUTH") {
            access
                .accessible_data
                .push("CONFIG GET accessible (admin commands available without auth)".into());
            access.auth_mechanism = Some("none (no authentication)".into());
        }

        let keys = cmd::run(
            "redis-cli",
            &[
                "-h",
                host,
                "-p",
                &port_str,
                "--no-auth-warning",
                "KEYS",
                "*",
            ],
            5,
        )
        .await;
        if keys.success && !keys.stdout.trim().is_empty() {
            let key_count = keys.stdout.lines().count();
            access
                .accessible_data
                .push(format!("KEYS *: {key_count} keys visible"));
        }
    } else if ping_output.contains("NOAUTH") || ping.stderr.contains("NOAUTH") {
        access.auth_mechanism = Some("password required (AUTH/NOAUTH)".into());
        access
            .evidence
            .push("NOAUTH — password required".into());
        access.banner = Some("Redis (NOAUTH response)".into());
    } else {
        access.evidence.push(format!(
            "PING failed: {}",
            if !ping_output.is_empty() {
                &ping_output
            } else {
                ping.stderr.trim()
            }
        ));
    }

    access
}

/// HTTP services: check headers, common unauthenticated endpoints.
async fn probe_http_unauth(host: &str, port: u16) -> UnauthenticatedAccess {
    let mut access = UnauthenticatedAccess {
        version: None,
        banner: None,
        allows_anonymous: false,
        accessible_data: Vec::new(),
        auth_mechanism: None,
        tls_required: None,
        evidence: Vec::new(),
    };

    let base_url = format!("http://{host}:{port}");

    let headers = cmd::run(
        "curl",
        &["-sI", "-m", "3", &base_url],
        5,
    )
    .await;

    if headers.success {
        let mut status = None;
        for line in headers.stdout.lines() {
            let lower = line.to_lowercase();
            if line.starts_with("HTTP/") {
                status = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse::<u16>().ok());
            }
            if lower.starts_with("server:") {
                let ver = line.split(':').nth(1).unwrap_or("").trim().to_string();
                access.version = Some(ver.clone());
                access.evidence.push(format!("Server: {ver}"));

                if lower.contains("haproxy") {
                    access.banner = Some("HAProxy".into());
                } else if lower.contains("nginx") {
                    access.banner = Some("Nginx".into());
                }
            }
            if lower.starts_with("www-authenticate:") {
                access.auth_mechanism = Some(
                    line.split(':').nth(1).unwrap_or("").trim().to_string(),
                );
            }
        }

        match status {
            Some(200) | Some(301) | Some(302) => {
                access.allows_anonymous = true;
                access.evidence.push(format!("HTTP {}", status.unwrap()));
            }
            Some(401) | Some(403) => {
                access
                    .evidence
                    .push(format!("HTTP {} — auth required", status.unwrap()));
            }
            Some(code) => {
                access.evidence.push(format!("HTTP {code}"));
            }
            None => {}
        }
    }

    let health_endpoints = [
        "/health",
        "/healthz",
        "/ready",
        "/readyz",
        "/metrics",
        "/nginx_status",
        "/haproxy?stats",
        "/server-status",
        "/status",
    ];

    for endpoint in &health_endpoints {
        let url = format!("{base_url}{endpoint}");
        let result = cmd::run(
            "curl",
            &["-sf", "-o", "/dev/null", "-w", "%{http_code}", "-m", "2", &url],
            3,
        )
        .await;
        if result.success {
            let code: u16 = result.stdout.trim().parse().unwrap_or(0);
            if code == 200 {
                access
                    .accessible_data
                    .push(format!("{endpoint} → 200 (public)"));
            }
        }
    }

    access
}

/// Generic TCP probe — just banner grab.
async fn probe_generic_unauth(host: &str, port: u16) -> UnauthenticatedAccess {
    let mut access = UnauthenticatedAccess {
        version: None,
        banner: None,
        allows_anonymous: false,
        accessible_data: Vec::new(),
        auth_mechanism: None,
        tls_required: None,
        evidence: Vec::new(),
    };

    let tcp = probe::tcp::connect(host, port).await;
    if tcp.success {
        access
            .evidence
            .push(format!("TCP connect OK ({}ms)", tcp.latency_ms));
    }

    let banner = cmd::run(
        "sh",
        &[
            "-c",
            &format!(
                "echo '' | timeout 3 nc -w 2 {host} {port} 2>/dev/null | head -c 256"
            ),
        ],
        5,
    )
    .await;

    if banner.success && !banner.stdout.trim().is_empty() {
        let raw = banner.stdout.trim().to_string();
        access.banner = Some(raw.clone());

        if raw.contains("SSH-") {
            access.version = raw.lines().next().map(|l| l.to_string());
        }
    }

    access
}

// === Credentialed health checks ===

/// Check if env vars provide credentials for a service type.
fn has_env_credentials(service_type: &ServiceType) -> bool {
    match service_type {
        ServiceType::Database(DatabaseType::PostgreSQL) => {
            std::env::var("PGPASSWORD").is_ok()
                || std::env::var("DATABASE_URL").is_ok()
                || std::env::var("POSTGRES_PASSWORD").is_ok()
        }
        ServiceType::Database(DatabaseType::MySQL) => {
            std::env::var("MYSQL_PASSWORD").is_ok()
                || std::env::var("MYSQL_ROOT_PASSWORD").is_ok()
        }
        ServiceType::Database(DatabaseType::Redis) => {
            std::env::var("REDIS_PASSWORD").is_ok()
        }
        _ => false,
    }
}

async fn run_health_check(
    host: &str,
    port: u16,
    service_type: &ServiceType,
    credentials: &ServiceCredentials,
) -> Option<serde_json::Value> {
    let target = format!("{host}:{port}");

    // Use configured credentials if available, otherwise fall back to env-based discovery
    let result = match service_type {
        ServiceType::Database(DatabaseType::PostgreSQL) => {
            if credentials.connection_string.is_some() || credentials.password.is_some() {
                super::postgres_health::check(
                    Some(&target),
                    credentials.user.as_deref(),
                    credentials.password.as_deref(),
                    credentials.database.as_deref(),
                )
                .await
            } else {
                super::postgres_health::check(Some(&target), None, None, None).await
            }
        }
        ServiceType::Database(DatabaseType::MySQL) => {
            if credentials.password.is_some() {
                super::mysql_health::check(
                    Some(&target),
                    credentials.user.as_deref(),
                    credentials.password.as_deref(),
                    credentials.database.as_deref(),
                )
                .await
            } else {
                super::mysql_health::check(Some(&target), None, None, None).await
            }
        }
        ServiceType::Database(DatabaseType::Redis) => {
            if credentials.password.is_some() {
                super::redis_health::check(
                    Some(&target),
                    credentials.password.as_deref(),
                )
                .await
            } else {
                super::redis_health::check(Some(&target), None).await
            }
        }
        ServiceType::Rest | ServiceType::GraphQL | ServiceType::StaticFiles => {
            let health = probe_http_server_type(host, port).await;
            match health.as_deref() {
                Some("nginx") => super::nginx_status::check(Some(&target)).await,
                Some("haproxy") => super::haproxy_stats::check(Some(&target)).await,
                _ => return None,
            }
        }
        _ => return None,
    };

    serde_json::from_str(&result).ok()
}

/// Check HTTP server type to decide which health tool to use.
async fn probe_http_server_type(host: &str, port: u16) -> Option<String> {
    let url = format!("http://{host}:{port}");
    let result = cmd::run(
        "curl",
        &["-sI", "-m", "2", &url],
        3,
    )
    .await;

    if !result.success {
        return None;
    }

    let lower = result.stdout.to_lowercase();
    if lower.contains("nginx") {
        Some("nginx".into())
    } else if lower.contains("haproxy") {
        Some("haproxy".into())
    } else {
        None
    }
}

// === Security findings generation ===

fn generate_findings(
    name: &str,
    host: &str,
    port: u16,
    service_type: &ServiceType,
    unauth: &UnauthenticatedAccess,
    _health: &Option<serde_json::Value>,
) -> Vec<SecurityFinding> {
    let mut findings = Vec::new();
    let svc_label = format!("{name} ({host}:{port})");

    // Critical: Anonymous access to data stores
    if unauth.allows_anonymous {
        match service_type {
            ServiceType::Database(DatabaseType::Redis) => {
                let severity = if unauth.accessible_data.iter().any(|d| d.contains("CONFIG GET")) {
                    Severity::Critical
                } else {
                    Severity::High
                };
                findings.push(SecurityFinding {
                    id: format!("SDP-REDIS-{port}"),
                    title: format!("Redis accessible without authentication: {svc_label}"),
                    severity,
                    category: "authentication".into(),
                    description: format!(
                        "Redis at {host}:{port} allows connections without authentication. {}",
                        if unauth.accessible_data.iter().any(|d| d.contains("CONFIG GET")) {
                            "Admin commands (CONFIG) are also accessible — full server control is possible."
                        } else {
                            "Data may be read or modified by any pod in the cluster."
                        }
                    ),
                    evidence: unauth.evidence.clone(),
                    remediation: Some(
                        "Set `requirepass` in Redis config. Use K8s NetworkPolicy to restrict access. Consider Redis ACLs for fine-grained control."
                            .into(),
                    ),
                });
            }
            ServiceType::Database(DatabaseType::PostgreSQL) => {
                findings.push(SecurityFinding {
                    id: format!("SDP-PG-{port}"),
                    title: format!("PostgreSQL trust auth enabled: {svc_label}"),
                    severity: Severity::Critical,
                    category: "authentication".into(),
                    description: format!(
                        "PostgreSQL at {host}:{port} accepts connections without password (trust authentication). Any pod in the cluster can read/write all databases."
                    ),
                    evidence: unauth.evidence.clone(),
                    remediation: Some(
                        "Change pg_hba.conf to use 'scram-sha-256' or 'md5' instead of 'trust'. Restart PostgreSQL after changes."
                            .into(),
                    ),
                });
            }
            ServiceType::Database(DatabaseType::MySQL) => {
                let is_root = unauth
                    .auth_mechanism
                    .as_deref()
                    .unwrap_or("")
                    .contains("root");
                findings.push(SecurityFinding {
                    id: format!("SDP-MYSQL-{port}"),
                    title: format!(
                        "MySQL {} without password: {svc_label}",
                        if is_root { "root access" } else { "anonymous access" }
                    ),
                    severity: if is_root {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    category: "authentication".into(),
                    description: format!(
                        "MySQL at {host}:{port} allows {} without a password.",
                        if is_root {
                            "root login"
                        } else {
                            "anonymous connections"
                        }
                    ),
                    evidence: unauth.evidence.clone(),
                    remediation: Some(
                        "Set passwords for all MySQL users. Remove anonymous users: DELETE FROM mysql.user WHERE User=''; FLUSH PRIVILEGES;"
                            .into(),
                    ),
                });
            }
            _ => {}
        }
    }

    // High: Version disclosure (helps attackers target known CVEs)
    if let Some(ref version) = unauth.version {
        if matches!(
            service_type,
            ServiceType::Database(_) | ServiceType::MessageQueue(_)
        ) {
            findings.push(SecurityFinding {
                id: format!("SDP-VERSION-{port}"),
                title: format!("Version disclosed without auth: {svc_label}"),
                severity: Severity::Low,
                category: "information_disclosure".into(),
                description: format!(
                    "Service at {host}:{port} reveals version '{version}' before authentication. This helps attackers identify applicable CVEs."
                ),
                evidence: vec![format!("version: {version}")],
                remediation: None,
            });
        }
    }

    // Medium: No TLS on database connections
    if matches!(unauth.tls_required, Some(false) | None)
        && matches!(service_type, ServiceType::Database(_))
    {
        findings.push(SecurityFinding {
            id: format!("SDP-NOTLS-{port}"),
            title: format!("Database accepts unencrypted connections: {svc_label}"),
            severity: Severity::Medium,
            category: "encryption".into(),
            description: format!(
                "Database at {host}:{port} does not require TLS. Credentials and data traverse the network in plaintext."
            ),
            evidence: unauth.evidence.clone(),
            remediation: Some(
                "Enable SSL/TLS in the database configuration. For PostgreSQL: ssl=on in postgresql.conf. For MySQL: require_secure_transport=ON."
                    .into(),
            ),
        });
    }

    // Info: Exposed health/metrics endpoints
    let public_endpoints: Vec<&str> = unauth
        .accessible_data
        .iter()
        .filter(|d| d.contains("→ 200 (public)"))
        .map(|d| d.as_str())
        .collect();

    if !public_endpoints.is_empty() {
        findings.push(SecurityFinding {
            id: format!("SDP-ENDPOINTS-{port}"),
            title: format!("Public endpoints found: {svc_label}"),
            severity: Severity::Info,
            category: "information_disclosure".into(),
            description: format!(
                "{} endpoints are accessible without authentication at {host}:{port}.",
                public_endpoints.len()
            ),
            evidence: public_endpoints.iter().map(|s| s.to_string()).collect(),
            remediation: Some(
                "Review if /metrics, /status, or debug endpoints should be exposed. Use K8s NetworkPolicy to restrict access."
                    .into(),
            ),
        });
    }

    findings
}

// === Helpers ===

fn detect_type(port: u16) -> ServiceType {
    match port {
        5432 => ServiceType::Database(DatabaseType::PostgreSQL),
        3306 => ServiceType::Database(DatabaseType::MySQL),
        6379 => ServiceType::Database(DatabaseType::Redis),
        27017 => ServiceType::Database(DatabaseType::MongoDB),
        9092 => ServiceType::MessageQueue(MqType::Kafka),
        4222 => ServiceType::MessageQueue(MqType::Nats),
        5672 => ServiceType::MessageQueue(MqType::RabbitMQ),
        80 | 443 | 8080 | 8443 | 3000 | 4000 | 5000 | 8000 | 9000 => ServiceType::Rest,
        _ => ServiceType::Unknown,
    }
}

fn parse_service_type(s: &str) -> Option<ServiceType> {
    match s.to_lowercase().as_str() {
        "postgres" | "postgresql" => Some(ServiceType::Database(DatabaseType::PostgreSQL)),
        "mysql" => Some(ServiceType::Database(DatabaseType::MySQL)),
        "redis" => Some(ServiceType::Database(DatabaseType::Redis)),
        "mongodb" | "mongo" => Some(ServiceType::Database(DatabaseType::MongoDB)),
        "nginx" => Some(ServiceType::Rest),
        "haproxy" => Some(ServiceType::Rest),
        _ => None,
    }
}

fn parse_target(target: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = target.rsplitn(2, ':').collect();
    if parts.len() == 2 {
        let port = parts[0].parse::<u16>().ok()?;
        Some((parts[1].to_string(), port))
    } else {
        None
    }
}

fn extract_pg_version_from_error(_stderr: &str) -> Option<String> {
    None // Version extraction from errors is unreliable; pg_isready is better
}

fn extract_mysql_version(banner: &str) -> Option<String> {
    let bytes = banner.as_bytes();
    let mut version = String::new();
    let mut found_start = false;

    for &b in bytes {
        if b.is_ascii_digit() || (found_start && (b == b'.' || b == b'-')) {
            found_start = true;
            version.push(b as char);
        } else if found_start && version.contains('.') {
            break;
        } else if found_start {
            version.clear();
            found_start = false;
        }
    }

    if version.contains('.') && version.len() >= 3 {
        Some(version)
    } else {
        None
    }
}
