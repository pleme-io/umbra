use crate::cmd;
use crate::probe;
use serde::Serialize;
use umbra_core::assessment::{DatabaseType, MqType, ServiceType, ServiceTypeResult};

#[derive(Serialize)]
struct ProbeReport {
    results: Vec<ServiceTypeResult>,
    total: usize,
    timestamp: String,
}

/// Detect the service type of a single target.
pub async fn detect(target: &str) -> String {
    let (host, port) = match parse_target(target) {
        Some(hp) => hp,
        None => {
            return serde_json::json!({
                "error": format!("Invalid target '{target}'. Use 'host:port' format.")
            })
            .to_string()
        }
    };

    let result = probe_service("", &host, port).await;
    serde_json::to_string_pretty(&result).unwrap()
}

/// Detect types for all discovered services.
pub async fn detect_all() -> String {
    let services = umbra_core::services::discover_services();
    let mut results = Vec::new();

    for svc in &services {
        let result = probe_service(&svc.name, &svc.host, svc.port).await;
        results.push(result);
    }

    let total = results.len();
    serde_json::to_string_pretty(&ProbeReport {
        results,
        total,
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
    .unwrap()
}

async fn probe_service(name: &str, host: &str, port: u16) -> ServiceTypeResult {
    let mut evidence = Vec::new();
    let mut service_type = ServiceType::Unknown;
    let mut confidence: f32 = 0.0;
    let mut tls = false;
    let mut http_status = None;
    let mut server_header = None;

    // Step 1: TCP connect
    let tcp = probe::tcp::connect(host, port).await;
    if !tcp.success {
        return ServiceTypeResult {
            name: name.to_string(),
            host: host.to_string(),
            port,
            service_type: ServiceType::Unknown,
            confidence: 0.0,
            evidence: vec!["TCP connection failed".into()],
            tls: false,
            reachable: false,
            latency_ms: None,
            http_status: None,
            server_header: None,
        };
    }

    let latency_ms = Some(tcp.latency_ms);
    evidence.push(format!("TCP connect OK ({}ms)", tcp.latency_ms));

    // Step 2: Well-known port detection
    if let Some((st, db_evidence)) = detect_by_port(port) {
        service_type = st;
        confidence = 0.6;
        evidence.push(db_evidence);
    }

    // Step 3: Try gRPC reflection (fast, fails quickly if not gRPC)
    if matches!(service_type, ServiceType::Unknown) || matches!(service_type, ServiceType::Rest) {
        if let Some(grpc_evidence) = try_grpc(host, port).await {
            service_type = ServiceType::Grpc;
            confidence = 0.95;
            evidence.push(grpc_evidence);
            return ServiceTypeResult {
                name: name.to_string(),
                host: host.to_string(),
                port,
                service_type,
                confidence,
                evidence,
                tls,
                reachable: true,
                latency_ms,
                http_status,
                server_header,
            };
        }
    }

    // Step 4: Try HTTP probing (GraphQL, REST, WebSocket, static)
    if matches!(service_type, ServiceType::Unknown) || confidence < 0.8 {
        let http_result = try_http(host, port).await;
        http_status = http_result.status_code;
        server_header = http_result.server.clone();
        tls = http_result.tls;

        if let Some(ref server) = http_result.server {
            evidence.push(format!("Server: {server}"));
        }

        if http_result.is_graphql {
            service_type = ServiceType::GraphQL;
            confidence = 0.95;
            evidence.push("GraphQL introspection succeeded".into());
        } else if http_result.has_websocket {
            service_type = ServiceType::WebSocket;
            confidence = 0.85;
            evidence.push("WebSocket upgrade supported".into());
        } else if http_result.is_http {
            if http_result.is_static {
                service_type = ServiceType::StaticFiles;
                confidence = 0.7;
                evidence.push("Static file server detected".into());
            } else if matches!(service_type, ServiceType::Unknown) {
                service_type = ServiceType::Rest;
                confidence = 0.7;
                evidence.push(format!(
                    "HTTP {} ({})",
                    http_result.status_code.unwrap_or(0),
                    http_result.content_type.unwrap_or_default()
                ));
            }
        }
    }

    // Step 5: Verify database detection with protocol probe
    if let ServiceType::Database(ref db_type) = service_type {
        if let Some(db_evidence) = verify_database(host, port, db_type).await {
            confidence = 0.95;
            evidence.push(db_evidence);
        }
    }

    ServiceTypeResult {
        name: name.to_string(),
        host: host.to_string(),
        port,
        service_type,
        confidence,
        evidence,
        tls,
        reachable: true,
        latency_ms,
        http_status,
        server_header,
    }
}

fn detect_by_port(port: u16) -> Option<(ServiceType, String)> {
    match port {
        5432 => Some((
            ServiceType::Database(DatabaseType::PostgreSQL),
            "Port 5432 → PostgreSQL".into(),
        )),
        6379 => Some((
            ServiceType::Database(DatabaseType::Redis),
            "Port 6379 → Redis".into(),
        )),
        3306 => Some((
            ServiceType::Database(DatabaseType::MySQL),
            "Port 3306 → MySQL".into(),
        )),
        27017 => Some((
            ServiceType::Database(DatabaseType::MongoDB),
            "Port 27017 → MongoDB".into(),
        )),
        9092 => Some((
            ServiceType::MessageQueue(MqType::Kafka),
            "Port 9092 → Kafka".into(),
        )),
        4222 => Some((
            ServiceType::MessageQueue(MqType::Nats),
            "Port 4222 → NATS".into(),
        )),
        5672 => Some((
            ServiceType::MessageQueue(MqType::RabbitMQ),
            "Port 5672 → RabbitMQ".into(),
        )),
        _ => None,
    }
}

async fn try_grpc(host: &str, port: u16) -> Option<String> {
    let target = format!("{host}:{port}");
    let result = cmd::run("grpcurl", &["-plaintext", &target, "list"], 5).await;
    if result.success && !result.stdout.trim().is_empty() {
        let services: Vec<&str> = result.stdout.lines().take(5).collect();
        Some(format!("gRPC services: {}", services.join(", ")))
    } else {
        None
    }
}

struct HttpProbeResult {
    is_http: bool,
    is_graphql: bool,
    has_websocket: bool,
    is_static: bool,
    tls: bool,
    status_code: Option<u16>,
    content_type: Option<String>,
    server: Option<String>,
}

async fn try_http(host: &str, port: u16) -> HttpProbeResult {
    let mut result = HttpProbeResult {
        is_http: false,
        is_graphql: false,
        has_websocket: false,
        is_static: false,
        tls: false,
        status_code: None,
        content_type: None,
        server: None,
    };

    let base_url = format!("http://{host}:{port}");

    // Try basic HTTP GET
    let http = cmd::run(
        "curl",
        &[
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}\\n%{content_type}\\n%{scheme}",
            "-m",
            "3",
            "-H",
            "User-Agent: umbra-agent/0.1",
            &base_url,
        ],
        5,
    )
    .await;

    if http.success {
        let lines: Vec<&str> = http.stdout.lines().collect();
        if let Some(code) = lines.first().and_then(|s| s.parse::<u16>().ok()) {
            if code > 0 {
                result.is_http = true;
                result.status_code = Some(code);
            }
        }
        result.content_type = lines.get(1).map(|s| s.to_string()).filter(|s| !s.is_empty());
        if let Some(scheme) = lines.get(2) {
            result.tls = *scheme == "HTTPS";
        }
    }

    // Try to get Server header
    let headers = cmd::run(
        "curl",
        &["-s", "-I", "-m", "3", &base_url],
        5,
    )
    .await;

    if headers.success {
        for line in headers.stdout.lines() {
            let lower = line.to_lowercase();
            if lower.starts_with("server:") {
                result.server = Some(line.trim_start_matches(|c: char| !c.is_whitespace() || c == ':')
                    .trim_start_matches(':')
                    .trim()
                    .to_string());
            }
            // Check for WebSocket support in Upgrade header
            if lower.starts_with("upgrade:") && lower.contains("websocket") {
                result.has_websocket = true;
            }
        }
    }

    // Try GraphQL introspection
    if result.is_http {
        for path in &["/graphql", "/api/graphql", "/query"] {
            let url = format!("{base_url}{path}");
            let gql = cmd::run_with_stdin(
                "curl",
                &[
                    "-s",
                    "-X",
                    "POST",
                    "-H",
                    "Content-Type: application/json",
                    "-m",
                    "3",
                    &url,
                ],
                r#"{"query":"{ __typename }"}"#,
                5,
            )
            .await;

            if gql.success {
                let body = gql.stdout.trim();
                if body.contains("__typename") || body.contains("\"data\"") {
                    result.is_graphql = true;
                    break;
                }
            }
        }
    }

    // Check if it looks like a static file server
    if result.is_http && !result.is_graphql {
        if let Some(ref ct) = result.content_type {
            if ct.contains("text/html") || ct.contains("text/plain") {
                // Check if it serves an index page with static assets
                let body = cmd::run(
                    "curl",
                    &["-s", "-m", "3", &base_url],
                    5,
                )
                .await;
                if body.success
                    && (body.stdout.contains("<script") || body.stdout.contains(".css"))
                    && !body.stdout.contains("\"errors\"")
                {
                    result.is_static = true;
                }
            }
        }
    }

    result
}

async fn verify_database(host: &str, port: u16, db_type: &DatabaseType) -> Option<String> {
    match db_type {
        DatabaseType::Redis => {
            let result = cmd::run(
                "redis-cli",
                &["-h", host, "-p", &port.to_string(), "PING"],
                3,
            )
            .await;
            if result.success && result.stdout.trim() == "PONG" {
                Some("Redis PING → PONG".into())
            } else {
                None
            }
        }
        DatabaseType::PostgreSQL => {
            // Try pg_isready
            let result = cmd::run(
                "pg_isready",
                &["-h", host, "-p", &port.to_string(), "-t", "2"],
                5,
            )
            .await;
            if result.success {
                Some("pg_isready → accepting connections".into())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn parse_target(target: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = target.rsplitn(2, ':').collect();
    if parts.len() == 2 {
        let port = parts[0].parse::<u16>().ok()?;
        let host = parts[1].to_string();
        Some((host, port))
    } else {
        None
    }
}
