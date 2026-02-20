mod cmd;
mod probe;
mod tools;

use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
};
use serde::Deserialize;
use umbra_core::targets::{ServiceCredentials, TargetConfig};

// --- Tool input types ---

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CheckInput {
    #[schemars(description = "Service to check: 'host:port', service name, or DNS name")]
    target: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DnsLookupInput {
    #[schemars(description = "Hostname or domain to query")]
    name: String,
    #[schemars(description = "Record type: A, AAAA, SRV, CNAME, MX, TXT, NS, SOA, PTR (default: A)")]
    record_type: Option<String>,
    #[schemars(description = "DNS server to query (e.g. '8.8.8.8'). Uses system default if omitted")]
    server: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct TraceRouteInput {
    #[schemars(description = "Target host or IP to trace")]
    target: String,
    #[schemars(description = "Maximum number of hops (default: 20)")]
    max_hops: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct PortScanInput {
    #[schemars(description = "Target host or IP to scan")]
    target: String,
    #[schemars(description = "Ports to scan: '80,443', '1-1024', or omit for top 100")]
    ports: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SocketListInput {
    #[schemars(description = "Filter: 'listening', 'established', or 'all' (default: all)")]
    filter: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct HttpRequestInput {
    #[schemars(description = "URL to request")]
    url: String,
    #[schemars(description = "HTTP method: GET, POST, PUT, DELETE, PATCH, HEAD (default: GET)")]
    method: Option<String>,
    #[schemars(description = "Request headers as 'Key: Value' strings")]
    headers: Option<Vec<String>>,
    #[schemars(description = "Request body")]
    body: Option<String>,
    #[schemars(description = "Follow redirects (default: true)")]
    follow_redirects: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct PsqlQueryInput {
    #[schemars(description = "PostgreSQL connection string (e.g. 'postgresql://user:pass@host:5432/db')")]
    connection_string: String,
    #[schemars(description = "SQL query to execute")]
    query: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RedisCmdInput {
    #[schemars(description = "Redis host")]
    host: String,
    #[schemars(description = "Redis port (default: 6379)")]
    port: Option<u16>,
    #[schemars(description = "Redis password")]
    password: Option<String>,
    #[schemars(description = "Redis command (e.g. 'GET mykey', 'INFO memory', 'KEYS user:*')")]
    command: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct OpenFilesInput {
    #[schemars(description = "Filter by PID")]
    pid: Option<u32>,
    #[schemars(description = "Filter type: 'network', 'file', or 'all' (default: all)")]
    filter: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct PacketCaptureInput {
    #[schemars(description = "Network interface (default: any)")]
    interface: Option<String>,
    #[schemars(description = "BPF filter expression (e.g. 'tcp port 80', 'host 10.0.0.1')")]
    filter: Option<String>,
    #[schemars(description = "Capture duration in seconds (default: 5, max: 30)")]
    duration_secs: Option<u64>,
    #[schemars(description = "Max packets to capture (default: 50, max: 200)")]
    max_packets: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SyscallTraceInput {
    #[schemars(description = "PID of process to trace")]
    pid: u32,
    #[schemars(description = "Trace duration in seconds (default: 5, max: 30)")]
    duration_secs: Option<u64>,
    #[schemars(description = "Syscall filter (e.g. 'read,write', 'network', 'file')")]
    syscall_filter: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct FilesystemInput {
    #[schemars(description = "File or directory path")]
    path: String,
    #[schemars(description = "Operation: 'ls' (list directory), 'cat' (read file), 'stat' (file metadata)")]
    operation: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct GrpcCallInput {
    #[schemars(description = "gRPC target (host:port)")]
    target: String,
    #[schemars(description = "Service name (e.g. 'grpc.health.v1.Health')")]
    service: String,
    #[schemars(description = "Method name (e.g. 'Check')")]
    method: String,
    #[schemars(description = "Request data as JSON")]
    data: Option<String>,
    #[schemars(description = "Use plaintext (no TLS). Default: true")]
    plaintext: Option<bool>,
    #[schemars(description = "Request headers")]
    headers: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WebsocketInput {
    #[schemars(description = "WebSocket URL (ws:// or wss://)")]
    url: String,
    #[schemars(description = "Message to send. If omitted, just listens")]
    message: Option<String>,
    #[schemars(description = "Timeout in seconds (default: 5, max: 30)")]
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct BandwidthInput {
    #[schemars(description = "iperf3 server target (host:port or host)")]
    target: String,
    #[schemars(description = "Test duration in seconds (default: 5, max: 30)")]
    duration: Option<u64>,
    #[schemars(description = "Test download instead of upload")]
    reverse: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct NamespacesInput {
    #[schemars(description = "Filter by PID")]
    pid: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DetectServiceTypeInput {
    #[schemars(description = "Target to detect: 'host:port' format")]
    target: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct PostgresHealthInput {
    #[schemars(description = "Target: 'host:port', connection string, or omit for auto-discovery from env")]
    target: Option<String>,
    #[schemars(description = "PostgreSQL user")]
    user: Option<String>,
    #[schemars(description = "PostgreSQL password")]
    password: Option<String>,
    #[schemars(description = "Database name")]
    database: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct MysqlHealthInput {
    #[schemars(description = "Target: 'host:port' or omit for auto-discovery from env")]
    target: Option<String>,
    #[schemars(description = "MySQL user")]
    user: Option<String>,
    #[schemars(description = "MySQL password")]
    password: Option<String>,
    #[schemars(description = "Database name")]
    database: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RedisHealthInput {
    #[schemars(description = "Target: 'host:port' or omit for auto-discovery from env")]
    target: Option<String>,
    #[schemars(description = "Redis password")]
    password: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct HaproxyStatsInput {
    #[schemars(description = "Stats URL or 'host:port'. Defaults to http://localhost:8404/stats")]
    target: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct NginxStatusInput {
    #[schemars(description = "Status URL or 'host:port'. Defaults to http://localhost/nginx_status")]
    target: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CertificateCheckInput {
    #[schemars(description = "TLS targets as 'host:port'. Omit to auto-discover from K8s services on 443/8443/6443")]
    targets: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ServiceDeepProbeInput {
    #[schemars(
        description = "Pre-configured targets with credentials. Each target has host, port, optional type, and optional credentials (user, password, database, connection_string). When provided, these targets are probed with given credentials in addition to auto-discovered services. Dynamic targets from K8s secret discovery go here."
    )]
    targets: Option<Vec<TargetConfig>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DeepProbeTargetInput {
    #[schemars(description = "Target: 'host:port' format")]
    target: String,
    #[schemars(description = "Force service type: 'postgres', 'mysql', 'redis', 'nginx', 'haproxy'. Auto-detected if omitted")]
    service_type: Option<String>,
    #[schemars(description = "Credentials for authenticated probing")]
    credentials: Option<ServiceCredentials>,
}

// --- Security scanning tool inputs (Tier 4) ---

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct FastScanInput {
    #[schemars(description = "Target host or IP to scan")]
    target: String,
    #[schemars(description = "Ports to scan: '80,443', '1-1024', or omit for all ports")]
    ports: Option<String>,
    #[schemars(description = "Timeout in seconds (default: 30)")]
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WebDiscoverInput {
    #[schemars(description = "Target URL (e.g. 'http://target:8080')")]
    target: String,
    #[schemars(description = "Path to wordlist file")]
    wordlist: Option<String>,
    #[schemars(description = "File extensions to probe (e.g. 'php,html,js')")]
    extensions: Option<String>,
    #[schemars(description = "Recursion depth (default: 2, max: 5)")]
    depth: Option<u32>,
    #[schemars(description = "Timeout in seconds (default: 60)")]
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct TlsAuditInput {
    #[schemars(description = "Target: 'host:port' format (e.g. 'example.com:443')")]
    target: String,
    #[schemars(description = "Timeout in seconds (default: 90)")]
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct VulnScanInput {
    #[schemars(description = "Target URL or host (e.g. 'http://target:8080')")]
    target: String,
    #[schemars(description = "Nuclei template path or tag filter")]
    templates: Option<String>,
    #[schemars(description = "Minimum severity: 'info', 'low', 'medium', 'high', 'critical'")]
    severity: Option<String>,
    #[schemars(description = "Requests per second rate limit (default: 50)")]
    rate_limit: Option<u32>,
    #[schemars(description = "Timeout in seconds (default: 120)")]
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SecretScanInput {
    #[schemars(description = "Filesystem path to scan (default: '/')")]
    path: Option<String>,
    #[schemars(description = "Timeout in seconds (default: 60)")]
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct JwtDecodeInput {
    #[schemars(
        description = "JWT token to decode. If omitted, auto-discovers the Kubernetes service account token"
    )]
    token: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct LoadTestInput {
    #[schemars(description = "Target URL to load test")]
    target: String,
    #[schemars(description = "Number of concurrent connections (default: 5, max: 50)")]
    concurrency: Option<u32>,
    #[schemars(description = "Test duration in seconds (default: 10, max: 60)")]
    duration_secs: Option<u64>,
    #[schemars(description = "Total number of requests (overrides duration)")]
    requests: Option<u64>,
    #[schemars(description = "HTTP method (default: GET)")]
    method: Option<String>,
    #[schemars(description = "Timeout in seconds (default: 65)")]
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct AuthTestInput {
    #[schemars(description = "Target: 'host:port' format")]
    target: String,
    #[schemars(
        description = "Protocol: 'http', 'ssh', 'ftp', 'smtp', 'mysql', 'postgres', etc. (default: http)"
    )]
    protocol: Option<String>,
    #[schemars(description = "Username or path to username wordlist")]
    usernames: Option<String>,
    #[schemars(description = "Password or path to password wordlist")]
    passwords: Option<String>,
    #[schemars(description = "Requests per second rate limit (default: 10, max: 50)")]
    rate: Option<u32>,
    #[schemars(description = "Timeout in seconds (default: 60)")]
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ContainerAuditInput {
    #[schemars(description = "Filesystem path to scan for CVEs (default: '/')")]
    path: Option<String>,
    #[schemars(description = "Minimum severity: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'")]
    severity: Option<String>,
    #[schemars(description = "Timeout in seconds (default: 90)")]
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct HttpProbeInput {
    #[schemars(description = "List of URLs or host:port targets to probe")]
    targets: Vec<String>,
    #[schemars(description = "Timeout in seconds (default: 30)")]
    timeout_secs: Option<u64>,
}

// --- MCP Server ---

#[derive(Debug, Clone)]
struct UmbraAgent {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl UmbraAgent {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    // === Core diagnostics (Tier 0 — native Rust) ===

    #[tool(description = "List K8s environment variables grouped by category (service_discovery, kubernetes, container, application, other). Returns structured EnvReport.")]
    async fn env(&self) -> String {
        tools::env::gather_env()
    }

    #[tool(description = "Parse Kubernetes service discovery env vars (*_SERVICE_HOST/*_PORT) into structured service list.")]
    async fn services(&self) -> String {
        tools::services::list_services()
    }

    #[tool(description = "Full pod diagnostic: identity, DNS, API server, service reachability, network interfaces. Returns comprehensive DiagnosticReport.")]
    async fn diagnose(&self) -> String {
        tools::diagnose::run_diagnostics().await
    }

    #[tool(description = "Test connectivity to a service with DNS, TCP, and HTTP probes. Accepts 'host:port', service name, or DNS name.")]
    async fn check(&self, Parameters(input): Parameters<CheckInput>) -> String {
        tools::check::check_service(&input.target).await
    }

    // === Network analysis (Tier 1 — wraps dig, mtr, nmap, ss) ===

    #[tool(description = "DNS lookup with record type selection. Supports A, AAAA, SRV, CNAME, MX, TXT, NS, SOA, PTR. Uses dig for detailed results including TTL and authority.")]
    async fn dns_lookup(&self, Parameters(input): Parameters<DnsLookupInput>) -> String {
        tools::dns_lookup::lookup(
            &input.name,
            input.record_type.as_deref(),
            input.server.as_deref(),
        )
        .await
    }

    #[tool(description = "Network path analysis from pod to target. Shows each hop with latency, loss, and AS info. Uses mtr for combined traceroute + ping.")]
    async fn trace_route(&self, Parameters(input): Parameters<TraceRouteInput>) -> String {
        tools::trace_route::trace(&input.target, input.max_hops).await
    }

    #[tool(description = "Port scan a target host. Shows open ports with service detection. Useful for debugging network policies and firewall rules.")]
    async fn port_scan(&self, Parameters(input): Parameters<PortScanInput>) -> String {
        tools::port_scan::scan(&input.target, input.ports.as_deref()).await
    }

    #[tool(description = "List active TCP/UDP sockets. Shows listening ports, established connections, and associated processes. Filter by state.")]
    async fn socket_list(&self, Parameters(input): Parameters<SocketListInput>) -> String {
        tools::socket_list::list(input.filter.as_deref()).await
    }

    // === Process debugging (Tier 1 — /proc + CLI wrappers) ===

    #[tool(description = "List running processes with PID, CPU%, memory, threads, and command line. Reads directly from /proc for accuracy.")]
    async fn process_list(&self) -> String {
        tools::process_list::list().await
    }

    // === HTTP/API testing (Tier 1 — wraps curl) ===

    #[tool(description = "Make an HTTP request from the pod's network. Full control over method, headers, body. Returns status, response headers, body, and timing breakdown (DNS, connect, TLS, TTFB).")]
    async fn http_request(&self, Parameters(input): Parameters<HttpRequestInput>) -> String {
        tools::http_request::request(
            &input.url,
            input.method.as_deref(),
            input.headers.as_deref(),
            input.body.as_deref(),
            input.follow_redirects.unwrap_or(true),
        )
        .await
    }

    // === Database clients (Tier 1 — wraps psql, redis-cli) ===

    #[tool(description = "Execute a PostgreSQL query from the pod. Returns results as JSON. Supports SELECT (returns rows), INSERT/UPDATE/DELETE (returns affected count), and DDL.")]
    async fn psql_query(&self, Parameters(input): Parameters<PsqlQueryInput>) -> String {
        tools::psql_query::query(&input.connection_string, &input.query).await
    }

    #[tool(description = "Execute a Redis command from the pod. Supports all Redis commands: GET, SET, KEYS, INFO, PING, etc. Returns parsed response.")]
    async fn redis_cmd(&self, Parameters(input): Parameters<RedisCmdInput>) -> String {
        tools::redis_cmd::execute(
            &input.host,
            input.port.unwrap_or(6379),
            input.password.as_deref(),
            &input.command,
        )
        .await
    }

    // === Deep debugging (Tier 2 — wraps lsof, tcpdump, strace) ===

    #[tool(description = "List open files and sockets. Filter by PID or type (network/file). Shows file descriptors, types, and names. Useful for debugging connection leaks.")]
    async fn open_files(&self, Parameters(input): Parameters<OpenFilesInput>) -> String {
        tools::open_files::list(input.pid, input.filter.as_deref()).await
    }

    #[tool(description = "Capture network packets with BPF filter. Time-limited and packet-count-limited for safety. Returns packet summaries. Requires NET_ADMIN capability.")]
    async fn packet_capture(&self, Parameters(input): Parameters<PacketCaptureInput>) -> String {
        tools::packet_capture::capture(
            input.interface.as_deref(),
            input.filter.as_deref(),
            input.duration_secs,
            input.max_packets,
        )
        .await
    }

    #[tool(description = "Trace system calls of a running process. Returns syscall summary with call counts and time distribution. Requires SYS_PTRACE capability.")]
    async fn syscall_trace(&self, Parameters(input): Parameters<SyscallTraceInput>) -> String {
        tools::syscall_trace::trace(
            input.pid,
            input.duration_secs,
            input.syscall_filter.as_deref(),
        )
        .await
    }

    // === Filesystem inspection (Tier 2 — native Rust) ===

    #[tool(description = "Inspect filesystem: list directories (ls), read files (cat), or get metadata (stat). Useful for checking mounted secrets, configs, and volume contents.")]
    async fn filesystem(&self, Parameters(input): Parameters<FilesystemInput>) -> String {
        tools::filesystem::inspect(&input.path, &input.operation)
    }

    // === gRPC/WebSocket (Tier 2 — wraps grpcurl, websocat) ===

    #[tool(description = "Make a gRPC call from the pod. Supports unary RPCs with JSON request/response. Useful for debugging service mesh and gRPC federation.")]
    async fn grpc_call(&self, Parameters(input): Parameters<GrpcCallInput>) -> String {
        tools::grpc_call::call(
            &input.target,
            &input.service,
            &input.method,
            input.data.as_deref(),
            input.plaintext.unwrap_or(true),
            input.headers.as_deref(),
        )
        .await
    }

    #[tool(description = "Connect to a WebSocket endpoint. Optionally send a message and receive response. Useful for debugging real-time connections.")]
    async fn websocket(&self, Parameters(input): Parameters<WebsocketInput>) -> String {
        tools::websocket::connect(
            &input.url,
            input.message.as_deref(),
            input.timeout_secs,
        )
        .await
    }

    // === Performance (Tier 2 — wraps iperf3) ===

    #[tool(description = "Test network bandwidth between pod and an iperf3 server. Measures throughput, jitter, and packet loss. Requires an iperf3 server at target.")]
    async fn bandwidth(&self, Parameters(input): Parameters<BandwidthInput>) -> String {
        tools::bandwidth::test(
            &input.target,
            input.duration,
            input.reverse.unwrap_or(false),
        )
        .await
    }

    // === Linux namespaces (Tier 2 — wraps lsns) ===

    #[tool(description = "List Linux namespaces (mount, UTS, IPC, PID, net, user, cgroup). Shows namespace type, owning PID, and command. Useful for debugging container isolation.")]
    async fn namespaces(&self, Parameters(input): Parameters<NamespacesInput>) -> String {
        tools::namespaces::list(input.pid).await
    }

    // === Assessment tools (Tier 3 — evaluations + audits) ===

    #[tool(description = "Detect the service type of a target (REST, GraphQL, gRPC, WebSocket, Database, MessageQueue). Probes TCP, HTTP, gRPC reflection, GraphQL introspection, and well-known ports. Returns type with confidence score and evidence.")]
    async fn detect_service_type(
        &self,
        Parameters(input): Parameters<DetectServiceTypeInput>,
    ) -> String {
        tools::detect_service_type::detect(&input.target).await
    }

    #[tool(description = "Detect service types for ALL discovered Kubernetes services. Probes each service for type classification. Returns full report with per-service type, confidence, and evidence.")]
    async fn detect_all_service_types(&self) -> String {
        tools::detect_service_type::detect_all().await
    }

    #[tool(description = "Security audit of the pod environment. Checks: secret exposure in env vars, root user, service account RBAC scope, writable sensitive paths, Linux capabilities, TLS coverage, host mounts. Returns findings with severity (critical/high/medium/low/info) and remediation advice.")]
    async fn security_audit(&self) -> String {
        tools::security_audit::audit().await
    }

    #[tool(description = "Build a network map from this pod's perspective. Discovers all services, probes each for type and reachability, produces a topology map with service types, TLS status, and latencies.")]
    async fn network_map(&self) -> String {
        tools::network_map::map().await
    }

    // === Service deep probe (Tier 3 — auto-discovery + credential-less recon + health) ===

    #[tool(description = "Deep probe ALL discovered services. For each service: (1) unauthenticated recon — banner grab, version extraction from errors/headers, anonymous access test, (2) credentialed health check if credentials are provided, env vars supply them, or anonymous access works, (3) security findings — reports unauthenticated access, version disclosure, missing TLS. Pass 'targets' with credentials discovered from K8s secrets (via kubectl/kubernetes MCP) for authenticated deep probing. Called automatically during assessment.")]
    async fn service_deep_probe(
        &self,
        Parameters(input): Parameters<ServiceDeepProbeInput>,
    ) -> String {
        tools::service_deep_probe::probe_all(input.targets).await
    }

    #[tool(description = "Deep probe a SINGLE target. Runs unauthenticated recon (banner, version, anonymous access test) then credentialed health check if credentials are provided or anonymous access works. Pass credentials for authenticated probing. Force service type with service_type param or let it auto-detect from port.")]
    async fn deep_probe_target(
        &self,
        Parameters(input): Parameters<DeepProbeTargetInput>,
    ) -> String {
        tools::service_deep_probe::probe_target(
            &input.target,
            input.service_type.as_deref(),
            input.credentials,
        )
        .await
    }

    // === Deep health checks (Tier 3 — database/service deep diagnostics) ===

    #[tool(description = "Comprehensive PostgreSQL health check. Runs 10 parallel diagnostic queries: version, connection states, max_connections, replication lag, lock contention (blocked + blocking queries), long-running queries (>5s), cache hit ratio, database sizes, table health (dead tuples, vacuum stats, seq/idx scans), and key pg_settings. Auto-discovers from DATABASE_URL, PGHOST, or K8s service env vars.")]
    async fn postgres_health(
        &self,
        Parameters(input): Parameters<PostgresHealthInput>,
    ) -> String {
        tools::postgres_health::check(
            input.target.as_deref(),
            input.user.as_deref(),
            input.password.as_deref(),
            input.database.as_deref(),
        )
        .await
    }

    #[tool(description = "Comprehensive MySQL health check. Runs 12 parallel diagnostic queries: version, thread stats, max_connections, max_used_connections, aborted client/connect stats, replica status, InnoDB buffer pool hit ratio, InnoDB lock stats (deadlocks, row_lock_waits), database sizes, lock waits, active processlist, and key global variables. Auto-discovers from MYSQL_HOST or K8s service env vars.")]
    async fn mysql_health(
        &self,
        Parameters(input): Parameters<MysqlHealthInput>,
    ) -> String {
        tools::mysql_health::check(
            input.target.as_deref(),
            input.user.as_deref(),
            input.password.as_deref(),
            input.database.as_deref(),
        )
        .await
    }

    #[tool(description = "Comprehensive Redis health check. Collects INFO ALL (version, memory, clients, persistence, replication, keyspace stats), SLOWLOG entries, CONFIG warnings (noeviction, no persistence, no timeout, no auth). Reports memory fragmentation, hit rate, ops/sec, blocked clients, and replication topology.")]
    async fn redis_health(
        &self,
        Parameters(input): Parameters<RedisHealthInput>,
    ) -> String {
        tools::redis_health::check(
            input.target.as_deref(),
            input.password.as_deref(),
        )
        .await
    }

    #[tool(description = "HAProxy health check via stats CSV endpoint or Unix socket. Reports frontends (session rates, denied requests), backends (queue depth, active/backup servers, connect/response times, error rates), individual servers (status, health checks, downtime, weight). Warns on down servers, queued connections, and backends with no active servers.")]
    async fn haproxy_stats(
        &self,
        Parameters(input): Parameters<HaproxyStatsInput>,
    ) -> String {
        tools::haproxy_stats::check(input.target.as_deref()).await
    }

    #[tool(description = "Nginx health check. Reads stub_status (active connections, accepts, handled, requests, reading/writing/waiting), parses full config (worker_processes, upstreams, server blocks, SSL, gzip), lists nginx processes with CPU/memory, and tails error/access logs. Warns on dropped connections and high wait ratios.")]
    async fn nginx_status(
        &self,
        Parameters(input): Parameters<NginxStatusInput>,
    ) -> String {
        tools::nginx_status::check(input.target.as_deref()).await
    }

    // === System resource monitoring (Tier 3) ===

    #[tool(description = "Container resource usage. Reports CPU (quota, available cores), memory (total, used, available from /proc/meminfo), cgroup limits (v1/v2: memory limit/usage/peak, CPU quota/period/shares, PID limits), load average, top 10 processes by memory, and OOM kill detection. Essential for diagnosing resource pressure and throttling.")]
    async fn resource_usage(&self) -> String {
        tools::resource_usage::check().await
    }

    #[tool(description = "Disk and filesystem health. Reports filesystem usage (size, used, available, inode usage), mount details (readonly, tmpfs, secrets, configmaps), disk I/O stats from /proc/diskstats, and sizes of /tmp, /var/log, /var/lib, /data. Warns on >90% disk/inode usage.")]
    async fn disk_usage(&self) -> String {
        tools::disk_usage::check().await
    }

    #[tool(description = "TLS certificate health check. Uses openssl s_client to inspect certificates: subject, issuer, SANs, expiry (days until), key type/size, signature algorithm, chain depth, TLS version, cipher, OCSP stapling. Auto-discovers TLS services from K8s env vars on ports 443/8443/6443. Warns on expiring/expired certificates.")]
    async fn certificate_check(
        &self,
        Parameters(input): Parameters<CertificateCheckInput>,
    ) -> String {
        let targets = input.targets.unwrap_or_default();
        tools::certificate_check::check(&targets).await
    }

    // === Security scanning (Tier 4 — wraps rustscan, feroxbuster, testssl, nuclei, etc.) ===

    #[tool(description = "Fast all-ports discovery (~3s with rustscan, nmap fallback). Finds open TCP ports on a target host. Use as the first step in security assessment to identify attack surface.")]
    async fn fast_scan(&self, Parameters(input): Parameters<FastScanInput>) -> String {
        tools::fast_scan::scan(&input.target, input.ports.as_deref(), input.timeout_secs).await
    }

    #[tool(description = "Recursive web content/endpoint discovery using feroxbuster. Finds hidden directories, files, and API endpoints. Use after port scanning to enumerate web application attack surface.")]
    async fn web_discover(&self, Parameters(input): Parameters<WebDiscoverInput>) -> String {
        tools::web_discover::discover(
            &input.target,
            input.wordlist.as_deref(),
            input.extensions.as_deref(),
            input.depth,
            input.timeout_secs,
        )
        .await
    }

    #[tool(description = "Deep TLS/SSL vulnerability analysis using testssl.sh. Checks for BEAST, POODLE, Heartbleed, DROWN, FREAK, LOGJAM, ROBOT, SWEET32, and more. Reports protocol support, cipher suites, and certificate details.")]
    async fn tls_audit(&self, Parameters(input): Parameters<TlsAuditInput>) -> String {
        tools::tls_audit::audit(&input.target, input.timeout_secs).await
    }

    #[tool(description = "Template-based vulnerability scanning using nuclei (9000+ templates). Scans for CVEs, misconfigurations, exposed panels, default credentials, and more. Configurable severity filter and rate limiting.")]
    async fn vuln_scan(&self, Parameters(input): Parameters<VulnScanInput>) -> String {
        tools::vuln_scan::scan(
            &input.target,
            input.templates.as_deref(),
            input.severity.as_deref(),
            input.rate_limit,
            input.timeout_secs,
        )
        .await
    }

    #[tool(description = "Secret and credential detection in container filesystem using noseyparker. Scans for API keys, passwords, tokens, private keys, and other sensitive data in files. Masks found secrets in output.")]
    async fn secret_scan(&self, Parameters(input): Parameters<SecretScanInput>) -> String {
        tools::secret_scan::scan(input.path.as_deref(), input.timeout_secs).await
    }

    #[tool(description = "JWT token analysis and decoding. Auto-discovers Kubernetes service account tokens if no token provided. Shows header, payload, expiry status, and remaining validity. Falls back to manual base64 decode if jwt-cli is not installed.")]
    async fn jwt_decode(&self, Parameters(input): Parameters<JwtDecodeInput>) -> String {
        tools::jwt_decode::decode(input.token.as_deref()).await
    }

    #[tool(description = "HTTP load/performance testing using oha. Measures throughput (req/s), latency percentiles (p50/p90/p99), and status code distribution. Conservative defaults (5 concurrent, 10s duration) to avoid disruption.")]
    async fn load_test(&self, Parameters(input): Parameters<LoadTestInput>) -> String {
        tools::load_test::test(
            &input.target,
            input.concurrency,
            input.duration_secs,
            input.requests,
            input.method.as_deref(),
            input.timeout_secs,
        )
        .await
    }

    #[tool(description = "Multi-protocol credential testing using legba (20+ protocols: HTTP, SSH, FTP, SMTP, MySQL, PostgreSQL, etc.). FOR AUTHORIZED SECURITY TESTING ONLY — use in pentesting engagements, CTF competitions, or with explicit authorization. Conservative rate limiting (default: 10 req/s).")]
    async fn auth_test(&self, Parameters(input): Parameters<AuthTestInput>) -> String {
        tools::auth_test::test(
            &input.target,
            input.protocol.as_deref(),
            input.usernames.as_deref(),
            input.passwords.as_deref(),
            input.rate,
            input.timeout_secs,
        )
        .await
    }

    #[tool(description = "Container filesystem CVE scanning using trivy. Detects known vulnerabilities in installed packages and libraries. Reports CVE IDs, affected packages, installed/fixed versions, and severity. DB is embedded at build time (--skip-db-update).")]
    async fn container_audit(
        &self,
        Parameters(input): Parameters<ContainerAuditInput>,
    ) -> String {
        tools::container_audit::audit(
            input.path.as_deref(),
            input.severity.as_deref(),
            input.timeout_secs,
        )
        .await
    }

    #[tool(description = "Multi-URL HTTP technology fingerprinting using httpx. Probes targets for status codes, web server, technology stack, page titles, and content types. Use after port scanning to identify HTTP services and their technology.")]
    async fn http_probe(&self, Parameters(input): Parameters<HttpProbeInput>) -> String {
        tools::http_probe::probe(&input.targets, input.timeout_secs).await
    }
}

#[tool_handler]
impl ServerHandler for UmbraAgent {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Umbra agent — Kubernetes container diagnostic toolkit. 44 tools: pod diagnostics (env, services, diagnose, check), network analysis (dns_lookup, trace_route, port_scan, socket_list), process debugging (process_list, open_files, syscall_trace, namespaces), HTTP/API testing (http_request, grpc_call, websocket), database clients (psql_query, redis_cmd), filesystem inspection, packet capture, bandwidth testing, assessment (detect_service_type, detect_all_service_types, security_audit, network_map), deep probe (service_deep_probe, deep_probe_target), deep health (postgres_health, mysql_health, redis_health, haproxy_stats, nginx_status), system monitoring (resource_usage, disk_usage, certificate_check), and security scanning (fast_scan, web_discover, tls_audit, vuln_scan, secret_scan, jwt_decode, load_test, auth_test, container_audit, http_probe). All tools return structured JSON."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("umbra-agent starting (44 tools)");

    let server = UmbraAgent::new().serve(stdio()).await?;
    server.waiting().await?;
    Ok(())
}
