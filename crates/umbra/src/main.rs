mod config;
mod pool;
mod tools;

use config::Config;
use pool::ConnectionPool;
use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
};
use serde::Deserialize;
use std::sync::Arc;
use umbra_core::targets::{ServiceCredentials, TargetConfig};

// --- Tool input types ---

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ConnectInput {
    #[schemars(description = "Kubernetes context name (e.g. 'plo', 'zek')")]
    context: String,
    #[schemars(description = "Kubernetes namespace")]
    namespace: String,
    #[schemars(description = "Pod name")]
    pod: String,
    #[schemars(description = "Container name (optional, for multi-container pods)")]
    container: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DisconnectInput {
    #[schemars(description = "Connection ID returned from connect")]
    connection_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DiscoverInput {
    #[schemars(description = "Kubernetes context name")]
    context: String,
    #[schemars(description = "Namespace to search (omit for all namespaces)")]
    namespace: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct AgentToolsInput {
    #[schemars(description = "Connection ID to query for available tools")]
    connection_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct AgentExecInput {
    #[schemars(description = "Connection ID (reuses existing). Provide this OR (context + namespace + pod).")]
    connection_id: Option<String>,
    #[schemars(description = "Kubernetes context (for auto-connect)")]
    context: Option<String>,
    #[schemars(description = "Kubernetes namespace (for auto-connect)")]
    namespace: Option<String>,
    #[schemars(description = "Pod name (for auto-connect)")]
    pod: Option<String>,
    #[schemars(description = "Container name (optional)")]
    container: Option<String>,
    #[schemars(description = "Name of the agent tool to call (e.g. 'diagnose', 'dns_lookup', 'psql_query')")]
    tool: String,
    #[schemars(description = "Tool arguments as a JSON object")]
    arguments: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ProxyInput {
    #[schemars(description = "Connection ID (reuses existing). Provide this OR (context + namespace + pod).")]
    connection_id: Option<String>,
    #[schemars(description = "Kubernetes context (for auto-connect)")]
    context: Option<String>,
    #[schemars(description = "Kubernetes namespace (for auto-connect)")]
    namespace: Option<String>,
    #[schemars(description = "Pod name (for auto-connect)")]
    pod: Option<String>,
    #[schemars(description = "Container name (optional)")]
    container: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CheckInput {
    #[schemars(description = "Connection ID (reuses existing). Provide this OR (context + namespace + pod).")]
    connection_id: Option<String>,
    #[schemars(description = "Kubernetes context (for auto-connect)")]
    context: Option<String>,
    #[schemars(description = "Kubernetes namespace (for auto-connect)")]
    namespace: Option<String>,
    #[schemars(description = "Pod name (for auto-connect)")]
    pod: Option<String>,
    #[schemars(description = "Container name (optional)")]
    container: Option<String>,
    #[schemars(description = "Service to check: 'host:port', service name, or DNS name")]
    service: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct PodTargetInput {
    #[schemars(description = "Kubernetes context")]
    context: String,
    #[schemars(description = "Kubernetes namespace")]
    namespace: String,
    #[schemars(description = "Pod name")]
    pod: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CompareInput {
    #[schemars(description = "List of pods to compare (each with context, namespace, pod)")]
    pods: Vec<PodTargetInput>,
    #[schemars(description = "Agent tool to run on each pod (e.g. 'diagnose', 'services', 'env')")]
    tool: String,
    #[schemars(description = "Tool arguments as JSON")]
    arguments: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SweepInput {
    #[schemars(description = "Connection ID (reuses existing). Provide this OR (context + namespace + pod).")]
    connection_id: Option<String>,
    #[schemars(description = "Kubernetes context (for auto-connect)")]
    context: Option<String>,
    #[schemars(description = "Kubernetes namespace (for auto-connect)")]
    namespace: Option<String>,
    #[schemars(description = "Pod name (for auto-connect)")]
    pod: Option<String>,
    #[schemars(description = "Container name (optional)")]
    container: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct AssessInput {
    #[schemars(description = "Connection ID (reuses existing). Provide this OR (context + namespace + pod).")]
    connection_id: Option<String>,
    #[schemars(description = "Kubernetes context (for auto-connect)")]
    context: Option<String>,
    #[schemars(description = "Kubernetes namespace (for auto-connect)")]
    namespace: Option<String>,
    #[schemars(description = "Pod name (for auto-connect)")]
    pod: Option<String>,
    #[schemars(description = "Container name (optional)")]
    container: Option<String>,
    #[schemars(
        description = "Additional targets with credentials for deep probing. Each target: {host, port, type?, credentials: {user?, password?, database?, connection_string?}}. Merged with targets from ~/.config/umbra/targets.yaml. Use to pass credentials discovered from K8s secrets."
    )]
    targets: Option<Vec<TargetConfig>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ReportInput {
    #[schemars(description = "Connection ID (reuses existing). Provide this OR (context + namespace + pod).")]
    connection_id: Option<String>,
    #[schemars(description = "Kubernetes context (for auto-connect)")]
    context: Option<String>,
    #[schemars(description = "Kubernetes namespace (for auto-connect)")]
    namespace: Option<String>,
    #[schemars(description = "Pod name (for auto-connect)")]
    pod: Option<String>,
    #[schemars(description = "Container name (optional)")]
    container: Option<String>,
    #[schemars(description = "Local file path to save the report JSON")]
    output_path: Option<String>,
    #[schemars(
        description = "Endpoint names to publish to (from ~/.config/umbra/config.toml). Omit to use the default endpoint. Use ['all'] to publish to every configured endpoint."
    )]
    endpoints: Option<Vec<String>>,
    #[schemars(
        description = "Additional targets with credentials for deep probing. Merged with targets.yaml. Use to pass credentials discovered from K8s secrets."
    )]
    targets: Option<Vec<TargetConfig>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct PublishInput {
    #[schemars(description = "Path to an existing report.json file to publish")]
    report_path: String,
    #[schemars(
        description = "Endpoint names to publish to. Omit to use default. Use ['all'] to publish to all."
    )]
    endpoints: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WatchInput {
    #[schemars(description = "Connection ID (reuses existing). Provide this OR (context + namespace + pod).")]
    connection_id: Option<String>,
    #[schemars(description = "Kubernetes context (for auto-connect)")]
    context: Option<String>,
    #[schemars(description = "Kubernetes namespace (for auto-connect)")]
    namespace: Option<String>,
    #[schemars(description = "Pod name (for auto-connect)")]
    pod: Option<String>,
    #[schemars(description = "Container name (optional)")]
    container: Option<String>,
    #[schemars(description = "Agent tool to run repeatedly")]
    tool: String,
    #[schemars(description = "Tool arguments as JSON")]
    arguments: Option<serde_json::Map<String, serde_json::Value>>,
    #[schemars(description = "Seconds between executions (default: 5, max: 60)")]
    interval_secs: Option<u64>,
    #[schemars(description = "Number of iterations (default: 3, max: 20)")]
    count: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DeepProbeInput {
    #[schemars(description = "Connection ID (reuses existing). Provide this OR (context + namespace + pod).")]
    connection_id: Option<String>,
    #[schemars(description = "Kubernetes context (for auto-connect)")]
    context: Option<String>,
    #[schemars(description = "Kubernetes namespace (for auto-connect)")]
    namespace: Option<String>,
    #[schemars(description = "Pod name (for auto-connect)")]
    pod: Option<String>,
    #[schemars(description = "Container name (optional)")]
    container: Option<String>,
    #[schemars(description = "Target: 'host:port' format")]
    target: String,
    #[schemars(description = "Force service type: 'postgres', 'mysql', 'redis', 'nginx', 'haproxy'. Auto-detected if omitted")]
    service_type: Option<String>,
    #[schemars(description = "Credentials for authenticated probing (user, password, database, connection_string)")]
    credentials: Option<ServiceCredentials>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SecurityScanInput {
    #[schemars(description = "Connection ID (reuses existing). Provide this OR (context + namespace + pod).")]
    connection_id: Option<String>,
    #[schemars(description = "Kubernetes context (for auto-connect)")]
    context: Option<String>,
    #[schemars(description = "Kubernetes namespace (for auto-connect)")]
    namespace: Option<String>,
    #[schemars(description = "Pod name (for auto-connect)")]
    pod: Option<String>,
    #[schemars(description = "Container name (optional)")]
    container: Option<String>,
    #[schemars(description = "Primary target to scan: host, host:port, or URL")]
    target: String,
    #[schemars(
        description = "Include Phase 4 (web_discover + auth_test + load_test). These are more intrusive — only use with explicit authorization. Default: false"
    )]
    include_phase4: Option<bool>,
}

// --- MCP Server ---

#[derive(Debug, Clone)]
struct Umbra {
    pool: Arc<ConnectionPool>,
    config: Arc<Config>,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl Umbra {
    fn new() -> Self {
        let config = Config::load();
        let ep_count = config.publish.endpoints.len();
        if ep_count > 0 {
            tracing::info!(
                "loaded {ep_count} publish endpoint(s), default: {:?}",
                config.publish.default
            );
        }
        let target_count = config.targets.len();
        if target_count > 0 {
            tracing::info!("loaded {target_count} target(s) from targets.yaml");
        }

        Self {
            pool: Arc::new(ConnectionPool::new()),
            config: Arc::new(config),
            tool_router: Self::tool_router(),
        }
    }

    // === Connection management ===

    #[tool(description = "Connect to an umbra-agent in a Kubernetes pod via kubectl exec. Returns connection_id for reuse. Connection persists until disconnect.")]
    async fn connect(&self, Parameters(input): Parameters<ConnectInput>) -> String {
        tools::connection::connect(
            &self.pool,
            &input.context,
            &input.namespace,
            &input.pod,
            input.container.as_deref(),
        )
        .await
    }

    #[tool(description = "Close a connection to an umbra-agent.")]
    async fn disconnect(&self, Parameters(input): Parameters<DisconnectInput>) -> String {
        tools::connection::disconnect(&self.pool, &input.connection_id).await
    }

    #[tool(description = "List all active agent connections with their context/namespace/pod.")]
    async fn list_connections(&self) -> String {
        tools::connection::list_connections(&self.pool).await
    }

    #[tool(description = "Discover pods with umbra-agent (labeled umbra.pleme.io/agent=true) using kubectl.")]
    async fn discover(&self, Parameters(input): Parameters<DiscoverInput>) -> String {
        tools::discover::discover_pods(&input.context, input.namespace.as_deref()).await
    }

    // === Agent introspection ===

    #[tool(description = "List all tools available on a connected agent. Returns tool names and descriptions. Use this to discover what diagnostics are available.")]
    async fn agent_tools(&self, Parameters(input): Parameters<AgentToolsInput>) -> String {
        tools::orchestrate::agent_tools(&self.pool, &input.connection_id).await
    }

    #[tool(description = "Execute any agent tool by name. Generic proxy — works with all 24 agent tools. Pass tool name and arguments. Use agent_tools to discover available tools first.")]
    async fn agent_exec(&self, Parameters(input): Parameters<AgentExecInput>) -> String {
        tools::orchestrate::agent_exec(
            &self.pool,
            input.connection_id.as_deref(),
            input.context.as_deref(),
            input.namespace.as_deref(),
            input.pod.as_deref(),
            input.container.as_deref(),
            &input.tool,
            input.arguments,
        )
        .await
    }

    // === Proxied diagnostics ===

    #[tool(description = "Full pod diagnostic: identity, DNS, API server, service reachability, interfaces. Proxied to agent's diagnose tool.")]
    async fn diagnose(&self, Parameters(input): Parameters<ProxyInput>) -> String {
        tools::proxy::proxy_tool(
            &self.pool,
            input.connection_id.as_deref(),
            input.context.as_deref(),
            input.namespace.as_deref(),
            input.pod.as_deref(),
            input.container.as_deref(),
            "diagnose",
            None,
        )
        .await
    }

    #[tool(description = "List K8s env vars on a pod, grouped by category. Proxied to agent's env tool.")]
    async fn env(&self, Parameters(input): Parameters<ProxyInput>) -> String {
        tools::proxy::proxy_tool(
            &self.pool,
            input.connection_id.as_deref(),
            input.context.as_deref(),
            input.namespace.as_deref(),
            input.pod.as_deref(),
            input.container.as_deref(),
            "env",
            None,
        )
        .await
    }

    #[tool(description = "Test connectivity to a service from a pod. DNS + TCP + HTTP probes. Proxied to agent's check tool.")]
    async fn check(&self, Parameters(input): Parameters<CheckInput>) -> String {
        let args = serde_json::json!({"target": input.service});
        tools::proxy::proxy_tool(
            &self.pool,
            input.connection_id.as_deref(),
            input.context.as_deref(),
            input.namespace.as_deref(),
            input.pod.as_deref(),
            input.container.as_deref(),
            "check",
            args.as_object().cloned(),
        )
        .await
    }

    #[tool(description = "List discovered K8s services from a pod's env vars. Proxied to agent's services tool.")]
    async fn services(&self, Parameters(input): Parameters<ProxyInput>) -> String {
        tools::proxy::proxy_tool(
            &self.pool,
            input.connection_id.as_deref(),
            input.context.as_deref(),
            input.namespace.as_deref(),
            input.pod.as_deref(),
            input.container.as_deref(),
            "services",
            None,
        )
        .await
    }

    // === Orchestration ===

    #[tool(description = "Run the same tool on multiple pods and compare results side-by-side. Useful for finding the broken pod in a set of replicas.")]
    async fn compare(&self, Parameters(input): Parameters<CompareInput>) -> String {
        let targets: Vec<tools::orchestrate::PodTarget> = input
            .pods
            .into_iter()
            .map(|p| tools::orchestrate::PodTarget {
                context: p.context,
                namespace: p.namespace,
                pod: p.pod,
            })
            .collect();
        tools::orchestrate::compare(&self.pool, &targets, &input.tool, input.arguments).await
    }

    #[tool(description = "Connectivity sweep: check every discovered service from a pod. Returns full connectivity matrix showing which services are reachable.")]
    async fn sweep(&self, Parameters(input): Parameters<SweepInput>) -> String {
        tools::orchestrate::sweep(
            &self.pool,
            input.connection_id.as_deref(),
            input.context.as_deref(),
            input.namespace.as_deref(),
            input.pod.as_deref(),
            input.container.as_deref(),
        )
        .await
    }

    // === Assessment + reporting ===

    #[tool(description = "Full assessment: network map + security audit + service type detection + deep service probe. Runs all 4 assessment tools on the agent in parallel. Deep probe auto-discovers services and runs unauthenticated recon (banner grab, version extraction, anonymous access testing) plus credentialed health checks. Pass 'targets' with credentials discovered from K8s secrets for authenticated deep probing. Targets are merged with ~/.config/umbra/targets.yaml. Produces comprehensive AssessmentReport with security score, protocol breakdown, TLS coverage, service health, and findings.")]
    async fn assess(&self, Parameters(input): Parameters<AssessInput>) -> String {
        let dynamic_targets = input.targets.unwrap_or_default();
        let merged_targets = self.config.merge_targets(&dynamic_targets);
        tools::assess::full_assessment(
            &self.pool,
            input.connection_id.as_deref(),
            input.context.as_deref(),
            input.namespace.as_deref(),
            input.pod.as_deref(),
            input.container.as_deref(),
            &merged_targets,
        )
        .await
    }

    #[tool(description = "Generate assessment report and publish to configured S3 endpoints. Runs full assessment, optionally saves JSON locally, and publishes to named endpoints (report + manifest + viewer assets). Configure endpoints in ~/.config/umbra/config.toml. Pass 'targets' with credentials for authenticated deep probing.")]
    async fn report(&self, Parameters(input): Parameters<ReportInput>) -> String {
        let endpoint_names = resolve_endpoint_names(&self.config, input.endpoints.as_deref());
        let dynamic_targets = input.targets.unwrap_or_default();
        let merged_targets = self.config.merge_targets(&dynamic_targets);
        tools::report::generate_report(
            &self.pool,
            &self.config,
            input.connection_id.as_deref(),
            input.context.as_deref(),
            input.namespace.as_deref(),
            input.pod.as_deref(),
            input.container.as_deref(),
            input.output_path.as_deref(),
            &endpoint_names,
            &merged_targets,
        )
        .await
    }

    #[tool(description = "Publish an existing report.json to configured S3 endpoints. Use this to re-publish or publish a saved report without re-running assessment.")]
    async fn publish(&self, Parameters(input): Parameters<PublishInput>) -> String {
        let report_json = match std::fs::read_to_string(&input.report_path) {
            Ok(json) => json,
            Err(e) => {
                return serde_json::json!({
                    "error": format!("Cannot read {}: {e}", input.report_path)
                })
                .to_string()
            }
        };
        let endpoint_names = resolve_endpoint_names(&self.config, input.endpoints.as_deref());
        tools::report::publish_report(&self.config, &report_json, &endpoint_names).await
    }

    #[tool(description = "List configured publish endpoints from ~/.config/umbra/config.toml. Shows endpoint names, buckets, regions, and which is the default.")]
    async fn endpoints(&self) -> String {
        serde_json::to_string_pretty(&self.config.list_endpoints()).unwrap()
    }

    // === Targets + credentials ===

    #[tool(description = "List configured targets from ~/.config/umbra/targets.yaml. Shows target names, hosts, ports, types, and whether credentials are configured (never shows credential values). Use this to see what pre-configured targets are available for authenticated deep probing.")]
    async fn list_targets(&self) -> String {
        serde_json::to_string_pretty(&self.config.list_targets()).unwrap()
    }

    #[tool(description = "Deep probe a single target from a pod. Runs unauthenticated recon (banner grab, version detection, anonymous access test) then credentialed health check if credentials are provided. Use this to probe a specific service with credentials discovered from K8s secrets (via kubectl get secret or kubernetes MCP).")]
    async fn deep_probe(&self, Parameters(input): Parameters<DeepProbeInput>) -> String {
        let mut args = serde_json::json!({
            "target": input.target,
        });
        if let Some(ref st) = input.service_type {
            args["service_type"] = serde_json::Value::String(st.clone());
        }
        if let Some(ref creds) = input.credentials {
            args["credentials"] = serde_json::to_value(creds).unwrap_or_default();
        }
        tools::proxy::proxy_tool(
            &self.pool,
            input.connection_id.as_deref(),
            input.context.as_deref(),
            input.namespace.as_deref(),
            input.pod.as_deref(),
            input.container.as_deref(),
            "deep_probe_target",
            args.as_object().cloned(),
        )
        .await
    }

    // === Watch ===

    #[tool(description = "Run a tool repeatedly at intervals to monitor changes over time. Returns time-series of results. Useful for watching recovery or tracking intermittent issues.")]
    async fn watch(&self, Parameters(input): Parameters<WatchInput>) -> String {
        tools::orchestrate::watch(
            self.pool.clone(),
            input.connection_id.as_deref(),
            input.context.as_deref(),
            input.namespace.as_deref(),
            input.pod.as_deref(),
            input.container.as_deref(),
            &input.tool,
            input.arguments,
            input.interval_secs.unwrap_or(5),
            input.count.unwrap_or(3),
        )
        .await
    }

    // === Security scanning ===

    #[tool(description = "Phased security scan pipeline. Phase 1 (parallel): fast_scan + secret_scan + jwt_decode + container_audit. Phase 2: http_probe on discovered HTTP ports. Phase 3 (parallel): vuln_scan + tls_audit. Phase 4 (optional, set include_phase4=true): web_discover + auth_test + load_test. Returns aggregated SecurityScanReport with findings by severity, open ports, CVEs, secrets. All tools degrade gracefully if binaries are missing.")]
    async fn security_scan(&self, Parameters(input): Parameters<SecurityScanInput>) -> String {
        tools::security_scan::security_scan(
            &self.pool,
            input.connection_id.as_deref(),
            input.context.as_deref(),
            input.namespace.as_deref(),
            input.pod.as_deref(),
            input.container.as_deref(),
            &input.target,
            input.include_phase4.unwrap_or(false),
        )
        .await
    }
}

/// Resolve endpoint names: handle "all" keyword and None → default.
fn resolve_endpoint_names(config: &Config, names: Option<&[String]>) -> Vec<String> {
    match names {
        Some(names) if !names.is_empty() => {
            if names.iter().any(|n| n.eq_ignore_ascii_case("all")) {
                // "all" → every configured endpoint
                config.publish.endpoints.keys().cloned().collect()
            } else {
                names.to_vec()
            }
        }
        _ => {
            // None or empty → resolve_endpoints handles default logic
            Vec::new()
        }
    }
}

#[tool_handler]
impl ServerHandler for Umbra {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Umbra — Kubernetes container diagnostic MCP. 21 tools: connection management (connect, disconnect, list_connections, discover), agent introspection (agent_tools, agent_exec), proxied diagnostics (diagnose, env, check, services), assessment (assess, report, publish, endpoints), targets + credentials (list_targets, deep_probe), orchestration (compare, sweep, watch), and security scanning (security_scan). Configure S3 publish endpoints in ~/.config/umbra/config.toml. Configure target credentials in ~/.config/umbra/targets.yaml. Pass dynamic credentials discovered from K8s secrets via 'targets' parameter on assess/report/deep_probe. Use 'report' to assess + publish, 'publish' for existing reports, 'endpoints' to list configured destinations. Use 'security_scan' for phased vulnerability assessment."
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

    tracing::info!("umbra starting (20 tools)");

    let server = Umbra::new().serve(stdio()).await?;
    server.waiting().await?;
    Ok(())
}
