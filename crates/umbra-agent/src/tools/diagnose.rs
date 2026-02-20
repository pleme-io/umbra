use umbra_core::{DiagnosticReport, PodIdentity, ServiceCheckResult};
use umbra_core::services::discover_services;

use crate::probe;

pub async fn run_diagnostics() -> String {
    let identity = PodIdentity::gather();

    // DNS check — resolve kubernetes.default.svc.cluster.local
    let dns = probe::dns::resolve("kubernetes.default.svc.cluster.local").await;

    // API server connectivity
    let api_host = std::env::var("KUBERNETES_SERVICE_HOST").unwrap_or_else(|_| "10.43.0.1".into());
    let api_port: u16 = std::env::var("KUBERNETES_SERVICE_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(443);
    let api_server = probe::tcp::connect(&api_host, api_port).await;

    // Check discovered services
    let discovered = discover_services();
    let mut service_checks = Vec::new();
    for svc in &discovered {
        // Skip kubernetes service itself (already checked)
        if svc.name == "kubernetes" {
            continue;
        }
        let dns_result = probe::dns::resolve(&svc.host).await;
        let tcp_result = probe::tcp::connect(&svc.host, svc.port).await;
        let http_result = if tcp_result.success {
            Some(probe::http::probe(&svc.host, svc.port).await)
        } else {
            None
        };
        service_checks.push(ServiceCheckResult {
            service: svc.clone(),
            dns: Some(dns_result),
            tcp: Some(tcp_result),
            http: http_result,
        });
    }

    // Network interfaces
    let interfaces = probe::network::list_interfaces();

    let report = DiagnosticReport {
        identity,
        dns,
        api_server,
        services: service_checks,
        interfaces,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    serde_json::to_string_pretty(&report).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
}
