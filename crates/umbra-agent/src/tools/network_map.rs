use umbra_core::assessment::{NetworkMap, NetworkNode, ServiceType};
use umbra_core::PodIdentity;

use super::detect_service_type;

/// Build a network map from this pod's perspective.
pub async fn map() -> String {
    let identity = PodIdentity::gather();
    let services = umbra_core::services::discover_services();
    let mut nodes = Vec::new();

    for svc in &services {
        // Probe each service for type detection
        let result_json = detect_service_type::detect(&format!("{}:{}", svc.host, svc.port)).await;
        let result: serde_json::Value =
            serde_json::from_str(&result_json).unwrap_or(serde_json::json!({}));

        let service_type: ServiceType = result
            .get("service_type")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or(ServiceType::Unknown);

        let reachable = result.get("reachable").and_then(|v| v.as_bool()).unwrap_or(false);
        let tls = result.get("tls").and_then(|v| v.as_bool()).unwrap_or(false);
        let latency_ms = result.get("latency_ms").and_then(|v| v.as_u64());
        let http_status = result
            .get("http_status")
            .and_then(|v| v.as_u64())
            .map(|v| v as u16);
        let server_header = result
            .get("server_header")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        nodes.push(NetworkNode {
            name: svc.name.clone(),
            host: svc.host.clone(),
            port: svc.port,
            service_type,
            reachable,
            tls,
            latency_ms,
            http_status,
            server_header,
        });
    }

    let reachable = nodes.iter().filter(|n| n.reachable).count();
    let unreachable = nodes.len() - reachable;

    let map = NetworkMap {
        source: identity,
        nodes,
        total_services: services.len(),
        reachable,
        unreachable,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    serde_json::to_string_pretty(&map).unwrap()
}
