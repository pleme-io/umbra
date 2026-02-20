use umbra_core::ServiceCheck;

use crate::probe;

pub async fn check_service(target: &str) -> String {
    // Parse target: either "host:port" or service name to look up
    let (host, port) = parse_target(target);

    let dns = probe::dns::resolve(&host).await;

    let tcp = probe::tcp::connect(&host, port).await;

    let http = if tcp.success {
        Some(probe::http::probe(&host, port).await)
    } else {
        None
    };

    let result = ServiceCheck {
        target: target.to_string(),
        dns,
        tcp,
        http,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
}

fn parse_target(target: &str) -> (String, u16) {
    if let Some((host, port_str)) = target.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (host.to_string(), port);
        }
    }

    // Try to find from environment: <TARGET>_SERVICE_HOST / <TARGET>_SERVICE_PORT
    let env_prefix = target.to_uppercase().replace('-', "_");
    let host = std::env::var(format!("{env_prefix}_SERVICE_HOST"))
        .unwrap_or_else(|_| target.to_string());
    let port: u16 = std::env::var(format!("{env_prefix}_SERVICE_PORT"))
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(80);

    (host, port)
}
