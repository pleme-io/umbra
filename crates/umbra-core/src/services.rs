use serde::{Deserialize, Serialize};
use std::env;

/// A Kubernetes service discovered from environment variables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub protocol: String,
}

/// Parse all Kubernetes service discovery environment variables
/// (*_SERVICE_HOST / *_SERVICE_PORT) into structured service info.
pub fn discover_services() -> Vec<ServiceInfo> {
    let vars: std::collections::HashMap<String, String> = env::vars().collect();
    let mut services = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for (name, _) in &vars {
        if let Some(prefix) = name.strip_suffix("_SERVICE_HOST") {
            if seen.contains(prefix) {
                continue;
            }
            seen.insert(prefix.to_string());

            let host = vars.get(name).cloned().unwrap_or_default();
            let port_key = format!("{prefix}_SERVICE_PORT");
            let port: u16 = vars
                .get(&port_key)
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);

            // Determine protocol from *_PORT_<port>_TCP or similar
            let protocol = if vars.contains_key(&format!("{prefix}_PORT_{port}_TCP")) {
                "TCP".to_string()
            } else if vars.contains_key(&format!("{prefix}_PORT_{port}_UDP")) {
                "UDP".to_string()
            } else {
                "TCP".to_string()
            };

            let name = prefix
                .to_lowercase()
                .replace('_', "-");

            services.push(ServiceInfo {
                name,
                host,
                port,
                protocol,
            });
        }
    }

    services.sort_by(|a, b| a.name.cmp(&b.name));
    services
}
