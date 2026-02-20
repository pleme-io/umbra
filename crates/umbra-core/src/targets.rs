use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Credentials for connecting to a service.
#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
pub struct ServiceCredentials {
    /// Username (postgres user, mysql user, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Password
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Database name (postgres, mysql)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    /// Full connection string override (e.g. postgresql://user:pass@host:5432/db)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_string: Option<String>,
    /// Additional key-value credential pairs for service-specific needs.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, String>,
}

/// A configured target service to probe with optional credentials.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetConfig {
    /// Human-readable name (e.g. "production-db", "redis-cache").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Service host or IP.
    pub host: String,
    /// Service port.
    pub port: u16,
    /// Service type: "postgres", "mysql", "redis", "nginx", "haproxy", etc.
    /// Auto-detected from port if omitted.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub service_type: Option<String>,
    /// Credentials for authenticated access.
    #[serde(default)]
    pub credentials: ServiceCredentials,
}

/// Top-level targets YAML file structure.
#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
pub struct TargetsFile {
    #[serde(default)]
    pub targets: Vec<TargetConfig>,
}
