use serde::{Deserialize, Serialize};
use std::env;

/// Category of a Kubernetes environment variable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EnvCategory {
    ServiceDiscovery,
    Kubernetes,
    Container,
    Application,
    Other,
}

/// A single environment variable with its category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
    pub category: EnvCategory,
}

/// Report of all environment variables, grouped by category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvReport {
    pub service_discovery: Vec<EnvVar>,
    pub kubernetes: Vec<EnvVar>,
    pub container: Vec<EnvVar>,
    pub application: Vec<EnvVar>,
    pub other: Vec<EnvVar>,
    pub total: usize,
}

impl EnvReport {
    /// Collect and categorize all environment variables.
    pub fn gather() -> Self {
        let mut service_discovery = Vec::new();
        let mut kubernetes = Vec::new();
        let mut container = Vec::new();
        let mut application = Vec::new();
        let mut other = Vec::new();

        let mut vars: Vec<(String, String)> = env::vars().collect();
        vars.sort_by(|a, b| a.0.cmp(&b.0));

        let total = vars.len();

        for (name, value) in vars {
            let category = categorize(&name);
            let var = EnvVar {
                name,
                value,
                category: category.clone(),
            };
            match category {
                EnvCategory::ServiceDiscovery => service_discovery.push(var),
                EnvCategory::Kubernetes => kubernetes.push(var),
                EnvCategory::Container => container.push(var),
                EnvCategory::Application => application.push(var),
                EnvCategory::Other => other.push(var),
            }
        }

        Self {
            service_discovery,
            kubernetes,
            container,
            application,
            other,
            total,
        }
    }
}

fn categorize(name: &str) -> EnvCategory {
    // Service discovery: *_SERVICE_HOST, *_SERVICE_PORT, *_PORT_*
    if name.ends_with("_SERVICE_HOST")
        || name.ends_with("_SERVICE_PORT")
        || (name.contains("_PORT_") && name.contains("_TCP"))
        || (name.contains("_PORT_") && name.contains("_UDP"))
        || name.ends_with("_PORT") && name.contains("_SERVICE")
    {
        return EnvCategory::ServiceDiscovery;
    }

    // Kubernetes core
    if name.starts_with("KUBERNETES_")
        || name == "POD_NAME"
        || name == "POD_NAMESPACE"
        || name == "POD_IP"
        || name == "NODE_NAME"
        || name == "SERVICE_ACCOUNT"
        || name == "HOSTNAME"
    {
        return EnvCategory::Kubernetes;
    }

    // Container runtime
    if name == "HOME"
        || name == "PATH"
        || name == "USER"
        || name == "LANG"
        || name == "TERM"
        || name == "SHELL"
        || name == "PWD"
        || name == "SHLVL"
        || name.starts_with("LC_")
    {
        return EnvCategory::Container;
    }

    // Application (common patterns)
    if name.starts_with("APP_")
        || name.starts_with("DATABASE_")
        || name.starts_with("REDIS_")
        || name.starts_with("LOG_")
        || name.starts_with("RUST_")
        || name.starts_with("CARGO_")
        || name.ends_with("_URL")
        || name.ends_with("_DSN")
        || name.ends_with("_KEY")
        || name.ends_with("_SECRET")
        || name.ends_with("_TOKEN")
    {
        return EnvCategory::Application;
    }

    EnvCategory::Other
}
