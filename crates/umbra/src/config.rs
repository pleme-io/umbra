use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use umbra_core::targets::{TargetConfig, TargetsFile};

/// S3-compatible endpoint configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    /// S3 bucket name.
    pub bucket: String,
    /// Key prefix within the bucket (e.g. "umbra/prod").
    #[serde(default)]
    pub prefix: String,
    /// AWS region (e.g. "us-east-1"). Optional for non-AWS endpoints.
    pub region: Option<String>,
    /// Custom S3 endpoint URL for non-AWS services (R2, MinIO, etc.).
    pub endpoint_url: Option<String>,
    /// AWS CLI profile to use. Falls back to default.
    pub profile: Option<String>,
}

impl Endpoint {
    /// Returns the bucket/prefix string used for S3 operations.
    pub fn bucket_prefix(&self) -> String {
        if self.prefix.is_empty() {
            self.bucket.clone()
        } else {
            format!(
                "{}/{}",
                self.bucket,
                self.prefix.trim_matches('/')
            )
        }
    }

    /// Build the common AWS CLI args for this endpoint.
    pub fn aws_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(ref region) = self.region {
            args.extend(["--region".into(), region.clone()]);
        }
        if let Some(ref url) = self.endpoint_url {
            args.extend(["--endpoint-url".into(), url.clone()]);
        }
        if let Some(ref profile) = self.profile {
            args.extend(["--profile".into(), profile.clone()]);
        }
        args
    }

    /// The public URL where the viewer would be accessible (if configured as static website).
    pub fn viewer_url(&self) -> Option<String> {
        // For custom endpoints (R2 custom domains, etc.), derive from endpoint_url
        self.endpoint_url.as_ref().map(|url| {
            let base = url.trim_end_matches('/');
            if self.prefix.is_empty() {
                format!("{base}/")
            } else {
                format!("{base}/{}/", self.prefix.trim_matches('/'))
            }
        })
    }
}

/// Publish section of the config.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PublishConfig {
    /// Default endpoint name to use when none specified.
    pub default: Option<String>,
    /// Named endpoints.
    #[serde(default)]
    pub endpoints: HashMap<String, Endpoint>,
}

/// Top-level umbra config.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub publish: PublishConfig,
    /// Pre-configured targets with credentials (loaded from targets.yaml).
    #[serde(skip)]
    pub targets: Vec<TargetConfig>,
}

impl Config {
    /// Load config from the standard path (~/.config/umbra/config.toml)
    /// and targets from (~/.config/umbra/targets.yaml).
    pub fn load() -> Self {
        let mut config = match Self::config_path() {
            Some(path) if path.exists() => {
                match std::fs::read_to_string(&path) {
                    Ok(content) => match toml::from_str(&content) {
                        Ok(config) => {
                            tracing::debug!("loaded config from {}", path.display());
                            config
                        }
                        Err(e) => {
                            tracing::warn!("invalid config at {}: {e}", path.display());
                            Self::default()
                        }
                    },
                    Err(e) => {
                        tracing::warn!("cannot read {}: {e}", path.display());
                        Self::default()
                    }
                }
            }
            _ => Self::default(),
        };

        // Load targets.yaml
        if let Some(targets_path) = Self::targets_path() {
            if targets_path.exists() {
                match std::fs::read_to_string(&targets_path) {
                    Ok(content) => match serde_yaml::from_str::<TargetsFile>(&content) {
                        Ok(tf) => {
                            tracing::info!(
                                "loaded {} target(s) from {}",
                                tf.targets.len(),
                                targets_path.display()
                            );
                            config.targets = tf.targets;
                        }
                        Err(e) => {
                            tracing::warn!(
                                "invalid targets at {}: {e}",
                                targets_path.display()
                            );
                        }
                    },
                    Err(e) => {
                        tracing::warn!(
                            "cannot read {}: {e}",
                            targets_path.display()
                        );
                    }
                }
            }
        }

        config
    }

    /// Resolve endpoint(s) for publishing.
    ///
    /// - If `names` is non-empty, returns those named endpoints.
    /// - If `names` is empty and there's a default, returns just the default.
    /// - If `names` is empty and there are endpoints but no default, returns all.
    /// - Returns empty vec if no endpoints configured.
    pub fn resolve_endpoints(&self, names: &[String]) -> Vec<(String, Endpoint)> {
        if !names.is_empty() {
            // Return only the requested names (skip unknown with warning)
            names
                .iter()
                .filter_map(|name| {
                    self.publish
                        .endpoints
                        .get(name)
                        .map(|ep| (name.clone(), ep.clone()))
                        .or_else(|| {
                            tracing::warn!("unknown endpoint: {name}");
                            None
                        })
                })
                .collect()
        } else if let Some(ref default_name) = self.publish.default {
            // Use the default
            self.publish
                .endpoints
                .get(default_name)
                .map(|ep| vec![(default_name.clone(), ep.clone())])
                .unwrap_or_default()
        } else if self.publish.endpoints.len() == 1 {
            // Single endpoint configured, use it as implicit default
            self.publish
                .endpoints
                .iter()
                .map(|(name, ep)| (name.clone(), ep.clone()))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// List all configured endpoints.
    pub fn list_endpoints(&self) -> serde_json::Value {
        let endpoints: Vec<serde_json::Value> = self
            .publish
            .endpoints
            .iter()
            .map(|(name, ep)| {
                serde_json::json!({
                    "name": name,
                    "bucket": ep.bucket,
                    "prefix": ep.prefix,
                    "region": ep.region,
                    "endpoint_url": ep.endpoint_url,
                    "profile": ep.profile,
                    "is_default": self.publish.default.as_deref() == Some(name.as_str()),
                })
            })
            .collect();

        serde_json::json!({
            "config_path": Self::config_path().map(|p| p.display().to_string()),
            "default": self.publish.default,
            "endpoints": endpoints,
        })
    }

    /// List configured targets (names and types only — never exposes credentials).
    pub fn list_targets(&self) -> serde_json::Value {
        let targets: Vec<serde_json::Value> = self
            .targets
            .iter()
            .map(|t| {
                serde_json::json!({
                    "name": t.name,
                    "host": t.host,
                    "port": t.port,
                    "type": t.service_type,
                    "has_credentials": t.credentials.user.is_some()
                        || t.credentials.password.is_some()
                        || t.credentials.connection_string.is_some(),
                })
            })
            .collect();

        serde_json::json!({
            "targets_path": Self::targets_path().map(|p| p.display().to_string()),
            "count": targets.len(),
            "targets": targets,
        })
    }

    /// Merge configured targets with dynamically provided ones.
    /// Dynamic targets override configured ones when host:port matches.
    pub fn merge_targets(&self, dynamic: &[TargetConfig]) -> Vec<TargetConfig> {
        let mut merged = self.targets.clone();

        for dyn_target in dynamic {
            // Check if this target already exists (by host:port match)
            let existing = merged.iter_mut().find(|t| {
                t.host == dyn_target.host && t.port == dyn_target.port
            });

            if let Some(existing) = existing {
                // Override with dynamic credentials
                if dyn_target.credentials.user.is_some() {
                    existing.credentials.user = dyn_target.credentials.user.clone();
                }
                if dyn_target.credentials.password.is_some() {
                    existing.credentials.password = dyn_target.credentials.password.clone();
                }
                if dyn_target.credentials.database.is_some() {
                    existing.credentials.database = dyn_target.credentials.database.clone();
                }
                if dyn_target.credentials.connection_string.is_some() {
                    existing.credentials.connection_string =
                        dyn_target.credentials.connection_string.clone();
                }
                if !dyn_target.credentials.extra.is_empty() {
                    existing
                        .credentials
                        .extra
                        .extend(dyn_target.credentials.extra.clone());
                }
                if dyn_target.service_type.is_some() {
                    existing.service_type = dyn_target.service_type.clone();
                }
                if dyn_target.name.is_some() {
                    existing.name = dyn_target.name.clone();
                }
            } else {
                merged.push(dyn_target.clone());
            }
        }

        merged
    }

    fn config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("umbra").join("config.toml"))
    }

    fn targets_path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("umbra").join("targets.yaml"))
    }
}
