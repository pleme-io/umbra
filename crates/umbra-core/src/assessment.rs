use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::identity::PodIdentity;
use crate::security_scan::SecurityScanReport;

/// Detected type of a network service.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceType {
    Rest,
    #[serde(rename = "graphql")]
    GraphQL,
    #[serde(rename = "grpc")]
    Grpc,
    WebSocket,
    Database(DatabaseType),
    MessageQueue(MqType),
    StaticFiles,
    Unknown,
}

impl ServiceType {
    pub fn label(&self) -> &str {
        match self {
            Self::Rest => "REST",
            Self::GraphQL => "GraphQL",
            Self::Grpc => "gRPC",
            Self::WebSocket => "WebSocket",
            Self::Database(_) => "Database",
            Self::MessageQueue(_) => "MessageQueue",
            Self::StaticFiles => "StaticFiles",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseType {
    PostgreSQL,
    Redis,
    MySQL,
    MongoDB,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MqType {
    Kafka,
    Nats,
    RabbitMQ,
    Unknown,
}

/// Result of probing a single service for its type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceTypeResult {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub service_type: ServiceType,
    pub confidence: f32,
    pub evidence: Vec<String>,
    pub tls: bool,
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    pub http_status: Option<u16>,
    pub server_header: Option<String>,
}

/// Severity of a security finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// A single security finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub category: String,
    pub description: String,
    pub evidence: Vec<String>,
    pub remediation: Option<String>,
}

/// Summary counts by severity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
    pub score: u8,
}

/// Full security audit report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    pub findings: Vec<SecurityFinding>,
    pub summary: SecuritySummary,
    pub identity: PodIdentity,
    pub timestamp: String,
}

/// A node in the network map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkNode {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub service_type: ServiceType,
    pub reachable: bool,
    pub tls: bool,
    pub latency_ms: Option<u64>,
    pub http_status: Option<u16>,
    pub server_header: Option<String>,
}

/// Network topology map from a pod's perspective.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMap {
    pub source: PodIdentity,
    pub nodes: Vec<NetworkNode>,
    pub total_services: usize,
    pub reachable: usize,
    pub unreachable: usize,
    pub timestamp: String,
}

/// Protocol breakdown counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolSummary {
    pub rest: usize,
    pub graphql: usize,
    pub grpc: usize,
    pub websocket: usize,
    pub database: usize,
    pub message_queue: usize,
    pub static_files: usize,
    pub unknown: usize,
}

/// Result of deep-probing a single service (with or without credentials).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceHealthResult {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub service_type: ServiceType,
    /// Whether credentials were available for authenticated access.
    pub authenticated: bool,
    /// What's accessible WITHOUT any credentials.
    pub unauthenticated_access: UnauthenticatedAccess,
    /// Full health data (only populated when authenticated or when service has no auth).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<serde_json::Value>,
    /// Security findings specific to this service.
    pub findings: Vec<SecurityFinding>,
}

/// What we could extract without any credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnauthenticatedAccess {
    /// Version string extracted from banners, error messages, or headers.
    pub version: Option<String>,
    /// Protocol-level banner or greeting.
    pub banner: Option<String>,
    /// Whether the service allows unauthenticated access (security concern).
    pub allows_anonymous: bool,
    /// What data was accessible without auth.
    pub accessible_data: Vec<String>,
    /// Auth mechanism detected (e.g. "password required", "trust auth", "NOAUTH").
    pub auth_mechanism: Option<String>,
    /// TLS/SSL status.
    pub tls_required: Option<bool>,
    /// Raw evidence strings.
    pub evidence: Vec<String>,
}

/// Deep probe report covering all discovered services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepProbeReport {
    pub services: Vec<ServiceHealthResult>,
    pub total_probed: usize,
    pub authenticated_count: usize,
    pub anonymous_access_count: usize,
    pub timestamp: String,
}

/// Overall assessment summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentSummary {
    pub total_services: usize,
    pub reachable_services: usize,
    pub service_type_breakdown: HashMap<String, usize>,
    pub security_score: u8,
    pub tls_coverage_percent: f32,
    pub protocols: ProtocolSummary,
}

/// Full assessment report combining network map + security + service types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentReport {
    pub id: String,
    pub version: String,
    pub source: PodIdentity,
    pub network_map: NetworkMap,
    pub security: SecurityReport,
    pub service_types: Vec<ServiceTypeResult>,
    /// Deep probe results for each discovered service (health + security).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_health: Vec<ServiceHealthResult>,
    /// Security scan results from Tier 4 scanning tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_scan: Option<SecurityScanReport>,
    pub summary: AssessmentSummary,
    pub timestamp: String,
    pub duration_ms: u64,
}

/// Lightweight manifest entry for the gallery view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub id: String,
    pub timestamp: String,
    pub source: ManifestSource,
    pub security_score: u8,
    pub total_services: usize,
    pub reachable_services: usize,
    pub tls_coverage_percent: f32,
    pub duration_ms: u64,
    pub report_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestSource {
    pub namespace: Option<String>,
    pub pod_name: Option<String>,
    pub hostname: String,
}

/// Report manifest — lists all published reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: String,
    pub updated: String,
    pub reports: Vec<ManifestEntry>,
}

impl AssessmentReport {
    /// Extract a lightweight manifest entry from a full report.
    pub fn to_manifest_entry(&self, report_path: &str) -> ManifestEntry {
        ManifestEntry {
            id: self.id.clone(),
            timestamp: self.timestamp.clone(),
            source: ManifestSource {
                namespace: self.source.namespace.clone(),
                pod_name: self.source.pod_name.clone(),
                hostname: self.source.hostname.clone(),
            },
            security_score: self.summary.security_score,
            total_services: self.summary.total_services,
            reachable_services: self.summary.reachable_services,
            tls_coverage_percent: self.summary.tls_coverage_percent,
            duration_ms: self.duration_ms,
            report_path: report_path.to_string(),
        }
    }
}
