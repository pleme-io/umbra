use serde::{Deserialize, Serialize};

use crate::identity::PodIdentity;
use crate::services::ServiceInfo;

/// Result of a DNS resolution probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProbeResult {
    pub hostname: String,
    pub addresses: Vec<String>,
    pub success: bool,
    pub error: Option<String>,
    pub latency_ms: u64,
}

/// Result of a TCP connection probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpProbeResult {
    pub host: String,
    pub port: u16,
    pub success: bool,
    pub error: Option<String>,
    pub latency_ms: u64,
}

/// Result of an HTTP health probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProbeResult {
    pub url: String,
    pub status_code: Option<u16>,
    pub success: bool,
    pub error: Option<String>,
    pub latency_ms: u64,
}

/// A network interface with its addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub addresses: Vec<String>,
}

/// Full diagnostic report for a pod.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub identity: PodIdentity,
    pub dns: DnsProbeResult,
    pub api_server: TcpProbeResult,
    pub services: Vec<ServiceCheckResult>,
    pub interfaces: Vec<NetworkInterface>,
    pub timestamp: String,
}

/// Result of checking a single service's connectivity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceCheckResult {
    pub service: ServiceInfo,
    pub dns: Option<DnsProbeResult>,
    pub tcp: Option<TcpProbeResult>,
    pub http: Option<HttpProbeResult>,
}

/// Full check result for a specific service target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceCheck {
    pub target: String,
    pub dns: DnsProbeResult,
    pub tcp: TcpProbeResult,
    pub http: Option<HttpProbeResult>,
    pub timestamp: String,
}
