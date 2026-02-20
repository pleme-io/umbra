use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::assessment::Severity;
use crate::identity::PodIdentity;

/// A single finding from a security scanning tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub tool: String,
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub category: String,
    pub description: String,
    pub evidence: Vec<String>,
    pub remediation: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Result from a single security scanning tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolScanResult {
    pub tool: String,
    pub success: bool,
    pub available: bool,
    pub duration_ms: u64,
    pub findings: Vec<ScanFinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Aggregated summary of a full security scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScanSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total_findings: usize,
    pub open_ports: usize,
    pub vulnerabilities: usize,
    pub secrets_found: usize,
    pub cves_found: usize,
}

/// Full security scan report aggregating results from multiple tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScanReport {
    pub identity: PodIdentity,
    pub tools: Vec<ToolScanResult>,
    pub summary: SecurityScanSummary,
    pub timestamp: String,
    pub duration_ms: u64,
}
