use crate::cmd;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct ContainerAuditResult {
    target: String,
    success: bool,
    vulnerabilities: Vec<TrivyVuln>,
    total_found: usize,
    truncated: bool,
    summary: Option<TrivySummary>,
    error: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct TrivyVuln {
    #[serde(default, alias = "VulnerabilityID")]
    vulnerability_id: String,
    #[serde(default, alias = "PkgName")]
    package: String,
    #[serde(default, alias = "InstalledVersion")]
    installed_version: String,
    #[serde(default, alias = "FixedVersion")]
    fixed_version: String,
    #[serde(default, alias = "Severity")]
    severity: String,
    #[serde(default, alias = "Title")]
    title: String,
}

#[derive(Serialize)]
struct TrivySummary {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    unknown: usize,
}

const MAX_FINDINGS: usize = 100;

pub async fn audit(path: Option<&str>, severity: Option<&str>, timeout_secs: Option<u64>) -> String {
    if !cmd::is_available("trivy").await {
        return cmd::binary_not_found("trivy", None);
    }

    let timeout = timeout_secs.unwrap_or(90);
    let scan_path = path.unwrap_or("/");

    let mut args = vec![
        "filesystem",
        "--format",
        "json",
        "--skip-db-update",
        "--no-progress",
        "--quiet",
    ];

    let sev_str;
    if let Some(s) = severity {
        sev_str = s.to_uppercase();
        args.extend(["--severity", &sev_str]);
    }

    args.push(scan_path);

    let result = cmd::run("trivy", &args, timeout).await;

    if !result.success && result.stdout.is_empty() {
        return serde_json::to_string_pretty(&ContainerAuditResult {
            target: scan_path.to_string(),
            success: false,
            vulnerabilities: vec![],
            total_found: 0,
            truncated: false,
            summary: None,
            error: Some(result.stderr.trim().to_string()),
        })
        .unwrap();
    }

    // Parse trivy JSON output
    let parsed: serde_json::Value = match serde_json::from_str(&result.stdout) {
        Ok(v) => v,
        Err(_) => {
            return serde_json::to_string_pretty(&ContainerAuditResult {
                target: scan_path.to_string(),
                success: false,
                vulnerabilities: vec![],
                total_found: 0,
                truncated: false,
                summary: None,
                error: Some("Could not parse trivy output as JSON".into()),
            })
            .unwrap();
        }
    };

    let mut vulns = Vec::new();

    // Trivy JSON has { "Results": [ { "Vulnerabilities": [...] } ] }
    if let Some(results) = parsed.get("Results").and_then(|r| r.as_array()) {
        for result_entry in results {
            if let Some(vuln_arr) = result_entry.get("Vulnerabilities").and_then(|v| v.as_array())
            {
                for v in vuln_arr {
                    let vuln = TrivyVuln {
                        vulnerability_id: v
                            .get("VulnerabilityID")
                            .and_then(|id| id.as_str())
                            .unwrap_or("")
                            .to_string(),
                        package: v
                            .get("PkgName")
                            .and_then(|p| p.as_str())
                            .unwrap_or("")
                            .to_string(),
                        installed_version: v
                            .get("InstalledVersion")
                            .and_then(|iv| iv.as_str())
                            .unwrap_or("")
                            .to_string(),
                        fixed_version: v
                            .get("FixedVersion")
                            .and_then(|fv| fv.as_str())
                            .unwrap_or("")
                            .to_string(),
                        severity: v
                            .get("Severity")
                            .and_then(|s| s.as_str())
                            .unwrap_or("UNKNOWN")
                            .to_string(),
                        title: v
                            .get("Title")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                            .to_string(),
                    };
                    vulns.push(vuln);
                }
            }
        }
    }

    let total = vulns.len();
    let truncated = total > MAX_FINDINGS;

    // Build summary before truncation
    let summary = TrivySummary {
        critical: vulns
            .iter()
            .filter(|v| v.severity.eq_ignore_ascii_case("CRITICAL"))
            .count(),
        high: vulns
            .iter()
            .filter(|v| v.severity.eq_ignore_ascii_case("HIGH"))
            .count(),
        medium: vulns
            .iter()
            .filter(|v| v.severity.eq_ignore_ascii_case("MEDIUM"))
            .count(),
        low: vulns
            .iter()
            .filter(|v| v.severity.eq_ignore_ascii_case("LOW"))
            .count(),
        unknown: vulns
            .iter()
            .filter(|v| v.severity.eq_ignore_ascii_case("UNKNOWN"))
            .count(),
    };

    if truncated {
        vulns.truncate(MAX_FINDINGS);
    }

    serde_json::to_string_pretty(&ContainerAuditResult {
        target: scan_path.to_string(),
        success: true,
        vulnerabilities: vulns,
        total_found: total,
        truncated,
        summary: Some(summary),
        error: None,
    })
    .unwrap()
}
