use crate::pool::ConnectionPool;
use umbra_core::security_scan::*;

/// Run a phased security scan pipeline on a connected agent.
///
/// Phase 1 (parallel): fast_scan + secret_scan + jwt_decode + container_audit
/// Phase 2 (sequential): http_probe on discovered HTTP ports from phase 1
/// Phase 3 (parallel): vuln_scan + tls_audit on discovered services
/// Phase 4 (optional, explicit): web_discover + auth_test + load_test
pub async fn security_scan(
    pool: &ConnectionPool,
    connection_id: Option<&str>,
    context: Option<&str>,
    namespace: Option<&str>,
    pod: Option<&str>,
    container: Option<&str>,
    target: &str,
    include_phase4: bool,
) -> String {
    let id = match super::proxy::resolve_connection_pub(
        pool,
        connection_id,
        context,
        namespace,
        pod,
        container,
    )
    .await
    {
        Ok(id) => id,
        Err(e) => return serde_json::json!({"error": e}).to_string(),
    };

    let start = std::time::Instant::now();
    let mut tool_results: Vec<ToolScanResult> = Vec::new();

    // === Phase 1: Parallel discovery + passive scans ===
    let fast_scan_args = serde_json::json!({"target": target});
    let secret_scan_args = serde_json::json!({});
    let jwt_args = serde_json::json!({});
    let container_audit_args = serde_json::json!({});

    let (fast_r, secret_r, jwt_r, container_r) = tokio::join!(
        timed_call(pool, &id, "fast_scan", fast_scan_args.as_object().cloned()),
        timed_call(pool, &id, "secret_scan", secret_scan_args.as_object().cloned()),
        timed_call(pool, &id, "jwt_decode", jwt_args.as_object().cloned()),
        timed_call(pool, &id, "container_audit", container_audit_args.as_object().cloned()),
    );

    tool_results.push(parse_tool_result("fast_scan", fast_r));
    tool_results.push(parse_tool_result("secret_scan", secret_r));
    tool_results.push(parse_tool_result("jwt_decode", jwt_r));
    tool_results.push(parse_tool_result("container_audit", container_r));

    // === Phase 2: HTTP probe on discovered open ports ===
    let http_targets = extract_http_targets(&tool_results, target);

    if !http_targets.is_empty() {
        let probe_args = serde_json::json!({"targets": http_targets});
        let probe_r = timed_call(pool, &id, "http_probe", probe_args.as_object().cloned()).await;
        tool_results.push(parse_tool_result("http_probe", probe_r));
    }

    // === Phase 3: Parallel vuln scan + TLS audit ===
    let vuln_args = serde_json::json!({"target": target});
    let tls_target = if target.contains(':') {
        target.to_string()
    } else {
        format!("{target}:443")
    };
    let tls_args = serde_json::json!({"target": tls_target});

    let (vuln_r, tls_r) = tokio::join!(
        timed_call(pool, &id, "vuln_scan", vuln_args.as_object().cloned()),
        timed_call(pool, &id, "tls_audit", tls_args.as_object().cloned()),
    );

    tool_results.push(parse_tool_result("vuln_scan", vuln_r));
    tool_results.push(parse_tool_result("tls_audit", tls_r));

    // === Phase 4 (optional): Web discover + auth test + load test ===
    if include_phase4 {
        let web_target = if target.starts_with("http") {
            target.to_string()
        } else {
            format!("http://{target}")
        };
        let web_args = serde_json::json!({"target": web_target});
        let auth_args = serde_json::json!({"target": target});
        let load_args = serde_json::json!({"target": web_target});

        let (web_r, auth_r, load_r) = tokio::join!(
            timed_call(pool, &id, "web_discover", web_args.as_object().cloned()),
            timed_call(pool, &id, "auth_test", auth_args.as_object().cloned()),
            timed_call(pool, &id, "load_test", load_args.as_object().cloned()),
        );

        tool_results.push(parse_tool_result("web_discover", web_r));
        tool_results.push(parse_tool_result("auth_test", auth_r));
        tool_results.push(parse_tool_result("load_test", load_r));
    }

    let duration_ms = start.elapsed().as_millis() as u64;

    // Build summary
    let summary = build_summary(&tool_results);

    // Get identity from fast_scan result if possible
    let identity = umbra_core::identity::PodIdentity::gather();

    let report = SecurityScanReport {
        identity,
        tools: tool_results,
        summary,
        timestamp: chrono::Utc::now().to_rfc3339(),
        duration_ms,
    };

    serde_json::to_string_pretty(&report).unwrap()
}

struct TimedResult {
    result: Result<String, String>,
    duration_ms: u64,
}

async fn timed_call(
    pool: &ConnectionPool,
    connection_id: &str,
    tool: &str,
    args: Option<serde_json::Map<String, serde_json::Value>>,
) -> TimedResult {
    let start = std::time::Instant::now();
    let result = pool.call_tool(connection_id, tool, args).await.map_err(|e| e.to_string());
    TimedResult {
        result,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

fn parse_tool_result(tool_name: &str, timed: TimedResult) -> ToolScanResult {
    match timed.result {
        Ok(raw) => {
            let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap_or_default();

            // Check if tool reported unavailability
            let available = parsed
                .get("tool_available")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);

            let error = parsed
                .get("error")
                .and_then(|e| e.as_str())
                .map(|s| s.to_string());

            let success = error.is_none()
                && parsed
                    .get("success")
                    .and_then(|s| s.as_bool())
                    .unwrap_or(true);

            let findings = extract_findings(tool_name, &parsed);

            ToolScanResult {
                tool: tool_name.to_string(),
                success,
                available,
                duration_ms: timed.duration_ms,
                findings,
                raw_output: Some(raw),
                error,
            }
        }
        Err(e) => ToolScanResult {
            tool: tool_name.to_string(),
            success: false,
            available: true,
            duration_ms: timed.duration_ms,
            findings: vec![],
            raw_output: None,
            error: Some(e),
        },
    }
}

fn extract_findings(tool_name: &str, parsed: &serde_json::Value) -> Vec<ScanFinding> {
    let mut findings = Vec::new();

    match tool_name {
        "fast_scan" => {
            if let Some(ports) = parsed.get("open_ports").and_then(|p| p.as_array()) {
                for port in ports {
                    let p = port.get("port").and_then(|p| p.as_u64()).unwrap_or(0);
                    let svc = port
                        .get("service")
                        .and_then(|s| s.as_str())
                        .unwrap_or("unknown");
                    findings.push(ScanFinding {
                        tool: tool_name.into(),
                        id: format!("PORT-{p}"),
                        title: format!("Open port {p}/{svc}"),
                        severity: umbra_core::assessment::Severity::Info,
                        category: "network".into(),
                        description: format!("Port {p} is open running {svc}"),
                        evidence: vec![format!("{p}/tcp open {svc}")],
                        remediation: None,
                        metadata: Default::default(),
                    });
                }
            }
        }
        "secret_scan" => {
            if let Some(secrets) = parsed.get("secrets").and_then(|s| s.as_array()) {
                for (i, secret) in secrets.iter().enumerate() {
                    let rule = secret
                        .get("rule_name")
                        .and_then(|r| r.as_str())
                        .unwrap_or("unknown");
                    let path = secret
                        .get("path")
                        .and_then(|p| p.as_str())
                        .unwrap_or("");
                    findings.push(ScanFinding {
                        tool: tool_name.into(),
                        id: format!("SECRET-{}", i + 1),
                        title: format!("Secret detected: {rule}"),
                        severity: umbra_core::assessment::Severity::High,
                        category: "secrets".into(),
                        description: format!("{rule} found in {path}"),
                        evidence: vec![format!("rule={rule} path={path}")],
                        remediation: Some(
                            "Remove secrets from filesystem. Use K8s Secret volumes or environment injection."
                                .into(),
                        ),
                        metadata: Default::default(),
                    });
                }
            }
        }
        "jwt_decode" => {
            if let Some(expiry) = parsed.get("expiry") {
                if expiry.get("expired").and_then(|e| e.as_bool()) == Some(true) {
                    findings.push(ScanFinding {
                        tool: tool_name.into(),
                        id: "JWT-EXPIRED".into(),
                        title: "JWT token is expired".into(),
                        severity: umbra_core::assessment::Severity::Medium,
                        category: "authentication".into(),
                        description: "The JWT token has expired".into(),
                        evidence: vec![],
                        remediation: Some("Rotate the expired token".into()),
                        metadata: Default::default(),
                    });
                }
            }
        }
        "container_audit" => {
            if let Some(vulns) = parsed.get("vulnerabilities").and_then(|v| v.as_array()) {
                for vuln in vulns.iter().take(50) {
                    let cve = vuln
                        .get("vulnerability_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let sev_str = vuln
                        .get("severity")
                        .and_then(|s| s.as_str())
                        .unwrap_or("unknown");
                    let pkg = vuln
                        .get("package")
                        .and_then(|p| p.as_str())
                        .unwrap_or("");
                    let title_str = vuln
                        .get("title")
                        .and_then(|t| t.as_str())
                        .unwrap_or("");

                    let severity = match sev_str.to_uppercase().as_str() {
                        "CRITICAL" => umbra_core::assessment::Severity::Critical,
                        "HIGH" => umbra_core::assessment::Severity::High,
                        "MEDIUM" => umbra_core::assessment::Severity::Medium,
                        "LOW" => umbra_core::assessment::Severity::Low,
                        _ => umbra_core::assessment::Severity::Info,
                    };

                    findings.push(ScanFinding {
                        tool: tool_name.into(),
                        id: cve.to_string(),
                        title: format!("{cve}: {title_str}"),
                        severity,
                        category: "cve".into(),
                        description: format!("CVE in package {pkg}"),
                        evidence: vec![format!("package={pkg}")],
                        remediation: Some(format!(
                            "Update {pkg} to fixed version: {}",
                            vuln.get("fixed_version")
                                .and_then(|f| f.as_str())
                                .unwrap_or("N/A")
                        )),
                        metadata: Default::default(),
                    });
                }
            }
        }
        "vuln_scan" => {
            if let Some(nuclei_findings) = parsed.get("findings").and_then(|f| f.as_array()) {
                for finding in nuclei_findings.iter().take(50) {
                    let template_id = finding
                        .get("template_id")
                        .and_then(|t| t.as_str())
                        .unwrap_or("unknown");
                    let name = finding
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("");
                    let sev_str = finding
                        .get("severity")
                        .and_then(|s| s.as_str())
                        .unwrap_or("info");

                    let severity = match sev_str.to_lowercase().as_str() {
                        "critical" => umbra_core::assessment::Severity::Critical,
                        "high" => umbra_core::assessment::Severity::High,
                        "medium" => umbra_core::assessment::Severity::Medium,
                        "low" => umbra_core::assessment::Severity::Low,
                        _ => umbra_core::assessment::Severity::Info,
                    };

                    findings.push(ScanFinding {
                        tool: tool_name.into(),
                        id: template_id.to_string(),
                        title: name.to_string(),
                        severity,
                        category: "vulnerability".into(),
                        description: finding
                            .get("description")
                            .and_then(|d| d.as_str())
                            .unwrap_or("")
                            .to_string(),
                        evidence: vec![finding
                            .get("matched_at")
                            .and_then(|m| m.as_str())
                            .unwrap_or("")
                            .to_string()],
                        remediation: None,
                        metadata: Default::default(),
                    });
                }
            }
        }
        "tls_audit" => {
            if let Some(vulns) = parsed.get("vulnerabilities").and_then(|v| v.as_array()) {
                for vuln in vulns {
                    let vulnerable = vuln
                        .get("vulnerable")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if vulnerable {
                        let vuln_id = vuln
                            .get("id")
                            .and_then(|i| i.as_str())
                            .unwrap_or("unknown");
                        let name = vuln
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("");
                        let sev_str = vuln
                            .get("severity")
                            .and_then(|s| s.as_str())
                            .unwrap_or("MEDIUM");

                        let severity = match sev_str.to_uppercase().as_str() {
                            "CRITICAL" => umbra_core::assessment::Severity::Critical,
                            "HIGH" => umbra_core::assessment::Severity::High,
                            "WARN" | "MEDIUM" => umbra_core::assessment::Severity::Medium,
                            "LOW" => umbra_core::assessment::Severity::Low,
                            _ => umbra_core::assessment::Severity::Info,
                        };

                        findings.push(ScanFinding {
                            tool: tool_name.into(),
                            id: format!("TLS-{vuln_id}"),
                            title: format!("TLS vulnerability: {vuln_id}"),
                            severity,
                            category: "tls".into(),
                            description: name.to_string(),
                            evidence: vec![],
                            remediation: Some(
                                "Update TLS configuration to disable vulnerable protocols/ciphers"
                                    .into(),
                            ),
                            metadata: Default::default(),
                        });
                    }
                }
            }
        }
        _ => {}
    }

    findings
}

fn extract_http_targets(tool_results: &[ToolScanResult], base_target: &str) -> Vec<String> {
    let mut targets = Vec::new();
    let http_ports = [80, 443, 8080, 8443, 3000, 4000, 5000, 8000, 8888, 9000, 9090];

    for result in tool_results {
        if result.tool == "fast_scan" {
            if let Some(ref raw) = result.raw_output {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(raw) {
                    if let Some(ports) = parsed.get("open_ports").and_then(|p| p.as_array()) {
                        // Get host from target (strip port if present)
                        let host = base_target.split(':').next().unwrap_or(base_target);
                        for port in ports {
                            let p = port.get("port").and_then(|p| p.as_u64()).unwrap_or(0) as u16;
                            if http_ports.contains(&p) || p >= 8000 {
                                let scheme = if p == 443 || p == 8443 {
                                    "https"
                                } else {
                                    "http"
                                };
                                targets.push(format!("{scheme}://{host}:{p}"));
                            }
                        }
                    }
                }
            }
        }
    }

    targets
}

fn build_summary(tool_results: &[ToolScanResult]) -> SecurityScanSummary {
    let mut summary = SecurityScanSummary {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        total_findings: 0,
        open_ports: 0,
        vulnerabilities: 0,
        secrets_found: 0,
        cves_found: 0,
    };

    for result in tool_results {
        for finding in &result.findings {
            summary.total_findings += 1;
            match finding.severity {
                umbra_core::assessment::Severity::Critical => summary.critical += 1,
                umbra_core::assessment::Severity::High => summary.high += 1,
                umbra_core::assessment::Severity::Medium => summary.medium += 1,
                umbra_core::assessment::Severity::Low => summary.low += 1,
                umbra_core::assessment::Severity::Info => summary.info += 1,
            }

            match finding.category.as_str() {
                "network" => summary.open_ports += 1,
                "secrets" => summary.secrets_found += 1,
                "cve" => summary.cves_found += 1,
                "vulnerability" | "tls" => summary.vulnerabilities += 1,
                _ => {}
            }
        }
    }

    summary
}
