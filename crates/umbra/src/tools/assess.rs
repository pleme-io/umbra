use crate::pool::ConnectionPool;
use std::collections::HashMap;
use umbra_core::assessment::*;
use umbra_core::targets::TargetConfig;

/// Run a full assessment on a pod: network map + security audit + service type detection.
/// If `targets` are provided, they are passed to the deep probe for credentialed access.
pub async fn full_assessment(
    pool: &ConnectionPool,
    connection_id: Option<&str>,
    context: Option<&str>,
    namespace: Option<&str>,
    pod: Option<&str>,
    container: Option<&str>,
    targets: &[TargetConfig],
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

    // Build deep probe arguments with targets if provided
    let deep_probe_args = if targets.is_empty() {
        None
    } else {
        let args = serde_json::json!({"targets": targets});
        args.as_object().cloned()
    };

    // Run all four assessment tools in parallel via the agent
    let (network_result, security_result, types_result, deep_probe_result) = tokio::join!(
        pool.call_tool(&id, "network_map", None),
        pool.call_tool(&id, "security_audit", None),
        pool.call_tool(&id, "detect_all_service_types", None),
        pool.call_tool(&id, "service_deep_probe", deep_probe_args),
    );

    // Parse results — use as_ref() to avoid consuming the Results
    let network_map: Option<NetworkMap> = network_result
        .as_ref()
        .ok()
        .and_then(|r| serde_json::from_str(r).ok());

    let security: Option<SecurityReport> = security_result
        .as_ref()
        .ok()
        .and_then(|r| serde_json::from_str(r).ok());

    let types_report: Option<Vec<ServiceTypeResult>> =
        types_result.as_ref().ok().and_then(|r| {
            let parsed: serde_json::Value = serde_json::from_str(r).ok()?;
            parsed
                .get("results")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
        });

    // Deep probe is optional — assessment succeeds even if it fails
    let deep_probe: Option<DeepProbeReport> = deep_probe_result
        .as_ref()
        .ok()
        .and_then(|r| serde_json::from_str(r).ok());

    let duration_ms = start.elapsed().as_millis() as u64;

    // Build the full report
    match (network_map, security, types_report) {
        (Some(net), Some(mut sec), Some(types)) => {
            // Merge deep probe security findings into the main security report
            let service_health = if let Some(ref probe) = deep_probe {
                // Add deep probe findings to the security report
                for svc in &probe.services {
                    for finding in &svc.findings {
                        sec.findings.push(finding.clone());
                    }
                }
                // Recalculate security summary with merged findings
                sec.summary = build_security_summary(&sec.findings);

                probe.services.clone()
            } else {
                Vec::new()
            };

            let summary = build_summary(&net, &sec, &types);
            let report = AssessmentReport {
                id: format!(
                    "umbra-{}",
                    chrono::Utc::now().format("%Y%m%d-%H%M%S")
                ),
                version: "1.0".into(),
                source: net.source.clone(),
                network_map: net,
                security: sec,
                service_types: types,
                service_health,
                security_scan: None,
                summary,
                timestamp: chrono::Utc::now().to_rfc3339(),
                duration_ms,
            };
            serde_json::to_string_pretty(&report).unwrap()
        }
        _ => {
            let net_err = network_result
                .as_ref()
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "ok".into());
            let sec_err = security_result
                .as_ref()
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "ok".into());
            let types_err = types_result
                .as_ref()
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "ok".into());

            serde_json::json!({
                "error": "One or more assessment tools failed",
                "network_map_status": net_err,
                "security_audit_status": sec_err,
                "service_types_status": types_err,
                "duration_ms": duration_ms,
            })
            .to_string()
        }
    }
}

fn build_security_summary(findings: &[SecurityFinding]) -> SecuritySummary {
    let mut summary = SecuritySummary {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        total: findings.len(),
        score: 100,
    };

    for f in findings {
        match f.severity {
            Severity::Critical => {
                summary.critical += 1;
                summary.score = summary.score.saturating_sub(25);
            }
            Severity::High => {
                summary.high += 1;
                summary.score = summary.score.saturating_sub(15);
            }
            Severity::Medium => {
                summary.medium += 1;
                summary.score = summary.score.saturating_sub(8);
            }
            Severity::Low => {
                summary.low += 1;
                summary.score = summary.score.saturating_sub(3);
            }
            Severity::Info => {
                summary.info += 1;
            }
        }
    }

    summary
}

fn build_summary(
    net: &NetworkMap,
    sec: &SecurityReport,
    types: &[ServiceTypeResult],
) -> AssessmentSummary {
    let mut breakdown: HashMap<String, usize> = HashMap::new();
    let mut protocols = ProtocolSummary {
        rest: 0,
        graphql: 0,
        grpc: 0,
        websocket: 0,
        database: 0,
        message_queue: 0,
        static_files: 0,
        unknown: 0,
    };

    for t in types {
        let label = t.service_type.label().to_string();
        *breakdown.entry(label).or_insert(0) += 1;

        match &t.service_type {
            ServiceType::Rest => protocols.rest += 1,
            ServiceType::GraphQL => protocols.graphql += 1,
            ServiceType::Grpc => protocols.grpc += 1,
            ServiceType::WebSocket => protocols.websocket += 1,
            ServiceType::Database(_) => protocols.database += 1,
            ServiceType::MessageQueue(_) => protocols.message_queue += 1,
            ServiceType::StaticFiles => protocols.static_files += 1,
            ServiceType::Unknown => protocols.unknown += 1,
        }
    }

    let tls_count = types.iter().filter(|t| t.tls).count();
    let reachable = types.iter().filter(|t| t.reachable).count();
    let tls_coverage = if reachable > 0 {
        (tls_count as f32 / reachable as f32) * 100.0
    } else {
        0.0
    };

    AssessmentSummary {
        total_services: net.total_services,
        reachable_services: net.reachable,
        service_type_breakdown: breakdown,
        security_score: sec.summary.score,
        tls_coverage_percent: tls_coverage,
        protocols,
    }
}
