use crate::cmd;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct VulnScanResult {
    target: String,
    success: bool,
    findings: Vec<NucleiFinding>,
    total_found: usize,
    truncated: bool,
    error: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct NucleiFinding {
    #[serde(default)]
    template_id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    r#type: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    matched_at: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    reference: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
}

const MAX_FINDINGS: usize = 100;

pub async fn scan(
    target: &str,
    templates: Option<&str>,
    severity: Option<&str>,
    rate_limit: Option<u32>,
    timeout_secs: Option<u64>,
) -> String {
    if !cmd::is_available("nuclei").await {
        return cmd::binary_not_found("nuclei", None);
    }

    let timeout = timeout_secs.unwrap_or(120);
    let rate = rate_limit.unwrap_or(50).to_string();

    let mut args = vec![
        "-u",
        target,
        "-jsonl",
        "-silent",
        "-rate-limit",
        &rate,
        "-no-color",
    ];

    if let Some(t) = templates {
        args.extend(["-t", t]);
    }

    let sev_str;
    if let Some(s) = severity {
        sev_str = s.to_string();
        args.extend(["-severity", &sev_str]);
    }

    let result = cmd::run("nuclei", &args, timeout).await;

    if !result.success && result.stdout.is_empty() {
        return serde_json::to_string_pretty(&VulnScanResult {
            target: target.to_string(),
            success: false,
            findings: vec![],
            total_found: 0,
            truncated: false,
            error: Some(result.stderr.trim().to_string()),
        })
        .unwrap();
    }

    let mut findings = Vec::new();
    for line in result.stdout.lines() {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            let template_id = val
                .get("template-id")
                .or_else(|| val.get("templateID"))
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();

            let info = val.get("info").cloned().unwrap_or_default();

            let name = info
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();

            let severity = info
                .get("severity")
                .and_then(|s| s.as_str())
                .unwrap_or("unknown")
                .to_string();

            let description = info
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_string();

            let reference = info
                .get("reference")
                .and_then(|r| r.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            let tags = info
                .get("tags")
                .and_then(|t| {
                    if let Some(arr) = t.as_array() {
                        Some(
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect(),
                        )
                    } else if let Some(s) = t.as_str() {
                        Some(s.split(',').map(|s| s.trim().to_string()).collect())
                    } else {
                        None
                    }
                })
                .unwrap_or_default();

            let host = val
                .get("host")
                .and_then(|h| h.as_str())
                .unwrap_or("")
                .to_string();

            let matched_at = val
                .get("matched-at")
                .or_else(|| val.get("matchedAt"))
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_string();

            let r#type = val
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();

            findings.push(NucleiFinding {
                template_id,
                name,
                severity,
                r#type,
                host,
                matched_at,
                description,
                reference,
                tags,
            });
        }
    }

    let total = findings.len();
    let truncated = total > MAX_FINDINGS;
    if truncated {
        findings.truncate(MAX_FINDINGS);
    }

    serde_json::to_string_pretty(&VulnScanResult {
        target: target.to_string(),
        success: true,
        findings,
        total_found: total,
        truncated,
        error: None,
    })
    .unwrap()
}
