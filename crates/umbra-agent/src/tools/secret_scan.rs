use crate::cmd;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct SecretScanResult {
    target: String,
    success: bool,
    secrets: Vec<SecretMatch>,
    total_found: usize,
    error: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct SecretMatch {
    rule_name: String,
    #[serde(default)]
    severity: String,
    path: String,
    #[serde(default)]
    line: Option<u64>,
    snippet: String,
}

pub async fn scan(path: Option<&str>, timeout_secs: Option<u64>) -> String {
    if !cmd::is_available("noseyparker").await {
        return cmd::binary_not_found("noseyparker", None);
    }

    let timeout = timeout_secs.unwrap_or(60);
    let scan_path = path.unwrap_or("/");
    let datastore = format!("/tmp/np-{}", uuid_v4());

    // Run scan phase
    let scan_result = cmd::run(
        "noseyparker",
        &["scan", "--datastore", &datastore, scan_path],
        timeout,
    )
    .await;

    if !scan_result.success {
        cleanup_datastore(&datastore).await;
        return serde_json::to_string_pretty(&SecretScanResult {
            target: scan_path.to_string(),
            success: false,
            secrets: vec![],
            total_found: 0,
            error: Some(scan_result.stderr.trim().to_string()),
        })
        .unwrap();
    }

    // Report phase — extract findings as JSONL
    let report_result = cmd::run(
        "noseyparker",
        &["report", "--datastore", &datastore, "--format", "jsonl"],
        30,
    )
    .await;

    cleanup_datastore(&datastore).await;

    if !report_result.success && report_result.stdout.is_empty() {
        return serde_json::to_string_pretty(&SecretScanResult {
            target: scan_path.to_string(),
            success: false,
            secrets: vec![],
            total_found: 0,
            error: Some(report_result.stderr.trim().to_string()),
        })
        .unwrap();
    }

    let mut secrets = Vec::new();
    for line in report_result.stdout.lines() {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            let rule_name = val
                .get("rule_name")
                .or_else(|| val.get("ruleName"))
                .and_then(|r| r.as_str())
                .unwrap_or("unknown")
                .to_string();

            let matches = val.get("matches").and_then(|m| m.as_array());
            if let Some(match_arr) = matches {
                for m in match_arr {
                    let provenance = m.get("provenance");
                    let path = provenance
                        .and_then(|p| p.get("path"))
                        .and_then(|p| p.as_str())
                        .unwrap_or("")
                        .to_string();
                    let line_num = m
                        .get("location")
                        .and_then(|l| l.get("source_span"))
                        .and_then(|s| s.get("start"))
                        .and_then(|s| s.get("line"))
                        .and_then(|l| l.as_u64());

                    let snippet = m
                        .get("snippet")
                        .and_then(|s| {
                            s.get("matching")
                                .or_else(|| s.get("before"))
                                .and_then(|v| v.as_str())
                        })
                        .unwrap_or("")
                        .to_string();

                    // Mask the snippet — show first 4 and last 2 chars
                    let masked = if snippet.len() > 8 {
                        format!("{}...{}", &snippet[..4], &snippet[snippet.len() - 2..])
                    } else if !snippet.is_empty() {
                        "****".to_string()
                    } else {
                        String::new()
                    };

                    secrets.push(SecretMatch {
                        rule_name: rule_name.clone(),
                        severity: "high".into(),
                        path,
                        line: line_num,
                        snippet: masked,
                    });
                }
            } else {
                // Flat format
                let path = val
                    .get("path")
                    .and_then(|p| p.as_str())
                    .unwrap_or("")
                    .to_string();
                let snippet = val
                    .get("match")
                    .and_then(|m| m.as_str())
                    .unwrap_or("****")
                    .to_string();
                let masked = if snippet.len() > 8 {
                    format!("{}...{}", &snippet[..4], &snippet[snippet.len() - 2..])
                } else {
                    "****".to_string()
                };

                secrets.push(SecretMatch {
                    rule_name,
                    severity: "high".into(),
                    path,
                    line: None,
                    snippet: masked,
                });
            }
        }
    }

    let total = secrets.len();

    serde_json::to_string_pretty(&SecretScanResult {
        target: scan_path.to_string(),
        success: true,
        secrets,
        total_found: total,
        error: None,
    })
    .unwrap()
}

async fn cleanup_datastore(path: &str) {
    let _ = cmd::run("rm", &["-rf", path], 5).await;
}

fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    format!("{nanos:x}-{pid:x}")
}
