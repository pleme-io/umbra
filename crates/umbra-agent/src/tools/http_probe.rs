use crate::cmd;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct HttpProbeResult {
    success: bool,
    probes: Vec<ProbeEntry>,
    total: usize,
    error: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ProbeEntry {
    #[serde(default)]
    url: String,
    #[serde(default, alias = "status-code", alias = "status_code")]
    status_code: Option<u16>,
    #[serde(default, alias = "content-length", alias = "content_length")]
    content_length: Option<u64>,
    #[serde(default)]
    title: String,
    #[serde(default)]
    webserver: String,
    #[serde(default)]
    tech: Vec<String>,
    #[serde(default, alias = "content-type", alias = "content_type")]
    content_type: String,
    #[serde(default)]
    scheme: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    port: String,
}

pub async fn probe(targets: &[String], timeout_secs: Option<u64>) -> String {
    if !cmd::is_available("httpx").await {
        return cmd::binary_not_found("httpx", None);
    }

    if targets.is_empty() {
        return serde_json::json!({
            "error": "No targets provided",
            "success": false,
        })
        .to_string();
    }

    let timeout = timeout_secs.unwrap_or(30);
    let input = targets.join("\n");

    let args = [
        "-json",
        "-silent",
        "-no-color",
        "-title",
        "-web-server",
        "-tech-detect",
        "-status-code",
        "-content-length",
        "-content-type",
    ];

    let result = cmd::run_with_stdin("httpx", &args, &input, timeout).await;

    if !result.success && result.stdout.is_empty() {
        return serde_json::to_string_pretty(&HttpProbeResult {
            success: false,
            probes: vec![],
            total: 0,
            error: Some(result.stderr.trim().to_string()),
        })
        .unwrap();
    }

    let mut probes = Vec::new();
    for line in result.stdout.lines() {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            let url = val
                .get("url")
                .and_then(|u| u.as_str())
                .unwrap_or("")
                .to_string();
            let status_code = val
                .get("status-code")
                .or_else(|| val.get("status_code"))
                .and_then(|s| s.as_u64())
                .map(|s| s as u16);
            let content_length = val
                .get("content-length")
                .or_else(|| val.get("content_length"))
                .and_then(|c| c.as_u64());
            let title = val
                .get("title")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            let webserver = val
                .get("webserver")
                .and_then(|w| w.as_str())
                .unwrap_or("")
                .to_string();
            let tech = val
                .get("tech")
                .and_then(|t| t.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let content_type = val
                .get("content-type")
                .or_else(|| val.get("content_type"))
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();
            let scheme = val
                .get("scheme")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let host = val
                .get("host")
                .and_then(|h| h.as_str())
                .unwrap_or("")
                .to_string();
            let port = val
                .get("port")
                .and_then(|p| {
                    p.as_str()
                        .map(|s| s.to_string())
                        .or_else(|| p.as_u64().map(|n| n.to_string()))
                })
                .unwrap_or_default();

            if !url.is_empty() {
                probes.push(ProbeEntry {
                    url,
                    status_code,
                    content_length,
                    title,
                    webserver,
                    tech,
                    content_type,
                    scheme,
                    host,
                    port,
                });
            }
        }
    }

    let total = probes.len();

    serde_json::to_string_pretty(&HttpProbeResult {
        success: true,
        probes,
        total,
        error: None,
    })
    .unwrap()
}
