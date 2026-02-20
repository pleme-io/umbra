use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct WebDiscoverResult {
    target: String,
    success: bool,
    endpoints: Vec<DiscoveredEndpoint>,
    total_found: usize,
    error: Option<String>,
}

#[derive(Serialize)]
struct DiscoveredEndpoint {
    url: String,
    status: u16,
    size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect: Option<String>,
}

pub async fn discover(
    target: &str,
    wordlist: Option<&str>,
    extensions: Option<&str>,
    depth: Option<u32>,
    timeout_secs: Option<u64>,
) -> String {
    if !cmd::is_available("feroxbuster").await {
        return cmd::binary_not_found("feroxbuster", None);
    }

    let timeout = timeout_secs.unwrap_or(60);
    let depth_val = depth.unwrap_or(2).min(5).to_string();

    let mut args = vec![
        "-u",
        target,
        "-d",
        &depth_val,
        "--silent",
        "--json",
        "--no-state",
        "--auto-tune",
    ];

    if let Some(wl) = wordlist {
        args.extend(["-w", wl]);
    }

    let ext_str;
    if let Some(ext) = extensions {
        ext_str = ext.to_string();
        args.extend(["-x", &ext_str]);
    }

    let result = cmd::run("feroxbuster", &args, timeout).await;

    if !result.success && result.stdout.is_empty() {
        return serde_json::to_string_pretty(&WebDiscoverResult {
            target: target.to_string(),
            success: false,
            endpoints: vec![],
            total_found: 0,
            error: Some(result.stderr.trim().to_string()),
        })
        .unwrap();
    }

    let mut endpoints = Vec::new();
    for line in result.stdout.lines() {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            if val.get("type").and_then(|t| t.as_str()) == Some("response") {
                let url = val
                    .get("url")
                    .and_then(|u| u.as_str())
                    .unwrap_or("")
                    .to_string();
                let status = val
                    .get("status")
                    .and_then(|s| s.as_u64())
                    .unwrap_or(0) as u16;
                let size = val
                    .get("content_length")
                    .and_then(|s| s.as_u64());
                let redirect = val
                    .get("redirect_url")
                    .and_then(|r| r.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string());

                if !url.is_empty() {
                    endpoints.push(DiscoveredEndpoint {
                        url,
                        status,
                        size,
                        redirect,
                    });
                }
            }
        }
    }

    let total = endpoints.len();
    // Cap output
    if endpoints.len() > 200 {
        endpoints.truncate(200);
    }

    serde_json::to_string_pretty(&WebDiscoverResult {
        target: target.to_string(),
        success: true,
        endpoints,
        total_found: total,
        error: None,
    })
    .unwrap()
}
