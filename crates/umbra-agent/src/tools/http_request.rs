use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct HttpResponse {
    url: String,
    method: String,
    status_code: Option<u16>,
    headers: Vec<(String, String)>,
    body: String,
    timing: Option<HttpTiming>,
    success: bool,
    error: Option<String>,
}

#[derive(Serialize)]
struct HttpTiming {
    dns_ms: f64,
    connect_ms: f64,
    tls_ms: f64,
    first_byte_ms: f64,
    total_ms: f64,
}

pub async fn request(
    url: &str,
    method: Option<&str>,
    headers: Option<&[String]>,
    body: Option<&str>,
    follow_redirects: bool,
) -> String {
    let method = method.unwrap_or("GET");

    let mut args: Vec<String> = vec![
        "-s".to_string(),
        "-S".to_string(),
        "-D".to_string(),
        "-".to_string(), // dump headers to stdout
        "-o".to_string(),
        "/dev/stderr".to_string(), // body to stderr so we can separate
        "-w".to_string(),
        r#"{"dns":%{time_namelookup},"connect":%{time_connect},"tls":%{time_appconnect},"first_byte":%{time_starttransfer},"total":%{time_total},"status":%{http_code}}"#.to_string(),
        "-X".to_string(),
        method.to_string(),
    ];

    if follow_redirects {
        args.push("-L".to_string());
    }

    if let Some(hdrs) = headers {
        for h in hdrs {
            args.push("-H".to_string());
            args.push(h.clone());
        }
    }

    if let Some(b) = body {
        args.push("-d".to_string());
        args.push(b.to_string());
    }

    args.push(url.to_string());

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = cmd::run("curl", &arg_refs, 30).await;

    // stdout has: HTTP headers + timing JSON
    // stderr has: body
    let stdout = &result.stdout;
    let body_text = result.stderr.clone();

    // Find the timing JSON (last line of stdout)
    let lines: Vec<&str> = stdout.lines().collect();

    let mut response_headers = Vec::new();
    let mut timing = None;
    let mut status_code = None;

    for line in &lines {
        let trimmed = line.trim();
        if trimmed.starts_with('{') && trimmed.contains("\"dns\"") {
            if let Ok(t) = serde_json::from_str::<serde_json::Value>(trimmed) {
                status_code = t["status"].as_u64().map(|s| s as u16);
                timing = Some(HttpTiming {
                    dns_ms: t["dns"].as_f64().unwrap_or(0.0) * 1000.0,
                    connect_ms: t["connect"].as_f64().unwrap_or(0.0) * 1000.0,
                    tls_ms: t["tls"].as_f64().unwrap_or(0.0) * 1000.0,
                    first_byte_ms: t["first_byte"].as_f64().unwrap_or(0.0) * 1000.0,
                    total_ms: t["total"].as_f64().unwrap_or(0.0) * 1000.0,
                });
            }
        } else if trimmed.contains(':') && !trimmed.starts_with("HTTP/") {
            if let Some((k, v)) = trimmed.split_once(':') {
                response_headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
    }

    // Truncate body if very large
    let body_truncated = if body_text.len() > 8192 {
        format!("{}... [truncated, {} bytes total]", &body_text[..8192], body_text.len())
    } else {
        body_text
    };

    serde_json::to_string_pretty(&HttpResponse {
        url: url.to_string(),
        method: method.to_string(),
        status_code,
        headers: response_headers,
        body: body_truncated,
        timing,
        success: result.success,
        error: if result.success { None } else { Some(result.stderr.trim().to_string()) },
    })
    .unwrap()
}
