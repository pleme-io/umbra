use std::time::Instant;
use umbra_core::HttpProbeResult;

const HEALTH_PATHS: &[&str] = &["/healthz", "/health", "/ready", "/readyz", "/"];

/// Probe HTTP health endpoints on a host:port.
/// Tries common health paths and returns the first non-error response.
pub async fn probe(host: &str, port: u16) -> HttpProbeResult {
    let start = Instant::now();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    for path in HEALTH_PATHS {
        let url = format!("http://{host}:{port}{path}");
        match client.get(&url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                return HttpProbeResult {
                    url,
                    status_code: Some(status),
                    success: status < 500,
                    error: None,
                    latency_ms: start.elapsed().as_millis() as u64,
                };
            }
            Err(e) if e.is_connect() || e.is_timeout() => {
                // Try next path
                continue;
            }
            Err(e) => {
                return HttpProbeResult {
                    url,
                    status_code: None,
                    success: false,
                    error: Some(e.to_string()),
                    latency_ms: start.elapsed().as_millis() as u64,
                };
            }
        }
    }

    HttpProbeResult {
        url: format!("http://{host}:{port}"),
        status_code: None,
        success: false,
        error: Some("No health endpoint responded".to_string()),
        latency_ms: start.elapsed().as_millis() as u64,
    }
}
