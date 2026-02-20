use std::time::Instant;
use tokio::net::TcpStream;
use umbra_core::TcpProbeResult;

/// Test TCP connectivity to a host:port with a 3-second timeout.
pub async fn connect(host: &str, port: u16) -> TcpProbeResult {
    let start = Instant::now();
    let addr = format!("{host}:{port}");

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        TcpStream::connect(&addr),
    )
    .await;

    match result {
        Ok(Ok(_)) => TcpProbeResult {
            host: host.to_string(),
            port,
            success: true,
            error: None,
            latency_ms: start.elapsed().as_millis() as u64,
        },
        Ok(Err(e)) => TcpProbeResult {
            host: host.to_string(),
            port,
            success: false,
            error: Some(e.to_string()),
            latency_ms: start.elapsed().as_millis() as u64,
        },
        Err(_) => TcpProbeResult {
            host: host.to_string(),
            port,
            success: false,
            error: Some("TCP connect timed out (3s)".to_string()),
            latency_ms: start.elapsed().as_millis() as u64,
        },
    }
}
