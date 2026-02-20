use hickory_resolver::TokioResolver;
use std::net::IpAddr;
use std::time::Instant;
use umbra_core::DnsProbeResult;

/// Resolve a hostname to IP addresses using the system DNS configuration.
pub async fn resolve(hostname: &str) -> DnsProbeResult {
    let start = Instant::now();

    let builder = match TokioResolver::builder_tokio() {
        Ok(b) => b,
        Err(e) => {
            return DnsProbeResult {
                hostname: hostname.to_string(),
                addresses: vec![],
                success: false,
                error: Some(format!("Failed to create resolver: {e}")),
                latency_ms: start.elapsed().as_millis() as u64,
            };
        }
    };
    let resolver = builder.build();

    let lookup = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        resolver.lookup_ip(hostname),
    )
    .await;

    match lookup {
        Ok(Ok(response)) => {
            let addresses: Vec<String> = response
                .iter()
                .map(|ip: IpAddr| ip.to_string())
                .collect();
            let success = !addresses.is_empty();
            DnsProbeResult {
                hostname: hostname.to_string(),
                addresses,
                success,
                error: None,
                latency_ms: start.elapsed().as_millis() as u64,
            }
        }
        Ok(Err(e)) => DnsProbeResult {
            hostname: hostname.to_string(),
            addresses: vec![],
            success: false,
            error: Some(e.to_string()),
            latency_ms: start.elapsed().as_millis() as u64,
        },
        Err(_) => DnsProbeResult {
            hostname: hostname.to_string(),
            addresses: vec![],
            success: false,
            error: Some("DNS lookup timed out (3s)".to_string()),
            latency_ms: start.elapsed().as_millis() as u64,
        },
    }
}
