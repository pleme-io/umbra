use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct LoadTestResult {
    target: String,
    success: bool,
    summary: Option<LoadSummary>,
    latency: Option<LatencyStats>,
    status_codes: Option<serde_json::Value>,
    error: Option<String>,
}

#[derive(Serialize)]
struct LoadSummary {
    total_requests: u64,
    success_count: u64,
    error_count: u64,
    requests_per_sec: f64,
    duration_secs: f64,
}

#[derive(Serialize)]
struct LatencyStats {
    avg_ms: f64,
    p50_ms: f64,
    p90_ms: f64,
    p99_ms: f64,
    max_ms: f64,
    min_ms: f64,
}

pub async fn test(
    target: &str,
    concurrency: Option<u32>,
    duration_secs: Option<u64>,
    requests: Option<u64>,
    method: Option<&str>,
    timeout_secs: Option<u64>,
) -> String {
    if !cmd::is_available("oha").await {
        return cmd::binary_not_found("oha", None);
    }

    let timeout = timeout_secs.unwrap_or(65);
    let conc = concurrency.unwrap_or(5).min(50).to_string();
    let dur = duration_secs.unwrap_or(10).min(60);
    let dur_str = format!("{dur}s");

    let mut args = vec!["-j", "--no-tui", "-c", &conc];

    let n_str = requests.map(|n| n.to_string());
    if let Some(ref ns) = n_str {
        args.extend(["-n", ns.as_str()]);
    } else {
        args.extend(["-z", &dur_str]);
    }

    let method_str = method.map(|m| m.to_uppercase());
    if let Some(ref ms) = method_str {
        args.extend(["-m", ms.as_str()]);
    }

    args.push(target);

    let result = cmd::run("oha", &args, timeout).await;

    if !result.success {
        return serde_json::to_string_pretty(&LoadTestResult {
            target: target.to_string(),
            success: false,
            summary: None,
            latency: None,
            status_codes: None,
            error: Some(result.stderr.trim().to_string()),
        })
        .unwrap();
    }

    // Parse oha JSON output
    let parsed: serde_json::Value = match serde_json::from_str(&result.stdout) {
        Ok(v) => v,
        Err(_) => {
            return serde_json::to_string_pretty(&LoadTestResult {
                target: target.to_string(),
                success: true,
                summary: None,
                latency: None,
                status_codes: None,
                error: Some("Could not parse oha output as JSON".into()),
            })
            .unwrap();
        }
    };

    let summary_data = parsed.get("summary");

    let summary = summary_data.map(|s| {
        let _success_rate = s
            .get("successRate")
            .and_then(|sr| sr.as_f64())
            .unwrap_or(0.0);
        let rps = s
            .get("requestsPerSec")
            .and_then(|r| r.as_f64())
            .unwrap_or(0.0);
        let duration = s.get("total").and_then(|t| t.as_f64()).unwrap_or(0.0);
        let success = s
            .get("successCount")
            .and_then(|sc| sc.as_u64())
            .unwrap_or(0);
        let total_req = s
            .get("requestCount")
            .and_then(|rc| rc.as_u64())
            .unwrap_or(0);

        LoadSummary {
            total_requests: total_req,
            success_count: success,
            error_count: total_req.saturating_sub(success),
            requests_per_sec: rps,
            duration_secs: duration,
        }
    });

    let latency = parsed.get("responseTimeHistogram").and_then(|h| {
        let percentiles = parsed.get("latencyPercentiles");
        let p50 = get_percentile(percentiles, "p50");
        let p90 = get_percentile(percentiles, "p90");
        let p99 = get_percentile(percentiles, "p99");

        Some(LatencyStats {
            avg_ms: h
                .get("average")
                .and_then(|a| a.as_f64())
                .unwrap_or(0.0)
                * 1000.0,
            p50_ms: p50 * 1000.0,
            p90_ms: p90 * 1000.0,
            p99_ms: p99 * 1000.0,
            max_ms: h.get("max").and_then(|m| m.as_f64()).unwrap_or(0.0) * 1000.0,
            min_ms: h.get("min").and_then(|m| m.as_f64()).unwrap_or(0.0) * 1000.0,
        })
    });

    let status_codes = parsed.get("statusCodeDistribution").cloned();

    serde_json::to_string_pretty(&LoadTestResult {
        target: target.to_string(),
        success: true,
        summary,
        latency,
        status_codes,
        error: None,
    })
    .unwrap()
}

fn get_percentile(percentiles: Option<&serde_json::Value>, name: &str) -> f64 {
    percentiles
        .and_then(|p| p.get(name))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0)
}
