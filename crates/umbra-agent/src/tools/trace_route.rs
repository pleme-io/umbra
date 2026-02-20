use crate::cmd;

pub async fn trace(target: &str, max_hops: Option<u32>) -> String {
    let hops = max_hops.unwrap_or(20).to_string();
    let result = cmd::run(
        "mtr",
        &["--json", "--report", "--report-cycles", "3", "--max-ttl", &hops, target],
        30,
    )
    .await;

    if !result.success {
        return serde_json::json!({
            "target": target,
            "success": false,
            "error": result.stderr.trim(),
        })
        .to_string();
    }

    // mtr --json returns valid JSON directly
    match serde_json::from_str::<serde_json::Value>(&result.stdout) {
        Ok(json) => serde_json::json!({
            "target": target,
            "success": true,
            "report": json,
        })
        .to_string(),
        Err(_) => {
            // Fallback: return raw output
            serde_json::json!({
                "target": target,
                "success": true,
                "raw": result.stdout.trim(),
            })
            .to_string()
        }
    }
}
