use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct BandwidthResult {
    target: String,
    duration_secs: u64,
    direction: String,
    result: Option<serde_json::Value>,
    success: bool,
    error: Option<String>,
}

pub async fn test(target: &str, duration: Option<u64>, reverse: bool) -> String {
    let dur = duration.unwrap_or(5).min(30);
    let dur_str = dur.to_string();

    let mut args: Vec<&str> = vec!["-c", target, "-t", &dur_str, "--json"];

    if reverse {
        args.push("-R"); // reverse: server sends, client receives
    }

    let result = cmd::run("iperf3", &args, dur + 10).await;

    if !result.success {
        return serde_json::to_string_pretty(&BandwidthResult {
            target: target.to_string(),
            duration_secs: dur,
            direction: if reverse { "download" } else { "upload" }.to_string(),
            result: None,
            success: false,
            error: Some(result.stderr.trim().to_string()),
        })
        .unwrap();
    }

    let json_result = serde_json::from_str::<serde_json::Value>(&result.stdout).ok();

    serde_json::to_string_pretty(&BandwidthResult {
        target: target.to_string(),
        duration_secs: dur,
        direction: if reverse { "download" } else { "upload" }.to_string(),
        result: json_result,
        success: true,
        error: None,
    })
    .unwrap()
}
