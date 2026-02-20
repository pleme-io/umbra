use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct CaptureResult {
    interface: String,
    filter: Option<String>,
    duration_secs: u64,
    max_packets: u32,
    packets: Vec<String>,
    packet_count: usize,
    success: bool,
    error: Option<String>,
}

pub async fn capture(
    interface: Option<&str>,
    filter: Option<&str>,
    duration_secs: Option<u64>,
    max_packets: Option<u32>,
) -> String {
    let iface = interface.unwrap_or("any");
    let duration = duration_secs.unwrap_or(5).min(30); // cap at 30s
    let count = max_packets.unwrap_or(50).min(200); // cap at 200 packets
    let count_str = count.to_string();

    let mut args: Vec<&str> = vec![
        "-i", iface,
        "-c", &count_str,
        "-nn",       // don't resolve names
        "-l",        // line-buffered
        "--immediate-mode",
    ];

    if let Some(f) = filter {
        args.push(f);
    }

    let result = cmd::run("tcpdump", &args, duration + 5).await;

    let packets: Vec<String> = result
        .stdout
        .lines()
        .filter(|l| !l.is_empty() && !l.contains("packets captured") && !l.contains("packets received"))
        .map(|l| l.to_string())
        .collect();

    let packet_count = packets.len();

    serde_json::to_string_pretty(&CaptureResult {
        interface: iface.to_string(),
        filter: filter.map(|f| f.to_string()),
        duration_secs: duration,
        max_packets: count,
        packets,
        packet_count,
        success: result.success || packet_count > 0,
        error: if result.success || packet_count > 0 {
            None
        } else {
            Some(result.stderr.trim().to_string())
        },
    })
    .unwrap()
}
