use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct SocketEntry {
    protocol: String,
    state: String,
    local_addr: String,
    local_port: String,
    remote_addr: String,
    remote_port: String,
    process: Option<String>,
}

#[derive(Serialize)]
struct SocketListResult {
    filter: String,
    sockets: Vec<SocketEntry>,
    total: usize,
    success: bool,
    error: Option<String>,
}

pub async fn list(filter: Option<&str>) -> String {
    let state_filter = filter.unwrap_or("all");

    let mut args = vec!["-tunp", "-H", "-O"];
    match state_filter {
        "listening" => args.push("-l"),
        "established" => {
            args.push("state");
            args.push("established");
        }
        _ => args.push("-a"),
    }

    let result = cmd::run("ss", &args, 10).await;

    if !result.success {
        return serde_json::to_string_pretty(&SocketListResult {
            filter: state_filter.to_string(),
            sockets: vec![],
            total: 0,
            success: false,
            error: Some(result.stderr.trim().to_string()),
        })
        .unwrap();
    }

    let sockets: Vec<SocketEntry> = result
        .stdout
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                let (local_addr, local_port) = split_addr(parts[3]);
                let (remote_addr, remote_port) = split_addr(parts[4]);
                let process = parts.get(5).map(|s| s.to_string());
                Some(SocketEntry {
                    protocol: parts[0].to_string(),
                    state: parts[1].to_string(),
                    local_addr,
                    local_port,
                    remote_addr,
                    remote_port,
                    process,
                })
            } else {
                None
            }
        })
        .collect();

    let total = sockets.len();
    serde_json::to_string_pretty(&SocketListResult {
        filter: state_filter.to_string(),
        sockets,
        total,
        success: true,
        error: None,
    })
    .unwrap()
}

fn split_addr(addr: &str) -> (String, String) {
    if let Some(pos) = addr.rfind(':') {
        (addr[..pos].to_string(), addr[pos + 1..].to_string())
    } else {
        (addr.to_string(), "*".to_string())
    }
}
