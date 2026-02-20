use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct ScanResult {
    target: String,
    ports: Option<String>,
    success: bool,
    open_ports: Vec<PortInfo>,
    error: Option<String>,
}

#[derive(Serialize)]
struct PortInfo {
    port: u16,
    protocol: String,
    state: String,
    service: String,
}

pub async fn scan(target: &str, ports: Option<&str>) -> String {
    let mut args = vec!["-T4", "--open", "-oG", "-"];

    if let Some(p) = ports {
        args.push("-p");
        args.push(p);
    } else {
        // Scan common ports
        args.push("--top-ports");
        args.push("100");
    }
    args.push(target);

    let result = cmd::run("nmap", &args, 60).await;

    if !result.success {
        return serde_json::to_string_pretty(&ScanResult {
            target: target.to_string(),
            ports: ports.map(|p| p.to_string()),
            success: false,
            open_ports: vec![],
            error: Some(result.stderr.trim().to_string()),
        })
        .unwrap();
    }

    // Parse greppable output
    let open_ports: Vec<PortInfo> = result
        .stdout
        .lines()
        .filter(|l| l.contains("Ports:"))
        .flat_map(|line| {
            // Format: Host: 10.0.0.1 () Ports: 80/open/tcp//http///, 443/open/tcp//https///
            if let Some(ports_section) = line.split("Ports: ").nth(1) {
                ports_section
                    .split(", ")
                    .filter_map(|entry| {
                        let parts: Vec<&str> = entry.split('/').collect();
                        if parts.len() >= 5 {
                            Some(PortInfo {
                                port: parts[0].parse().unwrap_or(0),
                                state: parts[1].to_string(),
                                protocol: parts[2].to_string(),
                                service: parts[4].to_string(),
                            })
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            } else {
                vec![]
            }
        })
        .collect();

    serde_json::to_string_pretty(&ScanResult {
        target: target.to_string(),
        ports: ports.map(|p| p.to_string()),
        success: true,
        open_ports,
        error: None,
    })
    .unwrap()
}
