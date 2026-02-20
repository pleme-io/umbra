use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct FastScanResult {
    target: String,
    tool: String,
    success: bool,
    open_ports: Vec<PortEntry>,
    scan_time_ms: Option<u64>,
    error: Option<String>,
}

#[derive(Serialize)]
struct PortEntry {
    port: u16,
    protocol: String,
    service: String,
}

pub async fn scan(target: &str, ports: Option<&str>, timeout_secs: Option<u64>) -> String {
    let timeout = timeout_secs.unwrap_or(30);

    // Try rustscan first, fall back to nmap
    if cmd::is_available("rustscan").await {
        run_rustscan(target, ports, timeout).await
    } else if cmd::is_available("nmap").await {
        run_nmap(target, ports, timeout).await
    } else {
        cmd::binary_not_found("rustscan", Some("nmap"))
    }
}

async fn run_rustscan(target: &str, ports: Option<&str>, timeout: u64) -> String {
    let mut args = vec!["-a", target, "--greppable", "--"];

    if let Some(p) = ports {
        args.extend(["-p", p]);
    }

    let start = std::time::Instant::now();
    let result = cmd::run("rustscan", &args, timeout).await;
    let elapsed = start.elapsed().as_millis() as u64;

    if !result.success {
        return serde_json::to_string_pretty(&FastScanResult {
            target: target.to_string(),
            tool: "rustscan".into(),
            success: false,
            open_ports: vec![],
            scan_time_ms: Some(elapsed),
            error: Some(result.stderr.trim().to_string()),
        })
        .unwrap();
    }

    let open_ports = parse_rustscan_output(&result.stdout);

    serde_json::to_string_pretty(&FastScanResult {
        target: target.to_string(),
        tool: "rustscan".into(),
        success: true,
        open_ports,
        scan_time_ms: Some(elapsed),
        error: None,
    })
    .unwrap()
}

fn parse_rustscan_output(output: &str) -> Vec<PortEntry> {
    let mut ports = Vec::new();
    for line in output.lines() {
        // rustscan outputs "Open <host>:<port>"
        if let Some(rest) = line.strip_prefix("Open ") {
            if let Some(port_str) = rest.rsplit(':').next() {
                if let Ok(port) = port_str.parse::<u16>() {
                    ports.push(PortEntry {
                        port,
                        protocol: "tcp".into(),
                        service: guess_service(port),
                    });
                }
            }
        }
    }
    ports
}

async fn run_nmap(target: &str, ports: Option<&str>, timeout: u64) -> String {
    let mut args = vec!["-T4", "--open", "-oG", "-", "-sV", "--version-light"];

    if let Some(p) = ports {
        args.push("-p");
        args.push(p);
    } else {
        args.push("-p-");
    }
    args.push(target);

    let start = std::time::Instant::now();
    let result = cmd::run("nmap", &args, timeout).await;
    let elapsed = start.elapsed().as_millis() as u64;

    if !result.success {
        return serde_json::to_string_pretty(&FastScanResult {
            target: target.to_string(),
            tool: "nmap".into(),
            success: false,
            open_ports: vec![],
            scan_time_ms: Some(elapsed),
            error: Some(result.stderr.trim().to_string()),
        })
        .unwrap();
    }

    let open_ports: Vec<PortEntry> = result
        .stdout
        .lines()
        .filter(|l| l.contains("Ports:"))
        .flat_map(|line| {
            if let Some(ports_section) = line.split("Ports: ").nth(1) {
                ports_section
                    .split(", ")
                    .filter_map(|entry| {
                        let parts: Vec<&str> = entry.split('/').collect();
                        if parts.len() >= 5 {
                            Some(PortEntry {
                                port: parts[0].parse().unwrap_or(0),
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

    serde_json::to_string_pretty(&FastScanResult {
        target: target.to_string(),
        tool: "nmap".into(),
        success: true,
        open_ports,
        scan_time_ms: Some(elapsed),
        error: None,
    })
    .unwrap()
}

fn guess_service(port: u16) -> String {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        445 => "smb",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5672 => "amqp",
        6379 => "redis",
        8080 => "http-alt",
        8443 => "https-alt",
        9092 => "kafka",
        27017 => "mongodb",
        _ => "unknown",
    }
    .into()
}
