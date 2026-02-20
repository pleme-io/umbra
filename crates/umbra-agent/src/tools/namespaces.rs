use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct NamespaceEntry {
    ns_type: String,
    nsinodes: String,
    pid: String,
    user: String,
    command: String,
}

#[derive(Serialize)]
struct NamespaceResult {
    pid_filter: Option<u32>,
    namespaces: Vec<NamespaceEntry>,
    total: usize,
    success: bool,
    error: Option<String>,
}

pub async fn list(pid: Option<u32>) -> String {
    let mut args: Vec<String> = vec!["-n".to_string()]; // numeric output

    if let Some(p) = pid {
        args.push("-p".to_string());
        args.push(p.to_string());
    }

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = cmd::run("lsns", &arg_refs, 10).await;

    if !result.success {
        return serde_json::to_string_pretty(&NamespaceResult {
            pid_filter: pid,
            namespaces: vec![],
            total: 0,
            success: false,
            error: Some(result.stderr.trim().to_string()),
        })
        .unwrap();
    }

    let namespaces: Vec<NamespaceEntry> = result
        .stdout
        .lines()
        .skip(1) // header
        .filter(|l| !l.is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                Some(NamespaceEntry {
                    ns_type: parts[1].to_string(),
                    nsinodes: parts[0].to_string(),
                    pid: parts[2].to_string(),
                    user: parts[3].to_string(),
                    command: parts[4..].join(" "),
                })
            } else {
                None
            }
        })
        .collect();

    let total = namespaces.len();
    serde_json::to_string_pretty(&NamespaceResult {
        pid_filter: pid,
        namespaces,
        total,
        success: true,
        error: None,
    })
    .unwrap()
}
