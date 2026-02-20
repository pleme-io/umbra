use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct DnsRecord {
    name: String,
    ttl: Option<String>,
    class: Option<String>,
    record_type: String,
    value: String,
}

#[derive(Serialize)]
struct DnsLookupResult {
    query: String,
    record_type: String,
    server: Option<String>,
    records: Vec<DnsRecord>,
    success: bool,
    error: Option<String>,
}

pub async fn lookup(name: &str, record_type: Option<&str>, server: Option<&str>) -> String {
    let rtype = record_type.unwrap_or("A");
    let mut args: Vec<&str> = vec!["+noall", "+answer", "+authority", "+time=3", "+tries=1"];

    if let Some(srv) = server {
        // dig @server format - need to build the string
        let server_arg = format!("@{srv}");
        let mut full_args = vec![server_arg.as_str()];
        full_args.extend_from_slice(&args);
        full_args.push(name);
        full_args.push(rtype);

        let result = cmd::run("dig", &full_args, 10).await;
        return format_result(name, rtype, Some(srv), &result);
    }

    args.push(name);
    args.push(rtype);

    let result = cmd::run("dig", &args, 10).await;
    format_result(name, rtype, None, &result)
}

fn format_result(name: &str, rtype: &str, server: Option<&str>, result: &cmd::CmdResult) -> String {
    if !result.success {
        return serde_json::to_string_pretty(&DnsLookupResult {
            query: name.to_string(),
            record_type: rtype.to_string(),
            server: server.map(|s| s.to_string()),
            records: vec![],
            success: false,
            error: Some(result.stderr.trim().to_string()),
        })
        .unwrap();
    }

    let records: Vec<DnsRecord> = result
        .stdout
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with(';'))
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                Some(DnsRecord {
                    name: parts[0].to_string(),
                    ttl: Some(parts[1].to_string()),
                    class: Some(parts[2].to_string()),
                    record_type: parts[3].to_string(),
                    value: parts[4..].join(" "),
                })
            } else if parts.len() >= 2 {
                Some(DnsRecord {
                    name: name.to_string(),
                    ttl: None,
                    class: None,
                    record_type: rtype.to_string(),
                    value: parts.join(" "),
                })
            } else {
                None
            }
        })
        .collect();

    serde_json::to_string_pretty(&DnsLookupResult {
        query: name.to_string(),
        record_type: rtype.to_string(),
        server: server.map(|s| s.to_string()),
        records,
        success: true,
        error: None,
    })
    .unwrap()
}
