use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct OpenFile {
    command: String,
    pid: String,
    user: String,
    fd: String,
    file_type: String,
    device: String,
    size_offset: String,
    node: String,
    name: String,
}

#[derive(Serialize)]
struct OpenFilesResult {
    pid: Option<u32>,
    filter: String,
    files: Vec<OpenFile>,
    total: usize,
    success: bool,
    error: Option<String>,
}

pub async fn list(pid: Option<u32>, filter: Option<&str>) -> String {
    let filter_type = filter.unwrap_or("all");

    let mut args = vec!["-n", "-P"]; // no hostname resolution, no port names

    match filter_type {
        "network" => args.push("-i"),
        "file" => {
            args.push("+D");
            args.push("/");
        }
        _ => {} // all
    }

    if let Some(p) = pid {
        let pid_str = p.to_string();
        args.push("-p");
        // Need to own the string
        let result = cmd::run("lsof", &["-n", "-P", "-p", &pid_str], 15).await;
        return format_result(Some(p), filter_type, &result);
    }

    let result = cmd::run("lsof", &args, 15).await;
    format_result(None, filter_type, &result)
}

fn format_result(pid: Option<u32>, filter: &str, result: &cmd::CmdResult) -> String {
    if !result.success && result.stdout.is_empty() {
        return serde_json::to_string_pretty(&OpenFilesResult {
            pid,
            filter: filter.to_string(),
            files: vec![],
            total: 0,
            success: false,
            error: Some(result.stderr.trim().to_string()),
        })
        .unwrap();
    }

    let files: Vec<OpenFile> = result
        .stdout
        .lines()
        .skip(1) // skip header
        .filter(|l| !l.is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.splitn(9, char::is_whitespace).collect();
            if parts.len() >= 9 {
                Some(OpenFile {
                    command: parts[0].to_string(),
                    pid: parts[1].to_string(),
                    user: parts[2].to_string(),
                    fd: parts[3].to_string(),
                    file_type: parts[4].to_string(),
                    device: parts[5].to_string(),
                    size_offset: parts[6].to_string(),
                    node: parts[7].to_string(),
                    name: parts[8].to_string(),
                })
            } else {
                None
            }
        })
        .collect();

    let total = files.len();
    serde_json::to_string_pretty(&OpenFilesResult {
        pid,
        filter: filter.to_string(),
        files,
        total,
        success: true,
        error: None,
    })
    .unwrap()
}
