use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct RedisResult {
    host: String,
    port: u16,
    command: String,
    response: serde_json::Value,
    success: bool,
    error: Option<String>,
}

pub async fn execute(host: &str, port: u16, password: Option<&str>, command: &str) -> String {
    let port_str = port.to_string();
    let mut args: Vec<&str> = vec!["-h", host, "-p", &port_str, "--no-auth-warning"];

    if let Some(pw) = password {
        args.push("-a");
        args.push(pw);
    }

    // Split command into redis-cli args
    let cmd_parts: Vec<&str> = command.split_whitespace().collect();
    args.extend_from_slice(&cmd_parts);

    let result = cmd::run("redis-cli", &args, 10).await;

    if !result.success {
        return serde_json::to_string_pretty(&RedisResult {
            host: host.to_string(),
            port,
            command: command.to_string(),
            response: serde_json::Value::Null,
            success: false,
            error: Some(result.stderr.trim().to_string()),
        })
        .unwrap();
    }

    let output = result.stdout.trim();

    // Try to parse as structured data
    let response = if output.starts_with("(error)") || output.starts_with("ERR") {
        return serde_json::to_string_pretty(&RedisResult {
            host: host.to_string(),
            port,
            command: command.to_string(),
            response: serde_json::Value::Null,
            success: false,
            error: Some(output.to_string()),
        })
        .unwrap();
    } else if output.starts_with("(integer)") {
        let num: i64 = output
            .strip_prefix("(integer) ")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        serde_json::json!(num)
    } else if output == "(nil)" {
        serde_json::Value::Null
    } else if output.contains('\n') && output.starts_with("1)") {
        // Array response
        let items: Vec<String> = output
            .lines()
            .filter_map(|l| {
                l.split(')').nth(1).map(|s| s.trim().trim_matches('"').to_string())
            })
            .collect();
        serde_json::json!(items)
    } else {
        serde_json::json!(output)
    };

    serde_json::to_string_pretty(&RedisResult {
        host: host.to_string(),
        port,
        command: command.to_string(),
        response,
        success: true,
        error: None,
    })
    .unwrap()
}
