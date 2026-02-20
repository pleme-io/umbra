use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct AuthTestResult {
    target: String,
    protocol: String,
    success: bool,
    valid_credentials: Vec<CredentialResult>,
    total_tested: u64,
    error: Option<String>,
}

#[derive(Serialize)]
struct CredentialResult {
    username: String,
    password_hint: String,
}

pub async fn test(
    target: &str,
    protocol: Option<&str>,
    usernames: Option<&str>,
    passwords: Option<&str>,
    rate: Option<u32>,
    timeout_secs: Option<u64>,
) -> String {
    if !cmd::is_available("legba").await {
        return cmd::binary_not_found("legba", None);
    }

    let timeout = timeout_secs.unwrap_or(60);
    let proto = protocol.unwrap_or("http");
    let rate_val = rate.unwrap_or(10).min(50).to_string();

    let mut args = vec![proto, "--target", target, "--rate", &rate_val];

    if let Some(u) = usernames {
        args.extend(["--username", u]);
    }

    if let Some(p) = passwords {
        args.extend(["--password", p]);
    }

    args.push("--output-format");
    args.push("json");

    let result = cmd::run("legba", &args, timeout).await;

    if !result.success && result.stdout.is_empty() {
        return serde_json::to_string_pretty(&AuthTestResult {
            target: target.to_string(),
            protocol: proto.to_string(),
            success: false,
            valid_credentials: vec![],
            total_tested: 0,
            error: Some(result.stderr.trim().to_string()),
        })
        .unwrap();
    }

    let mut valid_creds = Vec::new();
    let mut total_tested: u64 = 0;

    for line in result.stdout.lines() {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            if val.get("valid").and_then(|v| v.as_bool()) == Some(true) {
                let username = val
                    .get("username")
                    .and_then(|u| u.as_str())
                    .unwrap_or("")
                    .to_string();
                let password = val
                    .get("password")
                    .and_then(|p| p.as_str())
                    .unwrap_or("");
                let hint = if password.len() > 3 {
                    format!("{}...", &password[..2])
                } else {
                    "***".into()
                };

                valid_creds.push(CredentialResult {
                    username,
                    password_hint: hint,
                });
            }
            if let Some(t) = val.get("total").and_then(|t| t.as_u64()) {
                total_tested = t;
            }
        }
    }

    // Parse total from stderr if not in stdout
    if total_tested == 0 {
        for line in result.stderr.lines() {
            if let Some(n) = line
                .split_whitespace()
                .find(|w| w.parse::<u64>().is_ok())
            {
                if let Ok(n) = n.parse::<u64>() {
                    if n > total_tested {
                        total_tested = n;
                    }
                }
            }
        }
    }

    serde_json::to_string_pretty(&AuthTestResult {
        target: target.to_string(),
        protocol: proto.to_string(),
        success: true,
        valid_credentials: valid_creds,
        total_tested,
        error: None,
    })
    .unwrap()
}
