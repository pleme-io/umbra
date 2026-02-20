use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct WebsocketResult {
    url: String,
    messages_sent: Vec<String>,
    messages_received: Vec<String>,
    success: bool,
    error: Option<String>,
}

pub async fn connect(url: &str, message: Option<&str>, timeout_secs: Option<u64>) -> String {
    let timeout = timeout_secs.unwrap_or(5).min(30);

    if let Some(msg) = message {
        // Send a message and read response
        let result = cmd::run_with_stdin(
            "websocat",
            &["-n1", url], // -n1: exit after first reply
            &format!("{msg}\n"),
            timeout,
        )
        .await;

        let received: Vec<String> = result
            .stdout
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect();

        return serde_json::to_string_pretty(&WebsocketResult {
            url: url.to_string(),
            messages_sent: vec![msg.to_string()],
            messages_received: received,
            success: result.success,
            error: if result.success {
                None
            } else {
                Some(result.stderr.trim().to_string())
            },
        })
        .unwrap();
    }

    // Just connect and listen for messages
    let result = cmd::run("websocat", &["-E", url], timeout).await;

    let received: Vec<String> = result
        .stdout
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect();

    let success = result.success || !received.is_empty();
    let error = if success {
        None
    } else {
        Some(result.stderr.trim().to_string())
    };

    serde_json::to_string_pretty(&WebsocketResult {
        url: url.to_string(),
        messages_sent: vec![],
        messages_received: received,
        success,
        error,
    })
    .unwrap()
}
