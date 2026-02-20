use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct JwtDecodeResult {
    success: bool,
    source: String,
    token_preview: String,
    header: Option<serde_json::Value>,
    payload: Option<serde_json::Value>,
    expiry: Option<JwtExpiry>,
    error: Option<String>,
}

#[derive(Serialize)]
struct JwtExpiry {
    exp: i64,
    expired: bool,
    remaining_secs: Option<i64>,
}

pub async fn decode(token: Option<&str>) -> String {
    // Auto-discover K8s SA token if none provided
    let token_value = if let Some(t) = token {
        t.to_string()
    } else {
        let sa_path = "/var/run/secrets/kubernetes.io/serviceaccount/token";
        match std::fs::read_to_string(sa_path) {
            Ok(t) => t.trim().to_string(),
            Err(_) => {
                return serde_json::to_string_pretty(&JwtDecodeResult {
                    success: false,
                    source: "none".into(),
                    token_preview: String::new(),
                    header: None,
                    payload: None,
                    expiry: None,
                    error: Some(
                        "No token provided and no K8s SA token found at /var/run/secrets/kubernetes.io/serviceaccount/token"
                            .into(),
                    ),
                })
                .unwrap();
            }
        }
    };

    let source = if token.is_some() {
        "provided"
    } else {
        "kubernetes_service_account"
    };

    // Create a preview of the token (first 20 chars + ...)
    let preview = if token_value.len() > 20 {
        format!("{}...", &token_value[..20])
    } else {
        token_value.clone()
    };

    // Try jwt-cli first
    if cmd::is_available("jwt").await {
        return decode_with_jwt_cli(&token_value, source, &preview).await;
    }

    // Fallback: manual base64 decode of JWT parts
    decode_manual(&token_value, source, &preview)
}

async fn decode_with_jwt_cli(token: &str, source: &str, preview: &str) -> String {
    let result = cmd::run("jwt", &["decode", "--json", token], 5).await;

    if !result.success {
        return serde_json::to_string_pretty(&JwtDecodeResult {
            success: false,
            source: source.into(),
            token_preview: preview.into(),
            header: None,
            payload: None,
            expiry: None,
            error: Some(result.stderr.trim().to_string()),
        })
        .unwrap();
    }

    let parsed: serde_json::Value =
        serde_json::from_str(&result.stdout).unwrap_or_default();

    let header = parsed.get("header").cloned();
    let payload = parsed.get("payload").cloned();

    let expiry = payload.as_ref().and_then(|p| {
        p.get("exp").and_then(|e| e.as_i64()).map(|exp| {
            let now = chrono::Utc::now().timestamp();
            JwtExpiry {
                exp,
                expired: now > exp,
                remaining_secs: if now <= exp { Some(exp - now) } else { None },
            }
        })
    });

    serde_json::to_string_pretty(&JwtDecodeResult {
        success: true,
        source: source.into(),
        token_preview: preview.into(),
        header,
        payload,
        expiry,
        error: None,
    })
    .unwrap()
}

fn decode_manual(token: &str, source: &str, preview: &str) -> String {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return serde_json::to_string_pretty(&JwtDecodeResult {
            success: false,
            source: source.into(),
            token_preview: preview.into(),
            header: None,
            payload: None,
            expiry: None,
            error: Some("Invalid JWT format (expected header.payload.signature)".into()),
        })
        .unwrap();
    }

    let header = base64_decode_json(parts[0]);
    let payload = base64_decode_json(parts[1]);

    let expiry = payload.as_ref().and_then(|p| {
        p.get("exp").and_then(|e| e.as_i64()).map(|exp| {
            let now = chrono::Utc::now().timestamp();
            JwtExpiry {
                exp,
                expired: now > exp,
                remaining_secs: if now <= exp { Some(exp - now) } else { None },
            }
        })
    });

    serde_json::to_string_pretty(&JwtDecodeResult {
        success: header.is_some() && payload.is_some(),
        source: source.into(),
        token_preview: preview.into(),
        header,
        payload,
        expiry,
        error: None,
    })
    .unwrap()
}

fn base64_decode_json(input: &str) -> Option<serde_json::Value> {
    use base64::Engine;
    // JWT uses base64url without padding
    let padded = match input.len() % 4 {
        2 => format!("{input}=="),
        3 => format!("{input}="),
        _ => input.to_string(),
    };
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(padded.trim_end_matches('='))
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    serde_json::from_str(&text).ok()
}
