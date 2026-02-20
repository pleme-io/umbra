use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct GrpcResult {
    target: String,
    service: String,
    method: String,
    response: serde_json::Value,
    success: bool,
    error: Option<String>,
}

pub async fn call(
    target: &str,
    service: &str,
    method: &str,
    data: Option<&str>,
    plaintext: bool,
    headers: Option<&[String]>,
) -> String {
    let full_method = format!("{service}/{method}");

    let mut args: Vec<String> = vec![];

    if plaintext {
        args.push("-plaintext".to_string());
    }

    if let Some(hdrs) = headers {
        for h in hdrs {
            args.push("-H".to_string());
            args.push(h.clone());
        }
    }

    if let Some(d) = data {
        args.push("-d".to_string());
        args.push(d.to_string());
    }

    args.push(target.to_string());
    args.push(full_method.clone());

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = cmd::run("grpcurl", &arg_refs, 15).await;

    if !result.success {
        return serde_json::to_string_pretty(&GrpcResult {
            target: target.to_string(),
            service: service.to_string(),
            method: method.to_string(),
            response: serde_json::Value::Null,
            success: false,
            error: Some(result.stderr.trim().to_string()),
        })
        .unwrap();
    }

    let response = serde_json::from_str::<serde_json::Value>(&result.stdout)
        .unwrap_or_else(|_| serde_json::json!(result.stdout.trim()));

    serde_json::to_string_pretty(&GrpcResult {
        target: target.to_string(),
        service: service.to_string(),
        method: method.to_string(),
        response,
        success: true,
        error: None,
    })
    .unwrap()
}

/// List available gRPC services via reflection.
pub async fn list_services(target: &str, plaintext: bool) -> String {
    let mut args: Vec<&str> = vec![];
    if plaintext {
        args.push("-plaintext");
    }
    args.push(target);
    args.push("list");

    let result = cmd::run("grpcurl", &args, 10).await;

    if !result.success {
        return serde_json::json!({
            "target": target,
            "services": [],
            "success": false,
            "error": result.stderr.trim(),
        })
        .to_string();
    }

    let services: Vec<&str> = result.stdout.lines().filter(|l| !l.is_empty()).collect();

    serde_json::json!({
        "target": target,
        "services": services,
        "success": true,
    })
    .to_string()
}
