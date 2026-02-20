use crate::pool::ConnectionPool;
use serde::Serialize;
use std::sync::Arc;

// --- agent_tools: list available tools on a connected agent ---

pub async fn agent_tools(pool: &ConnectionPool, connection_id: &str) -> String {
    let conns = pool.connections_ref().await;
    let conn = match conns.get(connection_id) {
        Some(c) => c,
        None => return serde_json::json!({"error": format!("No connection '{connection_id}'")}).to_string(),
    };

    match conn.client.list_tools(Default::default()).await {
        Ok(tools) => {
            let tool_list: Vec<serde_json::Value> = tools
                .tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                    })
                })
                .collect();
            serde_json::json!({
                "connection_id": connection_id,
                "tools": tool_list,
                "total": tool_list.len(),
            })
            .to_string()
        }
        Err(e) => serde_json::json!({"error": format!("Failed to list tools: {e}")}).to_string(),
    }
}

// --- agent_exec: generic proxy for any agent tool ---

pub async fn agent_exec(
    pool: &ConnectionPool,
    connection_id: Option<&str>,
    context: Option<&str>,
    namespace: Option<&str>,
    pod: Option<&str>,
    container: Option<&str>,
    tool: &str,
    arguments: Option<serde_json::Map<String, serde_json::Value>>,
) -> String {
    let id = match resolve_connection(pool, connection_id, context, namespace, pod, container).await
    {
        Ok(id) => id,
        Err(e) => return serde_json::json!({"error": e}).to_string(),
    };

    match pool.call_tool(&id, tool, arguments).await {
        Ok(result) => result,
        Err(e) => serde_json::json!({"error": e}).to_string(),
    }
}

// --- compare: run a tool on multiple pods, diff results ---

#[derive(Serialize)]
struct CompareResult {
    tool: String,
    results: Vec<PodResult>,
    total_pods: usize,
}

#[derive(Serialize)]
struct PodResult {
    pod: String,
    namespace: String,
    context: String,
    result: serde_json::Value,
    success: bool,
}

pub async fn compare(
    pool: &ConnectionPool,
    pods: &[PodTarget],
    tool: &str,
    arguments: Option<serde_json::Map<String, serde_json::Value>>,
) -> String {
    let mut results = Vec::new();

    for target in pods {
        let id = match pool
            .get_or_connect(&target.context, &target.namespace, &target.pod, None)
            .await
        {
            Ok(id) => id,
            Err(e) => {
                results.push(PodResult {
                    pod: target.pod.clone(),
                    namespace: target.namespace.clone(),
                    context: target.context.clone(),
                    result: serde_json::json!({"error": e}),
                    success: false,
                });
                continue;
            }
        };

        match pool.call_tool(&id, tool, arguments.clone()).await {
            Ok(output) => {
                let parsed = serde_json::from_str::<serde_json::Value>(&output)
                    .unwrap_or(serde_json::json!({"raw": output}));
                results.push(PodResult {
                    pod: target.pod.clone(),
                    namespace: target.namespace.clone(),
                    context: target.context.clone(),
                    result: parsed,
                    success: true,
                });
            }
            Err(e) => {
                results.push(PodResult {
                    pod: target.pod.clone(),
                    namespace: target.namespace.clone(),
                    context: target.context.clone(),
                    result: serde_json::json!({"error": e}),
                    success: false,
                });
            }
        }
    }

    let total = results.len();
    serde_json::to_string_pretty(&CompareResult {
        tool: tool.to_string(),
        results,
        total_pods: total,
    })
    .unwrap()
}

// --- sweep: check all discovered services from a pod ---

pub async fn sweep(
    pool: &ConnectionPool,
    connection_id: Option<&str>,
    context: Option<&str>,
    namespace: Option<&str>,
    pod: Option<&str>,
    container: Option<&str>,
) -> String {
    let id = match resolve_connection(pool, connection_id, context, namespace, pod, container).await
    {
        Ok(id) => id,
        Err(e) => return serde_json::json!({"error": e}).to_string(),
    };

    // First get the service list
    let services_json = match pool.call_tool(&id, "services", None).await {
        Ok(r) => r,
        Err(e) => return serde_json::json!({"error": format!("Failed to list services: {e}")}).to_string(),
    };

    let services: Vec<serde_json::Value> =
        serde_json::from_str(&services_json).unwrap_or_default();

    let mut checks = Vec::new();

    for svc in &services {
        let name = svc["name"].as_str().unwrap_or("unknown");
        let host = svc["host"].as_str().unwrap_or("");
        let port = svc["port"].as_u64().unwrap_or(0);

        if host.is_empty() || port == 0 {
            continue;
        }

        let target = format!("{host}:{port}");
        let args = serde_json::json!({"target": target});

        match pool
            .call_tool(&id, "check", args.as_object().cloned())
            .await
        {
            Ok(result) => {
                let parsed = serde_json::from_str::<serde_json::Value>(&result)
                    .unwrap_or(serde_json::json!({"raw": result}));
                checks.push(serde_json::json!({
                    "service": name,
                    "result": parsed,
                }));
            }
            Err(e) => {
                checks.push(serde_json::json!({
                    "service": name,
                    "error": e,
                }));
            }
        }
    }

    serde_json::json!({
        "pod": id,
        "services_found": services.len(),
        "checks": checks,
    })
    .to_string()
}

// --- watch: repeated tool execution ---

pub async fn watch(
    pool: Arc<ConnectionPool>,
    connection_id: Option<&str>,
    context: Option<&str>,
    namespace: Option<&str>,
    pod: Option<&str>,
    container: Option<&str>,
    tool: &str,
    arguments: Option<serde_json::Map<String, serde_json::Value>>,
    interval_secs: u64,
    count: u32,
) -> String {
    let id = match resolve_connection(
        &pool,
        connection_id,
        context,
        namespace,
        pod,
        container,
    )
    .await
    {
        Ok(id) => id,
        Err(e) => return serde_json::json!({"error": e}).to_string(),
    };

    let mut samples = Vec::new();
    let interval = interval_secs.max(1).min(60);
    let iterations = count.max(1).min(20);

    for i in 0..iterations {
        if i > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        }

        let timestamp = chrono::Utc::now().to_rfc3339();
        match pool.call_tool(&id, tool, arguments.clone()).await {
            Ok(result) => {
                let parsed = serde_json::from_str::<serde_json::Value>(&result)
                    .unwrap_or(serde_json::json!({"raw": result}));
                samples.push(serde_json::json!({
                    "iteration": i + 1,
                    "timestamp": timestamp,
                    "result": parsed,
                }));
            }
            Err(e) => {
                samples.push(serde_json::json!({
                    "iteration": i + 1,
                    "timestamp": timestamp,
                    "error": e,
                }));
            }
        }
    }

    serde_json::json!({
        "tool": tool,
        "interval_secs": interval,
        "iterations": iterations,
        "samples": samples,
    })
    .to_string()
}

// --- helpers ---

pub struct PodTarget {
    pub context: String,
    pub namespace: String,
    pub pod: String,
}

async fn resolve_connection(
    pool: &ConnectionPool,
    connection_id: Option<&str>,
    context: Option<&str>,
    namespace: Option<&str>,
    pod: Option<&str>,
    container: Option<&str>,
) -> Result<String, String> {
    if let Some(id) = connection_id {
        return Ok(id.to_string());
    }
    let context = context.ok_or("Either connection_id or (context, namespace, pod) required")?;
    let namespace = namespace.ok_or("namespace required")?;
    let pod = pod.ok_or("pod required")?;
    pool.get_or_connect(context, namespace, pod, container).await
}
