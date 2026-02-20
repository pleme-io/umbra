use crate::pool::ConnectionPool;

/// Call a tool on a remote agent, auto-connecting if needed.
pub async fn proxy_tool(
    pool: &ConnectionPool,
    connection_id: Option<&str>,
    context: Option<&str>,
    namespace: Option<&str>,
    pod: Option<&str>,
    container: Option<&str>,
    tool_name: &str,
    arguments: Option<serde_json::Map<String, serde_json::Value>>,
) -> String {
    let id = match resolve_connection(pool, connection_id, context, namespace, pod, container).await
    {
        Ok(id) => id,
        Err(e) => return serde_json::json!({ "error": e }).to_string(),
    };

    match pool.call_tool(&id, tool_name, arguments).await {
        Ok(result) => result,
        Err(e) => serde_json::json!({ "error": e }).to_string(),
    }
}

pub async fn resolve_connection_pub(
    pool: &ConnectionPool,
    connection_id: Option<&str>,
    context: Option<&str>,
    namespace: Option<&str>,
    pod: Option<&str>,
    container: Option<&str>,
) -> Result<String, String> {
    resolve_connection(pool, connection_id, context, namespace, pod, container).await
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
    let namespace = namespace.ok_or("namespace is required when not using connection_id")?;
    let pod = pod.ok_or("pod is required when not using connection_id")?;

    pool.get_or_connect(context, namespace, pod, container).await
}
