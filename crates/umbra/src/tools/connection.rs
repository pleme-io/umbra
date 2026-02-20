use crate::pool::ConnectionPool;

pub async fn connect(
    pool: &ConnectionPool,
    context: &str,
    namespace: &str,
    pod: &str,
    container: Option<&str>,
) -> String {
    match pool.connect(context, namespace, pod, container).await {
        Ok(id) => serde_json::json!({
            "connection_id": id,
            "status": "connected"
        })
        .to_string(),
        Err(e) => serde_json::json!({
            "error": e
        })
        .to_string(),
    }
}

pub async fn disconnect(pool: &ConnectionPool, connection_id: &str) -> String {
    match pool.disconnect(connection_id).await {
        Ok(()) => serde_json::json!({
            "status": "disconnected",
            "connection_id": connection_id
        })
        .to_string(),
        Err(e) => serde_json::json!({
            "error": e
        })
        .to_string(),
    }
}

pub async fn list_connections(pool: &ConnectionPool) -> String {
    let connections = pool.list().await;
    serde_json::to_string_pretty(&connections).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
}
