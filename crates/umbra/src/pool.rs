use rmcp::{
    ServiceExt,
    model::CallToolRequestParams,
    service::RunningService,
    transport::TokioChildProcess,
};
use std::collections::HashMap;
use tokio::sync::RwLock;

type Client = RunningService<rmcp::RoleClient, ()>;

/// An active connection to an umbra-agent running in a pod.
pub struct AgentConnection {
    pub id: String,
    pub context: String,
    pub namespace: String,
    pub pod: String,
    pub container: Option<String>,
    pub client: Client,
}

impl std::fmt::Debug for AgentConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentConnection")
            .field("id", &self.id)
            .field("context", &self.context)
            .field("namespace", &self.namespace)
            .field("pod", &self.pod)
            .field("container", &self.container)
            .finish()
    }
}

/// Connection pool managing multiple kubectl-exec sessions.
#[derive(Debug)]
pub struct ConnectionPool {
    connections: RwLock<HashMap<String, AgentConnection>>,
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
        }
    }

    /// Connect to an umbra-agent in a pod via kubectl exec.
    pub async fn connect(
        &self,
        context: &str,
        namespace: &str,
        pod: &str,
        container: Option<&str>,
    ) -> Result<String, String> {
        let id = connection_id(context, namespace, pod);

        // Return existing connection if alive
        {
            let conns = self.connections.read().await;
            if conns.contains_key(&id) {
                return Ok(id);
            }
        }

        let client = spawn_agent(context, namespace, pod, container).await?;

        let conn = AgentConnection {
            id: id.clone(),
            context: context.to_string(),
            namespace: namespace.to_string(),
            pod: pod.to_string(),
            container: container.map(|s| s.to_string()),
            client,
        };

        self.connections.write().await.insert(id.clone(), conn);
        Ok(id)
    }

    /// Disconnect from a pod.
    pub async fn disconnect(&self, id: &str) -> Result<(), String> {
        let mut conns = self.connections.write().await;
        if let Some(conn) = conns.remove(id) {
            conn.client.cancel().await.map_err(|e| e.to_string())?;
            Ok(())
        } else {
            Err(format!("No connection with id '{id}'"))
        }
    }

    /// List all active connections.
    pub async fn list(&self) -> Vec<ConnectionInfo> {
        let conns = self.connections.read().await;
        conns
            .values()
            .map(|c| ConnectionInfo {
                id: c.id.clone(),
                context: c.context.clone(),
                namespace: c.namespace.clone(),
                pod: c.pod.clone(),
                container: c.container.clone(),
            })
            .collect()
    }

    /// Call a tool on a connected agent.
    pub async fn call_tool(
        &self,
        id: &str,
        tool_name: &str,
        arguments: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<String, String> {
        let conns = self.connections.read().await;
        let conn = conns.get(id).ok_or_else(|| format!("No connection '{id}'"))?;

        let result = conn
            .client
            .call_tool(CallToolRequestParams {
                meta: None,
                name: tool_name.to_string().into(),
                arguments,
                task: None,
            })
            .await
            .map_err(|e| format!("Tool call failed: {e}"))?;

        // Extract text content from the result
        let text: Vec<String> = result
            .content
            .iter()
            .filter_map(|c| c.as_text().map(|t| t.text.clone()))
            .collect();

        Ok(text.join("\n"))
    }

    /// Get a read guard on the connections map (for agent_tools).
    pub async fn connections_ref(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, HashMap<String, AgentConnection>> {
        self.connections.read().await
    }

    /// Get or create a connection, returning the connection ID.
    pub async fn get_or_connect(
        &self,
        context: &str,
        namespace: &str,
        pod: &str,
        container: Option<&str>,
    ) -> Result<String, String> {
        let id = connection_id(context, namespace, pod);
        {
            let conns = self.connections.read().await;
            if conns.contains_key(&id) {
                return Ok(id);
            }
        }
        self.connect(context, namespace, pod, container).await
    }
}

/// Summary info for a connection (serializable).
#[derive(Debug, serde::Serialize)]
pub struct ConnectionInfo {
    pub id: String,
    pub context: String,
    pub namespace: String,
    pub pod: String,
    pub container: Option<String>,
}

fn connection_id(context: &str, namespace: &str, pod: &str) -> String {
    format!("{context}/{namespace}/{pod}")
}

async fn spawn_agent(
    context: &str,
    namespace: &str,
    pod: &str,
    container: Option<&str>,
) -> Result<Client, String> {
    let mut cmd = tokio::process::Command::new("kubectl");
    cmd.args(["exec", "-i", "-n", namespace, "--context", context]);
    if let Some(c) = container {
        cmd.args(["-c", c]);
    }
    cmd.args([pod, "--", "umbra-agent"]);

    let transport = TokioChildProcess::new(cmd).map_err(|e| format!("Failed to spawn kubectl exec: {e}"))?;
    let client = ().serve(transport).await.map_err(|e| format!("MCP handshake failed: {e}"))?;

    // Verify connection by listing tools
    client
        .list_tools(Default::default())
        .await
        .map_err(|e| format!("Agent unreachable: {e}"))?;

    Ok(client)
}
