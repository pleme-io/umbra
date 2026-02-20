use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct DiscoveredPod {
    pub name: String,
    pub namespace: String,
    pub context: String,
    pub node: Option<String>,
    pub status: String,
}

/// Discover pods with the umbra-agent label using kubectl.
pub async fn discover_pods(context: &str, namespace: Option<&str>) -> String {
    let mut cmd = tokio::process::Command::new("kubectl");
    cmd.args(["get", "pods", "--context", context]);

    if let Some(ns) = namespace {
        cmd.args(["-n", ns]);
    } else {
        cmd.arg("--all-namespaces");
    }

    cmd.args([
        "-l",
        "umbra.pleme.io/agent=true",
        "-o",
        "jsonpath={range .items[*]}{.metadata.name},{.metadata.namespace},{.spec.nodeName},{.status.phase}{\"\\n\"}{end}",
    ]);

    let output = match cmd.output().await {
        Ok(o) => o,
        Err(e) => {
            return serde_json::json!({ "error": format!("kubectl failed: {e}") }).to_string();
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return serde_json::json!({ "error": format!("kubectl error: {stderr}") }).to_string();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let pods: Vec<DiscoveredPod> = stdout
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 4 {
                Some(DiscoveredPod {
                    name: parts[0].to_string(),
                    namespace: parts[1].to_string(),
                    context: context.to_string(),
                    node: if parts[2].is_empty() {
                        None
                    } else {
                        Some(parts[2].to_string())
                    },
                    status: parts[3].to_string(),
                })
            } else {
                None
            }
        })
        .collect();

    serde_json::to_string_pretty(&pods).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
}
