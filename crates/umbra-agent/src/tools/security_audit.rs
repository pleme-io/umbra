use crate::cmd;
use crate::probe;
use umbra_core::assessment::{SecurityFinding, SecurityReport, SecuritySummary, Severity};
use umbra_core::PodIdentity;

/// Run a security audit of the pod environment.
pub async fn audit() -> String {
    let identity = PodIdentity::gather();
    let mut findings = Vec::new();
    let mut next_id = 1;

    // Check 1: Secret-like values in environment variables
    check_env_secrets(&mut findings, &mut next_id);

    // Check 2: Running as root
    check_root_user(&mut findings, &mut next_id);

    // Check 3: Service account token
    check_sa_token(&mut findings, &mut next_id).await;

    // Check 4: Writable sensitive paths
    check_writable_paths(&mut findings, &mut next_id);

    // Check 5: API server access
    check_api_access(&mut findings, &mut next_id).await;

    // Check 6: Privileged capabilities
    check_capabilities(&mut findings, &mut next_id);

    // Check 7: Service TLS coverage
    check_service_tls(&mut findings, &mut next_id).await;

    // Check 8: Host filesystem mounts
    check_host_mounts(&mut findings, &mut next_id);

    // Build summary
    let summary = build_summary(&findings);

    let report = SecurityReport {
        findings,
        summary,
        identity,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    serde_json::to_string_pretty(&report).unwrap()
}

fn check_env_secrets(findings: &mut Vec<SecurityFinding>, next_id: &mut usize) {
    let secret_patterns = [
        "PASSWORD",
        "SECRET",
        "TOKEN",
        "API_KEY",
        "APIKEY",
        "PRIVATE_KEY",
        "CREDENTIAL",
        "AUTH_KEY",
        "ACCESS_KEY",
        "SECRET_KEY",
    ];

    let mut exposed = Vec::new();
    for (key, value) in std::env::vars() {
        let upper = key.to_uppercase();
        // Skip Kubernetes internal service discovery
        if upper.ends_with("_SERVICE_HOST") || upper.ends_with("_SERVICE_PORT") || upper.ends_with("_PORT") {
            continue;
        }
        for pattern in &secret_patterns {
            if upper.contains(pattern) && !value.is_empty() {
                let masked = if value.len() > 4 {
                    format!("{}...{}", &value[..2], &value[value.len() - 2..])
                } else {
                    "****".into()
                };
                exposed.push(format!("{key}={masked}"));
                break;
            }
        }
    }

    if !exposed.is_empty() {
        findings.push(SecurityFinding {
            id: format!("SEC-{:03}", *next_id),
            title: "Secret-like values in environment variables".into(),
            severity: Severity::High,
            category: "secrets".into(),
            description: format!(
                "{} environment variables contain patterns matching secrets (PASSWORD, TOKEN, SECRET, KEY, etc.). These are visible to any process in the container and may be logged.",
                exposed.len()
            ),
            evidence: exposed,
            remediation: Some(
                "Mount secrets as files via Kubernetes Secret volumes instead of environment variables. Use SOPS or sealed-secrets for encryption at rest."
                    .into(),
            ),
        });
        *next_id += 1;
    } else {
        findings.push(SecurityFinding {
            id: format!("SEC-{:03}", *next_id),
            title: "No secret-like environment variables detected".into(),
            severity: Severity::Info,
            category: "secrets".into(),
            description: "No environment variables matching common secret patterns were found.".into(),
            evidence: vec![],
            remediation: None,
        });
        *next_id += 1;
    }
}

fn check_root_user(findings: &mut Vec<SecurityFinding>, next_id: &mut usize) {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    if uid == 0 {
        findings.push(SecurityFinding {
            id: format!("SEC-{:03}", *next_id),
            title: "Container running as root".into(),
            severity: Severity::Medium,
            category: "identity".into(),
            description: format!(
                "Process is running as uid={uid}, gid={gid}. Running as root increases the blast radius of container escapes."
            ),
            evidence: vec![format!("uid={uid}"), format!("gid={gid}")],
            remediation: Some(
                "Set securityContext.runAsNonRoot: true and securityContext.runAsUser to a non-zero UID in the pod spec."
                    .into(),
            ),
        });
    } else {
        findings.push(SecurityFinding {
            id: format!("SEC-{:03}", *next_id),
            title: "Container running as non-root".into(),
            severity: Severity::Info,
            category: "identity".into(),
            description: format!("Process running as uid={uid}, gid={gid}."),
            evidence: vec![format!("uid={uid}"), format!("gid={gid}")],
            remediation: None,
        });
    }
    *next_id += 1;
}

async fn check_sa_token(findings: &mut Vec<SecurityFinding>, next_id: &mut usize) {
    let token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token";
    if std::path::Path::new(token_path).exists() {
        // Token is mounted — check if we can use it
        let result = cmd::run(
            "curl",
            &[
                "-s",
                "-k",
                "-H",
                &format!(
                    "Authorization: Bearer {}",
                    std::fs::read_to_string(token_path).unwrap_or_default().trim()
                ),
                "https://kubernetes.default.svc/api/v1/namespaces",
            ],
            5,
        )
        .await;

        if result.success && result.stdout.contains("\"items\"") {
            findings.push(SecurityFinding {
                id: format!("SEC-{:03}", *next_id),
                title: "Service account can list namespaces".into(),
                severity: Severity::High,
                category: "rbac".into(),
                description: "The mounted service account token has permission to list all namespaces. This may indicate overly broad RBAC permissions.".into(),
                evidence: vec!["GET /api/v1/namespaces → 200 with items".into()],
                remediation: Some(
                    "Use a dedicated ServiceAccount with minimal RBAC. Set automountServiceAccountToken: false if API access is not needed."
                        .into(),
                ),
            });
        } else {
            findings.push(SecurityFinding {
                id: format!("SEC-{:03}", *next_id),
                title: "Service account token mounted (limited scope)".into(),
                severity: Severity::Low,
                category: "rbac".into(),
                description: "A service account token is mounted but cannot list namespaces (scope appears limited).".into(),
                evidence: vec![format!("Token exists at {token_path}")],
                remediation: Some(
                    "If API access is not needed, set automountServiceAccountToken: false.".into(),
                ),
            });
        }
    } else {
        findings.push(SecurityFinding {
            id: format!("SEC-{:03}", *next_id),
            title: "No service account token mounted".into(),
            severity: Severity::Info,
            category: "rbac".into(),
            description: "No service account token found. automountServiceAccountToken may be disabled.".into(),
            evidence: vec![],
            remediation: None,
        });
    }
    *next_id += 1;
}

fn check_writable_paths(findings: &mut Vec<SecurityFinding>, next_id: &mut usize) {
    let sensitive_paths = [
        "/var/run/secrets",
        "/etc/shadow",
        "/etc/passwd",
        "/proc/sysrq-trigger",
        "/sys/kernel",
    ];

    let mut writable = Vec::new();
    for path in &sensitive_paths {
        let p = std::path::Path::new(path);
        if p.exists() {
            // Try to check writability
            let metadata = std::fs::metadata(path);
            if let Ok(meta) = metadata {
                let perms = meta.permissions();
                if !perms.readonly() {
                    writable.push(format!("{path} (writable)"));
                }
            }
        }
    }

    if !writable.is_empty() {
        findings.push(SecurityFinding {
            id: format!("SEC-{:03}", *next_id),
            title: "Writable sensitive filesystem paths".into(),
            severity: Severity::Medium,
            category: "filesystem".into(),
            description: format!(
                "{} sensitive paths are writable. This could allow privilege escalation or credential theft.",
                writable.len()
            ),
            evidence: writable,
            remediation: Some(
                "Use readOnlyRootFilesystem: true in securityContext. Mount sensitive paths as read-only."
                    .into(),
            ),
        });
        *next_id += 1;
    }
}

async fn check_api_access(findings: &mut Vec<SecurityFinding>, next_id: &mut usize) {
    let api_host = std::env::var("KUBERNETES_SERVICE_HOST").unwrap_or_default();
    let api_port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());

    if api_host.is_empty() {
        return;
    }

    let tcp = probe::tcp::connect(&api_host, api_port.parse().unwrap_or(443)).await;
    if tcp.success {
        findings.push(SecurityFinding {
            id: format!("SEC-{:03}", *next_id),
            title: "Kubernetes API server reachable".into(),
            severity: Severity::Info,
            category: "network".into(),
            description: format!(
                "The Kubernetes API server at {api_host}:{api_port} is reachable from this pod."
            ),
            evidence: vec![format!("TCP connect to {api_host}:{api_port} → OK ({}ms)", tcp.latency_ms)],
            remediation: None,
        });
        *next_id += 1;
    }
}

fn check_capabilities(findings: &mut Vec<SecurityFinding>, next_id: &mut usize) {
    // Read capabilities from /proc/self/status
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let mut cap_lines = Vec::new();

    for line in status.lines() {
        if line.starts_with("Cap") {
            cap_lines.push(line.to_string());
        }
    }

    // Check CapEff (effective capabilities)
    for line in &cap_lines {
        if line.starts_with("CapEff:") {
            let hex = line.trim_start_matches("CapEff:").trim();
            if let Ok(caps) = u64::from_str_radix(hex, 16) {
                let dangerous_caps = [
                    (0, "CAP_CHOWN"),
                    (1, "CAP_DAC_OVERRIDE"),
                    (5, "CAP_KILL"),
                    (7, "CAP_SETUID"),
                    (8, "CAP_SETGID"),
                    (12, "CAP_NET_RAW"),
                    (21, "CAP_SYS_ADMIN"),
                    (23, "CAP_SYS_NICE"),
                    (26, "CAP_SYS_PTRACE"),
                ];

                let mut active_dangerous = Vec::new();
                for (bit, name) in &dangerous_caps {
                    if caps & (1u64 << bit) != 0 {
                        active_dangerous.push(*name);
                    }
                }

                if active_dangerous.len() > 3 {
                    findings.push(SecurityFinding {
                        id: format!("SEC-{:03}", *next_id),
                        title: "Broad Linux capabilities".into(),
                        severity: Severity::Medium,
                        category: "capabilities".into(),
                        description: format!(
                            "Container has {} potentially dangerous capabilities. Capabilities should be dropped to minimum required.",
                            active_dangerous.len()
                        ),
                        evidence: active_dangerous.iter().map(|c| c.to_string()).collect(),
                        remediation: Some(
                            "Drop all capabilities and add only what's needed: securityContext.capabilities.drop: [ALL], add: [NET_BIND_SERVICE]"
                                .into(),
                        ),
                    });
                    *next_id += 1;
                }
            }
        }
    }
}

async fn check_service_tls(findings: &mut Vec<SecurityFinding>, next_id: &mut usize) {
    let services = umbra_core::services::discover_services();
    let http_ports = [80, 443, 8080, 8443, 3000, 4000, 5000, 8000, 9000];

    let mut no_tls = Vec::new();
    let mut _with_tls = 0;
    let mut checked = 0;

    for svc in &services {
        if !http_ports.contains(&svc.port) {
            continue;
        }
        checked += 1;

        // Try HTTPS
        let result = cmd::run(
            "curl",
            &[
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{scheme}",
                "-m",
                "2",
                &format!("https://{}:{}", svc.host, svc.port),
            ],
            4,
        )
        .await;

        if result.success && result.stdout.trim() == "HTTPS" {
            _with_tls += 1;
        } else {
            no_tls.push(format!("{} ({}:{})", svc.name, svc.host, svc.port));
        }
    }

    if !no_tls.is_empty() {
        findings.push(SecurityFinding {
            id: format!("SEC-{:03}", *next_id),
            title: "HTTP services without TLS".into(),
            severity: Severity::Medium,
            category: "encryption".into(),
            description: format!(
                "{}/{} HTTP services are not using TLS. Traffic may be intercepted within the cluster.",
                no_tls.len(),
                checked
            ),
            evidence: no_tls,
            remediation: Some(
                "Enable TLS for all services using cert-manager or a service mesh (Istio/Linkerd) for automatic mTLS."
                    .into(),
            ),
        });
        *next_id += 1;
    }
}

fn check_host_mounts(findings: &mut Vec<SecurityFinding>, next_id: &mut usize) {
    // Check /proc/mounts for hostPath-like mounts
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    let mut host_mounts = Vec::new();

    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let mount_point = parts[1];
            // Look for hostPath mounts (typically under /host or known system paths)
            if mount_point.starts_with("/host")
                || mount_point == "/var/run/docker.sock"
                || mount_point == "/var/run/containerd/containerd.sock"
            {
                host_mounts.push(mount_point.to_string());
            }
        }
    }

    if !host_mounts.is_empty() {
        findings.push(SecurityFinding {
            id: format!("SEC-{:03}", *next_id),
            title: "Host filesystem or socket mounts detected".into(),
            severity: Severity::Critical,
            category: "filesystem".into(),
            description: format!(
                "{} host-level mounts found. Access to host filesystem or container runtime socket enables container escape.",
                host_mounts.len()
            ),
            evidence: host_mounts,
            remediation: Some(
                "Remove hostPath volumes. Never mount the container runtime socket into pods."
                    .into(),
            ),
        });
        *next_id += 1;
    }
}

fn build_summary(findings: &[SecurityFinding]) -> SecuritySummary {
    let mut summary = SecuritySummary {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        total: findings.len(),
        score: 100,
    };

    for f in findings {
        match f.severity {
            Severity::Critical => {
                summary.critical += 1;
                summary.score = summary.score.saturating_sub(25);
            }
            Severity::High => {
                summary.high += 1;
                summary.score = summary.score.saturating_sub(15);
            }
            Severity::Medium => {
                summary.medium += 1;
                summary.score = summary.score.saturating_sub(8);
            }
            Severity::Low => {
                summary.low += 1;
                summary.score = summary.score.saturating_sub(3);
            }
            Severity::Info => {
                summary.info += 1;
            }
        }
    }

    summary
}
