use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct CertificateReport {
    certificates: Vec<CertificateInfo>,
    warnings: Vec<String>,
    success: bool,
    errors: Vec<String>,
}

#[derive(Serialize)]
struct CertificateInfo {
    target: String,
    subject: Option<String>,
    issuer: Option<String>,
    not_before: Option<String>,
    not_after: Option<String>,
    days_until_expiry: Option<i64>,
    serial: Option<String>,
    san: Vec<String>,
    signature_algorithm: Option<String>,
    key_type: Option<String>,
    key_size: Option<String>,
    chain_length: i64,
    chain: Vec<ChainCert>,
    ocsp_stapling: bool,
    tls_version: Option<String>,
    cipher: Option<String>,
    valid: bool,
    error: Option<String>,
}

#[derive(Serialize)]
struct ChainCert {
    depth: i64,
    subject: String,
    issuer: String,
    not_after: String,
}

pub async fn check(targets: &[String]) -> String {
    let mut report = CertificateReport {
        certificates: Vec::new(),
        warnings: Vec::new(),
        success: true,
        errors: Vec::new(),
    };

    // If no targets, auto-discover from K8s services and common ports
    let targets = if targets.is_empty() {
        discover_tls_targets().await
    } else {
        targets.to_vec()
    };

    // Check each target in parallel
    let mut handles = Vec::new();
    for target in &targets {
        let target = target.clone();
        handles.push(tokio::spawn(async move {
            check_certificate(&target).await
        }));
    }

    for handle in handles {
        if let Ok(cert) = handle.await {
            // Generate warnings
            if let Some(days) = cert.days_until_expiry {
                if days < 0 {
                    report.warnings.push(format!(
                        "{}: Certificate EXPIRED {} days ago",
                        cert.target,
                        -days
                    ));
                } else if days < 7 {
                    report.warnings.push(format!(
                        "{}: Certificate expires in {} days (CRITICAL)",
                        cert.target, days
                    ));
                } else if days < 30 {
                    report.warnings.push(format!(
                        "{}: Certificate expires in {} days (WARNING)",
                        cert.target, days
                    ));
                }
            }
            if !cert.valid {
                report.warnings.push(format!(
                    "{}: Certificate validation failed: {}",
                    cert.target,
                    cert.error.as_deref().unwrap_or("unknown")
                ));
            }
            report.certificates.push(cert);
        }
    }

    if report.certificates.is_empty() && !targets.is_empty() {
        report.success = false;
        report
            .errors
            .push("Could not check any certificates".into());
    }

    serde_json::to_string_pretty(&report).unwrap()
}

async fn check_certificate(target: &str) -> CertificateInfo {
    let (host, port) = parse_target(target);
    let connect = format!("{host}:{port}");

    // Use openssl s_client for maximum detail
    let result = cmd::run_with_stdin(
        "openssl",
        &[
            "s_client",
            "-connect",
            &connect,
            "-servername",
            &host,
            "-showcerts",
            "-brief",
        ],
        "",
        10,
    )
    .await;

    if !result.success && !result.stdout.contains("BEGIN CERTIFICATE") {
        return CertificateInfo {
            target: target.to_string(),
            subject: None,
            issuer: None,
            not_before: None,
            not_after: None,
            days_until_expiry: None,
            serial: None,
            san: Vec::new(),
            signature_algorithm: None,
            key_type: None,
            key_size: None,
            chain_length: 0,
            chain: Vec::new(),
            ocsp_stapling: false,
            tls_version: None,
            cipher: None,
            valid: false,
            error: Some(result.stderr.trim().lines().last().unwrap_or("connection failed").to_string()),
        };
    }

    let combined = format!("{}\n{}", result.stdout, result.stderr);

    // Parse certificate details using openssl x509
    let cert_result = cmd::run_with_stdin(
        "openssl",
        &[
            "x509",
            "-noout",
            "-subject",
            "-issuer",
            "-dates",
            "-serial",
            "-ext",
            "subjectAltName",
            "-fingerprint",
            "-text",
        ],
        &extract_first_cert(&result.stdout),
        10,
    )
    .await;

    let mut info = CertificateInfo {
        target: target.to_string(),
        subject: None,
        issuer: None,
        not_before: None,
        not_after: None,
        days_until_expiry: None,
        serial: None,
        san: Vec::new(),
        signature_algorithm: None,
        key_type: None,
        key_size: None,
        chain_length: count_certs(&result.stdout),
        chain: Vec::new(),
        ocsp_stapling: combined.contains("OCSP"),
        tls_version: None,
        cipher: None,
        valid: true,
        error: None,
    };

    // Parse TLS version and cipher from s_client output
    for line in combined.lines() {
        let line = line.trim();
        if line.starts_with("Protocol version:") || line.starts_with("Protocol  :") {
            info.tls_version = line.split(':').nth(1).map(|s| s.trim().to_string());
        } else if line.starts_with("Ciphersuite:") || line.starts_with("Cipher    :") {
            info.cipher = line.split(':').nth(1).map(|s| s.trim().to_string());
        } else if line.contains("Verification") && line.contains("error") {
            info.valid = false;
            info.error = Some(line.to_string());
        }
    }

    // Parse x509 output
    if cert_result.success {
        for line in cert_result.stdout.lines() {
            let line = line.trim();
            if let Some(val) = line.strip_prefix("subject=") {
                info.subject = Some(val.trim().to_string());
            } else if let Some(val) = line.strip_prefix("issuer=") {
                info.issuer = Some(val.trim().to_string());
            } else if let Some(val) = line.strip_prefix("notBefore=") {
                info.not_before = Some(val.trim().to_string());
            } else if let Some(val) = line.strip_prefix("notAfter=") {
                info.not_after = Some(val.trim().to_string());
                info.days_until_expiry = parse_days_until(val.trim());
            } else if let Some(val) = line.strip_prefix("serial=") {
                info.serial = Some(val.trim().to_string());
            } else if line.contains("DNS:") {
                // SAN line: DNS:example.com, DNS:*.example.com
                info.san = line
                    .split(',')
                    .filter_map(|s| {
                        s.trim()
                            .strip_prefix("DNS:")
                            .map(|d| d.to_string())
                    })
                    .collect();
            } else if line.contains("Signature Algorithm:") {
                info.signature_algorithm = line.split(':').nth(1).map(|s| s.trim().to_string());
            } else if line.contains("Public Key Algorithm:") {
                info.key_type = line.split(':').nth(1).map(|s| s.trim().to_string());
            } else if line.contains("Public-Key:") {
                info.key_size = line
                    .split('(')
                    .nth(1)
                    .and_then(|s| s.split(')').next())
                    .map(|s| s.trim().to_string());
            }
        }
    }

    // Parse certificate chain
    info.chain = parse_chain(&result.stdout);

    info
}

async fn discover_tls_targets() -> Vec<String> {
    let mut targets = Vec::new();

    // Check K8s services on common TLS ports
    for (key, val) in std::env::vars() {
        if key.ends_with("_SERVICE_PORT") {
            let port: u16 = val.parse().unwrap_or(0);
            if port == 443 || port == 8443 || port == 6443 || port == 9443 {
                let prefix = key.trim_end_matches("_SERVICE_PORT");
                if let Ok(host) = std::env::var(format!("{prefix}_SERVICE_HOST")) {
                    targets.push(format!("{host}:{port}"));
                }
            }
        }
    }

    // Always check kubernetes API
    if let Ok(host) = std::env::var("KUBERNETES_SERVICE_HOST") {
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());
        let target = format!("{host}:{port}");
        if !targets.contains(&target) {
            targets.push(target);
        }
    }

    targets
}

fn parse_target(target: &str) -> (String, String) {
    if target.contains(':') {
        let parts: Vec<&str> = target.splitn(2, ':').collect();
        (parts[0].to_string(), parts[1].to_string())
    } else {
        (target.to_string(), "443".to_string())
    }
}

fn extract_first_cert(output: &str) -> String {
    let mut in_cert = false;
    let mut cert = String::new();

    for line in output.lines() {
        if line.contains("BEGIN CERTIFICATE") {
            in_cert = true;
        }
        if in_cert {
            cert.push_str(line);
            cert.push('\n');
        }
        if line.contains("END CERTIFICATE") && in_cert {
            break;
        }
    }
    cert
}

fn count_certs(output: &str) -> i64 {
    output.matches("BEGIN CERTIFICATE").count() as i64
}

fn parse_chain(output: &str) -> Vec<ChainCert> {
    let mut chain = Vec::new();
    let mut depth: i64 = 0;

    // Split on BEGIN CERTIFICATE and parse each
    let certs: Vec<&str> = output.split("-----BEGIN CERTIFICATE-----").collect();
    for cert_pem in certs.iter().skip(1) {
        let full_pem = format!("-----BEGIN CERTIFICATE-----{cert_pem}");
        let end_idx = full_pem.find("-----END CERTIFICATE-----");
        if let Some(idx) = end_idx {
            let pem = &full_pem[..idx + 25];

            // Quick parse with openssl — synchronous is fine for chain parsing
            let output = std::process::Command::new("openssl")
                .args(["x509", "-noout", "-subject", "-issuer", "-enddate"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
                .and_then(|mut child| {
                    use std::io::Write;
                    if let Some(ref mut stdin) = child.stdin {
                        let _ = stdin.write_all(pem.as_bytes());
                    }
                    child.wait_with_output()
                });

            if let Ok(output) = output {
                let text = String::from_utf8_lossy(&output.stdout);
                let mut subject = String::new();
                let mut issuer = String::new();
                let mut not_after = String::new();

                for line in text.lines() {
                    if let Some(val) = line.strip_prefix("subject=") {
                        subject = val.trim().to_string();
                    } else if let Some(val) = line.strip_prefix("issuer=") {
                        issuer = val.trim().to_string();
                    } else if let Some(val) = line.strip_prefix("notAfter=") {
                        not_after = val.trim().to_string();
                    }
                }

                chain.push(ChainCert {
                    depth,
                    subject,
                    issuer,
                    not_after,
                });
            }

            depth += 1;
        }
    }

    chain
}

fn parse_days_until(date_str: &str) -> Option<i64> {
    // openssl date format: "Jan  1 00:00:00 2025 GMT"
    // Use `date` command to compute diff
    let output = std::process::Command::new("date")
        .args([
            "-d",
            date_str,
            "+%s",
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let expiry_ts: i64 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .ok()?;

    let now_output = std::process::Command::new("date")
        .args(["+%s"])
        .output()
        .ok()?;

    let now_ts: i64 = String::from_utf8_lossy(&now_output.stdout)
        .trim()
        .parse()
        .ok()?;

    Some((expiry_ts - now_ts) / 86400)
}
