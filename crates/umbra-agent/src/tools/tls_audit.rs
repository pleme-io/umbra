use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct TlsAuditResult {
    target: String,
    success: bool,
    vulnerabilities: Vec<TlsVuln>,
    protocols: Vec<ProtocolInfo>,
    ciphers: Vec<CipherInfo>,
    certificate: Option<CertInfo>,
    error: Option<String>,
}

#[derive(Serialize)]
struct TlsVuln {
    id: String,
    name: String,
    severity: String,
    vulnerable: bool,
}

#[derive(Serialize)]
struct ProtocolInfo {
    protocol: String,
    supported: bool,
}

#[derive(Serialize)]
struct CipherInfo {
    name: String,
    bits: Option<u32>,
    grade: String,
}

#[derive(Serialize)]
struct CertInfo {
    subject: String,
    issuer: String,
    valid_from: String,
    valid_until: String,
    sans: Vec<String>,
    key_size: Option<u32>,
    signature_algorithm: String,
}

pub async fn audit(target: &str, timeout_secs: Option<u64>) -> String {
    let timeout = timeout_secs.unwrap_or(90);

    // testssl.sh may be installed as 'testssl' or 'testssl.sh'
    let binary = if cmd::is_available("testssl").await {
        "testssl"
    } else if cmd::is_available("testssl.sh").await {
        "testssl.sh"
    } else {
        return cmd::binary_not_found("testssl", Some("testssl.sh"));
    };

    let args = [
        "--jsonfile=-",
        "--quiet",
        "--sneaky",
        "--fast",
        "--ip=one",
        target,
    ];

    let result = cmd::run(binary, &args, timeout).await;

    if !result.success && result.stdout.is_empty() {
        return serde_json::to_string_pretty(&TlsAuditResult {
            target: target.to_string(),
            success: false,
            vulnerabilities: vec![],
            protocols: vec![],
            ciphers: vec![],
            certificate: None,
            error: Some(result.stderr.trim().to_string()),
        })
        .unwrap();
    }

    let mut vulnerabilities = Vec::new();
    let mut protocols = Vec::new();
    let mut ciphers = Vec::new();
    let mut certificate = None;
    let mut cert_subject = String::new();
    let mut cert_issuer = String::new();
    let mut cert_valid_from = String::new();
    let mut cert_valid_until = String::new();
    let mut cert_sans = Vec::new();
    let mut cert_key_size: Option<u32> = None;
    let mut cert_sig_algo = String::new();
    let mut has_cert_info = false;

    // Parse JSONL output from testssl
    for line in result.stdout.lines() {
        let val: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let id = val.get("id").and_then(|i| i.as_str()).unwrap_or("");
        let finding = val.get("finding").and_then(|f| f.as_str()).unwrap_or("");
        let severity = val
            .get("severity")
            .and_then(|s| s.as_str())
            .unwrap_or("INFO");

        // Vulnerability checks
        let vuln_ids = [
            "heartbleed",
            "CCS",
            "ticketbleed",
            "ROBOT",
            "secure_renego",
            "secure_client_renego",
            "CRIME_TLS",
            "BREACH",
            "POODLE_SSL",
            "fallback_SCSV",
            "SWEET32",
            "FREAK",
            "DROWN",
            "LOGJAM",
            "BEAST",
            "LUCKY13",
            "RC4",
        ];

        if vuln_ids.iter().any(|v| id.eq_ignore_ascii_case(v)) {
            let vulnerable = severity == "CRITICAL"
                || severity == "HIGH"
                || severity == "MEDIUM"
                || severity == "WARN"
                || finding.to_lowercase().contains("vulnerable");

            vulnerabilities.push(TlsVuln {
                id: id.to_string(),
                name: finding.to_string(),
                severity: severity.to_string(),
                vulnerable,
            });
        }

        // Protocol support
        if id.starts_with("SSLv") || id.starts_with("TLS") || id.starts_with("ssl") || id.starts_with("tls") {
            let supported = finding.to_lowercase().contains("offered")
                || finding.to_lowercase().contains("yes");
            protocols.push(ProtocolInfo {
                protocol: id.to_string(),
                supported,
            });
        }

        // Certificate info
        if id.contains("cert_subject") || id == "cert_commonName" {
            cert_subject = finding.to_string();
            has_cert_info = true;
        }
        if id.contains("cert_issuer") || id == "cert_caIssuers" {
            cert_issuer = finding.to_string();
            has_cert_info = true;
        }
        if id == "cert_notBefore" {
            cert_valid_from = finding.to_string();
        }
        if id == "cert_notAfter" {
            cert_valid_until = finding.to_string();
        }
        if id == "cert_subjectAltName" {
            cert_sans = finding.split_whitespace().map(|s| s.to_string()).collect();
        }
        if id == "cert_keySize" {
            cert_key_size = finding
                .split_whitespace()
                .find_map(|w| w.parse::<u32>().ok());
        }
        if id == "cert_signatureAlgorithm" {
            cert_sig_algo = finding.to_string();
        }

        // Cipher info
        if id.starts_with("cipher_") || id.contains("cipher") {
            if !finding.is_empty() && id != "cipher_order" {
                ciphers.push(CipherInfo {
                    name: finding.to_string(),
                    bits: None,
                    grade: severity.to_string(),
                });
            }
        }
    }

    if has_cert_info {
        certificate = Some(CertInfo {
            subject: cert_subject,
            issuer: cert_issuer,
            valid_from: cert_valid_from,
            valid_until: cert_valid_until,
            sans: cert_sans,
            key_size: cert_key_size,
            signature_algorithm: cert_sig_algo,
        });
    }

    serde_json::to_string_pretty(&TlsAuditResult {
        target: target.to_string(),
        success: true,
        vulnerabilities,
        protocols,
        ciphers,
        certificate,
        error: None,
    })
    .unwrap()
}
