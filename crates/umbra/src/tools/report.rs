use crate::config::{Config, Endpoint};
use crate::pool::ConnectionPool;
use umbra_core::assessment::{AssessmentReport, Manifest};
use umbra_core::targets::TargetConfig;

/// Generate a report and optionally save to file or publish to configured endpoints.
pub async fn generate_report(
    pool: &ConnectionPool,
    config: &Config,
    connection_id: Option<&str>,
    context: Option<&str>,
    namespace: Option<&str>,
    pod: Option<&str>,
    container: Option<&str>,
    output_path: Option<&str>,
    endpoint_names: &[String],
    targets: &[TargetConfig],
) -> String {
    // Run the full assessment first
    let report_json = super::assess::full_assessment(
        pool,
        connection_id,
        context,
        namespace,
        pod,
        container,
        targets,
    )
    .await;

    // Parse the report
    let report: AssessmentReport = match serde_json::from_str(&report_json) {
        Ok(r) => r,
        Err(e) => {
            // Check if it was an error response from assessment
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&report_json) {
                if v.get("error").is_some() {
                    return report_json;
                }
            }
            return serde_json::json!({
                "error": format!("Failed to parse assessment: {e}")
            })
            .to_string();
        }
    };

    let mut result = serde_json::json!({
        "status": "generated",
        "report_id": report.id,
    });

    // Save to file if path provided
    if let Some(path) = output_path {
        match std::fs::write(path, &report_json) {
            Ok(_) => {
                result["saved_to"] = serde_json::json!(path);
            }
            Err(e) => {
                result["save_error"] = serde_json::json!(format!("Failed to save: {e}"));
            }
        }
    }

    // Resolve endpoints to publish to
    let endpoints = config.resolve_endpoints(endpoint_names);
    if !endpoints.is_empty() {
        let mut publish_results = serde_json::Map::new();
        for (name, endpoint) in &endpoints {
            match publish_to_endpoint(endpoint, &report, &report_json).await {
                Ok(info) => {
                    publish_results.insert(name.clone(), info);
                }
                Err(e) => {
                    publish_results.insert(
                        name.clone(),
                        serde_json::json!({ "error": e }),
                    );
                }
            }
        }
        result["published"] = serde_json::Value::Object(publish_results);
    }

    // Include the full report in the response
    result["report"] =
        serde_json::from_str(&report_json).unwrap_or(serde_json::Value::Null);

    serde_json::to_string_pretty(&result).unwrap()
}

/// Publish an existing report JSON to configured endpoints.
pub async fn publish_report(
    config: &Config,
    report_json: &str,
    endpoint_names: &[String],
) -> String {
    let report: AssessmentReport = match serde_json::from_str(report_json) {
        Ok(r) => r,
        Err(e) => {
            return serde_json::json!({
                "error": format!("Invalid report JSON: {e}")
            })
            .to_string();
        }
    };

    let endpoints = config.resolve_endpoints(endpoint_names);
    if endpoints.is_empty() {
        return serde_json::json!({
            "error": "No endpoints configured. Add endpoints to ~/.config/umbra/config.toml"
        })
        .to_string();
    }

    let mut results = serde_json::Map::new();
    for (name, endpoint) in &endpoints {
        match publish_to_endpoint(endpoint, &report, report_json).await {
            Ok(info) => {
                results.insert(name.clone(), info);
            }
            Err(e) => {
                results.insert(name.clone(), serde_json::json!({ "error": e }));
            }
        }
    }

    serde_json::json!({
        "status": "published",
        "report_id": report.id,
        "endpoints": results,
    })
    .to_string()
}

/// Publish to a single endpoint: upload report, update manifest, sync viewer.
async fn publish_to_endpoint(
    endpoint: &Endpoint,
    report: &AssessmentReport,
    report_json: &str,
) -> Result<serde_json::Value, String> {
    let bp = endpoint.bucket_prefix();
    let extra_args = endpoint.aws_args();

    // 1. Upload report.json
    let report_key = format!("reports/{}/report.json", report.id);
    s3_put(&bp, &report_key, report_json, "application/json", &extra_args).await?;

    // 2. Download existing manifest or create new
    let manifest_json = s3_get(&bp, "manifest.json", &extra_args).await;
    let mut manifest: Manifest = manifest_json
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| Manifest {
            version: "1".into(),
            updated: String::new(),
            reports: Vec::new(),
        });

    // 3. Add or update entry
    let entry = report.to_manifest_entry(&report_key);
    if let Some(pos) = manifest.reports.iter().position(|r| r.id == report.id) {
        manifest.reports[pos] = entry;
    } else {
        manifest.reports.push(entry);
    }
    manifest.updated = report.timestamp.clone();

    // 4. Upload manifest
    let manifest_str =
        serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?;
    s3_put(&bp, "manifest.json", &manifest_str, "application/json", &extra_args).await?;

    // 5. Sync viewer if not yet deployed
    let viewer_status = sync_viewer_assets(&bp, &extra_args).await;

    let mut info = serde_json::json!({
        "bucket": endpoint.bucket,
        "prefix": endpoint.prefix,
        "report_key": report_key,
        "total_reports": manifest.reports.len(),
    });

    if let Some(url) = endpoint.viewer_url() {
        info["viewer_url"] = serde_json::json!(url);
    }

    match viewer_status {
        Ok(msg) => info["viewer_assets"] = serde_json::json!(msg),
        Err(msg) => info["viewer_assets_error"] = serde_json::json!(msg),
    }

    Ok(info)
}

/// Sync the viewer dist/ directory to S3.
async fn sync_viewer_assets(
    bucket_prefix: &str,
    extra_args: &[String],
) -> Result<String, String> {
    // Check if index.html already exists — skip if so
    if s3_head(bucket_prefix, "index.html", extra_args)
        .await
        .is_ok()
    {
        return Ok("already deployed".into());
    }

    let dist_path = find_viewer_dist()?;
    upload_dist_files(bucket_prefix, &dist_path, extra_args).await
}

/// Upload dist files one by one with correct content types.
async fn upload_dist_files(
    bucket_prefix: &str,
    dist_path: &str,
    extra_args: &[String],
) -> Result<String, String> {
    let mut uploaded = 0;

    for entry in walkdir(dist_path)? {
        let rel = entry
            .strip_prefix(dist_path)
            .unwrap_or(&entry)
            .trim_start_matches('/');

        if rel.ends_with(".map") {
            continue;
        }

        let content_type = match rel.rsplit('.').next() {
            Some("html") => "text/html; charset=utf-8",
            Some("css") => "text/css; charset=utf-8",
            Some("js") => "application/javascript; charset=utf-8",
            Some("json") => "application/json",
            Some("svg") => "image/svg+xml",
            Some("png") => "image/png",
            Some("ico") => "image/x-icon",
            _ => "application/octet-stream",
        };

        let mut args = vec![
            "s3".into(),
            "cp".into(),
            entry.clone(),
            format!("s3://{bucket_prefix}/{rel}"),
            "--content-type".into(),
            content_type.into(),
        ];
        args.extend_from_slice(extra_args);

        let result = tokio::process::Command::new("aws")
            .args(&args)
            .output()
            .await
            .map_err(|e| format!("aws s3 cp {rel}: {e}"))?;

        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            return Err(format!("Failed to upload {rel}: {}", stderr.trim()));
        }

        uploaded += 1;
    }

    Ok(format!("uploaded {uploaded} files"))
}

fn walkdir(dir: &str) -> Result<Vec<String>, String> {
    let mut files = Vec::new();
    walk_recursive(dir, &mut files)?;
    Ok(files)
}

fn walk_recursive(dir: &str, files: &mut Vec<String>) -> Result<(), String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("Cannot read {dir}: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let path_str = path.to_string_lossy().to_string();
        if path.is_dir() {
            walk_recursive(&path_str, files)?;
        } else {
            files.push(path_str);
        }
    }
    Ok(())
}

fn find_viewer_dist() -> Result<String, String> {
    if let Ok(dist) = std::env::var("UMBRA_VIEWER_DIST") {
        let p = std::path::Path::new(&dist);
        if p.exists() {
            return Ok(dist);
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let dist = parent.join("viewer-dist");
            if dist.exists() {
                return Ok(dist.to_string_lossy().to_string());
            }
        }
    }

    let candidates = ["viewer/dist", "../viewer/dist", "../../viewer/dist"];
    for c in candidates {
        let p = std::path::Path::new(c);
        if p.exists() && p.join("index.html").exists() {
            return Ok(
                p.canonicalize()
                    .map_err(|e| e.to_string())?
                    .to_string_lossy()
                    .to_string(),
            );
        }
    }

    Err(
        "Viewer dist not found. Set UMBRA_VIEWER_DIST or build the viewer (cd viewer && bun run build)."
            .into(),
    )
}

// --- S3 helpers ---

async fn s3_put(
    bucket_prefix: &str,
    key: &str,
    body: &str,
    content_type: &str,
    extra_args: &[String],
) -> Result<(), String> {
    let tmp = format!("/tmp/umbra-upload-{}", key.replace('/', "-"));
    std::fs::write(&tmp, body).map_err(|e| format!("write tmp: {e}"))?;

    let mut args = vec![
        "s3".into(),
        "cp".into(),
        tmp.clone(),
        format!("s3://{bucket_prefix}/{key}"),
        "--content-type".into(),
        content_type.into(),
    ];
    args.extend_from_slice(extra_args);

    let result = tokio::process::Command::new("aws")
        .args(&args)
        .output()
        .await
        .map_err(|e| format!("aws s3 cp: {e}"))?;

    let _ = std::fs::remove_file(&tmp);

    if result.status.success() {
        Ok(())
    } else {
        Err(format!(
            "S3 PUT {key}: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        ))
    }
}

async fn s3_get(
    bucket_prefix: &str,
    key: &str,
    extra_args: &[String],
) -> Result<String, String> {
    let tmp = format!("/tmp/umbra-download-{}", key.replace('/', "-"));

    let mut args = vec![
        "s3".into(),
        "cp".into(),
        format!("s3://{bucket_prefix}/{key}"),
        tmp.clone(),
    ];
    args.extend_from_slice(extra_args);

    let result = tokio::process::Command::new("aws")
        .args(&args)
        .output()
        .await
        .map_err(|e| format!("aws s3 cp: {e}"))?;

    if !result.status.success() {
        return Err(format!(
            "S3 GET {key}: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        ));
    }

    let content = std::fs::read_to_string(&tmp).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&tmp);
    Ok(content)
}

async fn s3_head(
    bucket_prefix: &str,
    key: &str,
    extra_args: &[String],
) -> Result<(), String> {
    let bucket = bucket_prefix.split('/').next().unwrap_or(bucket_prefix);
    let full_key = if bucket_prefix.contains('/') {
        format!(
            "{}/{}",
            bucket_prefix.splitn(2, '/').nth(1).unwrap_or(""),
            key
        )
    } else {
        key.to_string()
    };

    let mut args = vec![
        "s3api".into(),
        "head-object".into(),
        "--bucket".into(),
        bucket.into(),
        "--key".into(),
        full_key,
    ];
    args.extend_from_slice(extra_args);

    let result = tokio::process::Command::new("aws")
        .args(&args)
        .output()
        .await
        .map_err(|e| format!("aws s3api: {e}"))?;

    if result.status.success() {
        Ok(())
    } else {
        Err("not found".into())
    }
}
