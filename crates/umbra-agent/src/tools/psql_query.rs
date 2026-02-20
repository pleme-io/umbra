use crate::cmd;
use serde::Serialize;

#[derive(Serialize)]
struct PsqlResult {
    query: String,
    rows: Vec<serde_json::Value>,
    row_count: usize,
    success: bool,
    error: Option<String>,
}

pub async fn query(connection_string: &str, sql: &str) -> String {
    // Use psql with JSON output via json_agg
    // Wrap user query to get JSON output
    let json_query = format!(
        "SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) AS result FROM ({}) t",
        sql.trim_end_matches(';')
    );

    let result = cmd::run_with_env(
        "psql",
        &[
            connection_string,
            "-t",  // tuples only
            "-A",  // unaligned
            "-c",
            &json_query,
        ],
        &[("PGCONNECT_TIMEOUT", "5")],
        30,
    )
    .await;

    if !result.success {
        // Fallback: try running the query directly for non-SELECT statements
        let direct = cmd::run_with_env(
            "psql",
            &[connection_string, "-t", "-A", "-c", sql],
            &[("PGCONNECT_TIMEOUT", "5")],
            30,
        )
        .await;

        if direct.success {
            return serde_json::to_string_pretty(&PsqlResult {
                query: sql.to_string(),
                rows: vec![serde_json::json!({"result": direct.stdout.trim()})],
                row_count: 1,
                success: true,
                error: None,
            })
            .unwrap();
        }

        return serde_json::to_string_pretty(&PsqlResult {
            query: sql.to_string(),
            rows: vec![],
            row_count: 0,
            success: false,
            error: Some(result.stderr.trim().to_string()),
        })
        .unwrap();
    }

    let output = result.stdout.trim();
    match serde_json::from_str::<Vec<serde_json::Value>>(output) {
        Ok(rows) => {
            let count = rows.len();
            serde_json::to_string_pretty(&PsqlResult {
                query: sql.to_string(),
                rows,
                row_count: count,
                success: true,
                error: None,
            })
            .unwrap()
        }
        Err(_) => serde_json::to_string_pretty(&PsqlResult {
            query: sql.to_string(),
            rows: vec![serde_json::json!({"raw": output})],
            row_count: 1,
            success: true,
            error: None,
        })
        .unwrap(),
    }
}
