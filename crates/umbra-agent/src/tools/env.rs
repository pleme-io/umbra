use umbra_core::EnvReport;

pub fn gather_env() -> String {
    let report = EnvReport::gather();
    serde_json::to_string_pretty(&report).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
}
