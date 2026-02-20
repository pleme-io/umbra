use umbra_core::services::discover_services;

pub fn list_services() -> String {
    let services = discover_services();
    serde_json::to_string_pretty(&services).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
}
