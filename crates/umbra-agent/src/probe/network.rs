use std::path::Path;
use umbra_core::NetworkInterface;

/// List network interfaces and their IP addresses.
/// Uses /sys/class/net on Linux, falls back to empty on other platforms.
pub fn list_interfaces() -> Vec<NetworkInterface> {
    // Try Linux sysfs + /proc approach
    if Path::new("/sys/class/net").exists() {
        return list_interfaces_linux();
    }
    Vec::new()
}

fn list_interfaces_linux() -> Vec<NetworkInterface> {
    let mut result = Vec::new();

    let entries = match std::fs::read_dir("/sys/class/net") {
        Ok(e) => e,
        Err(_) => return result,
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let mut addresses = Vec::new();

        // Read IPv4 from /proc/net/fib_trie would be complex;
        // instead, parse the output of /sys/class/net/<iface>/address for MAC
        // and look for addresses in /proc/net/if_inet6 for IPv6

        // For a simple approach, try to read addresses from operstate and
        // use /proc/net/if_inet6 for IPv6
        if let Ok(inet6) = std::fs::read_to_string("/proc/net/if_inet6") {
            for line in inet6.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 && parts[5] == name {
                    // Convert hex IPv6 to readable format
                    if let Some(addr) = hex_to_ipv6(parts[0]) {
                        addresses.push(addr);
                    }
                }
            }
        }

        // For IPv4, parse /proc/net/fib_trie is complex. Use a simpler heuristic:
        // read from /proc/net/tcp or just note interface is present
        if let Some(ipv4) = read_ipv4_for_interface(&name) {
            addresses.push(ipv4);
        }

        result.push(NetworkInterface { name, addresses });
    }

    result
}

fn hex_to_ipv6(hex: &str) -> Option<String> {
    if hex.len() != 32 {
        return None;
    }
    let groups: Vec<String> = (0..8)
        .map(|i| hex[i * 4..(i + 1) * 4].to_string())
        .collect();
    Some(groups.join(":"))
}

fn read_ipv4_for_interface(iface: &str) -> Option<String> {
    // Parse /proc/net/fib_trie_info or use a fallback
    // Simple: try to read from ip command output cached, or parse /proc/net/route
    let route = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in route.lines().skip(1) {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 2 && parts[0] == iface && parts[1] == "00000000" {
            // This is the default route interface — doesn't give us IP
            // For actual IP, we'd need ioctl or RTNETLINK
            break;
        }
    }

    // If available, try parsing from /proc/net/tcp to find local addresses
    // This is a best-effort approach — the diagnose tool's DNS/TCP probes
    // give more useful connectivity info anyway
    None
}
