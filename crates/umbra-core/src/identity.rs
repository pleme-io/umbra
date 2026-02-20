use serde::{Deserialize, Serialize};
use std::env;
use std::path::Path;

/// Pod identity information gathered from environment and mounted secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodIdentity {
    pub hostname: String,
    pub namespace: Option<String>,
    pub service_account: Option<String>,
    pub node_name: Option<String>,
    pub pod_name: Option<String>,
    pub pod_ip: Option<String>,
}

impl PodIdentity {
    /// Gather pod identity from environment variables and filesystem.
    pub fn gather() -> Self {
        let hostname = env::var("HOSTNAME").unwrap_or_else(|_| {
            gethostname().unwrap_or_else(|| "unknown".to_string())
        });

        let namespace = read_file("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
            .or_else(|| env::var("POD_NAMESPACE").ok());

        let service_account =
            read_file("/var/run/secrets/kubernetes.io/serviceaccount/service-account-name")
                .or_else(|| env::var("SERVICE_ACCOUNT").ok());

        let node_name = env::var("NODE_NAME").ok();
        let pod_name = env::var("POD_NAME").ok().or_else(|| Some(hostname.clone()));
        let pod_ip = env::var("POD_IP").ok();

        Self {
            hostname,
            namespace,
            service_account,
            node_name,
            pod_name,
            pod_ip,
        }
    }
}

fn gethostname() -> Option<String> {
    let mut buf = [0u8; 256];
    let c_str = unsafe {
        if libc_gethostname(&mut buf) != 0 {
            return None;
        }
        std::ffi::CStr::from_ptr(buf.as_ptr() as *const _)
    };
    c_str.to_str().ok().map(|s| s.to_string())
}

#[cfg(unix)]
unsafe fn libc_gethostname(buf: &mut [u8]) -> i32 {
    // Safety: buf is valid, len is correct
    unsafe { libc_gethostname_raw(buf.as_mut_ptr() as *mut _, buf.len()) }
}

#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "gethostname"]
    fn libc_gethostname_raw(name: *mut std::ffi::c_char, len: usize) -> i32;
}

#[cfg(not(unix))]
unsafe fn libc_gethostname(_buf: &mut [u8]) -> i32 {
    -1
}

fn read_file(path: &str) -> Option<String> {
    if Path::new(path).exists() {
        std::fs::read_to_string(path).ok().map(|s| s.trim().to_string())
    } else {
        None
    }
}
