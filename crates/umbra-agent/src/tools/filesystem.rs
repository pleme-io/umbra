use serde::Serialize;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[derive(Serialize)]
struct FileEntry {
    name: String,
    path: String,
    file_type: String,
    size: u64,
    permissions: String,
    uid: u32,
    gid: u32,
    modified: Option<String>,
}

#[derive(Serialize)]
struct FileContent {
    path: String,
    size: u64,
    content: String,
    truncated: bool,
}

#[derive(Serialize)]
struct FileStat {
    path: String,
    exists: bool,
    file_type: String,
    size: u64,
    permissions: String,
    uid: u32,
    gid: u32,
    modified: Option<String>,
    links: u64,
    inode: u64,
    device: u64,
}

#[derive(Serialize)]
#[serde(untagged)]
enum FsResult {
    List {
        path: String,
        entries: Vec<FileEntry>,
        total: usize,
        success: bool,
        error: Option<String>,
    },
    Read {
        file: FileContent,
        success: bool,
        error: Option<String>,
    },
    Stat {
        stat: FileStat,
        success: bool,
        error: Option<String>,
    },
}

pub fn inspect(path: &str, operation: &str) -> String {
    let p = Path::new(path);

    match operation {
        "ls" => list_dir(p),
        "cat" => read_file(p),
        "stat" => stat_path(p),
        other => serde_json::json!({
            "error": format!("Unknown operation: {other}. Use ls, cat, or stat."),
            "success": false,
        })
        .to_string(),
    }
}

fn list_dir(path: &Path) -> String {
    let entries = match std::fs::read_dir(path) {
        Ok(e) => e,
        Err(e) => {
            return serde_json::to_string_pretty(&FsResult::List {
                path: path.display().to_string(),
                entries: vec![],
                total: 0,
                success: false,
                error: Some(e.to_string()),
            })
            .unwrap();
        }
    };

    let mut items: Vec<FileEntry> = entries
        .flatten()
        .filter_map(|entry| {
            let meta = entry.metadata().ok()?;
            let ft = if meta.is_dir() {
                "directory"
            } else if meta.is_symlink() {
                "symlink"
            } else {
                "file"
            };
            Some(FileEntry {
                name: entry.file_name().to_string_lossy().to_string(),
                path: entry.path().display().to_string(),
                file_type: ft.to_string(),
                size: meta.len(),
                permissions: format!("{:o}", meta.mode() & 0o7777),
                uid: meta.uid(),
                gid: meta.gid(),
                modified: meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| chrono::DateTime::from_timestamp(d.as_secs() as i64, 0))
                    .flatten()
                    .map(|dt| dt.to_rfc3339()),
            })
        })
        .collect();

    items.sort_by(|a, b| a.name.cmp(&b.name));
    let total = items.len();

    serde_json::to_string_pretty(&FsResult::List {
        path: path.display().to_string(),
        entries: items,
        total,
        success: true,
        error: None,
    })
    .unwrap()
}

fn read_file(path: &Path) -> String {
    match std::fs::read(path) {
        Ok(bytes) => {
            let size = bytes.len() as u64;
            let max_size = 32768;
            let truncated = bytes.len() > max_size;
            let content = if truncated {
                String::from_utf8_lossy(&bytes[..max_size]).to_string()
            } else {
                String::from_utf8_lossy(&bytes).to_string()
            };

            serde_json::to_string_pretty(&FsResult::Read {
                file: FileContent {
                    path: path.display().to_string(),
                    size,
                    content,
                    truncated,
                },
                success: true,
                error: None,
            })
            .unwrap()
        }
        Err(e) => serde_json::to_string_pretty(&FsResult::Read {
            file: FileContent {
                path: path.display().to_string(),
                size: 0,
                content: String::new(),
                truncated: false,
            },
            success: false,
            error: Some(e.to_string()),
        })
        .unwrap(),
    }
}

fn stat_path(path: &Path) -> String {
    match std::fs::metadata(path) {
        Ok(meta) => {
            let ft = if meta.is_dir() {
                "directory"
            } else if meta.is_symlink() {
                "symlink"
            } else {
                "file"
            };

            let modified = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| chrono::DateTime::from_timestamp(d.as_secs() as i64, 0))
                .flatten()
                .map(|dt| dt.to_rfc3339());

            serde_json::to_string_pretty(&FsResult::Stat {
                stat: FileStat {
                    path: path.display().to_string(),
                    exists: true,
                    file_type: ft.to_string(),
                    size: meta.len(),
                    permissions: format!("{:o}", meta.mode() & 0o7777),
                    uid: meta.uid(),
                    gid: meta.gid(),
                    modified,
                    links: meta.nlink(),
                    inode: meta.ino(),
                    device: meta.dev(),
                },
                success: true,
                error: None,
            })
            .unwrap()
        }
        Err(e) => serde_json::to_string_pretty(&FsResult::Stat {
            stat: FileStat {
                path: path.display().to_string(),
                exists: false,
                file_type: String::new(),
                size: 0,
                permissions: String::new(),
                uid: 0,
                gid: 0,
                modified: None,
                links: 0,
                inode: 0,
                device: 0,
            },
            success: false,
            error: Some(e.to_string()),
        })
        .unwrap(),
    }
}
