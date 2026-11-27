//! Runtime configuration resolved from the same environment Agentmetry's own
//! hook reads, so a wrapped agent needs no extra setup:
//!
//! - `AGENTMETRY_DATA_DIR` / platform per-user data dir (mirrors core/paths.py)
//! - `<data dir>/ingest-token`, falling back to `<data dir>/api-token`
//! - `AGENTMETRY_API_KEY` wins when set
//! - `AGENTMETRY_AUDIT_INGEST_URL` / `AGENTMETRY_URL`, default http://127.0.0.1:8000
//! - `AGENTMETRY_CORRELATION_ID` / `AGENTMETRY_SESSION_ID` tie guard events to
//!   the tool call the Python hook is recording for the same child process.

use std::path::PathBuf;

pub struct Config {
    pub data_dir: PathBuf,
    pub ingest_url: String,
    pub api_key: String,
    pub correlation_id: String,
    pub session_id: String,
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_default().trim().to_string()
}

/// Mirrors agentmetry/core/paths.py `data_dir()` for a standalone binary:
/// AGENTMETRY_DATA_DIR, then AGENTMETRY_INSTALL_ROOT/data, then the platform
/// per-user directory. (The git-checkout branch of paths.py does not apply to
/// an installed guard binary.)
pub fn data_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("AGENTMETRY_DATA_DIR") {
        if !d.is_empty() {
            return PathBuf::from(d);
        }
    }
    if let Some(root) = std::env::var_os("AGENTMETRY_INSTALL_ROOT") {
        if !root.is_empty() {
            return PathBuf::from(root).join("data");
        }
    }
    if cfg!(windows) {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().join("AppData").join("Local"));
        base.join("Agentmetry")
    } else if cfg!(target_os = "macos") {
        home()
            .join("Library")
            .join("Application Support")
            .join("Agentmetry")
    } else {
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().join(".local").join("share"));
        base.join("agentmetry")
    }
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn read_token_file(path: &PathBuf) -> String {
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// A missing default is optional. A path selected by the operator is required.
pub fn guard_config_path(data_dir: &std::path::Path) -> (PathBuf, bool) {
    match std::env::var_os("AGENTMETRY_GUARD_CONFIG") {
        Some(path) => (PathBuf::from(path), true),
        None => (data_dir.join("guard.json"), false),
    }
}

pub fn load() -> Config {
    let data_dir = data_dir();
    let api_key = {
        let from_env = env("AGENTMETRY_API_KEY");
        if !from_env.is_empty() {
            from_env
        } else {
            let ingest = read_token_file(&data_dir.join("ingest-token"));
            if !ingest.is_empty() {
                ingest
            } else {
                read_token_file(&data_dir.join("api-token"))
            }
        }
    };
    let ingest_url = {
        let u = env("AGENTMETRY_AUDIT_INGEST_URL");
        if !u.is_empty() {
            u
        } else {
            let u = env("AGENTMETRY_URL");
            if !u.is_empty() {
                u
            } else {
                "http://127.0.0.1:8000".to_string()
            }
        }
    };
    Config {
        data_dir,
        ingest_url,
        api_key,
        correlation_id: env("AGENTMETRY_CORRELATION_ID"),
        session_id: env("AGENTMETRY_SESSION_ID"),
    }
}
