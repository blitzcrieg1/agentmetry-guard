//! OS-native user-space sandbox wrapper. Phase 1 keeps the network stack
//! shared (egress goes through the proxy via env vars) and hides well-known
//! credential locations instead of maintaining a denylist of paths:
//!
//! - macOS: a generated Seatbelt profile run through `sandbox-exec`.
//! - Linux: Bubblewrap with a tmpfs (or /dev/null for files) over each
//!   sensitive path that exists.
//! - anything else (incl. Windows): no wrapper; the proxy env injection is
//!   the whole measure. Reported in the wrap start event so a reader of the
//!   trail can tell which mode ran.

use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxKind {
    Seatbelt,
    Bwrap,
    None,
}

pub fn detect() -> SandboxKind {
    if cfg!(target_os = "macos") && which("sandbox-exec") {
        SandboxKind::Seatbelt
    } else if cfg!(target_os = "linux") && which("bwrap") {
        SandboxKind::Bwrap
    } else {
        SandboxKind::None
    }
}

fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|p| p.join(bin).is_file()))
        .unwrap_or(false)
}

/// Credential locations hidden when a wrapper is available. Dirs get a tmpfs
/// (bwrap) or a file-read deny (Seatbelt); plain files get /dev/null bind or a
/// read deny. `.env` is deliberately NOT listed: it is per-project, and hiding
/// the wrong one breaks legitimate local runs.
const SENSITIVE_DIRS: &[&str] = &[
    ".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure", ".gcloud", ".config/gcloud",
];
const SENSITIVE_FILES: &[&str] = &[".netrc", ".git-credentials", ".npmrc", ".pypirc"];

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Build the wrapper command. Returns the argv prefix that executes `program`
/// with `args` inside the sandbox, or just [program, args...] when no wrapper
/// is available.
pub fn wrap_command(kind: SandboxKind, program: &str, args: &[String]) -> (String, Vec<String>) {
    match kind {
        SandboxKind::Seatbelt => {
            let profile = seatbelt_profile();
            let dir = std::env::temp_dir().join(format!("agentmetry-guard-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&dir);
            let profile_path = dir.join("guard.sb");
            if std::fs::write(&profile_path, profile).is_ok() {
                let mut argv = vec![
                    "sandbox-exec".to_string(),
                    "-f".to_string(),
                    profile_path.to_string_lossy().into_owned(),
                    "--".to_string(),
                    program.to_string(),
                ];
                argv.extend(args.iter().cloned());
                return ("sandbox-exec".to_string(), argv[1..].to_vec());
            }
            (program.to_string(), args.to_vec())
        }
        SandboxKind::Bwrap => {
            let mut argv = vec![
                "bwrap".to_string(),
                "--ro-bind".to_string(),
                "/".to_string(),
                "/".to_string(),
                "--dev".to_string(),
                "/dev".to_string(),
                "--proc".to_string(),
                "/proc".to_string(),
            ];
            let home = home();
            for rel in SENSITIVE_DIRS {
                let p = home.join(rel);
                if p.is_dir() {
                    argv.push("--tmpfs".to_string());
                    argv.push(p.to_string_lossy().into_owned());
                }
            }
            for rel in SENSITIVE_FILES {
                let p = home.join(rel);
                if p.is_file() {
                    argv.push("--ro-bind".to_string());
                    argv.push("/dev/null".to_string());
                    argv.push(p.to_string_lossy().into_owned());
                }
            }
            argv.push("--".to_string());
            argv.push(program.to_string());
            argv.extend(args.iter().cloned());
            ("bwrap".to_string(), argv[1..].to_vec())
        }
        SandboxKind::None => (program.to_string(), args.to_vec()),
    }
}

fn seatbelt_profile() -> String {
    let home = home();
    let mut sb = String::from("(version 1)\n(allow default)\n");
    for rel in SENSITIVE_DIRS {
        let p = home.join(rel);
        if p.is_dir() {
            sb.push_str(&format!("(deny file-read* (subpath \"{}\"))\n", p.display()));
        }
    }
    for rel in SENSITIVE_FILES {
        let p = home.join(rel);
        if p.is_file() {
            sb.push_str(&format!("(deny file-read* (literal \"{}\"))\n", p.display()));
        }
    }
    sb
}

/// Spawn `program args` with the proxy environment injected, inside the
/// sandbox wrapper when one is available. Returns the child's exit code.
pub fn run_wrapped(
    kind: SandboxKind,
    program: &str,
    args: &[String],
    proxy_port: u16,
    extra_env: &[(String, String)],
) -> std::io::Result<i32> {
    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);
    let no_proxy = "localhost,127.0.0.1,::1";
    let (bin, argv) = wrap_command(kind, program, args);
    let mut cmd = Command::new(&bin);
    cmd.args(&argv);
    // Proxy env: both cases, since tools read either.
    for (k, v) in [
        ("HTTP_PROXY", proxy_url.as_str()),
        ("HTTPS_PROXY", proxy_url.as_str()),
        ("ALL_PROXY", proxy_url.as_str()),
        ("http_proxy", proxy_url.as_str()),
        ("https_proxy", proxy_url.as_str()),
        ("all_proxy", proxy_url.as_str()),
        ("NO_PROXY", no_proxy),
        ("no_proxy", no_proxy),
    ] {
        cmd.env(k, v);
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.env("AGENTMETRY_GUARD", "1");
    cmd.env("AGENTMETRY_GUARD_PROXY_PORT", proxy_port.to_string());
    let status = cmd.status()?;
    Ok(status.code().unwrap_or(-1))
}

/// Used by `wrap` to report which sandbox ran, for the trail.
pub fn kind_name(kind: SandboxKind) -> &'static str {
    match kind {
        SandboxKind::Seatbelt => "seatbelt",
        SandboxKind::Bwrap => "bwrap",
        SandboxKind::None => "env-only",
    }
}
