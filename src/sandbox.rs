//! OS-native user-space sandbox wrapper. Phase 1 keeps the network stack
//! shared (egress goes through the proxy via env vars) and hides well-known
//! credential locations instead of maintaining a denylist of paths:
//!
//! - macOS: a generated Seatbelt profile run through `sandbox-exec`.
//! - Linux: Bubblewrap with a tmpfs (or /dev/null for files) over each
//!   sensitive path that exists.
//! - anything else (incl. Windows): no wrapper; the proxy env injection is
//!   the whole measure. stderr reports the requested launch mode.

use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::process::Command;

const SEATBELT: &str = "/usr/bin/sandbox-exec";
const BWRAP: &[&str] = &["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxKind {
    Seatbelt,
    Bwrap,
    None,
}

pub fn detect() -> SandboxKind {
    if cfg!(target_os = "macos") && Path::new(SEATBELT).is_file() {
        SandboxKind::Seatbelt
    } else if cfg!(target_os = "linux") && bwrap_path().is_some() {
        SandboxKind::Bwrap
    } else {
        SandboxKind::None
    }
}

fn bwrap_path() -> Option<&'static str> {
    BWRAP
        .iter()
        .copied()
        .find(|candidate| Path::new(candidate).is_file())
}

/// Credential locations hidden when a wrapper is available. Dirs get a tmpfs
/// (bwrap) or a file-read deny (Seatbelt); plain files get /dev/null bind or a
/// read deny. `.env` is deliberately NOT listed: it is per-project, and hiding
/// the wrong one breaks legitimate local runs.
const SENSITIVE_DIRS: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".docker",
    ".azure",
    ".gcloud",
    ".config/gcloud",
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
fn wrap_command(
    kind: SandboxKind,
    program: &str,
    args: &[String],
) -> io::Result<(String, Vec<String>)> {
    match kind {
        SandboxKind::Seatbelt => {
            let mut argv = vec![
                "-p".to_string(),
                seatbelt_profile(&home())?,
                "--".to_string(),
                program.to_string(),
            ];
            argv.extend(args.iter().cloned());
            Ok((SEATBELT.to_string(), argv))
        }
        SandboxKind::Bwrap => {
            let binary = bwrap_path().ok_or_else(|| {
                io::Error::new(ErrorKind::NotFound, "Bubblewrap disappeared before launch")
            })?;
            let mut argv = vec![
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
                    argv.push(path_arg(&p)?.to_string());
                }
            }
            for rel in SENSITIVE_FILES {
                let p = home.join(rel);
                if p.is_file() {
                    argv.push("--ro-bind".to_string());
                    argv.push("/dev/null".to_string());
                    argv.push(path_arg(&p)?.to_string());
                }
            }
            argv.push("--".to_string());
            argv.push(program.to_string());
            argv.extend(args.iter().cloned());
            Ok((binary.to_string(), argv))
        }
        SandboxKind::None => Ok((program.to_string(), args.to_vec())),
    }
}

fn path_arg(path: &Path) -> io::Result<&str> {
    path.to_str()
        .filter(|path| !path.chars().any(char::is_control))
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "unsupported sandbox path"))
}

fn seatbelt_path(path: &Path) -> io::Result<String> {
    Ok(path_arg(path)?.replace('\\', "\\\\").replace('"', "\\\""))
}

fn seatbelt_profile(home: &Path) -> io::Result<String> {
    let mut sb = String::from("(version 1)\n(allow default)\n");
    for rel in SENSITIVE_DIRS {
        let p = home.join(rel);
        if p.is_dir() {
            sb.push_str(&format!(
                "(deny file-read* (subpath \"{}\"))\n",
                seatbelt_path(&p)?
            ));
        }
    }
    for rel in SENSITIVE_FILES {
        let p = home.join(rel);
        if p.is_file() {
            sb.push_str(&format!(
                "(deny file-read* (literal \"{}\"))\n",
                seatbelt_path(&p)?
            ));
        }
    }
    Ok(sb)
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
    let (bin, argv) = wrap_command(kind, program, args)?;
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
    eprintln!(
        "agentmetry-guard: requested launch mode: {}",
        kind_name(kind)
    );
    let status = cmd.status()?;
    Ok(status.code().unwrap_or(-1))
}

fn kind_name(kind: SandboxKind) -> &'static str {
    match kind {
        SandboxKind::Seatbelt => "seatbelt",
        SandboxKind::Bwrap => "bwrap",
        SandboxKind::None => "env-only",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seatbelt_quotes_quoted_paths_without_changing_the_rule_shape() {
        assert_eq!(
            seatbelt_path(Path::new("/synthetic/home\"with\\quotes")).unwrap(),
            "/synthetic/home\\\"with\\\\quotes",
        );
        assert!(seatbelt_path(Path::new("/synthetic/home\nnewline")).is_err());
    }
}
