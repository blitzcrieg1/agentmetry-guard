//! OS-native user-space sandbox wrapper. Phase 1 keeps the network stack
//! shared (egress goes through the proxy via env vars) and hides well-known
//! credential locations instead of maintaining a denylist of paths:
//!
//! - macOS: a generated Seatbelt profile run through `sandbox-exec`.
//! - Linux: Bubblewrap with a tmpfs (or /dev/null for files) over each
//!   sensitive path that exists. The root is bound read-only, so the wrapped
//!   command's own workspace stays writable by default (current directory and
//!   `/tmp`), plus any operator-listed paths in `guard.json`.
//! - anything else (incl. Windows): no wrapper; the proxy env injection is
//!   the whole measure. stderr reports the requested launch mode.
//!
//! Sensitive overlays are applied after the writable binds, so hiding always
//! wins over exposing: a writable path inside a sensitive directory is
//! skipped with a warning, never silently shadowed.

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

/// Writable workspace configuration for the Linux Bubblewrap wrapper, from
/// `guard.json` (`writable_paths`, `writable_defaults`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Writable {
    /// Bind the current directory writable and mount a fresh `/tmp`.
    pub defaults: bool,
    /// Extra writable paths, already home-expanded and cleaned.
    pub paths: Vec<PathBuf>,
}

impl Default for Writable {
    fn default() -> Self {
        Writable {
            defaults: true,
            paths: Vec::new(),
        }
    }
}

impl Writable {
    pub fn from_config(defaults: Option<bool>, paths: Vec<String>, home: &Path) -> Writable {
        Writable {
            defaults: defaults.unwrap_or(true),
            paths: paths
                .iter()
                .map(|p| expand_home(p, home))
                .filter(|p| !p.as_os_str().is_empty())
                .collect(),
        }
    }
}

/// `~` and `~/rest` expand against `home`; anything else is taken as-is.
pub fn expand_home(path: &str, home: &Path) -> PathBuf {
    if path == "~" {
        return home.to_path_buf();
    }
    if let Some(rest) = path.strip_prefix("~/") {
        return home.join(rest);
    }
    PathBuf::from(path)
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

/// A writable path that is itself inside (or equal to) a sensitive directory
/// would be shadowed by the sensitive overlay applied afterwards; refuse it
/// explicitly instead. A writable path that merely contains a sensitive
/// directory (e.g. the whole home) is fine: the overlay re-hides it.
fn under_sensitive(home: &Path, candidate: &Path) -> bool {
    SENSITIVE_DIRS.iter().any(|rel| {
        let sensitive = home.join(rel);
        candidate == sensitive || candidate.starts_with(&sensitive)
    })
}

/// Build the wrapper command. Returns the argv prefix that executes `program`
/// with `args` inside the sandbox, or just [program, args...] when no wrapper
/// is available.
fn wrap_command(
    kind: SandboxKind,
    writable: &Writable,
    cwd: Option<&Path>,
    program: &str,
    args: &[String],
) -> io::Result<(String, Vec<String>, Vec<String>)> {
    let warnings: Vec<String> = Vec::new();
    match kind {
        SandboxKind::Seatbelt => {
            let mut argv = vec![
                "-p".to_string(),
                seatbelt_profile(&home())?,
                "--".to_string(),
                program.to_string(),
            ];
            argv.extend(args.iter().cloned());
            Ok((SEATBELT.to_string(), argv, warnings))
        }
        SandboxKind::Bwrap => {
            let binary = bwrap_path().ok_or_else(|| {
                io::Error::new(ErrorKind::NotFound, "Bubblewrap disappeared before launch")
            })?;
            let (argv, warnings) = bwrap_argv(&home(), cwd, writable, program, args)?;
            Ok((binary.to_string(), argv, warnings))
        }
        SandboxKind::None => Ok((program.to_string(), args.to_vec(), warnings)),
    }
}

/// Pure argv construction for the Bubblewrap wrapper: no filesystem probe for
/// the binary itself, so tests can build and inspect argv on any host.
fn bwrap_argv(
    home: &Path,
    cwd: Option<&Path>,
    writable: &Writable,
    program: &str,
    args: &[String],
) -> io::Result<(Vec<String>, Vec<String>)> {
    let mut warnings: Vec<String> = Vec::new();
    let mut argv = vec![
        "--ro-bind".to_string(),
        "/".to_string(),
        "/".to_string(),
        "--dev".to_string(),
        "/dev".to_string(),
        "--proc".to_string(),
        "/proc".to_string(),
    ];
    // Mount the fresh /tmp before putting workspace binds inside it.
    // Sensitive overlays come last so they also cover writable workspaces.
    if writable.defaults {
        argv.push("--tmpfs".to_string());
        argv.push("/tmp".to_string());
        if let Some(cwd) = cwd.filter(|path| *path != Path::new("/tmp")) {
            if cwd.is_dir() {
                argv.push("--bind".to_string());
                argv.push(path_arg(cwd)?.to_string());
                argv.push(path_arg(cwd)?.to_string());
            } else {
                warnings.push(format!(
                    "writable default {} does not exist; skipped",
                    cwd.display()
                ));
            }
        }
    }
    for path in &writable.paths {
        if under_sensitive(home, path) {
            warnings.push(format!(
                "writable path {} is inside a hidden credential directory; skipped",
                path.display()
            ));
            continue;
        }
        if !path.is_dir() {
            warnings.push(format!(
                "writable path {} does not exist; skipped",
                path.display()
            ));
            continue;
        }
        argv.push("--bind".to_string());
        argv.push(path_arg(path)?.to_string());
        argv.push(path_arg(path)?.to_string());
    }
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
    Ok((argv, warnings))
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
    writable: &Writable,
    program: &str,
    args: &[String],
    proxy_port: u16,
    extra_env: &[(String, String)],
) -> std::io::Result<i32> {
    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);
    let no_proxy = "localhost,127.0.0.1,::1";
    let cwd = std::env::current_dir().ok();
    let (bin, argv, warnings) = wrap_command(kind, writable, cwd.as_deref(), program, args)?;
    for warning in &warnings {
        eprintln!("agentmetry-guard: {warning}");
    }
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

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "guard-sandbox-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn expand_home_shapes() {
        let home = Path::new("/home/dev");
        assert_eq!(expand_home("~", home), PathBuf::from("/home/dev"));
        assert_eq!(expand_home("~/.cache", home), PathBuf::from("/home/dev/.cache"));
        assert_eq!(expand_home("/srv/work", home), PathBuf::from("/srv/work"));
        assert_eq!(expand_home("", home), PathBuf::from(""));
    }

    #[test]
    fn writable_config_defaults_to_on() {
        let home = Path::new("/home/dev");
        let w = Writable::from_config(None, vec![], home);
        assert!(w.defaults);
        let w = Writable::from_config(Some(false), vec!["~/.cache".to_string()], home);
        assert!(!w.defaults);
        assert_eq!(w.paths, vec![PathBuf::from("/home/dev/.cache")]);
    }

    #[test]
    fn bwrap_binds_the_workspace_before_hiding_credentials() {
        let home = scratch("home");
        let cwd = scratch("cwd");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::create_dir_all(home.join(".aws")).unwrap();

        let (argv, warnings) =
            bwrap_argv(&home, Some(&cwd), &Writable::default(), "server", &["--stdio".into()])
                .unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");

        let cwd_str = cwd.to_str().unwrap();
        let ssh_str = home.join(".ssh").to_str().unwrap().to_string();
        let cwd_pos = argv
            .iter()
            .position(|a| a.as_str() == cwd_str)
            .expect("cwd is bound writable");
        // Both sides of the --bind pair.
        assert_eq!(argv[cwd_pos - 1], "--bind");
        assert_eq!(argv[cwd_pos + 1], cwd_str);
        let ssh_pos = argv
            .iter()
            .position(|a| a.as_str() == ssh_str)
            .expect("sensitive dir is overlaid");
        assert_eq!(argv[ssh_pos - 1], "--tmpfs");
        // Hiding must come after the writable bind, or the tmpfs would be
        // shadowed by the later mount.
        assert!(
            cwd_pos < ssh_pos,
            "writable bind must precede the sensitive overlay"
        );
        // /tmp must be mounted first or it shadows a workspace beneath it.
        let tmp_pos = argv.iter().position(|a| a == "/tmp").unwrap();
        assert_eq!(argv[tmp_pos - 1], "--tmpfs");
        assert!(tmp_pos < cwd_pos);
        // The command itself is last, after `--`.
        assert_eq!(argv.last().unwrap(), "--stdio");
        assert!(argv.contains(&"--".to_string()));

        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&cwd);
    }

    #[test]
    fn bwrap_keeps_the_tmp_root_private_when_it_is_the_current_directory() {
        let home = scratch("tmp-root-home");
        let (argv, _) = bwrap_argv(
            &home,
            Some(Path::new("/tmp")),
            &Writable::default(),
            "server",
            &[],
        )
        .unwrap();
        assert!(argv.windows(2).any(|args| args == ["--tmpfs", "/tmp"]));
        assert!(!argv.windows(2).any(|args| args == ["--bind", "/tmp"]));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn bwrap_defaults_off_removes_the_workspace_writes() {
        let home = scratch("home-off");
        let cwd = scratch("cwd-off");
        let writable = Writable {
            defaults: false,
            paths: vec![],
        };
        let (argv, _warnings) =
            bwrap_argv(&home, Some(&cwd), &writable, "server", &[]).unwrap();
        assert!(!argv.iter().any(|a| a == "/tmp"));
        assert!(!argv.iter().any(|a| a.as_str() == cwd.to_str().unwrap()));

        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&cwd);
    }

    #[test]
    fn bwrap_refuses_writable_paths_that_would_re_expose_credentials() {
        let home = scratch("home-guard");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        let ssh = home.join(".ssh");
        let cache = home.join(".cache");
        std::fs::create_dir_all(&cache).unwrap();

        let writable = Writable {
            defaults: false,
            paths: vec![ssh.clone(), cache.clone(), home.join(".missing")],
        };
        let (argv, warnings) = bwrap_argv(&home, None, &writable, "server", &[]).unwrap();
        // The sensitive-adjacent bind is refused with a warning...
        assert!(!argv
            .windows(2)
            .any(|w| w[0] == "--bind" && w[1].as_str() == ssh.to_str().unwrap()));
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].contains("credential directory"));
        assert!(warnings[1].contains("does not exist"));
        // ...while a legitimate cache dir passes through as a bind pair.
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "--bind" && w[1].as_str() == cache.to_str().unwrap()));

        let _ = std::fs::remove_dir_all(&home);
    }
}
