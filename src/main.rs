//! agentmetry-guard: user-space egress visibility sidecar for Agentmetry.
//!
//! Two subcommands:
//!
//!   agentmetry-guard proxy [--events-file PATH] [--deny hosts] [--allow hosts]
//!       Run the loopback proxy; print the chosen port on stdout. Used when
//!       the caller wants to manage the proxy process itself.
//!
//!   agentmetry-guard wrap  [--events-file PATH] [--deny hosts] [--allow hosts] -- <command...>
//!       Start the proxy on an ephemeral port, inject HTTP(S)_PROXY into the
//!       child's environment, run the command inside the OS-native user-space
//!       sandbox (Seatbelt on macOS, Bubblewrap on Linux, env-only elsewhere),
//!       wait for it, and exit with its exit code. Every intercepted request
//!       is emitted as a `network_egress` event correlated by
//!       AGENTMETRY_CORRELATION_ID.
//!
//! Host policy precedence, per list (deny/allow): CLI flag > environment
//! (AGENTMETRY_GUARD_DENY / AGENTMETRY_GUARD_ALLOW) > `<data dir>/guard.json`.
//! An empty allowlist allows everything; a non-empty one blocks all
//! non-matching hosts (outcome=denied, policy="allowlist" in the event).
//!
//! Events go to `--events-file` (JSONL) and, when a token is available, are
//! POSTed to Agentmetry's local ingest as source_app=agentmetry,
//! adapter=guard.

mod config;
mod emit;
mod fileconf;
mod json;
mod policy;
mod proxy;
mod sandbox;
mod timeutil;

use policy::Policy;
use std::sync::Arc;

struct Options {
    events_file: Option<std::path::PathBuf>,
    deny: Option<Vec<String>>,
    allow: Option<Vec<String>>,
}

fn parse_list(value: &str) -> Result<Vec<String>, String> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(|item| {
            let host = item.trim();
            if fileconf::valid_host(host) {
                Ok(host.to_string())
            } else {
                Err("invalid host in a guard allow or deny list".to_string())
            }
        })
        .collect()
}

fn parse_opts(args: &[String]) -> Result<Options, String> {
    let mut opts = Options {
        events_file: None,
        deny: None,
        allow: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--events-file" => {
                i += 1;
                opts.events_file = Some(std::path::PathBuf::from(
                    args.get(i).ok_or("--events-file needs a path")?,
                ));
            }
            "--deny" => {
                i += 1;
                opts.deny = Some(parse_list(
                    args.get(i).ok_or("--deny needs a comma-separated list")?,
                )?);
            }
            "--allow" => {
                i += 1;
                opts.allow = Some(parse_list(
                    args.get(i).ok_or("--allow needs a comma-separated list")?,
                )?);
            }
            _ => return Err("unknown guard option".to_string()),
        }
        i += 1;
    }
    Ok(opts)
}

fn resolve_list(
    cli: Option<Vec<String>>,
    name: &str,
    file: Vec<String>,
) -> Result<Vec<String>, String> {
    if let Some(cli) = cli {
        return Ok(cli);
    }
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => parse_list(&value),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err("guard policy list must be UTF-8".to_string())
        }
        _ => Ok(file),
    }
}

/// Load the file once and resolve overrides before starting the proxy or child.
fn resolve_options(
    opts: Options,
    cfg: &config::Config,
) -> Result<(Policy, std::path::PathBuf), String> {
    let (path, required) = config::guard_config_path(&cfg.data_dir);
    let file = fileconf::load(&path, required)?;
    let policy = Policy {
        deny: resolve_list(opts.deny, "AGENTMETRY_GUARD_DENY", file.deny)?,
        allow: resolve_list(opts.allow, "AGENTMETRY_GUARD_ALLOW", file.allow)?,
    };
    let events_file = opts
        .events_file
        .or_else(|| {
            std::env::var_os("AGENTMETRY_GUARD_EVENTS_FILE")
                .filter(|p| !p.is_empty())
                .map(std::path::PathBuf::from)
        })
        .or(file.events_file)
        .unwrap_or_else(|| cfg.data_dir.join("guard-events.jsonl"));
    Ok((policy, events_file))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(|s| s.as_str()) {
        Some("proxy") => cmd_proxy(&args[1..]),
        Some("wrap") => cmd_wrap(&args[1..]),
        Some("-h") | Some("--help") | None => {
            print_help();
            0
        }
        Some(_) => {
            eprintln!("unknown guard subcommand");
            print_help();
            2
        }
    };
    std::process::exit(code);
}

fn print_help() {
    eprintln!(
        "agentmetry-guard {}\n\nUSAGE:\n  agentmetry-guard proxy [--events-file PATH] [--deny hosts] [--allow hosts]\n  agentmetry-guard wrap  [--events-file PATH] [--deny hosts] [--allow hosts] -- <command...>\n\nPolicy precedence per list: CLI flag > AGENTMETRY_GUARD_DENY/ALLOW > <data dir>/guard.json\n",
        env!("CARGO_PKG_VERSION")
    );
}

fn build_emitter(
    events_file: std::path::PathBuf,
    cfg: &config::Config,
) -> Result<Arc<emit::Emitter>, String> {
    emit::Emitter::new(cfg_owned(cfg), Some(events_file))
        .map(Arc::new)
        .map_err(|e| format!("cannot open events file: {}", e))
}

fn cfg_owned(cfg: &config::Config) -> config::Config {
    config::Config {
        data_dir: cfg.data_dir.clone(),
        ingest_url: cfg.ingest_url.clone(),
        api_key: cfg.api_key.clone(),
        correlation_id: cfg.correlation_id.clone(),
        session_id: cfg.session_id.clone(),
    }
}

fn cmd_proxy(args: &[String]) -> i32 {
    let opts = match parse_opts(args) {
        Ok(o) => o,
        Err(e) => return err(&e),
    };
    let cfg = config::load();
    let (policy, events_file) = match resolve_options(opts, &cfg) {
        Ok(options) => options,
        Err(e) => return err(&e),
    };
    let emitter = match build_emitter(events_file, &cfg) {
        Ok(e) => e,
        Err(e) => return err(&e),
    };
    let corr = cfg.correlation_id.clone();
    let sess = cfg.session_id.clone();
    match proxy::Proxy::start(emitter, policy, corr, sess) {
        Ok(p) => {
            // The port on stdout is the contract with a supervising process.
            println!("{}", p.port);
            use std::io::Write;
            std::io::stdout().flush().ok();
            // Run until killed.
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        Err(e) => err(&format!("cannot bind proxy: {}", e)),
    }
}

fn cmd_wrap(args: &[String]) -> i32 {
    // Split at "--": everything before is our options, everything after is the
    // command to wrap.
    let sep = args.iter().position(|a| a == "--");
    let (opt_args, cmd) = match sep {
        Some(i) => (&args[..i], &args[i + 1..]),
        None => return err("wrap needs `-- <command...>`"),
    };
    if cmd.is_empty() {
        return err("wrap needs a command after `--`");
    }
    let opts = match parse_opts(opt_args) {
        Ok(o) => o,
        Err(e) => return err(&e),
    };
    let cfg = config::load();
    let (policy, events_file) = match resolve_options(opts, &cfg) {
        Ok(options) => options,
        Err(e) => return err(&e),
    };
    let emitter = match build_emitter(events_file, &cfg) {
        Ok(e) => e,
        Err(e) => return err(&e),
    };
    let corr = cfg.correlation_id.clone();
    let sess = cfg.session_id.clone();
    let mut proxy = match proxy::Proxy::start(Arc::clone(&emitter), policy, corr, sess) {
        Ok(p) => p,
        Err(e) => return err(&format!("cannot bind proxy: {}", e)),
    };
    let kind = sandbox::detect();
    let extra_env: Vec<(String, String)> = vec![
        (
            "AGENTMETRY_CORRELATION_ID".to_string(),
            cfg.correlation_id.clone(),
        ),
        ("AGENTMETRY_SESSION_ID".to_string(), cfg.session_id.clone()),
    ];
    let code = sandbox::run_wrapped(kind, &cmd[0], &cmd[1..], proxy.port, &extra_env);
    proxy.stop();
    emitter.drain(std::time::Duration::from_millis(1500));
    match code {
        Ok(c) => c,
        Err(e) => err(&format!("cannot start the wrapped command: {}", e)),
    }
}

fn err(msg: &str) -> i32 {
    eprintln!("agentmetry-guard: {}", msg);
    1
}
