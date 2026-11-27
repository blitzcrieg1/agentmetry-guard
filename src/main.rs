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

fn parse_list(value: &str) -> Vec<String> {
    value.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

fn parse_opts(args: &[String]) -> Result<Options, String> {
    let mut opts = Options { events_file: None, deny: None, allow: None };
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
                opts.deny = Some(parse_list(args.get(i).ok_or("--deny needs a comma-separated list")?));
            }
            "--allow" => {
                i += 1;
                opts.allow = Some(parse_list(args.get(i).ok_or("--allow needs a comma-separated list")?));
            }
            other => return Err(format!("unknown option: {}", other)),
        }
        i += 1;
    }
    Ok(opts)
}

/// Resolve the host policy: CLI flag wins, then env, then guard.json.
fn resolve_policy(opts: &Options, cfg: &config::Config) -> Policy {
    let file = std::fs::read_to_string(config::guard_config_path(&cfg.data_dir))
        .ok()
        .and_then(|text| fileconf::parse(&text).ok())
        .unwrap_or_default();
    let env_list = |name: &str| {
        let raw = std::env::var(name).unwrap_or_default();
        let trimmed = raw.trim();
        if trimmed.is_empty() { None } else { Some(parse_list(trimmed)) }
    };
    Policy {
        deny: opts.deny.clone().or_else(|| env_list("AGENTMETRY_GUARD_DENY")).unwrap_or(file.deny),
        allow: opts.allow.clone().or_else(|| env_list("AGENTMETRY_GUARD_ALLOW")).unwrap_or(file.allow),
    }
}

fn resolve_events_file(opts: &Options, cfg: &config::Config) -> std::path::PathBuf {
    if let Some(p) = &opts.events_file {
        return p.clone();
    }
    if let Some(p) = std::env::var_os("AGENTMETRY_GUARD_EVENTS_FILE") {
        if !p.is_empty() {
            return std::path::PathBuf::from(p);
        }
    }
    if let Ok(text) = std::fs::read_to_string(config::guard_config_path(&cfg.data_dir)) {
        if let Ok(fc) = fileconf::parse(&text) {
            if let Some(p) = fc.events_file {
                return p;
            }
        }
    }
    cfg.data_dir.join("guard-events.jsonl")
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
        Some(other) => {
            eprintln!("unknown subcommand: {}", other);
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

fn build_emitter(events_file: std::path::PathBuf, cfg: &config::Config) -> Result<Arc<emit::Emitter>, String> {
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
    let emitter = match build_emitter(resolve_events_file(&opts, &cfg), &cfg) {
        Ok(e) => e,
        Err(e) => return err(&e),
    };
    let corr = cfg.correlation_id.clone();
    let sess = cfg.session_id.clone();
    match proxy::Proxy::start(emitter, resolve_policy(&opts, &cfg), corr, sess) {
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
    let emitter = match build_emitter(resolve_events_file(&opts, &cfg), &cfg) {
        Ok(e) => e,
        Err(e) => return err(&e),
    };
    let corr = cfg.correlation_id.clone();
    let sess = cfg.session_id.clone();
    let mut proxy = match proxy::Proxy::start(Arc::clone(&emitter), resolve_policy(&opts, &cfg), corr, sess) {
        Ok(p) => p,
        Err(e) => return err(&format!("cannot bind proxy: {}", e)),
    };
    let kind = sandbox::detect();
    eprintln!("agentmetry-guard: sandbox mode: {}", sandbox::kind_name(kind));
    let extra_env: Vec<(String, String)> = vec![
        ("AGENTMETRY_CORRELATION_ID".to_string(), cfg.correlation_id.clone()),
        ("AGENTMETRY_SESSION_ID".to_string(), cfg.session_id.clone()),
    ];
    let code = sandbox::run_wrapped(kind, &cmd[0], &cmd[1..], proxy.port, &extra_env);
    proxy.stop();
    emitter.drain(std::time::Duration::from_millis(1500));
    match code {
        Ok(c) => c,
        Err(e) => err(&format!("cannot run {}: {}", cmd[0], e)),
    }
}

fn err(msg: &str) -> i32 {
    eprintln!("agentmetry-guard: {}", msg);
    1
}
