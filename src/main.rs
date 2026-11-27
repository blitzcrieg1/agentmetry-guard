//! agentmetry-guard: user-space egress visibility sidecar for Agentmetry.
//!
//! Two subcommands:
//!
//!   agentmetry-guard proxy [--events-file PATH] [--deny host,...]
//!       Run the loopback proxy; print the chosen port on stdout. Used when
//!       the caller wants to manage the proxy process itself.
//!
//!   agentmetry-guard wrap [--events-file PATH] [--deny host,...] -- <command...>
//!       Start the proxy on an ephemeral port, inject HTTP(S)_PROXY into the
//!       child's environment, run the command inside the OS-native user-space
//!       sandbox (Seatbelt on macOS, Bubblewrap on Linux, env-only elsewhere),
//!       wait for it, and exit with its exit code. Every intercepted request
//!       is emitted as a `network_egress` event correlated by
//!       AGENTMETRY_CORRELATION_ID.
//!
//! Events go to `--events-file` (JSONL) and, when a token is available, are
//! POSTed to Agentmetry's local `/audit/ingest` as source_app=agentmetry,
//! adapter=guard.

mod config;
mod emit;
mod json;
mod proxy;
mod sandbox;
mod timeutil;

use std::sync::Arc;

struct Options {
    events_file: Option<std::path::PathBuf>,
    denylist: Vec<String>,
}

fn parse_opts(args: &[String]) -> Result<Options, String> {
    let mut opts = Options { events_file: None, denylist: vec![] };
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
                let list = args.get(i).ok_or("--deny needs a comma-separated list")?;
                opts.denylist = list.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            }
            other => return Err(format!("unknown option: {}", other)),
        }
        i += 1;
    }
    Ok(opts)
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
        "agentmetry-guard {}\n\nUSAGE:\n  agentmetry-guard proxy [--events-file PATH] [--deny hosts]\n  agentmetry-guard wrap  [--events-file PATH] [--deny hosts] -- <command...>\n",
        env!("CARGO_PKG_VERSION")
    );
}

fn build_emitter(opts: &Options, cfg: &config::Config) -> Result<Arc<emit::Emitter>, String> {
    let path = opts
        .events_file
        .clone()
        .unwrap_or_else(|| cfg.data_dir.join("guard-events.jsonl"));
    emit::Emitter::new(cfg_owned(cfg), Some(path))
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
    let emitter = match build_emitter(&opts, &cfg) {
        Ok(e) => e,
        Err(e) => return err(&e),
    };
    let corr = cfg.correlation_id.clone();
    let sess = cfg.session_id.clone();
    match proxy::Proxy::start(emitter, opts.denylist, corr, sess) {
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
    let emitter = match build_emitter(&opts, &cfg) {
        Ok(e) => e,
        Err(e) => return err(&e),
    };
    let corr = cfg.correlation_id.clone();
    let sess = cfg.session_id.clone();
    let mut proxy = match proxy::Proxy::start(Arc::clone(&emitter), opts.denylist, corr, sess) {
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
