//! Event sinks. Every egress observation is appended to a local JSONL file
//! when `--events-file` is set, and POSTed to Agentmetry's `/audit/ingest`
//! when a URL and a token are available. Posting failure never blocks the
//! wrapped command: the file keeps the record.

use crate::config::Config;
use crate::json::EgressEvent;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;

pub struct Emitter {
    cfg: Config,
    file: Mutex<Option<std::fs::File>>,
    pending: std::sync::atomic::AtomicUsize,
}

impl Emitter {
    pub fn new(cfg: Config, events_file: Option<std::path::PathBuf>) -> std::io::Result<Emitter> {
        let file = match &events_file {
            Some(p) => {
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                Some(
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(p)?,
                )
            }
            None => None,
        };
        let _ = events_file;
        Ok(Emitter {
            cfg,
            file: Mutex::new(file),
            pending: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    pub fn emit(&self, ev: &EgressEvent) {
        let line = ev.to_json();
        if let Ok(mut guard) = self.file.lock() {
            if let Some(f) = guard.as_mut() {
                let _ = writeln!(f, "{}", line);
                let _ = f.flush();
            }
        }
        if !self.cfg.ingest_url.is_empty() && !self.cfg.api_key.is_empty() {
            self.pending.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let _ = self.post(&line);
            self.pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Wait until in-flight POSTs finish, bounded. Called before `wrap` exits
    /// so a fast child does not kill the process mid-emit.
    pub fn drain(&self, max: Duration) {
        let start = std::time::Instant::now();
        while self.pending.load(std::sync::atomic::Ordering::Relaxed) > 0 && start.elapsed() < max {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Minimal HTTP/1.1 POST. `cfg.ingest_url` is `http://host:port`; only http
    /// is supported, which is all the local recorder listens on.
    fn post(&self, body: &str) -> std::io::Result<()> {
        let url = self.cfg.ingest_url.trim_end_matches('/');
        let rest = url.strip_prefix("http://").unwrap_or(url);
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        // The recorder mounts the audit router under /api/v1; the hook builds
        // `{base}/api/v1/audit/ingest` from AGENTMETRY_URL, so a base URL here
        // means the same thing.
        let path = if path.is_empty() {
            "/api/v1/audit/ingest".to_string()
        } else {
            format!("{}/audit/ingest", path.trim_end_matches('/'))
        };
        let mut stream = TcpStream::connect_timeout(
            &authority
                .parse()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?,
            Duration::from_millis(500),
        )?;
        stream.set_read_timeout(Some(Duration::from_millis(1500)))?;
        stream.set_write_timeout(Some(Duration::from_millis(1500)))?;
        let req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nX-API-Key: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            path,
            authority,
            self.cfg.api_key,
            body.len(),
            body
        );
        stream.write_all(req.as_bytes())?;
        let mut resp = String::new();
        let _ = stream.read_to_string(&mut resp);
        // 2xx means accepted; anything else is treated as "not delivered" and
        // the caller still has the JSONL file.
        if resp.starts_with("HTTP/1.1 2") || resp.starts_with("HTTP/1.0 2") {
            Ok(())
        } else {
            Err(std::io::Error::other(format!(
                "ingest returned: {}",
                resp.lines().next().unwrap_or("")
            )))
        }
    }
}
