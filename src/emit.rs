//! Event sinks. Every egress observation is appended to a local JSONL file
//! when `--events-file` is set, and POSTed to Agentmetry's
//! `/api/v1/audit/ingest` when a URL and a token are available. The file write
//! is synchronous and is the authority; the POST runs on a background worker
//! thread with a bounded queue, so a slow or absent recorder never delays a
//! tunnel. Undelivered POSTs are retried a bounded number of times and then
//! dropped (the file keeps the record).

use crate::config::Config;
use crate::json::EgressEvent;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// Posts beyond this many pending lines are dropped from the queue (never
/// from the file) so a stalled ingest cannot grow memory without bound.
const MAX_QUEUE: usize = 128;
/// Total delivery attempts per line before it stays file-only.
const MAX_ATTEMPTS: u8 = 3;
/// Pause between attempts, so a briefly restarting recorder is covered.
const RETRY_PAUSE: Duration = Duration::from_millis(250);
/// Cap on resolved ingest addresses tried per POST.
const MAX_INGEST_ADDRS: usize = 4;

pub struct Emitter {
    file: Mutex<Option<std::fs::File>>,
    queue: Arc<Queue>,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
    dropped: AtomicUsize,
}

struct Queue {
    cfg: Config,
    items: Mutex<VecDeque<Item>>,
    ready: Condvar,
    closed: AtomicBool,
    pending: AtomicUsize,
    warned: AtomicBool,
}

struct Item {
    line: String,
    attempts: u8,
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
            file: Mutex::new(file),
            queue: Arc::new(Queue {
                cfg,
                items: Mutex::new(VecDeque::new()),
                ready: Condvar::new(),
                closed: AtomicBool::new(false),
                pending: AtomicUsize::new(0),
                warned: AtomicBool::new(false),
            }),
            worker: Mutex::new(None),
            dropped: AtomicUsize::new(0),
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
        if self.queue.cfg.ingest_url.is_empty() || self.queue.cfg.api_key.is_empty() {
            return;
        }
        self.queue.pending.fetch_add(1, Ordering::Relaxed);
        let mut items = match self.queue.items.lock() {
            Ok(items) => items,
            Err(_) => {
                // A poisoned lock means the worker died mid-update; telemetry
                // must never take the tunnel down with it.
                self.queue.pending.fetch_sub(1, Ordering::Relaxed);
                return;
            }
        };
        if items.len() >= MAX_QUEUE {
            self.queue.pending.fetch_sub(1, Ordering::Relaxed);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            drop(items);
            if !self.queue.warned.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "agentmetry-guard: ingest queue full ({MAX_QUEUE} pending); events stay in the file"
                );
            }
            return;
        }
        items.push_back(Item { line, attempts: 0 });
        drop(items);
        self.queue.ready.notify_one();
        self.ensure_worker();
    }

    /// Wait until queued and in-flight POSTs finish, bounded. Called before
    /// `wrap` exits so a fast child does not kill the process mid-emit.
    pub fn drain(&self, max: Duration) {
        let start = std::time::Instant::now();
        while self.queue.pending.load(Ordering::Relaxed) > 0 && start.elapsed() < max {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Posts dropped by the overflow policy. The file always keeps the line.
    #[cfg(test)]
    pub fn dropped(&self) -> usize {
        self.dropped.load(Ordering::Relaxed)
    }

    fn ensure_worker(&self) {
        let mut slot = match self.worker.lock() {
            Ok(slot) => slot,
            Err(_) => return,
        };
        if slot.is_none() {
            let queue = Arc::clone(&self.queue);
            *slot = std::thread::Builder::new()
                .name("agentmetry-guard-emit".to_string())
                .spawn(move || worker_loop(queue))
                .ok();
        }
    }
}

impl Drop for Emitter {
    fn drop(&mut self) {
        self.queue.closed.store(true, Ordering::Relaxed);
        self.queue.ready.notify_all();
    }
}

fn worker_loop(queue: Arc<Queue>) {
    loop {
        let item = {
            let mut items = match queue.items.lock() {
                Ok(items) => items,
                Err(_) => return,
            };
            loop {
                if let Some(item) = items.pop_front() {
                    break item;
                }
                if queue.closed.load(Ordering::Relaxed) {
                    return;
                }
                items = match queue.ready.wait(items) {
                    Ok(items) => items,
                    Err(_) => return,
                };
            }
        };
        if post(&queue.cfg, &item.line).is_ok() {
            queue.pending.fetch_sub(1, Ordering::Relaxed);
            continue;
        }
        if item.attempts + 1 < MAX_ATTEMPTS {
            std::thread::sleep(RETRY_PAUSE);
            match queue.items.lock() {
                Ok(mut items) => {
                    items.push_front(Item {
                        line: item.line,
                        attempts: item.attempts + 1,
                    });
                }
                Err(_) => {
                    queue.pending.fetch_sub(1, Ordering::Relaxed);
                }
            }
            continue;
        }
        queue.pending.fetch_sub(1, Ordering::Relaxed);
        if !queue.warned.swap(true, Ordering::Relaxed) {
            eprintln!(
                "agentmetry-guard: ingest POST failed after {MAX_ATTEMPTS} attempts; the events file keeps the record"
            );
        }
    }
}

/// Minimal HTTP/1.1 POST. `cfg.ingest_url` is `http://host[:port][/prefix]`;
/// only http is supported, which is all the local recorder listens on.
fn post(cfg: &Config, body: &str) -> std::io::Result<()> {
    let url = cfg.ingest_url.trim_end_matches('/');
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
    let mut stream = connect_ingest(authority)?;
    stream.set_read_timeout(Some(Duration::from_millis(1500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(1500)))?;
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nX-API-Key: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path,
        authority,
        cfg.api_key,
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

/// Connect to the ingest authority. An IP literal keeps the direct path; a
/// hostname (e.g. `http://localhost:8000`) resolves, bounded, so the guard no
/// longer needs an IP-only ingest URL.
fn connect_ingest(authority: &str) -> std::io::Result<TcpStream> {
    if let Ok(addr) = authority.parse::<SocketAddr>() {
        return TcpStream::connect_timeout(&addr, Duration::from_millis(500));
    }
    let (host, port) = split_authority(authority).map_err(|reason| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, reason)
    })?;
    let mut last_err =
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "ingest host did not resolve");
    let mut tried = 0;
    for addr in (host.as_str(), port).to_socket_addrs()? {
        tried += 1;
        match TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_err = error,
        }
        if tried >= MAX_INGEST_ADDRS {
            break;
        }
    }
    Err(last_err)
}

/// Split `host`, `host:port`, `[v6]:port` into host and port, defaulting to
/// port 80. A bare IPv6 literal without brackets or port cannot be split
/// unambiguously and is rejected, same as the IP-only path before it.
pub(crate) fn split_authority(authority: &str) -> Result<(String, u16), String> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| "unterminated IPv6 literal".to_string())?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p
                .parse()
                .map_err(|_| "invalid port after IPv6 literal".to_string())?,
            None if tail.is_empty() => 80,
            None => return Err("junk after IPv6 literal".to_string()),
        };
        return Ok((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port
                .parse()
                .map_err(|_| "invalid port in ingest authority".to_string())?;
            Ok((host.to_string(), port))
        }
        None => Ok((authority.to_string(), 80)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;

    fn test_config(ingest_url: String) -> Config {
        Config {
            data_dir: std::path::PathBuf::from("."),
            ingest_url,
            api_key: "test-key".to_string(),
            correlation_id: "corr".to_string(),
            session_id: "sess".to_string(),
        }
    }

    fn one_event() -> EgressEvent<'static> {
        EgressEvent {
            correlation_id: "corr-1",
            session_id: "sess-1",
            timestamp_utc: "2026-11-28T10:00:00Z",
            outcome: "success",
            scheme: "https",
            method: "CONNECT",
            host: "example.com",
            port: 443,
            policy: None,
        }
    }

    fn temp_events_file(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "guard-emit-{}-{}.jsonl",
            tag,
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// A one-shot ingest server: accepts one connection, reads the full POST,
    /// answers 200, and records the body for the test to inspect.
    fn ingest_200() -> (u16, Arc<Mutex<Option<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let body = Arc::new(Mutex::new(None));
        let seen = Arc::clone(&body);
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut head = String::new();
                let mut content_length = 0usize;
                loop {
                    head.clear();
                    if reader.read_line(&mut head).unwrap_or(0) == 0 {
                        break;
                    }
                    let line = head.trim_end();
                    if line.is_empty() {
                        break;
                    }
                    if let Some(v) = line
                        .to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(str::trim)
                    {
                        content_length = v.parse().unwrap_or(0);
                    }
                }
                let mut body_bytes = vec![0u8; content_length];
                if content_length > 0 {
                    reader.read_exact(&mut body_bytes).unwrap();
                }
                *seen.lock().unwrap() = Some(String::from_utf8_lossy(&body_bytes).to_string());
                let mut stream = stream;
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            }
        });
        (port, body)
    }

    #[test]
    fn splits_authority_shapes() {
        assert_eq!(
            split_authority("localhost:8000").unwrap(),
            ("localhost".to_string(), 8000)
        );
        assert_eq!(
            split_authority("localhost").unwrap(),
            ("localhost".to_string(), 80)
        );
        assert_eq!(
            split_authority("[::1]:8000").unwrap(),
            ("::1".to_string(), 8000)
        );
        assert_eq!(
            split_authority("[::1]").unwrap(),
            ("::1".to_string(), 80)
        );
        assert!(split_authority("host:notaport").is_err());
        assert!(split_authority("[::1").is_err());
        assert!(split_authority("[::1]junk").is_err());
    }

    #[test]
    fn hostname_ingest_url_is_delivered() {
        // Regression: `http://localhost:PORT` used to fail the SocketAddr
        // parse and silently fall back to file-only.
        let (port, body) = ingest_200();
        let path = temp_events_file("hostname");
        let emitter =
            Emitter::new(test_config(format!("http://localhost:{port}")), Some(path.clone()))
                .unwrap();
        emitter.emit(&one_event());
        emitter.drain(Duration::from_secs(5));
        let delivered = body
            .lock()
            .unwrap()
            .clone()
            .expect("ingest server saw no POST");
        assert!(delivered.contains("\"event_type\":\"network_egress\""));
        assert!(delivered.contains("\"host\":\"example.com\""));
    }

    #[test]
    fn emit_returns_fast_while_ingest_stalls() {
        // A server that accepts and never answers: a synchronous POST would
        // sit in the 1.5 s read timeout per event. emit() must stay fast.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hold = Arc::new(AtomicBool::new(true));
        let hold2 = Arc::clone(&hold);
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                while hold2.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(50));
                }
                drop(stream);
            }
        });
        let path = temp_events_file("stall");
        let emitter =
            Emitter::new(test_config(format!("http://127.0.0.1:{port}")), Some(path.clone()))
                .unwrap();
        let start = std::time::Instant::now();
        for _ in 0..5 {
            emitter.emit(&one_event());
        }
        let elapsed = start.elapsed();
        hold.store(false, Ordering::Relaxed);
        assert!(
            elapsed < Duration::from_millis(800),
            "emit blocked for {elapsed:?}; the tunnel would wait on telemetry"
        );
        emitter.drain(Duration::from_secs(10));
        let file = std::fs::read_to_string(&path).unwrap();
        assert_eq!(file.lines().count(), 5);
    }

    #[test]
    fn failed_posts_retry_bounded_then_stay_in_the_file() {
        // Port with no listener: every POST fails fast.
        let gone = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = gone.local_addr().unwrap().port();
        drop(gone);
        let path = temp_events_file("retry");
        let emitter =
            Emitter::new(test_config(format!("http://127.0.0.1:{port}")), Some(path.clone()))
                .unwrap();
        emitter.emit(&one_event());
        // 3 attempts with 250 ms pauses: bounded by a few seconds.
        emitter.drain(Duration::from_secs(8));
        assert_eq!(
            emitter.queue.pending.load(Ordering::Relaxed),
            0,
            "retries must be bounded"
        );
        let file = std::fs::read_to_string(&path).unwrap();
        assert_eq!(file.lines().count(), 1, "the file is the authority");
    }

    #[test]
    fn queue_overflow_drops_posts_but_never_file_records() {
        // The stalled server pins the worker for ~1.5 s per POST, so a burst
        // larger than MAX_QUEUE must overflow instead of growing the queue.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hold = Arc::new(AtomicBool::new(true));
        let hold2 = Arc::clone(&hold);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        while hold2.load(Ordering::Relaxed) {
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        drop(stream);
                    }
                    Err(_) => break,
                }
            }
        });
        let path = temp_events_file("overflow");
        let emitter =
            Emitter::new(test_config(format!("http://127.0.0.1:{port}")), Some(path.clone()))
                .unwrap();
        let burst = MAX_QUEUE + 16;
        for _ in 0..burst {
            emitter.emit(&one_event());
        }
        let file = std::fs::read_to_string(&path).unwrap();
        assert_eq!(file.lines().count(), burst, "every line is in the file");
        assert!(
            emitter.dropped() >= 1,
            "a burst larger than the queue must drop POSTs, not block or grow"
        );
        hold.store(false, Ordering::Relaxed);
    }
}
