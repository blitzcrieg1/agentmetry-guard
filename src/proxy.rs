//! The local egress proxy. One thread per accepted connection; each
//! connection is classified from its first bytes:
//!
//! - `CONNECT host:port` (HTTPS tunneling): the destination host is the whole
//!   signal. Logged as scheme=https; optionally refused by the denylist.
//! - anything else is treated as plain HTTP: the request line and Host header
//!   give the method and destination. Logged as scheme=http; optionally refused.
//!
//! This is a visibility layer, not a containment boundary: a cooperative
//! client honours the proxy env vars, a non-cooperative one can bypass it.
//! The sandbox wrapper (`wrap`) is what hides credential files; the proxy is
//! what sees where the traffic goes.

use crate::emit::Emitter;
use crate::json::EgressEvent;
use crate::policy::Policy;
use crate::timeutil::now_utc_iso;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

pub struct Proxy {
    pub port: u16,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Proxy {
    /// Bind an ephemeral loopback port and start accepting.
    pub fn start(
        emitter: Arc<Emitter>,
        policy: Policy,
        correlation_id: String,
        session_id: String,
    ) -> std::io::Result<Proxy> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown2 = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            while !shutdown2.load(std::sync::atomic::Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let emitter = Arc::clone(&emitter);
                        let policy = policy.clone();
                        let corr = correlation_id.clone();
                        let sess = session_id.clone();
                        std::thread::spawn(move || {
                            let _ = handle_connection(stream, emitter, policy, corr, sess);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(50)),
                }
            }
        });
        Ok(Proxy {
            port,
            shutdown,
            handle: Some(handle),
        })
    }

    pub fn stop(&mut self) {
        self.shutdown
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Read the request head (up to \r\n\r\n), capped, with a short timeout so an
/// idle or stalling client cannot pin a thread forever.
fn read_head(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    // Winsock accept inherits the listener's nonblocking mode. Connection
    // workers wait for request data under the read timeout below.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= 65_536 {
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break
            }
            Err(e) => return Err(e),
        }
    }
    Ok(buf)
}

fn handle_connection(
    mut client: TcpStream,
    emitter: Arc<Emitter>,
    policy: Policy,
    corr: String,
    sess: String,
) -> std::io::Result<()> {
    let head = match read_head(&mut client) {
        Ok(h) => h,
        Err(_) => return Ok(()), // client went away before sending anything
    };
    let Some(head_end) = head
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
    else {
        return Ok(());
    };
    let head_text = String::from_utf8_lossy(&head[..head_end]);
    let mut parts = head_text.lines().next().unwrap_or("").split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return Ok(());
    };
    let connect = method == "CONNECT";
    let (host, port) = if connect {
        split_authority(target, 443)
    } else {
        parse_http_destination(target, &head_text)
    };
    if host.is_empty()
        || host
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '?' | '#'))
    {
        return Ok(());
    }
    let timestamp = now_utc_iso();
    let mut evidence = EgressEvent {
        correlation_id: &corr,
        session_id: &sess,
        timestamp_utc: &timestamp,
        outcome: "error",
        scheme: if connect { "https" } else { "http" },
        method,
        host: &host,
        port,
        policy: policy.verdict(&host),
    };
    if evidence.policy.is_some() {
        evidence.outcome = "denied";
        // Reply first, emit second: the ingest POST is bounded but can still
        // take up to ~2s against a dead endpoint, and the client must not
        // wait on our telemetry.
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
        emitter.emit(&evidence);
        return Ok(());
    }

    // The CONNECT header belongs to the proxy. Only data after the header
    // goes to the origin. A plain HTTP request is forwarded as received.
    let initial_bytes = if connect { &head[head_end..] } else { &head };
    // Bound the upstream dial: a host that blackholes SYNs must not wedge the
    // client connection (seen as an 8s+ hang on macOS runners for a refused
    // loopback port).
    let addr = (host.as_str(), port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no address"))?;
    let upstream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).and_then(|mut stream| {
        stream.write_all(initial_bytes)?;
        Ok(stream)
    });
    let upstream = match upstream {
        Ok(upstream) => upstream,
        Err(error) => {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
            emitter.emit(&evidence);
            return Err(error);
        }
    };
    evidence.outcome = "success";
    if connect {
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    }
    emitter.emit(&evidence);
    tunnel(client, upstream)
}

fn split_authority(authority: &str, default_port: u16) -> (String, u16) {
    // Strip userinfo if present.
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(stripped) = authority.strip_prefix('[') {
        // IPv6 literal [::1]:443
        if let Some(end) = stripped.find(']') {
            let host = &stripped[..end];
            let port = stripped[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(default_port);
            return (host.to_string(), port);
        }
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
            (h.to_string(), p.parse().unwrap_or(default_port))
        }
        _ => (authority.to_string(), default_port),
    }
}

fn parse_http_destination(target: &str, head_text: &str) -> (String, u16) {
    if let Some(rest) = target.strip_prefix("http://") {
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        split_authority(&rest[..end], 80)
    } else {
        // origin-form: Host header carries the authority
        let host_header = head_text
            .lines()
            .skip(1)
            .find_map(|l| {
                l.split_once(':')
                    .filter(|(k, _)| k.trim().eq_ignore_ascii_case("host"))
                    .map(|(_, v)| v.trim())
            })
            .unwrap_or("");
        split_authority(host_header, 80)
    }
}

/// Relay bytes between an established upstream and its client.
fn tunnel(client: TcpStream, mut upstream: TcpStream) -> std::io::Result<()> {
    client.set_read_timeout(None)?;
    let mut client_read = client.try_clone()?;
    let mut upstream_write = upstream.try_clone()?;
    let mut client_write = client;
    let t = std::thread::spawn(move || {
        let mut buf = [0u8; 16_384];
        loop {
            match client_read.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if upstream_write.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = upstream_write.shutdown(std::net::Shutdown::Write);
    });
    let mut buf = [0u8; 16_384];
    loop {
        match upstream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if client_write.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = client_write.shutdown(std::net::Shutdown::Write);
    let _ = t.join();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::net::Shutdown;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct EventFile(PathBuf);

    impl Drop for EventFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn serve_one(
        policy: Policy,
    ) -> (
        TcpStream,
        std::thread::JoinHandle<std::io::Result<()>>,
        EventFile,
    ) {
        static NEXT_FILE: AtomicUsize = AtomicUsize::new(0);
        let events = EventFile(std::env::temp_dir().join(format!(
            "agentmetry-guard-proxy-test-{}-{}.jsonl",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        )));
        let cfg = Config {
            data_dir: std::env::temp_dir(),
            ingest_url: String::new(),
            api_key: String::new(),
            correlation_id: String::new(),
            session_id: String::new(),
        };
        let emitter = Arc::new(Emitter::new(cfg, Some(events.0.clone())).unwrap());
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (accepted, _) = listener.accept().unwrap();
        let worker = std::thread::spawn(move || {
            handle_connection(
                accepted,
                emitter,
                policy,
                "test-corr".into(),
                "test-session".into(),
            )
        });
        (client, worker, events)
    }

    #[test]
    fn authority_with_port() {
        assert_eq!(
            split_authority("example.com:443", 443),
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            split_authority("example.com", 443),
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            split_authority("example.com:8080", 443),
            ("example.com".to_string(), 8080)
        );
    }

    #[test]
    fn authority_with_userinfo_and_ipv6() {
        assert_eq!(
            split_authority("user:pw@example.com:443", 443),
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            split_authority("[::1]:8443", 443),
            ("::1".to_string(), 8443)
        );
        assert_eq!(
            split_authority("[2001:db8::1]", 443),
            ("2001:db8::1".to_string(), 443)
        );
    }

    #[test]
    fn http_target_absolute_uri() {
        let (host, port) = parse_http_destination("http://example.com:8080/a/b?x=1", "");
        assert_eq!((host.as_str(), port), ("example.com", 8080));
        let (host, port) = parse_http_destination("http://example.com?x=1", "");
        assert_eq!((host.as_str(), port), ("example.com", 80));
    }

    #[test]
    fn http_target_origin_form_uses_host_header() {
        let head = "GET /x HTTP/1.1\r\nHost: api.example.com:9000\r\n\r\n";
        let (host, port) = parse_http_destination("/x", head);
        assert_eq!((host.as_str(), port), ("api.example.com", 9000));
    }

    #[test]
    fn http_target_bare_host_header_defaults_80() {
        let head = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (host, port) = parse_http_destination("/", head);
        assert_eq!((host.as_str(), port), ("example.com", 80));
    }

    #[test]
    fn accepted_socket_waits_for_delayed_request_bytes() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut accepted, _) = listener.accept().unwrap();
        // Match the mode inherited from a nonblocking listener on Windows.
        accepted.set_nonblocking(true).unwrap();
        let (started, start_signal) = std::sync::mpsc::channel();
        let (finished, result) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            started.send(()).unwrap();
            finished.send(read_head(&mut accepted)).unwrap();
        });
        start_signal.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(
            result.recv_timeout(Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        let request = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        client.write_all(request).unwrap();
        assert_eq!(
            result
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap(),
            request
        );
        reader.join().unwrap();
    }

    #[test]
    fn connect_acknowledges_and_relays_only_tunnel_bytes() {
        let origin = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = origin.local_addr().unwrap();
        let upstream = std::thread::spawn(move || {
            let (mut origin_stream, _) = origin.accept().unwrap();
            origin_stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut data = [0; 10];
            origin_stream.read_exact(&mut data).unwrap();
            assert_eq!(&data, b"earlylater");
            origin_stream.write_all(b"origin-reply").unwrap();
        });
        let (mut client, proxy, events) = serve_one(Policy::default());
        write!(
            client,
            "CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\nearly"
        )
        .unwrap();
        let expected = b"HTTP/1.1 200 Connection Established\r\n\r\n";
        let mut response = vec![0; expected.len()];
        client.read_exact(&mut response).unwrap();
        assert_eq!(response.as_slice(), expected);
        client.write_all(b"later").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"origin-reply");
        upstream.join().unwrap();
        proxy.join().unwrap().unwrap();
        let event = std::fs::read_to_string(&events.0).unwrap();
        assert!(event.contains("\"outcome\":\"success\""));
        assert!(event.contains("\"connection_established\":true"));
        assert!(!event.contains("early"));
    }

    #[test]
    fn failed_upstream_never_records_success() {
        let origin = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = origin.local_addr().unwrap();
        drop(origin);
        let (mut client, proxy, events) = serve_one(Policy::default());
        write!(
            client,
            "CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n"
        )
        .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 502 "));
        assert!(proxy.join().unwrap().is_err());
        let event = std::fs::read_to_string(&events.0).unwrap();
        assert!(event.contains("\"outcome\":\"error\""));
        assert!(event.contains("\"connection_established\":false"));
        assert!(!event.contains("\"outcome\":\"success\""));
    }

    #[test]
    fn http_forwards_original_target_without_logging_it() {
        let origin = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = origin.local_addr().unwrap();
        let request = format!(
            "GET http://{address}/private-path?value=synthetic-test-value HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
        );
        let expected = request.clone();
        let upstream = std::thread::spawn(move || {
            let (mut origin_stream, _) = origin.accept().unwrap();
            origin_stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut actual = vec![0; expected.len()];
            origin_stream.read_exact(&mut actual).unwrap();
            assert_eq!(actual, expected.as_bytes());
            origin_stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        let (mut client, proxy, events) = serve_one(Policy::default());
        client.write_all(request.as_bytes()).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 "));
        upstream.join().unwrap();
        proxy.join().unwrap().unwrap();
        let event = std::fs::read_to_string(&events.0).unwrap();
        assert!(event.contains(&format!("\"command\":\"GET {address}\"")));
        assert!(event.contains("\"connection_established\":true"));
        assert!(!event.contains("\"path\":"));
        assert!(!event.contains("private-path"));
        assert!(!event.contains("synthetic-test-value"));
    }
}
