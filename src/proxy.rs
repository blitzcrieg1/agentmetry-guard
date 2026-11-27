//! The local egress proxy. One thread per accepted connection; each
//! connection is classified from its first bytes:
//!
//! - `CONNECT host:port` (HTTPS tunneling): the destination host is the whole
//!   signal. Logged as scheme=https; optionally refused by the denylist.
//! - anything else is treated as plain HTTP: the request line and Host header
//!   give method, host and path. Logged as scheme=http; optionally refused.
//!
//! This is a visibility layer, not a containment boundary: a cooperative
//! client honours the proxy env vars, a non-cooperative one can bypass it.
//! The sandbox wrapper (`wrap`) is what hides credential files; the proxy is
//! what sees where the traffic goes.

use crate::emit::Emitter;
use crate::json::EgressEvent;
use crate::timeutil::now_utc_iso;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

pub struct Proxy {
    pub port: u16,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Proxy {
    /// Bind an ephemeral loopback port and start accepting.
    pub fn start(emitter: Arc<Emitter>, denylist: Vec<String>, correlation_id: String, session_id: String) -> std::io::Result<Proxy> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown2 = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            listener
                .set_nonblocking(true)
                .ok();
            while !shutdown2.load(std::sync::atomic::Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let emitter = Arc::clone(&emitter);
                        let denylist = denylist.clone();
                        let corr = correlation_id.clone();
                        let sess = session_id.clone();
                        std::thread::spawn(move || {
                            let _ = handle_connection(stream, emitter, denylist, corr, sess);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(50)),
                }
            }
        });
        Ok(Proxy { port, shutdown, handle: Some(handle) })
    }

    pub fn stop(&mut self) {
        self.shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
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

fn denied(host: &str, denylist: &[String]) -> bool {
    // Strip one trailing dot on both sides: "evil.com." and "evil.com" are
    // the same DNS name, and a denylist that misses the dotted form is an
    // evasion, not a distinction.
    let host = host.to_ascii_lowercase().trim_end_matches('.').to_string();
    denylist.iter().any(|d| {
        let d = d.to_ascii_lowercase().trim_end_matches('.').to_string();
        host == d || host.ends_with(&format!(".{}", d))
    })
}

fn emit(emitter: &Emitter, ev: &EgressEvent) {
    emitter.emit(ev);
}

/// Read the request head (up to \r\n\r\n), capped, with a short timeout so an
/// idle or stalling client cannot pin a thread forever.
fn read_head(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
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
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => return Err(e),
        }
    }
    Ok(buf)
}

fn handle_connection(mut client: TcpStream, emitter: Arc<Emitter>, denylist: Vec<String>, corr: String, sess: String) -> std::io::Result<()> {
    let head = match read_head(&mut client) {
        Ok(h) => h,
        Err(_) => return Ok(()), // client went away before sending anything
    };
    let head_text = String::from_utf8_lossy(&head);
    let first_line = head_text.lines().next().unwrap_or("");

    if let Some(rest) = first_line.strip_prefix("CONNECT ") {
        let authority = rest.split_whitespace().next().unwrap_or("").trim();
        let (host, port) = split_authority(authority, 443);
        let ts = now_utc_iso();
        if denied(&host, &denylist) {
            emit(&emitter, &EgressEvent { correlation_id: &corr, session_id: &sess, timestamp_utc: &ts, outcome: "denied", scheme: "https", method: "CONNECT", host: &host, port, path: "" });
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
            return Ok(());
        }
        emit(&emitter, &EgressEvent { correlation_id: &corr, session_id: &sess, timestamp_utc: &ts, outcome: "success", scheme: "https", method: "CONNECT", host: &host, port, path: "" });
        return tunnel(client, &host, port, head);
    }

    // Plain HTTP: METHOD SP target SP HTTP/x.y
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    if method.is_empty() || target.is_empty() {
        return Ok(()); // not HTTP; nothing to report
    }
    let (host, port, path) = parse_http_target(&target, &head_text);
    if host.is_empty() {
        return Ok(());
    }
    let ts = now_utc_iso();
    if denied(&host, &denylist) {
        emit(&emitter, &EgressEvent { correlation_id: &corr, session_id: &sess, timestamp_utc: &ts, outcome: "denied", scheme: "http", method: &method, host: &host, port, path: &path });
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
        return Ok(());
    }
    emit(&emitter, &EgressEvent { correlation_id: &corr, session_id: &sess, timestamp_utc: &ts, outcome: "success", scheme: "http", method: &method, host: &host, port, path: &path });
    tunnel(client, &host, port, head)
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

fn parse_http_target(target: &str, head_text: &str) -> (String, u16, String) {
    if let Some(rest) = target.strip_prefix("http://") {
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = split_authority(authority, 80);
        (host, port, path.to_string())
    } else {
        // origin-form: Host header carries the authority
        let host_header = head_text
            .lines()
            .skip(1)
            .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("host")).map(|(_, v)| v.trim()))
            .unwrap_or("");
        let (host, port) = split_authority(host_header, 80);
        (host, port, target.to_string())
    }
}

/// Connect upstream, replay the bytes we already buffered, then pump both
/// directions until either side closes.
fn tunnel(client: TcpStream, host: &str, port: u16, buffered: Vec<u8>) -> std::io::Result<()> {
    let mut upstream = TcpStream::connect((host, port))?;
    upstream.set_read_timeout(None)?;
    client.set_read_timeout(None)?;
    upstream.write_all(&buffered)?;
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

    #[test]
    fn authority_with_port() {
        assert_eq!(split_authority("example.com:443", 443), ("example.com".to_string(), 443));
        assert_eq!(split_authority("example.com", 443), ("example.com".to_string(), 443));
        assert_eq!(split_authority("example.com:8080", 443), ("example.com".to_string(), 8080));
    }

    #[test]
    fn authority_with_userinfo_and_ipv6() {
        assert_eq!(split_authority("user:pw@example.com:443", 443), ("example.com".to_string(), 443));
        assert_eq!(split_authority("[::1]:8443", 443), ("::1".to_string(), 8443));
        assert_eq!(split_authority("[2001:db8::1]", 443), ("2001:db8::1".to_string(), 443));
    }

    #[test]
    fn trailing_dot_does_not_evade_the_denylist() {
        // "evil.com." is the same DNS name as "evil.com"; the denylist must
        // still match, or the dotted form is a trivial bypass.
        let (host, _) = split_authority("evil.com.:443", 443);
        assert_eq!(host, "evil.com.");
        assert!(denied(&host, &["evil.com".to_string()]));
        assert!(denied("evil.com", &["evil.com.".to_string()]));
    }

    #[test]
    fn deny_matches_exact_and_subdomain_only() {
        let list = vec!["evil.example.com".to_string(), "10.9.9.9".to_string()];
        assert!(denied("evil.example.com", &list));
        assert!(denied("api.evil.example.com", &list)); // suffix match
        assert!(denied("10.9.9.9", &list));
        assert!(!denied("notevil.example.com", &list)); // no partial-suffix match
        assert!(!denied("example.com", &list));
        assert!(!denied("10.9.9.90", &list));
        assert!(denied("EVIL.EXAMPLE.COM", &list)); // case-insensitive
    }

    #[test]
    fn http_target_absolute_uri() {
        let (host, port, path) = parse_http_target("http://example.com:8080/a/b?x=1", "");
        assert_eq!((host.as_str(), port, path.as_str()), ("example.com", 8080, "/a/b?x=1"));
    }

    #[test]
    fn http_target_origin_form_uses_host_header() {
        let head = "GET /x HTTP/1.1\r\nHost: api.example.com:9000\r\n\r\n";
        let (host, port, path) = parse_http_target("/x", head);
        assert_eq!((host.as_str(), port, path.as_str()), ("api.example.com", 9000, "/x"));
    }

    #[test]
    fn http_target_bare_host_header_defaults_80() {
        let head = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (host, port, _) = parse_http_target("/", head);
        assert_eq!((host.as_str(), port), ("example.com", 80));
    }
}
