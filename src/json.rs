//! Minimal JSON emission. We control every field, so a correct string escaper
//! is all that is needed. No serde: zero dependencies keeps startup under a
//! millisecond and the supply-chain surface empty.

/// Escape a string for inclusion in a JSON document (with surrounding quotes).
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// One egress observation, serialized to the Agentmetry external ingest shape
/// (`ExternalIngestBody` on the Python side). Only declared fields are sent:
/// pydantic drops everything else silently.
pub struct EgressEvent<'a> {
    pub correlation_id: &'a str,
    pub session_id: &'a str,
    pub timestamp_utc: &'a str,
    pub outcome: &'a str, // "success" | "denied"
    pub scheme: &'a str,  // "http" | "https"
    pub method: &'a str,  // "CONNECT" or the HTTP method
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str, // request target for plain HTTP; "" for CONNECT
}

impl<'a> EgressEvent<'a> {
    pub fn to_json(&self) -> String {
        // The destination rides in `tool.command` (scrubbed and stored on
        // ingest even in hashed-only mode) and in `tool.arguments` for
        // structured consumers. action.type is `network_egress`, which the
        // sequence rules do not match, so these events are visible in the
        // trail and join the session by correlation_id without feeding
        // tool-call rules.
        let command = if self.method == "CONNECT" {
            format!("CONNECT {}:{}", self.host, self.port)
        } else if self.path.is_empty() {
            format!("{} {}", self.method, self.host)
        } else {
            format!("{} {}{}", self.method, self.host, self.path)
        };
        let mut s = String::with_capacity(256);
        s.push_str("{\"source_app\":\"agentmetry\",\"adapter\":\"guard\",\"event_type\":\"network_egress\",");
        s.push_str(&format!("\"correlation_id\":{},", quote(self.correlation_id)));
        s.push_str(&format!("\"session_id\":{},", quote(self.session_id)));
        s.push_str(&format!("\"timestamp_utc\":{},", quote(self.timestamp_utc)));
        s.push_str(&format!("\"outcome\":{},", quote(self.outcome)));
        s.push_str("\"tool\":{\"qualified\":\"guard.egress\",\"server\":\"guard\",");
        s.push_str(&format!("\"command\":{},", quote(&command)));
        s.push_str(&format!(
            "\"arguments\":{{\"scheme\":{},\"method\":{},\"host\":{},\"port\":{},\"path\":{}}}}}",
            quote(self.scheme),
            quote(self.method),
            quote(self.host),
            self.port,
            quote(self.path)
        ));
        s.push('}');
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_quotes_backslash_and_control() {
        assert_eq!(quote("a\"b\\c\nd\u{1}"), "\"a\\\"b\\\\c\\nd\\u0001\"");
    }

    #[test]
    fn event_shape_has_declared_fields_only() {
        let ev = EgressEvent {
            correlation_id: "corr-1",
            session_id: "sess-1",
            timestamp_utc: "2026-11-27T10:00:00Z",
            outcome: "denied",
            scheme: "https",
            method: "CONNECT",
            host: "evil.example.com",
            port: 443,
            path: "",
        };
        let j = ev.to_json();
        assert!(j.contains("\"event_type\":\"network_egress\""));
        assert!(j.contains("\"adapter\":\"guard\""));
        assert!(j.contains("\"command\":\"CONNECT evil.example.com:443\""));
        assert!(j.contains("\"port\":443"));
        // Must parse as JSON: round-trip through a tiny check that braces balance.
        assert_eq!(j.matches('{').count(), j.matches('}').count());
    }
}
