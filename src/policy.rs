//! Host matching policy shared by the denylist and the allowlist.
//!
//! Matching is exact-host or domain-suffix, case-insensitive, with one
//! trailing dot normalized away on both sides (`evil.com.` is `evil.com`).
//! An empty allowlist means "everything allowed"; a non-empty allowlist
//! means only matching hosts pass.

#[derive(Debug, Default, Clone)]
pub struct Policy {
    pub deny: Vec<String>,
    pub allow: Vec<String>,
}

impl Policy {
    /// None = allowed through; Some("denylist") / Some("allowlist") = blocked,
    /// naming which list decided.
    pub fn verdict(&self, host: &str) -> Option<&'static str> {
        let host = normalize(host);
        if self.deny.iter().any(|d| matches(&host, d)) {
            return Some("denylist");
        }
        if !self.allow.is_empty() && !self.allow.iter().any(|d| matches(&host, d)) {
            return Some("allowlist");
        }
        None
    }
}

fn normalize(host: &str) -> String {
    host.to_ascii_lowercase().trim_end_matches('.').to_string()
}

fn matches(host: &str, pattern: &str) -> bool {
    let p = normalize(pattern);
    host == p || host.ends_with(&format!(".{}", p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(deny: &[&str], allow: &[&str]) -> Policy {
        Policy {
            deny: deny.iter().map(|s| s.to_string()).collect(),
            allow: allow.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn empty_policy_allows_everything() {
        assert_eq!(policy(&[], &[]).verdict("anything.example"), None);
    }

    #[test]
    fn denylist_blocks_exact_and_subdomain() {
        let p = policy(&["evil.example.com"], &[]);
        assert_eq!(p.verdict("evil.example.com"), Some("denylist"));
        assert_eq!(p.verdict("api.evil.example.com"), Some("denylist"));
        assert_eq!(p.verdict("notevil.example.com"), None);
        assert_eq!(p.verdict("example.com"), None);
    }

    #[test]
    fn trailing_dot_and_case_are_normalized() {
        let p = policy(&["evil.com"], &[]);
        assert_eq!(p.verdict("EVIL.COM."), Some("denylist"));
        let a = policy(&[], &["api.example.com"]);
        assert_eq!(a.verdict("API.Example.COM."), None);
        assert_eq!(a.verdict("other.example.com"), Some("allowlist"));
    }

    #[test]
    fn allowlist_blocks_everything_not_listed() {
        let p = policy(&[], &["api.example.com", "10.1.1.1"]);
        assert_eq!(p.verdict("api.example.com"), None);
        assert_eq!(p.verdict("v2.api.example.com"), None);
        assert_eq!(p.verdict("10.1.1.1"), None);
        assert_eq!(p.verdict("10.1.1.10"), Some("allowlist"));
        assert_eq!(p.verdict("evil.com"), Some("allowlist"));
    }

    #[test]
    fn denylist_wins_over_allowlist() {
        let p = policy(&["evil.com"], &["evil.com", "api.example.com"]);
        assert_eq!(p.verdict("evil.com"), Some("denylist"));
        assert_eq!(p.verdict("api.example.com"), None);
    }
}
