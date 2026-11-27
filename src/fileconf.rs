//! `<data dir>/guard.json` — the managed config file. Precedence is CLI flag
//! over environment over file, per list. Strictly parsed: this file is written
//! by fleet tooling, not typed by hand, so anything but a flat object of
//! string arrays (and one optional string) is rejected rather than guessed at.
//!
//! Shape: `{"deny": ["evil.example.com"], "allow": ["api.example.com"], "events_file": "/path"}`

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

const MAX_POLICY_BYTES: u64 = 64 * 1024;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct FileConfig {
    pub deny: Vec<String>,
    pub allow: Vec<String>,
    pub events_file: Option<PathBuf>,
}

pub fn load(path: &Path, required: bool) -> Result<FileConfig, String> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound && !required => {
            // A present but broken symlink is not a missing default.
            if fs::symlink_metadata(path).is_err_and(|e| e.kind() == ErrorKind::NotFound) {
                return Ok(FileConfig::default());
            }
            return Err("cannot read the default guard policy".to_string());
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Err("configured guard policy file is missing".to_string());
        }
        Err(_) => return Err("cannot read guard policy".to_string()),
    };
    if !metadata.is_file() || metadata.len() > MAX_POLICY_BYTES {
        return Err("guard policy must be a regular file at most 64 KiB".to_string());
    }
    let mut text = String::new();
    File::open(path)
        .and_then(|file| file.take(MAX_POLICY_BYTES + 1).read_to_string(&mut text))
        .map_err(|_| "cannot read guard policy as UTF-8".to_string())?;
    if text.len() as u64 > MAX_POLICY_BYTES {
        return Err("guard policy exceeds 64 KiB".to_string());
    }
    parse(&text).map_err(|reason| format!("invalid guard policy: {reason}"))
}

pub fn valid_host(host: &str) -> bool {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    let dns = host.strip_suffix('.').unwrap_or(host);
    dns.len() <= 253
        && dns.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
}

/// Minimal strict JSON parser for the shape above. No floats, no nesting
/// beyond one level. Returns Err on
/// anything else so a malformed file never silently becomes "allow all".
pub fn parse(text: &str) -> Result<FileConfig, String> {
    let mut p = Parser {
        chars: text.chars().collect(),
        pos: 0,
    };
    p.ws();
    p.expect('{')?;
    let mut cfg = FileConfig::default();
    let mut keys = HashSet::new();
    p.ws();
    if p.peek() == Some('}') {
        p.pos += 1;
        p.ws();
        p.eof()?;
        return Ok(cfg);
    }
    loop {
        p.ws();
        let key = p.string()?;
        if !keys.insert(key.clone()) {
            return Err("duplicate key".to_string());
        }
        p.ws();
        p.expect(':')?;
        p.ws();
        match key.as_str() {
            "deny" => cfg.deny = p.string_array()?,
            "allow" => cfg.allow = p.string_array()?,
            "events_file" => {
                let v = p.string()?;
                if v.trim().is_empty() || v.chars().any(char::is_control) {
                    return Err(
                        "events_file must be a nonempty path without control characters"
                            .to_string(),
                    );
                }
                cfg.events_file = Some(PathBuf::from(v));
            }
            _ => return Err("unknown key".to_string()),
        }
        p.ws();
        match p.peek() {
            Some(',') => {
                p.pos += 1;
            }
            Some('}') => {
                p.pos += 1;
                p.ws();
                p.eof()?;
                return Ok(cfg);
            }
            _ => return Err("expected ',' or '}'".to_string()),
        }
    }
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }
    fn ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\r' | '\n')) {
            self.pos += 1;
        }
    }
    fn expect(&mut self, c: char) -> Result<(), String> {
        if self.peek() == Some(c) {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!("expected {:?} at offset {}", c, self.pos))
        }
    }
    fn eof(&self) -> Result<(), String> {
        if self.pos >= self.chars.len() {
            Ok(())
        } else {
            Err("trailing content after JSON value".to_string())
        }
    }
    fn string(&mut self) -> Result<String, String> {
        self.expect('"')?;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err("unterminated string".to_string()),
                Some('"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some('\\') => {
                    self.pos += 1;
                    match self.peek() {
                        Some('"') => out.push('"'),
                        Some('\\') => out.push('\\'),
                        Some('/') => out.push('/'),
                        Some('n') => out.push('\n'),
                        Some('r') => out.push('\r'),
                        Some('t') => out.push('\t'),
                        Some('b') => out.push('\u{8}'),
                        Some('f') => out.push('\u{c}'),
                        Some('u') => {
                            self.pos += 1;
                            out.push(self.unicode_escape()?);
                            continue;
                        }
                        _ => return Err("unsupported escape".to_string()),
                    }
                    self.pos += 1;
                }
                Some(c) if (c as u32) < 0x20 => return Err("control char in string".to_string()),
                Some(c) => {
                    out.push(c);
                    self.pos += 1;
                }
            }
        }
    }
    fn hex_quad(&mut self) -> Result<u32, String> {
        let mut value = 0;
        for _ in 0..4 {
            let digit = self
                .peek()
                .and_then(|c| c.to_digit(16))
                .ok_or("invalid Unicode escape")?;
            value = value * 16 + digit;
            self.pos += 1;
        }
        Ok(value)
    }
    fn unicode_escape(&mut self) -> Result<char, String> {
        let first = self.hex_quad()?;
        let scalar = if (0xd800..=0xdbff).contains(&first) {
            self.expect('\\')?;
            self.expect('u')?;
            let second = self.hex_quad()?;
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err("invalid Unicode surrogate pair".to_string());
            }
            0x1_0000 + ((first - 0xd800) << 10) + second - 0xdc00
        } else {
            first
        };
        char::from_u32(scalar).ok_or_else(|| "invalid Unicode escape".to_string())
    }
    fn string_array(&mut self) -> Result<Vec<String>, String> {
        self.expect('[')?;
        let mut out = Vec::new();
        self.ws();
        if self.peek() == Some(']') {
            self.pos += 1;
            return Ok(out);
        }
        loop {
            self.ws();
            let host = self.string()?;
            if !valid_host(&host) {
                return Err("allow and deny entries must be hosts".to_string());
            }
            out.push(host);
            self.ws();
            match self.peek() {
                Some(',') => {
                    self.pos += 1;
                }
                Some(']') => {
                    self.pos += 1;
                    return Ok(out);
                }
                _ => return Err("expected ',' or ']' in array".to_string()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_shape() {
        let cfg = parse(r#"{"deny": ["evil.com", "10.0.0.0"], "allow": ["api.example.com"], "events_file": "/tmp/ev.jsonl"}"#).unwrap();
        assert_eq!(cfg.deny, vec!["evil.com", "10.0.0.0"]);
        assert_eq!(cfg.allow, vec!["api.example.com"]);
        assert_eq!(cfg.events_file, Some(PathBuf::from("/tmp/ev.jsonl")));
    }

    #[test]
    fn empty_object_is_valid() {
        assert_eq!(parse("{}").unwrap(), FileConfig::default());
        assert_eq!(parse("  {  }  ").unwrap(), FileConfig::default());
    }

    #[test]
    fn rejects_unknown_keys_and_malformed_json() {
        assert!(parse(r#"{"block": []}"#).is_err());
        assert!(parse(r#"{"deny": [1]}"#).is_err());
        assert!(parse(r#"{"deny": []} trailing"#).is_err());
        assert!(parse(r#"{"deny": ["x""#).is_err());
        assert!(parse(r#"{"deny": {"a": 1}}"#).is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn rejects_invalid_values_and_duplicate_keys_without_echoing_input() {
        assert!(parse(r#"{"deny":["safe.invalid"],"deny":[]}"#).is_err());
        assert!(parse(r#"{"allow":["https://test.invalid/path"]}"#).is_err());
        assert!(parse(r#"{"deny":[""]}"#).is_err());
        assert!(parse(r#"{"events_file":""}"#).is_err());
        assert!(parse(r#"{"events_file":"\uD800"}"#).is_err());
        assert_eq!(
            parse(r#"{"private-key-with-marker":[]}"#),
            Err("unknown key".to_string())
        );
        assert!(parse(r#"{"events_file":"scratch-\uD83D\uDE80.jsonl"}"#).is_ok());
    }
}
