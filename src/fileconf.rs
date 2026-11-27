//! `<data dir>/guard.json` — the managed config file. Precedence is CLI flag
//! over environment over file, per list. Strictly parsed: this file is written
//! by fleet tooling, not typed by hand, so anything but a flat object of
//! string arrays (and one optional string) is rejected rather than guessed at.
//!
//! Shape: `{"deny": ["evil.example.com"], "allow": ["api.example.com"], "events_file": "/path"}`

use std::path::PathBuf;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct FileConfig {
    pub deny: Vec<String>,
    pub allow: Vec<String>,
    pub events_file: Option<PathBuf>,
}

/// Minimal strict JSON parser for the shape above. No floats, no nesting
/// beyond one level, no escapes beyond the common ones. Returns Err on
/// anything else so a malformed file never silently becomes "allow all".
pub fn parse(text: &str) -> Result<FileConfig, String> {
    let mut p = Parser { chars: text.chars().collect(), pos: 0 };
    p.ws();
    p.expect('{')?;
    let mut cfg = FileConfig::default();
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
        p.ws();
        p.expect(':')?;
        p.ws();
        match key.as_str() {
            "deny" => cfg.deny = p.string_array()?,
            "allow" => cfg.allow = p.string_array()?,
            "events_file" => {
                let v = p.string()?;
                cfg.events_file = Some(PathBuf::from(v));
            }
            other => return Err(format!("unknown key {:?}", other)),
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
        while matches!(self.peek(), Some(c) if c.is_whitespace()) {
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
            out.push(self.string()?);
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
}
