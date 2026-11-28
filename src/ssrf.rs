//! Post-resolution egress guardrails. The deny/allow lists in `policy.rs`
//! match the name the client asked for; these checks match the address the
//! proxy would actually connect to, after DNS, so alternate IP encodings
//! (glibc resolves `2852039166` to `169.254.169.254`) and DNS rebinding land
//! on the same decision as the dotted form.
//!
//! Modes:
//!
//! - `metadata` (default): block link-local ranges, which is where every
//!   cloud metadata service lives (AWS/GCP/Azure IMDS at 169.254.169.254,
//!   ECS at 169.254.170.2), plus the AWS IPv6 IMDS. Loopback and RFC1918 stay
//!   reachable: a wrapped dev tool talking to a local LLM or an internal API
//!   is normal, and `NO_PROXY` already carves localhost out at the client.
//! - `off`: no address checks; the name lists are the whole policy.
//! - `strict`: `metadata` plus loopback, RFC1918, IPv6 ULA and the unspecified
//!   address. This blocks a wrapped child from reaching the recorder's own
//!   ingest port through the proxy; it does not stop a client that bypasses
//!   the proxy entirely (network isolation is the wrapper's job).

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Guard {
    #[default]
    Metadata,
    Off,
    Strict,
}

impl Guard {
    /// Resolve the mode from its config-file string. `None` (key absent) is
    /// the default, so only a present-but-wrong value is an error.
    pub fn from_value(value: Option<&str>) -> Result<Guard, String> {
        match value {
            None | Some("metadata") => Ok(Guard::Metadata),
            Some("off") => Ok(Guard::Off),
            Some("strict") => Ok(Guard::Strict),
            Some(other) => Err(format!("ssrf_guard must be off, metadata or strict, not {other}")),
        }
    }

    pub fn denies(&self, addr: SocketAddr) -> bool {
        let ip = normalize(addr.ip());
        match self {
            Guard::Off => false,
            Guard::Metadata => is_link_local(ip) || is_metadata_v6(ip),
            Guard::Strict => {
                is_link_local(ip)
                    || is_metadata_v6(ip)
                    || ip.is_loopback()
                    || is_private(ip)
                    || ip.is_unspecified()
            }
        }
    }
}

/// IPv4-mapped IPv6 addresses compare as the IPv4 they carry.
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(), // 169.254.0.0/16
        IpAddr::V6(v6) => is_v6_link_local(&v6), // fe80::/10
    }
}

/// AWS documents fd00:ec2::254 as the IMDS IPv6 endpoint; it sits inside
/// fc00::/7, which `strict` blocks wholesale anyway.
fn is_metadata_v6(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if v6.segments() == [0xfd00, 0x0, 0x0, 0x0, 0x0, 0xec2, 0x0, 0x254])
}

fn is_v6_link_local(v6: &Ipv6Addr) -> bool {
    v6.segments()[0] & 0xffc0 == 0xfe80
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(), // 10/8, 172.16/12, 192.168/16
        IpAddr::V6(v6) => v6.segments()[0] & 0xfe00 == 0xfc00, // fc00::/7 ULA
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(a, b, c, d), 443))
    }

    #[test]
    fn metadata_mode_blocks_link_local_only() {
        let guard = Guard::Metadata;
        assert!(guard.denies(v4(169, 254, 169, 254)));
        assert!(guard.denies(v4(169, 254, 170, 2)));
        assert!(guard.denies(SocketAddr::from((
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0xec2, 0, 0x254),
            80
        ))));
        // Normal dev destinations stay reachable.
        assert!(!guard.denies(v4(127, 0, 0, 1)));
        assert!(!guard.denies(v4(10, 1, 2, 3)));
        assert!(!guard.denies(v4(93, 184, 216, 34)));
        assert!(!guard.denies(SocketAddr::from((
            Ipv6Addr::LOCALHOST,
            80
        ))));
    }

    #[test]
    fn strict_blocks_private_loopback_and_unspecified() {
        let guard = Guard::Strict;
        assert!(guard.denies(v4(127, 0, 0, 1)));
        assert!(guard.denies(v4(10, 0, 0, 1)));
        assert!(guard.denies(v4(172, 16, 0, 1)));
        assert!(guard.denies(v4(192, 168, 1, 1)));
        assert!(guard.denies(v4(0, 0, 0, 0)));
        assert!(guard.denies(v4(169, 254, 169, 254)));
        assert!(guard.denies(SocketAddr::from((
            Ipv6Addr::new(0xfc00, 1, 0, 0, 0, 0, 0, 1),
            80
        ))));
        assert!(!guard.denies(v4(93, 184, 216, 34)));
    }

    #[test]
    fn off_blocks_nothing() {
        let guard = Guard::Off;
        assert!(!guard.denies(v4(169, 254, 169, 254)));
        assert!(!guard.denies(v4(127, 0, 0, 1)));
    }

    #[test]
    fn ipv4_mapped_ipv6_compares_as_ipv4() {
        let mapped = SocketAddr::from((
            Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xa9fe, 0xa9fe),
            80
        ));
        assert_eq!(
            mapped.ip(),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xa9fe, 0xa9fe))
        );
        assert!(Guard::Metadata.denies(mapped));
        let loopback_mapped = SocketAddr::from((
            Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x1),
            80
        ));
        assert!(Guard::Strict.denies(loopback_mapped));
    }

    #[test]
    fn mode_strings_resolve_or_fail_loudly() {
        assert_eq!(Guard::from_value(None).unwrap(), Guard::Metadata);
        assert_eq!(
            Guard::from_value(Some("metadata")).unwrap(),
            Guard::Metadata
        );
        assert_eq!(Guard::from_value(Some("off")).unwrap(), Guard::Off);
        assert_eq!(Guard::from_value(Some("strict")).unwrap(), Guard::Strict);
        assert!(Guard::from_value(Some("paranoid")).is_err());
    }
}
