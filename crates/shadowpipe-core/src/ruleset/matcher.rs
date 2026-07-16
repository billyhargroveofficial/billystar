//! Fast domain / IP matching for split-routing policy.

use ipnet::IpNet;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

/// Whether a flow should use the shadowpipe tunnel or the physical interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchVerdict {
    /// Through shadowpipe (blocked / AI lists).
    Proxy,
    /// Residential / default path.
    Direct,
}

#[derive(Default)]
pub struct DomainMatcher {
    full: HashSet<Arc<str>>,
    suffix: Vec<Arc<str>>,
    keyword: Vec<Arc<str>>,
    regex: Vec<(regex::Regex, Arc<str>)>,
}

impl DomainMatcher {
    pub fn insert_full(&mut self, d: impl Into<Arc<str>>) {
        self.full.insert(d.into());
    }

    pub fn insert_suffix(&mut self, d: impl Into<Arc<str>>) {
        self.suffix.push(d.into());
    }

    pub fn insert_keyword(&mut self, d: impl Into<Arc<str>>) {
        self.keyword.push(d.into());
    }

    pub fn insert_regex(&mut self, pattern: &str) -> anyhow::Result<()> {
        let re = regex::Regex::new(pattern)?;
        self.regex.push((re, Arc::from(pattern)));
        Ok(())
    }

    pub fn from_geosite_domains(domains: &[geosite_rs::Domain]) -> anyhow::Result<Self> {
        let mut m = Self::default();
        for d in domains {
            // v2ray geosite.dat wire types (see geosite-rs geosite_to_hashmap).
            match d.r#type {
                0 => m.insert_keyword(d.value.to_ascii_lowercase()),
                1 => {
                    let mut s = d.value.to_ascii_lowercase();
                    if !s.starts_with('.') {
                        s.insert(0, '.');
                    }
                    m.insert_suffix(Arc::<str>::from(s));
                }
                2 => m.insert_full(d.value.to_ascii_lowercase()),
                3 => m.insert_regex(&d.value)?,
                _ => {}
            }
        }
        Ok(m)
    }

    pub fn merge(&mut self, other: Self) {
        self.full.extend(other.full);
        self.suffix.extend(other.suffix);
        self.keyword.extend(other.keyword);
        self.regex.extend(other.regex);
    }

    /// True when host matches any rule in this matcher set.
    pub fn contains(&self, host: &str) -> bool {
        self.match_domain(host) == MatchVerdict::Proxy
    }

    pub fn match_domain(&self, host: &str) -> MatchVerdict {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return MatchVerdict::Direct;
        }
        if self.full.contains(host.as_str()) {
            return MatchVerdict::Proxy;
        }
        for sfx in &self.suffix {
            if host.ends_with(sfx.as_ref()) {
                return MatchVerdict::Proxy;
            }
        }
        for kw in &self.keyword {
            if host.contains(kw.as_ref()) {
                return MatchVerdict::Proxy;
            }
        }
        for (re, _) in &self.regex {
            if re.is_match(&host) {
                return MatchVerdict::Proxy;
            }
        }
        MatchVerdict::Direct
    }
}

#[derive(Default)]
pub struct IpMatcher {
    nets: Vec<IpNet>,
}

impl IpMatcher {
    pub fn insert_cidr(&mut self, cidr: IpNet) {
        self.nets.push(cidr);
    }

    pub fn merge(&mut self, other: Self) {
        self.nets.extend(other.nets);
    }

    pub fn nets(&self) -> &[IpNet] {
        &self.nets
    }

    pub fn from_geoip_entry(entry: &geosite_rs::GeoIp) -> Self {
        let mut m = Self::default();
        for c in &entry.cidr {
            if let Some(net) = cidr_to_ipnet(c) {
                m.insert_cidr(net);
            }
        }
        m
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|n| n.contains(&ip))
    }
}

fn cidr_to_ipnet(c: &geosite_rs::Cidr) -> Option<IpNet> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    match c.ip.len() {
        4 => {
            let a = Ipv4Addr::new(c.ip[0], c.ip[1], c.ip[2], c.ip[3]);
            format!("{a}/{}", c.prefix).parse().ok()
        }
        16 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&c.ip);
            let a = Ipv6Addr::from(o);
            format!("{a}/{}", c.prefix).parse().ok()
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DomainMatch;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_and_keyword() {
        let mut m = DomainMatcher::default();
        m.insert_suffix(".anthropic.com");
        m.insert_keyword("openai");
        assert_eq!(m.match_domain("claude.ai"), MatchVerdict::Direct);
        assert_eq!(m.match_domain("api.anthropic.com"), MatchVerdict::Proxy);
        assert_eq!(m.match_domain("chat.openai.com"), MatchVerdict::Proxy);
    }
}
