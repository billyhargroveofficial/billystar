//! IP ↔ domain cache from DNS answers (sing-box resolve / fake-ip lite without fake-ip).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Entry {
    domains: Vec<String>,
    expires: Instant,
}

/// Reverse mapping learned from split DNS — helps IP-only connects pick a policy.
#[derive(Default)]
pub struct IpDomainCache {
    by_ip: Mutex<HashMap<Ipv4Addr, Entry>>,
}

impl IpDomainCache {
    pub fn remember(&self, domain: &str, ips: &[Ipv4Addr], ttl: Duration) {
        if domain.is_empty() || ips.is_empty() {
            return;
        }
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let expires = Instant::now() + ttl;
        let Ok(mut map) = self.by_ip.lock() else {
            return;
        };
        map.retain(|_, e| e.expires > Instant::now());
        for ip in ips {
            let e = map.entry(*ip).or_insert(Entry {
                domains: Vec::new(),
                expires,
            });
            e.expires = e.expires.max(expires);
            if !e.domains.iter().any(|d| d == &domain) {
                e.domains.push(domain.clone());
            }
        }
    }

    pub fn domains_for(&self, ip: Ipv4Addr) -> Vec<String> {
        let Ok(mut map) = self.by_ip.lock() else {
            return Vec::new();
        };
        let now = Instant::now();
        map.retain(|_, e| e.expires > now);
        map.get(&ip)
            .filter(|e| e.expires > now)
            .map(|e| e.domains.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remembers_and_expires() {
        let c = IpDomainCache::default();
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        c.remember("api.anthropic.com", &[ip], Duration::from_secs(60));
        assert_eq!(c.domains_for(ip), vec!["api.anthropic.com"]);
    }
}
