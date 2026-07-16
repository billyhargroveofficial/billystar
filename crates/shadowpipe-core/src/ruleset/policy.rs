//! sing-box-style ordered split policy: direct rules → proxy rules → final direct.

use crate::ruleset::matcher::{DomainMatcher, IpMatcher};
use anyhow::{Context, Result};
use geosite_rs::{decode_geoip, decode_geosite, GeoIpList, GeoSiteList};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Parsed rules list entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleTags {
    Geosite(String),
    Geoip(String),
    Domain { action: RuleListKind, name: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleListKind {
    Direct,
    Proxy,
}

impl RuleTags {
    pub fn parse_line(line: &str, default_kind: RuleListKind) -> Option<Self> {
        let line = line.split('#').next()?.trim();
        if line.is_empty() {
            return None;
        }
        let (kind, rest) = if let Some(r) = line.strip_prefix("direct:") {
            (RuleListKind::Direct, r)
        } else if let Some(r) = line.strip_prefix("proxy:") {
            (RuleListKind::Proxy, r)
        } else {
            (default_kind, line)
        };
        if let Some(name) = rest.strip_prefix("geosite:") {
            return Some(Self::Geosite(normalize_tag(name)));
        }
        if let Some(name) = rest.strip_prefix("geoip:") {
            return Some(Self::Geoip(normalize_tag(name)));
        }
        if let Some(name) = rest.strip_prefix("domain:") {
            return Some(Self::Domain {
                action: kind,
                name: name.trim_end_matches('.').to_ascii_lowercase(),
            });
        }
        None
    }
}

fn normalize_tag(name: &str) -> String {
    name.trim().to_ascii_uppercase()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteAction {
    Direct,
    Proxy,
    Reject,
}

pub struct SplitPolicy {
    direct_domain: DomainMatcher,
    direct_ip: IpMatcher,
    proxy_domain: DomainMatcher,
    proxy_ip: IpMatcher,
    loaded_direct: Vec<String>,
    loaded_proxy: Vec<String>,
}

impl SplitPolicy {
    pub fn route_domain(&self, host: &str) -> RouteAction {
        let host = host.trim_end_matches('.');
        if host.is_empty() {
            return RouteAction::Direct;
        }
        if self.direct_domain.contains(host) {
            return RouteAction::Direct;
        }
        if self.proxy_domain.contains(host) {
            return RouteAction::Proxy;
        }
        RouteAction::Direct
    }

    pub fn route_ip(&self, ip: IpAddr) -> RouteAction {
        if is_builtin_direct_ip(ip) {
            return RouteAction::Direct;
        }
        if self.direct_ip.contains(ip) {
            return RouteAction::Direct;
        }
        if self.proxy_ip.contains(ip) {
            return RouteAction::Proxy;
        }
        RouteAction::Direct
    }

    pub fn route(&self, host: Option<&str>, ip: Option<IpAddr>) -> RouteAction {
        if let Some(h) = host {
            return self.route_domain(h);
        }
        ip.map(|i| self.route_ip(i)).unwrap_or(RouteAction::Direct)
    }

    pub fn loaded_direct_tags(&self) -> &[String] {
        &self.loaded_direct
    }

    pub fn loaded_proxy_tags(&self) -> &[String] {
        &self.loaded_proxy
    }

    pub fn proxy_ip_nets(&self) -> &[ipnet::IpNet] {
        self.proxy_ip.nets()
    }

    pub fn loaded_tags(&self) -> Vec<String> {
        let mut t = self.loaded_direct.clone();
        t.extend(self.loaded_proxy.clone());
        t
    }
}

pub struct PolicyLoadPaths {
    pub geosite_dat: PathBuf,
    pub geoip_dat: PathBuf,
    pub proxy_rules: PathBuf,
    pub direct_rules: Option<PathBuf>,
}

impl PolicyLoadPaths {
    pub fn from_dir(
        dir: impl AsRef<Path>,
        proxy_rules: impl AsRef<Path>,
        direct_rules: Option<PathBuf>,
    ) -> Self {
        let dir = dir.as_ref();
        Self {
            geosite_dat: dir.join("geosite.dat"),
            geoip_dat: dir.join("geoip.dat"),
            proxy_rules: proxy_rules.as_ref().to_path_buf(),
            direct_rules,
        }
    }

    pub fn from_legacy(load: &crate::ruleset::LoadPaths, direct_rules: Option<PathBuf>) -> Self {
        Self {
            geosite_dat: load.geosite_dat.clone(),
            geoip_dat: load.geoip_dat.clone(),
            proxy_rules: load.rules_list.clone(),
            direct_rules,
        }
    }
}

pub fn load_split_policy(paths: &PolicyLoadPaths) -> Result<SplitPolicy> {
    let geosite = decode_geosite(
        &std::fs::read(&paths.geosite_dat)
            .with_context(|| format!("read {}", paths.geosite_dat.display()))?,
    )
    .context("decode geosite.dat")?;
    let geoip = decode_geoip(
        &std::fs::read(&paths.geoip_dat)
            .with_context(|| format!("read {}", paths.geoip_dat.display()))?,
    )
    .context("decode geoip.dat")?;

    let proxy_rules = read_rules_list(&paths.proxy_rules, RuleListKind::Proxy)?;
    let direct_rules = if let Some(p) = &paths.direct_rules {
        if p.exists() {
            read_rules_list(p, RuleListKind::Direct)?
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    build_split_policy(&direct_rules, &proxy_rules, &geosite, &geoip)
}

fn read_rules_list(path: &Path, kind: RuleListKind) -> Result<Vec<RuleTags>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(text
        .lines()
        .filter_map(|l| RuleTags::parse_line(l, kind))
        .collect())
}

pub(crate) fn build_split_policy(
    direct_rules: &[RuleTags],
    proxy_rules: &[RuleTags],
    geosite: &GeoSiteList,
    geoip: &GeoIpList,
) -> Result<SplitPolicy> {
    let (direct_domain, direct_ip, loaded_direct) =
        build_rule_set(direct_rules, geosite, geoip, "direct-rules")?;
    let (proxy_domain, proxy_ip, loaded_proxy) =
        build_rule_set(proxy_rules, geosite, geoip, "proxy-rules")?;

    Ok(SplitPolicy {
        direct_domain,
        direct_ip,
        proxy_domain,
        proxy_ip,
        loaded_direct,
        loaded_proxy,
    })
}

fn build_rule_set(
    rules: &[RuleTags],
    geosite: &GeoSiteList,
    geoip: &GeoIpList,
    label: &str,
) -> Result<(DomainMatcher, IpMatcher, Vec<String>)> {
    let site_index: HashMap<String, &geosite_rs::GeoSite> = geosite
        .entry
        .iter()
        .map(|e| (e.country_code.to_ascii_uppercase(), e))
        .collect();
    let ip_index: HashMap<String, &geosite_rs::GeoIp> = geoip
        .entry
        .iter()
        .map(|e| (e.country_code.to_ascii_uppercase(), e))
        .collect();

    let mut domain = DomainMatcher::default();
    let mut ip = IpMatcher::default();
    let mut loaded = Vec::new();

    for rule in rules {
        match rule {
            RuleTags::Geosite(tag) => {
                let entry = site_index.get(tag).with_context(|| {
                    format!("geosite tag {tag:?} not in geosite.dat (check {label})")
                })?;
                domain.merge(DomainMatcher::from_geosite_domains(&entry.domain)?);
                loaded.push(format!("geosite:{tag}"));
            }
            RuleTags::Geoip(tag) => {
                let entry = ip_index.get(tag).with_context(|| {
                    format!("geoip tag {tag:?} not in geoip.dat (check {label})")
                })?;
                ip.merge(IpMatcher::from_geoip_entry(entry));
                loaded.push(format!("geoip:{tag}"));
            }
            RuleTags::Domain { name, .. } => {
                domain.insert_full(name.clone());
                loaded.push(format!("domain:{name}"));
            }
        }
    }

    Ok((domain, ip, loaded))
}

fn is_builtin_direct_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_broadcast()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use geosite_rs::{Cidr, Domain, GeoIp, GeoSite};

    fn fixture() -> SplitPolicy {
        let geosite = GeoSiteList {
            entry: vec![
                GeoSite {
                    country_code: "TESTAI".into(),
                    domain: vec![Domain {
                        r#type: 1,
                        value: "anthropic.com".into(),
                        attribute: vec![],
                    }],
                },
                GeoSite {
                    country_code: "TESTRU".into(),
                    domain: vec![Domain {
                        r#type: 1,
                        value: "yandex.ru".into(),
                        attribute: vec![],
                    }],
                },
            ],
        };
        let geoip = GeoIpList {
            entry: vec![GeoIp {
                country_code: "TESTIP".into(),
                cidr: vec![Cidr {
                    ip: vec![93, 184, 216, 34],
                    prefix: 32,
                }],
                reverse_match: false,
            }],
        };
        build_split_policy(
            &[RuleTags::Geosite("TESTRU".into())],
            &[
                RuleTags::Geosite("TESTAI".into()),
                RuleTags::Geoip("TESTIP".into()),
            ],
            &geosite,
            &geoip,
        )
        .expect("policy")
    }

    #[test]
    fn parse_rule_tags() {
        assert_eq!(
            RuleTags::parse_line("geosite:anthropic", RuleListKind::Proxy),
            Some(RuleTags::Geosite("ANTHROPIC".into()))
        );
    }

    #[test]
    fn direct_overrides_before_proxy() {
        let p = fixture();
        assert_eq!(p.route_domain("mail.yandex.ru"), RouteAction::Direct);
        assert_eq!(p.route_domain("api.anthropic.com"), RouteAction::Proxy);
    }

    #[test]
    fn private_ip_always_direct() {
        let p = fixture();
        assert_eq!(
            p.route_ip("192.168.1.1".parse().unwrap()),
            RouteAction::Direct
        );
    }

    #[test]
    fn final_direct() {
        let p = fixture();
        assert_eq!(p.route_domain("example.com"), RouteAction::Direct);
    }
}
