//! Legacy catalog wrapper around [`SplitPolicy`].

use crate::ruleset::matcher::MatchVerdict;
use crate::ruleset::policy::{load_split_policy, PolicyLoadPaths, RouteAction, SplitPolicy};
use anyhow::Result;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

pub struct ProxyCatalog {
    policy: SplitPolicy,
}

impl ProxyCatalog {
    pub fn from_policy(policy: SplitPolicy) -> Self {
        Self { policy }
    }

    pub fn policy(&self) -> &SplitPolicy {
        &self.policy
    }

    pub fn domain_verdict(&self, host: &str) -> MatchVerdict {
        match self.policy.route_domain(host) {
            RouteAction::Proxy => MatchVerdict::Proxy,
            _ => MatchVerdict::Direct,
        }
    }

    pub fn ip_verdict(&self, ip: IpAddr) -> MatchVerdict {
        match self.policy.route_ip(ip) {
            RouteAction::Proxy => MatchVerdict::Proxy,
            _ => MatchVerdict::Direct,
        }
    }

    pub fn should_proxy(&self, host: Option<&str>, ip: Option<IpAddr>) -> MatchVerdict {
        match self.policy.route(host, ip) {
            RouteAction::Proxy => MatchVerdict::Proxy,
            _ => MatchVerdict::Direct,
        }
    }

    pub fn loaded_tags(&self) -> Vec<String> {
        self.policy.loaded_tags()
    }

    pub fn ip_verdict_nets(&self) -> &[ipnet::IpNet] {
        self.policy.proxy_ip_nets()
    }
}

pub struct LoadPaths {
    pub rules_list: PathBuf,
    pub geosite_dat: PathBuf,
    pub geoip_dat: PathBuf,
}

impl LoadPaths {
    pub fn from_dir(dir: impl AsRef<Path>, rules_list: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref();
        Self {
            rules_list: rules_list.as_ref().to_path_buf(),
            geosite_dat: dir.join("geosite.dat"),
            geoip_dat: dir.join("geoip.dat"),
        }
    }
}

pub fn load_proxy_catalog(paths: &LoadPaths) -> Result<ProxyCatalog> {
    let policy = load_split_policy(&PolicyLoadPaths::from_legacy(paths, None))?;
    Ok(ProxyCatalog::from_policy(policy))
}

pub fn load_split_policy_with_direct(
    paths: &LoadPaths,
    direct_rules: Option<PathBuf>,
) -> Result<SplitPolicy> {
    load_split_policy(&PolicyLoadPaths::from_legacy(paths, direct_rules))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::policy::RuleTags;
    use geosite_rs::{Cidr, Domain, GeoIp, GeoIpList, GeoSite, GeoSiteList};

    #[test]
    fn proxy_catalog_from_tags() {
        let geosite = GeoSiteList {
            entry: vec![GeoSite {
                country_code: "TESTAI".into(),
                domain: vec![Domain {
                    r#type: 1,
                    value: "anthropic.com".into(),
                    attribute: vec![],
                }],
            }],
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
        let policy = crate::ruleset::policy::build_split_policy(
            &[],
            &[
                RuleTags::Geosite("TESTAI".into()),
                RuleTags::Geoip("TESTIP".into()),
            ],
            &geosite,
            &geoip,
        )
        .expect("policy");
        let cat = ProxyCatalog::from_policy(policy);
        assert_eq!(cat.domain_verdict("api.anthropic.com"), MatchVerdict::Proxy);
    }

    #[test]
    #[ignore = "needs ~/.config/shadowpipe-macos/rules/geosite.dat"]
    fn loads_split_policy() {
        let dir =
            PathBuf::from(std::env::var("HOME").unwrap()).join(".config/shadowpipe-macos/rules");
        let proxy =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/macos/proxy-rules.list");
        let direct =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/macos/direct-rules.list");
        if !dir.join("geosite.dat").exists() {
            return;
        }
        let paths = LoadPaths::from_dir(&dir, &proxy);
        let policy = load_split_policy_with_direct(&paths, Some(direct)).expect("policy");
        assert!(!policy.loaded_proxy_tags().is_empty());
        assert!(!policy.loaded_direct_tags().is_empty());
    }

    #[test]
    #[ignore = "needs ~/.config/shadowpipe-macos/rules/geosite.dat"]
    fn loads_runetfreedom_tags() {
        let dir =
            PathBuf::from(std::env::var("HOME").unwrap()).join(".config/shadowpipe-macos/rules");
        let list =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/macos/proxy-rules.list");
        if !dir.join("geosite.dat").exists() {
            return;
        }
        let cat = load_proxy_catalog(&LoadPaths::from_dir(&dir, &list)).expect("catalog");
        assert!(cat.loaded_tags().len() >= 10);
    }
}
