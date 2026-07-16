//! Routing rule catalogs for split-tunnel policy (runetfreedom / v2ray geosite+geoip).
//!
//! sing-box-style ordered policy: `direct-rules.list` → `proxy-rules.list` → final direct.

mod binread;
mod catalog;
mod matcher;
mod policy;

pub use catalog::{load_proxy_catalog, load_split_policy_with_direct, LoadPaths, ProxyCatalog};
pub use matcher::{DomainMatch, MatchVerdict};
pub use policy::{
    load_split_policy, PolicyLoadPaths, RouteAction, RuleListKind, RuleTags, SplitPolicy,
};
