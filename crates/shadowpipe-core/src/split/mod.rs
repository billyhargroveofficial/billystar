//! Split tunnel — sing-box ideas without sing-box: ordered policy, dual DNS, route-based steering.

mod dns;
mod dns_guard;
mod dns_packet;
mod ip_cache;
mod leak_guard;
mod preload;
mod routes;

pub use dns::{SplitDnsConfig, SplitDnsHandle};
pub use dns_guard::MacSplitDnsGuard;
pub use ip_cache::IpDomainCache;
pub use leak_guard::{LeakGuardConfig, SplitLeakGuard};
pub use preload::{preload_domains, read_preload_list};
pub use routes::{install_geoip_routes, install_host_route, remove_host_route, SplitRouteGuard};

use crate::ruleset::{load_split_policy_with_direct, LoadPaths, SplitPolicy};
use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub struct SplitTunnel {
    pub policy: Arc<SplitPolicy>,
    pub ip_cache: Arc<IpDomainCache>,
    routes: Arc<Mutex<SplitRouteGuard>>,
    dns: Option<SplitDnsHandle>,
    tun_iface: String,
}

impl SplitTunnel {
    pub async fn start(
        tun_iface: impl Into<String>,
        rules_dir: impl AsRef<Path>,
        proxy_rules: impl AsRef<Path>,
        direct_rules: Option<PathBuf>,
        dns_cfg: SplitDnsConfig,
        preload_list: Option<PathBuf>,
    ) -> Result<Self> {
        let tun_iface = tun_iface.into();
        let paths = LoadPaths::from_dir(rules_dir, proxy_rules);
        let policy = Arc::new(load_split_policy_with_direct(&paths, direct_rules)?);
        tracing::info!(
            direct_tags = policy.loaded_direct_tags().len(),
            proxy_tags = policy.loaded_proxy_tags().len(),
            direct = ?policy.loaded_direct_tags(),
            proxy = ?policy.loaded_proxy_tags(),
            "split policy loaded (direct → proxy → final direct)"
        );

        let routes = SplitRouteGuard::shared(tun_iface.clone());
        {
            let mut guard = routes.lock().expect("split routes lock");
            let resolver_ips = [dns_cfg.direct_upstream.ip(), dns_cfg.proxy_upstream.ip()];
            if let (std::net::IpAddr::V4(d), std::net::IpAddr::V4(p)) =
                (resolver_ips[0], resolver_ips[1])
            {
                guard
                    .install_resolver_bypasses(&[d, p])
                    .context("split DNS resolver bypass routes")?;
                tracing::info!(
                    direct_dns = %d,
                    proxy_dns = %p,
                    "split DNS resolvers pinned to residential gateway"
                );
            }
            install_geoip_routes(&policy, &mut guard)?;
        }

        if let Some(list_path) = preload_list {
            if list_path.exists() {
                let domains = read_preload_list(&list_path)?;
                preload_domains(dns_cfg.proxy_upstream, &policy, &routes, &domains).await;
            }
        }

        let ip_cache = Arc::new(IpDomainCache::default());
        let dns = SplitDnsHandle::spawn(
            dns_cfg,
            Arc::clone(&policy),
            Arc::clone(&routes),
            Arc::clone(&ip_cache),
        )
        .await?;

        Ok(Self {
            policy,
            ip_cache,
            routes,
            dns: Some(dns),
            tun_iface,
        })
    }

    pub fn tun_iface(&self) -> &str {
        &self.tun_iface
    }
}

impl Drop for SplitTunnel {
    fn drop(&mut self) {
        self.dns.take();
        if let Ok(mut guard) = self.routes.lock() {
            guard.teardown();
        }
    }
}

pub fn route_proxy_ip(tun_iface: &str, ip: Ipv4Addr) -> Result<()> {
    install_host_route(tun_iface, ip)
}
