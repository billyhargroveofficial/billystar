//! sing-box-style split DNS: policy picks upstream (direct vs proxy), AAAA kill for proxy.

use super::dns_packet::{
    build_empty_response, min_answer_ttl, parse_a_records, parse_cnames, parse_qname, query_type,
    response_code,
};
use super::ip_cache::IpDomainCache;
use super::routes::SplitRouteGuard;
use crate::ruleset::{RouteAction, SplitPolicy};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, warn};

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
const CACHE_DEFAULT_TTL: Duration = Duration::from_secs(60);
const CACHE_MAX_TTL: Duration = Duration::from_secs(300);
const QTYPE_AAAA: u16 = 28;

#[derive(Clone, Debug)]
pub struct SplitDnsConfig {
    pub bind: SocketAddr,
    /// RU / ISP resolver for direct domains (sing-box `server: local`).
    pub direct_upstream: SocketAddr,
    /// Foreign resolver for proxy domains.
    pub proxy_upstream: SocketAddr,
    /// Return empty AAAA for proxy domains — force IPv4 + /32 routes (sing-box kill AAAA).
    pub reject_aaaa_for_proxy: bool,
}

impl Default for SplitDnsConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:1053".parse().unwrap(),
            direct_upstream: "77.88.8.8:53".parse().unwrap(),
            proxy_upstream: "8.8.8.8:53".parse().unwrap(),
            reject_aaaa_for_proxy: true,
        }
    }
}

impl SplitDnsConfig {
    /// Back-compat: single upstream treated as proxy; direct stays Yandex.
    pub fn with_proxy_upstream(upstream: SocketAddr) -> Self {
        Self {
            proxy_upstream: upstream,
            ..Self::default()
        }
    }
}

struct CacheEntry {
    response: Vec<u8>,
    expires: Instant,
}

pub struct SplitDnsHandle {
    task: tokio::task::JoinHandle<()>,
}

impl SplitDnsHandle {
    pub async fn spawn(
        cfg: SplitDnsConfig,
        policy: Arc<SplitPolicy>,
        routes: Arc<Mutex<SplitRouteGuard>>,
        ip_cache: Arc<IpDomainCache>,
    ) -> Result<Self> {
        let sock = Arc::new(
            UdpSocket::bind(cfg.bind)
                .await
                .with_context(|| format!("bind split DNS {}", cfg.bind))?,
        );
        tracing::info!(
            bind = %cfg.bind,
            direct = %cfg.direct_upstream,
            proxy = %cfg.proxy_upstream,
            "split DNS listening (sing-box-style dual upstream)"
        );

        let cache = Arc::new(Mutex::new(HashMap::<String, CacheEntry>::new()));

        let task = {
            let sock = Arc::clone(&sock);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                        break;
                    };
                    let query = buf[..n].to_vec();
                    let policy = Arc::clone(&policy);
                    let routes = Arc::clone(&routes);
                    let cache = Arc::clone(&cache);
                    let ip_cache = Arc::clone(&ip_cache);
                    let sock2 = Arc::clone(&sock);
                    let cfg = cfg.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_query(
                            &sock2, peer, &query, &cfg, &policy, &routes, &cache, &ip_cache,
                        )
                        .await
                        {
                            debug!(%e, "split dns query failed");
                        }
                    });
                }
            })
        };

        Ok(Self { task })
    }
}

impl Drop for SplitDnsHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_query(
    sock: &Arc<UdpSocket>,
    peer: SocketAddr,
    query: &[u8],
    cfg: &SplitDnsConfig,
    policy: &SplitPolicy,
    routes: &Arc<Mutex<SplitRouteGuard>>,
    cache: &Arc<Mutex<HashMap<String, CacheEntry>>>,
    ip_cache: &Arc<IpDomainCache>,
) -> Result<()> {
    let qname = parse_qname(query).unwrap_or_default();
    let qtype = query_type(query).unwrap_or(0);
    let action = policy.route_domain(&qname);
    let cache_key = format!("{qname}:{qtype}:{action:?}");

    if action == RouteAction::Proxy && cfg.reject_aaaa_for_proxy && qtype == QTYPE_AAAA {
        if let Some(resp) = build_empty_response(query) {
            sock.send_to(&resp, peer).await?;
            return Ok(());
        }
    }

    if let Some(resp) = cache_get(cache, &cache_key) {
        sock.send_to(&resp, peer).await?;
        post_process(&qname, &resp, policy, routes, ip_cache);
        return Ok(());
    }

    let upstream = match action {
        RouteAction::Proxy => cfg.proxy_upstream,
        RouteAction::Direct | RouteAction::Reject => cfg.direct_upstream,
    };

    let upstream_sock = UdpSocket::bind("0.0.0.0:0").await?;
    upstream_sock.send_to(query, upstream).await?;
    let mut resp = vec![0u8; 4096];
    let n = timeout(UPSTREAM_TIMEOUT, upstream_sock.recv(&mut resp))
        .await
        .context("upstream dns timeout")?
        .context("upstream dns recv")?;
    resp.truncate(n);

    if response_code(&resp) == 0 {
        let ttl_secs = min_answer_ttl(&resp, CACHE_DEFAULT_TTL.as_secs() as u32);
        let ttl = Duration::from_secs(u64::from(ttl_secs)).min(CACHE_MAX_TTL);
        cache_insert(cache, cache_key, resp.clone(), ttl);
    }

    sock.send_to(&resp, peer).await?;
    post_process(&qname, &resp, policy, routes, ip_cache);
    Ok(())
}

fn post_process(
    qname: &str,
    resp: &[u8],
    policy: &SplitPolicy,
    routes: &Arc<Mutex<SplitRouteGuard>>,
    ip_cache: &Arc<IpDomainCache>,
) {
    let ttl_secs = min_answer_ttl(resp, CACHE_DEFAULT_TTL.as_secs() as u32);
    let ttl = Duration::from_secs(u64::from(ttl_secs)).min(CACHE_MAX_TTL);
    let ips = parse_a_records(resp);
    if !ips.is_empty() {
        ip_cache.remember(qname, &ips, ttl);
    }

    let mut names = vec![qname.to_string()];
    names.extend(parse_cnames(resp));

    for name in names {
        if policy.route_domain(&name) != RouteAction::Proxy {
            continue;
        }
        if ips.is_empty() {
            continue;
        }
        install_proxy_routes(&name, &ips, routes);
    }
}

fn install_proxy_routes(qname: &str, ips: &[Ipv4Addr], routes: &Arc<Mutex<SplitRouteGuard>>) {
    let Ok(mut guard) = routes.lock() else {
        return;
    };
    for ip in ips {
        if ip.is_private() || ip.is_loopback() || ip.is_link_local() {
            continue;
        }
        if let Err(e) = guard.install_proxy_host(*ip) {
            warn!(domain = %qname, %ip, %e, "split dns route install failed");
        } else {
            tracing::info!(domain = %qname, %ip, iface = guard.iface(), "proxy route installed");
        }
    }
}

fn cache_get(cache: &Mutex<HashMap<String, CacheEntry>>, key: &str) -> Option<Vec<u8>> {
    let mut guard = cache.lock().ok()?;
    let now = Instant::now();
    guard.retain(|_, e| e.expires > now);
    guard.get(key).and_then(|e| {
        if e.expires > now {
            Some(e.response.clone())
        } else {
            None
        }
    })
}

fn cache_insert(
    cache: &Mutex<HashMap<String, CacheEntry>>,
    key: String,
    response: Vec<u8>,
    ttl: Duration,
) {
    if let Ok(mut guard) = cache.lock() {
        guard.insert(
            key,
            CacheEntry {
                response,
                expires: Instant::now() + ttl,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::split::dns_packet::parse_qname;

    #[test]
    fn parse_qname_smoke() {
        let mut p = vec![0u8; 12];
        p[5] = 1;
        p.extend_from_slice(&[
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0,
        ]);
        assert_eq!(parse_qname(&p).as_deref(), Some("www.example.com"));
    }
}
