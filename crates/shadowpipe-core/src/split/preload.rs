//! Pre-resolve proxy domains at split start.

use crate::ruleset::{RouteAction, SplitPolicy};
use crate::split::dns_packet::{build_query, parse_a_records, response_code};
use crate::split::routes::SplitRouteGuard;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};

const RESOLVE_TIMEOUT: Duration = Duration::from_secs(4);

pub fn read_preload_list(path: &Path) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read preload list {}", path.display()))?;
    Ok(text
        .lines()
        .filter_map(|l| {
            let l = l.split('#').next()?.trim();
            if l.is_empty() {
                None
            } else {
                Some(l.to_ascii_lowercase())
            }
        })
        .collect())
}

pub async fn preload_domains(
    upstream: SocketAddr,
    policy: &SplitPolicy,
    routes: &Arc<Mutex<SplitRouteGuard>>,
    domains: &[String],
) -> usize {
    let mut installed = 0usize;
    for domain in domains {
        if policy.route_domain(domain) != RouteAction::Proxy {
            debug!(domain, "preload skip (not proxy policy)");
            continue;
        }
        match resolve_a(upstream, domain).await {
            Ok(ips) if !ips.is_empty() => {
                if let Ok(mut guard) = routes.lock() {
                    for ip in ips {
                        if ip.is_private() || ip.is_loopback() {
                            continue;
                        }
                        if guard.install_proxy_host(ip).is_ok() {
                            installed += 1;
                            debug!(domain, %ip, "preload route");
                        }
                    }
                }
            }
            Ok(_) => debug!(domain, "preload: no A records"),
            Err(e) => warn!(domain, %e, "preload resolve failed"),
        }
    }
    if installed > 0 {
        info!(
            routes = installed,
            count = domains.len(),
            "split preload routes installed"
        );
    }
    installed
}

async fn resolve_a(upstream: SocketAddr, qname: &str) -> Result<Vec<std::net::Ipv4Addr>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    let query = build_query(qname, 1);
    sock.send_to(&query, upstream).await?;
    let mut buf = vec![0u8; 4096];
    let n = timeout(RESOLVE_TIMEOUT, sock.recv(&mut buf))
        .await
        .context("preload dns timeout")?
        .context("preload dns recv")?;
    buf.truncate(n);
    if response_code(&buf) != 0 {
        anyhow::bail!("dns rcode {}", response_code(&buf));
    }
    Ok(parse_a_records(&buf))
}
