//! Platform routes for split tunnel (proxy IPs → utun, default stays direct).

use crate::ruleset::SplitPolicy;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use anyhow::Context;
use anyhow::Result;
use ipnet::IpNet;
use std::collections::HashSet;
use std::net::Ipv4Addr;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

pub struct SplitRouteGuard {
    iface: String,
    installed_hosts: HashSet<Ipv4Addr>,
    installed_nets: Vec<IpNet>,
    bypass_hosts: HashSet<Ipv4Addr>,
}

impl SplitRouteGuard {
    pub fn new(iface: impl Into<String>) -> Self {
        Self {
            iface: iface.into(),
            installed_hosts: HashSet::new(),
            installed_nets: Vec::new(),
            bypass_hosts: HashSet::new(),
        }
    }

    pub fn shared(iface: impl Into<String>) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self::new(iface)))
    }

    pub fn install_proxy_host(&mut self, ip: Ipv4Addr) -> Result<()> {
        if self.installed_hosts.insert(ip) {
            install_host_route(&self.iface, ip)?;
        }
        Ok(())
    }

    pub fn iface(&self) -> &str {
        &self.iface
    }

    pub fn install_resolver_bypasses(&mut self, ips: &[Ipv4Addr]) -> Result<()> {
        for ip in ips {
            if self.bypass_hosts.insert(*ip) {
                install_direct_bypass(*ip)?;
            }
        }
        Ok(())
    }

    /// Remove all installed host/CIDR routes (called on split shutdown).
    pub fn teardown(&mut self) {
        let mut empty = Self::new(&self.iface);
        std::mem::swap(self, &mut empty);
    }
}

impl Drop for SplitRouteGuard {
    fn drop(&mut self) {
        for ip in self.bypass_hosts.drain() {
            let _ = remove_direct_bypass(ip);
        }
        for ip in self.installed_hosts.drain() {
            let _ = remove_host_route(&self.iface, ip);
        }
        for net in self.installed_nets.drain(..) {
            let _ = remove_net_route(&self.iface, net);
        }
    }
}

pub fn install_geoip_routes(policy: &SplitPolicy, guard: &mut SplitRouteGuard) -> Result<()> {
    let mut n = 0usize;
    for net in policy.proxy_ip_nets() {
        if net.addr().is_loopback() {
            continue;
        }
        install_net_route(&guard.iface, *net)?;
        guard.installed_nets.push(*net);
        n += 1;
    }
    tracing::info!(cidr_routes = n, "split geoip routes installed");
    Ok(())
}

pub fn install_host_route(iface: &str, ip: Ipv4Addr) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let ip_s = ip.to_string();
    #[cfg(target_os = "macos")]
    {
        let _ = run_route("route", &["delete", "-host", &ip_s]);
        run_route("route", &["add", "-inet", &ip_s, "-interface", iface])
            .context("route add host")?;
    }
    #[cfg(target_os = "linux")]
    {
        run_route("ip", &["route", "replace", &ip_s, "dev", iface])
            .context("ip route replace host")?;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = (iface, ip);
    Ok(())
}

/// Pin a host to the current default gateway (residential path).
pub fn install_direct_bypass(ip: Ipv4Addr) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let ip_s = ip.to_string();
        let gw = default_gateway().context("default gateway for DNS bypass")?;
        let _ = run_route("route", &["delete", "-host", &ip_s]);
        run_route("route", &["add", "-host", &ip_s, "-gateway", &gw])
            .with_context(|| format!("route bypass {ip_s} via {gw}"))?;
    }
    #[cfg(target_os = "linux")]
    {
        crate::routes::RouteGuard::install_server_bypass_linux(ip)?;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = ip;
    Ok(())
}

pub fn remove_direct_bypass(ip: Ipv4Addr) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let ip_s = ip.to_string();
    #[cfg(target_os = "macos")]
    {
        let _ = run_route("route", &["delete", "-host", &ip_s]);
    }
    #[cfg(target_os = "linux")]
    {
        let _ = run_route("ip", &["route", "del", &ip_s]);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = ip;
    Ok(())
}

#[cfg(target_os = "macos")]
fn default_gateway() -> Result<String> {
    let out = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .context("route -n get default")?;
    if !out.status.success() {
        anyhow::bail!(
            "route get default failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.trim().strip_prefix("gateway: ").map(str::to_string))
        .ok_or_else(|| anyhow::anyhow!("no gateway in `route -n get default`"))
}

pub fn remove_host_route(iface: &str, ip: Ipv4Addr) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let ip_s = ip.to_string();
    #[cfg(target_os = "macos")]
    {
        let _ = run_route("route", &["delete", "-host", &ip_s, "-interface", iface]);
    }
    #[cfg(target_os = "linux")]
    {
        let _ = run_route("ip", &["route", "del", &ip_s, "dev", iface]);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = (iface, ip);
    Ok(())
}

fn install_net_route(iface: &str, net: IpNet) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let net_s = net.to_string();
    #[cfg(target_os = "macos")]
    {
        let _ = run_route("route", &["delete", "-net", &net_s]);
        run_route("route", &["add", "-net", &net_s, "-interface", iface])
            .with_context(|| format!("route add -net {net_s}"))?;
    }
    #[cfg(target_os = "linux")]
    {
        run_route("ip", &["route", "replace", &net_s, "dev", iface])
            .with_context(|| format!("ip route replace {net_s}"))?;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = (iface, net);
    Ok(())
}

fn remove_net_route(iface: &str, net: IpNet) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let net_s = net.to_string();
    #[cfg(target_os = "macos")]
    {
        let _ = run_route("route", &["delete", "-net", &net_s, "-interface", iface]);
    }
    #[cfg(target_os = "linux")]
    {
        let _ = run_route("ip", &["route", "del", &net_s, "dev", iface]);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = (iface, net);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_route(cmd: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(cmd)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("run {cmd} {}", args.join(" ")))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains("File exists") || stderr.contains("already exists") {
        return Ok(());
    }
    // Deleting an absent route is a no-op, not an error. The delete verb is
    // `route delete …` on macOS and `ip route del …` on Linux, and each prints
    // a different "route not present" message — swallow both on either form.
    let is_delete = args.contains(&"delete") || args.contains(&"del");
    if is_delete
        && (stderr.contains("not in table")        // macOS `route delete`
            || stderr.contains("No such process")  // Linux `ip route del` (RTNETLINK)
            || stderr.contains("Cannot find"))
    {
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "{cmd} {} failed: {}",
        args.join(" "),
        stderr.trim()
    ))
}
