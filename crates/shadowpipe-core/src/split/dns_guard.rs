//! macOS system DNS pin for split mode (networksetup restore-on-Drop).

#[cfg(target_os = "macos")]
use anyhow::Context;
use anyhow::Result;
#[cfg(target_os = "macos")]
use std::process::Command;

#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
struct DnsRestore {
    v4: V4Restore,
    v6: V6Restore,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
enum V4Restore {
    Empty,
    Servers(Vec<String>),
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
enum V6Restore {
    Unchanged,
    Empty,
    Servers(Vec<String>),
}

/// Pins a network service resolver to `127.0.0.1` (or another split DNS address).
#[cfg(target_os = "macos")]
pub struct MacSplitDnsGuard {
    service: String,
    restore: DnsRestore,
}

#[cfg(target_os = "macos")]
impl MacSplitDnsGuard {
    /// `service` is a networksetup name (e.g. "Wi-Fi"). `resolver` is the IP only.
    pub fn apply(service: &str, resolver: &str) -> Result<Self> {
        let restore = read_dns_restore(service)?;
        set_dns_servers(service, &[resolver])?;
        clear_v6_dns(service)?;
        tracing::info!(
            service,
            resolver,
            "macOS split DNS pinned (v4 + v6 cleared)"
        );
        Ok(Self {
            service: service.to_string(),
            restore,
        })
    }

    /// Best-effort: map default-route interface → networksetup service name.
    pub fn detect_service() -> Result<String> {
        if let Ok(svc) = std::env::var("SHADOWPIPE_SPLIT_DNS_SERVICE") {
            if !svc.is_empty() {
                return Ok(svc);
            }
        }
        let iface = default_route_interface()?;
        map_interface_to_service(&iface).with_context(|| {
            format!("map interface {iface} to network service — set SHADOWPIPE_SPLIT_DNS_SERVICE")
        })
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacSplitDnsGuard {
    fn drop(&mut self) {
        let r = restore_dns_servers(&self.service, &self.restore);
        if let Err(e) = r {
            tracing::warn!(service = %self.service, %e, "macOS split DNS restore failed");
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub struct MacSplitDnsGuard;

#[cfg(not(target_os = "macos"))]
impl MacSplitDnsGuard {
    pub fn apply(_service: &str, _resolver: &str) -> Result<Self> {
        Ok(Self)
    }

    pub fn detect_service() -> Result<String> {
        Ok(String::new())
    }
}

#[cfg(target_os = "macos")]
fn read_dns_restore(service: &str) -> Result<DnsRestore> {
    Ok(DnsRestore {
        v4: read_v4_dns(service)?,
        v6: read_v6_dns(service)?,
    })
}

#[cfg(target_os = "macos")]
fn read_v4_dns(service: &str) -> Result<V4Restore> {
    let out = Command::new("networksetup")
        .args(["-getdnsservers", service])
        .output()
        .with_context(|| format!("networksetup -getdnsservers {service}"))?;
    if !out.status.success() {
        anyhow::bail!(
            "networksetup -getdnsservers failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    if lines
        .iter()
        .any(|l| l.eq_ignore_ascii_case("there aren't any dns servers"))
    {
        return Ok(V4Restore::Empty);
    }
    Ok(V4Restore::Servers(lines))
}

#[cfg(target_os = "macos")]
fn read_v6_dns(service: &str) -> Result<V6Restore> {
    let out = Command::new("networksetup")
        .args(["-getv6dnsservers", service])
        .output();
    let Ok(out) = out else {
        return Ok(V6Restore::Unchanged);
    };
    if !out.status.success() {
        return Ok(V6Restore::Unchanged);
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    if lines
        .iter()
        .any(|l| l.eq_ignore_ascii_case("there aren't any dns servers"))
    {
        return Ok(V6Restore::Empty);
    }
    Ok(V6Restore::Servers(lines))
}

#[cfg(target_os = "macos")]
fn clear_v6_dns(service: &str) -> Result<()> {
    let out = Command::new("networksetup")
        .args(["-setv6dnsservers", service, "Empty"])
        .output()
        .with_context(|| format!("networksetup -setv6dnsservers {service} Empty"))?;
    if out.status.success() {
        return Ok(());
    }
    // Older macOS / unsupported interface — non-fatal.
    Ok(())
}

#[cfg(target_os = "macos")]
fn set_dns_servers(service: &str, servers: &[&str]) -> Result<()> {
    let mut cmd = Command::new("networksetup");
    cmd.arg("-setdnsservers").arg(service);
    cmd.args(servers);
    let out = cmd.output().with_context(|| {
        format!(
            "networksetup -setdnsservers {} {}",
            service,
            servers.join(" ")
        )
    })?;
    if out.status.success() {
        return Ok(());
    }
    anyhow::bail!(
        "networksetup -setdnsservers failed: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    )
}

#[cfg(target_os = "macos")]
fn restore_dns_servers(service: &str, restore: &DnsRestore) -> Result<()> {
    match &restore.v4 {
        V4Restore::Empty => set_dns_servers(service, &["Empty"])?,
        V4Restore::Servers(list) => {
            let refs: Vec<&str> = list.iter().map(String::as_str).collect();
            set_dns_servers(service, &refs)?;
        }
    }
    match &restore.v6 {
        V6Restore::Unchanged => {}
        V6Restore::Empty => {
            let _ = Command::new("networksetup")
                .args(["-setv6dnsservers", service, "Empty"])
                .status();
        }
        V6Restore::Servers(list) => {
            let refs: Vec<&str> = list.iter().map(String::as_str).collect();
            let mut cmd = Command::new("networksetup");
            cmd.arg("-setv6dnsservers").arg(service);
            cmd.args(refs);
            let _ = cmd.status();
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn default_route_interface() -> Result<String> {
    let out = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .context("route -n get default")?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.trim().strip_prefix("interface: ").map(str::to_string))
        .context("default route interface not found")
}

#[cfg(target_os = "macos")]
fn map_interface_to_service(iface: &str) -> Result<String> {
    let out = Command::new("networksetup")
        .args(["-listallhardwareports"])
        .output()
        .context("networksetup -listallhardwareports")?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut current: Option<String> = None;
    for line in text.lines() {
        if let Some(name) = line.strip_prefix("Hardware Port: ") {
            current = Some(name.trim().to_string());
        } else if let Some(dev) = line.strip_prefix("Device: ") {
            if dev.trim() == iface {
                return current.context("hardware port name missing for interface");
            }
        }
    }
    anyhow::bail!("no network service for interface {iface}")
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn detect_or_env_service() {
        let svc = MacSplitDnsGuard::detect_service();
        assert!(svc.is_ok() || std::env::var("SHADOWPIPE_SPLIT_DNS_SERVICE").is_err());
    }
}
