//! Hard DNS leak guard for split mode: hijack :53, block DoT/DoH (sing-box-class).
//!
//! macOS: pf anchor `shadowpipe.split` (user != root → split DNS; root = upstream).
//! Linux: iptables OUTPUT NAT/REJECT chain `SHADOWPIPE_DNS`.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use anyhow::Context;
use anyhow::Result;
#[cfg(target_os = "macos")]
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::PathBuf;

const DNS_CHAIN: &str = "SHADOWPIPE_DNS";
#[cfg(target_os = "macos")]
const PF_ANCHOR: &str = "shadowpipe.split";

/// Known DoH resolver IPs (443). Intentionally excludes 8.8.8.8 — too much collateral.
pub const DOH_BLOCK_IPS: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "149.112.112.112",
    "94.140.14.14",
    "94.140.15.15",
    "45.90.28.0",
    "45.90.30.0",
    "208.67.222.222",
    "208.67.220.220",
];

#[derive(Clone, Debug)]
pub struct LeakGuardConfig {
    pub dns_bind: SocketAddr,
    pub direct_upstream: SocketAddr,
    pub proxy_upstream: SocketAddr,
    pub block_doh: bool,
    pub block_dot: bool,
}

impl LeakGuardConfig {
    pub fn from_split_dns(dns: &super::SplitDnsConfig) -> Self {
        Self {
            dns_bind: dns.bind,
            direct_upstream: dns.direct_upstream,
            proxy_upstream: dns.proxy_upstream,
            block_doh: true,
            block_dot: true,
        }
    }
}

pub struct SplitLeakGuard {
    active: bool,
    // read only by the Linux teardown path
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    block_dot: bool,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    block_doh: bool,
    #[allow(dead_code)]
    rules_path: Option<PathBuf>,
}

impl SplitLeakGuard {
    pub fn engage(cfg: &LeakGuardConfig) -> Result<Self> {
        #[cfg(target_os = "macos")]
        {
            let path = write_pf_rules(cfg)?;
            install_pf_anchor(&path)?;
            tracing::info!(
                dns = %cfg.dns_bind,
                "split DNS leak guard engaged (pf hijack :53 + DoT/DoH block)"
            );
            Ok(Self {
                active: true,
                block_dot: cfg.block_dot,
                block_doh: cfg.block_doh,
                rules_path: Some(path),
            })
        }
        #[cfg(target_os = "linux")]
        {
            let install = leak_guard_install_argv(cfg);
            let teardown = leak_guard_teardown_argv(cfg.block_dot, cfg.block_doh);
            run_install_with_rollback(&install, &teardown, ipt)?;
            tracing::info!(
                dns = %cfg.dns_bind,
                "split DNS leak guard engaged (iptables hijack :53 + DoT/DoH block)"
            );
            Ok(Self {
                active: true,
                block_dot: cfg.block_dot,
                block_doh: cfg.block_doh,
                rules_path: None,
            })
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = cfg;
            Ok(Self {
                active: false,
                block_dot: false,
                block_doh: false,
                rules_path: None,
            })
        }
    }
}

impl Drop for SplitLeakGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            let _ = Command::new("pfctl")
                .args(["-a", PF_ANCHOR, "-F", "all"])
                .status();
            if let Some(p) = self.rules_path.take() {
                let _ = std::fs::remove_file(p);
            }
        }
        #[cfg(target_os = "linux")]
        {
            for args in leak_guard_teardown_argv(self.block_dot, self.block_doh) {
                let _ = ipt(&args);
            }
        }
        self.active = false;
    }
}

/// Linux iptables rules for unit tests and runtime.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn leak_guard_install_argv(cfg: &LeakGuardConfig) -> Vec<Vec<String>> {
    let dns_ip = cfg.dns_bind.ip().to_string();
    let dns_port = cfg.dns_bind.port().to_string();
    let mut rules = vec![
        argv(&["-t", "nat", "-N", DNS_CHAIN]),
        argv(&["-t", "nat", "-F", DNS_CHAIN]),
        argv(&[
            "-t",
            "nat",
            "-A",
            DNS_CHAIN,
            "-p",
            "udp",
            "-j",
            "DNAT",
            "--to-destination",
            &format!("{dns_ip}:{dns_port}"),
        ]),
        argv(&[
            "-t",
            "nat",
            "-A",
            DNS_CHAIN,
            "-p",
            "tcp",
            "-j",
            "DNAT",
            "--to-destination",
            &format!("{dns_ip}:{dns_port}"),
        ]),
        argv(&[
            "-t",
            "nat",
            "-A",
            "OUTPUT",
            "-p",
            "udp",
            "--dport",
            "53",
            "-m",
            "owner",
            "!",
            "--uid-owner",
            "0",
            "-j",
            DNS_CHAIN,
        ]),
        argv(&[
            "-t",
            "nat",
            "-A",
            "OUTPUT",
            "-p",
            "tcp",
            "--dport",
            "53",
            "-m",
            "owner",
            "!",
            "--uid-owner",
            "0",
            "-j",
            DNS_CHAIN,
        ]),
    ];
    if cfg.block_dot {
        rules.push(argv(&[
            "-A",
            "OUTPUT",
            "-p",
            "tcp",
            "--dport",
            "853",
            "-m",
            "owner",
            "!",
            "--uid-owner",
            "0",
            "-j",
            "REJECT",
        ]));
        rules.push(argv(&[
            "-A",
            "OUTPUT",
            "-p",
            "udp",
            "--dport",
            "853",
            "-m",
            "owner",
            "!",
            "--uid-owner",
            "0",
            "-j",
            "REJECT",
        ]));
    }
    if cfg.block_doh {
        for ip in DOH_BLOCK_IPS {
            rules.push(argv(&[
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "-d",
                ip,
                "--dport",
                "443",
                "-m",
                "owner",
                "!",
                "--uid-owner",
                "0",
                "-j",
                "REJECT",
            ]));
        }
    }
    rules
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn leak_guard_teardown_argv(block_dot: bool, block_doh: bool) -> Vec<Vec<String>> {
    let mut rules = vec![
        argv(&[
            "-t",
            "nat",
            "-D",
            "OUTPUT",
            "-p",
            "udp",
            "--dport",
            "53",
            "-m",
            "owner",
            "!",
            "--uid-owner",
            "0",
            "-j",
            DNS_CHAIN,
        ]),
        argv(&[
            "-t",
            "nat",
            "-D",
            "OUTPUT",
            "-p",
            "tcp",
            "--dport",
            "53",
            "-m",
            "owner",
            "!",
            "--uid-owner",
            "0",
            "-j",
            DNS_CHAIN,
        ]),
        argv(&["-t", "nat", "-F", DNS_CHAIN]),
        argv(&["-t", "nat", "-X", DNS_CHAIN]),
    ];
    if block_dot {
        rules.push(argv(&[
            "-D",
            "OUTPUT",
            "-p",
            "tcp",
            "--dport",
            "853",
            "-m",
            "owner",
            "!",
            "--uid-owner",
            "0",
            "-j",
            "REJECT",
        ]));
        rules.push(argv(&[
            "-D",
            "OUTPUT",
            "-p",
            "udp",
            "--dport",
            "853",
            "-m",
            "owner",
            "!",
            "--uid-owner",
            "0",
            "-j",
            "REJECT",
        ]));
    }
    if block_doh {
        for ip in DOH_BLOCK_IPS {
            rules.push(argv(&[
                "-D",
                "OUTPUT",
                "-p",
                "tcp",
                "-d",
                ip,
                "--dport",
                "443",
                "-m",
                "owner",
                "!",
                "--uid-owner",
                "0",
                "-j",
                "REJECT",
            ]));
        }
    }
    rules
}

/// Execute an iptables install plan transactionally. If any command fails, run
/// the complete best-effort teardown plan in order and report both the original
/// failure and any rollback failures. Keeping the executor injectable makes the
/// ordering and fail-closed behavior testable without iptables or Linux.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn run_install_with_rollback<F>(
    install: &[Vec<String>],
    teardown: &[Vec<String>],
    mut execute: F,
) -> Result<()>
where
    F: FnMut(&[String]) -> Result<()>,
{
    for (index, args) in install.iter().enumerate() {
        if let Err(install_error) = execute(args) {
            let mut rollback_failures = Vec::new();
            for rollback_args in teardown {
                if let Err(error) = execute(rollback_args) {
                    rollback_failures
                        .push(format!("iptables {}: {error}", rollback_args.join(" ")));
                }
            }

            let rollback_status = if rollback_failures.is_empty() {
                format!("all {} rollback commands completed", teardown.len())
            } else {
                format!(
                    "{} of {} rollback commands failed: {}",
                    rollback_failures.len(),
                    teardown.len(),
                    rollback_failures.join("; ")
                )
            };
            return Err(install_error.context(format!(
                "iptables install command {}/{} (`iptables {}`) failed; rollback attempted: {}",
                index + 1,
                install.len(),
                args.join(" "),
                rollback_status
            )));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn upstream_ips(cfg: &LeakGuardConfig) -> Vec<String> {
    let mut ips = vec![cfg.direct_upstream.ip(), cfg.proxy_upstream.ip()];
    ips.sort_by_key(|a| format!("{a}"));
    ips.dedup();
    ips.into_iter()
        .filter(|ip| !ip.is_loopback())
        .map(|ip| ip.to_string())
        .collect()
}

#[cfg(target_os = "macos")]
fn write_pf_rules(cfg: &LeakGuardConfig) -> Result<PathBuf> {
    use std::fs;
    use std::io::Write;

    let dir = std::env::var("HOME")
        .map(|h| PathBuf::from(h).join(".config/shadowpipe-macos/run"))
        .unwrap_or_else(|_| PathBuf::from("/tmp/shadowpipe-run"));
    fs::create_dir_all(&dir).context("create run dir for pf rules")?;
    let path = dir.join("shadowpipe-split.pf");

    let dns_ip = match cfg.dns_bind.ip() {
        IpAddr::V4(v) => v.to_string(),
        IpAddr::V6(v) => v.to_string(),
    };
    let dns_port = cfg.dns_bind.port();
    let upstream = upstream_ips(cfg);
    let upstream_table = upstream.join(", ");

    let mut f = fs::File::create(&path).context("write pf rules")?;
    writeln!(f, "# shadowpipe split leak guard (auto)")?;
    writeln!(f, "set skip on lo0")?;
    writeln!(f)?;
    if !upstream.is_empty() {
        writeln!(
            f,
            "pass out quick inet proto {{ udp tcp }} to {{ {upstream_table} }} port 53 keep state"
        )?;
    }
    writeln!(
        f,
        "rdr pass inet proto udp user > root to any port 53 -> {dns_ip} port {dns_port}"
    )?;
    writeln!(
        f,
        "rdr pass inet proto tcp user > root to any port 53 -> {dns_ip} port {dns_port}"
    )?;
    if cfg.block_dot {
        writeln!(
            f,
            "block out quick inet proto {{ udp tcp }} user > root to any port 853"
        )?;
    }
    if cfg.block_doh {
        let doh = DOH_BLOCK_IPS.join(", ");
        writeln!(
            f,
            "block out quick inet proto tcp user > root to {{ {doh} }} port 443"
        )?;
    }
    Ok(path)
}

#[cfg(target_os = "macos")]
fn install_pf_anchor(rules_path: &std::path::Path) -> Result<()> {
    use std::process::Command;

    ensure_pf_anchor_installed()?;

    let out = Command::new("pfctl")
        .args(["-a", PF_ANCHOR, "-f", &rules_path.to_string_lossy()])
        .output()
        .context("pfctl load anchor")?;
    if !out.status.success() {
        anyhow::bail!(
            "pfctl -a {} -f failed: {}",
            PF_ANCHOR,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let _ = Command::new("pfctl").arg("-e").status();
    Ok(())
}

/// Create pf anchor + patch pf.conf on first `--split-leak-guard` (needs root).
#[cfg(target_os = "macos")]
fn ensure_pf_anchor_installed() -> Result<()> {
    use std::fs;
    use std::process::Command;

    const ANCHOR_PATH: &str = "/etc/pf.anchors/shadowpipe.split";
    const PF_CONF: &str = "/etc/pf.conf";
    const MARKER: &str = "shadowpipe.split";

    if std::env::var("HOME").is_err() {
        // running as root via sudo — fine
    }

    if !std::path::Path::new("/etc/pf.anchors").exists() {
        fs::create_dir_all("/etc/pf.anchors").context("mkdir /etc/pf.anchors")?;
    }
    if !std::path::Path::new(ANCHOR_PATH).exists() {
        fs::write(
            ANCHOR_PATH,
            "# shadowpipe split DNS leak guard — rules loaded at runtime\n",
        )
        .context("write pf anchor stub")?;
        tracing::info!("created {ANCHOR_PATH}");
    }

    let pf_conf = fs::read_to_string(PF_CONF).unwrap_or_default();
    if !pf_conf.contains(MARKER) {
        let backup = format!("{PF_CONF}.bak.{}", chrono_lite_timestamp());
        fs::copy(PF_CONF, &backup).ok();
        let mut updated = pf_conf;
        if !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated.push_str(
            "\n# shadowpipe split DNS leak guard\nanchor \"shadowpipe.split\"\nload anchor \"shadowpipe.split\" from \"/etc/pf.anchors/shadowpipe.split\"\n",
        );
        fs::write(PF_CONF, updated).context("patch pf.conf with shadowpipe anchor")?;
        tracing::info!("patched {PF_CONF} (backup: {backup})");
        let _ = Command::new("pfctl").args(["-f", PF_CONF]).status();
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn chrono_lite_timestamp() -> String {
    use std::process::Command;
    Command::new("date")
        .args(["+%Y%m%d-%H%M%S"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "0".into())
}

#[cfg(target_os = "linux")]
fn ipt(args: &[String]) -> Result<()> {
    use std::process::Command;
    let out = Command::new("iptables")
        .args(args)
        .output()
        .with_context(|| format!("iptables {}", args.join(" ")))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains("Chain already exists") {
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "iptables {} failed: {}",
        args.join(" "),
        stderr.trim()
    ))
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> LeakGuardConfig {
        LeakGuardConfig {
            dns_bind: "127.0.0.1:1053".parse().unwrap(),
            direct_upstream: "77.88.8.8:53".parse().unwrap(),
            proxy_upstream: "8.8.8.8:53".parse().unwrap(),
            block_doh: true,
            block_dot: true,
        }
    }

    #[test]
    fn install_rules_hijack_and_block_doh() {
        let cfg = test_config();
        let rules = leak_guard_install_argv(&cfg);
        let flat: Vec<String> = rules.iter().flatten().cloned().collect();
        assert!(flat.contains(&"SHADOWPIPE_DNS".to_string()));
        assert!(flat.iter().any(|s| s == "DNAT"));
        assert!(flat.iter().any(|s| s == "853"));
        assert!(flat.iter().any(|s| s == "1.1.1.1"));
    }

    #[test]
    fn dns_chain_lifecycle_stays_in_nat_table_and_in_safe_order() {
        let install = leak_guard_install_argv(&test_config());
        assert_eq!(install[0], argv(&["-t", "nat", "-N", DNS_CHAIN]));
        assert_eq!(install[1], argv(&["-t", "nat", "-F", DNS_CHAIN]));
        assert_eq!(
            install[2],
            argv(&[
                "-t",
                "nat",
                "-A",
                DNS_CHAIN,
                "-p",
                "udp",
                "-j",
                "DNAT",
                "--to-destination",
                "127.0.0.1:1053",
            ])
        );
        assert_eq!(
            install[3],
            argv(&[
                "-t",
                "nat",
                "-A",
                DNS_CHAIN,
                "-p",
                "tcp",
                "-j",
                "DNAT",
                "--to-destination",
                "127.0.0.1:1053",
            ])
        );
        for jump in &install[4..6] {
            assert_eq!(&jump[..2], ["-t", "nat"]);
            assert_eq!(jump[2], "-A");
            assert_eq!(jump[3], "OUTPUT");
            assert_eq!(jump.last().map(String::as_str), Some(DNS_CHAIN));
        }

        let teardown = leak_guard_teardown_argv(true, true);
        for jump in &teardown[..2] {
            assert_eq!(&jump[..2], ["-t", "nat"]);
            assert_eq!(jump[2], "-D");
            assert_eq!(jump[3], "OUTPUT");
            assert_eq!(jump.last().map(String::as_str), Some(DNS_CHAIN));
        }
        assert_eq!(teardown[2], argv(&["-t", "nat", "-F", DNS_CHAIN]));
        assert_eq!(teardown[3], argv(&["-t", "nat", "-X", DNS_CHAIN]));
    }

    #[test]
    fn partial_install_failure_runs_complete_teardown_and_stops_installing() {
        let install = vec![
            argv(&["install-1"]),
            argv(&["install-2"]),
            argv(&["install-must-not-run"]),
        ];
        let teardown = vec![argv(&["rollback-1"]), argv(&["rollback-2"])];
        let mut calls = Vec::new();

        let error = run_install_with_rollback(&install, &teardown, |args| {
            calls.push(args.to_vec());
            match args[0].as_str() {
                "install-2" => anyhow::bail!("synthetic install failure"),
                "rollback-1" => anyhow::bail!("synthetic rollback failure"),
                _ => Ok(()),
            }
        })
        .unwrap_err();

        assert_eq!(
            calls,
            vec![
                argv(&["install-1"]),
                argv(&["install-2"]),
                argv(&["rollback-1"]),
                argv(&["rollback-2"]),
            ]
        );
        let detail = format!("{error:#}");
        assert!(detail.contains("install command 2/3"));
        assert!(detail.contains("1 of 2 rollback commands failed"));
        assert!(detail.contains("synthetic rollback failure"));
        assert!(detail.contains("synthetic install failure"));
    }

    #[test]
    fn successful_install_never_runs_teardown() {
        let install = vec![argv(&["install-1"]), argv(&["install-2"])];
        let teardown = vec![argv(&["rollback-1"]), argv(&["rollback-2"])];
        let mut calls = Vec::new();

        run_install_with_rollback(&install, &teardown, |args| {
            calls.push(args.to_vec());
            Ok(())
        })
        .unwrap();

        assert_eq!(calls, install);
    }

    #[test]
    fn pf_rules_contain_rdr_and_doh() {
        #[cfg(target_os = "macos")]
        {
            let cfg = test_config();
            let path = write_pf_rules(&cfg).expect("pf rules");
            let text = std::fs::read_to_string(path).expect("read");
            assert!(text.contains("rdr pass inet proto udp user > root"));
            assert!(text.contains("1.1.1.1"));
            assert!(text.contains("port 853"));
        }
    }
}
