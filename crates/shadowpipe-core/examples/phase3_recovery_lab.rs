//! Disposable Linux namespace crash/recovery driver for the Phase-3 lab.
//!
//! This is deliberately an example target: production binaries do not compile
//! or expose its SIGKILL checkpoints. The host orchestrator runs it only as
//! root inside a disposable OrbStack clone and a private network+mount
//! namespace. See `tests/host-recovery/run-orbstack-phase3.sh`.

#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{bail, ensure, Context, Result};
    use shadowpipe_core::dns_exchange::{ActiveDnsExchange, PreparedDnsExchange};
    use shadowpipe_core::host_recovery::{
        recover_host_state, HostRecoveryAdapter, PreparedDnsGroup, PreparedHostRecoveryAdapter,
        PreparedLinuxRouteGroup, PreparedResourceGroup, PreparedTunGroup, RecoveryConvergenceError,
        RecoveryRunOutcome,
    };
    use shadowpipe_core::host_state::{
        classify_owner, observe_owner, AddressFamily, BootEvidence, DurableHostJournal,
        FirewallEndpointResource, FirewallResource, HostStateJournalV2, HostStateLease,
        JournalPhase, JournalStore, LeaseEvidence, OperationState, OwnedResource, OwnerDisposition,
        OwnerIdentity, ResourceObservation,
    };
    use shadowpipe_core::netguard::{
        AllowedEndpoint, EndpointProtocol, KillSwitch, KillSwitchIdentity, KillSwitchInstallToken,
        PreparedKillSwitchRecovery,
    };
    use shadowpipe_core::routes::{
        LinuxOwnedRouteSpec, LinuxRouteOwner, LinuxUnderlayPath, RouteGuard,
    };
    use shadowpipe_core::tun_state::{capture_tun_resource, mark_tun_owned};
    use std::fs::{self, File};
    use std::io::Write;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    const JOURNAL_NAME: &str = "host-state-v2.json";
    const LEASE_NAME: &str = "host-state-v2.lock";
    const TUN_NAME: &str = "sp3tun0";
    const ENDPOINT_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 77);
    const RECOVERY_STEPS: usize = 8;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SeedCut {
        Planned,
        AfterApply(usize),
        DnsStaged,
        FirewallAfterIpv4Ack,
        FirewallAfterIpv6Ack,
        FirewallAfterEndpointAck,
        Active,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum RecoveryCut {
        None,
        Before(usize),
        After(usize),
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ExpectedOutcome {
        Recovered,
        Conflict,
    }

    fn parse_seed_cut(value: &str) -> Result<SeedCut> {
        if value == "planned" {
            return Ok(SeedCut::Planned);
        }
        if value == "active" {
            return Ok(SeedCut::Active);
        }
        match value {
            "dns-staged" => return Ok(SeedCut::DnsStaged),
            "firewall-after-ipv4-ack" => return Ok(SeedCut::FirewallAfterIpv4Ack),
            "firewall-after-ipv6-ack" => return Ok(SeedCut::FirewallAfterIpv6Ack),
            "firewall-after-endpoint-ack" => return Ok(SeedCut::FirewallAfterEndpointAck),
            _ => {}
        }
        if let Some(value) = value.strip_prefix("after-apply-") {
            let action = value.parse::<usize>().context("parse seed action")?;
            ensure!((1..=6).contains(&action), "seed action must be 1..=6");
            return Ok(SeedCut::AfterApply(action));
        }
        bail!("unknown seed cut {value:?}")
    }

    fn parse_recovery_cut(value: &str) -> Result<RecoveryCut> {
        if value == "none" {
            return Ok(RecoveryCut::None);
        }
        for (prefix, before) in [("before-step-", true), ("after-step-", false)] {
            if let Some(value) = value.strip_prefix(prefix) {
                let step = value.parse::<usize>().context("parse recovery step")?;
                ensure!(
                    (1..=RECOVERY_STEPS).contains(&step),
                    "recovery step must be 1..={RECOVERY_STEPS}"
                );
                return Ok(if before {
                    RecoveryCut::Before(step)
                } else {
                    RecoveryCut::After(step)
                });
            }
        }
        bail!("unknown recovery cut {value:?}")
    }

    fn parse_expected(value: &str) -> Result<ExpectedOutcome> {
        match value {
            "recovered" => Ok(ExpectedOutcome::Recovered),
            "conflict" => Ok(ExpectedOutcome::Conflict),
            _ => bail!("expected outcome must be recovered or conflict"),
        }
    }

    fn require_distinct_namespace(
        kind: &str,
        current: &Path,
        parent_fd_env: &str,
        expected_parent_fd: i32,
    ) -> Result<()> {
        let observed_fd = std::env::var(parent_fd_env)
            .with_context(|| format!("missing {parent_fd_env}"))?
            .parse::<i32>()
            .with_context(|| format!("parse {parent_fd_env}"))?;
        ensure!(
            observed_fd == expected_parent_fd,
            "unexpected inherited namespace FD for {kind}"
        );
        let parent = PathBuf::from(format!("/proc/self/fd/{expected_parent_fd}"));
        let expected_prefix = format!("{kind}:[");
        for (label, path) in [("current", current), ("parent", parent.as_path())] {
            let target = fs::read_link(path)
                .with_context(|| format!("read {label} {kind} namespace link"))?;
            let target = target.to_string_lossy();
            let inode = target
                .strip_prefix(&expected_prefix)
                .and_then(|value| value.strip_suffix(']'))
                .context("namespace descriptor has an unexpected type or shape")?;
            ensure!(
                !inode.is_empty()
                    && inode.bytes().all(|byte| byte.is_ascii_digit())
                    && inode != "0",
                "namespace descriptor has an invalid inode"
            );
        }
        let current_metadata =
            fs::metadata(current).with_context(|| format!("stat current {kind} namespace"))?;
        let parent_metadata = fs::metadata(&parent)
            .with_context(|| format!("stat inherited parent {kind} namespace"))?;
        ensure!(
            (current_metadata.dev(), current_metadata.ino())
                != (parent_metadata.dev(), parent_metadata.ino()),
            "Phase-3 helper refused the clone root {kind} namespace"
        );
        Ok(())
    }

    fn require_private_lab() -> Result<()> {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "Phase-3 helper requires root"
        );
        ensure!(
            std::env::var_os("SHADOWPIPE_PHASE3_GUEST").as_deref()
                == Some(std::ffi::OsStr::new("1")),
            "missing disposable-guest attestation"
        );
        ensure!(
            std::env::var_os("SHADOWPIPE_PHASE3_PRIVATE_NS").as_deref()
                == Some(std::ffi::OsStr::new("1")),
            "missing private namespace attestation"
        );
        ensure!(
            Path::new("/proc/thread-self/ns/net").exists(),
            "network namespace unavailable"
        );
        ensure!(
            Path::new("/proc/thread-self/ns/mnt").exists(),
            "mount namespace unavailable"
        );
        require_distinct_namespace(
            "net",
            Path::new("/proc/thread-self/ns/net"),
            "SHADOWPIPE_PHASE3_PARENT_NETNS_FD",
            7,
        )?;
        require_distinct_namespace(
            "mnt",
            Path::new("/proc/thread-self/ns/mnt"),
            "SHADOWPIPE_PHASE3_PARENT_MNTNS_FD",
            8,
        )?;
        Ok(())
    }

    fn sync_parent(path: &Path) -> Result<()> {
        let parent = path.parent().context("marker has no parent")?;
        File::open(parent)
            .with_context(|| format!("open marker parent {}", parent.display()))?
            .sync_all()
            .with_context(|| format!("fsync marker parent {}", parent.display()))
    }

    fn crash(marker: &Path, label: &str) -> ! {
        let result = (|| -> Result<()> {
            let mut file = File::create(marker)
                .with_context(|| format!("create crash marker {}", marker.display()))?;
            writeln!(file, "checkpoint={label}")?;
            writeln!(file, "pid={}", std::process::id())?;
            file.sync_all()?;
            sync_parent(marker)
        })();
        if let Err(error) = result {
            eprintln!("could not persist crash marker: {error:#}");
            std::process::abort();
        }
        eprintln!("PHASE3_CHECKPOINT {label}");
        let _ = std::io::stderr().flush();
        // SAFETY: kill targets this process and SIGKILL has no user handler.
        let status = unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
        if status != 0 {
            std::process::abort();
        }
        unreachable!("SIGKILL returned without terminating the process")
    }

    fn create_nonpersistent_tun() -> Result<tun::Device> {
        let mut configuration = tun::Configuration::default();
        configuration.tun_name(TUN_NAME).up();
        tun::create(&configuration).context("create production-shaped non-persistent Phase-3 TUN")
    }

    fn maybe_crash_after_apply(cut: SeedCut, action: usize, marker: &Path, label: &str) {
        if cut == SeedCut::AfterApply(action) {
            crash(marker, label);
        }
    }

    fn seed(state_dir: &Path, resolver: &Path, cut: SeedCut, marker: &Path) -> Result<()> {
        fs::create_dir_all(state_dir)
            .with_context(|| format!("create state directory {}", state_dir.display()))?;
        let store = JournalStore::new(state_dir.join(JOURNAL_NAME));
        let _lease = HostStateLease::try_acquire(state_dir.join(LEASE_NAME))
            .context("acquire seed host-state lease")?;
        let owner = OwnerIdentity::capture().context("capture seed owner identity")?;
        let session = owner.session_id;

        // TUN ifindex is allocated by the kernel, so the lab creates it before
        // forming the exact durable resource. Keep its exact descriptor alive
        // until SIGKILL, matching the production non-persistent lifecycle: the
        // kernel removes the interface when the killed process closes its last
        // FD. Recovery must prove absence rather than delete by reusable index.
        let tun_device = create_nonpersistent_tun()?;
        let tun_resource = capture_tun_resource(TUN_NAME).context("capture exact TUN identity")?;

        let prepared_dns = PreparedDnsExchange::stage_unnamed(
            resolver,
            session,
            b"# Phase-3 private resolver\nnameserver 100.64.0.53\n",
        )
        .context("prepare private resolver exchange")?;
        let dns_resource = prepared_dns.resource().clone();

        let route_owner = LinuxRouteOwner::for_session(session);
        let route_zero =
            LinuxOwnedRouteSpec::split_default(Ipv4Addr::UNSPECIFIED, TUN_NAME, route_owner)?;
        let route_high =
            LinuxOwnedRouteSpec::split_default(Ipv4Addr::new(128, 0, 0, 0), TUN_NAME, route_owner)?;
        let route_zero_resource = route_zero.journal_resource()?;
        let route_high_resource = route_high.journal_resource()?;
        let underlay = LinuxUnderlayPath::capture(ENDPOINT_IP)
            .context("capture private-lab underlay path before split-default routes")?;
        let endpoint_route = underlay
            .owned_bypass_spec(ENDPOINT_IP, route_owner)
            .context("derive journaled private-lab endpoint bypass")?;
        let endpoint_route_resource = endpoint_route.journal_resource()?;

        let firewall_install = KillSwitchInstallToken::prepare_runtime_for_session(session)
            .context("capture firewall backend, table lifecycle and fresh chain tokens")?;
        let firewall_identity = firewall_install.identity();
        let endpoint = AllowedEndpoint {
            address: SocketAddrV4::new(ENDPOINT_IP, 443),
            protocol: EndpointProtocol::Tcp,
        };
        let endpoint_resource = firewall_identity.endpoint_journal_resource(endpoint);
        let [firewall_v4, firewall_v6] = firewall_install.journal_resources();

        let resources = vec![
            OwnedResource::Tun(tun_resource.clone()),
            OwnedResource::Route(route_zero_resource.clone()),
            OwnedResource::Route(route_high_resource.clone()),
            OwnedResource::Route(endpoint_route_resource.clone()),
            OwnedResource::Dns(dns_resource),
            OwnedResource::Firewall(firewall_v4),
            OwnedResource::Firewall(firewall_v6),
            OwnedResource::FirewallEndpoint(endpoint_resource),
        ];
        let mut durable = DurableHostJournal::create(store, owner)?;
        let ids = durable.begin_add_batch(resources)?;
        ensure!(ids.len() == RECOVERY_STEPS, "unexpected operation count");
        if cut == SeedCut::Planned {
            crash(marker, "wal-planned-before-host-ownership");
        }

        mark_tun_owned(&tun_resource, session).context("mark exact TUN ownership")?;
        maybe_crash_after_apply(cut, 1, marker, "tun-applied-before-wal-ack");
        durable.acknowledge_add(ids[0])?;

        let mut route_guards = Vec::<RouteGuard>::with_capacity(3);
        route_guards.push(RouteGuard::install_linux_owned_journaled(
            &route_zero,
            &route_zero_resource,
        )?);
        maybe_crash_after_apply(cut, 2, marker, "route-zero-applied-before-wal-ack");
        durable.acknowledge_add(ids[1])?;

        route_guards.push(RouteGuard::install_linux_owned_journaled(
            &route_high,
            &route_high_resource,
        )?);
        maybe_crash_after_apply(cut, 3, marker, "route-high-applied-before-wal-ack");
        durable.acknowledge_add(ids[2])?;

        route_guards.push(RouteGuard::install_linux_owned_journaled(
            &endpoint_route,
            &endpoint_route_resource,
        )?);
        maybe_crash_after_apply(cut, 4, marker, "endpoint-bypass-applied-before-wal-ack");
        durable.acknowledge_add(ids[3])?;

        let linked_dns = prepared_dns
            .link_after_journal()
            .context("link journaled private resolver inode")?;
        if cut == SeedCut::DnsStaged {
            crash(marker, "dns-staged-after-link-before-rename-exchange");
        }
        let active_dns: ActiveDnsExchange = linked_dns
            .activate_after_journal()
            .context("activate private resolver exchange")?;
        maybe_crash_after_apply(cut, 5, marker, "dns-applied-before-wal-ack");
        durable.acknowledge_add(ids[4])?;

        let firewall = KillSwitch::engage_preflighted(TUN_NAME, &[endpoint], firewall_install)
            .context("engage journaled IPv4/IPv6 firewall")?;
        maybe_crash_after_apply(cut, 6, marker, "firewall-bundle-applied-before-wal-ack");
        durable.acknowledge_add(ids[5])?;
        if cut == SeedCut::FirewallAfterIpv4Ack {
            crash(marker, "firewall-ipv4-applied-ipv6-endpoint-planned");
        }
        durable.acknowledge_add(ids[6])?;
        if cut == SeedCut::FirewallAfterIpv6Ack {
            crash(marker, "firewall-bases-applied-before-endpoint-wal-ack");
        }
        durable.acknowledge_add(ids[7])?;
        if cut == SeedCut::FirewallAfterEndpointAck {
            crash(marker, "all-resources-applied-before-active-publication");
        }
        durable.publish_active()?;

        // Make guard ownership visibly live until SIGKILL; normal unwinding is
        // intentionally not a crash simulation.
        std::hint::black_box(&route_guards);
        std::hint::black_box(&active_dns);
        std::hint::black_box(&firewall);
        std::hint::black_box(&tun_device);
        match cut {
            SeedCut::Active => crash(marker, "active-after-all-wal-acks"),
            SeedCut::Planned
            | SeedCut::AfterApply(_)
            | SeedCut::DnsStaged
            | SeedCut::FirewallAfterIpv4Ack
            | SeedCut::FirewallAfterIpv6Ack
            | SeedCut::FirewallAfterEndpointAck => {
                bail!("requested seed cut was not reached")
            }
        }
    }

    fn all_firewall_identity(journal: &HostStateJournalV2) -> Result<(KillSwitchIdentity, String)> {
        let mut ipv4 = None::<FirewallResource>;
        let mut ipv6 = None::<FirewallResource>;
        let mut tun_name = None::<String>;
        for operation in &journal.operations {
            match &operation.resource {
                OwnedResource::Firewall(resource) => match resource.family {
                    AddressFamily::Ipv4 => ipv4 = Some(resource.clone()),
                    AddressFamily::Ipv6 => ipv6 = Some(resource.clone()),
                },
                OwnedResource::Tun(resource) => {
                    tun_name = Some(resource.interface.name.clone());
                }
                _ => {}
            }
        }
        let ipv4 = ipv4.context("journal has no IPv4 firewall identity")?;
        let ipv6 = ipv6.context("journal has no IPv6 firewall identity")?;
        ensure!(
            ipv4.backend == ipv6.backend,
            "firewall backend mismatch in journal"
        );
        let identity = KillSwitchIdentity::from_parts(
            journal.owner.session_id,
            ipv4.chain_token,
            ipv6.chain_token,
            ipv4.backend,
        )?;
        Ok((identity, tun_name.context("journal has no TUN interface")?))
    }

    fn prepared_adapter(
        journal: &HostStateJournalV2,
        resolver: &Path,
        same_boot: bool,
    ) -> Result<PreparedHostRecoveryAdapter> {
        let mut routes = Vec::new();
        let mut dns = Vec::new();
        let mut tuns = Vec::new();
        let mut firewall_bases = Vec::<FirewallResource>::new();
        let mut firewall_endpoints = Vec::<FirewallEndpointResource>::new();
        for operation in journal
            .operations
            .iter()
            .filter(|operation| operation.state != OperationState::Removed)
        {
            match &operation.resource {
                OwnedResource::Route(resource) => routes.push(resource.clone()),
                OwnedResource::Dns(resource) => dns.push(resource.clone()),
                OwnedResource::Tun(resource) => tuns.push(resource.clone()),
                OwnedResource::Firewall(resource) => firewall_bases.push(resource.clone()),
                OwnedResource::FirewallEndpoint(resource) => {
                    firewall_endpoints.push(resource.clone())
                }
            }
        }

        let mut groups: Vec<Box<dyn PreparedResourceGroup>> = Vec::new();
        if !routes.is_empty() {
            let namespace = journal
                .owner
                .network_namespace
                .context("journal lacks network namespace identity")?;
            groups.push(Box::new(
                PreparedLinuxRouteGroup::prepare(
                    journal.owner.session_id,
                    namespace,
                    &routes,
                    same_boot,
                )
                .context("prepare route recovery group")?,
            ));
        }
        for resource in dns {
            groups.push(Box::new(
                PreparedDnsGroup::prepare(resolver, journal.owner.session_id, resource)
                    .context("prepare DNS recovery group")?,
            ));
        }
        for resource in tuns {
            groups.push(Box::new(
                PreparedTunGroup::prepare(resource, journal.owner.session_id, same_boot)
                    .context("prepare TUN recovery group")?,
            ));
        }
        if !firewall_bases.is_empty() || !firewall_endpoints.is_empty() {
            let (identity, tun_name) = all_firewall_identity(journal)?;
            groups.push(Box::new(
                PreparedKillSwitchRecovery::prepare_for_boot(
                    &tun_name,
                    identity,
                    &firewall_bases,
                    &firewall_endpoints,
                    same_boot,
                )
                .context("prepare firewall recovery group")?,
            ));
        }
        PreparedHostRecoveryAdapter::new(journal, groups)
            .context("compose all-resource recovery adapter")
    }

    struct CuttingAdapter {
        inner: PreparedHostRecoveryAdapter,
        cut: RecoveryCut,
        marker: PathBuf,
        step: usize,
    }

    impl HostRecoveryAdapter for CuttingAdapter {
        fn inspect_all(
            &mut self,
            journal: &HostStateJournalV2,
        ) -> Result<Vec<ResourceObservation>> {
            self.inner.inspect_all(journal)
        }

        fn converge_absent(
            &mut self,
            resource: &OwnedResource,
        ) -> std::result::Result<(), RecoveryConvergenceError> {
            self.step += 1;
            if self.cut == RecoveryCut::Before(self.step) {
                crash(
                    &self.marker,
                    &format!("cleaning-before-converge-step-{}-{resource:?}", self.step),
                );
            }
            let result = self.inner.converge_absent(resource);
            if result.is_ok() && self.cut == RecoveryCut::After(self.step) {
                crash(
                    &self.marker,
                    &format!(
                        "cleaning-after-converge-before-wal-ack-step-{}-{resource:?}",
                        self.step
                    ),
                );
            }
            result
        }
    }

    fn recover(
        state_dir: &Path,
        resolver: &Path,
        cut: RecoveryCut,
        expected: ExpectedOutcome,
        marker: &Path,
    ) -> Result<()> {
        let store = JournalStore::new(state_dir.join(JOURNAL_NAME));
        let _lease = HostStateLease::try_acquire(state_dir.join(LEASE_NAME))
            .context("acquire recovery host-state lease")?;
        let mut durable = DurableHostJournal::load(store).context("load stale host journal")?;
        let evidence = observe_owner(&durable.journal().owner, LeaseEvidence::Available);
        let disposition = classify_owner(evidence);
        ensure!(
            disposition == OwnerDisposition::Stale,
            "crashed owner is not provably stale: {evidence:?}"
        );
        let same_boot = evidence.boot == BootEvidence::Same;
        let snapshot = durable.journal().clone();
        let inner = prepared_adapter(&snapshot, resolver, same_boot)?;
        let mut adapter = CuttingAdapter {
            inner,
            cut,
            marker: marker.to_path_buf(),
            step: 0,
        };
        let outcome = recover_host_state(&mut durable, disposition, &mut adapter)
            .context("execute all-resource host recovery")?;
        println!("owner_evidence={evidence:?}");
        println!("outcome={outcome:?}");
        println!("convergence_calls={}", adapter.step);

        match (expected, outcome) {
            (ExpectedOutcome::Recovered, RecoveryRunOutcome::Recovered { removed_records }) => {
                ensure!(
                    removed_records <= RECOVERY_STEPS,
                    "removed record count exceeds journal vocabulary"
                );
                ensure!(
                    !state_dir.join(JOURNAL_NAME).exists(),
                    "successful recovery retained journal"
                );
            }
            (ExpectedOutcome::Conflict, RecoveryRunOutcome::Refused(refusal)) => {
                ensure!(
                    durable.journal().phase == JournalPhase::Conflict,
                    "refusal was not durably marked Conflict: {refusal:?}"
                );
                ensure!(
                    state_dir.join(JOURNAL_NAME).exists(),
                    "Conflict journal unexpectedly disappeared"
                );
            }
            (expected, actual) => {
                bail!("expected {expected:?}, observed {actual:?}")
            }
        }
        Ok(())
    }

    fn usage() -> ! {
        eprintln!(
            "{}",
            "usage:\n  phase3_recovery_lab seed STATE_DIR RESOLVER \\\n              (planned|after-apply-1..5|dns-staged|firewall-after-ipv4-ack|firewall-after-ipv6-ack|firewall-after-endpoint-ack|active) MARKER\n  \\
             phase3_recovery_lab recover STATE_DIR RESOLVER \\
             (none|before-step-1..7|after-step-1..7) \\
             (recovered|conflict) MARKER"
                .replace("after-apply-1..5", "after-apply-1..6")
                .replace("before-step-1..7", "before-step-1..8")
                .replace("after-step-1..7", "after-step-1..8")
        );
        std::process::exit(64)
    }

    pub fn run() -> Result<()> {
        require_private_lab()?;
        let arguments: Vec<_> = std::env::args_os().skip(1).collect();
        if arguments.len() != 5 {
            usage();
        }
        let mode = arguments[0].to_string_lossy();
        let state_dir = PathBuf::from(&arguments[1]);
        let resolver = PathBuf::from(&arguments[2]);
        let marker_or_cut = arguments[3].to_string_lossy();
        let final_argument = PathBuf::from(&arguments[4]);
        match mode.as_ref() {
            "seed" => seed(
                &state_dir,
                &resolver,
                parse_seed_cut(&marker_or_cut)?,
                &final_argument,
            ),
            "recover" => {
                // Recover has six logical arguments after the program, so the
                // compact parser above cannot represent it. Keep the usage
                // error explicit instead of silently shifting arguments.
                usage()
            }
            _ => usage(),
        }
    }

    pub fn run_recover() -> Result<()> {
        require_private_lab()?;
        let arguments: Vec<_> = std::env::args_os().skip(1).collect();
        if arguments.len() != 6 || arguments[0] != "recover" {
            return run();
        }
        recover(
            Path::new(&arguments[1]),
            Path::new(&arguments[2]),
            parse_recovery_cut(&arguments[3].to_string_lossy())?,
            parse_expected(&arguments[4].to_string_lossy())?,
            Path::new(&arguments[5]),
        )
    }
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    linux::run_recover()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("phase3_recovery_lab is Linux-only and must run in a disposable private namespace");
    std::process::exit(69);
}
