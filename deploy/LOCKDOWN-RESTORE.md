# Early-boot restart lockdown

`shadowpipe-client` normally leaves `handoff-lockdown-v1.json` and its exact
native-nft `inet`/`output` barrier active across a service stop. A reboot flushes
the kernel ruleset, so the WAL must be replayed before the host network stack is
allowed to start.

> **Do not start or enable this unit from a remote SSH session.** If an owned
> WAL exists, the command intentionally removes every pre-reboot SSH exception
> and can strand the host immediately. Provision and test from a VM/VPS console.

The unit requires systemd 254 or newer (`RestartMode=direct`). It retries a
bounded 20-second restore at most three times while keeping hard
`Requires+After` dependents waiting. The total-attempt limit is three (an
infinite start-limit interval prevents old attempts aging out); exhaustion
isolates `emergency.target`.
Manual stop is refused and there is intentionally no `ExecStop`.

Install the files first, without enabling or starting either service:

```sh
sudo install -m 0755 target/release/shadowpipe-client /usr/local/bin/shadowpipe-client
sudo install -d -o root -g root -m 0700 /var/lib/shadowpipe
sudo install -m 0644 deploy/shadowpipe-lockdown-restore.service \
  /etc/systemd/system/shadowpipe-lockdown-restore.service
sudo systemctl daemon-reload
test "$(systemd --version | awk 'NR==1 {print $2}')" -ge 254
```

The enabled unit is a requirement of `sysinit.target`, runs after local filesystems
but before both `sysinit.target` and `network-pre.target`. It pulls in the
otherwise-passive `network-pre.target`.

Enabling also installs reverse `Requires=` edges from the common Linux network
managers (`systemd-networkd`, NetworkManager, ifupdown `networking`, iwd,
wpa_supplicant, and dhcpcd), while `Before=` supplies ordering. Audit the actual
machine and add the same `Requires=/After=shadowpipe-lockdown-restore.service`
drop-in to any custom link/address manager not in that list. `network-pre.target`
alone is passive and is not a sufficient failure gate.

`--restore-lockdown` is a no-network, no-main-recovery operation. Under the same
singleton host lease as the client, it:

1. treats any possible `host-state-v2.json` entry as reason to protect;
2. adopts/replays an existing barrier WAL or creates one for a possible main WAL;
3. on a new boot, creates a fresh table identity and discards the previous boot's
   SSH exception;
4. re-inspects the full table/rule census and kernel handle, requiring durable
   `Active` state;
5. exits without policy reads, resolver calls, sockets, TUNs, routes, DNS changes,
   main-journal recovery, or barrier release.

When neither WAL exists, the early-boot command is a no-op so an explicitly
released/direct host is not unexpectedly locked down on its next boot.

## Required underlay and replacement service

The early-boot barrier intentionally allows only loopback at the Linux `inet
output` (L3 local-output) hook. It discards a prior boot's SSH tuple and does
**not** allow ordinary IPv4/IPv6 DNS, NTP, DHCPv6, or a new SSH connection.
There is no remote-SSH recovery path while this barrier is holding; use the
VM/VPS console for recovery.

This is not a zero-frame L2 barrier. AF_PACKET/link-layer traffic bypasses
`NF_INET_LOCAL_OUT`: ARP and some clients' initial DHCPv4 frames can still leave
an interface. Strict suppression of those frames requires a separately designed
and verified per-interface nft `netdev` egress or tc-BPF layer. Until that exists,
use a static/preconfigured IPv4 underlay, disable DHCP, and describe the guarantee
as fail-closed L3 egress continuity rather than universal packet silence.
The `output` hook also does not cover forwarded traffic from containers or other
network namespaces. Reboot-safe scope therefore excludes routed/bridged guests
unless a separately verified forward/netdev barrier protects every such path.

The full-tunnel client must be enabled for automatic startup on the same boot.
Order it after the service that applies the static interface/routes, require
`shadowpipe-lockdown-restore.service`, and start it before workloads that need
`network-online.target`. Its endpoint authority must be a signed policy with
literal IPv4 seeds (or a manual numeric `A.B.C.D:PORT`). The client installs and
durably verifies its complete main kill-switch, TUN, endpoint bypasses, two `/1`
routes, and DNS exchange; it then releases the early barrier before its first
carrier dial. A hostname-only manual configuration is deliberately rejected.

Do not enable this early-boot unit on a DHCP-only machine. Either provision a
static underlay plus an auto-start replacement client first, or accept that the
console will be required to repair networking.

Shadowpipe must be the exclusive firewall/ruleset owner. A later nftables,
firewalld, ufw, iptables, or ip6tables loader can execute `flush ruleset` and
erase a verified barrier. Unit `Conflicts=` is not sufficient: starting the
other unit may indirectly stop the restore service first. From the console,
mask every incompatible loader before enabling the gate:

```sh
sudo systemctl mask --now nftables.service firewalld.service ufw.service \
  iptables.service ip6tables.service
systemctl is-enabled nftables firewalld ufw iptables ip6tables 2>/dev/null || true
```

The expected result for every installed loader is `masked`. Do not run cron
jobs, configuration agents, or custom units that flush/replace nftables behind
the client. Rollback, only after an intentional `--release-lockdown`, is:

```sh
sudo systemctl unmask nftables.service firewalld.service ufw.service \
  iptables.service ip6tables.service
```

The guarantee starts in the real root filesystem. It does not cover an initrd or
initramfs that brings up networking before switch-root. Disable initrd networking
and remote-unlock networking, or install and independently verify an equivalent
lockdown hook inside that initrd. Do not claim reboot leak protection until the
actual initrd and boot dependency graph have been audited.

A generic paired unit and environment template are included. Fill the template
with the real signed-policy paths/keys and install it while still on the console:

```sh
sudo install -d -o root -g root -m 0700 /etc/shadowpipe
# Generate only on this client. Transfer enrollment JSON to the server over an
# authenticated channel; never transfer client-credential.json.
sudo shadowpipe-client --generate-client-credential \
  --client-credential /etc/shadowpipe/client-credential.json \
  --write-client-enrollment /root/shadowpipe-client-enrollment.json
sudo install -m 0600 deploy/shadowpipe-client.env.example /etc/shadowpipe/client.env
sudo install -m 0644 deploy/shadowpipe-client-full-tunnel.service \
  /etc/systemd/system/shadowpipe-client-full-tunnel.service
sudo systemctl daemon-reload
```

The server commits that artifact with `shadowpipe-server --enroll-client PATH
--client-allowlist /etc/shadowpipe/client-allowlist.json`, validates it with
`--validate-client-allowlist`, and passes the same allowlist on every daemon
start. Delete the transported enrollment after validation. Client credential
and server allowlist remain root-owned, single-link regular files with exact
mode `0600`; missing, empty, malformed, unsafe, unknown, or revoked identity
fails before session startup. Neither private seed nor PSK belongs in this
EnvironmentFile, an endpoint URI, argv, journal, or logs.

The paired unit requires the restore gate, starts after locally configured
`network.target`, restarts indefinitely on invalid/unavailable replacement
state, and sends SIGTERM with a 90-second cleanup budget. It does not configure
the static underlay; that remains an explicit machine-specific prerequisite.

## First activation, then enable the reboot gate

This mechanism preserves fail-closed continuity after an owned WAL has been
created; it is not first-boot always-on enforcement. With neither WAL present,
`--restore-lockdown` deliberately does nothing. A broken paired-client config on
that fresh host can therefore loop while ordinary direct networking still
exists.

Before enabling the boot gate, perform one successful console-supervised
full-tunnel activation. On a fresh policy store, run the same fully expanded
arguments as `SHADOWPIPE_CLIENT_ARGS` once with `--policy-enroll`. Wait until the
logs confirm the complete main host state and carrier are active, then send
SIGTERM/Ctrl-C. Normal teardown will leave the independent lockdown WAL/table
active. Remove `--policy-enroll` from every normal-start configuration.

Only after that successful activation and the static-underlay/firewall-manager
checks above:

```sh
sudo systemctl enable shadowpipe-lockdown-restore.service
sudo systemctl enable shadowpipe-client-full-tunnel.service
# Prefer a console-observed reboot test. Do not run the next command over SSH.
sudo systemctl reboot
```

Before deployment, verify the real boot graph:

```sh
sudo systemd-analyze verify /etc/systemd/system/shadowpipe-lockdown-restore.service
systemctl list-dependencies --reverse shadowpipe-lockdown-restore.service
systemd-analyze critical-chain network-pre.target
systemctl is-enabled nftables firewalld ufw iptables ip6tables 2>/dev/null || true
```

Never use `--release-lockdown` in this unit. That one-shot is reserved for an
operator who intentionally wants direct networking: it first arms the barrier,
recovers the complete ordinary main journal, proves that WAL absent, and only
then deletes the barrier.
