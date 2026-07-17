# VDSina NL Linux Alpha deployment — 2026-07-17

## Outcome

The deployed server binary was built from Rust source baseline
`9cc8dc3a32f8469c76d59dd6054f4b745cc0d8a2` for Linux x86_64 GNU and installed
as a bounded Shadowpipe server on the existing VDSina NL host.  This is an
Alpha endpoint for the first
current-source paired Linux test; it is not a production or field-resistance
claim.

Server deployment:

- public endpoint: `91.201.114.192:24443/TCP`;
- carrier: mandatory-v3 REALITY/TCP;
- cover: `www.microsoft.com:443`;
- egress: `ens3`;
- server TUN: `shadowpipe0`, `10.8.0.1` with peer `10.8.0.2`;
- explicit client IPv6 policy for the test bundle: block;
- installed server binary SHA-256:
  `17ac94e4f9c6b2c4a5aeb568259eb749edab5ab7454cf378d30849443555c370`;
- paired Linux x86_64 client SHA-256:
  `e9bdfa93a275ecedcf041c252bc8a121986a10465ca68f27e5167aa43324b013`;
- both artifacts use explicit wire magic `0x53504731` and require glibc 2.28
  or newer.

The existing Xray listener on `47843/TCP`, Hysteria2 on `36712/UDP`,
AmneziaWG, Mieru and SSH were not reconfigured or restarted.  `24443/TCP` was
selected because it was free and below the host ephemeral port range.  The
installer made only its documented forwarding sysctl, scoped TUN/NAT/FORWARD,
binary, identity, allowlist and systemd changes.

## Preservation and secret handling

Before activation, the legacy May Shadowpipe binaries, private identity
directory and complete iptables/nft state were copied to the root-only server
directory:

```text
/root/shadowpipe-preinstall-20260717T062850Z
```

The fresh client credential was generated on the client/provisioning side,
not on the VPS.  Only the one-time enrollment crossed to the server.  The
server consumed that file after allowlist commit.  The root-only bootstrap URI
was copied back into the private local bundle and then removed from the VPS.
No credential, PSK, REALITY short ID or complete URI is stored in this document
or in Git.

The transferable bundle is outside the repository:

```text
/Users/billy/shadowpipe/
  bin/shadowpipe-client
  config/client-credential.json
  config/endpoint.uri
  install.sh
  run-tun-only.sh
  run-full-tunnel.sh
  release-lockdown.sh
  verify.sh
  README.md
```

It is user-owned staging on the Mac.  `install.sh` verifies the fixed client
digest, glibc/TUN/firewall prerequisites and private-file metadata, constructs
the complete active tree in a root-owned same-filesystem staging directory, and
publishes it atomically as `/root/shadowpipe`.  It refuses to mix this Alpha
bundle with an existing active tree and removes the credential and URI copies
from a successful `/home/...` staging transfer.  A normal user-owned home path
is not used at runtime because the production loaders require trusted
root-owned ancestors, exact `0600` single-link files and effective UID 0.

## Checks completed

- Ubuntu 24.04 x86_64, systemd 255, `/dev/net/tun`, `ens3`, free subnet and
  port were verified immediately before install.
- Current GNU server/client release builds passed offline; repository remained
  clean before the deployment-specific fixes below.
- Service is enabled and active, owns `shadowpipe0`, and listens once on
  `24443/TCP`.
- Allowlist is non-empty and validated; replay store and lock are root-owned
  `0600`.
- A normal unauthenticated TLS 1.3 ClientHello to the endpoint was forwarded to
  the real cover and returned the valid `www.microsoft.com` certificate.
- That probe produced zero authenticated Shadowpipe sessions.
- Xray remained active with the same server PID and the Hysteria2 UDP listener
  remained present during deployment verification.
- The portable bundle scripts pass `bash -n` and ShellCheck; private config is
  `0600` and the Linux binary digest matches the installed server-side build
  pair.
- A disposable OrbStack Ubuntu 24.04 x86_64 VM completed the atomic client
  install, verified root-only metadata and the pinned binary digest, refused a
  second mixed install, and showed no Shadowpipe TUN or owned firewall rules
  before client start.  The VM and its copied credential were then deleted.

Two deploy defects were found by the real host and fixed in source:

1. The old Bash advertise regex rejected a valid IPv4 `host:port` on Ubuntu.
   It now accepts only the implemented hostname/IPv4 carrier form, validates
   ports and IPv4 octets, and rejects bracketed IPv6 in all three deploy entry
   points.
2. `cleanup_owned_temps` could return 1 after a committed install under
   `set -e`, preventing bootstrap export while leaving the healthy service
   active.  It now tolerates individual removal failures, explicitly returns
   0, and the idempotent retry completed.

Post-deploy review also restricted bootstrap advertisement to the actually
implemented IPv4 carrier plane, enforced ports `1..65535`, required root-owned
single-link non-writable server input binaries, removed the implicit production
wire-magic fallback, delegated rebuild decisions to Cargo fingerprints, and
made the portable Linux client publication atomic.  These are source/bundle
hardening fixes; they are not additional live-host failure claims.

## Mac safety observation

No command in this deployment stopped, started, signalled or reconfigured the
Mac sing-box process, and no Mac route, DNS, PF, TUN or NetworkExtension
mutation was issued.  The user confirmed that the two observed sing-box
restarts were intentional manual actions: one at `2026-07-17 09:33:16 MSK` and
one at `09:43:27 MSK`.  The later read-only snapshot showed PID `6427` with the
same exact argv, started after the current validated config had been written;
default route remained `192.168.0.1` on `en0`, DNS remained `8.8.8.8`, and the
observed exit remained the NL server.

Those intentional restarts mean this run still must not be cited as an
unchanged-process proof across the complete interval.  They are no longer an
unexplained safety anomaly and were not caused by a deployment command.

## What remains before a stronger claim

1. Transfer the bundle to a console-accessible Linux x86_64 machine and run
   TUN-only, then the exact-route/DNS/firewall/ICMP/HTTPS/64 MiB/IPv6-block
   full-tunnel smoke.  Explicit UDP and upload evidence remain separate.
2. Exercise carrier stop/start and client reconnect while proving no direct
   fallback, then run explicit lockdown release.
3. Rebuild and rerun current-source ARM64 portability if that is the client
   architecture.
4. Fix the current x86_64-musl build (`libc::statx` portability); current
   deliverables are glibc 2.28+ GNU binaries.
5. Add owned reboot-persistent NAT/FORWARD restoration.  The current installer
   writes persistent forwarding sysctls but its three iptables rules are
   runtime-only; do not reboot the VDS before this is fixed or revalidated.
6. Provision signed endpoint-policy artifacts before enabling the permanent
   client systemd units.  The bootstrap URI is a manual Alpha diagnostic.
7. Harden the unrestricted-root server unit, add an uninstall transaction,
   validate inner IPv4 source ownership, and remove the current single-active-
   tunnel limitation before any multi-user claim.

## Client sequence

Transfer from the Mac into a fresh versioned staging directory:

```bash
scp -r ~/shadowpipe USER@LINUX:~/shadowpipe-nl-20260717
```

On the separate Linux machine:

```bash
cd ~/shadowpipe-nl-20260717
sudo ./install.sh
sudo /root/shadowpipe/run-tun-only.sh
```

After the TUN-only check and `Ctrl-C`, from a local/VM console, not SSH:

```bash
sudo /root/shadowpipe/run-full-tunnel.sh
```

In a second terminal:

```bash
sudo /root/shadowpipe/verify.sh
```

After `Ctrl-C`, explicitly restore direct networking:

```bash
sudo /root/shadowpipe/release-lockdown.sh
```

This manual Alpha bundle is a one-session test and does not install the
early-boot restore/full-tunnel units.  Stop and explicitly release lockdown
before rebooting the client machine.
