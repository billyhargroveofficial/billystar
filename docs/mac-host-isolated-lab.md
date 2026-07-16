# Host-safe VPN laboratory on macOS

Snapshot: 2026-07-16.

## Verdict

A privileged full-tunnel client cannot be safely isolated from the working
macOS network stack with `sandbox-exec` or App Sandbox. Those mechanisms limit
process capabilities; they do not create an independent Darwin routing table,
DNS configuration, PF instance, TUN namespace, or Network Extension control
plane.

Therefore:

- the working Mac may run builds, unit/property tests, packet-engine
  simulations, loopback tests and read-only safety observers;
- Linux TUN, route, DNS and firewall tests belong in a dedicated Linux virtual
  machine and then in private Linux network namespaces;
- a native macOS packet-tunnel client must be tested in a separate macOS VM or
  on another physical Mac.

The live host sing-box process, its configuration, routes, DNS, PF and TUN
interfaces are outside the Shadowpipe lab authority.

## Recommended topology

```text
working macOS
  |
  +-- live sing-box                       immutable lab dependency
  +-- unprivileged build/observer         no host network mutation
  |
  +-- isolated OrbStack Linux machine
  |     +-- client netns
  |     +-- router/censor netns
  |     +-- Linux production-server netns
  |     `-- sink/cover netns
  |
  +-- Parallels Windows VM                Wintun/WFP client tests
  `-- Parallels macOS ARM VM              Network Extension client tests
```

The Linux topology needs no public Internet for its correctness and leak
matrix. All endpoints can remain inside one disposable VM kernel. Failure of
the client can then damage only its owned namespace or disposable VM.

## Linux boundary

Use an OrbStack machine created as isolated and network-isolated. OrbStack
documents that an isolated machine does not mount the Mac, cannot access the
host, and receives no host SSH agent; network isolation additionally separates
it from the host and other OrbStack machines:

- <https://docs.orbstack.dev/machines/isolated>
- <https://docs.orbstack.dev/architecture>

Inside that VM:

1. require a root-owned lab identity file with an expected random UUID;
2. permit the guest-root orchestrator to create identity-bound namespaces and
   veth pairs, but require every client/server/listener/workload and every
   TUN, route, DNS or firewall mutation to run outside the PID 1 network
   namespace;
3. leave no lab listener, route, TUN or firewall object in the guest-root
   namespace;
4. use a guest-local checkout at a pinned pushed commit, transferred only
   through explicit OrbStack push/pull;
5. keep build output, credentials and raw evidence guest-local;
6. bound endpoints, bytes, rate and wall-clock duration;
7. destroy or revert the disposable machine after the run.

The current `arch` source machine is not an isolated OrbStack machine. Its
clone-plus-netns harness protects the host routing plane, but it is not the
strongest available filesystem/integration boundary. A dedicated isolated
base should replace it before unattended privileged testing is treated as the
normal gate. Until then it is a legacy integrated runner, not the final
capability-isolated proof path.

OrbStack machines share one Linux kernel. This boundary is appropriate for
testing trusted Shadowpipe code and fault injection, not for containing a
hostile kernel exploit.

## Native macOS boundary

Use a separate Apple-silicon macOS VM in Parallels with Shared/NAT networking,
never Bridged:

- <https://kb.parallels.com/en/4948>
- <https://kb.parallels.com/en/128867>
- <https://developer.apple.com/documentation/virtualization>
- <https://developer.apple.com/documentation/virtualization/vznatnetworkdeviceattachment>

Guest routes, DNS and `utun` interfaces then belong to the guest network stack.
The host VPN is only the NAT underlay. This protects working connectivity, but
it also means the VM cannot supply valid anti-DPI field evidence: its traffic
is already nested inside the host sing-box path.

The production macOS backend should be a signed
`NEPacketTunnelProvider`, not a privileged standalone CLI:

- <https://developer.apple.com/documentation/networkextension/nepackettunnelprovider>
- <https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment>
- <https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension>

The local Mac currently lacks a full signed Network Extension toolchain:
Command Line Tools alone and zero valid signing identities are insufficient.
Full Xcode, an App ID with the Network Extension capability, provisioning and
the appropriate distribution entitlement are real prerequisites.

The macOS VM can prove:

- guest-only `utun`, routes and DNS;
- explicit IPv6 block behavior;
- path-change handling exposed by `NWPathMonitor`;
- carrier loss, provider crash, reassert, update and uninstall recovery.

It cannot faithfully prove physical Wi-Fi roaming, captive portal behavior,
lid sleep/wake, battery use, or performance without nested-tunnel overhead.
Those gates require a second physical Mac or an Apple-hardware cloud Mac on an
independent network path.

## Mandatory host launcher interlocks

The host orchestrator must:

- refuse to execute `shadowpipe-client` when `uname -s` is `Darwin`;
- reject `sudo`, mutating `route`, mutating `networksetup`, mutating `pfctl`,
  mutating `ifconfig`, `launchctl`, and signals to host VPN processes; exact
  read-only route/PF observations are allowed;
- address guests by a previously captured opaque VM identity, not a free-form
  name alone;
- require the guest lab identity before copying or executing anything;
- reject shared Mac folders, shared home, SSH-agent forwarding, clipboard and
  USB integration for the Linux lab;
- reject a dirty or unpushed source tree and never build from a Mac-mounted
  checkout;
- take read-only before/after fingerprints of the exact sing-box
  PID/start-time/argv/binary/config, host IPv4/IPv6 routes, DNS and PF;
- mark the entire result invalid if any protected host observation changes;
- never stop, restart, reconfigure or signal the live sing-box service.

For a macOS VM, additionally require:

- Shared/NAT networking and explicit rejection of Bridged mode;
- a revertible snapshot made before installing the test build;
- a first smoke test proving the `utun` exists only inside the guest;
- bounded memory so the Windows VM remains suspended while the macOS VM runs.

## Evidence boundary

This laboratory can support local correctness, crash safety and L3 leak claims.
It cannot support claims about Russian DPI, a physical access network, universal
packet silence, or production battery/roaming behavior.
