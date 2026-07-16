# Host-safe VPN laboratory on macOS

Snapshot: 2026-07-16.

## Verdict

A privileged full-tunnel client cannot be safely isolated from the working
macOS network stack with `sandbox-exec` or App Sandbox. Those mechanisms limit
process capabilities; they do not create an independent Darwin routing table,
DNS configuration, PF instance, TUN namespace, or Network Extension control
plane.

- <https://developer.apple.com/documentation/security/app-sandbox>
- <https://developer.apple.com/forums/thread/661939>

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
  +-- Parallels macOS ARM VM              Network Extension client tests
  `-- Parallels Linux VM                  native-macOS lab server/router peer
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
- <https://docs.orbstack.dev/machines/network>

OrbStack external networking still follows the host VPN and DNS path. That is
acceptable for the self-contained private-netns correctness lab below, but it
is not independent Internet or anti-DPI evidence.

Inside that VM:

1. require a root-owned lab identity file with an expected random UUID;
2. permit the guest-root orchestrator to create identity-bound namespaces and
   veth pairs, but require every client/server/listener/workload and every
   TUN, route, DNS or firewall mutation to run outside the PID 1 network
   namespace;
3. leave no lab listener, route, TUN or firewall object in the guest-root
   namespace;
4. use a guest-local checkout at a pinned pushed commit, transferred as a
   bounded hash-verified stdin stream through the already bound opaque VM ID;
5. keep build output, credentials and raw evidence guest-local;
6. bound endpoints, bytes, rate and wall-clock duration;
7. destroy or revert the disposable machine after the run.

The legacy `arch` machine is not an accepted source for privileged runs.
`shadowpipe-lab-base` plus a disposable isolated clone is the mandatory path.
Provisioning the base is not evidence by itself: an integrated claim requires
a sealed result with valid test, guest cleanup, clone cleanup, source transfer,
private-material scan and host-safety statuses.

OrbStack machines share one Linux kernel. This boundary is appropriate for
testing trusted Shadowpipe code and fault injection, not for containing a
hostile kernel exploit.

The dedicated `shadowpipe-lab-base` now exists and is stopped. Its observed
profile is `isolated=true`, `isolate_network=true`,
`forward_ssh_agent=false`, with zero HTTP/HTTPS forwards, 6 GiB memory, four
CPUs and a 32 GiB disk. The guest toolchain, TUN device, overlayfs, netns,
nftables/iptables, tcpdump and Rust build were verified before it was stopped.

In the installed OrbStack version, `orbctl push/pull` attempted to use the
disabled read-only sharing layer of the isolated machine. The hardened runner
therefore must not depend on those commands. Source enters through bounded
stdin to a root-owned create-only guest file; sealed evidence returns through
bounded stdout. Both directions require SHA-256 and byte-count agreement, and
the host extractor rejects absolute paths, traversal, duplicate entries,
links, devices and oversized archives.

Current Linux evidence:

- [`20260716T173837Z-18283-m8K2po`](../tests/tun/results/20260716T173837Z-18283-m8K2po/RESULT.md)
  is a scoped PASS for pinned source
  `81f188f772cc6b674fde748a361691f1bda19691`;
- it proves a real `c0` to `c1` default-route handoff with the exact
  `DefaultRouteChanged` cause, a strict intermediate lockdown, generation-2
  activation through `c1`, a live promiscuous-observer regression,
  directional IPv6 egress blocking, manager-gated shutdown, explicit release
  and complete clone cleanup;
- the working sing-box remained PID `74899`, start time
  `Wed Jul 15 12:04:27 2026`, with the same argv;
- this is Linux VM evidence only, not native macOS `NetworkExtension`,
  Windows, production, field or censorship-resistance evidence.

## Native macOS boundary

Use a separate Apple-silicon macOS VM. `sandbox-exec` and App Sandbox are not
network namespaces: they do not provide an independent routing table, DNS
configuration or `utun` control plane.

Parallels Shared/NAT is safe for the host but is not an independent network
proof. Parallels documents that Shared networking passes guest connectivity
through the host, including the host VPN. A Shadowpipe test there is nested
inside sing-box and cannot prove that the macOS client works without it.

No Parallels or Virtualization.framework mode proves the desired boundary by
its name alone. The usable evidence tiers are:

### Tier 1: Parallels Host-Only, hermetic and no-WAN

The correctness topology is:

```text
macOS client VM
       |
       +-- Parallels Host-Only/private L2
                    |
                    +-- Parallels Linux Shadowpipe server/router VM
                    `-- Parallels Linux DNS/canary VM
```

On Apple silicon, Host-Only for a macOS guest requires host macOS 15 or newer
and Parallels Desktop 20.4.0 or newer. Creating an additional custom Host-Only
network is available only in Pro and Business/Enterprise editions. The
Parallels virtual gateway remains reachable in this mode; its presence or a
guest default route to it is not WAN evidence. The official contract is that
the subnet is isolated from the outer world.

The native macOS client peer must be another Parallels Linux VM attached to
the same Host-Only segment. Do not route the test to OrbStack through a host
listener, port forward or proxy: that reintroduces the working Mac network
stack and invalidates the private-L2 boundary. OrbStack remains the separate
Linux netns laboratory described above.

### Tier 2: Parallels Bridged Ethernet, conditional independent-WAN evidence

Bridged Ethernet is the intermediate one-Mac tier. Parallels presents the
guest as a separate LAN computer and the LAN DHCP server may give it its own
address. It can support an independence claim only when the evidence collected
before Shadowpipe starts proves all of the following:

- the adapter is explicitly bridged to a wired Ethernet interface, not
  `Default Adapter`, Shared/NAT or the working Mac's Wi-Fi;
- the guest has a separate LAN address, route and resolver path;
- an external observer or the Shadowpipe server sees the guest's direct
  pre-tunnel source path and sees a source distinct from the host sing-box
  egress;
- a guest packet capture and server-side capture agree that the Shadowpipe
  carrier leaves through that bridged interface.

Without that pre-tunnel and server-source proof, Bridged Ethernet is only a
candidate independent uplink, not evidence. Bridged Wi-Fi is weaker:
Parallels documents that the guest shares the host MAC identity and may fail
to obtain an address or work reliably depending on the access network. It is
not equivalent to wired Bridged Ethernet for this claim.

### Tier 3: direct USB Ethernet passthrough, strongest one-Mac tier

The strongest one-Mac arrangement is a dedicated USB Ethernet adapter passed
directly to the macOS VM and connected to a separate router or mobile uplink.
Disable every Shared/NAT and bridged adapter in that VM. Once attached directly,
the USB device is no longer available to the host, which gives a materially
stronger physical boundary than bridging a host-owned interface.

USB passthrough to Apple-silicon macOS VMs requires host macOS 15 or newer and
Parallels Desktop 20.3.0 or newer. Apple Virtualization.framework does not
support every USB device, and Parallels cannot guarantee that a particular USB
Ethernet chipset and macOS driver combination will appear or work in the
guest. This tier can be claimed only after device enumeration, link, DHCP,
pre-tunnel source and server-side source proofs succeed.

### Virtualization.framework attachment semantics

A custom runner can make the topology more explicit, but its attachment type
still defines the evidence boundary:

- `VZNATNetworkDeviceAttachment` routes through the host and therefore
  inherits the host egress boundary; it is not independent-WAN evidence;
- `VZBridgedNetworkDeviceAttachment` attaches to a physical host interface and
  requires the `com.apple.vm.networking` entitlement; apply the same
  pre-tunnel and server-source proof required for Parallels Bridged Ethernet;
- `VZFileHandleNetworkDeviceAttachment` transports raw frames through a
  datagram socket and can be used to construct a private L2 between controlled
  VM endpoints; it supplies no independent WAN by itself;
- `VZVmnetNetworkDeviceAttachment`, available on macOS 26 and newer, supports
  a custom multi-VM topology backed by vmnet. A private vmnet topology is
  useful for hermetic tests, but is not independent-WAN evidence unless a
  separately evidenced physical uplink is supplied.

A second physical Mac remains the cleanest field host. Third-party
Network Extension compatibility, VM networking and physical-network support
are not universal, so all statements below are conditional on the selected
tier's prerequisites and evidence actually passing.

- <https://kb.parallels.com/en/4948>
- <https://docs.parallels.com/landing/pdfm-ug/parallels-desktop-for-mac-26-users-guide/advanced-topics/creating-custom-host-only-networks>
- <https://kb.parallels.com/en/129897>
- <https://kb.parallels.com/en/128867>
- <https://docs.parallels.com/landing/pdfm-ug/parallels-desktop-for-mac-26-users-guide/advanced-topics/using-other-operating-systems-on-your-mac/running-macos-virtual-machines/connecting-usb-devices-directly-to-your-macos-virtual-machine>
- <https://kb.parallels.com/en/122993>
- <https://developer.apple.com/documentation/virtualization/virtualize-macos-on-a-mac>
- <https://developer.apple.com/documentation/virtualization/vznatnetworkdeviceattachment>
- <https://developer.apple.com/documentation/virtualization/vzbridgednetworkdeviceattachment>
- <https://developer.apple.com/documentation/virtualization/vzfilehandlenetworkdeviceattachment>
- <https://developer.apple.com/documentation/virtualization/vzvmnetnetworkdeviceattachment>

The production macOS backend should be a signed
`NEPacketTunnelProvider`, not a privileged standalone CLI:

- <https://developer.apple.com/documentation/networkextension/nepackettunnelprovider>
- <https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment>
- <https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension>

The local Mac currently lacks a full signed Network Extension toolchain:
Command Line Tools alone and zero valid signing identities are insufficient.
Full Xcode, an App ID with the Network Extension capability, provisioning and
the appropriate distribution entitlement are real prerequisites.

When the third-party client runs correctly in the VM, signing and entitlements
are valid, and the chosen network-tier proofs above pass, the macOS VM can
support scoped evidence for:

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

- Host-Only/private L2 plus a Parallels Linux peer on that same segment for
  hermetic tests, with no OrbStack-via-host forwarding;
- explicit rejection of Shared/NAT as evidence of independence from host
  sing-box;
- for wired Bridged external tests, a separate guest LAN address plus
  pre-tunnel and server-side source proof before accepting independence;
- reject Bridged Wi-Fi as equivalent evidence because its guest shares the
  host MAC identity and access-network support is unreliable;
- for the strongest external-network test, a dedicated USB Ethernet adapter
  passed directly to the guest, never the working Mac's primary network path,
  with actual guest compatibility and source-path proof;
- a revertible snapshot made before installing the test build;
- a first smoke test proving the `utun` exists only inside the guest;
- before/after equality of host sing-box PID/start/argv, `utun` census,
  IPv4/IPv6 default routes, DNS and PF observations;
- bounded memory so the Windows VM remains suspended while the macOS VM runs.

## Evidence boundary

The Linux laboratory supports scoped local correctness, crash safety and L3
egress-leak claims. A separate macOS VM can support native
`NEPacketTunnelProvider` lifecycle claims only after Xcode, signing and
entitlement provisioning exist inside that guest. Neither setup alone supports
claims about Russian DPI, a physical access network, universal packet silence,
or production battery/roaming behavior.
