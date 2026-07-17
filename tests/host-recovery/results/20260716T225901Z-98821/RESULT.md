# ShadowPipe privileged Phase-3 crash/recovery lab

- Run: 20260716T225901Z-98821
- Guest verdict: **PASS**
- Isolation: disposable OrbStack clone; fresh net+mount+PID namespace per scenario
- Resolver: private tmpfs target, never guest /etc/resolv.conf
- Runtime resources: two TUN split-default routes plus one persistent-underlay protocol-186 /32, non-persistent TUN+ifalias ownership, DNS rename exchange, iptables/ip6tables kill-switch
- Crash cuts: WAL Planned; every resource-family apply; DNS Staged; partial firewall WAL acknowledgements; all-Applied/Preparing; Active; and both before mutation plus after convergence/before WAL ack for each of 8 recovery steps
- Crash evidence: every SIGKILL marker has one exact cut label/PID/log record; every crash retains a mandatory root-owned schema-v3 WAL with the exact eight-resource vocabulary, phase, per-operation states, and recovery-marker resource binding
- Conflict oracle: exact pre/post network snapshot equality plus durable Conflict journal
- Release helper build: explicit validated SHADOWPIPE_MAGIC=0x50334852

## Honest scope limits

- Same-boot namespace recovery only; this does not simulate a kernel reboot.
- SIGKILL tests process crashes, not torn filesystem writes or power-loss storage semantics.
- Synthetic namespace state is not field evidence for hostile ISP/RKN networks.
- The private resolver target validates exchange mechanics without touching systemd-resolved or the clone /etc.
- A malicious same-UID/root writer remains outside the 0700-directory + singleton-lease trust boundary.
- The shared lock excludes other Shadowpipe OrbStack runners; unrelated same-host lifecycle operators remain outside the trust boundary.

## Failures

~~~text
<none>
~~~
