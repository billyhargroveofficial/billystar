# Windows ARM64 H2 no-TUN gate

- Run: `20260716T125113Z-36840-dd0c2571`
- Carrier: Shadowpipe H2 chunk framing over TCP; inner protocol: mandatory authenticated v3.
- Native client: Windows 11 ARM64 PE, `--no-default-features`, strict warnings.
- Negative controls: missing pin opened 0 loopback TCP connections; unenrolled device credential received no echo.
- Positive controls: exact nonce echo plus 1,048,576 bytes sent and echoed.
- Windows state: route and DNS canonical digests must match before/after; no TUN/firewall/adapter mutation command exists in the helper.
- Endpoint: exact RFC1918 address on one opaque-ID-bound disposable OrbStack clone; Mac route-to-endpoint had to avoid every `utun*` interface.
- Cleanup: Windows private files removed and VM re-suspended; clone deleted by name only after a fresh name-to-bound-ID check because OrbStack 2.2.1 panics on delete-by-ID; ID and name remained absent for 60 seconds; source `arch` stayed stopped.
- macOS: live sing-box PID/start/argv/config/binary plus stable IPv4/IPv6 routes and DNS were read-only and byte-compared before/after.
- Field evidence: false. This is a private-VM implementation/portability gate, not censorship-resistance evidence.
- Overall: `valid`.
