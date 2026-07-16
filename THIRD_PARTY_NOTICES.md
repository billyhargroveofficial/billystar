# Third-party notices and reference boundaries

Shadowpipe is an independent implementation. No sing-box, sing-tun or Xray-core
source is vendored in this repository.

The project studies public behavior and operating-system integration patterns
from separately cloned reference repositories:

- sing-box and sing-tun — GPL-3.0-or-later;
- Xray-core — MPL-2.0;
- sing-box Apple, Android and Desktop clients — their respective upstream
  licenses, audited separately from the Shadowpipe source tree.

These repositories are research inputs only. See
[`docs/upstream-clean-room-policy.md`](docs/upstream-clean-room-policy.md).

Windows builds may use the Rust `wintun-bindings` package and a Wintun prebuilt
DLL. The DLL is governed by the Wintun Prebuilt Binaries License rather than
the Rust binding crate's license. Any distributed Windows artifact must retain
the applicable Wintun license and notices and must not modify or reverse
engineer the DLL.

The root Cargo metadata currently declares Shadowpipe `UNLICENSED`. Source
visibility on GitHub does not grant redistribution, modification or trademark
rights. An explicit project license and contribution policy remain an owner
decision.
