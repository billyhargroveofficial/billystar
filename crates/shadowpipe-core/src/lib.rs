pub mod cam;
pub mod carrier;
pub mod client_auth;
pub mod control;
pub mod crypto;
pub mod dns_exchange;
pub mod endpoint;
pub mod endpoint_dns;
pub mod endpoint_policy;
pub mod endpoint_runtime;
pub mod host_recovery;
pub mod host_state;
pub mod lockdown;
pub mod measurement;
pub mod mux;
pub mod netguard;
pub mod pacing;
pub mod packet;
pub mod policy_state;
pub mod profile;
pub mod proto;
#[cfg(feature = "quic")]
pub mod quic;
pub mod reality;
pub mod routes;
pub mod ruleset;
pub mod session;
pub mod signed_policy;
pub mod split;
#[cfg(feature = "tls-chrome")]
pub mod tls;
pub mod tun_dev;
pub mod tun_state;
pub mod tunnel;
pub mod volume_guard;

include!(concat!(env!("OUT_DIR"), "/magic.rs"));

/// Version 3 has mandatory per-device hybrid client authentication, encrypted
/// Finished records on separate handshake traffic keys, and final application
/// keys derived only after both Finished messages. There is deliberately no v2
/// negotiation or fallback path.
pub const PROTO_VERSION: u8 = 3;
