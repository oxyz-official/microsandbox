//! Linux raw-TAP networking mode.
//!
//! In [`NetworkMode::RawTap`](crate::config::NetworkMode::RawTap) the guest NIC
//! is bridged straight to a pre-provisioned host TAP device instead of the
//! in-process smoltcp userspace stack. Because the guest's own kernel owns the
//! guest IP, it gets true raw L3 egress — `nmap -sS` half-open scans, masscan,
//! ICMP sweeps, traceroute — none of which survive the smoltcp L4 proxy.
//!
//! This module is host-side glue only: it resolves whether raw mode is active
//! (from config or the `MSB_RAWNET_TAP` env override), derives the guest MAC,
//! and builds the same `MSB_NET*` env vars smoltcp mode uses so the guest
//! `agentd` configures `eth0` with a static address, default route, and DNS.
//!
//! The TAP device and the host NAT/forwarding rules (e.g. an `iptables`
//! MASQUERADE for the raw subnet) must already exist; the runtime attaches the
//! guest NIC to the TAP via `VmBuilder::net().tap(name)` and does not manage the
//! host network lifecycle.

use microsandbox_protocol::{ENV_HOST_ALIAS, ENV_NET, ENV_NET_IPV4};

use crate::config::{NetworkMode, RawTapConfig};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Env var that force-enables raw-TAP mode at runtime, overriding the sandbox
/// network config. Its value is the host TAP device name (e.g. `msbtap0`).
///
/// Optional companions tune the addressing (all fall back to [`RawTapConfig`]
/// defaults): `MSB_RAWNET_GUEST_IP`, `MSB_RAWNET_GATEWAY`, `MSB_RAWNET_PREFIX`,
/// `MSB_RAWNET_DNS`.
pub const ENV_RAWNET_TAP: &str = "MSB_RAWNET_TAP";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolve the active raw-TAP config, if any. The `MSB_RAWNET_TAP` env override
/// takes precedence over the declarative [`NetworkMode`] in config.
pub fn resolve(mode: &NetworkMode) -> Option<RawTapConfig> {
    if let Some(cfg) = env_override() {
        return Some(cfg);
    }
    match mode {
        NetworkMode::RawTap(cfg) => Some(cfg.clone()),
        NetworkMode::Smoltcp => None,
    }
}

/// Read a raw-TAP override from the environment, returning `Some` only when
/// `MSB_RAWNET_TAP` is set to a non-empty device name.
pub fn env_override() -> Option<RawTapConfig> {
    let tap_name = std::env::var(ENV_RAWNET_TAP).ok().filter(|s| !s.is_empty())?;

    let mut cfg = RawTapConfig {
        tap_name,
        ..RawTapConfig::default()
    };
    if let Some(v) = env_parse("MSB_RAWNET_GUEST_IP") {
        cfg.guest_ipv4 = v;
    }
    if let Some(v) = env_parse("MSB_RAWNET_GATEWAY") {
        cfg.gateway_ipv4 = v;
    }
    if let Some(v) = env_parse("MSB_RAWNET_PREFIX") {
        cfg.prefix = v;
    }
    if let Some(v) = env_parse("MSB_RAWNET_DNS") {
        cfg.dns = v;
    }
    Some(cfg)
}

/// Derive a stable guest MAC for raw mode from the sandbox slot.
///
/// Format `02:6d:73:SS:SS:02` (the locally-administered `02:6d:73` OUI with the
/// slot in the middle), matching the smoltcp engine's guest-MAC scheme so the
/// two modes are interchangeable for a given slot.
pub fn guest_mac(slot: u64) -> [u8; 6] {
    let s = slot.to_be_bytes();
    [0x02, 0x6d, 0x73, s[6], s[7], 0x02]
}

/// Build the `MSB_NET*` env vars that tell the guest `agentd` its interface,
/// static IPv4 address, default-route gateway, and DNS resolver for raw mode.
pub fn guest_env_vars(cfg: &RawTapConfig, mac: [u8; 6], mtu: u16) -> Vec<(String, String)> {
    let mac_str = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );

    vec![
        (
            ENV_NET.to_string(),
            format!("iface=eth0,mac={mac_str},mtu={mtu}"),
        ),
        (ENV_HOST_ALIAS.to_string(), crate::HOST_ALIAS.to_string()),
        (
            ENV_NET_IPV4.to_string(),
            format!(
                "addr={}/{},gw={},dns={}",
                cfg.guest_ipv4, cfg.prefix, cfg.gateway_ipv4, cfg.dns
            ),
        ),
    ]
}

fn env_parse<T: std::str::FromStr>(key: &str) -> Option<T> {
    std::env::var(key).ok()?.parse().ok()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn guest_mac_encodes_slot() {
        assert_eq!(guest_mac(0), [0x02, 0x6d, 0x73, 0x00, 0x00, 0x02]);
        assert_eq!(guest_mac(0x0102), [0x02, 0x6d, 0x73, 0x01, 0x02, 0x02]);
    }

    #[test]
    fn guest_env_vars_emit_static_ipv4_route_and_dns() {
        let cfg = RawTapConfig {
            tap_name: "msbtap0".into(),
            guest_ipv4: Ipv4Addr::new(10, 0, 42, 2),
            gateway_ipv4: Ipv4Addr::new(10, 0, 42, 1),
            prefix: 24,
            dns: Ipv4Addr::new(1, 1, 1, 1),
        };
        let vars = guest_env_vars(&cfg, guest_mac(0), 1500);

        assert_eq!(vars[0].0, ENV_NET);
        assert!(vars[0].1.contains("iface=eth0"));
        assert!(vars[0].1.contains("mac=02:6d:73:00:00:02"));
        assert_eq!(vars[1].0, ENV_HOST_ALIAS);
        assert_eq!(vars[2].0, ENV_NET_IPV4);
        assert_eq!(vars[2].1, "addr=10.0.42.2/24,gw=10.0.42.1,dns=1.1.1.1");
    }

    #[test]
    fn resolve_returns_none_for_smoltcp() {
        assert!(resolve(&NetworkMode::Smoltcp).is_none());
    }

    #[test]
    fn resolve_returns_config_for_raw_tap() {
        let cfg = RawTapConfig::default();
        assert_eq!(resolve(&NetworkMode::RawTap(cfg.clone())), Some(cfg));
    }
}
