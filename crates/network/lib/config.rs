//! Serializable network configuration types.
//!
//! These types represent the user-facing declarative network configuration
//! for sandbox networking. Designed for the smoltcp in-process engine.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnetwork::{Ipv4Network, Ipv6Network};
use serde::{Deserialize, Serialize};

use crate::dns::Nameserver;

use crate::policy::NetworkPolicy;
use crate::secrets::config::SecretsConfig;
use crate::tls::TlsConfig;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Complete network configuration for a sandbox.
///
/// Narrowed for the smoltcp in-process engine. Gateway, prefix length, and
/// other host-backend details are engine internals derived from the sandbox
/// slot — the user only specifies what matters: interface overrides, ports,
/// policy, DNS, TLS, and connection limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Whether networking is enabled for this sandbox.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Guest interface overrides. Unset fields derived from sandbox slot.
    #[serde(default)]
    pub interface: InterfaceOverrides,

    /// Host → guest port mappings.
    #[serde(default)]
    pub ports: Vec<PublishedPort>,

    /// Egress/ingress policy rules.
    #[serde(default)]
    pub policy: NetworkPolicy,

    /// DNS interception and filtering settings.
    #[serde(default)]
    pub dns: DnsConfig,

    /// TLS interception settings.
    #[serde(default)]
    pub tls: TlsConfig,

    /// Secret injection settings.
    #[serde(default)]
    pub secrets: SecretsConfig,

    /// Max concurrent guest connections. Default: 256.
    #[serde(default)]
    pub max_connections: Option<usize>,

    /// Ship the host's trusted root CAs into the guest at boot so outbound
    /// TLS works behind corporate MITM proxies (Cloudflare Warp Zero
    /// Trust, Zscaler, Netskope, etc.) whose gateway CA is installed on
    /// the host but not shipped in the Mozilla root bundle the guest OS
    /// uses. Opt-in: host trust is not copied into the guest unless
    /// this is explicitly enabled. Default: false.
    #[serde(default)]
    pub trust_host_cas: bool,

    /// How the guest NIC is bridged to the host network. Default: smoltcp
    /// (the in-process userspace stack with policy/DNS/TLS controls).
    #[serde(default)]
    pub mode: NetworkMode,
}

/// How the guest NIC is bridged to the host network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum NetworkMode {
    /// Default. Bridge the guest NIC to the in-process smoltcp userspace stack
    /// (egress policy, DNS interception, TLS-MITM secret injection). Because
    /// connections terminate at L4 and are re-originated from host sockets,
    /// raw/half-open scans (`nmap -sS`, masscan, raw ICMP) are NOT possible.
    Smoltcp,

    /// Linux only. Bridge the guest NIC directly to a pre-provisioned host TAP
    /// device. The guest gets true raw L3 egress — `nmap -sS`, masscan, ICMP,
    /// traceroute — because its own kernel owns the guest IP. This BYPASSES the
    /// smoltcp stack entirely, so egress policy, DNS interception, and TLS-MITM
    /// secret injection do not apply. The host TAP and its NAT/forwarding rules
    /// must already exist; this mode only attaches the guest NIC to them.
    RawTap(RawTapConfig),
}

impl Default for NetworkMode {
    fn default() -> Self {
        NetworkMode::Smoltcp
    }
}

/// Settings for [`NetworkMode::RawTap`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawTapConfig {
    /// Name of the pre-provisioned host TAP device to attach the guest NIC to.
    #[serde(default = "default_tap_name")]
    pub tap_name: String,

    /// Static IPv4 address assigned to the guest interface.
    #[serde(default = "default_raw_guest_ipv4")]
    pub guest_ipv4: Ipv4Addr,

    /// Host-side gateway — the address assigned to the TAP on the host, used as
    /// the guest's default route.
    #[serde(default = "default_raw_gateway_ipv4")]
    pub gateway_ipv4: Ipv4Addr,

    /// Prefix length for the raw subnet (e.g. 24 for a /24).
    #[serde(default = "default_raw_prefix")]
    pub prefix: u8,

    /// DNS resolver handed to the guest (written to the guest's resolv.conf).
    #[serde(default = "default_raw_dns")]
    pub dns: Ipv4Addr,
}

impl Default for RawTapConfig {
    fn default() -> Self {
        Self {
            tap_name: default_tap_name(),
            guest_ipv4: default_raw_guest_ipv4(),
            gateway_ipv4: default_raw_gateway_ipv4(),
            prefix: default_raw_prefix(),
            dns: default_raw_dns(),
        }
    }
}

/// Optional overrides for the guest interface.
///
/// If omitted, values are derived deterministically from the sandbox slot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InterfaceOverrides {
    /// Guest MAC address. Default: derived from slot.
    #[serde(default)]
    pub mac: Option<[u8; 6]>,

    /// Interface MTU. Default: 1500.
    #[serde(default)]
    pub mtu: Option<u16>,

    /// Guest IPv4 address. Default: derived from slot within `ipv4_pool`.
    #[serde(default)]
    pub ipv4_address: Option<Ipv4Addr>,

    /// Guest IPv4 pool. Default: derived from slot (172.16.0.0/12 pool).
    #[serde(default)]
    pub ipv4_pool: Option<Ipv4Network>,

    /// Guest IPv6 address. Default: derived from slot within `ipv6_pool`.
    #[serde(default)]
    pub ipv6_address: Option<Ipv6Addr>,

    /// Guest IPv6 pool. Default: derived from slot (fd42:6d73:62::/48 pool).
    #[serde(default)]
    pub ipv6_pool: Option<Ipv6Network>,
}

/// DNS interception settings for the sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Whether DNS rebinding protection is enabled.
    #[serde(default = "default_true")]
    pub rebind_protection: bool,

    /// Nameservers to forward DNS queries to. When empty, fall back to
    /// the `nameserver` entries in the host's `/etc/resolv.conf`. Set
    /// this to pin specific resolvers (e.g. `1.1.1.1:53`, `dns.google`)
    /// or to work around split-DNS / VPN setups where the host's
    /// resolv.conf is incomplete. Accepts IPs, `IP:PORT`, or hostnames
    /// (resolved once at startup via the host's OS resolver).
    #[serde(default)]
    pub nameservers: Vec<Nameserver>,

    /// Per-query timeout in milliseconds. Default: 5000.
    #[serde(default = "default_query_timeout_ms")]
    pub query_timeout_ms: u64,
}

/// A published port mapping between host and guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedPort {
    /// Host-side port to bind.
    pub host_port: u16,

    /// Guest-side port to forward to.
    pub guest_port: u16,

    /// Protocol (TCP or UDP).
    #[serde(default)]
    pub protocol: PortProtocol,

    /// Host address to bind. Defaults to loopback.
    #[serde(default = "default_host_bind")]
    pub host_bind: IpAddr,
}

/// Protocol for a published port.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortProtocol {
    /// TCP (default).
    #[default]
    #[serde(rename = "tcp", alias = "Tcp")]
    Tcp,

    /// UDP.
    #[serde(rename = "udp", alias = "Udp")]
    Udp,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interface: InterfaceOverrides::default(),
            ports: Vec::new(),
            policy: NetworkPolicy::default(),
            dns: DnsConfig::default(),
            tls: TlsConfig::default(),
            secrets: SecretsConfig::default(),
            max_connections: None,
            trust_host_cas: false,
            mode: NetworkMode::Smoltcp,
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            rebind_protection: true,
            nameservers: Vec::new(),
            query_timeout_ms: default_query_timeout_ms(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

fn default_host_bind() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

fn default_query_timeout_ms() -> u64 {
    5000
}

fn default_tap_name() -> String {
    "msbtap0".to_string()
}

fn default_raw_guest_ipv4() -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 42, 2)
}

fn default_raw_gateway_ipv4() -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 42, 1)
}

fn default_raw_prefix() -> u8 {
    24
}

fn default_raw_dns() -> Ipv4Addr {
    Ipv4Addr::new(1, 1, 1, 1)
}

#[cfg(test)]
mod tests {
    use super::PortProtocol;

    #[test]
    fn port_protocol_serializes_lowercase_and_accepts_legacy_case() {
        assert_eq!(
            serde_json::to_string(&PortProtocol::Tcp).unwrap(),
            "\"tcp\""
        );
        assert_eq!(
            serde_json::to_string(&PortProtocol::Udp).unwrap(),
            "\"udp\""
        );
        assert_eq!(
            serde_json::from_str::<PortProtocol>("\"Tcp\"").unwrap(),
            PortProtocol::Tcp
        );
        assert_eq!(
            serde_json::from_str::<PortProtocol>("\"Udp\"").unwrap(),
            PortProtocol::Udp
        );
    }
}
