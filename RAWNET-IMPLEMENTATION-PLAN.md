# Raw‑Socket Networking for microsandbox (Blackbit WAR)

**Status:** Plan / pre‑implementation · **Branch:** `feat/raw-socket-networking`
**Goal:** Give the microsandbox microVM guest a networking mode that supports *active* offensive reconnaissance — `nmap -sS` (half‑open SYN), `-sU`, `masscan`, `hping3`, ICMP sweeps, traceroute — against external **and** internal (RFC1918) targets, so the **Orgn CDE "Blackbit WAR"** feature can run the `vxcontrol/kali-linux` toolchain inside a hardware‑isolated microVM instead of a privileged Docker Kali container (`docker run --cap-add=NET_RAW --cap-add=NET_ADMIN ...`).

All repo paths below are relative to this repository root. Line numbers were verified against this checkout.

---

## TL;DR verdict

**Buildable in this codebase with no fork of `msb_krun`.** The crate exposes `NetBuilder::custom(Box<dyn NetBackend + Send>)` (generic, not hardcoded), a Linux‑native `tap(name)`, and a cross‑platform `unixgram_path(...)`; microsandbox **already** drives the `custom()` seam at `crates/runtime/lib/vm.rs:1260`. A raw‑egress mode is a drop‑in sibling backend.

**The work is host‑side plumbing + privilege, not the Rust binding.**

- **Linux is clean and high‑confidence** — `msb_krun` ships a first‑class `tap()` backend, so no custom backend code is even required; pair it with host NAT.
- **macOS is shippable at NAT fidelity** via a root `vmnet` helper (SHARED mode) over the `unixgram`+vfkit path — **no `com.apple.vm.networking` entitlement needed**. SHARED‑NAT covers `nmap -sS` + ICMP‑echo (the common recon path); only traceroute / `hping3` / raw‑IP / non‑echo‑ICMP (and, less reliably, `-sU`) degrade. Those need BRIDGED mode, which *is* gated behind the restricted entitlement.

**Recommendation:** ship **Linux raw‑mode** as v1; on macOS use the SHARED‑NAT helper for `-sS`/ping and **keep Docker‑Kali as the fallback** for the genuinely‑raw slice until/unless the Apple entitlement is pursued.

---

## 1. Background — why scans break today

The fork already gives the guest a **real virtio‑net interface** (not libkrun TSI). Guest ethernet frames reach the host via `SmoltcpBackend` (`crates/network/lib/backend.rs:65`), which implements `msb_krun::backends::net::NetBackend` and feeds a custom **smoltcp userspace TCP/IP stack** (`crates/network/lib/stack.rs`) plus policy / DNS / TLS‑MITM / secrets layers.

Because smoltcp **terminates connections at L4 and re‑originates them from host sockets**, raw scans lose fidelity (verified in‑source):

- **SYN scan → connect scan.** On a guest SYN, the host stack completes the handshake itself and opens a fresh `TcpStream::connect()` — not half‑open (`crates/network/lib/stack.rs`).
- **ICMP is echo‑only.** `crates/network/lib/icmp_relay.rs` header, verbatim: *"Only Echo Request/Reply is supported. Non‑echo ICMP (traceroute, destination unreachable, etc.) is intentionally not relayed."* → traceroute / `hping3` dead.
- **Stateless masscan SYNs** and arbitrary non‑TCP/UDP/DNS frames are dropped by the smoltcp passthrough.

The guest kernel itself is fully raw‑capable (it owns the guest IP and has `CAP_NET_RAW`). **The limiter is purely the host‑side smoltcp proxy** — replace what the guest frames feed into and raw scanning works.

---

## 2. Feasibility — the `NetBackend` seam (no fork)

Verified against `msb_krun 0.1.19` source (`crates.io`, pinned `=0.1.19` in `Cargo.toml:79`, no `[patch]`/git override) and this repo:

- **`NetBackend` is a public trait** (gated only by the `net` feature), re‑exported at `msb_krun::backends::net`. The builder accepts an arbitrary `Box<dyn NetBackend + Send>` via `NetBuilder::custom(...)` (`msb_krun .../api/builders.rs:686`), stored as `NetConfig::Custom` and wired to `VirtioNetBackend::Custom`. Not hardcoded.
- **The repo already uses it:** `SmoltcpBackend` is a third‑party `impl NetBackend` (`crates/network/lib/backend.rs:65`), boxed at `crates/network/lib/network.rs:221` (`take_backend() -> Box<dyn NetBackend + Send>`) and attached at the single call site `crates/runtime/lib/vm.rs:1260`:
  ```rust
  let guest_mac  = network.guest_mac();          // vm.rs:1242
  let net_backend = network.take_backend();       // vm.rs:1243
  builder = builder.net(move |n| n.mac(guest_mac).custom(net_backend)); // vm.rs:1260
  ```
- **Linux needs no custom backend at all.** `msb_krun` ships `NetBuilder::tap(name)` (`#[cfg(target_os="linux")]`) → `VirtioNetBackend::Tap`. So Linux raw‑mode is `.net(|n| n.mac(mac).tap("msbtap0"))`.
- **macOS `vmnet` has no built‑in variant** → must go through `.custom()` *or* (preferred) `unixgram_path(path, send_vfkit_magic=true)` feeding an external `vmnet` helper.
- **Multiple NICs are supported** (`NetConfig` is a `Vec`, named `eth0`, `eth1`, …). Option worth keeping in mind: attach smoltcp `eth0` (keeps DNS/policy/secret‑injection) **and** a raw NIC `eth1` simultaneously, rather than losing all controls in raw mode.

**Caveats for a custom backend:** must be `Send + 'static` (not `Sync`); its `raw_socket_fd()` must be a single pollable fd that becomes readable exactly when an inbound frame is ready (vmnet's dispatch‑queue API likely needs a self‑pipe/eventfd shim — the same trick `SmoltcpBackend` uses with `rx_wake`); and it must add/strip the 12‑byte virtio‑net header (`backend.rs:90-115`). One unverified item: the literal `trait NetBackend` definition lives in an un‑vendored sub‑crate, so there may be additional **defaulted** methods — confirm with `cargo doc` before relying on any connect‑time hook. Does not change the no‑fork verdict.

---

## 3. Architecture

### 3.1 Config — a `mode` field (default preserves today's behavior)

- **`crates/network/lib/config.rs`** — add to `NetworkConfig` (struct at `:28`):
  ```rust
  #[serde(default)]
  pub mode: NetworkMode,

  #[derive(Debug, Clone, Default, Serialize, Deserialize)]
  #[serde(rename_all = "kebab-case")]
  pub enum NetworkMode {
      #[default] Smoltcp,
      RawTap { tap_name: String, gateway_ipv4: Ipv4Addr, guest_ipv4: Ipv4Addr },
      RawUnixgram { helper_socket: PathBuf },
  }
  ```
  Update `impl Default for NetworkConfig` (`:157`) so `mode` defaults to `Smoltcp`. **Default MUST be `Smoltcp`** — raw mode is opt‑in.
- **`crates/network/lib/builder.rs`** — add `pub fn mode(self, m: NetworkMode) -> Self` mirroring `trust_host_cas` (`:251`).
- **`packages/microsandbox-types/rust/lib/domain.rs`** — add a matching `mode` field to `NetworkSpec` (`:397`) and its `Default` (`:1030`). **Mandatory and the subtlest hazard:** the SDK round‑trips config via `serde_json::from_value(to_value(...))` (`sdk/rust/lib/sandbox/config.rs`), so any top‑level field missing from `NetworkSpec` is **silently dropped at runtime while compiling fine.**

### 3.2 Backend selection — one branch in `vm.rs`

`crates/runtime/lib/vm.rs:1242-1260` is the only switch point. Branch on `network.mode()`:

| mode | call | platform |
|---|---|---|
| `Smoltcp` (default) | existing: `take_backend()` → `.custom(net_backend)` | all |
| `RawTap` | `n.mac(mac).tap(tap_name)` (skip smoltcp) | Linux |
| `RawUnixgram` | `n.mac(mac).unixgram_path(helper_sock, /*vfkit*/true)` | macOS |

For raw modes, emit raw‑mode guest env (`MSB_NET*`: guest IP/CIDR, gateway = host TAP/helper IP, DNS = real resolver) instead of the smoltcp slot‑derived scheme.

### 3.3 Orchestration + lifecycle

- Add a `RawNetwork` struct beside `SmoltcpNetwork` in `crates/network/lib/network.rs` exposing the same fixed surface the runtime calls (`guest_mac()`, `guest_env_vars()`; raw modes have no `take_backend()`).
- New module **`crates/network/lib/raw.rs`** owns the host‑side lifecycle: TAP create/destroy + NAT (Linux), helper‑socket connect (macOS), teardown on exit/crash.

### 3.4 CLI / SDK plumbing (mechanical, Phase 3)

- CLI: `--net-mode` flag threaded into the `.network(|n| ...)` closure in `crates/cli/lib/commands/common.rs` (gate `has_network_config`). `LaunchConfig` needs **no** change — the whole `NetworkConfig` already travels (`crates/runtime/lib/launch.rs`, `crates/cli/lib/sandbox_cmd.rs`).
- FFI SDK passthroughs (one each, Phase 3 only): TS `sdk/node-ts/native/network_builder.rs` + `sdk/node-ts/src/network-config.ts`; Python `sdk/python/src/helpers.rs`; Go `sdk/go/native/src/lib.rs`.

### 3.5 Metrics (optional, Phase 4)

`tap()`/`unixgram()` bypass `SmoltcpBackend`, so `net_rx/tx_bytes` (`backend.rs:82` → `crates/metrics/lib/layout.rs`) are lost. If per‑sandbox byte metrics are required, write a thin `RawCountingBackend` (a `NetBackend` impl wrapping the TAP/socket fd) and attach via `.custom()`.

---

## 4. Phased plan

| Phase | Deliverable | Files | Effort | Biggest risk |
|---|---|---|---|---|
| **0 — Linux TAP PoC** | Prove `nmap -sS` egresses real half‑open SYNs from the Kali guest (tcpdump on TAP, no host‑completed handshake) + masscan/hping3/traceroute/ICMP smoke | shortcut `.tap("msbtap0")` at `vm.rs:1260` behind a throwaway env flag; host setup script (see Appendix A) | 3–4 d | **No `/dev/kvm` on stock `ubuntu-latest`** (needs self‑hosted/nested‑virt or a local box); guest virtio‑net/TAP offload (VNET_HDR/TSO) negotiation |
| **1 — Linux RawTap productization** | Real `NetworkMode` enum + `NetworkSpec` mirror + builder method + `vm.rs` branch; `raw.rs` TAP/NAT lifecycle | `config.rs`, `builder.rs`, `domain.rs`, `vm.rs`, new `raw.rs` | 4–6 d | conntrack INVALID‑RST drop leaks half‑open conns; CAP_NET_ADMIN ownership + teardown on crash |
| **2 — Host firewall (MANDATORY)** | nft/iptables egress allowlist (CIDR/port) + inbound DNAT to guest; **reject unenforceable rules at config‑build time** | `raw.rs`, validation in `config.rs`/`builder.rs` | 5–8 d | **silent fail‑open** — make irreducible losses *loud errors* |
| **3 — macOS via root `vmnet` helper** | `RawUnixgram` working: reuse `vmnet-helper`/`socket_vmnet` in SHARED/NAT, feed libkrun over `unixgram`+vfkit; CLI/SDK passthroughs | `vm.rs` branch, helper packaging, FFI SDKs | 4–7 d | **privileged‑helper install/UX** in a notarized app (root‑owned path + sudoers); 1‑day vfkit‑framing spike first |
| **4 — Metrics + Orgn CDE swap** | optional `RawCountingBackend`; Orgn CDE `KaliContainer` adapter | `network/`, Orgn CDE | 4–6 d | guest addressing (agentd `eth0` bring‑up) under the raw subnet |

**Sequence the spend on confidence:** Phase 0 de‑risks the one thing that could kill the idea (does raw egress actually work in this VMM + guest); Phase 2 makes Linux safe to ship; Phase 3's framing spike decides whether macOS is worth the helper‑packaging cost before sinking days into it.

**Linux v1 to shippable ≈ 16–24 person‑days** (Phase 0→1→2→4), contingent on a KVM‑capable runner.

---

## 5. Security tradeoffs of raw mode

Raw mode bypasses the entire smoltcp pipeline — frames no longer transit it. Verified losses + mitigations:

| Control | Source | Lost? | Mitigation |
|---|---|---|---|
| Egress CIDR/port allowlist | `policy/`, `stack.rs` | Yes | **Reimpose as host nft/pf (Phase 2) — MANDATORY.** Only thing stopping the guest reaching `169.254.169.254` / the operator LAN. |
| Domain / DomainSuffix / SNI policy | `policy/`, `dns/forwarder.rs` | Yes, **irreducibly** | No stateless host analog. **Reject at config‑build time in raw mode** so it errors instead of silently failing open. |
| DNS interception / rebind protection | `dns/forwarder.rs` | Yes | Optional host DNS proxy; recon tools bypass it anyway (`dig @8.8.8.8`). |
| TLS‑MITM secret injection | `tls/`, `secrets/` | Yes, **irreducibly** | No analog (terminating proxy). Document the downgrade; keep feature off in raw mode. |
| Connection limit | `conn.rs` | Yes | Coarse `iptables connlimit`/`pf` state caps. |
| Net byte metrics | `backend.rs:82` | Yes (tap/unixgram) | `RawCountingBackend` via `.custom()` (Phase 4). |
| ICMP / traceroute / `-sU` fidelity | `icmp_relay.rs` (echo‑only today) | **Improves on Linux** (real TTL‑exceeded) | **Stays broken on macOS‑NAT** (see §6). |

**Net posture:** raw mode is a Kali microVM with no in‑process containment. Must be opt‑in (`default = Smoltcp`), loudly gated, host‑firewalled, ideally audit‑logged. The multi‑NIC option (§2) is the way to keep some controls if needed.

---

## 6. macOS specifics (verified)

- **Entitlement avoided by design.** `vmnet` SHARED (`VMNET_SHARED_MODE`, NAT) and HOST modes need **only root to create the interface**, *not* `com.apple.vm.networking`; only BRIDGED needs it (Apple DTS, [forum 710763](https://developer.apple.com/forums/thread/710763)). `com.apple.vm.networking` is a **restricted, contract‑gated** entitlement (socket_vmnet/vmnet‑helper READMEs) — not self‑assignable by a notarized third‑party app.
- **Reuse an existing helper, don't write a vmnet backend.** `vmnet-helper`/`socket_vmnet` hold the privilege and forward frames over a Unix datagram socket; libkrun ingests them via `krun_add_net_unixgram(..., NET_FLAG_VFKIT)` ⇔ `unixgram_path(path, send_vfkit_magic=true)`. This is the *designed* model (krunkit/vfkit/minikube/CRC ship it). The main `msb` process keeps hardened runtime + `com.apple.security.hypervisor` (already in `msb-entitlements.plist`; **no vmnet entry needed**).
- **SHARED‑NAT capability matrix** (test the UNKNOWN row empirically):
  | Tool | SHARED‑NAT |
  |---|---|
  | `nmap -sS` (half‑open) | ✅ works — NAT translates SYN‑ACK/RST back; valid port state |
  | ICMP echo / ping sweep | ✅ works |
  | `nmap -sU` | ⚠️ unreliable (returned ICMP‑unreachable through NAT is the weak spot) |
  | traceroute, `hping3`, non‑echo / raw‑IP ICMP | ❌ break (NAT rewrites TTL; raw‑IP not faithfully relayed) |
  | arbitrary IP protocols (GRE, raw‑IP) | ❓ **UNKNOWN** — no vmnet‑engine doc; test in‑guest |
- **The real macOS blocker is install/UX, not Apple approval.** On macOS ≤15 the helper needs root to create the interface, so it must live at a root‑owned, non‑user‑writable path with a sudoers rule (vmnet‑helper refuses Homebrew on ≤15 for priv‑esc reasons). **macOS 26+ removes the root requirement**, de‑risking over time.

---

## 7. Orgn CDE integration (consumer side — clean adapter swap)

The consumer abstraction is the Effect `Interface` at `orgn.cde.v2/packages/core/src/filesystem/kali-container.ts:55` (`exec` / `execBackground` / `jobTail` / `jobStdin` / `ensure`). Today every method shells `docker exec`; the container is created with `--cap-add=NET_RAW/NET_ADMIN/SYS_PTRACE`.

- The kali tools (`kali_exec.ts`, `kali_job_wait.ts`, `kali_job_stdin.ts`) consume only the `Interface`, so add a **microsandbox‑backed implementation of the same `Interface`**: map `exec`/`execBackground`/`jobTail`/`jobStdin` onto the SDK exec channel / agentd, recreating the `/work/jobs/<id>/{done,exitcode,output}` job convention in the guest.
- Replace `ensureKaliContainer` with booting `vxcontrol/kali-linux` in a microsandbox VM with `network.mode = "raw-tap"` (Linux) / `"raw-unixgram"` (macOS). **The `--cap-add` flags disappear** — `CAP_NET_RAW` works inside the guest kernel automatically.
- No changes to `kali_exec.ts` / `kali_job_*.ts` or their IPC. Provider is a per‑platform Effect `Layer`, so **Docker stays as the macOS fallback** for the raw slice.

---

## 8. Open uncertainties to retire (in order)

1. **KVM availability** on the chosen runner (Phase 0 gate).
2. Guest virtio‑net **TAP offload negotiation** (VNET_HDR/TSO; the `msb_krun` TAP path has a hardcoded `vnethdrsz` TODO).
3. **Reverse‑path conntrack** — replies (SYN‑ACK/RST, ICMP time‑exceeded) actually NAT back to the guest.
4. **vfkit framing** — `send_vfkit_magic=true` wire format vs `vmnet-helper` (1‑day spike before Phase 3 build).
5. The exact **IP protocols vmnet SHARED‑NAT forwards** (raw‑IP, GRE, non‑echo ICMP) — empirical test in‑guest.
6. Whether the Orgn Apple identity can obtain `com.apple.vm.networking` — **business gate, not code** (only if full macOS masscan/traceroute fidelity is required).

---

## Appendix A — Phase 0 runbook (Linux + KVM host)

Run on a host with `/dev/kvm` and `CAP_NET_ADMIN`. Replace `<uplink>` with the host's egress NIC (e.g. `eth0`).

```sh
# 1. Host TAP + NAT (one-time)
sudo ip tuntap add dev msbtap0 mode tap user "$(id -u)"
sudo ip addr add 10.0.42.1/24 dev msbtap0
sudo ip link set msbtap0 up
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 10.0.42.0/24 -o <uplink> -j MASQUERADE
# Allow replies to NAT back (relax INVALID drop if a firewall is present):
sudo iptables -A FORWARD -i msbtap0 -s 10.0.42.0/24 -j ACCEPT
sudo iptables -A FORWARD -o msbtap0 -d 10.0.42.0/24 -m state --state RELATED,ESTABLISHED -j ACCEPT

# 2. Boot the Kali guest with the TAP backend
#    (shortcut at crates/runtime/lib/vm.rs:1260 -> n.mac(mac).tap("msbtap0"), behind an env flag)
#    Inject guest net env: IP 10.0.42.2/24, gw 10.0.42.1, dns 1.1.1.1
msb run -i vxcontrol/kali-linux --name bbraw   # (with the Phase-0 tap shortcut compiled in)

# 3. Verify raw egress on the host TAP while scanning from inside the guest
sudo tcpdump -ni msbtap0 'tcp[tcpflags] & tcp-syn != 0' &
msb exec bbraw -- nmap -sS -Pn -p 22,80,443 scanme.nmap.org   # expect raw SYNs, NO host-completed handshake
msb exec bbraw -- nmap -sS -Pn 10.0.0.0/24                     # internal/RFC1918 reachability
msb exec bbraw -- ping -c2 1.1.1.1                             # ICMP echo
msb exec bbraw -- traceroute -n 1.1.1.1                        # multi-hop (Linux raw path should show intermediate hops)
# masscan needs an in-guest rule so the guest kernel doesn't RST its own stateless scan:
msb exec bbraw -- sh -c 'iptables -A INPUT -p tcp --dport 40000:41000 -j DROP; masscan -p443 scanme.nmap.org --rate 100 --source-port 40000'
```

**Pass criteria:** `tcpdump` shows SYNs leaving `msbtap0` with **no full 3‑way handshake originated by the host**, SYN‑ACK/RST replies return to the guest, `nmap` reports accurate `open/closed`, ICMP echo + multi‑hop traceroute work. Compare against the same scans in `smoltcp` mode (which will show host‑completed connects and single‑hop traceroute) to prove the difference.

---

## Appendix B — primary sources

- libkrun `unixgram` + vfkit flag: `https://raw.githubusercontent.com/containers/libkrun/refs/heads/main/include/libkrun.h`, `https://github.com/libkrun/krunkit/blob/main/docs/usage.md`
- vmnet modes vs entitlement (Apple DTS): `https://developer.apple.com/forums/thread/710763`
- Restricted entitlement + root‑helper model: `https://github.com/lima-vm/socket_vmnet`, `https://github.com/nirs/vmnet-helper`
- NAT breaks path/TTL tooling: `https://docs.thousandeyes.com/product-documentation/internet-and-wan-monitoring/path-visualization/troubleshooting/virtual-machine-with-nat-breaks-path-visualization`
- nmap SYN scan / masscan host‑RST caveat: `https://nmap.org/book/synscan.html`, `https://github.com/robertdavidgraham/masscan`
