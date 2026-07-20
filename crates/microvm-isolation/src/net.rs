//! Per-VM network namespace, TAP device, and nftables NAT management.
//!
//! This module owns the orchestrator's network isolation boundary. Each VM
//! receives a dedicated **network namespace** containing a single TAP device.
//! The host side of the TAP is addressed from a deterministic /24 subnet, and
//! NAT is applied via a generated **nftables** ruleset whose shape depends on
//! the VM's [`NetworkPolicy`].
//!
//! # Model
//! - One **network namespace** per VM (`/var/run/netns/microvm-<vm-id>`).
//! - One **TAP device** per VM inside its namespace, named `tap<slot>` (TAP
//!   names are limited to 15 bytes by `IFNAMSIZ`).
//! - A deterministic **address allocator** hands out host/guest pairs from a
//!   configurable /24 subnet (default `172.30.0.0/24`). The gateway is always
//!   `.1`; VMs start at `.2`.
//! - A pure **nftables ruleset generator** (`nft_ruleset`) renders the exact
//!   `nft -f` script the operator loads. `NatOnly` restricts forwarding to
//!   the host subnet; `EgressAllowed` masquerades to all destinations.
//!
//! # Error contract
//! All failures are typed [`MicrovmError`]s. Address exhaustion, invalid
//! configuration, and namespace/TAP setup failures yield
//! [`ErrorCode::NetworkSetupError`]. Invalid [`NetConfig`] values yield
//! [`ErrorCode::InvalidResourceSpec`].
//!
//! # Determinism
//! [`NetConfig`] validation, [`AddressAllocator`] slot arithmetic, and
//! [`nft_ruleset`] generation are **pure** — no filesystem, netlink, or
//! process calls. [`NetManager`] path computation is pure; its filesystem
//! operations take a configurable root and are exercised against a temporary
//! directory in the default test run. Actual namespace and TAP creation
//! require root and live behind the `privileged` feature.
//!
//! [`MicrovmError`]: microvm_errors::MicrovmError
//! [`ErrorCode::NetworkSetupError`]: microvm_errors::ErrorCode::NetworkSetupError
//! [`ErrorCode::InvalidResourceSpec`]: microvm_errors::ErrorCode::InvalidResourceSpec
//! [`NetworkPolicy`]: microvm_types::NetworkPolicy

use microvm_errors::{ErrorCode, MicrovmError};
use microvm_types::{NetworkPolicy, VmId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

/// Maximum TAP interface name length (Linux `IFNAMSIZ` is 16 including NUL).
pub const IFNAMSIZ: usize = 15;

/// Default subnet for VM address allocation: `172.30.0.0/24`.
pub const DEFAULT_SUBNET_OCTETS: [u8; 3] = [172, 30, 0];

/// Default subnet prefix length.
pub const DEFAULT_PREFIX_LEN: u8 = 24;

/// Default netns runtime directory.
pub const DEFAULT_NETNS_ROOT: &str = "/var/run/netns";

/// Default nftables table name for microVM NAT.
pub const NFT_TABLE: &str = "microvm_nat";

/// Maximum number of allocatable VM slots in a /24 (`.2` through `.254`).
pub const MAX_SLOTS: u8 = 253;

// ---------------------------------------------------------------------------
// NetConfig
// ---------------------------------------------------------------------------

/// Per-VM network configuration: the TAP device, addressing, and policy.
///
/// All fields are validated at construction time. The configuration is
/// deterministic and serializable — it can be produced by the
/// [`AddressAllocator`] or deserialized from a transport boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetConfig {
    /// The VM this configuration belongs to.
    vm_id: VmId,
    /// TAP device name inside the VM's network namespace (≤ 15 bytes).
    tap_name: String,
    /// Guest IP address assigned to the TAP inside the namespace.
    guest_ip: Ipv4Addr,
    /// Host-side (gateway) IP address for the TAP's peer.
    host_ip: Ipv4Addr,
    /// Subnet prefix length (e.g. `24` for a /24).
    prefix_len: u8,
    /// Network egress policy.
    policy: NetworkPolicy,
}

impl NetConfig {
    /// Create a new network configuration, validating all fields.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidResourceSpec`] if:
    /// - `tap_name` is empty or exceeds [`IFNAMSIZ`] bytes.
    /// - `guest_ip` equals `host_ip`.
    /// - `prefix_len` is 0 or greater than 30 (a /31 or /32 has no usable
    ///   host addresses for a point-to-point TAP link).
    /// - `policy` is [`NetworkPolicy::None`] (a `NetConfig` must not exist
    ///   for a VM with no network).
    pub fn new(
        vm_id: VmId,
        tap_name: impl Into<String>,
        guest_ip: Ipv4Addr,
        host_ip: Ipv4Addr,
        prefix_len: u8,
        policy: NetworkPolicy,
    ) -> Result<Self, MicrovmError> {
        let tap_name = tap_name.into();
        if tap_name.is_empty() {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "tap_name must not be empty",
            )
            .with_context("vm_id", vm_id.as_str()));
        }
        if tap_name.len() > IFNAMSIZ {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                format!(
                    "tap_name exceeds IFNAMSIZ ({} bytes): got {}",
                    IFNAMSIZ,
                    tap_name.len()
                ),
            )
            .with_context("vm_id", vm_id.as_str())
            .with_context("tap_name", &tap_name));
        }
        if guest_ip == host_ip {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "guest_ip and host_ip must differ",
            )
            .with_context("vm_id", vm_id.as_str()));
        }
        if prefix_len == 0 || prefix_len > 30 {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                format!("prefix_len must be 1..=30, got {}", prefix_len),
            )
            .with_context("vm_id", vm_id.as_str()));
        }
        if policy == NetworkPolicy::None {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "NetConfig requires a network policy other than None",
            )
            .with_context("vm_id", vm_id.as_str()));
        }
        Ok(Self {
            vm_id,
            tap_name,
            guest_ip,
            host_ip,
            prefix_len,
            policy,
        })
    }

    /// The VM this configuration belongs to.
    pub fn vm_id(&self) -> &VmId {
        &self.vm_id
    }

    /// TAP device name inside the VM's network namespace.
    pub fn tap_name(&self) -> &str {
        &self.tap_name
    }

    /// Guest IP address assigned to the TAP.
    pub fn guest_ip(&self) -> Ipv4Addr {
        self.guest_ip
    }

    /// Host-side (gateway) IP address.
    pub fn host_ip(&self) -> Ipv4Addr {
        self.host_ip
    }

    /// Subnet prefix length.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Network egress policy.
    pub fn policy(&self) -> NetworkPolicy {
        self.policy
    }

    /// The network namespace name for this VM (`microvm-<vm-id>`).
    pub fn netns_name(&self) -> String {
        netns_name(&self.vm_id)
    }

    /// The CIDR notation for the guest address (e.g. `172.30.0.2/24`).
    pub fn guest_cidr(&self) -> String {
        format!("{}/{}", self.guest_ip, self.prefix_len)
    }

    /// The CIDR notation for the host address (e.g. `172.30.0.1/24`).
    pub fn host_cidr(&self) -> String {
        format!("{}/{}", self.host_ip, self.prefix_len)
    }
}

impl fmt::Display for NetConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "net:{} tap={} guest={} host={}/{} policy={:?}",
            self.vm_id, self.tap_name, self.guest_ip, self.host_ip, self.prefix_len, self.policy
        )
    }
}

/// Compute the network namespace name for a VM.
pub fn netns_name(vm_id: &VmId) -> String {
    format!("microvm-{}", vm_id.as_str())
}

// ---------------------------------------------------------------------------
// AddressAllocator
// ---------------------------------------------------------------------------

/// Deterministic IP address allocator for VM TAP interfaces.
///
/// Allocates host/guest pairs from a /24 subnet. The gateway is always `.1`;
/// VMs receive `.2` through `.254`. Each slot maps to exactly one VM, and
/// the allocator tracks assignments in a sorted map for deterministic
/// iteration and serialization.
///
/// # Slot arithmetic
/// For the default subnet `172.30.0.0/24`:
/// - Slot 0 → guest `172.30.0.2`, host `172.30.0.1`
/// - Slot 1 → guest `172.30.0.3`, host `172.30.0.1`
/// - Slot 252 → guest `172.30.0.254`, host `172.30.0.1`
///
/// The host IP is shared (it is the gateway); the guest IP is unique per VM.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressAllocator {
    /// First three octets of the /24 subnet.
    subnet: [u8; 3],
    /// Prefix length (always 24 for this allocator).
    prefix_len: u8,
    /// Map from VM ID to allocated slot (0-based, guest = slot + 2).
    assignments: BTreeMap<String, u8>,
    /// Set of used slots (derived from assignments, kept for O(1) lookup).
    used_slots: Vec<bool>,
}

impl Default for AddressAllocator {
    fn default() -> Self {
        Self::new(DEFAULT_SUBNET_OCTETS)
    }
}

impl AddressAllocator {
    /// Create an allocator for the given /24 subnet with no assignments.
    pub fn new(subnet: [u8; 3]) -> Self {
        Self {
            subnet,
            prefix_len: DEFAULT_PREFIX_LEN,
            assignments: BTreeMap::new(),
            used_slots: vec![false; MAX_SLOTS as usize],
        }
    }

    /// The gateway (host) IP for this subnet (always `.1`).
    pub fn gateway(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.subnet[0], self.subnet[1], self.subnet[2], 1)
    }

    /// Compute the guest IP for a given slot (0-based).
    ///
    /// Slot 0 → `.2`, slot 1 → `.3`, …, slot 252 → `.254`.
    pub fn guest_ip_for_slot(&self, slot: u8) -> Ipv4Addr {
        Ipv4Addr::new(self.subnet[0], self.subnet[1], self.subnet[2], slot + 2)
    }

    /// The number of currently allocated slots.
    pub fn allocated_count(&self) -> usize {
        self.assignments.len()
    }

    /// The number of remaining free slots.
    pub fn free_count(&self) -> usize {
        MAX_SLOTS as usize - self.assignments.len()
    }

    /// The subnet prefix length.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Look up the slot assigned to a VM, if any.
    pub fn slot_for(&self, vm_id: &VmId) -> Option<u8> {
        self.assignments.get(vm_id.as_str()).copied()
    }

    /// Look up the VM assigned to a slot, if any.
    pub fn vm_for_slot(&self, slot: u8) -> Option<&str> {
        self.assignments
            .iter()
            .find(|(_, &s)| s == slot)
            .map(|(id, _)| id.as_str())
    }

    /// Allocate the next free slot for a VM and return a [`NetConfig`].
    ///
    /// The TAP name is derived from the slot: `tap<slot>` (always ≤ 15 bytes
    /// for slots 0–252).
    ///
    /// # Errors
    /// - [`ErrorCode::NetworkSetupError`] if all slots are exhausted.
    /// - [`ErrorCode::NetworkSetupError`] if the VM already has an allocation.
    /// - [`ErrorCode::InvalidResourceSpec`] if `policy` is
    ///   [`NetworkPolicy::None`].
    pub fn allocate(
        &mut self,
        vm_id: &VmId,
        policy: NetworkPolicy,
    ) -> Result<NetConfig, MicrovmError> {
        if self.assignments.contains_key(vm_id.as_str()) {
            return Err(MicrovmError::new(
                ErrorCode::NetworkSetupError,
                "VM already has a network allocation",
            )
            .with_context("vm_id", vm_id.as_str()));
        }

        let slot = self
            .used_slots
            .iter()
            .position(|&used| !used)
            .map(|i| i as u8)
            .ok_or_else(|| {
                MicrovmError::new(
                    ErrorCode::NetworkSetupError,
                    "address pool exhausted: all 253 slots allocated",
                )
                .with_context("vm_id", vm_id.as_str())
            })?;

        self.used_slots[slot as usize] = true;
        self.assignments.insert(vm_id.as_str().to_string(), slot);

        let tap_name = format!("tap{}", slot);
        NetConfig::new(
            vm_id.clone(),
            tap_name,
            self.guest_ip_for_slot(slot),
            self.gateway(),
            self.prefix_len,
            policy,
        )
    }

    /// Release the slot held by a VM, making it available for reuse.
    ///
    /// Returns the freed slot number, or `None` if the VM had no allocation.
    pub fn release(&mut self, vm_id: &VmId) -> Option<u8> {
        if let Some(slot) = self.assignments.remove(vm_id.as_str()) {
            self.used_slots[slot as usize] = false;
            Some(slot)
        } else {
            None
        }
    }

    /// Build a [`NetConfig`] for an already-allocated VM without mutating
    /// state. Useful for reconstructing configuration after a restart.
    ///
    /// # Errors
    /// Returns [`ErrorCode::NetworkSetupError`] if the VM has no allocation.
    pub fn config_for(
        &self,
        vm_id: &VmId,
        policy: NetworkPolicy,
    ) -> Result<NetConfig, MicrovmError> {
        let slot = self.slot_for(vm_id).ok_or_else(|| {
            MicrovmError::new(ErrorCode::NetworkSetupError, "VM has no network allocation")
                .with_context("vm_id", vm_id.as_str())
        })?;
        let tap_name = format!("tap{}", slot);
        NetConfig::new(
            vm_id.clone(),
            tap_name,
            self.guest_ip_for_slot(slot),
            self.gateway(),
            self.prefix_len,
            policy,
        )
    }
}

// ---------------------------------------------------------------------------
// nft_ruleset
// ---------------------------------------------------------------------------

/// Generate a deterministic nftables ruleset for microVM NAT.
///
/// The output is a complete `nft -f` script that:
/// 1. Flushes and recreates the [`NFT_TABLE`] inet table.
/// 2. Creates a `postrouting` chain with a masquerade rule for each VM
///    config, scoped by the VM's guest IP.
/// 3. For [`NetworkPolicy::NatOnly`], the masquerade is restricted to the
///    host subnet (VM can reach the gateway but not external networks).
/// 4. For [`NetworkPolicy::EgressAllowed`], the masquerade applies to all
///    destinations.
///
/// This function is **pure**: it performs no I/O and always produces the
/// same output for the same input.
///
/// # Panics
/// Does not panic; the caller is responsible for passing valid configs.
pub fn nft_ruleset(configs: &[NetConfig]) -> String {
    let mut out = String::with_capacity(512 + configs.len() * 160);

    out.push_str("#!/usr/sbin/nft -f\n");
    out.push_str("# Auto-generated by microvm-isolation. Do not edit.\n");
    out.push_str(&format!("flush table inet {}\n", NFT_TABLE));
    out.push_str(&format!("table inet {} {{\n", NFT_TABLE));

    // -- postrouting chain (SNAT / masquerade) --
    out.push_str("    chain postrouting {\n");
    out.push_str("        type nat hook postrouting priority srcnat; policy accept;\n");

    for cfg in configs {
        let guest = cfg.guest_ip();
        match cfg.policy() {
            NetworkPolicy::EgressAllowed => {
                out.push_str(&format!(
                    "        ip saddr {} masquerade comment \"vm:{}\"\n",
                    guest,
                    cfg.vm_id().as_str()
                ));
            }
            NetworkPolicy::NatOnly => {
                // Restrict masquerade to the host subnet only.
                let host_cidr = cfg.host_cidr();
                out.push_str(&format!(
                    "        ip saddr {} ip daddr {} masquerade comment \"vm:{} nat-only\"\n",
                    guest,
                    host_cidr,
                    cfg.vm_id().as_str()
                ));
            }
            NetworkPolicy::None => {
                // A NetConfig with None policy cannot exist (validated at
                // construction), but handle defensively.
                out.push_str(&format!(
                    "        # vm:{} policy=none (no rule)\n",
                    cfg.vm_id().as_str()
                ));
            }
        }
    }

    out.push_str("    }\n");

    // -- forward chain (inter-VM isolation) --
    out.push_str("    chain forward {\n");
    out.push_str("        type filter hook forward priority filter; policy drop;\n");
    out.push_str("        # Allow established/related return traffic.\n");
    out.push_str("        ct state established,related accept\n");
    out.push_str("        # Allow VM-to-gateway traffic.\n");

    for cfg in configs {
        let guest = cfg.guest_ip();
        let host = cfg.host_ip();
        out.push_str(&format!(
            "        ip saddr {} ip daddr {} accept comment \"vm:{} to-gw\"\n",
            guest,
            host,
            cfg.vm_id().as_str()
        ));
        if cfg.policy() == NetworkPolicy::EgressAllowed {
            out.push_str(&format!(
                "        ip saddr {} accept comment \"vm:{} egress\"\n",
                guest,
                cfg.vm_id().as_str()
            ));
        }
    }

    out.push_str("    }\n");
    out.push_str("}\n");

    out
}

// ---------------------------------------------------------------------------
// NetManager
// ---------------------------------------------------------------------------

/// Manages per-VM network namespace lifecycle and TAP device paths.
///
/// Path computation and namespace naming are **pure**. Filesystem operations
/// (creating the netns mount-point file, writing the nftables script) take a
/// configurable root so they can be exercised against a temporary directory
/// without root. Actual `ip netns add`, `ip tuntap add`, and `nft -f`
/// invocations require `CAP_NET_ADMIN` and live behind the `privileged`
/// feature.
#[derive(Clone, Debug)]
pub struct NetManager {
    netns_root: PathBuf,
    allocator: AddressAllocator,
}

impl Default for NetManager {
    fn default() -> Self {
        Self::new(DEFAULT_NETNS_ROOT)
    }
}

impl NetManager {
    /// Create a manager with the given netns root directory and a default
    /// address allocator.
    pub fn new(netns_root: impl Into<PathBuf>) -> Self {
        Self {
            netns_root: netns_root.into(),
            allocator: AddressAllocator::default(),
        }
    }

    /// Create a manager with a custom subnet.
    pub fn with_subnet(netns_root: impl Into<PathBuf>, subnet: [u8; 3]) -> Self {
        Self {
            netns_root: netns_root.into(),
            allocator: AddressAllocator::new(subnet),
        }
    }

    /// The netns root directory.
    pub fn netns_root(&self) -> &Path {
        &self.netns_root
    }

    /// A reference to the underlying address allocator.
    pub fn allocator(&self) -> &AddressAllocator {
        &self.allocator
    }

    /// A mutable reference to the underlying address allocator.
    pub fn allocator_mut(&mut self) -> &mut AddressAllocator {
        &mut self.allocator
    }

    /// The network namespace path for a VM.
    pub fn netns_path(&self, vm_id: &VmId) -> PathBuf {
        self.netns_root.join(netns_name(vm_id))
    }

    /// The path where the generated nftables script is written.
    pub fn nft_script_path(&self) -> PathBuf {
        self.netns_root.join("microvm-nat.nft")
    }

    /// Allocate a network configuration for a VM and create the netns
    /// mount-point file.
    ///
    /// This is the deterministic (non-privileged) portion: it allocates an
    /// address, creates the netns root directory if needed, and writes an
    /// empty mount-point file. The actual `ip netns add` bind-mount and TAP
    /// creation require root.
    ///
    /// # Errors
    /// - [`ErrorCode::NetworkSetupError`] on address exhaustion or duplicate
    ///   allocation.
    /// - [`ErrorCode::NetworkSetupError`] if the netns root cannot be created.
    pub fn setup_netns(
        &mut self,
        vm_id: &VmId,
        policy: NetworkPolicy,
    ) -> Result<NetConfig, MicrovmError> {
        let config = self.allocator.allocate(vm_id, policy)?;

        std::fs::create_dir_all(&self.netns_root).map_err(|e| {
            MicrovmError::new(
                ErrorCode::NetworkSetupError,
                format!("failed to create netns root: {}", e),
            )
            .with_context("path", self.netns_root.display().to_string())
        })?;

        let ns_path = self.netns_path(vm_id);
        std::fs::write(&ns_path, "").map_err(|e| {
            MicrovmError::new(
                ErrorCode::NetworkSetupError,
                format!("failed to create netns mount point: {}", e),
            )
            .with_context("path", ns_path.display().to_string())
        })?;

        Ok(config)
    }

    /// Write the nftables ruleset for all currently allocated VMs.
    ///
    /// The script is written to [`nft_script_path`](Self::nft_script_path).
    /// Loading it with `nft -f` requires root.
    ///
    /// # Errors
    /// Returns [`ErrorCode::NetworkSetupError`] if the file cannot be written.
    pub fn write_nft_ruleset(&self, configs: &[NetConfig]) -> Result<PathBuf, MicrovmError> {
        let script = nft_ruleset(configs);
        let path = self.nft_script_path();
        std::fs::write(&path, &script).map_err(|e| {
            MicrovmError::new(
                ErrorCode::NetworkSetupError,
                format!("failed to write nft ruleset: {}", e),
            )
            .with_context("path", path.display().to_string())
        })?;
        Ok(path)
    }

    /// Tear down a VM's network namespace mount point and release its address.
    ///
    /// Removes the netns file and releases the allocator slot. Idempotent:
    /// tearing down a VM with no namespace file is a no-op.
    ///
    /// # Errors
    /// Returns [`ErrorCode::NetworkSetupError`] if the file exists but cannot
    /// be removed.
    pub fn teardown_netns(&mut self, vm_id: &VmId) -> Result<(), MicrovmError> {
        let ns_path = self.netns_path(vm_id);
        if ns_path.exists() {
            std::fs::remove_file(&ns_path).map_err(|e| {
                MicrovmError::new(
                    ErrorCode::NetworkSetupError,
                    format!("failed to remove netns mount point: {}", e),
                )
                .with_context("path", ns_path.display().to_string())
            })?;
        }
        self.allocator.release(vm_id);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn vm(name: &str) -> VmId {
        VmId::new(name).unwrap()
    }

    // -- NetConfig validation -----------------------------------------------

    #[test]
    fn valid_net_config() {
        let cfg = NetConfig::new(
            vm("vm-001"),
            "tap0",
            Ipv4Addr::new(172, 30, 0, 2),
            Ipv4Addr::new(172, 30, 0, 1),
            24,
            NetworkPolicy::EgressAllowed,
        )
        .unwrap();
        assert_eq!(cfg.vm_id().as_str(), "vm-001");
        assert_eq!(cfg.tap_name(), "tap0");
        assert_eq!(cfg.guest_ip(), Ipv4Addr::new(172, 30, 0, 2));
        assert_eq!(cfg.host_ip(), Ipv4Addr::new(172, 30, 0, 1));
        assert_eq!(cfg.prefix_len(), 24);
        assert_eq!(cfg.policy(), NetworkPolicy::EgressAllowed);
        assert_eq!(cfg.netns_name(), "microvm-vm-001");
        assert_eq!(cfg.guest_cidr(), "172.30.0.2/24");
        assert_eq!(cfg.host_cidr(), "172.30.0.1/24");
    }

    #[test]
    fn net_config_rejects_empty_tap_name() {
        let err = NetConfig::new(
            vm("vm-001"),
            "",
            Ipv4Addr::new(172, 30, 0, 2),
            Ipv4Addr::new(172, 30, 0, 1),
            24,
            NetworkPolicy::NatOnly,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    }

    #[test]
    fn net_config_rejects_long_tap_name() {
        let long_name = "a".repeat(16);
        let err = NetConfig::new(
            vm("vm-001"),
            long_name,
            Ipv4Addr::new(172, 30, 0, 2),
            Ipv4Addr::new(172, 30, 0, 1),
            24,
            NetworkPolicy::NatOnly,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
        assert!(err.context.contains_key("tap_name"));
    }

    #[test]
    fn net_config_accepts_max_length_tap_name() {
        let name = "a".repeat(IFNAMSIZ);
        assert!(NetConfig::new(
            vm("vm-001"),
            name,
            Ipv4Addr::new(172, 30, 0, 2),
            Ipv4Addr::new(172, 30, 0, 1),
            24,
            NetworkPolicy::NatOnly,
        )
        .is_ok());
    }

    #[test]
    fn net_config_rejects_same_guest_host_ip() {
        let err = NetConfig::new(
            vm("vm-001"),
            "tap0",
            Ipv4Addr::new(172, 30, 0, 1),
            Ipv4Addr::new(172, 30, 0, 1),
            24,
            NetworkPolicy::NatOnly,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    }

    #[test]
    fn net_config_rejects_zero_prefix() {
        let err = NetConfig::new(
            vm("vm-001"),
            "tap0",
            Ipv4Addr::new(172, 30, 0, 2),
            Ipv4Addr::new(172, 30, 0, 1),
            0,
            NetworkPolicy::NatOnly,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    }

    #[test]
    fn net_config_rejects_prefix_over_30() {
        let err = NetConfig::new(
            vm("vm-001"),
            "tap0",
            Ipv4Addr::new(172, 30, 0, 2),
            Ipv4Addr::new(172, 30, 0, 1),
            31,
            NetworkPolicy::NatOnly,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    }

    #[test]
    fn net_config_rejects_none_policy() {
        let err = NetConfig::new(
            vm("vm-001"),
            "tap0",
            Ipv4Addr::new(172, 30, 0, 2),
            Ipv4Addr::new(172, 30, 0, 1),
            24,
            NetworkPolicy::None,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    }

    #[test]
    fn net_config_serde_roundtrip() {
        let cfg = NetConfig::new(
            vm("vm-001"),
            "tap0",
            Ipv4Addr::new(172, 30, 0, 2),
            Ipv4Addr::new(172, 30, 0, 1),
            24,
            NetworkPolicy::EgressAllowed,
        )
        .unwrap();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: NetConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn net_config_display() {
        let cfg = NetConfig::new(
            vm("vm-001"),
            "tap0",
            Ipv4Addr::new(172, 30, 0, 2),
            Ipv4Addr::new(172, 30, 0, 1),
            24,
            NetworkPolicy::NatOnly,
        )
        .unwrap();
        let s = cfg.to_string();
        assert!(s.contains("vm-001"));
        assert!(s.contains("tap0"));
        assert!(s.contains("172.30.0.2"));
    }

    // -- netns_name ---------------------------------------------------------

    #[test]
    fn netns_name_format() {
        assert_eq!(netns_name(&vm("vm-001")), "microvm-vm-001");
        assert_eq!(netns_name(&vm("web.server")), "microvm-web.server");
    }

    // -- AddressAllocator ---------------------------------------------------

    #[test]
    fn allocator_default_subnet() {
        let alloc = AddressAllocator::default();
        assert_eq!(alloc.gateway(), Ipv4Addr::new(172, 30, 0, 1));
        assert_eq!(alloc.prefix_len(), 24);
        assert_eq!(alloc.allocated_count(), 0);
        assert_eq!(alloc.free_count(), 253);
    }

    #[test]
    fn allocator_custom_subnet() {
        let alloc = AddressAllocator::new([10, 0, 0]);
        assert_eq!(alloc.gateway(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(alloc.guest_ip_for_slot(0), Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn allocator_slot_arithmetic() {
        let alloc = AddressAllocator::default();
        assert_eq!(alloc.guest_ip_for_slot(0), Ipv4Addr::new(172, 30, 0, 2));
        assert_eq!(alloc.guest_ip_for_slot(1), Ipv4Addr::new(172, 30, 0, 3));
        assert_eq!(alloc.guest_ip_for_slot(252), Ipv4Addr::new(172, 30, 0, 254));
    }

    #[test]
    fn allocator_sequential_allocation() {
        let mut alloc = AddressAllocator::default();
        let c1 = alloc
            .allocate(&vm("vm-a"), NetworkPolicy::EgressAllowed)
            .unwrap();
        let c2 = alloc.allocate(&vm("vm-b"), NetworkPolicy::NatOnly).unwrap();

        assert_eq!(c1.guest_ip(), Ipv4Addr::new(172, 30, 0, 2));
        assert_eq!(c1.tap_name(), "tap0");
        assert_eq!(c2.guest_ip(), Ipv4Addr::new(172, 30, 0, 3));
        assert_eq!(c2.tap_name(), "tap1");
        assert_eq!(alloc.allocated_count(), 2);
        assert_eq!(alloc.free_count(), 251);
    }

    #[test]
    fn allocator_rejects_duplicate_vm() {
        let mut alloc = AddressAllocator::default();
        alloc
            .allocate(&vm("vm-a"), NetworkPolicy::EgressAllowed)
            .unwrap();
        let err = alloc
            .allocate(&vm("vm-a"), NetworkPolicy::NatOnly)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NetworkSetupError);
        assert!(err.message.contains("already"));
    }

    #[test]
    fn allocator_rejects_none_policy() {
        let mut alloc = AddressAllocator::default();
        let err = alloc
            .allocate(&vm("vm-a"), NetworkPolicy::None)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    }

    #[test]
    fn allocator_release_and_reuse() {
        let mut alloc = AddressAllocator::default();
        alloc
            .allocate(&vm("vm-a"), NetworkPolicy::EgressAllowed)
            .unwrap();
        alloc
            .allocate(&vm("vm-b"), NetworkPolicy::EgressAllowed)
            .unwrap();

        let freed = alloc.release(&vm("vm-a"));
        assert_eq!(freed, Some(0));
        assert_eq!(alloc.allocated_count(), 1);

        // Next allocation reuses slot 0.
        let c = alloc.allocate(&vm("vm-c"), NetworkPolicy::NatOnly).unwrap();
        assert_eq!(c.guest_ip(), Ipv4Addr::new(172, 30, 0, 2));
        assert_eq!(c.tap_name(), "tap0");
    }

    #[test]
    fn allocator_release_unknown_vm_is_none() {
        let mut alloc = AddressAllocator::default();
        assert_eq!(alloc.release(&vm("vm-ghost")), None);
    }

    #[test]
    fn allocator_slot_lookup() {
        let mut alloc = AddressAllocator::default();
        alloc
            .allocate(&vm("vm-a"), NetworkPolicy::EgressAllowed)
            .unwrap();
        assert_eq!(alloc.slot_for(&vm("vm-a")), Some(0));
        assert_eq!(alloc.slot_for(&vm("vm-b")), None);
        assert_eq!(alloc.vm_for_slot(0), Some("vm-a"));
        assert_eq!(alloc.vm_for_slot(1), None);
    }

    #[test]
    fn allocator_config_for_existing() {
        let mut alloc = AddressAllocator::default();
        alloc
            .allocate(&vm("vm-a"), NetworkPolicy::EgressAllowed)
            .unwrap();
        let cfg = alloc
            .config_for(&vm("vm-a"), NetworkPolicy::NatOnly)
            .unwrap();
        assert_eq!(cfg.guest_ip(), Ipv4Addr::new(172, 30, 0, 2));
        assert_eq!(cfg.policy(), NetworkPolicy::NatOnly);
    }

    #[test]
    fn allocator_config_for_missing_vm() {
        let alloc = AddressAllocator::default();
        let err = alloc
            .config_for(&vm("vm-ghost"), NetworkPolicy::EgressAllowed)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NetworkSetupError);
    }

    #[test]
    fn allocator_exhaustion() {
        let mut alloc = AddressAllocator::default();
        for i in 0..MAX_SLOTS {
            let id = vm(&format!("vm-{:03}", i));
            alloc.allocate(&id, NetworkPolicy::EgressAllowed).unwrap();
        }
        assert_eq!(alloc.free_count(), 0);
        let err = alloc
            .allocate(&vm("vm-overflow"), NetworkPolicy::EgressAllowed)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NetworkSetupError);
        assert!(err.message.contains("exhausted"));
    }

    #[test]
    fn allocator_serde_roundtrip() {
        let mut alloc = AddressAllocator::default();
        alloc
            .allocate(&vm("vm-a"), NetworkPolicy::EgressAllowed)
            .unwrap();
        alloc.allocate(&vm("vm-b"), NetworkPolicy::NatOnly).unwrap();
        let json = serde_json::to_string(&alloc).unwrap();
        let back: AddressAllocator = serde_json::from_str(&json).unwrap();
        assert_eq!(alloc, back);
        assert_eq!(back.allocated_count(), 2);
    }

    // -- nft_ruleset --------------------------------------------------------

    #[test]
    fn nft_ruleset_empty() {
        let rules = nft_ruleset(&[]);
        assert!(rules.contains("#!/usr/sbin/nft -f"));
        assert!(rules.contains(&format!("flush table inet {}", NFT_TABLE)));
        assert!(rules.contains("chain postrouting"));
        assert!(rules.contains("chain forward"));
        assert!(rules.contains("ct state established,related accept"));
    }

    #[test]
    fn nft_ruleset_full_egress() {
        let cfg = NetConfig::new(
            vm("vm-web"),
            "tap0",
            Ipv4Addr::new(172, 30, 0, 2),
            Ipv4Addr::new(172, 30, 0, 1),
            24,
            NetworkPolicy::EgressAllowed,
        )
        .unwrap();
        let rules = nft_ruleset(&[cfg]);

        // Masquerade without destination restriction.
        assert!(rules.contains("ip saddr 172.30.0.2 masquerade comment \"vm:vm-web\""));
        // Forward chain allows egress.
        assert!(rules.contains("ip saddr 172.30.0.2 accept comment \"vm:vm-web egress\""));
        // Gateway traffic allowed.
        assert!(rules.contains(
            "ip saddr 172.30.0.2 ip daddr 172.30.0.1 accept comment \"vm:vm-web to-gw\""
        ));
    }

    #[test]
    fn nft_ruleset_nat_only() {
        let cfg = NetConfig::new(
            vm("vm-db"),
            "tap1",
            Ipv4Addr::new(172, 30, 0, 3),
            Ipv4Addr::new(172, 30, 0, 1),
            24,
            NetworkPolicy::NatOnly,
        )
        .unwrap();
        let rules = nft_ruleset(&[cfg]);

        // Masquerade restricted to host subnet.
        assert!(rules.contains(
            "ip saddr 172.30.0.3 ip daddr 172.30.0.1/24 masquerade comment \"vm:vm-db nat-only\""
        ));
        // No unrestricted egress rule.
        assert!(!rules.contains("vm:vm-db egress"));
        // Gateway traffic still allowed.
        assert!(rules
            .contains("ip saddr 172.30.0.3 ip daddr 172.30.0.1 accept comment \"vm:vm-db to-gw\""));
    }

    #[test]
    fn nft_ruleset_mixed_policies() {
        let c1 = NetConfig::new(
            vm("vm-a"),
            "tap0",
            Ipv4Addr::new(172, 30, 0, 2),
            Ipv4Addr::new(172, 30, 0, 1),
            24,
            NetworkPolicy::EgressAllowed,
        )
        .unwrap();
        let c2 = NetConfig::new(
            vm("vm-b"),
            "tap1",
            Ipv4Addr::new(172, 30, 0, 3),
            Ipv4Addr::new(172, 30, 0, 1),
            24,
            NetworkPolicy::NatOnly,
        )
        .unwrap();
        let rules = nft_ruleset(&[c1, c2]);

        assert!(rules.contains("vm:vm-a"));
        assert!(rules.contains("vm:vm-b"));
        // vm-a has egress, vm-b does not.
        assert!(rules.contains("vm:vm-a egress"));
        assert!(!rules.contains("vm:vm-b egress"));
    }

    #[test]
    fn nft_ruleset_is_deterministic() {
        let cfg = NetConfig::new(
            vm("vm-det"),
            "tap0",
            Ipv4Addr::new(172, 30, 0, 2),
            Ipv4Addr::new(172, 30, 0, 1),
            24,
            NetworkPolicy::EgressAllowed,
        )
        .unwrap();
        let r1 = nft_ruleset(std::slice::from_ref(&cfg));
        let r2 = nft_ruleset(&[cfg]);
        assert_eq!(r1, r2);
    }

    // -- NetManager ---------------------------------------------------------

    #[test]
    fn net_manager_paths() {
        let mgr = NetManager::new("/run/netns");
        assert_eq!(mgr.netns_root(), Path::new("/run/netns"));
        assert_eq!(
            mgr.netns_path(&vm("vm-001")),
            PathBuf::from("/run/netns/microvm-vm-001")
        );
        assert_eq!(
            mgr.nft_script_path(),
            PathBuf::from("/run/netns/microvm-nat.nft")
        );
    }

    #[test]
    fn net_manager_setup_and_teardown() {
        let tmp = TempDir::new().unwrap();
        let mut mgr = NetManager::new(tmp.path().join("netns"));

        let cfg = mgr
            .setup_netns(&vm("vm-001"), NetworkPolicy::EgressAllowed)
            .unwrap();
        assert_eq!(cfg.guest_ip(), Ipv4Addr::new(172, 30, 0, 2));
        assert!(mgr.netns_path(&vm("vm-001")).exists());
        assert_eq!(mgr.allocator().allocated_count(), 1);

        mgr.teardown_netns(&vm("vm-001")).unwrap();
        assert!(!mgr.netns_path(&vm("vm-001")).exists());
        assert_eq!(mgr.allocator().allocated_count(), 0);
    }

    #[test]
    fn net_manager_teardown_idempotent() {
        let tmp = TempDir::new().unwrap();
        let mut mgr = NetManager::new(tmp.path().join("netns"));

        mgr.setup_netns(&vm("vm-001"), NetworkPolicy::NatOnly)
            .unwrap();
        mgr.teardown_netns(&vm("vm-001")).unwrap();
        // Second teardown is a no-op.
        mgr.teardown_netns(&vm("vm-001")).unwrap();
    }

    #[test]
    fn net_manager_write_nft_ruleset() {
        let tmp = TempDir::new().unwrap();
        let mut mgr = NetManager::new(tmp.path().join("netns"));

        let cfg = mgr
            .setup_netns(&vm("vm-001"), NetworkPolicy::EgressAllowed)
            .unwrap();
        let path = mgr.write_nft_ruleset(&[cfg]).unwrap();
        assert!(path.exists());

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("#!/usr/sbin/nft -f"));
        assert!(contents.contains("172.30.0.2"));
    }

    #[test]
    fn net_manager_multiple_vms() {
        let tmp = TempDir::new().unwrap();
        let mut mgr = NetManager::new(tmp.path().join("netns"));

        let c1 = mgr
            .setup_netns(&vm("vm-a"), NetworkPolicy::EgressAllowed)
            .unwrap();
        let c2 = mgr
            .setup_netns(&vm("vm-b"), NetworkPolicy::NatOnly)
            .unwrap();

        assert_ne!(c1.guest_ip(), c2.guest_ip());
        assert!(mgr.netns_path(&vm("vm-a")).exists());
        assert!(mgr.netns_path(&vm("vm-b")).exists());
        assert_eq!(mgr.allocator().allocated_count(), 2);

        // Write combined ruleset.
        let path = mgr.write_nft_ruleset(&[c1, c2]).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("vm:vm-a"));
        assert!(contents.contains("vm:vm-b"));

        // Teardown one, other remains.
        mgr.teardown_netns(&vm("vm-a")).unwrap();
        assert!(!mgr.netns_path(&vm("vm-a")).exists());
        assert!(mgr.netns_path(&vm("vm-b")).exists());
        assert_eq!(mgr.allocator().allocated_count(), 1);
    }

    #[test]
    fn net_manager_with_custom_subnet() {
        let tmp = TempDir::new().unwrap();
        let mut mgr = NetManager::with_subnet(tmp.path().join("netns"), [10, 100, 0]);

        let cfg = mgr
            .setup_netns(&vm("vm-x"), NetworkPolicy::EgressAllowed)
            .unwrap();
        assert_eq!(cfg.guest_ip(), Ipv4Addr::new(10, 100, 0, 2));
        assert_eq!(cfg.host_ip(), Ipv4Addr::new(10, 100, 0, 1));
    }

    #[test]
    fn net_manager_duplicate_setup_fails() {
        let tmp = TempDir::new().unwrap();
        let mut mgr = NetManager::new(tmp.path().join("netns"));

        mgr.setup_netns(&vm("vm-dup"), NetworkPolicy::EgressAllowed)
            .unwrap();
        let err = mgr
            .setup_netns(&vm("vm-dup"), NetworkPolicy::NatOnly)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NetworkSetupError);
    }

    // -- End-to-end lifecycle -----------------------------------------------

    #[test]
    fn end_to_end_net_lifecycle() {
        let tmp = TempDir::new().unwrap();
        let mut mgr = NetManager::new(tmp.path().join("netns"));

        // Allocate two VMs with different policies.
        let c1 = mgr
            .setup_netns(&vm("vm-web"), NetworkPolicy::EgressAllowed)
            .unwrap();
        let c2 = mgr
            .setup_netns(&vm("vm-db"), NetworkPolicy::NatOnly)
            .unwrap();

        // Addresses are deterministic and non-overlapping.
        assert_eq!(c1.guest_ip(), Ipv4Addr::new(172, 30, 0, 2));
        assert_eq!(c2.guest_ip(), Ipv4Addr::new(172, 30, 0, 3));
        assert_eq!(c1.host_ip(), c2.host_ip()); // shared gateway

        // Namespace mount points exist.
        assert!(mgr.netns_path(&vm("vm-web")).is_file());
        assert!(mgr.netns_path(&vm("vm-db")).is_file());

        // Generate and write the combined ruleset.
        let nft_path = mgr.write_nft_ruleset(&[c1.clone(), c2.clone()]).unwrap();
        let rules = std::fs::read_to_string(&nft_path).unwrap();

        // EgressAllowed VM gets unrestricted masquerade.
        assert!(rules.contains("ip saddr 172.30.0.2 masquerade"));
        // NatOnly VM gets restricted masquerade.
        assert!(rules.contains("ip saddr 172.30.0.3 ip daddr 172.30.0.1/24 masquerade"));
        // Forward chain has default-drop with explicit accepts.
        assert!(rules.contains("policy drop"));

        // Teardown vm-web; vm-db remains.
        mgr.teardown_netns(&vm("vm-web")).unwrap();
        assert!(!mgr.netns_path(&vm("vm-web")).exists());
        assert!(mgr.netns_path(&vm("vm-db")).is_file());

        // Freed slot is reusable.
        let c3 = mgr
            .setup_netns(&vm("vm-cache"), NetworkPolicy::EgressAllowed)
            .unwrap();
        assert_eq!(c3.guest_ip(), Ipv4Addr::new(172, 30, 0, 2)); // reused slot 0

        // Final teardown.
        mgr.teardown_netns(&vm("vm-db")).unwrap();
        mgr.teardown_netns(&vm("vm-cache")).unwrap();
        assert_eq!(mgr.allocator().allocated_count(), 0);
        assert_eq!(mgr.allocator().free_count(), 253);
    }
}
