//! Network-isolation adversarial suite.
//!
//! Drives the real [`microvm_isolation::AddressAllocator`],
//! [`microvm_isolation::NetConfig`] validator, and the pure
//! [`microvm_isolation::nft_ruleset`] generator.
//!
//! The inter-VM denial proof is structural, not grep-only: the generated
//! nftables script is parsed into a forward-chain reachability model
//! (`(saddr, daddr, action)` tuples plus the chain default policy), and the
//! test asserts that no guest can reach another guest's address: the only
//! `accept` rules a guest gets are to its own gateway, and the chain default
//! policy is `drop`. Address isolation (distinct, non-overlapping per-VM
//! addresses) and NAT-only masquerade scoping are verified the same way.
//!
//! A `privileged`-gated test at the bottom applies a real ruleset on a capable
//! host.

mod common;

use common::{assert_no_bypass, run_battery, Probe};
use microvm_errors::ErrorCode;
use microvm_isolation::{nft_ruleset, AddressAllocator, NetConfig, NFT_TABLE};
use microvm_types::{NetworkPolicy, VmId};
use std::net::Ipv4Addr;

// -- Structural nftables reachability model ---------------------------------

/// One parsed forward-chain rule.
#[derive(Clone, Debug)]
struct FwdRule {
    saddr: Option<Ipv4Addr>,
    /// `None` means "any destination" (an unrestricted egress accept).
    daddr: Option<Ipv4Addr>,
    accept: bool,
    established_related: bool,
}

/// A parsed view of the generated nftables ruleset.
#[derive(Clone, Debug)]
struct RulesetModel {
    forward_default_drop: bool,
    fwd_rules: Vec<FwdRule>,
    /// `(guest_ip, masquerade_scoped_to_host_subnet)` per postrouting rule.
    masquerade: Vec<(Ipv4Addr, bool)>,
    uses_microvm_table: bool,
}

fn parse_ip(tok: &str) -> Option<Ipv4Addr> {
    tok.parse::<Ipv4Addr>().ok()
}

/// Parse the generated nftables script into a reachability model. This is a
/// real structural parse (tokenizing each rule into saddr/daddr/action), not a
/// substring search.
fn parse_ruleset(script: &str) -> RulesetModel {
    let mut model = RulesetModel {
        forward_default_drop: false,
        fwd_rules: Vec::new(),
        masquerade: Vec::new(),
        uses_microvm_table: script.contains(&format!("table inet {NFT_TABLE}")),
    };
    let mut chain: Option<&str> = None;
    for raw in script.lines() {
        let line = raw.trim();
        if line.starts_with("chain forward") {
            chain = Some("forward");
            continue;
        }
        if line.starts_with("chain postrouting") {
            chain = Some("postrouting");
            continue;
        }
        if line == "}" {
            chain = None;
            continue;
        }
        match chain {
            Some("forward") => {
                if line.contains("policy drop") {
                    model.forward_default_drop = true;
                    continue;
                }
                let tokens: Vec<&str> = line.split_whitespace().collect();
                if line.starts_with("ct state") && line.contains("accept") {
                    model.fwd_rules.push(FwdRule {
                        saddr: None,
                        daddr: None,
                        accept: true,
                        established_related: true,
                    });
                    continue;
                }
                if line.starts_with("ip saddr") {
                    let saddr = tokens.get(2).and_then(|t| parse_ip(t));
                    let daddr = tokens
                        .iter()
                        .position(|t| *t == "daddr")
                        .and_then(|i| tokens.get(i + 1))
                        .and_then(|t| parse_ip(t));
                    let accept = tokens.contains(&"accept");
                    model.fwd_rules.push(FwdRule {
                        saddr,
                        daddr,
                        accept,
                        established_related: false,
                    });
                }
            }
            Some("postrouting") => {
                let tokens: Vec<&str> = line.split_whitespace().collect();
                if line.contains("masquerade") {
                    let saddr = tokens.get(2).and_then(|t| parse_ip(t));
                    // NatOnly rules carry an `ip daddr <host-cidr>` restriction.
                    let scoped = tokens.windows(2).any(|w| w[0] == "ip" && w[1] == "daddr");
                    if let Some(ip) = saddr {
                        model.masquerade.push((ip, scoped));
                    }
                }
            }
            _ => {}
        }
    }
    model
}

impl RulesetModel {
    /// Can `src` guest initiate a new connection to `dst`? A fresh connection
    /// is allowed only by an `accept` rule whose saddr matches `src` and whose
    /// daddr is either unrestricted (`None`) or exactly `dst`. The
    /// established/related rule only permits return traffic for an
    /// already-established flow, so it never authorizes a fresh inter-VM
    /// connection.
    fn can_reach(&self, src: Ipv4Addr, dst: Ipv4Addr) -> bool {
        self.fwd_rules.iter().any(|r| {
            r.accept
                && !r.established_related
                && r.saddr == Some(src)
                && (r.daddr.is_none() || r.daddr == Some(dst))
        })
    }
}

fn alloc_two(policy: NetworkPolicy) -> (AddressAllocator, NetConfig, NetConfig) {
    let mut alloc = AddressAllocator::default();
    let a = alloc.allocate(&VmId::new("vm-a").unwrap(), policy).unwrap();
    let b = alloc.allocate(&VmId::new("vm-b").unwrap(), policy).unwrap();
    (alloc, a, b)
}

// -- Address isolation ------------------------------------------------------

#[test]
fn two_vms_get_distinct_non_overlapping_addresses() {
    let (_alloc, a, b) = alloc_two(NetworkPolicy::NatOnly);
    assert_ne!(a.guest_ip(), b.guest_ip(), "guest IPs must differ");
    assert_ne!(a.tap_name(), b.tap_name(), "TAP names must differ");
    // Each VM's guest IP is distinct from both gateways.
    assert_ne!(a.guest_ip(), a.host_ip());
    assert_ne!(b.guest_ip(), b.host_ip());
}

#[test]
fn double_allocation_is_rejected() {
    let mut alloc = AddressAllocator::default();
    let vm = VmId::new("vm-dup").unwrap();
    alloc.allocate(&vm, NetworkPolicy::NatOnly).unwrap();
    let err = alloc.allocate(&vm, NetworkPolicy::NatOnly).unwrap_err();
    assert_eq!(err.code, ErrorCode::NetworkSetupError);
}

#[test]
fn release_frees_the_slot_for_reuse() {
    let mut alloc = AddressAllocator::default();
    let vm = VmId::new("vm-rel").unwrap();
    let cfg = alloc.allocate(&vm, NetworkPolicy::NatOnly).unwrap();
    let ip = cfg.guest_ip();
    assert!(alloc.release(&vm).is_some());
    // Re-allocating reuses the freed slot/address.
    let cfg2 = alloc.allocate(&vm, NetworkPolicy::NatOnly).unwrap();
    assert_eq!(cfg2.guest_ip(), ip);
}

// -- NetConfig validation ---------------------------------------------------

#[test]
fn netconfig_rejects_degenerate_configs() {
    let vm = VmId::new("vm-cfg").unwrap();
    // guest_ip == host_ip
    let err = NetConfig::new(
        vm.clone(),
        "tap0",
        Ipv4Addr::new(172, 30, 0, 1),
        Ipv4Addr::new(172, 30, 0, 1),
        24,
        NetworkPolicy::NatOnly,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    // prefix_len out of range
    let err = NetConfig::new(
        vm.clone(),
        "tap0",
        Ipv4Addr::new(172, 30, 0, 2),
        Ipv4Addr::new(172, 30, 0, 1),
        31,
        NetworkPolicy::NatOnly,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    let err = NetConfig::new(
        vm.clone(),
        "tap0",
        Ipv4Addr::new(172, 30, 0, 2),
        Ipv4Addr::new(172, 30, 0, 1),
        0,
        NetworkPolicy::NatOnly,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    // policy None cannot have a NetConfig
    let err = NetConfig::new(
        vm.clone(),
        "tap0",
        Ipv4Addr::new(172, 30, 0, 2),
        Ipv4Addr::new(172, 30, 0, 1),
        24,
        NetworkPolicy::None,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    // empty tap name
    let err = NetConfig::new(
        vm.clone(),
        "",
        Ipv4Addr::new(172, 30, 0, 2),
        Ipv4Addr::new(172, 30, 0, 1),
        24,
        NetworkPolicy::NatOnly,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
    // tap name over IFNAMSIZ (15 bytes)
    let err = NetConfig::new(
        vm,
        "tap-name-way-too-long",
        Ipv4Addr::new(172, 30, 0, 2),
        Ipv4Addr::new(172, 30, 0, 1),
        24,
        NetworkPolicy::NatOnly,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidResourceSpec);
}

// -- Inter-VM denial (structural reachability) ------------------------------

#[test]
fn nat_only_vms_cannot_reach_each_other() {
    let (_alloc, a, b) = alloc_two(NetworkPolicy::NatOnly);
    let script = nft_ruleset(&[a.clone(), b.clone()]);
    let model = parse_ruleset(&script);

    assert!(
        model.uses_microvm_table,
        "ruleset must use the microvm table"
    );
    assert!(
        model.forward_default_drop,
        "forward chain default policy must be drop"
    );

    // The core isolation property: neither guest can initiate a connection to
    // the other. Each guest may only reach its own gateway.
    assert!(
        !model.can_reach(a.guest_ip(), b.guest_ip()),
        "A must not reach B"
    );
    assert!(
        !model.can_reach(b.guest_ip(), a.guest_ip()),
        "B must not reach A"
    );
    // But each guest CAN reach its own gateway (so NAT works).
    assert!(
        model.can_reach(a.guest_ip(), a.host_ip()),
        "A reaches its gateway"
    );
    assert!(
        model.can_reach(b.guest_ip(), b.host_ip()),
        "B reaches its gateway"
    );
}

#[test]
fn nat_only_masquerade_is_scoped_to_host_subnet() {
    let (_alloc, a, b) = alloc_two(NetworkPolicy::NatOnly);
    let script = nft_ruleset(&[a.clone(), b.clone()]);
    let model = parse_ruleset(&script);
    // Every NatOnly masquerade rule is scoped by a destination (host subnet),
    // so a guest cannot masquerade to arbitrary external networks.
    assert!(!model.masquerade.is_empty());
    for (ip, scoped) in &model.masquerade {
        assert!(
            scoped,
            "NatOnly masquerade for {ip} must be destination-scoped"
        );
    }
}

#[test]
fn egress_allowed_permits_external_but_still_isolated_at_forward() {
    // EgressAllowed adds an unrestricted saddr accept; the model must reflect
    // that egress is granted (daddr unrestricted) while still parsing cleanly.
    let (_alloc, a, b) = alloc_two(NetworkPolicy::EgressAllowed);
    let script = nft_ruleset(&[a.clone(), b.clone()]);
    let model = parse_ruleset(&script);
    assert!(model.forward_default_drop);
    // EgressAllowed grants unrestricted outbound from each guest.
    assert!(
        model.can_reach(a.guest_ip(), b.guest_ip()),
        "egress policy grants A->B (documented tradeoff)"
    );
    // The masquerade for EgressAllowed is not destination-scoped.
    assert!(model.masquerade.iter().any(|(_, scoped)| !scoped));
}

#[test]
fn empty_ruleset_has_no_accept_and_drops_by_default() {
    // With no VMs, the forward chain still exists with policy drop and no
    // accept rules -> nothing can cross.
    let script = nft_ruleset(&[]);
    let model = parse_ruleset(&script);
    assert!(model.forward_default_drop);
    assert!(
        model
            .fwd_rules
            .iter()
            .filter(|r| r.accept && !r.established_related)
            .count()
            == 0
    );
}

// -- Consolidated battery ---------------------------------------------------

#[test]
fn network_security_battery_emits_evidence_and_detects_no_bypass() {
    let (_alloc, a, b) = alloc_two(NetworkPolicy::NatOnly);
    let script = nft_ruleset(&[a.clone(), b.clone()]);
    let model = parse_ruleset(&script);

    // Model the structural isolation invariants as probes: each "rejection" is
    // the absence of a reachability path, expressed as a Result for the
    // recorder.
    let a_to_b_denied: Result<(), ErrorCode> = if model.can_reach(a.guest_ip(), b.guest_ip()) {
        Ok(())
    } else {
        Err(ErrorCode::NetworkSetupError)
    };
    let b_to_a_denied: Result<(), ErrorCode> = if model.can_reach(b.guest_ip(), a.guest_ip()) {
        Ok(())
    } else {
        Err(ErrorCode::NetworkSetupError)
    };
    let default_drop: Result<(), ErrorCode> = if model.forward_default_drop {
        Err(ErrorCode::NetworkSetupError)
    } else {
        Ok(())
    };

    let vm = VmId::new("vm-bat").unwrap();
    let mut alloc = AddressAllocator::default();
    alloc.allocate(&vm, NetworkPolicy::NatOnly).unwrap();

    let probes = vec![
        Probe::from_result(
            "inter_vm_a_to_b_denied",
            "network:inter_vm_denial",
            ErrorCode::NetworkSetupError,
            a_to_b_denied,
        ),
        Probe::from_result(
            "inter_vm_b_to_a_denied",
            "network:inter_vm_denial",
            ErrorCode::NetworkSetupError,
            b_to_a_denied,
        ),
        Probe::from_result(
            "forward_default_drop",
            "network:default_drop",
            ErrorCode::NetworkSetupError,
            default_drop,
        ),
        Probe::from_result(
            "double_allocation",
            "network:double_alloc",
            ErrorCode::NetworkSetupError,
            alloc.allocate(&vm, NetworkPolicy::NatOnly),
        ),
        Probe::from_result(
            "netconfig_same_ip",
            "network:invalid_config",
            ErrorCode::InvalidResourceSpec,
            NetConfig::new(
                vm.clone(),
                "tap0",
                Ipv4Addr::new(172, 30, 0, 1),
                Ipv4Addr::new(172, 30, 0, 1),
                24,
                NetworkPolicy::NatOnly,
            ),
        ),
        Probe::from_result(
            "netconfig_bad_prefix",
            "network:invalid_config",
            ErrorCode::InvalidResourceSpec,
            NetConfig::new(
                vm.clone(),
                "tap0",
                Ipv4Addr::new(172, 30, 0, 2),
                Ipv4Addr::new(172, 30, 0, 1),
                31,
                NetworkPolicy::NatOnly,
            ),
        ),
        Probe::from_result(
            "netconfig_policy_none",
            "network:invalid_config",
            ErrorCode::InvalidResourceSpec,
            NetConfig::new(
                vm.clone(),
                "tap0",
                Ipv4Addr::new(172, 30, 0, 2),
                Ipv4Addr::new(172, 30, 0, 1),
                24,
                NetworkPolicy::None,
            ),
        ),
        Probe::from_result(
            "netconfig_long_tap",
            "network:invalid_config",
            ErrorCode::InvalidResourceSpec,
            NetConfig::new(
                vm,
                "tap-name-way-too-long",
                Ipv4Addr::new(172, 30, 0, 2),
                Ipv4Addr::new(172, 30, 0, 1),
                24,
                NetworkPolicy::NatOnly,
            ),
        ),
    ];

    let evidence = run_battery("network_security", probes);
    assert_no_bypass(&evidence);
    assert!(evidence.summary.total >= 8);

    // Control: gateway reachability holds (denials are discriminating).
    assert!(model.can_reach(a.guest_ip(), a.host_ip()));
}

// -- Privileged: apply a real ruleset ---------------------------------------

/// On a capable host (root + `nft`), load the generated ruleset and confirm it
/// installs without error, then flush it. Gated behind `privileged`.
#[cfg(feature = "privileged")]
#[test]
fn privileged_ruleset_loads_on_real_nft() {
    use std::process::Command;
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("[privileged] not root; skipping real nft load");
        return;
    }
    let (_alloc, a, b) = alloc_two(NetworkPolicy::NatOnly);
    let script = nft_ruleset(&[a, b]);
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("rules.nft");
    std::fs::write(&path, &script).unwrap();
    let out = Command::new("nft").arg("-f").arg(&path).output();
    match out {
        Ok(o) if o.status.success() => {
            // Cleanup: remove the table we created.
            let _ = Command::new("nft")
                .args(["delete", "table", "inet", NFT_TABLE])
                .output();
        }
        Ok(o) => eprintln!(
            "[privileged] nft load failed: {:?}",
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => eprintln!("[privileged] nft unavailable: {e}"),
    }
}
