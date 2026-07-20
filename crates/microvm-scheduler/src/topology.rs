//! Host CPU/memory topology and NUMA metadata (plan todo 24).
//!
//! [`HostTopology`] is the **preflight-supplied** description of a single host:
//! total logical CPU count, total memory, and an *optional* set of NUMA nodes.
//! The scheduler is a pure bin-packer over this topology; the NUMA nodes (when
//! present) are the bins. When no NUMA topology is supplied the host is treated
//! as one flat bin and the scheduler makes **no** NUMA-awareness claim.
//!
//! This module performs no I/O. Topology is validated at construction time and
//! is safe to serialize across transport boundaries.

use microvm_errors::{ErrorCode, MicrovmError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Maximum length in bytes for a host identifier (mirrors the platform-wide
/// identifier rules in `microvm-types`).
pub const MAX_HOST_ID_BYTES: usize = 64;

/// A validated host identifier.
///
/// Follows the same rules as the platform identifier types in `microvm-types`:
/// non-empty, ≤ [`MAX_HOST_ID_BYTES`] bytes, no `/`, no `..`, no uppercase
/// ASCII, and only `a-z 0-9 - _ .`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HostId(String);

impl HostId {
    /// Create a new validated host identifier.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidId`] if the identifier violates the platform
    /// identifier rules.
    pub fn new(raw: impl Into<String>) -> Result<Self, MicrovmError> {
        let s = raw.into();
        validate_host_id(&s)?;
        Ok(Self(s))
    }

    /// Return the identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_host_id(raw: &str) -> Result<(), MicrovmError> {
    let invalid = |reason: &str| {
        MicrovmError::new(ErrorCode::InvalidId, "invalid host identifier")
            .with_context("reason", reason)
    };
    if raw.is_empty() {
        return Err(invalid("identifier must not be empty"));
    }
    if raw.len() > MAX_HOST_ID_BYTES {
        return Err(invalid("identifier exceeds maximum length"));
    }
    if raw.contains('/') {
        return Err(invalid("identifier must not contain '/'"));
    }
    if raw.contains("..") {
        return Err(invalid("identifier must not contain '..'"));
    }
    if raw.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(invalid("identifier must not contain uppercase letters"));
    }
    if !raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(invalid("allowed characters: a-z 0-9 - _ ."));
    }
    Ok(())
}

impl fmt::Display for HostId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for HostId {
    type Error = MicrovmError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl From<HostId> for String {
    fn from(id: HostId) -> Self {
        id.0
    }
}

impl AsRef<str> for HostId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A single NUMA node discovered by host preflight.
///
/// `cpus` is the set of logical CPU ids local to this node; `cpu_count` must
/// equal `cpus.len()`. Node bins are disjoint: a logical CPU belongs to at most
/// one node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumaNode {
    /// NUMA node id (e.g. the `N` in `/sys/devices/system/node/nodeN`).
    pub id: u32,
    /// Logical CPU ids local to this node.
    pub cpus: BTreeSet<u32>,
    /// Memory local to this node, in MiB.
    pub memory_mib: u64,
}

impl NumaNode {
    /// Number of CPUs local to this node.
    #[must_use]
    pub fn cpu_count(&self) -> u32 {
        u32::try_from(self.cpus.len()).unwrap_or(u32::MAX)
    }
}

/// Preflight-supplied topology for a single host.
///
/// # NUMA awareness is opt-in and evidence-backed
/// `numa_nodes` is `None` unless preflight actually discovered NUMA topology.
/// The scheduler refuses to make any NUMA-awareness claim (and rejects
/// NUMA-affinity requests) when `numa_nodes` is `None`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostTopology {
    /// Identifier for this host.
    pub host_id: HostId,
    /// Total logical CPU count on the host.
    pub cpu_count: u32,
    /// Total host memory in MiB.
    pub memory_mib: u64,
    /// NUMA nodes, if preflight discovered them. `None` => flat (non-NUMA) host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub numa_nodes: Option<Vec<NumaNode>>,
}

impl HostTopology {
    /// Build a validated host topology.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidResourceSpec`] when:
    /// - `cpu_count` or `memory_mib` is zero,
    /// - a NUMA node has an empty CPU set or a zero memory size,
    /// - NUMA node ids are not unique,
    /// - a NUMA node references a CPU id ≥ `cpu_count`,
    /// - two NUMA nodes claim the same CPU id, or
    /// - `numa_nodes` is `Some` but empty.
    pub fn new(
        host_id: HostId,
        cpu_count: u32,
        memory_mib: u64,
        numa_nodes: Option<Vec<NumaNode>>,
    ) -> Result<Self, MicrovmError> {
        if cpu_count == 0 {
            return Err(Self::spec_error("cpu_count must be greater than zero"));
        }
        if memory_mib == 0 {
            return Err(Self::spec_error("memory_mib must be greater than zero"));
        }
        if let Some(nodes) = &numa_nodes {
            Self::validate_nodes(cpu_count, nodes)?;
        }
        Ok(Self {
            host_id,
            cpu_count,
            memory_mib,
            numa_nodes,
        })
    }

    /// Build a flat (non-NUMA) topology with no NUMA awareness.
    ///
    /// # Errors
    /// See [`HostTopology::new`].
    pub fn flat(host_id: HostId, cpu_count: u32, memory_mib: u64) -> Result<Self, MicrovmError> {
        Self::new(host_id, cpu_count, memory_mib, None)
    }

    /// Whether this topology carries preflight NUMA metadata.
    #[must_use]
    pub fn is_numa_aware(&self) -> bool {
        self.numa_nodes.is_some()
    }

    fn spec_error(reason: &'static str) -> MicrovmError {
        MicrovmError::new(ErrorCode::InvalidResourceSpec, "invalid host topology")
            .with_context("reason", reason)
    }

    fn validate_nodes(cpu_count: u32, nodes: &[NumaNode]) -> Result<(), MicrovmError> {
        if nodes.is_empty() {
            return Err(Self::spec_error(
                "numa_nodes must not be empty when present",
            ));
        }
        let mut seen_node_ids = BTreeSet::new();
        let mut seen_cpus: BTreeSet<u32> = BTreeSet::new();
        for node in nodes {
            if !seen_node_ids.insert(node.id) {
                return Err(Self::spec_error("duplicate numa node id"));
            }
            if node.cpus.is_empty() {
                return Err(Self::spec_error("numa node has an empty cpu set"));
            }
            if node.memory_mib == 0 {
                return Err(Self::spec_error(
                    "numa node memory_mib must be greater than zero",
                ));
            }
            for cpu in &node.cpus {
                if *cpu >= cpu_count {
                    return Err(Self::spec_error("numa node references cpu id >= cpu_count"));
                }
                if !seen_cpus.insert(*cpu) {
                    return Err(Self::spec_error("numa nodes claim overlapping cpu ids"));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> HostId {
        HostId::new("host-0").unwrap()
    }

    #[test]
    fn valid_flat_topology() {
        let t = HostTopology::flat(host(), 8, 4096).unwrap();
        assert!(!t.is_numa_aware());
        assert_eq!(t.cpu_count, 8);
        assert_eq!(t.memory_mib, 4096);
    }

    #[test]
    fn zero_cpu_or_memory_rejected() {
        assert!(HostTopology::flat(host(), 0, 4096).is_err());
        assert!(HostTopology::flat(host(), 8, 0).is_err());
    }

    #[test]
    fn valid_numa_topology() {
        let nodes = vec![
            NumaNode {
                id: 0,
                cpus: [0, 1, 2, 3].into_iter().collect(),
                memory_mib: 2048,
            },
            NumaNode {
                id: 1,
                cpus: [4, 5, 6, 7].into_iter().collect(),
                memory_mib: 2048,
            },
        ];
        let t = HostTopology::new(host(), 8, 4096, Some(nodes)).unwrap();
        assert!(t.is_numa_aware());
    }

    #[test]
    fn empty_numa_vec_rejected() {
        assert!(HostTopology::new(host(), 8, 4096, Some(vec![])).is_err());
    }

    #[test]
    fn duplicate_node_id_rejected() {
        let nodes = vec![
            NumaNode {
                id: 0,
                cpus: [0, 1].into_iter().collect(),
                memory_mib: 1024,
            },
            NumaNode {
                id: 0,
                cpus: [2, 3].into_iter().collect(),
                memory_mib: 1024,
            },
        ];
        assert!(HostTopology::new(host(), 4, 2048, Some(nodes)).is_err());
    }

    #[test]
    fn overlapping_cpus_rejected() {
        let nodes = vec![
            NumaNode {
                id: 0,
                cpus: [0, 1].into_iter().collect(),
                memory_mib: 1024,
            },
            NumaNode {
                id: 1,
                cpus: [1, 2].into_iter().collect(),
                memory_mib: 1024,
            },
        ];
        assert!(HostTopology::new(host(), 4, 2048, Some(nodes)).is_err());
    }

    #[test]
    fn cpu_id_out_of_range_rejected() {
        let nodes = vec![NumaNode {
            id: 0,
            cpus: [0, 9].into_iter().collect(),
            memory_mib: 1024,
        }];
        assert!(HostTopology::new(host(), 4, 2048, Some(nodes)).is_err());
    }

    #[test]
    fn empty_node_cpu_set_rejected() {
        let nodes = vec![NumaNode {
            id: 0,
            cpus: BTreeSet::new(),
            memory_mib: 1024,
        }];
        assert!(HostTopology::new(host(), 4, 2048, Some(nodes)).is_err());
    }

    #[test]
    fn host_id_validation_rules() {
        assert!(HostId::new("host-0").is_ok());
        assert!(HostId::new("").is_err());
        assert!(HostId::new("Host").is_err());
        assert!(HostId::new("host/0").is_err());
        assert!(HostId::new("host..0").is_err());
        assert!(HostId::new("a".repeat(65)).is_err());
        assert!(HostId::new("a".repeat(64)).is_ok());
    }

    #[test]
    fn host_id_serde_roundtrip() {
        let id = host();
        let json = serde_json::to_string(&id).unwrap();
        let back: HostId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn numa_node_cpu_count() {
        let node = NumaNode {
            id: 0,
            cpus: [0, 1, 2].into_iter().collect(),
            memory_mib: 512,
        };
        assert_eq!(node.cpu_count(), 3);
    }
}
