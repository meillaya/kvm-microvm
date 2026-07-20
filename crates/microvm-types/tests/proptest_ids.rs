//! Property-based tests for identifier validation using proptest.

use microvm_types::*;
use proptest::prelude::*;

/// Strategy that generates valid identifiers: 1-64 chars from the allowed alphabet.
fn valid_id_strategy() -> impl Strategy<Value = String> {
    "[a-z0-9][a-z0-9._-]{0,63}".prop_filter("must not contain '..'", |s| !s.contains(".."))
}

proptest! {
    #[test]
    fn valid_ids_always_accepted(raw in valid_id_strategy()) {
        prop_assert!(VmId::new(raw.clone()).is_ok(), "rejected valid id: {}", raw);
        prop_assert!(ImageId::new(raw.clone()).is_ok());
        prop_assert!(SnapshotId::new(raw.clone()).is_ok());
        prop_assert!(TenantId::new(raw).is_ok());
    }

    #[test]
    fn ids_with_slash_always_rejected(
        prefix in "[a-z0-9]{1,10}",
        suffix in "[a-z0-9]{1,10}",
    ) {
        let raw = format!("{}/{}", prefix, suffix);
        prop_assert!(VmId::new(raw).is_err());
    }

    #[test]
    fn ids_with_dotdot_always_rejected(
        prefix in "[a-z0-9]{1,10}",
        suffix in "[a-z0-9]{1,10}",
    ) {
        let raw = format!("{}..{}", prefix, suffix);
        prop_assert!(VmId::new(raw).is_err());
    }

    #[test]
    fn ids_with_uppercase_always_rejected(
        prefix in "[a-z]{1,5}",
        upper in "[A-Z]{1,1}",
        suffix in "[a-z]{1,5}",
    ) {
        let raw = format!("{}{}{}", prefix, upper, suffix);
        prop_assert!(VmId::new(raw).is_err());
    }

    #[test]
    fn ids_over_64_bytes_always_rejected(extra in 1usize..100) {
        let raw = "a".repeat(64 + extra);
        prop_assert!(VmId::new(raw).is_err());
    }

    #[test]
    fn empty_id_always_rejected(_dummy in 0u8..1) {
        prop_assert!(VmId::new("").is_err());
        prop_assert!(ImageId::new("").is_err());
        prop_assert!(SnapshotId::new("").is_err());
        prop_assert!(TenantId::new("").is_err());
    }
}
