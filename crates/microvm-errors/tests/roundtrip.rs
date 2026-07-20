//! Serde round-trip and uniqueness tests for microvm-errors.

use microvm_errors::*;

#[test]
fn all_error_codes_roundtrip() {
    for code in ErrorCode::all() {
        let json = serde_json::to_string(code).expect("serialize");
        let back: ErrorCode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*code, back, "roundtrip failed for {:?}", code);
    }
}

#[test]
fn no_duplicate_code_strings() {
    let mut seen = std::collections::HashSet::new();
    for code in ErrorCode::all() {
        let s = code.as_str();
        assert!(
            seen.insert(s),
            "duplicate error code string '{}' from variant {:?}",
            s,
            code
        );
    }
}

#[test]
fn microvm_error_roundtrip_with_context() {
    let err = MicrovmError::new(ErrorCode::PathEscape, "symlink escape detected")
        .with_context("path", "/var/lib/microvm/../../etc/shadow")
        .with_context("tenant", "t-42");
    let json = serde_json::to_string_pretty(&err).expect("serialize");
    let back: MicrovmError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, back);
}

#[test]
fn microvm_error_roundtrip_without_context() {
    let err = MicrovmError::new(ErrorCode::CgroupUnavailable, "cgroup v2 not mounted");
    let json = serde_json::to_string(&err).expect("serialize");
    let back: MicrovmError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, back);
}

#[test]
fn all_codes_have_snake_case_strings() {
    for code in ErrorCode::all() {
        let s = code.as_str();
        assert!(
            s.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "error code string '{}' is not snake_case",
            s
        );
        assert!(
            !s.starts_with('_') && !s.ends_with('_') && !s.contains("__"),
            "error code string '{}' has malformed underscores",
            s
        );
    }
}
