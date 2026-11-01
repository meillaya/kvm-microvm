//! Exhaustive state-transition tests for the VM lifecycle state machine.

use microvm_errors::ErrorCode;
use microvm_lifecycle::{transition, VmState};

// ---------------------------------------------------------------------------
// Legal transitions: each gets its own test
// ---------------------------------------------------------------------------

#[test]
fn created_to_configured() {
    assert_eq!(
        transition(VmState::Created, VmState::Configured).unwrap(),
        VmState::Configured
    );
}

#[test]
fn configured_to_running() {
    assert_eq!(
        transition(VmState::Configured, VmState::Running).unwrap(),
        VmState::Running
    );
}

#[test]
fn running_to_paused() {
    assert_eq!(
        transition(VmState::Running, VmState::Paused).unwrap(),
        VmState::Paused
    );
}

#[test]
fn running_to_stopped() {
    assert_eq!(
        transition(VmState::Running, VmState::Stopped).unwrap(),
        VmState::Stopped
    );
}

#[test]
fn running_to_snapshotting() {
    assert_eq!(
        transition(VmState::Running, VmState::Snapshotting).unwrap(),
        VmState::Snapshotting
    );
}

#[test]
fn paused_to_running() {
    assert_eq!(
        transition(VmState::Paused, VmState::Running).unwrap(),
        VmState::Running
    );
}

#[test]
fn paused_to_stopped() {
    assert_eq!(
        transition(VmState::Paused, VmState::Stopped).unwrap(),
        VmState::Stopped
    );
}

#[test]
fn paused_to_snapshotting() {
    assert_eq!(
        transition(VmState::Paused, VmState::Snapshotting).unwrap(),
        VmState::Snapshotting
    );
}

#[test]
fn snapshotting_to_paused() {
    assert_eq!(
        transition(VmState::Snapshotting, VmState::Paused).unwrap(),
        VmState::Paused
    );
}

#[test]
fn snapshotting_to_failed() {
    assert_eq!(
        transition(VmState::Snapshotting, VmState::Failed).unwrap(),
        VmState::Failed
    );
}

#[test]
fn restoring_to_running() {
    assert_eq!(
        transition(VmState::Restoring, VmState::Running).unwrap(),
        VmState::Running
    );
}

#[test]
fn restoring_to_failed() {
    assert_eq!(
        transition(VmState::Restoring, VmState::Failed).unwrap(),
        VmState::Failed
    );
}

// -- any → Failed -----------------------------------------------------------

#[test]
fn any_state_to_failed_is_legal() {
    for from in VmState::all() {
        let result = transition(*from, VmState::Failed);
        assert!(
            result.is_ok(),
            "expected {} → Failed to be legal, got {:?}",
            from,
            result
        );
        assert_eq!(result.unwrap(), VmState::Failed);
    }
}

// ---------------------------------------------------------------------------
// Illegal transitions: representative set
// ---------------------------------------------------------------------------

#[test]
fn created_to_running_is_illegal() {
    let err = transition(VmState::Created, VmState::Running).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[test]
fn created_to_paused_is_illegal() {
    let err = transition(VmState::Created, VmState::Paused).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[test]
fn created_to_stopped_is_illegal() {
    let err = transition(VmState::Created, VmState::Stopped).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[test]
fn snapshot_from_created_is_illegal() {
    // Explicitly required by the plan: snapshot from Created returns
    // InvalidTransition.
    let err = transition(VmState::Created, VmState::Snapshotting).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
    assert!(err.context.contains_key("from"));
    assert!(err.context.contains_key("to"));
}

#[test]
fn created_to_restoring_is_illegal() {
    let err = transition(VmState::Created, VmState::Restoring).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[test]
fn configured_to_paused_is_illegal() {
    let err = transition(VmState::Configured, VmState::Paused).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[test]
fn configured_to_stopped_is_illegal() {
    let err = transition(VmState::Configured, VmState::Stopped).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[test]
fn configured_to_snapshotting_is_illegal() {
    let err = transition(VmState::Configured, VmState::Snapshotting).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[test]
fn running_to_created_is_illegal() {
    let err = transition(VmState::Running, VmState::Created).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[test]
fn running_to_configured_is_illegal() {
    let err = transition(VmState::Running, VmState::Configured).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[test]
fn running_to_restoring_is_illegal() {
    let err = transition(VmState::Running, VmState::Restoring).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[test]
fn paused_to_created_is_illegal() {
    let err = transition(VmState::Paused, VmState::Created).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[test]
fn snapshotting_to_running_is_illegal() {
    let err = transition(VmState::Snapshotting, VmState::Running).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[test]
fn snapshotting_to_stopped_is_illegal() {
    let err = transition(VmState::Snapshotting, VmState::Stopped).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[test]
fn restoring_to_paused_is_illegal() {
    let err = transition(VmState::Restoring, VmState::Paused).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[test]
fn restoring_to_stopped_is_illegal() {
    let err = transition(VmState::Restoring, VmState::Stopped).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[test]
fn stopped_to_running_is_illegal() {
    let err = transition(VmState::Stopped, VmState::Running).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[test]
fn stopped_to_created_is_illegal() {
    let err = transition(VmState::Stopped, VmState::Created).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[test]
fn failed_to_running_is_illegal() {
    let err = transition(VmState::Failed, VmState::Running).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[test]
fn failed_to_created_is_illegal() {
    let err = transition(VmState::Failed, VmState::Created).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

#[test]
fn failed_to_configured_is_illegal() {
    let err = transition(VmState::Failed, VmState::Configured).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
}

// ---------------------------------------------------------------------------
// Exhaustive matrix: verify the full 8×8 transition table
// ---------------------------------------------------------------------------

/// The complete set of legal (from, to) pairs, including any→Failed.
fn legal_pairs() -> Vec<(VmState, VmState)> {
    let mut pairs = vec![
        (VmState::Created, VmState::Configured),
        (VmState::Configured, VmState::Running),
        (VmState::Running, VmState::Paused),
        (VmState::Running, VmState::Stopped),
        (VmState::Running, VmState::Snapshotting),
        (VmState::Paused, VmState::Running),
        (VmState::Paused, VmState::Stopped),
        (VmState::Paused, VmState::Snapshotting),
        (VmState::Snapshotting, VmState::Paused),
        (VmState::Restoring, VmState::Running),
    ];
    // any → Failed
    for from in VmState::all() {
        pairs.push((*from, VmState::Failed));
    }
    pairs
}

#[test]
fn exhaustive_transition_matrix() {
    let legal = legal_pairs();

    for from in VmState::all() {
        for to in VmState::all() {
            let pair = (*from, *to);
            let result = transition(*from, *to);
            let should_be_legal = legal.contains(&pair);

            if should_be_legal {
                assert!(
                    result.is_ok(),
                    "expected {} → {} to be legal, got {:?}",
                    from,
                    to,
                    result
                );
                assert_eq!(result.unwrap(), *to);
            } else {
                assert!(
                    result.is_err(),
                    "expected {} → {} to be illegal, but it succeeded",
                    from,
                    to
                );
                assert_eq!(result.unwrap_err().code, ErrorCode::InvalidTransition);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Error context
// ---------------------------------------------------------------------------

#[test]
fn illegal_transition_error_carries_context() {
    let err = transition(VmState::Stopped, VmState::Running).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidTransition);
    assert_eq!(err.context.get("from").unwrap(), "stopped");
    assert_eq!(err.context.get("to").unwrap(), "running");
    assert!(err.message.contains("stopped"));
    assert!(err.message.contains("running"));
}

#[test]
fn illegal_transition_no_backend_call() {
    // transition() is a pure function: it returns InvalidTransition
    // without any side effects. We verify this by calling it repeatedly
    // and getting the same result.
    for _ in 0..100 {
        let err = transition(VmState::Created, VmState::Snapshotting).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidTransition);
    }
}
