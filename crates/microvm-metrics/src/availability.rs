//! Availability-flagged metric slots.
//!
//! The orchestrator's metrics contract requires that missing data is marked
//! unavailable, never zero-filled. A `0` in a metrics field
//! must mean "measured zero", not "we could not measure it". [`Availability`]
//! makes that distinction unrepresentable-as-zero by construction: a source
//! either produced a value ([`Availability::Available`]) or it did not
//! ([`Availability::Unavailable`], carrying a bounded [`UnavailableReason`]).
//!
//! # Wire format
//! Serializes to an explicit-flag shape so consumers can branch on a boolean
//! without inspecting presence:
//!
//! ```json
//! { "available": true,  "value": { ... } }
//! { "available": false, "reason": "agent_unreachable" }
//! ```

use serde::de::{self, Deserializer};
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};

/// Why a metric source could not produce a value.
///
/// This is a bounded, stable enum, never a free-form string, so error
/// labels cannot grow unboundedly (no high-cardinality labels). The
/// `snake_case` serialization is part of the stable wire contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableReason {
    /// The collector has no backend/source configured for this metric.
    NoBackend,
    /// The source (cgroup leaf, TAP sysfs dir, ...) does not exist or was
    /// removed while sampling.
    SourceMissing,
    /// The source existed but its contents could not be parsed.
    ParseError,
    /// Reading the source failed with an I/O error.
    ReadError,
    /// The guest agent did not respond / the vsock channel is unavailable.
    AgentUnreachable,
    /// A derived value is not ready yet (e.g. a throughput rate needs a
    /// previous sample to compute a delta).
    NotYetSampled,
}

impl UnavailableReason {
    /// Stable `snake_case` string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoBackend => "no_backend",
            Self::SourceMissing => "source_missing",
            Self::ParseError => "parse_error",
            Self::ReadError => "read_error",
            Self::AgentUnreachable => "agent_unreachable",
            Self::NotYetSampled => "not_yet_sampled",
        }
    }
}

impl std::fmt::Display for UnavailableReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A metric slot that is either a measured value or an explicit unavailability.
///
/// The enum shape guarantees the invariant a boolean-plus-`Option` struct
/// could not: an unavailable slot carries no value, so it can never be
/// mistaken for a measured zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Availability<T> {
    /// The source produced a value.
    Available(T),
    /// The source could not produce a value; the reason is recorded.
    Unavailable(UnavailableReason),
}

impl<T> Availability<T> {
    /// Construct an available slot.
    pub fn available(value: T) -> Self {
        Self::Available(value)
    }

    /// Construct an unavailable slot with a reason.
    pub fn unavailable(reason: UnavailableReason) -> Self {
        Self::Unavailable(reason)
    }

    /// True iff a value is present.
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available(_))
    }

    /// The value, if available.
    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Available(v) => Some(v),
            Self::Unavailable(_) => None,
        }
    }

    /// The unavailability reason, if unavailable.
    pub fn reason(&self) -> Option<UnavailableReason> {
        match self {
            Self::Available(_) => None,
            Self::Unavailable(r) => Some(*r),
        }
    }

    /// Map the inner value, preserving unavailability.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Availability<U> {
        match self {
            Self::Available(v) => Availability::Available(f(v)),
            Self::Unavailable(r) => Availability::Unavailable(r),
        }
    }
}

impl<T> From<Option<T>> for Availability<T> {
    /// `None` maps to [`UnavailableReason::SourceMissing`].
    fn from(opt: Option<T>) -> Self {
        match opt {
            Some(v) => Self::Available(v),
            None => Self::Unavailable(UnavailableReason::SourceMissing),
        }
    }
}

// ---------------------------------------------------------------------------
// Serde: explicit `{ available, value | reason }` shape
// ---------------------------------------------------------------------------

impl<T: Serialize> Serialize for Availability<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Availability", 2)?;
        match self {
            Self::Available(value) => {
                state.serialize_field("available", &true)?;
                state.serialize_field("value", value)?;
            }
            Self::Unavailable(reason) => {
                state.serialize_field("available", &false)?;
                state.serialize_field("reason", reason)?;
            }
        }
        state.end()
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Availability<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Shadow with both optional branches; the `available` flag selects.
        #[derive(Deserialize)]
        struct Shadow<T> {
            available: bool,
            value: Option<T>,
            reason: Option<UnavailableReason>,
        }

        let shadow = Shadow::<T>::deserialize(deserializer)?;
        if shadow.available {
            match shadow.value {
                Some(value) => Ok(Self::Available(value)),
                None => Err(de::Error::missing_field("value")),
            }
        } else {
            match shadow.reason {
                Some(reason) => Ok(Self::Unavailable(reason)),
                None => Err(de::Error::missing_field("reason")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn available_serializes_with_value_and_flag() {
        let slot: Availability<u64> = Availability::Available(42);
        let json = serde_json::to_value(slot).unwrap();
        assert_eq!(json["available"], serde_json::json!(true));
        assert_eq!(json["value"], serde_json::json!(42));
        assert!(json.get("reason").is_none());
    }

    #[test]
    fn unavailable_serializes_with_reason_and_flag() {
        let slot: Availability<u64> =
            Availability::Unavailable(UnavailableReason::AgentUnreachable);
        let json = serde_json::to_value(slot).unwrap();
        assert_eq!(json["available"], serde_json::json!(false));
        assert_eq!(json["reason"], serde_json::json!("agent_unreachable"));
        assert!(json.get("value").is_none());
    }

    #[test]
    fn roundtrip_preserves_variant() {
        let avail: Availability<u64> = Availability::Available(7);
        let back: Availability<u64> =
            serde_json::from_str(&serde_json::to_string(&avail).unwrap()).unwrap();
        assert_eq!(avail, back);

        let unavail: Availability<u64> = Availability::Unavailable(UnavailableReason::ReadError);
        let back: Availability<u64> =
            serde_json::from_str(&serde_json::to_string(&unavail).unwrap()).unwrap();
        assert_eq!(unavail, back);
    }

    #[test]
    fn available_without_value_is_rejected() {
        let err = serde_json::from_str::<Availability<u64>>(r#"{"available": true}"#);
        assert!(err.is_err());
    }

    #[test]
    fn unavailable_without_reason_is_rejected() {
        let err = serde_json::from_str::<Availability<u64>>(r#"{"available": false}"#);
        assert!(err.is_err());
    }

    #[test]
    fn unavailable_never_yields_a_value() {
        let slot: Availability<u64> = Availability::Unavailable(UnavailableReason::SourceMissing);
        assert!(!slot.is_available());
        assert_eq!(slot.value(), None);
        assert_eq!(slot.reason(), Some(UnavailableReason::SourceMissing));
    }
}
