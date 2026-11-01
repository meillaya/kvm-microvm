//! SHA-256 digest computation and constant-time verification.
//!
//! Digests are the content-addressing primitive for the local artifact store.
//! A [`Digest`] is a 32-byte SHA-256 value that round-trips through lowercase
//! hex so it can be embedded in manifests, logs, and API responses.

use microvm_errors::{ErrorCode, MicrovmError};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::io::Read;

/// Length in bytes of a SHA-256 digest.
pub const SHA256_LEN: usize = 32;

/// Length in characters of the lowercase hex encoding of a SHA-256 digest.
pub const SHA256_HEX_LEN: usize = SHA256_LEN * 2;

/// Read buffer size used when streaming a file through the hasher.
const HASH_BUF_LEN: usize = 8192;

/// A 32-byte SHA-256 content digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Digest([u8; SHA256_LEN]);

impl Digest {
    /// Wrap a raw 32-byte digest value.
    pub fn from_bytes(bytes: [u8; SHA256_LEN]) -> Self {
        Self(bytes)
    }

    /// Return the raw digest bytes.
    pub fn as_bytes(&self) -> &[u8; SHA256_LEN] {
        &self.0
    }

    /// Return the lowercase hex encoding.
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }

    /// Parse a 64-character hex string (upper- or lowercase).
    pub fn from_hex(s: &str) -> Result<Self, MicrovmError> {
        let bytes = from_hex(s)?;
        Ok(Self(bytes))
    }

    /// Constant-time equality check against another digest.
    pub fn ct_eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", self.to_hex())
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl From<Digest> for String {
    fn from(d: Digest) -> Self {
        d.to_hex()
    }
}

impl TryFrom<String> for Digest {
    type Error = MicrovmError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_hex(&s)
    }
}

/// Compute the SHA-256 digest of everything readable from `reader`.
pub fn compute_sha256<R: Read>(mut reader: R) -> Result<Digest, MicrovmError> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; HASH_BUF_LEN];
    loop {
        let n = reader.read(&mut buf).map_err(|e| {
            MicrovmError::new(ErrorCode::InternalError, "failed reading artifact bytes")
                .with_context("io", e.to_string())
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let finalized = hasher.finalize();
    let mut bytes = [0u8; SHA256_LEN];
    bytes.copy_from_slice(&finalized);
    Ok(Digest(bytes))
}

/// Verify that `reader` hashes to `expected`, returning [`ErrorCode::DigestMismatch`]
/// on any difference. Comparison is constant-time.
pub fn verify_sha256<R: Read>(reader: R, expected: &Digest) -> Result<(), MicrovmError> {
    let actual = compute_sha256(reader)?;
    if actual.ct_eq(expected) {
        return Ok(());
    }
    Err(
        MicrovmError::new(ErrorCode::DigestMismatch, "sha256 digest mismatch")
            .with_context("expected", expected.to_hex())
            .with_context("actual", actual.to_hex()),
    )
}

/// Constant-time comparison of two fixed-size byte arrays.
fn constant_time_eq(a: &[u8; SHA256_LEN], b: &[u8; SHA256_LEN]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn from_hex(s: &str) -> Result<[u8; SHA256_LEN], MicrovmError> {
    let invalid = || {
        MicrovmError::new(ErrorCode::DigestMismatch, "malformed sha256 hex digest")
            .with_context("len", s.len().to_string())
    };
    if s.len() != SHA256_HEX_LEN {
        return Err(invalid());
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; SHA256_LEN];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_val(bytes[i * 2]).ok_or_else(invalid)?;
        let lo = hex_val(bytes[i * 2 + 1]).ok_or_else(invalid)?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_sha256_vector() {
        // SHA-256("abc"). RFC 6234 test vector.
        let d = compute_sha256(&b"abc"[..]).unwrap();
        assert_eq!(
            d.to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn empty_input_vector() {
        let d = compute_sha256(&b""[..]).unwrap();
        assert_eq!(
            d.to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hex_roundtrip() {
        let d = compute_sha256(&b"kernel"[..]).unwrap();
        let hex = d.to_hex();
        let back = Digest::from_hex(&hex).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn hex_accepts_uppercase() {
        let d = compute_sha256(&b"abc"[..]).unwrap();
        let upper = d.to_hex().to_uppercase();
        assert_eq!(Digest::from_hex(&upper).unwrap(), d);
    }

    #[test]
    fn rejects_wrong_length_hex() {
        assert!(Digest::from_hex("abcd").is_err());
        assert!(Digest::from_hex(&"a".repeat(63)).is_err());
        assert!(Digest::from_hex(&"a".repeat(65)).is_err());
    }

    #[test]
    fn rejects_non_hex_chars() {
        let bad = format!("{}zz", "a".repeat(62));
        assert!(Digest::from_hex(&bad).is_err());
    }

    #[test]
    fn detects_mismatch() {
        let expected = compute_sha256(&b"rootfs-v1"[..]).unwrap();
        let err = verify_sha256(&b"rootfs-v2"[..], &expected).unwrap_err();
        assert_eq!(err.code, ErrorCode::DigestMismatch);
        assert!(err.context.contains_key("expected"));
        assert!(err.context.contains_key("actual"));
    }

    #[test]
    fn verifies_matching_digest() {
        let expected = compute_sha256(&b"rootfs-v1"[..]).unwrap();
        assert!(verify_sha256(&b"rootfs-v1"[..], &expected).is_ok());
    }

    #[test]
    fn serde_roundtrip_is_hex_string() {
        let d = compute_sha256(&b"abc"[..]).unwrap();
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, format!("\"{}\"", d.to_hex()));
        let back: Digest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn streaming_matches_oneshot() {
        // Force multiple buffer fills to exercise the streaming loop.
        let data = vec![0x5au8; HASH_BUF_LEN * 3 + 17];
        let streamed = compute_sha256(&data[..]).unwrap();
        let oneshot = compute_sha256(&data[..]).unwrap();
        assert_eq!(streamed, oneshot);
    }
}
