//! # pubky-molt — Molt routing core
//!
//! Molt is a privacy routing layer that carries intent across identity,
//! transport, and payment networks while shedding the continuity that lets
//! observers join one network's view to another's.
//!
//! This crate is the protocol-neutral routing core. It contains **no**
//! cryptography and depends on no other Pubky crate; it defines its own
//! [`PeerId`] newtype. Clients (e.g. `paykit-rs`) supply [`route::Adapter`]
//! implementations and [`route::RouteState`] values; this crate provides:
//!
//! - [`witness`] — what observers learn ([`witness::Field`], [`witness::Witness`],
//!   [`witness::Manifest`]), observation domains and the advisory-only
//!   [`witness::DomainRegistry`], what protocols require to stay continuous
//!   ([`witness::CorrelatorSpec`], [`witness::Segment`]), and
//!   [`witness::detach_level`].
//! - [`route`] — route graph types: [`route::RouteState`], [`route::Holder`],
//!   [`route::Amount`], [`route::RouteConstraint`] (fail-closed),
//!   [`route::Adapter`], [`route::Route`].
//! - [`planner`] — bounded BFS planner ([`planner::plan`]) that extends only
//!   from [`route::Holder::Self_`]-held states.
//! - [`score`] — continuity-cost scorer ([`score::score`]) with caller-supplied
//!   [`score::CostPolicy`].
//! - [`comparisons`] — renders `docs/COMPARISONS.md` from the S11 fixtures.
//!
//! The objective is *constrained minimization*: minimize observable continuity,
//! subject to the continuity the higher-level protocol explicitly requires
//! (open [`witness::Segment`]s).
//!
//! # Deterministic encodings
//!
//! Any object that is byte-encoded for cross-implementation comparison is
//! encoded as deterministic CBOR (RFC 8949 §4.2) with integer map keys via
//! the `to_cbor()` methods on the relevant types.
//!
//! # Generated documentation
//!
//! `docs/COMPARISONS.md` is rendered from the fixtures under `fixtures/` by
//! [`comparisons::render_comparisons`] and pinned by the following test, which
//! fails if the committed file drifts from what the code renders:
//!
//! ```
//! // Regenerate intentionally with: MOLT_COMPARISONS_REGENERATE=1 cargo test --doc
//! let rendered = pubky_molt::comparisons::render_comparisons().expect("render comparisons");
//! let path = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/COMPARISONS.md");
//! if std::env::var_os("MOLT_COMPARISONS_REGENERATE").is_some() {
//!     std::fs::write(path, &rendered).expect("write docs/COMPARISONS.md");
//! } else {
//!     let committed = std::fs::read_to_string(path).expect("read committed docs/COMPARISONS.md");
//!     assert_eq!(
//!         rendered, committed,
//!         "docs/COMPARISONS.md has drifted from the code; regenerate with \
//!          MOLT_COMPARISONS_REGENERATE=1 cargo test --doc and commit the result"
//!     );
//! }
//! ```

pub mod comparisons;
pub mod planner;
pub mod route;
pub mod score;
pub mod witness;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// A Pubky root identity: 32 bytes of Ed25519 public key material.
///
/// This crate deliberately defines its own `PeerId` newtype so the routing
/// core depends on no other Pubky crate. Clients holding a different `PeerId`
/// type (e.g. `pubky-crypto`'s) convert at their boundary.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(pub [u8; 32]);

impl PeerId {
    /// Wrap raw key bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        PeerId(bytes)
    }

    /// Borrow the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parse a 64-character lowercase hex string into a `PeerId`.
    pub fn from_hex(s: &str) -> Result<Self, MoltError> {
        let bytes = from_hex(s)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            MoltError::InvalidHex(format!("expected 32 bytes, got {}", v.len()))
        })?;
        Ok(PeerId(arr))
    }

    /// Lowercase hex encoding of the key bytes.
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", self.to_hex())
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for PeerId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PeerId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        PeerId::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Encode bytes as lowercase hex.
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decode a hex string (upper or lower case) into bytes.
pub fn from_hex(s: &str) -> Result<Vec<u8>, MoltError> {
    let nib = |c: u8| -> Result<u8, MoltError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(MoltError::InvalidHex(format!(
                "invalid hex character '{}'",
                c as char
            ))),
        }
    };
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return Err(MoltError::InvalidHex("odd-length hex string".into()));
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks_exact(2) {
        out.push((nib(pair[0])? << 4) | nib(pair[1])?);
    }
    Ok(out)
}

/// Maximum byte length of a [`PurposeId`].
pub const PURPOSE_ID_MAX_LEN: usize = 64;

/// A versioned, registered domain-separation namespace with the grammar
/// `pubky.molt.<app>.v<N>` (lowercase ASCII, `.`-separated segments of
/// `[a-z0-9_]`, at most 64 bytes). Not free text: anything outside the
/// grammar is rejected on construction.
///
/// `PurposeId` scopes channel derivation in the crypto crate and names
/// application-defined states and constraints here. This crate defines its
/// own `PurposeId` so it depends on no other Pubky crate.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PurposeId(String);

impl PurposeId {
    /// Well-known purpose: first-contact hello channels.
    pub const HELLO: &'static str = "pubky.molt.hello.v1";
    /// Well-known purpose: Molt intro / first contact.
    pub const INTRO: &'static str = "pubky.molt.intro.v1";
    /// Well-known purpose: Paykit request/proposal/ACK traffic.
    pub const PAYKIT: &'static str = "pubky.molt.paykit.v1";

    /// Parse and validate a purpose id against the grammar
    /// `pubky.molt.<app>.v<N>`.
    pub fn parse(s: &str) -> Result<Self, MoltError> {
        validate_namespace_shape(s)
            .map_err(|e| MoltError::InvalidPurposeId(format!("{s:?}: {e}")))?;
        let segs: Vec<&str> = s.split('.').collect();
        if segs.len() < 4 || segs[0] != "pubky" || segs[1] != "molt" {
            return Err(MoltError::InvalidPurposeId(format!(
                "{s:?}: must match pubky.molt.<app>.v<N>"
            )));
        }
        let last = segs[segs.len() - 1];
        let ver = last.strip_prefix('v').ok_or_else(|| {
            MoltError::InvalidPurposeId(format!("{s:?}: final segment must be v<N>"))
        })?;
        if ver.is_empty() || !ver.bytes().all(|b| b.is_ascii_digit()) {
            return Err(MoltError::InvalidPurposeId(format!(
                "{s:?}: final segment must be v<N>"
            )));
        }
        Ok(PurposeId(s.to_string()))
    }

    /// The canonical string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Crate-internal constructor for statically valid namespaces used to tag
    /// errors that name no application namespace. Not public: callers must go
    /// through [`PurposeId::parse`].
    pub(crate) fn internal(s: &str) -> PurposeId {
        PurposeId(s.to_string())
    }
}

impl fmt::Debug for PurposeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PurposeId({})", self.0)
    }
}

impl fmt::Display for PurposeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for PurposeId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PurposeId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        PurposeId::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Validate the `PurposeId`-like namespace shape used by
/// [`witness::CorrelatorSpec`] namespaces: lowercase ASCII, `.`-separated
/// segments of `[a-z0-9_]`, no empty segments, at most
/// [`PURPOSE_ID_MAX_LEN`] bytes. Unlike [`PurposeId::parse`], no
/// `pubky.molt.` prefix or `v<N>` suffix is required (e.g.
/// `lightning.payment_hash`, `btc.sats`).
pub fn validate_namespace(s: &str) -> Result<(), MoltError> {
    validate_namespace_shape(s).map_err(|e| MoltError::InvalidNamespace(format!("{s:?}: {e}")))
}

fn validate_namespace_shape(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("empty namespace".into());
    }
    if s.len() > PURPOSE_ID_MAX_LEN {
        return Err(format!("exceeds {PURPOSE_ID_MAX_LEN} bytes"));
    }
    for seg in s.split('.') {
        if seg.is_empty() {
            return Err("empty segment".into());
        }
        if !seg
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(format!(
                "segment {seg:?}: must be lowercase ASCII [a-z0-9_]"
            ));
        }
    }
    Ok(())
}

/// Errors produced by this crate.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum MoltError {
    /// A [`PurposeId`] string violated the grammar.
    #[error("invalid purpose id: {0}")]
    InvalidPurposeId(String),
    /// A namespace string violated the `PurposeId`-like grammar.
    #[error("invalid namespace: {0}")]
    InvalidNamespace(String),
    /// Hex decoding failed.
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    /// Deterministic CBOR encoding failed.
    #[error("cbor encoding failed: {0}")]
    Cbor(String),
    /// A [`score::CostPolicy`] rejected a route's quotes.
    #[error("cost policy rejected route: {0}")]
    CostPolicyRejected(String),
    /// A route hop named an adapter that was not supplied.
    #[error("unknown adapter: {0}")]
    UnknownAdapter(String),
    /// A fixture file was missing or malformed.
    #[error("fixture error: {0}")]
    Fixture(String),
    /// I/O failure while reading or writing project files.
    #[error("io error: {0}")]
    Io(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purpose_id_accepts_grammar() {
        for ok in [
            PurposeId::HELLO,
            PurposeId::INTRO,
            PurposeId::PAYKIT,
            "pubky.molt.my_app.v12",
        ] {
            let p = PurposeId::parse(ok).expect(ok);
            assert_eq!(p.as_str(), ok);
            assert_eq!(p.to_string(), ok);
        }
    }

    #[test]
    fn purpose_id_rejects_outside_grammar() {
        for bad in [
            "",
            "pubky.molt.paykit",      // no version
            "pubky.molt.paykit.vX",   // non-numeric version
            "lightning.payment_hash", // missing pubky.molt prefix
            "Pubky.molt.paykit.v1",   // uppercase
            "pubky.molt.pay kit.v1",  // space
            "pubky.molt..v1",         // empty segment
            "pubky.molt.paykit.v1.extra",
        ] {
            assert!(PurposeId::parse(bad).is_err(), "accepted {bad:?}");
        }
        let long = format!("pubky.molt.{}.v1", "a".repeat(64));
        assert!(PurposeId::parse(&long).is_err());
    }

    #[test]
    fn purpose_id_serde_roundtrip_and_rejection() {
        let p = PurposeId::parse(PurposeId::PAYKIT).expect("parse");
        let j = serde_json::to_string(&p).expect("ser");
        assert_eq!(j, "\"pubky.molt.paykit.v1\"");
        let back: PurposeId = serde_json::from_str(&j).expect("de");
        assert_eq!(back, p);
        assert!(serde_json::from_str::<PurposeId>("\"nope\"").is_err());
    }

    #[test]
    fn namespace_shape_allows_non_purpose_names() {
        for ok in [
            "lightning.payment_hash",
            "btc.sats",
            "time.unix",
            "credit.receipt_id",
        ] {
            validate_namespace(ok).expect(ok);
        }
        assert!(validate_namespace("Lightning.X").is_err());
        assert!(validate_namespace("a..b").is_err());
    }

    #[test]
    fn peer_id_hex_roundtrip() {
        let id = PeerId([7u8; 32]);
        let hex = id.to_hex();
        assert_eq!(hex.len(), 64);
        let back = PeerId::from_hex(&hex).expect("parse");
        assert_eq!(back, id);
        let j = serde_json::to_string(&id).expect("ser");
        let back2: PeerId = serde_json::from_str(&j).expect("de");
        assert_eq!(back2, id);
    }

    #[test]
    fn peer_id_rejects_bad_hex() {
        assert!(PeerId::from_hex("zz").is_err());
        assert!(PeerId::from_hex(&"ab".repeat(31)).is_err()); // wrong length
        assert!(PeerId::from_hex("abc").is_err()); // odd length
    }
}
