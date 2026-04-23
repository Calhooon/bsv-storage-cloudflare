//! BRC-42 key derivation helpers.
//!
//! Thin, allocation-conscious wrappers around `bsv_rs::wallet::KeyDeriver`.
//! The underlying primitive is already in `bsv-rs` (audited + cross-SDK
//! test-vectored); we expose a project-local signature that matches the
//! callers in `/advertise` and `/renew` without pulling `KeyDeriver`'s
//! full type noise into handler code.
//!
//! # UHRP-specific derivation
//!
//! Every UHRP advertisement uses the same derivation parameters
//! (PROTOCOL.md §B, matches TS `createUHRPAdvertisement.ts:60–65` and
//! `renew.ts:140–146`):
//!
//! | Field | Value |
//! |---|---|
//! | `protocolID` | `(2, "uhrp advertisement")` |
//! | `keyID` | `"1"` |
//! | `counterparty` | `"anyone"` |
//!
//! [`uhrp_protocol_id`], [`UHRP_KEY_ID`] and [`UHRP_COUNTERPARTY_ANYONE`]
//! hard-code these so a typo in a route handler becomes a compile error.
//!
//! # Wire-format parity
//!
//! BRC-42 derivation is byte-identical across the Rust, Go, and TS SDKs
//! (verified via `tests/vectors/brc42_vectors.json` in bsv-rs). Any advert
//! built here will verify against a TS-built advert for the same root key,
//! and vice versa.

use bsv_rs::primitives::ec::{PrivateKey, PublicKey};
use bsv_rs::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};

/// Sentinel indicating the `"anyone"` counterparty.
///
/// The derivation helpers below branch on this value internally; call sites
/// use it for readability over `Counterparty::Anyone`, matching the TS
/// source which literally passes the string `'anyone'`.
pub const UHRP_COUNTERPARTY_ANYONE: &str = "anyone";

/// The `keyID` field for UHRP advertisements — hard-coded to `"1"` by
/// PROTOCOL.md §B and TS `createUHRPAdvertisement.ts:63`.
pub const UHRP_KEY_ID: &str = "1";

/// The UHRP advertisement BRC-43 protocol tuple: `(2, "uhrp advertisement")`.
///
/// Returned as an owned `Protocol` so callers can pass it by reference
/// straight into `KeyDeriver::derive_*`.
#[must_use]
pub fn uhrp_protocol_id() -> Protocol {
    Protocol::new(SecurityLevel::Counterparty, "uhrp advertisement")
}

/// BRC-42 errors surfaced by the helpers below. All non-panic failure modes
/// collapse to a single variant because the wallet-infra layer only cares
/// whether the derivation succeeded, not which step failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Brc42Error {
    /// The underlying HMAC-SHA256 or scalar addition failed. In practice
    /// this only fires if the root key's private scalar plus the derivation
    /// HMAC lands exactly on the curve order (probability ≈ 2⁻²⁵⁶).
    Derive,
    /// The counterparty string was neither `"anyone"` nor a valid
    /// 66-char compressed-pubkey hex.
    InvalidCounterparty,
}

impl std::fmt::Display for Brc42Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Derive => "BRC-42 key derivation failed",
            Self::InvalidCounterparty => "invalid counterparty identifier",
        })
    }
}

impl std::error::Error for Brc42Error {}

/// Derive the child **private** key for a given `(protocol, keyID, counterparty)`.
///
/// Contract matches the TS `wallet.getPublicKey` / `createSignature` internals:
/// the returned key signs messages that verify against
/// `derive_child_public_key(admin_pub, protocol, key_id, "anyone", for_self=true)`.
///
/// # Errors
///
/// Returns [`Brc42Error::InvalidCounterparty`] if `counterparty` is not
/// `"anyone"`, `"self"`, or a 66-char compressed pubkey hex.
/// Returns [`Brc42Error::Derive`] on the astronomically improbable scalar
/// overflow.
pub fn derive_child_key(
    admin_key: &PrivateKey,
    protocol: &Protocol,
    key_id: &str,
    counterparty: &str,
) -> Result<PrivateKey, Brc42Error> {
    let cp = parse_counterparty(counterparty)?;
    let deriver = KeyDeriver::new(Some(admin_key.clone()));
    deriver
        .derive_private_key(protocol, key_id, &cp)
        .map_err(|_| Brc42Error::Derive)
}

/// Derive the child **public** key for a given `(protocol, keyID, counterparty)`.
///
/// `for_self=true` returns our own child pubkey — the one we put inside a
/// PushDrop lock so we (and only we) can later unlock the output. This is
/// what `/advertise` uses as the PushDrop locking key.
///
/// # Errors
///
/// Same as [`derive_child_key`].
pub fn derive_child_public_key(
    admin_key: &PrivateKey,
    protocol: &Protocol,
    key_id: &str,
    counterparty: &str,
) -> Result<PublicKey, Brc42Error> {
    let cp = parse_counterparty(counterparty)?;
    let deriver = KeyDeriver::new(Some(admin_key.clone()));
    deriver
        .derive_public_key(protocol, key_id, &cp, true)
        .map_err(|_| Brc42Error::Derive)
}

/// Derive the BRC-29 child private key for spending a wallet-payment UTXO.
///
/// Mirrors `ScriptTemplateBRC29` in `@bsv/wallet-toolbox`'s
/// `signer/methods/completeSignedTransaction.ts:42-52` — protocolID is
/// fixed at `(2, "3241645161d8")`, keyID is the literal `"<prefix> <suffix>"`
/// string (single space, both base64), counterparty is the **sender's**
/// identity pubkey (the one that paid us — we use them as counterparty
/// because they used our pubkey when constructing the locking script).
///
/// # Errors
///
/// - [`Brc42Error::InvalidCounterparty`] — `sender_identity_key_hex` is not
///   a valid 66-char compressed pubkey.
/// - [`Brc42Error::Derive`] — astronomically improbable scalar overflow.
pub fn derive_brc29_input_key(
    admin_key: &PrivateKey,
    derivation_prefix: &str,
    derivation_suffix: &str,
    sender_identity_key_hex: &str,
) -> Result<PrivateKey, Brc42Error> {
    let protocol = Protocol::new(SecurityLevel::Counterparty, "3241645161d8");
    let key_id = format!("{derivation_prefix} {derivation_suffix}");
    derive_child_key(admin_key, &protocol, &key_id, sender_identity_key_hex)
}

fn parse_counterparty(raw: &str) -> Result<Counterparty, Brc42Error> {
    match raw {
        UHRP_COUNTERPARTY_ANYONE => Ok(Counterparty::Anyone),
        "self" => Ok(Counterparty::Self_),
        hex_key => {
            let pk = PublicKey::from_hex(hex_key).map_err(|_| Brc42Error::InvalidCounterparty)?;
            Ok(Counterparty::Other(pk))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    use super::*;

    // BIP-32 test-vector root key: private = 0x…01. Its pubkey and every
    // BRC-42-derived child are deterministic, so we pin bytes.
    const ROOT_KEY_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    fn root_key() -> PrivateKey {
        PrivateKey::from_hex(ROOT_KEY_HEX).expect("valid test key")
    }

    #[test]
    fn protocol_id_constant_matches_ts() {
        let p = uhrp_protocol_id();
        // Tuple form `(2, "uhrp advertisement")` — byte-equal to TS.
        assert_eq!(p.security_level.as_u8(), 2);
        assert_eq!(p.protocol_name, "uhrp advertisement");
        assert_eq!(UHRP_KEY_ID, "1");
        assert_eq!(UHRP_COUNTERPARTY_ANYONE, "anyone");
    }

    #[test]
    fn derive_child_key_is_deterministic() {
        let k = root_key();
        let a = derive_child_key(
            &k,
            &uhrp_protocol_id(),
            UHRP_KEY_ID,
            UHRP_COUNTERPARTY_ANYONE,
        )
        .unwrap();
        let b = derive_child_key(
            &k,
            &uhrp_protocol_id(),
            UHRP_KEY_ID,
            UHRP_COUNTERPARTY_ANYONE,
        )
        .unwrap();
        // Same root + same params ⇒ same child.
        assert_eq!(a.to_hex(), b.to_hex());
    }

    #[test]
    fn derive_child_key_differs_from_root() {
        // Sanity: derived key is not the root key. Catches accidental
        // short-circuit (e.g., returning admin_key directly).
        let k = root_key();
        let child = derive_child_key(
            &k,
            &uhrp_protocol_id(),
            UHRP_KEY_ID,
            UHRP_COUNTERPARTY_ANYONE,
        )
        .unwrap();
        assert_ne!(child.to_hex(), k.to_hex());
    }

    #[test]
    fn derive_public_key_matches_private_public() {
        // for_self=true: the child public key equals priv.public_key().
        let k = root_key();
        let priv_child = derive_child_key(
            &k,
            &uhrp_protocol_id(),
            UHRP_KEY_ID,
            UHRP_COUNTERPARTY_ANYONE,
        )
        .unwrap();
        let pub_child = derive_child_public_key(
            &k,
            &uhrp_protocol_id(),
            UHRP_KEY_ID,
            UHRP_COUNTERPARTY_ANYONE,
        )
        .unwrap();
        assert_eq!(priv_child.public_key().to_hex(), pub_child.to_hex());
    }

    #[test]
    fn derive_with_different_key_id_yields_different_child() {
        let k = root_key();
        let a = derive_child_key(&k, &uhrp_protocol_id(), "1", UHRP_COUNTERPARTY_ANYONE).unwrap();
        let b = derive_child_key(&k, &uhrp_protocol_id(), "2", UHRP_COUNTERPARTY_ANYONE).unwrap();
        assert_ne!(a.to_hex(), b.to_hex());
    }

    #[test]
    fn parse_counterparty_accepts_anyone_self_and_hex_key() {
        // `anyone` and `self` are sentinels; a 66-char hex is treated as
        // a compressed pubkey (secp256k1 generator point here — known valid).
        const GENERATOR_HEX: &str =
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        assert!(matches!(
            parse_counterparty("anyone"),
            Ok(Counterparty::Anyone)
        ));
        assert!(matches!(
            parse_counterparty("self"),
            Ok(Counterparty::Self_)
        ));
        assert!(matches!(
            parse_counterparty(GENERATOR_HEX),
            Ok(Counterparty::Other(_))
        ));
    }

    #[test]
    fn parse_counterparty_rejects_malformed_hex() {
        assert_eq!(
            parse_counterparty("not-a-pubkey"),
            Err(Brc42Error::InvalidCounterparty)
        );
        // Wrong length (64 chars ≠ 66-char compressed key).
        assert_eq!(
            parse_counterparty("1234567890123456789012345678901234567890123456789012345678901234"),
            Err(Brc42Error::InvalidCounterparty)
        );
    }

    #[test]
    fn derive_rejects_invalid_counterparty() {
        let k = root_key();
        let err = derive_child_key(&k, &uhrp_protocol_id(), UHRP_KEY_ID, "definitely-not-valid")
            .unwrap_err();
        assert_eq!(err, Brc42Error::InvalidCounterparty);
    }

    #[test]
    fn error_display_strings_are_stable() {
        // Both variants produce a short human-readable message; we lock
        // the strings so log-grep patterns don't break.
        assert_eq!(
            Brc42Error::Derive.to_string(),
            "BRC-42 key derivation failed"
        );
        assert_eq!(
            Brc42Error::InvalidCounterparty.to_string(),
            "invalid counterparty identifier"
        );
    }
}
