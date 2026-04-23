//! BRC-29 payment envelope builder for the parity harness.
//!
//! Everything here is **pure** — no UTXO selection, no broadcasting, no
//! wallet calls. The function surface is deliberately split so scenarios
//! can glue the pieces together against whatever wallet they have:
//!
//! 1. [`derive_recipient_pubkey`] — sender-side BRC-42 derivation of the
//!    recipient's P2PKH locking key. Matches TS `pushdrop.derive(...)`
//!    with protocol `[2, "3241645161d8"]` and keyID `"{prefix} {suffix}"`.
//! 2. [`p2pkh_payment_output`] — wraps a derived pubkey + satoshi amount
//!    into a `TransactionOutput` whose locking script is a standard
//!    25-byte P2PKH to `hash160(derived_pubkey)`.
//! 3. [`PaymentEnvelope::to_header_value`] — given the final BEEF of the
//!    signed payment transaction plus the derivation prefix/suffix, emits
//!    the JSON string that goes in the `x-bsv-payment` HTTP header.
//!
//! The signed-transaction step (steps between 2 and 3) is intentionally
//! not in this module. For live-fire scenarios the caller assembles a
//! `Transaction` with the output from [`p2pkh_payment_output`] plus inputs
//! spending their own UTXOs, signs via `bsv-rs`'s `KeyDeriver` or an
//! external wallet (MetaNet Client's `createAction`), and wraps in BEEF
//! via `bsv_rs::transaction::Beef`.
//!
//! # Protocol reference
//!
//! Server-side BRC-29 validation (`storage.babbage.systems`):
//! - Parses `x-bsv-payment` → `{derivationPrefix, derivationSuffix, transaction}`
//! - Derives its own-side pubkey via `KeyDeriver::derive_public_key(
//!     protocol=[2,"3241645161d8"], keyID="{prefix} {suffix}",
//!     counterparty=sender_identity, for_self=true)`
//! - Matches `hash160(derived_pubkey)` against the P2PKH hash in the
//!   transaction's output locking script
//! - Verifies the transaction via BEEF SPV
//!
//! Symmetric: the SENDER uses `counterparty=recipient_identity,
//! for_self=false` to derive the SAME pubkey. Proven byte-exact against
//! `@bsv/sdk 1.10.1` via `tests/parity/fixtures/parity/brc29_payment_*.json`
//! and the test below.
//!
//! # Scope limits
//!
//! - This module does not ensure derivation prefix/suffix uniqueness or
//!   randomness. Callers must generate fresh prefix/suffix per request
//!   (base64-encoded random bytes) — re-using them across requests is a
//!   replay vector on servers that index paid outputs by prefix+suffix.
//! - No multi-output / change support yet. `/upload` pays a flat quoted
//!   amount; if a scenario needs multi-output, extend here.

use crate::wallet::{self, ActionOutput};
use bsv_rs::primitives::ec::{PrivateKey, PublicKey};
use bsv_rs::primitives::hash::hash160;
use bsv_rs::primitives::to_base64;
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};
use rand::RngCore;

/// BRC-29 wallet protocol name. Fixed on the wire — the same 12-char token
/// the TS SDK's `AuthFetch` uses for payment derivation (see
/// `@bsv/sdk/src/auth/clients/AuthFetch.ts` search for `"3241645161d8"`).
pub const BRC29_PROTOCOL_NAME: &str = "3241645161d8";

/// Security level used for BRC-29 derivations — `Counterparty` (level 2).
/// Matches the TS SDK's `[2, "3241645161d8"]` protocol ID encoding.
pub const BRC29_SECURITY_LEVEL: SecurityLevel = SecurityLevel::Counterparty;

/// Sender-side BRC-29 derivation: compute the P2PKH-locking pubkey that
/// the recipient (a server) expects to see in the payment output.
///
/// # Arguments
/// - `sender_priv` — the paying party's identity private key.
/// - `recipient_identity` — the server's identity public key (published in
///   the 402 response's `x-bsv-payment-identity` header, or known ahead of
///   time for well-known endpoints).
/// - `derivation_prefix_b64` / `derivation_suffix_b64` — base64-encoded
///   random strings, jointly forming the BRC-42 keyID `"{prefix} {suffix}"`.
///   Must be fresh per request (see module docs).
///
/// The returned pubkey is what the caller should pass to
/// [`p2pkh_payment_output`].
pub fn derive_recipient_pubkey(
    sender_priv: &PrivateKey,
    recipient_identity: &PublicKey,
    derivation_prefix_b64: &str,
    derivation_suffix_b64: &str,
) -> Result<PublicKey, String> {
    let protocol = Protocol::new(BRC29_SECURITY_LEVEL, BRC29_PROTOCOL_NAME);
    let key_id = format!("{derivation_prefix_b64} {derivation_suffix_b64}");
    let deriver = KeyDeriver::new(Some(sender_priv.clone()));
    let counterparty = Counterparty::Other(recipient_identity.clone());
    deriver
        .derive_public_key(&protocol, &key_id, &counterparty, false)
        .map_err(|e| format!("BRC-29 derive_public_key failed: {e}"))
}

/// Build a P2PKH locking script paying `satoshis` to the BRC-29-derived
/// recipient pubkey. This is the exact single output the server expects at
/// some index of the payment transaction.
///
/// Returns `(locking_script_bytes, satoshis)` — the caller inserts this as
/// a `TransactionOutput` at whichever index their wallet puts it.
pub fn p2pkh_payment_output(
    derived_recipient: &PublicKey,
    satoshis: u64,
) -> Result<(LockingScript, u64), String> {
    let pub_hash = hash160(&derived_recipient.to_compressed());
    // Standard P2PKH locking script: OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG
    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // push 20 bytes
    script.extend_from_slice(&pub_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    let script = LockingScript::from_binary(&script)
        .map_err(|e| format!("LockingScript::from_binary: {e}"))?;
    Ok((script, satoshis))
}

/// JSON envelope that goes in the `x-bsv-payment` HTTP header. Matches
/// what `storage.babbage.systems` and our worker accept.
#[derive(Debug, Clone)]
pub struct PaymentEnvelope {
    /// Base64 string — the prefix half of the BRC-29 keyID.
    pub derivation_prefix_b64: String,
    /// Base64 string — the suffix half of the BRC-29 keyID.
    pub derivation_suffix_b64: String,
    /// Raw BEEF bytes (BRC-62) of the signed payment transaction, including
    /// all ancestor tx inputs / merkle proofs needed for SPV verification.
    pub transaction_beef: Vec<u8>,
}

impl PaymentEnvelope {
    /// Serialize to the JSON string that's set as the `x-bsv-payment`
    /// HTTP header value. Base64-encodes the transaction bytes.
    pub fn to_header_value(&self) -> String {
        let json = serde_json::json!({
            "derivationPrefix": self.derivation_prefix_b64,
            "derivationSuffix": self.derivation_suffix_b64,
            "transaction": to_base64(&self.transaction_beef),
        });
        json.to_string()
    }
}

/// Generate a fresh BRC-29 derivation suffix: 32 random bytes, STANDARD
/// base64 (padded). Matches `x402-client/lib/payment.py` — nanostore's
/// storage server rejects anything other than base64-of-random-bytes
/// (tried UUIDs, got rejected).
pub fn random_derivation_suffix() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    to_base64(&bytes)
}

/// End-to-end payment envelope construction. Wires the pure primitives
/// above with the MetaNet Client wallet adapter to produce an
/// `x-bsv-payment` header payload the server will accept.
///
/// # Flow
///
/// 1. Derive the recipient pubkey (sender_priv + server_identity + key_id).
/// 2. Build a P2PKH locking script to `hash160(derived_pubkey)`.
/// 3. Hand that script + satoshis to MetaNet Client's `createAction`
///    with `randomizeOutputs=false` so the payment output lands at
///    index 0 (server always checks index 0).
/// 4. Wrap the signed-transaction bytes returned by the wallet in the
///    BRC-29 JSON envelope.
///
/// # Arguments
///
/// - `sender_priv` — the BRC-31 identity key of the caller. Both signs
///   BRC-31 auth (outside this module) and derives the payment key here.
/// - `server_identity_hex` — 66-char compressed hex of the server's
///   identity pubkey, learned from the BRC-31 session after handshake.
/// - `derivation_prefix_b64` — echoed from the server's 402 response
///   header (`x-bsv-payment-derivation-prefix`). The server is the
///   authority on the prefix; we must round-trip it verbatim.
/// - `satoshis` — from the 402's `x-bsv-payment-satoshis-required`.
/// - `http` — preconstructed reqwest client (`wallet::build_client`).
///
/// # Gotchas pinned by the Python reference
///
/// - `randomizeOutputs: false` — server rejects otherwise (index drift).
/// - `acceptDelayedBroadcast: false` — payment must be immediately
///   broadcast, server validates via SPV on storage.babbage.systems.
/// - `outputDescription` must be ≥ 5 chars (wallet validation).
pub async fn create_payment_envelope(
    sender_priv: &PrivateKey,
    server_identity_hex: &str,
    derivation_prefix_b64: &str,
    satoshis: u64,
    http: &reqwest::Client,
) -> Result<PaymentEnvelope, String> {
    let server_identity = PublicKey::from_hex(server_identity_hex)
        .map_err(|e| format!("bad server identity hex: {e}"))?;

    let suffix = random_derivation_suffix();

    let derived = derive_recipient_pubkey(
        sender_priv,
        &server_identity,
        derivation_prefix_b64,
        &suffix,
    )?;
    let (script, sats) = p2pkh_payment_output(&derived, satoshis)?;

    let description = format!("BRC-29 payment: {sats} sats");
    let action = wallet::create_action(
        http,
        description,
        vec![ActionOutput {
            locking_script_hex: script.to_hex(),
            satoshis: sats,
            // Min 5 chars — matches `x402-client`'s "BRC-29 payment output".
            output_description: "BRC-29 payment output".to_string(),
        }],
        // acceptDelayedBroadcast=false, randomizeOutputs=false — see doc.
        false,
        false,
    )
    .await?;

    Ok(PaymentEnvelope {
        derivation_prefix_b64: derivation_prefix_b64.to_string(),
        derivation_suffix_b64: suffix,
        transaction_beef: action.tx,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde::Deserialize;

    /// Loaded from `tests/parity/fixtures/parity/brc29_payment_*.json` —
    /// byte-exact goldens produced by `@bsv/sdk 1.10.1`. If any of our
    /// builder outputs drift from these, we've regressed TS parity.
    #[derive(Debug, Deserialize)]
    struct Brc29Fixture {
        sender_priv_hex: String,
        receiver_pub_hex: String,
        derivation: Brc29Derivation,
        expected: Brc29Expected,
    }

    #[derive(Debug, Deserialize)]
    struct Brc29Derivation {
        derivation_prefix: String,
        derivation_suffix: String,
    }

    #[derive(Debug, Deserialize)]
    struct Brc29Expected {
        derived_pubkey_hex: String,
        locking_script_hex: String,
        satoshis: u64,
    }

    const FIXTURES: &[(&str, &str)] = &[
        (
            "brc29_payment_basic",
            include_str!("../fixtures/parity/brc29_payment_basic.json"),
        ),
        (
            "brc29_payment_large_keyid",
            include_str!("../fixtures/parity/brc29_payment_large_keyid.json"),
        ),
    ];

    #[test]
    fn derive_recipient_pubkey_matches_ts_fixtures() {
        for (label, raw) in FIXTURES {
            let f: Brc29Fixture =
                serde_json::from_str(raw).unwrap_or_else(|e| panic!("{label}: fixture parse: {e}"));

            let sender = PrivateKey::from_hex(&f.sender_priv_hex).unwrap();
            let receiver = PublicKey::from_hex(&f.receiver_pub_hex).unwrap();
            let got = derive_recipient_pubkey(
                &sender,
                &receiver,
                &f.derivation.derivation_prefix,
                &f.derivation.derivation_suffix,
            )
            .unwrap_or_else(|e| panic!("{label}: {e}"));

            assert_eq!(
                got.to_hex(),
                f.expected.derived_pubkey_hex,
                "{label}: derived pubkey must match TS byte-exact"
            );
        }
    }

    #[test]
    fn p2pkh_payment_output_matches_ts_fixture_script() {
        for (label, raw) in FIXTURES {
            let f: Brc29Fixture = serde_json::from_str(raw).unwrap();
            let derived = PublicKey::from_hex(&f.expected.derived_pubkey_hex).unwrap();
            let (script, sats) = p2pkh_payment_output(&derived, f.expected.satoshis)
                .unwrap_or_else(|e| panic!("{label}: {e}"));
            assert_eq!(
                script.to_hex(),
                f.expected.locking_script_hex,
                "{label}: P2PKH locking script must match TS byte-exact"
            );
            assert_eq!(sats, f.expected.satoshis);
        }
    }

    #[test]
    fn envelope_header_value_is_valid_json_with_expected_keys() {
        let env = PaymentEnvelope {
            derivation_prefix_b64: "pfx-test".to_string(),
            derivation_suffix_b64: "sfx-test".to_string(),
            transaction_beef: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let hdr = env.to_header_value();
        let v: serde_json::Value = serde_json::from_str(&hdr).unwrap();
        // Exact key names — any drift here silently breaks server-side
        // `x-bsv-payment` parsing.
        assert_eq!(v["derivationPrefix"], "pfx-test");
        assert_eq!(v["derivationSuffix"], "sfx-test");
        assert_eq!(v["transaction"], "3q2+7w==");
        // No extra keys leaking in.
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), 3, "envelope must have exactly 3 fields");
    }

    #[test]
    fn envelope_handles_empty_transaction_bytes() {
        // Defensive: base64 of empty is "". Not a useful real payment but
        // shouldn't panic.
        let env = PaymentEnvelope {
            derivation_prefix_b64: "a".into(),
            derivation_suffix_b64: "b".into(),
            transaction_beef: Vec::new(),
        };
        let hdr = env.to_header_value();
        let v: serde_json::Value = serde_json::from_str(&hdr).unwrap();
        assert_eq!(v["transaction"], "");
    }
}
