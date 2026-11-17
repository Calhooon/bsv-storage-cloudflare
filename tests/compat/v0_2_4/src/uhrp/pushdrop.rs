//! UHRP PushDrop advertisement encoding — byte-exact port of the TS builder
//! in `~/bsv/storage-server/src/utils/createUHRPAdvertisement.ts:40–66`.
//!
//! # Field layout (PROTOCOL.md §B, authoritative via TS source)
//!
//! The TS server builds **five** PushDrop data fields in strict order, then
//! `PushDrop.lock(..., includeSignature=true)` appends the ECDSA signature as
//! a sixth field:
//!
//! | # | TS field                    | Encoding                                       |
//! |---|-----------------------------|------------------------------------------------|
//! | 0 | server identity pubkey      | raw bytes of `Utils.toArray(pubkey, 'hex')`    |
//! | 1 | file SHA-256 hash           | raw 32 bytes                                    |
//! | 2 | public download URL         | UTF-8 bytes                                     |
//! | 3 | expiry time (unix seconds)  | Bitcoin VarInt (`Writer.writeVarIntNum`)       |
//! | 4 | content length (bytes)      | Bitcoin VarInt                                  |
//! | 5 | signature (auto-appended)   | raw bytes (DER, emitted by the wallet)         |
//!
//! Caller responsibilities (this module does NOT sign):
//! - Compute the signature over `field0 || field1 || field2 || field3 || field4`
//!   via the wallet (protocolID `[2, 'uhrp advertisement']`, keyID `"1"`,
//!   counterparty `"anyone"`), then pass the DER bytes in as `signature`.
//! - Provide the locking public key, which is **different** from field 0: it is
//!   the BRC-42-derived key the wallet returns for the protocol tuple above.
//!   For the storage-server use case they come from the same root identity,
//!   but conceptually — and in our `build_uhrp_advert_lock` signature — they
//!   are independent inputs.
//!
//! # Deviation from task brief
//!
//! The task brief proposed a six-field struct with `content_type` and an
//! explicit `signature` field. The TS advertisement has **no** `content_type`
//! — MIME types are stored in R2/GCS object metadata, never in the PushDrop.
//! Matching TS exactly is the stated quality bar ("byte-equal to TS PushDrop"),
//! so we deviate from the brief's proposed struct and model the five TS fields
//! plus the caller-provided signature. Any future field additions must be
//! mirrored in TS first, never here.
//!
//! # Script shape
//!
//! `PushDrop.lock` lays out:
//!
//! ```text
//! <lockingPubkey:33>  OP_CHECKSIG
//! <field0>  <field1>  <field2>  <field3>  <field4>  <signature>
//! OP_2DROP OP_2DROP OP_2DROP
//! ```
//!
//! Six data fields → three `OP_2DROP`s (no trailing `OP_DROP`). Each field is
//! minimally encoded (OP_0 for empty, OP_1..OP_16 for 1..16, OP_1NEGATE for
//! 0x81, otherwise a direct push / OP_PUSHDATA1/2/4 as size dictates). The
//! bsv-rs `PushDrop` template implements this verbatim — we reuse it rather
//! than re-inlining the logic.

// Routes that consume this module land in task #7b (/advertise + /renew).
// Clippy runs with `-D warnings`, so silence dead_code at the module boundary
// rather than temporarily re-exporting the API through lib.rs.
#![allow(dead_code)]

use bsv_rs::primitives::ec::PublicKey;
use bsv_rs::primitives::encoding::Writer;
use bsv_rs::script::templates::PushDrop;

/// Inputs to `build_uhrp_advert_lock`. Field names mirror the TS source so a
/// cross-check against `createUHRPAdvertisement.ts` is trivial.
#[derive(Debug, Clone)]
pub struct UhrpAdvertFields {
    /// Field 0. Storage-host identity public key, hex-encoded (33 bytes
    /// compressed typical). Pushed as raw bytes after hex decode.
    pub server_identity_key_hex: String,
    /// Field 1. Raw SHA-256 of file contents — the 32-byte payload of the
    /// UHRP URL. `get_hash_from_url` produces exactly these bytes from the URL
    /// callers already have; we take it as `Vec<u8>` to avoid redundant
    /// base58-decode work in the hot path.
    pub hash: Vec<u8>,
    /// Field 2. Public download URL, UTF-8. Pushed as UTF-8 bytes.
    pub url: String,
    /// Field 3. Unix seconds. VarInt-encoded.
    pub expiry_time: u64,
    /// Field 4. File size in bytes. VarInt-encoded.
    pub content_length: u64,
    /// Appended as the trailing PushDrop field. Caller computes this by
    /// signing `field0 || field1 || field2 || field3 || field4` with the wallet
    /// using protocolID `[2, 'uhrp advertisement']`, keyID `"1"`, counterparty
    /// `"anyone"`. Matches what `PushDrop.lock(..., includeSignature=true)`
    /// does on the TS side.
    pub signature: Vec<u8>,
}

/// Module-local error enum. Routes (task #7b) will wire these to the shared
/// `ErrorBody` shape; here we only need a stable string code per the task brief.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UhrpError {
    /// `server_identity_key_hex` was not valid hex or not a valid compressed
    /// pubkey. Stays a single variant because the TS impl handles both cases
    /// identically: a 400 with `ERR_INVALID_REQUEST` on the caller side.
    InvalidPublicKey,
    /// `hash` was not exactly 32 bytes (SHA-256 digest size).
    InvalidHashLength,
    /// `signature` was empty. TS `PushDrop.lock` always appends a non-empty
    /// signature; a caller passing an empty vec is a logic bug, not a user
    /// input we should silently accept.
    EmptySignature,
}

impl UhrpError {
    /// Stable string code for caller-side ErrorBody wiring.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidPublicKey => "ERR_INVALID_PUBLIC_KEY",
            Self::InvalidHashLength => "ERR_INVALID_HASH_LENGTH",
            Self::EmptySignature => "ERR_EMPTY_SIGNATURE",
        }
    }
}

impl std::fmt::Display for UhrpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidPublicKey => "invalid locking public key",
            Self::InvalidHashLength => "UHRP hash must be 32 bytes",
            Self::EmptySignature => "signature must not be empty",
        })
    }
}

impl std::error::Error for UhrpError {}

/// Builds a UHRP-advertisement PushDrop locking script and returns it as
/// lowercase hex. Byte-equal to `@bsv/sdk` `PushDrop.lock(...).toHex()` for
/// identical inputs; enforced by `tests/fixtures/pushdrop/*.json` goldens.
///
/// The `locking_public_key_hex` is the key the wallet returns via
/// `getPublicKey({ protocolID: [2, 'uhrp advertisement'], keyID: '1',
/// counterparty: 'anyone' })`. It is **not** necessarily equal to
/// `fields.server_identity_key_hex` — the former is a BRC-42-derived child,
/// the latter is the root identity. Callers sometimes use the same root key
/// for both; the code makes no such assumption.
pub fn build_uhrp_advert_lock(
    locking_public_key_hex: &str,
    fields: &UhrpAdvertFields,
) -> Result<String, UhrpError> {
    // Parse the locking pubkey. `PublicKey::from_hex` validates both hex format
    // and that the point is on the secp256k1 curve — matches how TS's
    // `wallet.getPublicKey` response would have been validated upstream.
    let locking_pubkey =
        PublicKey::from_hex(locking_public_key_hex).map_err(|_| UhrpError::InvalidPublicKey)?;

    if fields.hash.len() != 32 {
        return Err(UhrpError::InvalidHashLength);
    }
    if fields.signature.is_empty() {
        return Err(UhrpError::EmptySignature);
    }

    // Field 0 — server identity pubkey bytes. Accept any hex-decodable string;
    // the TS version does not curve-validate this field (it's just data), so
    // we don't either. Strict validation happens at the route layer (task
    // #7b) if/when we choose to add it.
    let server_identity_bytes =
        hex_decode(&fields.server_identity_key_hex).map_err(|_| UhrpError::InvalidPublicKey)?;

    // Field 3 — expiry as VarInt. Bitcoin-style VarInt from bsv-rs matches
    // `Utils.Writer.writeVarIntNum` byte-for-byte for non-negative u64.
    let mut expiry_writer = Writer::new();
    expiry_writer.write_var_int(fields.expiry_time);
    let expiry_bytes = expiry_writer.into_bytes();

    // Field 4 — content length as VarInt.
    let mut len_writer = Writer::new();
    len_writer.write_var_int(fields.content_length);
    let content_length_bytes = len_writer.into_bytes();

    // Assemble the six PushDrop fields in TS order: the TS helper pushes the
    // caller-supplied signature as the last field under `includeSignature=true`.
    // Here we do the equivalent explicitly (no wallet call).
    let pushdrop_fields: Vec<Vec<u8>> = vec![
        server_identity_bytes,
        fields.hash.clone(),
        fields.url.as_bytes().to_vec(),
        expiry_bytes,
        content_length_bytes,
        fields.signature.clone(),
    ];

    // `PushDrop::new` defaults to `LockPosition::Before` (the TS default and
    // what `createUHRPAdvertisement.ts` uses). Leave it as-is rather than
    // setting it explicitly to keep the parallel to TS tight.
    let script = PushDrop::new(locking_pubkey, pushdrop_fields).lock();
    Ok(script.to_hex())
}

/// Minimal hex decoder. We don't want to pull an extra hex dep here; the crate
/// already has `hex = "0.4"`, but `hex::decode` returns a typed error that
/// would require importing. Keep the surface tiny.
fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = nibble(bytes[i])?;
        let lo = nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn nibble(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    // Test code is permitted to use `.unwrap()` / `.expect()` freely; the
    // clippy warnings are aimed at production paths. Other test modules in
    // this crate (routes, wallet, storage) follow the same pattern.
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]

    use super::*;
    use serde::Deserialize;

    /// Fixture emitted by `scripts/gen-pushdrop-fixtures.mjs`. Covers
    /// baseline, variable-length URL across the `OP_PUSHDATA2` boundary, a
    /// mismatched server-vs-locking key pair, and large numeric values that
    /// cross the `0xff` VarInt boundary.
    #[derive(Deserialize)]
    struct PushdropFixture {
        locking_public_key_hex: String,
        server_identity_key_hex: String,
        hash_hex: String,
        url: String,
        expiry_time: u64,
        content_length: u64,
        signature_hex: String,
        expected_locking_script_hex: String,
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        hex_decode(s).expect("fixture hex must decode")
    }

    fn fixture_fields(f: &PushdropFixture) -> UhrpAdvertFields {
        UhrpAdvertFields {
            server_identity_key_hex: f.server_identity_key_hex.clone(),
            hash: hex_bytes(&f.hash_hex),
            url: f.url.clone(),
            expiry_time: f.expiry_time,
            content_length: f.content_length,
            signature: hex_bytes(&f.signature_hex),
        }
    }

    macro_rules! golden {
        ($name:ident, $path:literal) => {
            #[test]
            fn $name() {
                let raw = include_str!($path);
                let fixture: PushdropFixture =
                    serde_json::from_str(raw).expect("fixture JSON must parse");
                let fields = fixture_fields(&fixture);
                let got = build_uhrp_advert_lock(&fixture.locking_public_key_hex, &fields)
                    .expect("golden inputs must be valid");
                assert_eq!(
                    got, fixture.expected_locking_script_hex,
                    "PushDrop hex diverged from TS oracle for fixture {}",
                    $path
                );
            }
        };
    }

    golden!(
        golden_baseline_small_cdn_url,
        "../../tests/fixtures/pushdrop/baseline_small_cdn_url.json"
    );
    golden!(
        golden_mismatched_server_and_uploader_keys,
        "../../tests/fixtures/pushdrop/mismatched_server_and_uploader_keys.json"
    );
    golden!(
        golden_url_over_253_bytes_varint_boundary,
        "../../tests/fixtures/pushdrop/url_over_253_bytes_varint_boundary.json"
    );
    golden!(
        golden_large_content_length_over_u32_max,
        "../../tests/fixtures/pushdrop/large_content_length_over_u32_max.json"
    );

    // ---- Unit checks, independent of the golden oracle ---------------------

    fn sample_fields() -> UhrpAdvertFields {
        UhrpAdvertFields {
            server_identity_key_hex:
                "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9".to_string(),
            hash: vec![0u8; 32],
            url: "https://example.com/cdn/abc".to_string(),
            expiry_time: 100,
            content_length: 42,
            signature: vec![0x30, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
        }
    }

    const VALID_LOCKING_PUBKEY: &str =
        "0323176c6e72cf211dd17fe2640444f5df3f82b00e78273374adaee681794b9139";

    #[test]
    fn builder_is_deterministic() {
        let fields = sample_fields();
        let a = build_uhrp_advert_lock(VALID_LOCKING_PUBKEY, &fields)
            .expect("valid inputs must succeed");
        let b = build_uhrp_advert_lock(VALID_LOCKING_PUBKEY, &fields)
            .expect("valid inputs must succeed");
        assert_eq!(a, b, "same inputs must produce same lock script");
    }

    #[test]
    fn rejects_wrong_hash_length() {
        let mut fields = sample_fields();
        fields.hash = vec![0u8; 31];
        let err = build_uhrp_advert_lock(VALID_LOCKING_PUBKEY, &fields)
            .expect_err("31-byte hash must fail");
        assert_eq!(err, UhrpError::InvalidHashLength);
        assert_eq!(err.code(), "ERR_INVALID_HASH_LENGTH");
    }

    #[test]
    fn rejects_empty_signature() {
        let mut fields = sample_fields();
        fields.signature.clear();
        let err = build_uhrp_advert_lock(VALID_LOCKING_PUBKEY, &fields)
            .expect_err("empty signature must fail");
        assert_eq!(err, UhrpError::EmptySignature);
        assert_eq!(err.code(), "ERR_EMPTY_SIGNATURE");
    }

    #[test]
    fn rejects_invalid_locking_public_key_hex() {
        let fields = sample_fields();
        let err = build_uhrp_advert_lock("not-hex-at-all", &fields)
            .expect_err("malformed pubkey must fail");
        assert_eq!(err, UhrpError::InvalidPublicKey);
        assert_eq!(err.code(), "ERR_INVALID_PUBLIC_KEY");
    }

    #[test]
    fn rejects_invalid_server_identity_key_hex() {
        let mut fields = sample_fields();
        fields.server_identity_key_hex = "gg".to_string();
        let err = build_uhrp_advert_lock(VALID_LOCKING_PUBKEY, &fields)
            .expect_err("malformed server identity key must fail");
        assert_eq!(err, UhrpError::InvalidPublicKey);
    }

    #[test]
    fn url_at_252_byte_boundary_matches_subsequent_run() {
        // 252 bytes → direct push (len byte = 0xfc). Compare same-input
        // runs to catch non-determinism creeping in via hashmap ordering
        // or similar.
        let mut fields = sample_fields();
        fields.url = "x".repeat(252);
        let a = build_uhrp_advert_lock(VALID_LOCKING_PUBKEY, &fields)
            .expect("valid inputs must succeed");
        let b = build_uhrp_advert_lock(VALID_LOCKING_PUBKEY, &fields)
            .expect("valid inputs must succeed");
        assert_eq!(a, b);
    }

    #[test]
    fn error_codes_are_stable_strings() {
        // UhrpError codes are part of the public surface — routes will wire
        // them into `ErrorBody.code`. Lock the values so a future rename
        // doesn't silently break the wire contract.
        assert_eq!(UhrpError::InvalidPublicKey.code(), "ERR_INVALID_PUBLIC_KEY");
        assert_eq!(
            UhrpError::InvalidHashLength.code(),
            "ERR_INVALID_HASH_LENGTH"
        );
        assert_eq!(UhrpError::EmptySignature.code(), "ERR_EMPTY_SIGNATURE");
    }

    /// End-to-end: build an advert via the same primitives as
    /// `routes/advertise.rs::build_advert_bundle`, then run inline the
    /// EXACT checks tm_uhrp's `identify_admissible_outputs` performs
    /// (signature verify + locking-key linkage). If this test passes, our
    /// PushDrop bytes are admissible — meaning any "empty admissions"
    /// rejection from a deployed overlay must come from a downstream
    /// transformation (BEEF construction, signing pipeline, etc).
    #[test]
    fn validator_admits_our_advert() {
        use bsv_rs::primitives::ec::{PrivateKey, PublicKey};
        use bsv_rs::primitives::encoding::{to_hex, Reader};
        use bsv_rs::primitives::hash::sha256;
        use bsv_rs::script::templates::PushDrop as PushDropTemplate;
        use bsv_rs::script::LockingScript;
        use bsv_rs::wallet::{GetPublicKeyArgs, KeyDeriver, ProtoWallet, VerifySignatureArgs};

        use crate::wallet::brc42::{uhrp_protocol_id, UHRP_KEY_ID};
        use bsv_rs::wallet::Counterparty;

        // ── Author side (mirrors advertise.rs:413-475) ────────────────
        let admin_key = PrivateKey::random();
        let identity_pub = admin_key.public_key();
        let identity_bytes = identity_pub.to_compressed();

        let deriver = KeyDeriver::new(Some(admin_key.clone()));
        let locking_pubkey = deriver
            .derive_public_key(
                &uhrp_protocol_id(),
                UHRP_KEY_ID,
                &Counterparty::Anyone,
                true,
            )
            .unwrap();
        let signing_key = deriver
            .derive_private_key(&uhrp_protocol_id(), UHRP_KEY_ID, &Counterparty::Anyone)
            .unwrap();

        let url = "https://example.com/cdn/abc123";
        let hash = [0xAAu8; 32];
        let expiry: u64 = 1_800_000_000;
        let length: u64 = 12_345;

        let mut w = Writer::new();
        w.write_var_int(expiry);
        let expiry_bytes = w.into_bytes();
        let mut w = Writer::new();
        w.write_var_int(length);
        let length_bytes = w.into_bytes();

        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(&identity_bytes);
        sign_data.extend_from_slice(&hash);
        sign_data.extend_from_slice(url.as_bytes());
        sign_data.extend_from_slice(&expiry_bytes);
        sign_data.extend_from_slice(&length_bytes);
        let sig_der = signing_key.sign(&sha256(&sign_data)).unwrap().to_der();

        let advert_fields = UhrpAdvertFields {
            server_identity_key_hex: to_hex(&identity_bytes),
            hash: hash.to_vec(),
            url: url.to_string(),
            expiry_time: expiry,
            content_length: length,
            signature: sig_der.clone(),
        };
        let lock_hex = build_uhrp_advert_lock(&locking_pubkey.to_hex(), &advert_fields).unwrap();

        // ── Validator side (mirrors topic_manager.rs:218-265) ─────────
        let lock = LockingScript::from_hex(&lock_hex).unwrap();
        let pd = PushDropTemplate::decode(&lock).unwrap();

        assert_eq!(pd.fields.len(), 6, "5 data fields + signature");
        assert_eq!(pd.fields[0], identity_bytes.to_vec(), "field[0] identity");
        assert_eq!(pd.fields[1].len(), 32, "field[1] hash size");
        assert_eq!(pd.fields[2], url.as_bytes(), "field[2] URL");
        assert_eq!(
            Reader::new(&pd.fields[3]).read_var_int().unwrap(),
            expiry,
            "field[3] expiry decode"
        );
        assert_eq!(
            Reader::new(&pd.fields[4]).read_var_int().unwrap(),
            length,
            "field[4] length decode"
        );
        assert_eq!(pd.fields[5], sig_der, "field[5] signature");

        // Verifier: data = concat(field[0..5]) (the 5 data fields)
        let verify_data: Vec<u8> = pd.fields[0..5]
            .iter()
            .flat_map(|f| f.iter().copied())
            .collect();
        assert_eq!(verify_data, sign_data, "verifier reconstructs sign_data");

        let anyone = ProtoWallet::anyone();
        let counterparty = Counterparty::Other(identity_pub);
        let sig_check = anyone
            .verify_signature(VerifySignatureArgs {
                data: Some(verify_data),
                hash_to_directly_verify: None,
                signature: pd.fields[5].clone(),
                protocol_id: uhrp_protocol_id(),
                key_id: UHRP_KEY_ID.to_string(),
                counterparty: Some(counterparty.clone()),
                for_self: None,
            })
            .expect("verify_signature should succeed");
        assert!(sig_check.valid, "signature must verify");

        let expected = anyone
            .get_public_key(GetPublicKeyArgs {
                identity_key: false,
                protocol_id: Some(uhrp_protocol_id()),
                key_id: Some(UHRP_KEY_ID.to_string()),
                counterparty: Some(counterparty),
                for_self: None,
            })
            .unwrap()
            .public_key;
        let pd_locking_hex = pd.locking_public_key.to_hex();
        assert_eq!(
            expected, pd_locking_hex,
            "locking key linkage: expected (anyone-view of identity) must equal pushdrop locking key"
        );

        // Sanity: round-trip via PublicKey too
        let _ = PublicKey::from_hex(&expected).unwrap();
    }

    /// TS-SDK parity: every BRC-42 `derivePublicKey(protocol, keyID,
    /// counterparty, forSelf)` variant we use in production must produce
    /// the exact same child pubkey `@bsv/sdk 1.10.1`'s `KeyDeriver` does.
    /// If this test ever flips red, our wallet is signing with a key
    /// different from what the TS side expects — silent federation
    /// break, invisible until a cross-network push.
    #[test]
    #[allow(clippy::panic)]
    fn ts_sdk_brc42_derivation_byte_exact_goldens() {
        use bsv_rs::primitives::ec::PrivateKey;
        use bsv_rs::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Input {
            protocol: (u32, String),
            key_id: String,
            counterparty: String,
            for_self: bool,
        }
        #[derive(Deserialize)]
        struct Expected {
            derived_pubkey_hex: String,
        }
        #[derive(Deserialize)]
        struct Fixture {
            admin_priv_hex: String,
            input: Input,
            expected: Expected,
        }

        let fixtures: &[(&str, &str)] = &[
            (
                "brc42_uhrp_anyone_locking",
                include_str!("../../tests/parity/fixtures/parity/brc42_uhrp_anyone_locking.json"),
            ),
            (
                "brc42_ship_anyone_locking",
                include_str!("../../tests/parity/fixtures/parity/brc42_ship_anyone_locking.json"),
            ),
            (
                "brc42_brc29_payment_to_admin",
                include_str!(
                    "../../tests/parity/fixtures/parity/brc42_brc29_payment_to_admin.json"
                ),
            ),
        ];

        for (name, raw) in fixtures {
            let f: Fixture = serde_json::from_str(raw).expect("fixture parse");
            let admin_key = PrivateKey::from_hex(&f.admin_priv_hex).unwrap();
            let security_level = match f.input.protocol.0 {
                0 => SecurityLevel::Silent,
                1 => SecurityLevel::App,
                2 => SecurityLevel::Counterparty,
                other => panic!("{name}: unknown security level {other}"),
            };
            let protocol = Protocol::new(security_level, &f.input.protocol.1);
            let counterparty = match f.input.counterparty.as_str() {
                "anyone" => Counterparty::Anyone,
                "self" => Counterparty::Self_,
                hex_str if hex_str.len() == 66 => Counterparty::Other(
                    bsv_rs::primitives::ec::PublicKey::from_hex(hex_str).unwrap(),
                ),
                other => panic!("{name}: unsupported counterparty {other}"),
            };

            let deriver = KeyDeriver::new(Some(admin_key));
            let derived = deriver
                .derive_public_key(&protocol, &f.input.key_id, &counterparty, f.input.for_self)
                .unwrap();
            assert_eq!(
                derived.to_hex(),
                f.expected.derived_pubkey_hex,
                "\nBRC-42 {name} DIVERGES FROM @bsv/sdk 1.10.1\n  ours  : {}\n  theirs: {}\n",
                derived.to_hex(),
                f.expected.derived_pubkey_hex
            );
        }
    }

    /// TS-SDK parity: rebuild every UHRP PushDrop fixture in
    /// `tests/parity/fixtures/parity/uhrp_*.json` using our Rust
    /// implementation, assert byte-exact match against the canonical
    /// `locking_script_hex` produced by `@bsv/sdk 1.10.1` (the exact
    /// version `nanostore.babbage.systems` runs).
    ///
    /// Fixtures are regenerated by
    /// `tests/parity/ts-fixtures/generate.mjs`. Any change in bsv-rs's
    /// PushDrop template, BRC-42 derivation, varint encoding, or ECDSA
    /// deterministic-k path that diverges from @bsv/sdk will flip this
    /// test red.
    ///
    /// We invoke our own BRC-42 helpers + the signer path that
    /// `build_advert_bundle` uses — NOT a shortcut — so the whole
    /// advert-build pipeline is protocol-equivalent to TS.
    #[test]
    fn ts_sdk_uhrp_pushdrop_byte_exact_goldens() {
        use crate::wallet::brc42::{
            derive_child_key, derive_child_public_key, uhrp_protocol_id, UHRP_COUNTERPARTY_ANYONE,
            UHRP_KEY_ID,
        };
        use bsv_rs::primitives::ec::PrivateKey;
        use bsv_rs::primitives::encoding::{to_hex, Writer};
        use bsv_rs::primitives::hash::sha256;
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Input {
            url: String,
            hash_hex: String,
            expiry_time: u64,
            content_length: u64,
        }
        #[derive(Deserialize)]
        struct Expected {
            locking_script_hex: String,
        }
        #[derive(Deserialize)]
        struct Fixture {
            admin_priv_hex: String,
            input: Input,
            expected: Expected,
        }

        // Every fixture file in tests/parity/fixtures/parity/uhrp_*.json.
        // include_str! embeds them so cargo test needs no filesystem setup.
        let fixtures: &[(&str, &str)] = &[
            (
                "uhrp_baseline_small_cdn_url",
                include_str!("../../tests/parity/fixtures/parity/uhrp_baseline_small_cdn_url.json"),
            ),
            (
                "uhrp_url_at_253_byte_varint_boundary",
                include_str!(
                    "../../tests/parity/fixtures/parity/uhrp_url_at_253_byte_varint_boundary.json"
                ),
            ),
            (
                "uhrp_url_over_varint_u16_boundary",
                include_str!(
                    "../../tests/parity/fixtures/parity/uhrp_url_over_varint_u16_boundary.json"
                ),
            ),
            (
                "uhrp_zero_hash_edge",
                include_str!("../../tests/parity/fixtures/parity/uhrp_zero_hash_edge.json"),
            ),
            (
                "uhrp_past_expiry_ts_parity",
                include_str!("../../tests/parity/fixtures/parity/uhrp_past_expiry_ts_parity.json"),
            ),
        ];

        for (name, raw) in fixtures {
            let f: Fixture = serde_json::from_str(raw).expect("fixture parse");
            let admin_key = PrivateKey::from_hex(&f.admin_priv_hex).unwrap();
            let hash: Vec<u8> = hex_decode(&f.input.hash_hex).unwrap();
            assert_eq!(hash.len(), 32, "{name}: hash must be 32 bytes");

            let protocol = uhrp_protocol_id();
            let locking_pk = derive_child_public_key(
                &admin_key,
                &protocol,
                UHRP_KEY_ID,
                UHRP_COUNTERPARTY_ANYONE,
            )
            .unwrap();
            let signing_key =
                derive_child_key(&admin_key, &protocol, UHRP_KEY_ID, UHRP_COUNTERPARTY_ANYONE)
                    .unwrap();

            let id_bytes = admin_key.public_key().to_compressed();
            let mut ew = Writer::new();
            ew.write_var_int(f.input.expiry_time);
            let expiry_bytes = ew.into_bytes();
            let mut lw = Writer::new();
            lw.write_var_int(f.input.content_length);
            let len_bytes = lw.into_bytes();

            let mut sign_data = Vec::new();
            sign_data.extend_from_slice(&id_bytes);
            sign_data.extend_from_slice(&hash);
            sign_data.extend_from_slice(f.input.url.as_bytes());
            sign_data.extend_from_slice(&expiry_bytes);
            sign_data.extend_from_slice(&len_bytes);
            let sig_der = signing_key.sign(&sha256(&sign_data)).unwrap().to_der();

            let advert = UhrpAdvertFields {
                server_identity_key_hex: to_hex(&id_bytes),
                hash,
                url: f.input.url.clone(),
                expiry_time: f.input.expiry_time,
                content_length: f.input.content_length,
                signature: sig_der,
            };
            let got = build_uhrp_advert_lock(&locking_pk.to_hex(), &advert).unwrap();

            assert_eq!(
                got, f.expected.locking_script_hex,
                "\nFIXTURE {name} DIVERGES FROM @bsv/sdk 1.10.1\n  ours  : {got}\n  theirs: {}\n",
                f.expected.locking_script_hex
            );
        }
    }

    /// Captured `locking_script_hex` from a LIVE queue-driven /advertise
    /// attempt (CF tail 2026-04-21) that rust-overlay's tm_uhrp rejected
    /// with `outputsToAdmit=[]`. If this script is structurally valid and
    /// signature-linked, the bug is NOT in the PushDrop bytes — it's
    /// elsewhere (BEEF wrapping, topic manager de-dup, something).
    ///
    /// Admin pubkey: 02837c91defe23ca5bb4ec1fccd82e1e6fcba8f80e7632d360a7cb34e851dda663
    /// Locking pubkey derived: 026c825ea077ba06dcbf6503fcfd429f48afb63093fdc4ea3e1f345a7d54928a7e
    #[test]
    fn on_chain_advert_parses_and_linkage_check() {
        use crate::wallet::brc42::{uhrp_protocol_id, UHRP_KEY_ID};
        use bsv_rs::primitives::ec::PublicKey;
        use bsv_rs::primitives::encoding::Reader;
        use bsv_rs::script::templates::PushDrop as PushDropTemplate;
        use bsv_rs::script::LockingScript;
        use bsv_rs::wallet::Counterparty;
        use bsv_rs::wallet::{GetPublicKeyArgs, ProtoWallet, VerifySignatureArgs};

        // This is the EXACT script_hex from the production log.
        let hex = "21026c825ea077ba06dcbf6503fcfd429f48afb63093fdc4ea3e1f345a7d54928a7eac2102837c91defe23ca5bb4ec1fccd82e1e6fcba8f80e7632d360a7cb34e851dda6632062a79a5d0c9a18e9a9c3cf88959be4b95bee1e041c031a7c12f22bf5c9f7e84e4c4d68747470733a2f2f7075622d30633936353334343935343134323930393632326434633261656439316638372e72322e6465762f63646e2f73335169314e66386d7866444c7067366567545a6405fe9bd7f969011b463044022024fd69e50f52cc0f900b1e9340466beebd2f759b8747fee99d30443672f22ca602200f9a20e0a60a0217a0be31cad9c25c42e42a969aa01456c9bec973a88c99f7d26d6d6d";

        let lock = LockingScript::from_hex(hex).unwrap();
        let pd = PushDropTemplate::decode(&lock).unwrap();
        assert_eq!(pd.fields.len(), 6, "expected 5 data + signature");

        // Field 0 must parse as a valid compressed pubkey.
        let identity_pub = PublicKey::from_bytes(&pd.fields[0])
            .expect("field[0] must be a valid compressed pubkey");
        println!("field[0] pubkey: {}", identity_pub.to_hex());

        // Field 2 must parse as UTF-8 + valid URL.
        let url = std::str::from_utf8(&pd.fields[2]).expect("field[2] is UTF-8");
        println!("field[2] URL: {}", url);
        assert!(url.starts_with("https://"), "URL must be https");

        // Field 3 must decode as VarInt (expiry).
        let expiry = Reader::new(&pd.fields[3])
            .read_var_int()
            .expect("VarInt expiry");
        println!("field[3] expiry: {}", expiry);
        assert!(expiry >= 1, "expiry must be >= 1");

        // Field 4 must decode as VarInt (content_length).
        let length = Reader::new(&pd.fields[4])
            .read_var_int()
            .expect("VarInt length");
        println!("field[4] length: {}", length);
        assert!(length >= 1, "length must be >= 1");

        // Check locking key linkage: anyone-wallet view of counterparty=Other(identity)
        // should equal the PushDrop locking key.
        let anyone = ProtoWallet::anyone();
        let expected = anyone
            .get_public_key(GetPublicKeyArgs {
                identity_key: false,
                protocol_id: Some(uhrp_protocol_id()),
                key_id: Some(UHRP_KEY_ID.to_string()),
                counterparty: Some(Counterparty::Other(identity_pub.clone())),
                for_self: None,
            })
            .unwrap()
            .public_key;
        let locking_hex = pd.locking_public_key.to_hex();
        println!("expected linkage pubkey: {}", expected);
        println!("actual locking pubkey:   {}", locking_hex);
        assert_eq!(expected, locking_hex, "locking key linkage mismatch");

        // Verify signature.
        let sign_data: Vec<u8> = pd.fields[0..5]
            .iter()
            .flat_map(|f| f.iter().copied())
            .collect();
        let r = anyone
            .verify_signature(VerifySignatureArgs {
                data: Some(sign_data),
                hash_to_directly_verify: None,
                signature: pd.fields[5].clone(),
                protocol_id: uhrp_protocol_id(),
                key_id: UHRP_KEY_ID.to_string(),
                counterparty: Some(Counterparty::Other(identity_pub)),
                for_self: None,
            })
            .expect("verify_signature must succeed for on-chain advert");
        assert!(r.valid, "signature verification failed for on-chain advert");
        println!("ADMITTED: signature valid + linkage valid");
    }
}
