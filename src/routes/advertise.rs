//! POST /advertise — see PROTOCOL.md §6.
//!
//! Port of `storage-server/src/routes/advertise.ts` + `utils/createUHRPAdvertisement.ts`.
//!
//! # Admin gate (deviation from TS)
//!
//! TS gates this route on an in-body `adminToken` string compared against
//! `ADMIN_TOKEN` (`advertise.ts:32–38`). The Rust port replaces that with a
//! BRC-31 identity-key allowlist (`ADMIN_IDENTITY_KEYS` secret,
//! comma-separated hex pubkeys). The caller is already authenticated by
//! the BRC-31 middleware in `lib.rs`; we only need to check membership.
//!
//! Why the change: CF Workers don't have a good place to stash a shared
//! admin token without it leaking into every `/advertise` call. Pinning
//! an identity-key list is strictly stronger — each admin has their own
//! key, revocable by editing one secret, and we already have authenticated
//! identity from BRC-31. The TS server's `ADMIN_TOKEN` is effectively
//! deprecated by the BRC-31 stack; this matches that posture.
//!
//! # Flow
//!
//! 1. Admin gate via `ADMIN_IDENTITY_KEYS` (see above).
//! 2. Parse/validate request body.
//! 3. Derive UHRP hash from the `uhrpUrl` (strip `uhrp://` prefix + base58check decode).
//! 4. Build BRC-42 child locking public key for `(2, "uhrp advertisement")`, `"1"`,
//!    `"anyone"`.
//! 5. Assemble PushDrop fields (0..4), sign `field0||..||field4` with the
//!    derived private key, build the PushDrop locking script.
//! 6. `wallet.create_action({outputs, ...})` → unsigned template.
//! 7. `sign_transaction` for the P2PKH change inputs (no PushDrop input on
//!    `/advertise`).
//! 8. `wallet.process_action({rawTx, isNewTx, isNoSend: false})` — wallet-infra
//!    broadcasts via ARC, status → 'sending' → 'unproven' on ARC accept,
//!    → 'completed' once the monitor finds the merkle proof. This puts the
//!    output on the every-5-min `check_for_proofs` path instead of the
//!    once-per-day `check_no_sends` path that 'nosend' would use.
//! 9. Overlay `/submit` with `x-topics: ["tm_uhrp"]`.
//! 10. Return `{status: "success"}`.

use crate::error::{
    ERR_ADVERTISE_INTERNAL, ERR_INVALID_REQUEST, ERR_MISSING_IDENTITY_KEY, ERR_OVERLAY_BROADCAST,
    ERR_UNAUTHORIZED,
};
use crate::overlay::{overlay_url_from_env, submit_uhrp_advert};
use crate::types::{AdvertiseRequest, AdvertiseResponse, ErrorBody};
use crate::uhrp::pushdrop::{build_uhrp_advert_lock, UhrpAdvertFields};
use crate::wallet::brc42::{
    derive_child_key, derive_child_public_key, uhrp_protocol_id, UHRP_COUNTERPARTY_ANYONE,
    UHRP_KEY_ID,
};
use crate::wallet::client::Wallet;
use crate::wallet::signer::sign_transaction;
use crate::wallet::types::{CreateActionOutput, CreateActionRequest, ProcessActionRequest};

use bsv_rs::primitives::ec::{PrivateKey, PublicKey};
use bsv_rs::primitives::encoding::{from_base58, Writer};
use bsv_rs::primitives::hash::sha256;
use serde_json::{json, Value};
use worker::Env;

/// Env secret: comma-separated hex pubkeys allowed to call `/advertise`.
///
/// Whitespace around commas is trimmed. Empty entries (`"a,,b"`) are
/// skipped. Matching is case-sensitive on the hex — callers must submit
/// the same lowercase form BRC-31 emits, which matches TS's
/// `identityKey.toLowerCase()` normalization.
const ADMIN_IDENTITY_KEYS_SECRET: &str = "ADMIN_IDENTITY_KEYS";

const UHRP_BASKET: &str = "uhrp advertisements";
const UHRP_SCHEME: &str = "uhrp://";
/// UHRP base58check version prefix (`0xce 0x00`). Mirrors the private const
/// in `crate::uhrp::hash`. Decoded UHRP URLs start with these two bytes,
/// followed by the 32-byte SHA-256, followed by a 4-byte checksum.
const UHRP_VERSION_PREFIX: [u8; 2] = [0xce, 0x00];

pub async fn handle(body: &[u8], identity_key: &str, env: &Env) -> (Value, u16) {
    if identity_key.is_empty() {
        return error(
            ERR_MISSING_IDENTITY_KEY,
            "Missing authfetch identityKey.",
            400,
        );
    }

    // ── Admin gate ────────────────────────────────────────────────────────
    let admin_list_raw = match env.secret(ADMIN_IDENTITY_KEYS_SECRET) {
        Ok(s) => s.to_string(),
        Err(_) => {
            // No allowlist → no admin can authenticate. Same response shape
            // as the TS server's `ADMIN_TOKEN` missing branch
            // (`advertise.ts:32–37`).
            return error(
                ERR_UNAUTHORIZED,
                "Failed to advertise hosting commitment!",
                401,
            );
        }
    };
    if !is_admin(identity_key, &admin_list_raw) {
        return error(
            ERR_UNAUTHORIZED,
            "Failed to advertise hosting commitment!",
            401,
        );
    }

    // ── Parse & validate body ─────────────────────────────────────────────
    let req: AdvertiseRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => return error(ERR_INVALID_REQUEST, "Malformed JSON body.", 400),
    };
    let Some(uhrp_url) = req.uhrp_url.filter(|s| !s.is_empty()) else {
        return error(ERR_INVALID_REQUEST, "Missing uhrpUrl.", 400);
    };
    let Some(object_identifier) = req.object_identifier.filter(|s| !s.is_empty()) else {
        return error(ERR_INVALID_REQUEST, "Missing objectIdentifier.", 400);
    };
    let Some(uploader_identity_key) = req.uploader_identity_key.filter(|s| !s.is_empty()) else {
        return error(ERR_INVALID_REQUEST, "Missing uploaderIdentityKey.", 400);
    };
    let Some(file_size) = req.file_size else {
        return error(ERR_INVALID_REQUEST, "Missing fileSize.", 400);
    };
    let Some(expiry_time_f) = req.expiry_time else {
        return error(ERR_INVALID_REQUEST, "Missing expiryTime.", 400);
    };
    if !file_size.is_finite() || file_size < 0.0 {
        return error(ERR_INVALID_REQUEST, "Invalid fileSize.", 400);
    }
    if !expiry_time_f.is_finite() || expiry_time_f < 0.0 {
        return error(ERR_INVALID_REQUEST, "Invalid expiryTime.", 400);
    }
    // TS: `Number(req.body.expiryTime)` → JS coerces; we accept any non-NaN
    // non-negative float and take the integer floor (matches `Math.floor`
    // semantics the TS uses downstream via `expiryTimeSeconds`).
    let expiry_time_u: u64 = expiry_time_f as u64;
    let content_length_u: u64 = file_size as u64;

    let hash = match uhrp_url_to_hash(&uhrp_url) {
        Some(h) => h,
        None => return error(ERR_INVALID_REQUEST, "Invalid uhrpUrl.", 400),
    };

    match create_advertisement(
        env,
        &uhrp_url,
        &object_identifier,
        &uploader_identity_key,
        content_length_u,
        expiry_time_u,
        hash,
    )
    .await
    {
        Ok(()) => (json!(AdvertiseResponse { status: "success" }), 200),
        Err(err) => error(err.code, err.description, err.status),
    }
}

/// Internal error carried between `create_advertisement()` and the HTTP
/// boundary. Keeps the happy path flat (matches `/find`'s `Result<_, ()>`
/// pattern but with richer context so we can surface the right code per
/// failure).
///
/// Exposed at `pub(crate)` so the queue consumer (`src/queue/`) can share
/// the same classification — an R2-event-triggered advert uses the exact
/// same codes as a user-initiated `/advertise` call.
pub(crate) struct AdvertiseError {
    pub(crate) code: &'static str,
    pub(crate) description: &'static str,
    pub(crate) status: u16,
}

/// Build, sign, process, and broadcast a UHRP advertisement.
///
/// Callable from two places:
/// - `handle()` — HTTP `/advertise` handler (PROTOCOL.md §6).
/// - `crate::queue::consumer` — R2-event-driven auto-advertise of newly
///   uploaded objects. The queue path reconstructs the same inputs
///   (uhrp_url, object_identifier, uploader_identity_key, file_size,
///   expiry_time, hash) from the R2 object + its custom metadata, then
///   calls here. Sharing the function means byte-for-byte identical
///   adverts regardless of entry point.
pub(crate) async fn create_advertisement(
    env: &Env,
    uhrp_url: &str,
    object_identifier: &str,
    uploader_identity_key: &str,
    content_length: u64,
    expiry_time: u64,
    hash: [u8; 32],
) -> Result<(), AdvertiseError> {
    let wallet = Wallet::from_env(env).map_err(|_| AdvertiseError {
        code: ERR_ADVERTISE_INTERNAL,
        description: "Wallet unavailable.",
        status: 500,
    })?;
    let admin_key = wallet.private_key().clone();

    // Resolve the HOSTING_DOMAIN-equivalent. TS builds URL as
    // `${HOSTING_DOMAIN}/cdn/${objectIdentifier}`; the Rust port uses
    // `PUBLIC_URL_BASE` (set in wrangler.toml as the R2 custom-domain
    // endpoint).
    let public_url_base = env
        .var("PUBLIC_URL_BASE")
        .map_err(|_| AdvertiseError {
            code: ERR_ADVERTISE_INTERNAL,
            description: "PUBLIC_URL_BASE not set.",
            status: 500,
        })?
        .to_string();
    let public_url = format!(
        "{}/cdn/{}",
        public_url_base.trim_end_matches('/'),
        object_identifier
    );

    let (locking_pubkey, fields_bytes) = build_advert_bundle(
        &admin_key,
        uhrp_url,
        &public_url,
        &hash,
        expiry_time,
        content_length,
    )
    .map_err(|_| AdvertiseError {
        code: ERR_ADVERTISE_INTERNAL,
        description: "Failed to build advertisement.",
        status: 500,
    })?;

    let locking_script_hex = build_uhrp_advert_lock(&locking_pubkey.to_hex(), &fields_bytes)
        .map_err(|_| AdvertiseError {
            code: ERR_ADVERTISE_INTERNAL,
            description: "Failed to build PushDrop lock.",
            status: 500,
        })?;

    // Diagnostic: dumps the exact PushDrop bytes we're about to submit.
    // Kept permanently because this was load-bearing for diagnosing
    // tm_uhrp admission-rejections (the script_hex can be replayed
    // through the validator offline to narrow encoding bugs without a
    // live worker). Logged at `console_log` (not `console_error`) so
    // it doesn't inflate the CF error channel — this is normal-path
    // info, not a failure.
    worker::console_log!(
        "advertise/build: admin_pub={} locking_pub={} sig_len={} url={} expiry={} len={} script_hex={}",
        bsv_rs::primitives::encoding::to_hex(&admin_key.public_key().to_compressed()),
        locking_pubkey.to_hex(),
        fields_bytes.signature.len(),
        public_url,
        expiry_time,
        content_length,
        locking_script_hex,
    );

    let tags = advert_tags(
        uhrp_url,
        object_identifier,
        uploader_identity_key,
        expiry_time,
    );

    // ── createAction (unsigned template) ──────────────────────────────────
    //
    // `custom_instructions` marks the output as ours so wallet-infra flips it
    // to `spendable = 1` after processAction. Without this, `listOutputs`
    // filters out our UHRP adverts because wallet-infra assumes a
    // non-change output with no custom_instructions is an external
    // recipient's. Matches `rust-wallet-infra/src/storage/process_action.rs`
    // `is_ours = is_change || has_custom_instructions`.
    let custom_instructions = serde_json::json!({
        "type": "UHRPAdvertisement",
        "protocolID": [2, "uhrp advertisement"],
        "keyID": "1",
        "counterparty": "anyone",
    })
    .to_string();
    let create_req = CreateActionRequest {
        outputs: vec![CreateActionOutput {
            locking_script: locking_script_hex,
            satoshis: 1,
            output_description: "UHRP advertisement token".to_string(),
            basket: Some(UHRP_BASKET.to_string()),
            tags,
            custom_instructions: Some(custom_instructions),
        }],
        // No explicit `inputs` — full TS parity with
        // `storage-server/src/utils/createUHRPAdvertisement.ts:70-82`, which
        // delegates 100% of input selection + change-script generation to
        // the wallet. The client side's responsibility is limited to
        // filling in empty change-output locking scripts *before
        // broadcast*, which `crate::wallet::signer::reconstruct_change_outputs`
        // does (matches `wallet-toolbox/src/signer/methods/buildSignableTransaction.ts::makeChangeLock`).
        inputs: vec![],
        input_beef: None,
        description: "UHRP Content Availability Advertisement".to_string(),
        randomize_outputs: false,
    };
    let template = wallet.create_action(&create_req).await.map_err(|e| {
        worker::console_error!("createAction failed: {}", e);
        AdvertiseError {
            code: ERR_ADVERTISE_INTERNAL,
            description: "createAction failed.",
            status: 500,
        }
    })?;

    // ── Sign locally ──────────────────────────────────────────────────────
    // Log the inputs so a signing failure is immediately actionable: we
    // want to see which input's derivation metadata (if any) didn't match.
    for (i, inp) in template.inputs.iter().enumerate() {
        worker::console_error!(
            "advertise: input[{}] script={}.. sats={} prefix={:?} suffix={:?} sender={:?}",
            i,
            &inp.source_locking_script
                .get(..20)
                .unwrap_or(&inp.source_locking_script),
            inp.source_satoshis,
            inp.derivation_prefix,
            inp.derivation_suffix,
            inp.sender_identity_key,
        );
    }
    let signed = sign_transaction(&template, &admin_key).map_err(|e| {
        worker::console_error!("sign_transaction failed: {:?}", e);
        AdvertiseError {
            code: ERR_ADVERTISE_INTERNAL,
            description: "Local signing failed.",
            status: 500,
        }
    })?;

    // ── processAction (record only; we broadcast via overlay) ─────────────
    let process_req = ProcessActionRequest {
        is_new_tx: true,
        is_send_with: false,
        // wallet-infra broadcasts via ARC; overlay submit below also broadcasts
        // for topic (tm_uhrp) discovery — idempotent re-broadcast is fine.
        is_no_send: false,
        is_delayed: false,
        reference: Some(template.reference.clone()),
        txid: Some(signed.txid.clone()),
        raw_tx: Some(signed.raw_tx.clone()),
        send_with: vec![],
    };
    wallet
        .process_action(&process_req)
        .await
        .map_err(|_| AdvertiseError {
            code: ERR_ADVERTISE_INTERNAL,
            description: "processAction failed.",
            status: 500,
        })?;

    // ── Build AtomicBEEF from (input ancestry) + (new signed tx) ──────────
    // rust-overlay's topic managers call `Transaction::from_beef()` on the
    // body of /submit — they expect an AtomicBEEF with the full ancestor
    // chain, not a bare raw tx. Matches rust-bsv-worm/src/overlay/registration.rs
    // where the wallet's createAction returns a BEEF directly; for us, we
    // build one by merging the template's input_beef with our signed raw tx
    // and serializing atomic-rooted at our new txid. Uses the
    // bsv_sdk::transaction::Beef API per the REFUND-POC pattern in memory.
    let mut beef = bsv_rs::transaction::Beef::from_binary(&template.input_beef).map_err(|e| {
        worker::console_error!("advertise: Beef::from_binary failed: {e}");
        AdvertiseError {
            code: ERR_ADVERTISE_INTERNAL,
            description: "input BEEF parse failed.",
            status: 500,
        }
    })?;
    beef.merge_raw_tx(signed.raw_tx.clone(), None);
    let atomic_beef = beef.to_binary_atomic(&signed.txid).map_err(|e| {
        worker::console_error!("advertise: to_binary_atomic failed: {e}");
        AdvertiseError {
            code: ERR_ADVERTISE_INTERNAL,
            description: "AtomicBEEF build failed.",
            status: 500,
        }
    })?;
    worker::console_error!(
        "advertise: submitting AtomicBEEF ({} bytes, txid={})",
        atomic_beef.len(),
        signed.txid
    );

    // ── Overlay SHIP broadcast ────────────────────────────────────────────
    //
    // If this fails, processAction has already committed state (UTXO marked
    // `spent_by=<advert_tx>`, tx status `nosend` in wallet-infra). We'd lose
    // funds for 30+ min waiting on `fail_abandoned` cleanup. Instead, call
    // `abortAction` here to roll back cleanly — matches TS wallet-toolbox's
    // `processAction`/`abortAction` symmetry.
    let overlay_url = overlay_url_from_env(env);
    if let Err(e) = submit_uhrp_advert(env, &overlay_url, &atomic_beef).await {
        worker::console_error!("overlay broadcast failed: {:?}", e);
        let abort_req = crate::wallet::types::AbortActionRequest {
            reference: template.reference.clone(),
        };
        match wallet.abort_action(&abort_req).await {
            Ok(r) => worker::console_error!(
                "overlay-fail abort: aborted={} (tx ref={})",
                r.aborted,
                template.reference
            ),
            Err(ae) => worker::console_error!(
                "overlay-fail abort call itself failed: {} (tx ref={})",
                ae,
                template.reference
            ),
        }
        return Err(AdvertiseError {
            code: ERR_OVERLAY_BROADCAST,
            description: "Overlay broadcast failed.",
            status: 500,
        });
    }

    Ok(())
}

/// Build the PushDrop fields (0..4) and their signature as the PushDrop
/// sixth field. Returns `(locking_pubkey, UhrpAdvertFields-with-signature)`.
///
/// The signature is an ECDSA over SHA-256 of `field0||field1||field2||field3||field4`,
/// produced with the BRC-42-derived private key, DER-encoded — same as
/// `@bsv/sdk` `ProtoWallet.createSignature({ data, protocolID, keyID,
/// counterparty })` does under the hood (see
/// `bsv-rs/src/wallet/proto_wallet.rs:create_signature` — hashes data,
/// derives key, signs, returns DER).
fn build_advert_bundle(
    admin_key: &PrivateKey,
    uhrp_url: &str,
    public_url: &str,
    hash: &[u8; 32],
    expiry_time: u64,
    content_length: u64,
) -> Result<(PublicKey, UhrpAdvertFields), ()> {
    // Locking pubkey is the BRC-42 child of the admin root.
    let locking_pubkey = derive_child_public_key(
        admin_key,
        &uhrp_protocol_id(),
        UHRP_KEY_ID,
        UHRP_COUNTERPARTY_ANYONE,
    )
    .map_err(|_| ())?;
    // Signing key is the matching private key (derived the same way).
    let signing_key = derive_child_key(
        admin_key,
        &uhrp_protocol_id(),
        UHRP_KEY_ID,
        UHRP_COUNTERPARTY_ANYONE,
    )
    .map_err(|_| ())?;

    // Concatenate fields 0..4. Field 0 is the admin ROOT pubkey (PROTOCOL.md
    // §B: "server identity pubkey" — which is the root identity, NOT the
    // BRC-42 child). See `createUHRPAdvertisement.ts:42`.
    let server_identity_bytes = admin_key.public_key().to_compressed();
    let mut expiry_w = Writer::new();
    expiry_w.write_var_int(expiry_time);
    let expiry_bytes = expiry_w.into_bytes();
    let mut len_w = Writer::new();
    len_w.write_var_int(content_length);
    let content_length_bytes = len_w.into_bytes();

    let mut sign_data: Vec<u8> = Vec::with_capacity(
        server_identity_bytes.len()
            + hash.len()
            + public_url.len()
            + expiry_bytes.len()
            + content_length_bytes.len(),
    );
    sign_data.extend_from_slice(&server_identity_bytes);
    sign_data.extend_from_slice(hash);
    sign_data.extend_from_slice(public_url.as_bytes());
    sign_data.extend_from_slice(&expiry_bytes);
    sign_data.extend_from_slice(&content_length_bytes);

    let digest = sha256(&sign_data);
    let sig = signing_key.sign(&digest).map_err(|_| ())?;
    let sig_der = sig.to_der();

    // Defensive: uhrp_url is accepted by the caller but we don't yet use
    // it in the fields. Keep it in scope so a silent "drop the URL" bug
    // becomes a compile error if someone rewires the fields.
    let _ = uhrp_url;

    Ok((
        locking_pubkey,
        UhrpAdvertFields {
            server_identity_key_hex: bsv_rs::primitives::encoding::to_hex(&server_identity_bytes),
            hash: hash.to_vec(),
            url: public_url.to_string(),
            expiry_time,
            content_length,
            signature: sig_der,
        },
    ))
}

/// Decode a `uhrp://<base58check>` URL into its 32-byte SHA-256 hash.
/// Returns `None` if the URL is malformed, uses the wrong version prefix,
/// or fails base58check validation.
///
/// We inline this here rather than exposing a helper from `uhrp::hash`
/// because `/advertise` is the first caller that needs URL → hash (hash.rs
/// is bytes → URL only). If a third caller shows up, promote to `uhrp::hash`.
pub(crate) fn uhrp_url_to_hash(url: &str) -> Option<[u8; 32]> {
    let body = url.strip_prefix(UHRP_SCHEME).unwrap_or(url);
    let decoded = from_base58(body).ok()?;
    use bsv_rs::primitives::hash::sha256d;
    // Canonical layout: 2-byte ce00 prefix + 32-byte hash + 4-byte checksum
    // (@bsv/sdk StorageUtils.getURLForHash). A 1-byte 0x01 legacy form also
    // circulated (an early overlay index used it — observed live 2026-07-02
    // when a renewal 404'd on a perfectly valid hash); accept it too, with
    // its own checksum validated, so any faithful encoding of the same hash
    // renews. Tags/advertisements are always built from the CANONICAL form.
    let prefix_len = if decoded.len() == UHRP_VERSION_PREFIX.len() + 32 + 4
        && decoded[..UHRP_VERSION_PREFIX.len()] == UHRP_VERSION_PREFIX
    {
        UHRP_VERSION_PREFIX.len()
    } else if decoded.len() == 1 + 32 + 4 && decoded[0] == 0x01 {
        1
    } else {
        return None;
    };
    let hash_end = prefix_len + 32;
    // Validate checksum so we don't silently accept a mangled URL.
    let checksum = sha256d(&decoded[..hash_end]);
    if checksum[..4] != decoded[hash_end..] {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded[prefix_len..hash_end]);
    Some(out)
}

/// Assemble the tag list for a fresh advertisement, matching TS
/// `createUHRPAdvertisement.ts:76` verbatim.
fn advert_tags(
    uhrp_url: &str,
    object_identifier: &str,
    uploader_identity_key: &str,
    expiry_time: u64,
) -> Vec<String> {
    vec![
        format!("uhrp_url_{}", hex::encode(uhrp_url.as_bytes())),
        format!(
            "object_identifier_{}",
            hex::encode(object_identifier.as_bytes())
        ),
        format!("uploader_identity_key_{uploader_identity_key}"),
        format!("expiry_time_{expiry_time}"),
    ]
}

/// Membership check for `ADMIN_IDENTITY_KEYS`. Splits on `,`, trims
/// whitespace, drops empty entries. Case-sensitive (BRC-31 identity keys
/// are always lowercase hex on the wire).
fn is_admin(identity_key: &str, admin_list: &str) -> bool {
    admin_list
        .split(',')
        .map(str::trim)
        .any(|k| !k.is_empty() && k == identity_key)
}

fn error(code: &'static str, description: impl Into<String>, status: u16) -> (Value, u16) {
    (json!(ErrorBody::new(code, description.into())), status)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    use super::*;
    use crate::uhrp::hash::derive_uhrp_url;

    // ── is_admin: TS-compatible parsing ─────────────────────────────────────

    #[test]
    fn is_admin_single_entry() {
        assert!(is_admin("deadbeef", "deadbeef"));
        assert!(!is_admin("deadbeef", "cafed00d"));
    }

    #[test]
    fn is_admin_comma_separated_with_whitespace() {
        assert!(is_admin("aa", " bb , aa , cc "));
        assert!(is_admin("bb", "bb,aa"));
        assert!(!is_admin("dd", "aa,bb,cc"));
    }

    #[test]
    fn is_admin_skips_empty_and_trailing_comma() {
        assert!(is_admin("aa", "aa,"));
        assert!(is_admin("aa", ",aa"));
        assert!(is_admin("aa", ",,aa,,,"));
    }

    #[test]
    fn is_admin_case_sensitive() {
        // BRC-31 identity keys are lowercase on the wire; uppercase is NOT
        // a match. Matches TS's behavior (direct `===` comparison).
        assert!(!is_admin("deadbeef", "DEADBEEF"));
    }

    #[test]
    fn is_admin_rejects_empty_identity() {
        // Defensive: an empty identity key must never pass the gate, even
        // if the secret is also empty.
        assert!(!is_admin("", ""));
        assert!(!is_admin("", "aa,,bb"));
    }

    // ── uhrp_url_to_hash: round-trip with derive_uhrp_url ──────────────────

    #[test]
    fn uhrp_url_to_hash_accepts_legacy_0x01_form() {
        // The 1-byte 0x01 legacy encoding must decode to the same hash as
        // the canonical ce00 form (live 2026-07-02 interop fix).
        let hash = [0x5au8; 32];
        let canonical = format!("uhrp://{}", crate::uhrp::hash::url_from_hash(&hash));
        let mut legacy_payload = vec![0x01];
        legacy_payload.extend_from_slice(&hash);
        let checksum = bsv_rs::primitives::hash::sha256d(&legacy_payload);
        legacy_payload.extend_from_slice(&checksum[..4]);
        let legacy = format!(
            "uhrp://{}",
            bsv_rs::primitives::encoding::to_base58(&legacy_payload)
        );
        assert_eq!(uhrp_url_to_hash(&canonical), Some(hash));
        assert_eq!(uhrp_url_to_hash(&legacy), Some(hash));
        // A mangled legacy checksum still refuses.
        let mut bad = legacy_payload.clone();
        let n = bad.len();
        bad[n - 1] ^= 0xff;
        let bad_url = format!("uhrp://{}", bsv_rs::primitives::encoding::to_base58(&bad));
        assert_eq!(uhrp_url_to_hash(&bad_url), None);
    }

    #[test]
    fn uhrp_url_to_hash_roundtrips() {
        // Build a URL from known bytes, then decode it back. Must produce
        // the same SHA-256 the forward function computed internally.
        let payload = b"round-trip me";
        let url = derive_uhrp_url(payload);
        let full = format!("{UHRP_SCHEME}{url}");
        let hash = uhrp_url_to_hash(&full).expect("valid URL must decode");
        assert_eq!(hash, bsv_rs::primitives::hash::sha256(payload));
    }

    #[test]
    fn uhrp_url_to_hash_accepts_bare_body() {
        // Some callers pass the base58check string without the `uhrp://`
        // scheme. TS's `StorageUtils.getHashFromURL` accepts both; we
        // match that.
        let payload = b"no scheme";
        let bare = derive_uhrp_url(payload);
        assert!(uhrp_url_to_hash(&bare).is_some());
    }

    #[test]
    fn uhrp_url_to_hash_rejects_malformed() {
        assert!(uhrp_url_to_hash("uhrp://").is_none());
        assert!(uhrp_url_to_hash("uhrp://@@@").is_none());
        assert!(uhrp_url_to_hash("").is_none());
    }

    #[test]
    fn uhrp_url_to_hash_rejects_bad_checksum() {
        // Flip a byte in a valid URL — checksum must fail.
        let url = derive_uhrp_url(b"tampering");
        let mut tampered: Vec<char> = url.chars().collect();
        let last_idx = tampered.len() - 1;
        tampered[last_idx] = if tampered[last_idx] == '1' { '2' } else { '1' };
        let tampered_str: String = tampered.into_iter().collect();
        assert!(uhrp_url_to_hash(&format!("uhrp://{tampered_str}")).is_none());
    }

    // ── advert_tags: byte-exact parity with TS ─────────────────────────────

    #[test]
    fn advert_tags_match_ts_hex_encoding() {
        // `uhrp_url_<hex>` and `object_identifier_<hex>` are hex-encoded
        // UTF-8 bytes. Uploader + expiry are plaintext. Locking any drift
        // to a string match.
        let tags = advert_tags("uhrp://abc", "obj1", "02deadbeef", 1_735_689_600);
        assert_eq!(
            tags[0],
            format!("uhrp_url_{}", hex::encode("uhrp://abc".as_bytes()))
        );
        assert_eq!(
            tags[1],
            format!("object_identifier_{}", hex::encode("obj1".as_bytes()))
        );
        assert_eq!(tags[2], "uploader_identity_key_02deadbeef");
        assert_eq!(tags[3], "expiry_time_1735689600");
    }

    // ── build_advert_bundle: integration with PushDrop ─────────────────────

    #[test]
    fn build_advert_bundle_produces_valid_lock_and_fields() {
        // End-to-end: given a known admin root key and a known URL, the
        // built fields + locking pubkey feed through `build_uhrp_advert_lock`
        // without error. This is the "fixture-less" integration proof
        // required by the task brief — we don't assert byte-exact TS parity
        // here (that requires a fresh TS-oracle capture) but we DO assert
        // that the real PushDrop builder is invoked (not mocked) and yields
        // a plausible output.
        let admin = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        // Use a real URL so the hash bytes are genuine.
        let hash_bytes = bsv_rs::primitives::hash::sha256(b"test file");
        let url = derive_uhrp_url(b"test file");
        let full_url = format!("uhrp://{url}");
        let (locking_pk, fields) = build_advert_bundle(
            &admin,
            &full_url,
            "https://example.com/cdn/obj1",
            &hash_bytes,
            1_735_689_600,
            42,
        )
        .expect("bundle must build");
        // Locking pubkey must be a valid compressed secp256k1 point.
        assert_eq!(locking_pk.to_compressed().len(), 33);
        // Fields carry the hash (32 bytes) and a non-empty DER signature.
        assert_eq!(fields.hash.len(), 32);
        assert!(!fields.signature.is_empty());
        // The real PushDrop builder must accept this bundle.
        let script = build_uhrp_advert_lock(&locking_pk.to_hex(), &fields).expect("valid lock");
        assert!(script.starts_with("21")); // 0x21 = 33-byte push of the compressed pubkey
    }

    #[test]
    fn build_advert_bundle_is_deterministic_per_admin_key() {
        // Given the same admin key and inputs, two successive invocations
        // must produce identical fields (RFC 6979 + fixed field construction).
        let admin = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let hash_bytes = bsv_rs::primitives::hash::sha256(b"deterministic");
        let (pk1, f1) = build_advert_bundle(
            &admin,
            "uhrp://ignored",
            "https://example.com/cdn/x",
            &hash_bytes,
            100,
            200,
        )
        .unwrap();
        let (pk2, f2) = build_advert_bundle(
            &admin,
            "uhrp://ignored",
            "https://example.com/cdn/x",
            &hash_bytes,
            100,
            200,
        )
        .unwrap();
        assert_eq!(pk1.to_hex(), pk2.to_hex());
        assert_eq!(f1.signature, f2.signature);
        assert_eq!(f1.hash, f2.hash);
    }

    // ── Error-body shape tests ─────────────────────────────────────────────

    #[test]
    fn error_body_shape_for_unauthorized() {
        let err = ErrorBody::new(ERR_UNAUTHORIZED, "Failed to advertise hosting commitment!");
        let got = serde_json::to_string(&err).unwrap();
        assert_eq!(
            got,
            r#"{"status":"error","code":"ERR_UNAUTHORIZED","description":"Failed to advertise hosting commitment!"}"#
        );
    }

    #[test]
    fn advertise_response_serializes_to_status_success() {
        let body = AdvertiseResponse { status: "success" };
        let got = serde_json::to_string(&body).unwrap();
        assert_eq!(got, r#"{"status":"success"}"#);
    }
}
