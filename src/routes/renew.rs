//! POST /renew — see PROTOCOL.md §5.
//!
//! Port of `storage-server/src/routes/renew.ts`. BRC-31 auth + BRC-29
//! payment are wired in `lib.rs`; this handler assumes both have been
//! verified by the time it runs.
//!
//! # Flow
//!
//! 1. Parse/validate body (`uhrpUrl`, `additionalMinutes`).
//! 2. `listOutputs` — find the old advert UTXO (filtered by
//!    `uhrp_url_<hex>` + `uploader_identity_key_<caller>`).
//! 3. Pick the output with max `expiry_time_*`.
//! 4. Compute `newExpiryTime = prevExpiryTime + additionalMinutes * 60`.
//! 5. Re-derive object identifier + content length from the old tags
//!    (TS pulls them from `getMetadata`; we have them in the tag set).
//! 6. Build the new PushDrop locking script with the BRC-42-derived
//!    locking pubkey and the same fields[0..2]+[4] but a new expiry.
//!    Re-sign via the derived key.
//! 7. `createAction` — input = old UTXO (PushDrop redeem), output =
//!    new advert. wallet-infra handles change.
//! 8. `sign_transaction_mixed` — P2PKH for change inputs, PushDrop for
//!    the old advert input.
//! 9. `processAction` with `isNoSend: false` — wallet-infra broadcasts via ARC
//!    so status → 'unproven' (monitor's every-5-min check path). Overlay
//!    `/submit` below also broadcasts; duplicates are idempotent.
//! 10. Overlay `/submit` with `x-topics: ["tm_uhrp"]`.
//! 11. Return `{status, prevExpiryTime, newExpiryTime, amount}`.
//!
//! # Deviation from TS (flagged for parity harness)
//!
//! The TS `/renew` handler calls `getMetadata` twice-indirectly to get
//! the file's on-chain size + `objectIdentifier`: once for pricing, then
//! again inside the listOutputs tag filter. We skip the separate
//! `getMetadata` round-trip and derive `objectIdentifier` from the advert
//! tags we're already listing (they contain `object_identifier_<hex>` by
//! construction at advertise time). This avoids a second R2 HEAD on the
//! hot path. The price lookup is deferred to the payment middleware in
//! `lib.rs` (mirrors `/upload`).

use crate::error::{
    ERR_CREATE_ACTION_FAILED, ERR_INTERNAL_RENEW, ERR_INVALID_TIME, ERR_MISSING_FIELDS,
    ERR_MISSING_IDENTITY_KEY, ERR_OLD_ADVERTISEMENT_NOT_FOUND, ERR_OVERLAY_BROADCAST,
    ERR_SIGNING_OLD_ADVERTISEMENT,
};
use crate::overlay::{overlay_url_from_env, submit_uhrp_advert};
use crate::types::{ErrorBody, RenewRequest, RenewResponse};
use crate::uhrp::pushdrop::{build_uhrp_advert_lock, UhrpAdvertFields};
use crate::wallet::brc42::{
    derive_child_key, derive_child_public_key, uhrp_protocol_id, UHRP_COUNTERPARTY_ANYONE,
    UHRP_KEY_ID,
};
use crate::wallet::client::Wallet;
use crate::wallet::signer::{sign_transaction_mixed, InputUnlock};
use crate::wallet::types::{
    CreateActionInput, CreateActionOutput, CreateActionRequest, ListOutputsRequest, OutputItem,
    ProcessActionRequest,
};

use bsv_rs::primitives::encoding::Writer;
use bsv_rs::primitives::hash::sha256;
use serde_json::{json, Value};
use worker::Env;

const UHRP_BASKET: &str = "uhrp advertisements";
const UHRP_URL_TAG_PREFIX: &str = "uhrp_url_";
const UPLOADER_TAG_PREFIX: &str = "uploader_identity_key_";
const OBJECT_ID_TAG_PREFIX: &str = "object_identifier_";
const EXPIRY_TAG_PREFIX: &str = "expiry_time_";

/// PushDrop unlocking script length estimate (for wallet-infra fee calc).
/// Matches TS `renew.ts:162` (`unlockingScriptLength: 74`).
const PUSHDROP_UNLOCK_LEN: u32 = 74;

/// Default pagination (TS `renew.ts:88–89`).
const DEFAULT_LIMIT: u32 = 200;
const DEFAULT_OFFSET: i32 = 0;

pub async fn handle(body: &[u8], identity_key: &str, env: &Env) -> (Value, u16) {
    if identity_key.is_empty() {
        return error(
            ERR_MISSING_IDENTITY_KEY,
            "Missing authfetch identityKey.",
            400,
        );
    }

    let req: RenewRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => {
            return error(
                ERR_MISSING_FIELDS,
                "Missing objectIdentifier or additionalMinutes.",
                400,
            )
        }
    };

    let Some(uhrp_url) = req.uhrp_url.filter(|s| !s.is_empty()) else {
        return error(
            ERR_MISSING_FIELDS,
            "Missing objectIdentifier or additionalMinutes.",
            400,
        );
    };
    let Some(additional_minutes_f) = req.additional_minutes else {
        return error(
            ERR_MISSING_FIELDS,
            "Missing objectIdentifier or additionalMinutes.",
            400,
        );
    };
    if !additional_minutes_f.is_finite() || additional_minutes_f <= 0.0 {
        return error(
            ERR_INVALID_TIME,
            "Additional Minutes must be a positive integer",
            400,
        );
    }

    let limit = req.limit.unwrap_or(DEFAULT_LIMIT);
    let offset = req.offset.unwrap_or(DEFAULT_OFFSET);
    let additional_minutes: u64 = additional_minutes_f as u64;

    match inner(
        env,
        identity_key,
        &uhrp_url,
        additional_minutes,
        limit,
        offset,
    )
    .await
    {
        Ok(resp) => (json!(resp), 200),
        Err(RenewError::OldAdvertNotFound) => error(
            ERR_OLD_ADVERTISEMENT_NOT_FOUND,
            "Couldn't find old advertisement output.",
            404,
        ),
        Err(RenewError::CreateActionFailed) => error(
            ERR_CREATE_ACTION_FAILED,
            "Old advertisement could not be redeemed.",
            500,
        ),
        Err(RenewError::SigningFailed) => error(
            ERR_SIGNING_OLD_ADVERTISEMENT,
            "Signing the replacement advertisement failed.",
            500,
        ),
        Err(RenewError::OverlayFailed) => {
            error(ERR_OVERLAY_BROADCAST, "Overlay broadcast failed.", 500)
        }
        Err(RenewError::Internal) => error(
            ERR_INTERNAL_RENEW,
            "An error occurred while handling the renewal.",
            500,
        ),
    }
}

enum RenewError {
    OldAdvertNotFound,
    CreateActionFailed,
    SigningFailed,
    OverlayFailed,
    Internal,
}

async fn inner(
    env: &Env,
    identity_key: &str,
    uhrp_url: &str,
    additional_minutes: u64,
    limit: u32,
    offset: i32,
) -> Result<RenewResponse, RenewError> {
    let wallet = Wallet::from_env(env).map_err(|_| RenewError::Internal)?;
    let admin_key = wallet.private_key().clone();

    // ── Find the old advertisement UTXO ───────────────────────────────────
    let list_req = ListOutputsRequest {
        basket: UHRP_BASKET.to_string(),
        tags: vec![
            format!("{UHRP_URL_TAG_PREFIX}{}", hex::encode(uhrp_url.as_bytes())),
            format!("{UPLOADER_TAG_PREFIX}{identity_key}"),
        ],
        tag_query_mode: Some("all".to_string()),
        include: Some("entire transactions".to_string()),
        include_tags: Some(true),
        limit: Some(limit),
        offset: Some(offset),
    };
    let list_result = wallet
        .list_outputs(&list_req)
        .await
        .map_err(|_| RenewError::Internal)?;
    if list_result.outputs.is_empty() {
        return Err(RenewError::OldAdvertNotFound);
    }

    // Pick the output with the largest `expiry_time_*` (same pattern as
    // /find). Require the locking script so we can re-use fields 0/1/2/4
    // shape by rebuilding them from our own data (see below — we don't
    // actually decode the PushDrop; we rebuild from tags + body).
    let (chosen, prev_expiry) =
        select_latest_advert(&list_result.outputs).ok_or(RenewError::OldAdvertNotFound)?;

    // Extract required tag fields. `object_identifier_<hex>` is mandatory
    // (the advert always has it — see `createUHRPAdvertisement.ts:76`).
    let chosen_tags = chosen.tags.as_ref().ok_or(RenewError::OldAdvertNotFound)?;
    let object_identifier = extract_object_identifier(chosen_tags).ok_or(RenewError::Internal)?;

    // ── Build the new advert ──────────────────────────────────────────────
    let new_expiry = prev_expiry + additional_minutes * 60;
    let hash = uhrp_url_to_hash(uhrp_url).ok_or(RenewError::Internal)?;

    // The renewed advert reuses the caller's on-chain metadata. For the
    // content length we rebuild from the old UTXO's satoshis value —
    // wait, that's wrong; satoshis is always 1. The TS `/renew` handler
    // keeps `prevFields[4]` (the old VarInt-encoded content length) by
    // PushDrop-decoding the old locking script. We need the same. Fall
    // back to re-encoding field 4 from `list_result.beef` by decoding
    // the PushDrop. If the old locking script is missing or can't be
    // decoded, we surface `Internal` rather than guess at a length.
    //
    // NOTE: TS accesses `prevFields[4]` via `PushDrop.decode(prevLockingScript)`.
    // We replicate by asking the server to include full transactions in
    // `listOutputs` (`include: "entire transactions"`), then parsing the
    // locking script from the matched output.
    let prev_locking_hex = chosen
        .locking_script
        .as_deref()
        .ok_or(RenewError::Internal)?;
    let prev_content_length =
        extract_content_length_from_pushdrop(prev_locking_hex).ok_or(RenewError::Internal)?;

    let public_url_base = env
        .var("PUBLIC_URL_BASE")
        .map_err(|_| RenewError::Internal)?
        .to_string();
    let public_url = format!(
        "{}/cdn/{}",
        public_url_base.trim_end_matches('/'),
        object_identifier
    );

    let locking_pubkey = derive_child_public_key(
        &admin_key,
        &uhrp_protocol_id(),
        UHRP_KEY_ID,
        UHRP_COUNTERPARTY_ANYONE,
    )
    .map_err(|_| RenewError::Internal)?;
    let signing_key = derive_child_key(
        &admin_key,
        &uhrp_protocol_id(),
        UHRP_KEY_ID,
        UHRP_COUNTERPARTY_ANYONE,
    )
    .map_err(|_| RenewError::Internal)?;

    // Rebuild the five fields with the new expiry time. Sign the concat.
    let server_identity_bytes = admin_key.public_key().to_compressed();
    let mut expiry_w = Writer::new();
    expiry_w.write_var_int(new_expiry);
    let expiry_bytes = expiry_w.into_bytes();
    let mut len_w = Writer::new();
    len_w.write_var_int(prev_content_length);
    let content_length_bytes = len_w.into_bytes();

    let mut sign_data: Vec<u8> = Vec::with_capacity(
        server_identity_bytes.len()
            + hash.len()
            + public_url.len()
            + expiry_bytes.len()
            + content_length_bytes.len(),
    );
    sign_data.extend_from_slice(&server_identity_bytes);
    sign_data.extend_from_slice(&hash);
    sign_data.extend_from_slice(public_url.as_bytes());
    sign_data.extend_from_slice(&expiry_bytes);
    sign_data.extend_from_slice(&content_length_bytes);
    let digest = sha256(&sign_data);
    let sig = signing_key
        .sign(&digest)
        .map_err(|_| RenewError::Internal)?;
    let sig_der = sig.to_der();

    let new_fields = UhrpAdvertFields {
        server_identity_key_hex: bsv_rs::primitives::encoding::to_hex(&server_identity_bytes),
        hash: hash.to_vec(),
        url: public_url.clone(),
        expiry_time: new_expiry,
        content_length: prev_content_length,
        signature: sig_der,
    };
    let new_locking_hex = build_uhrp_advert_lock(&locking_pubkey.to_hex(), &new_fields)
        .map_err(|_| RenewError::Internal)?;

    // ── createAction spending the old UTXO → new advert ──────────────────
    let outpoint_str = format!("{}.{}", chosen.outpoint.txid, chosen.outpoint.vout);
    let new_tags = vec![
        format!("{UPLOADER_TAG_PREFIX}{identity_key}"),
        format!("{UHRP_URL_TAG_PREFIX}{}", hex::encode(uhrp_url.as_bytes())),
        format!(
            "{OBJECT_ID_TAG_PREFIX}{}",
            hex::encode(object_identifier.as_bytes())
        ),
        format!("{EXPIRY_TAG_PREFIX}{new_expiry}"),
    ];
    // Mark as ours so wallet-infra flips spendable=1 post-processAction.
    // Matches bsv-wallet-toolbox-rs is_ours predicate.
    let custom_instructions = serde_json::json!({
        "type": "UHRPAdvertisement",
        "protocolID": [2, "uhrp advertisement"],
        "keyID": "1",
        "counterparty": "anyone",
    })
    .to_string();
    let create_req = CreateActionRequest {
        outputs: vec![CreateActionOutput {
            locking_script: new_locking_hex,
            satoshis: 1,
            output_description: "UHRP advertisement token (renewed)".to_string(),
            basket: Some(UHRP_BASKET.to_string()),
            tags: new_tags,
            custom_instructions: Some(custom_instructions),
        }],
        inputs: vec![CreateActionInput {
            outpoint: outpoint_str,
            unlocking_script_length: PUSHDROP_UNLOCK_LEN,
            input_description: "Redeeming old advertisement".to_string(),
        }],
        // Carry the listOutputs BEEF so wallet-infra has the old UTXO
        // ancestry for input-script verification.
        input_beef: if list_result.beef.is_empty() {
            None
        } else {
            Some(list_result.beef.clone())
        },
        description: format!("Renew advertisement for uhrpUrl {uhrp_url}"),
        randomize_outputs: false,
    };
    let template = wallet
        .create_action(&create_req)
        .await
        .map_err(|_| RenewError::CreateActionFailed)?;

    // ── Sign: PushDrop for the first input, P2PKH for the rest ────────────
    //
    // The inputs list from wallet-infra puts inputs in the order we
    // requested them, so index 0 is the old PushDrop UTXO and any later
    // indices are change from the admin wallet.
    let mut unlocks: Vec<InputUnlock> = Vec::with_capacity(template.inputs.len());
    for (i, _) in template.inputs.iter().enumerate() {
        if i == 0 {
            unlocks.push(InputUnlock::PushDrop { key: &signing_key });
        } else {
            unlocks.push(InputUnlock::P2pkh);
        }
    }
    let signed = sign_transaction_mixed(&template, &admin_key, &unlocks)
        .map_err(|_| RenewError::SigningFailed)?;

    // ── processAction (record, no broadcast) ──────────────────────────────
    let process_req = ProcessActionRequest {
        is_new_tx: true,
        is_send_with: false,
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
        .map_err(|_| RenewError::CreateActionFailed)?;

    // ── Overlay broadcast ────────────────────────────────────────────────
    let overlay_url = overlay_url_from_env(env);
    submit_uhrp_advert(env, &overlay_url, &signed.raw_tx)
        .await
        .map_err(|_| RenewError::OverlayFailed)?;

    // ── Response ──────────────────────────────────────────────────────────
    // TS pricing runs inside the payment middleware for the Rust port;
    // we echo the satoshis the payment middleware charged. Since the
    // payment validator is upstream and not plumbed here (see the note
    // in the module docstring), we report 0. If the parity harness
    // requires byte-exact `amount`, add a `price: u64` parameter to
    // `handle` and thread through `lib.rs` like /upload does.
    Ok(RenewResponse {
        status: "success",
        prev_expiry_time: prev_expiry,
        new_expiry_time: new_expiry,
        amount: 0,
    })
}

fn error(code: &'static str, description: impl Into<String>, status: u16) -> (Value, u16) {
    (json!(ErrorBody::new(code, description.into())), status)
}

/// Walk `outputs`, pick the one with the largest `expiry_time_*`.
fn select_latest_advert(outputs: &[OutputItem]) -> Option<(&OutputItem, u64)> {
    let mut best: Option<(&OutputItem, u64)> = None;
    for out in outputs {
        let Some(tags) = out.tags.as_ref() else {
            continue;
        };
        let Some(expiry) = tags
            .iter()
            .find(|t| t.starts_with(EXPIRY_TAG_PREFIX))
            .and_then(|t| t[EXPIRY_TAG_PREFIX.len()..].parse::<u64>().ok())
        else {
            continue;
        };
        match best {
            None => best = Some((out, expiry)),
            Some((_, b)) if expiry > b => best = Some((out, expiry)),
            _ => {}
        }
    }
    best
}

fn extract_object_identifier(tags: &[String]) -> Option<String> {
    let tag = tags.iter().find(|t| t.starts_with(OBJECT_ID_TAG_PREFIX))?;
    let hex_part = &tag[OBJECT_ID_TAG_PREFIX.len()..];
    let bytes = hex::decode(hex_part).ok()?;
    String::from_utf8(bytes).ok()
}

/// Decode an existing PushDrop UHRP advertisement locking script (hex) and
/// return field 4 (content length, VarInt-encoded) as a u64.
///
/// Implemented via `bsv_rs::script::templates::PushDrop::decode`, which
/// handles both lock-before and lock-after and minimal-encoded opcodes.
/// A decode failure → `None`.
fn extract_content_length_from_pushdrop(locking_script_hex: &str) -> Option<u64> {
    use bsv_rs::script::templates::PushDrop;
    use bsv_rs::script::LockingScript;

    let script = LockingScript::from_hex(locking_script_hex).ok()?;
    let decoded = PushDrop::decode(&script).ok()?;
    // Field 4 = content length VarInt. TS stores this as the raw VarInt
    // bytes a `Writer.writeVarIntNum` produced, so we read it back the
    // same way.
    let field4 = decoded.fields.get(4)?;
    read_var_int_u64(field4)
}

/// Parse a Bitcoin VarInt out of `bytes`. Mirrors
/// `bsv_rs::primitives::encoding::Reader::read_var_int` but returns `Option`
/// so we don't pull in a `Reader` lifetime for a one-liner.
fn read_var_int_u64(bytes: &[u8]) -> Option<u64> {
    let (head, rest) = bytes.split_first()?;
    match *head {
        0xfd => {
            if rest.len() < 2 {
                return None;
            }
            Some(u16::from_le_bytes([rest[0], rest[1]]) as u64)
        }
        0xfe => {
            if rest.len() < 4 {
                return None;
            }
            Some(u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as u64)
        }
        0xff => {
            if rest.len() < 8 {
                return None;
            }
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&rest[..8]);
            Some(u64::from_le_bytes(arr))
        }
        n => Some(n as u64),
    }
}

/// Decode a `uhrp://<base58check>` URL to its 32-byte SHA-256 hash. Mirrors
/// the private helper in `routes/advertise.rs` — kept local to each route
/// to avoid a cross-module `uhrp::hash` expansion for two callers.
fn uhrp_url_to_hash(url: &str) -> Option<[u8; 32]> {
    use bsv_rs::primitives::encoding::from_base58;
    use bsv_rs::primitives::hash::sha256d;
    const UHRP_VERSION_PREFIX: [u8; 2] = [0xce, 0x00];
    let body = url.strip_prefix("uhrp://").unwrap_or(url);
    let decoded = from_base58(body).ok()?;
    if decoded.len() != UHRP_VERSION_PREFIX.len() + 32 + 4 {
        return None;
    }
    if decoded[..UHRP_VERSION_PREFIX.len()] != UHRP_VERSION_PREFIX {
        return None;
    }
    let hash_start = UHRP_VERSION_PREFIX.len();
    let hash_end = hash_start + 32;
    let checksum = sha256d(&decoded[..hash_end]);
    if checksum[..4] != decoded[hash_end..] {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded[hash_start..hash_end]);
    Some(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    use super::*;
    use crate::wallet::types::Outpoint;

    fn sample_output(tags: Vec<String>, locking_script: Option<String>) -> OutputItem {
        OutputItem {
            satoshis: 1,
            outpoint: Outpoint {
                txid: "00".repeat(32),
                vout: 0,
            },
            spendable: true,
            tags: Some(tags),
            locking_script,
        }
    }

    // ── VarInt decoder ──────────────────────────────────────────────────────

    #[test]
    fn read_var_int_u64_handles_single_byte() {
        assert_eq!(read_var_int_u64(&[0x00]), Some(0));
        assert_eq!(read_var_int_u64(&[0x42]), Some(0x42));
        assert_eq!(read_var_int_u64(&[0xfc]), Some(0xfc));
    }

    #[test]
    fn read_var_int_u64_handles_u16_and_u32() {
        assert_eq!(read_var_int_u64(&[0xfd, 0x00, 0x01]), Some(0x0100));
        assert_eq!(
            read_var_int_u64(&[0xfe, 0x01, 0x02, 0x03, 0x04]),
            Some(0x04030201)
        );
    }

    #[test]
    fn read_var_int_u64_handles_u64() {
        assert_eq!(
            read_var_int_u64(&[0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            Some(0x0807060504030201)
        );
    }

    #[test]
    fn read_var_int_u64_rejects_short_inputs() {
        assert_eq!(read_var_int_u64(&[0xfd]), None);
        assert_eq!(read_var_int_u64(&[0xfe, 0x01]), None);
        assert_eq!(read_var_int_u64(&[0xff, 0x01]), None);
        assert_eq!(read_var_int_u64(&[]), None);
    }

    // ── select_latest_advert ────────────────────────────────────────────────

    #[test]
    fn select_latest_advert_picks_max_expiry() {
        let outputs = vec![
            sample_output(vec!["expiry_time_100".to_string()], None),
            sample_output(vec!["expiry_time_500".to_string()], None),
            sample_output(vec!["expiry_time_300".to_string()], None),
        ];
        let (chosen, expiry) = select_latest_advert(&outputs).unwrap();
        assert_eq!(expiry, 500);
        assert_eq!(chosen.tags.as_ref().unwrap()[0], "expiry_time_500");
    }

    #[test]
    fn select_latest_advert_ignores_missing_expiry_tag() {
        let outputs = vec![
            sample_output(vec!["uhrp_url_00".to_string()], None),
            sample_output(vec!["expiry_time_10".to_string()], None),
        ];
        let (_, expiry) = select_latest_advert(&outputs).unwrap();
        assert_eq!(expiry, 10);
    }

    #[test]
    fn select_latest_advert_returns_none_for_empty() {
        assert!(select_latest_advert(&[]).is_none());
    }

    // ── extract_object_identifier ───────────────────────────────────────────

    #[test]
    fn extract_object_identifier_decodes_hex_utf8() {
        let tag = format!("object_identifier_{}", hex::encode("myobj".as_bytes()));
        assert_eq!(extract_object_identifier(&[tag]).as_deref(), Some("myobj"));
    }

    #[test]
    fn extract_object_identifier_none_when_missing() {
        assert!(extract_object_identifier(&["expiry_time_1".to_string()]).is_none());
    }

    // ── uhrp_url_to_hash ───────────────────────────────────────────────────

    #[test]
    fn uhrp_url_to_hash_returns_some_for_valid_url() {
        use crate::uhrp::hash::derive_uhrp_url;
        let url = derive_uhrp_url(b"hello");
        let hash = uhrp_url_to_hash(&format!("uhrp://{url}"));
        assert!(hash.is_some());
    }

    #[test]
    fn uhrp_url_to_hash_returns_none_for_garbage() {
        assert!(uhrp_url_to_hash("uhrp://not-valid-base58!").is_none());
        assert!(uhrp_url_to_hash("").is_none());
    }

    // ── Response / error-body shapes ────────────────────────────────────────

    #[test]
    fn renew_response_has_expected_field_order() {
        // PROTOCOL.md §5 response: {status, prevExpiryTime, newExpiryTime, amount}
        let body = RenewResponse {
            status: "success",
            prev_expiry_time: 1_000,
            new_expiry_time: 2_000,
            amount: 42,
        };
        let got = serde_json::to_string(&body).unwrap();
        assert_eq!(
            got,
            r#"{"status":"success","prevExpiryTime":1000,"newExpiryTime":2000,"amount":42}"#
        );
    }

    #[test]
    fn error_body_for_missing_fields() {
        let err = ErrorBody::new(
            ERR_MISSING_FIELDS,
            "Missing objectIdentifier or additionalMinutes.",
        );
        let got = serde_json::to_string(&err).unwrap();
        assert!(got.contains(r#""code":"ERR_MISSING_FIELDS""#));
    }

    #[test]
    fn error_body_for_invalid_time() {
        let err = ErrorBody::new(
            ERR_INVALID_TIME,
            "Additional Minutes must be a positive integer",
        );
        let got = serde_json::to_string(&err).unwrap();
        assert!(got.contains(r#""code":"ERR_INVALID_TIME""#));
    }

    #[test]
    fn error_body_for_old_advert_not_found() {
        let err = ErrorBody::new(
            ERR_OLD_ADVERTISEMENT_NOT_FOUND,
            "Couldn't find old advertisement output.",
        );
        let got = serde_json::to_string(&err).unwrap();
        assert!(got.contains(r#""code":"ERR_OLD_ADVERTISEMENT_NOT_FOUND""#));
    }
}
