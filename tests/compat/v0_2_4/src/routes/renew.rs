//! POST /renew — see PROTOCOL.md §5.
//!
//! Port of `storage-server/src/routes/renew.ts`, redesigned for real
//! pricing (the-composer #45). BRC-31 auth + BRC-29 payment are wired in
//! `lib.rs`; this handler assumes both have been verified by the time it
//! runs.
//!
//! # Flow
//!
//! 0. (`lib.rs`, pre-payment) [`prepare`] — parse the body, `listOutputs`
//!    the old advert by `uhrp_url_<hex>` tag, pick the output with max
//!    `expiry_time_*`, PushDrop-decode field 4 (content length) from the
//!    old locking script. The result both prices the request and is
//!    threaded into [`handle`], so the wallet round-trip happens exactly
//!    once per call.
//! 1. Parse/validate body (`uhrpUrl`, `additionalMinutes`).
//! 2. Compute `newExpiryTime = prevExpiryTime + additionalMinutes * 60`.
//! 3. Build the new PushDrop locking script with the BRC-42-derived
//!    locking pubkey and the same fields[0..2]+[4] but a new expiry.
//!    Re-sign via the derived key.
//! 4. `createAction` — input = old UTXO (PushDrop redeem), output =
//!    new advert. wallet-infra handles change. A refusal here answers
//!    409: two concurrent renews race to spend the same outpoint and
//!    the loser's `createAction` fails (see [`RenewError::Conflict`]).
//! 5. `sign_transaction_mixed` — P2PKH for change inputs, PushDrop for
//!    the old advert input.
//! 6. `processAction` with `isNoSend: false` — wallet-infra broadcasts via ARC
//!    so status → 'unproven' (monitor's every-5-min check path). Overlay
//!    `/submit` below also broadcasts; duplicates are idempotent.
//! 7. Overlay `/submit` with `x-topics: ["tm_uhrp"]`.
//! 8. Extend the R2 object's `custom-time` to (newExpiry + 300 s buffer)
//!    via a same-key copy — the R2 stand-in for TS `renew.ts:212–213`'s
//!    GCS `file.setMetadata({customTime})`. Best-effort (see `inner`).
//! 9. Return `{status, prevExpiryTime, newExpiryTime, amount}` where
//!    `amount` echoes the satoshis the payment middleware charged.
//!
//! # Pricing (the-composer #45)
//!
//! `fileSize` is NOT in the renew body — it is read from field 4 of the
//! old advertisement's PushDrop, so the price is bound to on-chain data,
//! never client claims. `lib.rs` feeds [`PreparedRenew::price_inputs`]
//! into `routes::quote::compute_price_from_env` (the same formula `/quote`
//! and `/upload` use) and runs the BRC-29 middleware with the result.
//!
//! # Any-identity renewal (deviation from the first cut)
//!
//! The old advert is looked up by `uhrp_url_<hex>` alone — the
//! `uploader_identity_key_<caller>` filter is gone, so anyone who pays can
//! extend hosting (reference TS `renew.ts:84` filters by uhrp_url +
//! object_identifier, not uploader). Critically, the renewed advert's tags
//! preserve the ORIGINAL uploader tag instead of stamping the caller's key
//! (like TS `renew.ts:150–153` copying old tags) — otherwise a stranger's
//! renewal would re-tag the advert and the owner would lose `/list` and
//! future-`/renew` visibility of their own upload.
//!
//! # Deviation from TS (flagged for parity harness)
//!
//! - We derive `objectIdentifier` from the advert tags instead of a
//!   `getMetadata` round-trip (they contain `object_identifier_<hex>` by
//!   construction at advertise time), avoiding an R2 HEAD on the hot path.
//! - `ERR_CREATE_ACTION_FAILED` is answered 409 (TS: 500). The dominant
//!   cause of a createAction refusal on this route is the concurrent-renew
//!   race on the old outpoint; 409 tells the client to re-quote and retry
//!   (its next `prepare` finds the freshly renewed advert). A wallet-infra
//!   outage at exactly this step also lands on 409 — the retry guidance is
//!   correct for that cause too.
//! - `processAction` failure is `ERR_INTERNAL_RENEW` 500 (previously it
//!   shared `ERR_CREATE_ACTION_FAILED` with the createAction branch, which
//!   would now mislabel an internal failure as a conflict).

use crate::error::{
    ERR_CREATE_ACTION_FAILED, ERR_INTERNAL_RENEW, ERR_INVALID_TIME, ERR_MISSING_FIELDS,
    ERR_MISSING_IDENTITY_KEY, ERR_OLD_ADVERTISEMENT_NOT_FOUND, ERR_OVERLAY_BROADCAST,
    ERR_SIGNING_OLD_ADVERTISEMENT,
};
use crate::overlay::{overlay_url_from_env, submit_uhrp_advert};
use crate::routes::upload::{iso8601_millis, CUSTOM_TIME_BUFFER_SECONDS};
use crate::storage::custom_time::extend_custom_time;
use crate::storage::head::UHRP_BINDING;
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

/// Parsed + validated `/renew` body. Produced by [`parse_renew_body`],
/// shared by [`prepare`] (pre-payment) and [`handle`] (post-payment) so
/// the two stages can never disagree on validation.
#[derive(Debug)]
struct ParsedRenew {
    uhrp_url: String,
    additional_minutes: u64,
    limit: u32,
    offset: i32,
}

/// Pre-fetched old-advert context — everything the post-payment handler
/// needs from the single pre-payment `listOutputs` round-trip in
/// [`prepare`].
pub struct RenewContext {
    /// Canonical `uhrp://…` URL from the request body.
    pub uhrp_url: String,
    /// Whole minutes to extend by (validated finite and > 0).
    pub additional_minutes: u64,
    /// Expiry of the chosen (max-`expiry_time_*`) old advert, unix seconds.
    pub prev_expiry: u64,
    /// Field 4 of the old advert's PushDrop — the on-chain content length
    /// in bytes. This is the `fileSize` the renewal price derives from.
    pub content_length: u64,
    /// Decoded from the old advert's `object_identifier_<hex>` tag.
    pub object_identifier: String,
    /// The old advert's FULL `uploader_identity_key_<key>` tag, preserved
    /// verbatim onto the renewed advert (see module doc: any-identity
    /// renewal must not re-tag the advert with the caller's key).
    pub original_uploader_tag: Option<String>,
    /// Old advert outpoint — becomes input 0 of the renewal transaction.
    pub prev_txid: String,
    pub prev_vout: u32,
    /// BEEF from `listOutputs` covering the old UTXO's ancestry (handed to
    /// `createAction` for input-script verification).
    pub beef: Vec<u8>,
}

/// Outcome of the pre-payment [`prepare`] step. Mirrors `/upload`'s
/// `parse_pricing_inputs` contract: only `Ready` is priceable; every other
/// variant prices at 0 (a free pass through the payment middleware) so the
/// handler can emit the correct error without the client paying for it.
pub enum PreparedRenew {
    /// Old advert found and decoded; renewal is priceable.
    Ready(RenewContext),
    /// Body malformed/invalid — `handle` re-parses and emits the exact 400.
    InvalidBody,
    /// No advert matched the `uhrp_url_<hex>` tag — `handle` emits the 404.
    NotFound,
    /// Wallet lookup or PushDrop decode failed — `handle` emits the 500.
    LookupFailed,
}

impl PreparedRenew {
    /// Pricing inputs `(fileSize, additionalMinutes)` for
    /// `routes::quote::compute_price_from_env`. `fileSize` comes from field
    /// 4 of the old advert's PushDrop — never from the client. `None` =
    /// price 0 (free pass; the handler then produces the right error).
    #[must_use]
    pub fn price_inputs(&self) -> Option<(f64, f64)> {
        match self {
            Self::Ready(ctx) => Some((ctx.content_length as f64, ctx.additional_minutes as f64)),
            _ => None,
        }
    }
}

/// Pre-payment lookup + decode of the old advertisement. Called by
/// `lib.rs` BEFORE the payment middleware so the price can be derived from
/// the on-chain content length; the result is then passed into [`handle`]
/// to avoid a second wallet round-trip.
pub async fn prepare(body: &[u8], env: &Env) -> PreparedRenew {
    let Ok(parsed) = parse_renew_body(body) else {
        return PreparedRenew::InvalidBody;
    };

    let Ok(wallet) = Wallet::from_env(env) else {
        return PreparedRenew::LookupFailed;
    };

    // ── Find the old advertisement UTXO (any-identity: uhrp_url only) ─────
    let list_req = ListOutputsRequest {
        basket: UHRP_BASKET.to_string(),
        tags: lookup_tags(&parsed.uhrp_url),
        tag_query_mode: Some("all".to_string()),
        // wallet-infra implements exactly `"locking scripts"` (it has no
        // BEEF support in listOutputs — its createAction resolves its own
        // txids internally, so `input_beef: None` on the spend is fine).
        // `"entire transactions"` silently returned rows with NEITHER the
        // script NOR a BEEF — the renewal 500'd on every real call.
        include: Some("locking scripts".to_string()),
        include_tags: Some(true),
        include_locking_scripts: Some(true),
        limit: Some(parsed.limit),
        offset: Some(parsed.offset),
    };
    let list_result = match wallet.list_outputs(&list_req).await {
        Ok(r) => r,
        Err(e) => {
            worker::console_log!("renew/prepare: listOutputs failed: {e:?}");
            return PreparedRenew::LookupFailed;
        }
    };
    if list_result.outputs.is_empty() {
        return PreparedRenew::NotFound;
    }

    // Pick the output with the largest `expiry_time_*` (same pattern as
    // /find).
    let Some((chosen, prev_expiry)) = select_latest_advert(&list_result.outputs) else {
        return PreparedRenew::NotFound;
    };

    // `object_identifier_<hex>` is mandatory (the advert always has it —
    // see `createUHRPAdvertisement.ts:76`). The uploader tag is preserved
    // opportunistically: legacy adverts without one simply stay untagged.
    let Some(chosen_tags) = chosen.tags.as_ref() else {
        return PreparedRenew::NotFound;
    };
    let Some(object_identifier) = extract_object_identifier(chosen_tags) else {
        worker::console_log!("renew/prepare: advert has no object_identifier tag");
        return PreparedRenew::LookupFailed;
    };
    let original_uploader_tag = extract_uploader_tag(chosen_tags);

    // TS accesses `prevFields[4]` via `PushDrop.decode(prevLockingScript)`.
    // We replicate by asking the server to include full transactions in
    // `listOutputs` (`include: "entire transactions"`), then parsing the
    // locking script from the matched output. If the old locking script is
    // missing or can't be decoded, we surface a failure rather than guess
    // at a length (the price would be unbound otherwise).
    // Per-output lockingScript when the server provides it; else recover it
    // from the returned BEEF (wallet-infra builds the script into the raw tx,
    // not always onto the row — observed live 2026-07-02).
    let beef_script;
    let prev_locking_hex = match chosen.locking_script.as_deref() {
        Some(hex) => hex,
        None => {
            let Some(hex) = locking_script_from_beef(
                &list_result.beef,
                &chosen.outpoint.txid,
                chosen.outpoint.vout,
            ) else {
                worker::console_log!(
                    "renew/prepare: no lockingScript on row and none recoverable from BEEF for {}",
                    chosen.outpoint.txid
                );
                return PreparedRenew::LookupFailed;
            };
            beef_script = hex;
            &beef_script
        }
    };
    let Some(content_length) = extract_content_length_from_pushdrop(prev_locking_hex) else {
        worker::console_log!("renew/prepare: PushDrop field-4 decode failed");
        return PreparedRenew::LookupFailed;
    };

    PreparedRenew::Ready(RenewContext {
        uhrp_url: parsed.uhrp_url,
        additional_minutes: parsed.additional_minutes,
        prev_expiry,
        content_length,
        object_identifier,
        original_uploader_tag,
        prev_txid: chosen.outpoint.txid.clone(),
        prev_vout: chosen.outpoint.vout,
        beef: list_result.beef,
    })
}

/// Handle `POST /renew`.
///
/// `price` is pre-computed by `lib.rs` (via the payment middleware's price
/// calculation over [`prepare`]'s on-chain content length) and passed in so
/// the handler returns the exact satoshi figure the client paid — same
/// contract as `/upload`'s `amount` parameter. `prepared` is the pre-fetched
/// old-advert context from the same pre-payment step.
pub async fn handle(
    body: &[u8],
    identity_key: &str,
    price: u64,
    prepared: PreparedRenew,
    env: &Env,
) -> (Value, u16) {
    if identity_key.is_empty() {
        return error(
            ERR_MISSING_IDENTITY_KEY,
            "Missing authfetch identityKey.",
            400,
        );
    }

    // Re-run body validation for the exact TS error codes/order. Cheap (no
    // I/O) and guarantees the 400s never depend on `prepare`'s classification.
    if let Err(resp) = parse_renew_body(body) {
        return resp;
    }

    let ctx = match prepared {
        PreparedRenew::Ready(ctx) => ctx,
        // `parse_renew_body` above already answered the 400 for anything
        // `prepare` classified as InvalidBody; this arm is defensive.
        PreparedRenew::InvalidBody => {
            return error(
                ERR_MISSING_FIELDS,
                "Missing objectIdentifier or additionalMinutes.",
                400,
            )
        }
        PreparedRenew::NotFound => {
            return error(
                ERR_OLD_ADVERTISEMENT_NOT_FOUND,
                "Couldn't find old advertisement output.",
                404,
            )
        }
        PreparedRenew::LookupFailed => {
            return error(
                ERR_INTERNAL_RENEW,
                "An error occurred while handling the renewal.",
                500,
            )
        }
    };

    match inner(env, ctx, price).await {
        Ok(resp) => (json!(resp), 200),
        Err(err) => error_for(&err),
    }
}

enum RenewError {
    /// `createAction` refused to spend the old outpoint — the concurrent-
    /// renew race (another request just redeemed it). Answered 409.
    Conflict,
    SigningFailed,
    /// `processAction` (post-signing record/broadcast) failed.
    ProcessFailed,
    OverlayFailed,
    Internal,
}

/// Map a [`RenewError`] to its HTTP error body + status. Extracted from
/// [`handle`] so the 409 conflict mapping is unit-testable without a live
/// wallet.
fn error_for(err: &RenewError) -> (Value, u16) {
    match err {
        RenewError::Conflict => error(
            ERR_CREATE_ACTION_FAILED,
            "Old advertisement could not be redeemed. It may have just been renewed by a concurrent request.",
            409,
        ),
        RenewError::SigningFailed => error(
            ERR_SIGNING_OLD_ADVERTISEMENT,
            "Signing the replacement advertisement failed.",
            500,
        ),
        RenewError::ProcessFailed => error(
            ERR_INTERNAL_RENEW,
            "Recording the renewal transaction failed.",
            500,
        ),
        RenewError::OverlayFailed => error(ERR_OVERLAY_BROADCAST, "Overlay broadcast failed.", 500),
        RenewError::Internal => error(
            ERR_INTERNAL_RENEW,
            "An error occurred while handling the renewal.",
            500,
        ),
    }
}

async fn inner(env: &Env, ctx: RenewContext, price: u64) -> Result<RenewResponse, RenewError> {
    let wallet = Wallet::from_env(env).map_err(|_| RenewError::Internal)?;
    let admin_key = wallet.private_key().clone();

    // ── Build the new advert ──────────────────────────────────────────────
    let new_expiry = ctx.prev_expiry + ctx.additional_minutes * 60;
    let hash = uhrp_url_to_hash(&ctx.uhrp_url).ok_or(RenewError::Internal)?;

    // The renewed advert rebuilds its download URL from the CURRENT
    // PUBLIC_URL_BASE — renewals automatically migrate adverts minted under
    // an old base (e.g. the r2.dev dev URL) onto the custom domain.
    let public_url_base = env
        .var("PUBLIC_URL_BASE")
        .map_err(|_| RenewError::Internal)?
        .to_string();
    let public_url = format!(
        "{}/cdn/{}",
        public_url_base.trim_end_matches('/'),
        ctx.object_identifier
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

    // Rebuild the five fields with the new expiry time. Field 4 (content
    // length) is carried over verbatim from the old advert's PushDrop (it
    // was decoded once in `prepare`). Sign the concat.
    let server_identity_bytes = admin_key.public_key().to_compressed();
    let mut expiry_w = Writer::new();
    expiry_w.write_var_int(new_expiry);
    let expiry_bytes = expiry_w.into_bytes();
    let mut len_w = Writer::new();
    len_w.write_var_int(ctx.content_length);
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
        content_length: ctx.content_length,
        signature: sig_der,
    };
    let new_locking_hex = build_uhrp_advert_lock(&locking_pubkey.to_hex(), &new_fields)
        .map_err(|_| RenewError::Internal)?;

    // ── createAction spending the old UTXO → new advert ──────────────────
    let outpoint_str = format!("{}.{}", ctx.prev_txid, ctx.prev_vout);
    let new_tags = build_renewal_tags(
        ctx.original_uploader_tag.as_deref(),
        &ctx.uhrp_url,
        &ctx.object_identifier,
        new_expiry,
    );
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
        input_beef: if ctx.beef.is_empty() {
            None
        } else {
            Some(ctx.beef.clone())
        },
        description: format!("Renew advertisement for uhrpUrl {}", ctx.uhrp_url),
        randomize_outputs: false,
    };
    let template = wallet
        .create_action(&create_req)
        .await
        .map_err(|_| RenewError::Conflict)?;

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
        .map_err(|_| RenewError::ProcessFailed)?;

    // ── Overlay broadcast ────────────────────────────────────────────────
    // Both references submit a FULL AtomicBEEF, never a bare raw tx: the TS
    // renew broadcasts `Transaction.fromAtomicBEEF(tx)` (renew.ts:209) and
    // advertise.rs merges the template's input ancestry with the signed tx.
    // A naked tx fails the overlay's SPV on the spent-advert input —
    // observed live 2026-07-02 (the one paid hop that failed).
    let mut beef = bsv_rs::transaction::Beef::from_binary(&template.input_beef).map_err(|e| {
        worker::console_error!("renew: input BEEF parse failed: {e}");
        RenewError::OverlayFailed
    })?;
    beef.merge_raw_tx(signed.raw_tx.clone(), None);
    let atomic_beef = beef.to_binary_atomic(&signed.txid).map_err(|e| {
        worker::console_error!("renew: to_binary_atomic failed: {e}");
        RenewError::OverlayFailed
    })?;
    let overlay_url = overlay_url_from_env(env);
    submit_uhrp_advert(env, &overlay_url, &atomic_beef)
        .await
        .map_err(|e| {
            worker::console_error!("renew: overlay broadcast failed: {e:?}");
            RenewError::OverlayFailed
        })?;

    // ── Extend the R2 object's custom-time ───────────────────────────────
    // TS parity: `renew.ts:212–213` does `file.setMetadata({customTime})`.
    // R2 can't patch metadata in place, so this is a same-key copy (see
    // `storage::custom_time`). Best-effort by design: the payment is taken
    // and the renewed advert is on-chain + broadcast by this point, so
    // failing the response would report a successful renewal as failed.
    // Nothing on R2 reads custom-time operationally (no lifecycle rule) —
    // it exists for the queue consumer's dup-advert guard and tooling.
    let object_key = format!("cdn/{}", ctx.object_identifier);
    let custom_time = renewal_custom_time(new_expiry);
    if let Err(code) = extend_custom_time(env, UHRP_BINDING, &object_key, &custom_time).await {
        worker::console_error!(
            "renew: custom-time extend failed code={code} key={object_key} \
             (advert renewed on-chain; R2 metadata stays stale until the next renewal)"
        );
    }

    // ── Response ──────────────────────────────────────────────────────────
    // `amount` echoes the satoshis the payment middleware charged, threaded
    // from lib.rs exactly the way /upload's `amount` is.
    Ok(RenewResponse {
        status: "success",
        prev_expiry_time: ctx.prev_expiry,
        new_expiry_time: new_expiry,
        amount: price,
    })
}

fn error(code: &'static str, description: impl Into<String>, status: u16) -> (Value, u16) {
    (json!(ErrorBody::new(code, description.into())), status)
}

/// Parse + validate the `/renew` body. Error tuples match the TS error
/// codes/order verbatim (`ERR_MISSING_FIELDS` before `ERR_INVALID_TIME`).
fn parse_renew_body(body: &[u8]) -> Result<ParsedRenew, (Value, u16)> {
    let missing = || {
        error(
            ERR_MISSING_FIELDS,
            "Missing objectIdentifier or additionalMinutes.",
            400,
        )
    };
    let req: RenewRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => return Err(missing()),
    };
    let Some(uhrp_url) = req.uhrp_url.filter(|s| !s.is_empty()) else {
        return Err(missing());
    };
    let Some(additional_minutes_f) = req.additional_minutes else {
        return Err(missing());
    };
    if !additional_minutes_f.is_finite() || additional_minutes_f <= 0.0 {
        return Err(error(
            ERR_INVALID_TIME,
            "Additional Minutes must be a positive integer",
            400,
        ));
    }
    // Canonicalize: decode whatever faithful encoding the caller used
    // (canonical ce00, or the 1-byte 0x01 legacy form an early overlay
    // index circulated) down to the hash, then re-derive the CANONICAL
    // string. Tags, lookups, and the renewed advert all speak canonical —
    // observed live 2026-07-02: a legacy-encoded request 404'd because the
    // raw request string was hex-tagged instead of the canonical form.
    let canonical = match crate::routes::advertise::uhrp_url_to_hash(&uhrp_url) {
        Some(hash) => format!("uhrp://{}", crate::uhrp::hash::url_from_hash(&hash)),
        None => {
            return Err(error(
                ERR_MISSING_FIELDS,
                "uhrpUrl is not a valid UHRP reference.",
                400,
            ))
        }
    };
    Ok(ParsedRenew {
        uhrp_url: canonical,
        additional_minutes: additional_minutes_f as u64,
        limit: req.limit.unwrap_or(DEFAULT_LIMIT),
        offset: req.offset.unwrap_or(DEFAULT_OFFSET),
    })
}

/// Recover an output's locking script from a listOutputs BEEF: find the
/// advert's transaction by txid and read the script at `vout`.
fn locking_script_from_beef(beef: &[u8], txid: &str, vout: u32) -> Option<String> {
    if beef.is_empty() {
        return None;
    }
    let parsed = bsv_rs::transaction::Beef::from_binary(beef).ok()?;
    let tx = parsed.find_transaction_for_signing(txid)?;
    let out = tx.outputs.get(vout as usize)?;
    Some(hex::encode(out.locking_script.to_binary()))
}

/// Tag filter for the old-advert lookup: `uhrp_url_<hex>` ONLY. The
/// uploader tag is deliberately absent — renewal is any-identity (see
/// module doc).
fn lookup_tags(uhrp_url: &str) -> Vec<String> {
    vec![format!(
        "{UHRP_URL_TAG_PREFIX}{}",
        hex::encode(uhrp_url.as_bytes())
    )]
}

/// Assemble the renewed advert's tags. The uploader tag is the ORIGINAL
/// advert's, copied verbatim (never the renewing caller's key) so the
/// owner keeps `/list` and future-`/renew` visibility after a third-party
/// renewal. Legacy adverts without an uploader tag stay untagged.
fn build_renewal_tags(
    original_uploader_tag: Option<&str>,
    uhrp_url: &str,
    object_identifier: &str,
    new_expiry: u64,
) -> Vec<String> {
    let mut tags = Vec::with_capacity(4);
    if let Some(uploader_tag) = original_uploader_tag {
        tags.push(uploader_tag.to_string());
    }
    tags.push(format!(
        "{UHRP_URL_TAG_PREFIX}{}",
        hex::encode(uhrp_url.as_bytes())
    ));
    tags.push(format!(
        "{OBJECT_ID_TAG_PREFIX}{}",
        hex::encode(object_identifier.as_bytes())
    ));
    tags.push(format!("{EXPIRY_TAG_PREFIX}{new_expiry}"));
    tags
}

/// The renewed object's `custom-time` metadata value: ISO-8601 of
/// `(newExpiry + 300 s buffer)`, byte-identical to what `/upload`'s
/// presigner stamps at upload time (`upload.rs::iso8601_millis`).
fn renewal_custom_time(new_expiry: u64) -> String {
    iso8601_millis((new_expiry + CUSTOM_TIME_BUFFER_SECONDS) * 1000)
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

/// Find the old advert's `uploader_identity_key_<key>` tag, returned as
/// the FULL tag string so [`build_renewal_tags`] can copy it verbatim.
fn extract_uploader_tag(tags: &[String]) -> Option<String> {
    tags.iter()
        .find(|t| t.starts_with(UPLOADER_TAG_PREFIX))
        .cloned()
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

    /// Build a REAL UHRP advert locking script (via the same PushDrop
    /// builder production uses) with a chosen field-4 content length.
    fn advert_script_with_content_length(content_length: u64) -> String {
        use bsv_rs::primitives::ec::PrivateKey;
        let admin = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let locking_pubkey = derive_child_public_key(
            &admin,
            &uhrp_protocol_id(),
            UHRP_KEY_ID,
            UHRP_COUNTERPARTY_ANYONE,
        )
        .unwrap();
        let signing_key = derive_child_key(
            &admin,
            &uhrp_protocol_id(),
            UHRP_KEY_ID,
            UHRP_COUNTERPARTY_ANYONE,
        )
        .unwrap();
        let hash = bsv_rs::primitives::hash::sha256(b"renew pricing fixture");
        let sig = signing_key.sign(&hash).unwrap();
        let fields = UhrpAdvertFields {
            server_identity_key_hex: bsv_rs::primitives::encoding::to_hex(
                &admin.public_key().to_compressed(),
            ),
            hash: hash.to_vec(),
            url: "https://example.com/cdn/obj1".to_string(),
            expiry_time: 1_735_689_600,
            content_length,
            signature: sig.to_der(),
        };
        build_uhrp_advert_lock(&locking_pubkey.to_hex(), &fields).unwrap()
    }

    // ── Price derivation from PushDrop field 4 ──────────────────────────────

    #[test]
    fn derives_content_length_from_pushdrop_field4() {
        // Round-trip through the real PushDrop builder: whatever field 4
        // carries on chain is exactly what pricing sees.
        for len in [1u64, 0x42, 0xfc, 0x0100, 5_000_000_000] {
            let script = advert_script_with_content_length(len);
            assert_eq!(
                extract_content_length_from_pushdrop(&script),
                Some(len),
                "content length {len} must survive the PushDrop round-trip"
            );
        }
    }

    #[test]
    fn price_derivation_from_field4_matches_quote_formula() {
        // 5 GB advert renewed for 1 month (43 200 min) at $0.05/GB-mo with
        // the 15 USD/BSV fallback rate:
        //   usd  = 5 × 1 × 0.05 = 0.25
        //   sats = floor(0.25 × 1e8/15) = 1_666_666
        let script = advert_script_with_content_length(5_000_000_000);
        let file_size = extract_content_length_from_pushdrop(&script).unwrap() as f64;
        let sats = crate::routes::quote::compute_sat_price(file_size, 43_200.0, 0.05, 15.0);
        assert_eq!(sats, 1_666_666);
    }

    #[test]
    fn price_inputs_come_from_context_not_client() {
        let prepared = PreparedRenew::Ready(RenewContext {
            uhrp_url: "uhrp://x".to_string(),
            additional_minutes: 43_200,
            prev_expiry: 1_000,
            content_length: 5_000_000_000,
            object_identifier: "obj1".to_string(),
            original_uploader_tag: None,
            prev_txid: "00".repeat(32),
            prev_vout: 0,
            beef: vec![],
        });
        assert_eq!(prepared.price_inputs(), Some((5_000_000_000.0, 43_200.0)));
    }

    #[test]
    fn price_inputs_are_none_for_unpriceable_variants() {
        // None = free pass through the middleware; the handler then emits
        // the matching 400/404/500 without the client having paid.
        assert_eq!(PreparedRenew::InvalidBody.price_inputs(), None);
        assert_eq!(PreparedRenew::NotFound.price_inputs(), None);
        assert_eq!(PreparedRenew::LookupFailed.price_inputs(), None);
    }

    // ── Any-identity lookup ─────────────────────────────────────────────────

    #[test]
    fn lookup_tags_filter_by_uhrp_url_only() {
        let tags = lookup_tags("uhrp://abc");
        assert_eq!(
            tags,
            vec![format!("uhrp_url_{}", hex::encode("uhrp://abc".as_bytes()))]
        );
        assert!(
            !tags.iter().any(|t| t.starts_with(UPLOADER_TAG_PREFIX)),
            "renewal lookup must not filter by uploader identity"
        );
    }

    // ── Tag preservation ────────────────────────────────────────────────────

    #[test]
    fn renewal_tags_preserve_original_uploader_tag() {
        // A stranger renews the owner's advert: the new tags carry the
        // ORIGINAL owner's uploader tag, never the caller's key.
        let original = "uploader_identity_key_03aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let tags = build_renewal_tags(Some(original), "uhrp://abc", "obj1", 2_000);
        assert_eq!(tags[0], original);
        assert_eq!(
            tags.iter()
                .filter(|t| t.starts_with(UPLOADER_TAG_PREFIX))
                .count(),
            1,
            "exactly one uploader tag — the original's"
        );
        assert_eq!(
            tags[1],
            format!("uhrp_url_{}", hex::encode("uhrp://abc".as_bytes()))
        );
        assert_eq!(
            tags[2],
            format!("object_identifier_{}", hex::encode("obj1".as_bytes()))
        );
        assert_eq!(tags[3], "expiry_time_2000");
    }

    #[test]
    fn renewal_tags_omit_uploader_when_original_had_none() {
        // Legacy advert without an uploader tag: never stamp the caller.
        let tags = build_renewal_tags(None, "uhrp://abc", "obj1", 2_000);
        assert!(!tags.iter().any(|t| t.starts_with(UPLOADER_TAG_PREFIX)));
        assert_eq!(tags.len(), 3);
    }

    #[test]
    fn extract_uploader_tag_returns_full_tag() {
        let tags = vec![
            "expiry_time_1".to_string(),
            "uploader_identity_key_02bb".to_string(),
        ];
        assert_eq!(
            extract_uploader_tag(&tags).as_deref(),
            Some("uploader_identity_key_02bb")
        );
        assert!(extract_uploader_tag(&["expiry_time_1".to_string()]).is_none());
    }

    // ── custom-time formatting ──────────────────────────────────────────────

    #[test]
    fn renewal_custom_time_is_expiry_plus_buffer_iso8601() {
        // newExpiry 1746880196 + 300 s buffer = 1746880496 s
        // → JS `new Date(1746880496000).toISOString()` = "2025-05-10T12:34:56.000Z".
        // Byte-identical to the value /upload's presigner would stamp.
        assert_eq!(
            renewal_custom_time(1_746_880_196),
            "2025-05-10T12:34:56.000Z"
        );
    }

    // ── 409 conflict mapping ────────────────────────────────────────────────

    #[test]
    fn concurrent_renew_conflict_maps_to_409() {
        let (body, status) = error_for(&RenewError::Conflict);
        assert_eq!(status, 409);
        let got = serde_json::to_string(&body).unwrap();
        assert!(got.contains(r#""code":"ERR_CREATE_ACTION_FAILED""#));
        assert!(got.contains("concurrent"));
    }

    #[test]
    fn process_failure_is_500_internal_not_conflict() {
        let (body, status) = error_for(&RenewError::ProcessFailed);
        assert_eq!(status, 500);
        let got = serde_json::to_string(&body).unwrap();
        assert!(got.contains(r#""code":"ERR_INTERNAL_RENEW""#));
    }

    // ── Body parsing ────────────────────────────────────────────────────────

    #[test]
    fn parse_renew_body_happy_path() {
        // Any faithful encoding parses; the result is ALWAYS the canonical
        // ce00 form (the tag/lookup/advert currency).
        let hash = [0x5au8; 32];
        let canonical = format!("uhrp://{}", crate::uhrp::hash::url_from_hash(&hash));
        let body = format!(r#"{{"uhrpUrl":"{canonical}","additionalMinutes":1440}}"#);
        let parsed = parse_renew_body(body.as_bytes()).unwrap();
        assert_eq!(parsed.uhrp_url, canonical);
        assert_eq!(parsed.additional_minutes, 1440);
        assert_eq!(parsed.limit, DEFAULT_LIMIT);
        assert_eq!(parsed.offset, DEFAULT_OFFSET);

        // Legacy 0x01 input canonicalizes to the SAME string.
        let mut legacy_payload = vec![0x01];
        legacy_payload.extend_from_slice(&hash);
        let checksum = bsv_rs::primitives::hash::sha256d(&legacy_payload);
        legacy_payload.extend_from_slice(&checksum[..4]);
        let legacy = format!(
            "uhrp://{}",
            bsv_rs::primitives::encoding::to_base58(&legacy_payload)
        );
        let body2 = format!(r#"{{"uhrpUrl":"{legacy}","additionalMinutes":1440}}"#);
        assert_eq!(
            parse_renew_body(body2.as_bytes()).unwrap().uhrp_url,
            canonical
        );

        // Garbage refuses at 400 (never a wallet round-trip).
        assert!(parse_renew_body(br#"{"uhrpUrl":"uhrp://abc","additionalMinutes":1440}"#).is_err());
    }

    #[test]
    fn parse_renew_body_rejects_missing_and_nonpositive() {
        assert!(parse_renew_body(b"not json").is_err());
        assert!(parse_renew_body(br#"{"uhrpUrl":"uhrp://abc"}"#).is_err());
        assert!(parse_renew_body(br#"{"additionalMinutes":10}"#).is_err());
        let (_, status) =
            parse_renew_body(br#"{"uhrpUrl":"uhrp://abc","additionalMinutes":0}"#).unwrap_err();
        assert_eq!(status, 400);
        let (_, status) =
            parse_renew_body(br#"{"uhrpUrl":"uhrp://abc","additionalMinutes":-5}"#).unwrap_err();
        assert_eq!(status, 400);
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
