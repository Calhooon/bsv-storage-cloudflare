//! POST /renew — see PROTOCOL.md §5.
//!
//! Port of the reference's `renew` route, redesigned for real pricing (the
//! price is bound to the advert's on-chain content length). BRC-31 auth and
//! the BRC-29 payment door are wired in `lib.rs`.
//!
//! # What the route does, in order
//!
//! 0. Before any payment ([`prepare`], called by `lib.rs`): parse the body;
//!    `listOutputs` the advert by its `uhrp_url_<hex>` tag (any identity) and
//!    pick the one with the largest `expiry_time_*`; decode field 4 (the
//!    content length) from its PushDrop; then HEAD the stored object
//!    `cdn/<object identifier>` through the `UHRP_FILES` binding (no byte of
//!    it is read). No object, or an object whose size differs from field 4,
//!    is a free 404 `ERR_FILE_NOT_FOUND`: nothing is claimed and the wallet
//!    is not asked to take a payment. The price is `/quote`'s formula over
//!    field 4 and `additionalMinutes`.
//! 1. The payment door (`lib.rs`): the 402, the claim, `internalizeAction`,
//!    the grant row `paid`.
//! 2. The renewing step ([`renew_from`]): the new PushDrop advert (fields
//!    0-2 and 4 as before, field 3 the new expiry, re-signed), then
//!    `createAction` spending the old advert, the signature (PushDrop for the
//!    old advert, P2PKH for change), and the Atomic BEEF of the new
//!    transaction. Then the renewal's row is written (`renewals`: the
//!    payment's txid, the renewing txid, the advert's bytes, the outcome no
//!    word), and only then `processAction` with `isNoSend: false` and
//!    `isDelayed: false` (the wallet sends it now). If the row cannot be
//!    written the transaction is not handed over: the action is released and
//!    the renewal is not made. After any answer of `processAction` that is
//!    not a take, one read of the wallet's record of the txid
//!    (`findProvenTxReqs`); the record decides when there is one
//!    ([`crate::renewal::decide`]).
//!    - `createAction` refused with the answer a spent advert gives (the
//!      explicit input is unavailable): after [`RE_READ_DELAY_MS`], one
//!      re-read of the file's current advert and, when it names the same
//!      stored object at an expiry not lower than the first attempt's, one
//!      more try of the whole step from it, in the same request, so that
//!      two payers of one file at once can both be served. The second payer
//!      is served when that try's renewing transaction is taken; otherwise
//!      the answer is that of a payment taken with no renewal. There is
//!      never a third try, and any other refusal is not retried.
//!    - A failure after `createAction` and before `processAction` (the
//!      signature, the BEEF, the row), or `processAction` refused with an
//!      error by name while the wallet holds no record of the txid: the
//!      action is released in the wallet, and with it the old advert.
//! 3. Taken (a broadcaster took the renewing transaction): served. The
//!    answer is the signed 200 `{status, prevExpiryTime, newExpiryTime,
//!    amount, overlayAdmitted}` and the grant is `granted`, whatever
//!    follows. The renewed advert is then submitted to the overlay, within
//!    `overlay::ADMISSION_DEADLINE_MS`; `overlayAdmitted` says whether its
//!    admission names the advert's output. A refusal in the overlay's error
//!    shape is recorded with its reason and never submitted again; any other
//!    answer is a fault and puts one re-submit on the Worker's queue
//!    (`renewal::QUEUE_DELIVERIES` deliveries at most), then the hourly pass.
//! 4. Not made: `500 ERR_RENEWAL_NOT_MADE`. No word: `502
//!    ERR_RENEWAL_UNCONFIRMED`. The grant stays `paid`; `lib.rs` settles the
//!    renewal's row under the payment's prefix (`renewals`), with the
//!    renewing txid and the outcome.
//!
//! The route reads and writes no byte of the stored object: the HEAD before
//! the payment is its only use of the object store.
//!
//! # Any-identity renewal
//!
//! The old advert is looked up by `uhrp_url_<hex>` alone, so anyone who
//! pays can extend hosting. The renewed advert keeps the ORIGINAL uploader
//! tag (never the caller's key), so the owner keeps `/list` and `/renew`
//! visibility of the upload.
//!
//! # Deviation from the TypeScript reference
//!
//! The reference is `infra/uhrp-server-cloud-bucket` in bsv-blockchain/ts-stack
//! at 57c5f13055b555b83c1ef368fff3650abd21b6ef.
//!
//! - **Served at the take.** This route answers 200 once a broadcaster took
//!   the renewing transaction, and the overlay's admission is a duty after
//!   it. The reference still requires the object's retention write and the
//!   overlay's broadcast before its 200 (`src/routes/renew.ts:152-163`), and
//!   answers 500 or 502 when either fails.
//! - **A recorded `paid` row.** A taken payment with no renewal is answered
//!   500 or 502 with the payment's txid and kept as a `paid` grant with a
//!   `renewals` row; the reference records nothing (`renew.ts:168-171`).
//! - **A missing object before any charge.** A missing or mismatched stored
//!   object is a free 404 `ERR_FILE_NOT_FOUND`; the reference's pricing
//!   answers it 500 `ERR_PAYMENT_INTERNAL`, also before any charge
//!   (`src/utils/getMetadata.ts:54-59`).
//! - **No custom time on a renewal.** The stored object's custom time is
//!   not advanced; the term of record is the advert's expiry and the
//!   grant's. The reference advances it with a metadata-only write
//!   (`src/utils/extendObjectRetention.ts:4-27`, called at `renew.ts:156`).
//! - **The object identifier** is read from the advert's
//!   `object_identifier_<hex>` tag.

use crate::error::{
    ERR_FILE_NOT_FOUND, ERR_INTERNAL_RENEW, ERR_INVALID_TIME, ERR_MISSING_FIELDS,
    ERR_MISSING_IDENTITY_KEY, ERR_OLD_ADVERTISEMENT_NOT_FOUND,
};
use crate::overlay::{admit_uhrp_advert, overlay_url_from_env, ADMISSION_DEADLINE_MS};
use crate::pass::Ledger;
use crate::renewal::{self, Admission, Outcome, ProcessWord};
use crate::storage::head::{head_object, UHRP_BINDING};
use crate::types::{ErrorBody, RenewRequest, RenewResponse};
use crate::uhrp::pushdrop::{build_uhrp_advert_lock, UhrpAdvertFields};
use crate::wallet::brc42::{
    derive_child_key, derive_child_public_key, uhrp_protocol_id, UHRP_COUNTERPARTY_ANYONE,
    UHRP_KEY_ID,
};
use crate::wallet::client::{RpcFailure, Wallet};
use crate::wallet::signer::{sign_transaction_mixed, InputUnlock};
use crate::wallet::types::{
    AbortActionRequest, CreateActionInput, CreateActionOutput, CreateActionRequest,
    ListOutputsRequest, OutputItem, ProcessActionRequest, SignedTransaction,
};

use bsv_rs::primitives::ec::PrivateKey;
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
/// Matches the reference's `unlockingScriptLength: 74`.
const PUSHDROP_UNLOCK_LEN: u32 = 74;

/// Default pagination (the reference's defaults).
const DEFAULT_LIMIT: u32 = 200;
const DEFAULT_OFFSET: i32 = 0;

/// The wait before the one re-read of the advert after `createAction`
/// refused a spent advert, in milliseconds: the other renewal's
/// `processAction` makes its advert the file's current one.
pub const RE_READ_DELAY_MS: u64 = 2_000;

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

/// The advert a renewal starts from: everything the renewing step needs
/// from the pre-payment `listOutputs` (or the one re-read).
pub struct RenewContext {
    /// Canonical `uhrp://…` URL from the request body.
    pub uhrp_url: String,
    /// Whole minutes to extend by (validated finite and > 0).
    pub additional_minutes: u64,
    /// The body's pagination, kept for the one re-read.
    pub limit: u32,
    pub offset: i32,
    /// Expiry of the chosen (max-`expiry_time_*`) old advert, unix seconds.
    pub prev_expiry: u64,
    /// Field 4 of the old advert's PushDrop — the on-chain content length
    /// in bytes. This is the `fileSize` the renewal price derives from.
    pub content_length: u64,
    /// Decoded from the old advert's `object_identifier_<hex>` tag.
    pub object_identifier: String,
    /// The old advert's FULL `uploader_identity_key_<key>` tag, preserved
    /// verbatim onto the renewed advert.
    pub original_uploader_tag: Option<String>,
    /// Old advert outpoint — becomes input 0 of the renewal transaction.
    pub prev_txid: String,
    pub prev_vout: u32,
    /// BEEF from `listOutputs` covering the old UTXO's ancestry (handed to
    /// `createAction` for input-script verification).
    pub beef: Vec<u8>,
}

/// Outcome of the pre-payment [`prepare`] step. Only `Ready` is priceable;
/// every other variant prices at 0 (a free pass through the payment door)
/// so the handler answers it without the client paying for it.
pub enum PreparedRenew {
    /// Advert found and decoded, its stored object present at its size.
    Ready(RenewContext),
    /// Body malformed/invalid — `handle` re-parses and emits the exact 400.
    InvalidBody,
    /// No advert matched the `uhrp_url_<hex>` tag — 404.
    NotFound,
    /// The advert's stored object is not there — 404 `ERR_FILE_NOT_FOUND`.
    FileMissing,
    /// The stored object's size differs from the advert's content length —
    /// 404 `ERR_FILE_NOT_FOUND`.
    FileMismatch,
    /// Wallet lookup, PushDrop decode or the object store's HEAD failed —
    /// 500.
    LookupFailed,
}

impl PreparedRenew {
    /// What a renewal of this advert grants, but its new expiry (the
    /// handler's answer carries it).
    #[must_use]
    pub fn granted(&self) -> Option<crate::claims::Granted> {
        match self {
            Self::Ready(ctx) => Some(crate::claims::Granted {
                object_identifier: Some(ctx.object_identifier.clone()),
                uhrp_url: Some(ctx.uhrp_url.clone()),
                file_size: Some(ctx.content_length),
                minutes: Some(ctx.additional_minutes as f64),
                expiry_time: None,
            }),
            _ => None,
        }
    }

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

/// The pre-payment step: the advert, then a HEAD of its stored object.
/// Called by `lib.rs` BEFORE the payment door so the price is derived from
/// the on-chain content length; the result is passed into [`handle`].
pub async fn prepare(body: &[u8], env: &Env) -> PreparedRenew {
    let Ok(parsed) = parse_renew_body(body) else {
        return PreparedRenew::InvalidBody;
    };
    let Ok(wallet) = Wallet::from_env(env) else {
        return PreparedRenew::LookupFailed;
    };
    let found = find_advert(
        &wallet,
        parsed.uhrp_url,
        parsed.additional_minutes,
        parsed.limit,
        parsed.offset,
    )
    .await;
    let ctx = match found {
        PreparedRenew::Ready(ctx) => ctx,
        other => return other,
    };
    // The stored object: a HEAD, no body.
    let key = format!("cdn/{}", ctx.object_identifier);
    match head_object(env, UHRP_BINDING, &key).await {
        Ok(Some(head)) if head.size == ctx.content_length => PreparedRenew::Ready(ctx),
        Ok(Some(head)) => {
            worker::console_log!(
                "renew/prepare: {key} holds {} bytes, the advert {}",
                head.size,
                ctx.content_length
            );
            PreparedRenew::FileMismatch
        }
        Ok(None) => PreparedRenew::FileMissing,
        Err(code) => {
            worker::console_log!("renew/prepare: HEAD {key} failed: {code}");
            PreparedRenew::LookupFailed
        }
    }
}

/// The file's current advert: `listOutputs` by `uhrp_url_<hex>` (any
/// identity), the output with the largest `expiry_time_*`, its object
/// identifier and uploader tags, and field 4 of its PushDrop.
async fn find_advert(
    wallet: &Wallet<'_>,
    uhrp_url: String,
    additional_minutes: u64,
    limit: u32,
    offset: i32,
) -> PreparedRenew {
    let list_req = ListOutputsRequest {
        basket: UHRP_BASKET.to_string(),
        tags: lookup_tags(&uhrp_url),
        tag_query_mode: Some("all".to_string()),
        // wallet-infra implements exactly `"locking scripts"` (it has no
        // BEEF support in listOutputs — its createAction resolves its own
        // txids internally, so `input_beef: None` on the spend is fine).
        include: Some("locking scripts".to_string()),
        include_tags: Some(true),
        include_locking_scripts: Some(true),
        limit: Some(limit),
        offset: Some(offset),
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

    // `object_identifier_<hex>` is mandatory (the advert always has it).
    // The uploader tag is preserved when present: legacy adverts without
    // one stay untagged.
    let Some(chosen_tags) = chosen.tags.as_ref() else {
        return PreparedRenew::NotFound;
    };
    let Some(object_identifier) = extract_object_identifier(chosen_tags) else {
        worker::console_log!("renew/prepare: advert has no object_identifier tag");
        return PreparedRenew::LookupFailed;
    };
    let original_uploader_tag = extract_uploader_tag(chosen_tags);

    // The locking script from the row when the server provides it; else
    // recovered from the returned BEEF. A script that is missing or cannot
    // be decoded is a failure, never a guessed length.
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
        uhrp_url,
        additional_minutes,
        limit,
        offset,
        prev_expiry,
        content_length,
        object_identifier,
        original_uploader_tag,
        prev_txid: chosen.outpoint.txid.clone(),
        prev_vout: chosen.outpoint.vout,
        beef: list_result.beef,
    })
}

/// The handler's answer, and what its renewing step came to when it ran.
pub struct Renewed {
    pub body: Value,
    pub status: u16,
    /// `None` when no renewing step ran (a 400, a 404, a lookup failure).
    pub step: Option<StepRecord>,
}

/// What a renewing step came to: the row `lib.rs` records.
#[derive(Debug, Clone)]
pub struct StepRecord {
    pub outcome: Outcome,
    /// The renewing transaction, once one was signed.
    pub renewing_txid: Option<String>,
    /// The expiry the renewed advert carries, once one was signed.
    pub new_expiry: Option<u64>,
    /// The overlay's answer to the renewed advert (taken renewals only).
    pub admission: Option<Admission>,
    /// The renewed advert's Atomic BEEF, to submit again (taken or no word).
    pub beef: Option<Vec<u8>>,
}

/// Handle `POST /renew` after the payment door.
///
/// `price` is the satoshi figure the door charged (the answer's `amount`).
/// `prepared` is the pre-payment step's result. `payment_txid` is the taken
/// payment's transaction (`None` when no payment was taken), which the
/// answers name when no renewal is served. `ledger` is where the renewal's
/// row is written before its transaction is handed to the wallet (`None`
/// when no payment was claimed).
pub async fn handle(
    body: &[u8],
    identity_key: &str,
    price: u64,
    prepared: PreparedRenew,
    payment_txid: Option<&str>,
    ledger: Option<&Ledger<'_>>,
    env: &Env,
) -> Renewed {
    let plain = |(body, status): (Value, u16)| Renewed {
        body,
        status,
        step: None,
    };
    if identity_key.is_empty() {
        return plain(error(
            ERR_MISSING_IDENTITY_KEY,
            "Missing authfetch identityKey.",
            400,
        ));
    }

    // Re-run body validation for the exact error codes and order. Cheap (no
    // I/O) and the 400s never depend on `prepare`'s classification.
    if let Err(resp) = parse_renew_body(body) {
        return plain(resp);
    }

    let ctx = match prepared {
        PreparedRenew::Ready(ctx) => ctx,
        // `parse_renew_body` above already answered the 400 for anything
        // `prepare` classified as InvalidBody; this arm is defensive.
        PreparedRenew::InvalidBody => {
            return plain(error(
                ERR_MISSING_FIELDS,
                "Missing objectIdentifier or additionalMinutes.",
                400,
            ))
        }
        PreparedRenew::NotFound => {
            return plain(error(
                ERR_OLD_ADVERTISEMENT_NOT_FOUND,
                "Couldn't find old advertisement output.",
                404,
            ))
        }
        PreparedRenew::FileMissing => {
            return plain(error(
                ERR_FILE_NOT_FOUND,
                "The stored file was not found.",
                404,
            ))
        }
        PreparedRenew::FileMismatch => {
            return plain(error(
                ERR_FILE_NOT_FOUND,
                "The stored file does not match its advertisement.",
                404,
            ))
        }
        PreparedRenew::LookupFailed => {
            return plain(error(
                ERR_INTERNAL_RENEW,
                "An error occurred while handling the renewal.",
                500,
            ))
        }
    };

    let Ok(wallet) = Wallet::from_env(env) else {
        return not_made(None, payment_txid);
    };
    let (ctx, attempt) = renew_with_one_more_try(&wallet, env, ctx, ledger).await;
    match attempt {
        Attempt::Taken(made) => {
            let admission = admit_uhrp_advert(
                env,
                &overlay_url_from_env(env),
                &made.beef,
                ADMISSION_DEADLINE_MS,
            )
            .await;
            if admission != Admission::Admitted {
                worker::console_error!(
                    "renew: the overlay's answer for {}: {admission:?}",
                    made.txid
                );
            }
            let response = RenewResponse {
                status: "success",
                prev_expiry_time: ctx.prev_expiry,
                new_expiry_time: made.new_expiry,
                amount: price,
                overlay_admitted: admission == Admission::Admitted,
            };
            Renewed {
                body: json!(response),
                status: 200,
                step: Some(StepRecord {
                    outcome: Outcome::Taken,
                    renewing_txid: Some(made.txid),
                    new_expiry: Some(made.new_expiry),
                    admission: Some(admission),
                    beef: Some(made.beef),
                }),
            }
        }
        Attempt::NoWord(made) => {
            let (body, status) = renewal::no_word_answer(payment_txid);
            Renewed {
                body,
                status,
                step: Some(StepRecord {
                    outcome: Outcome::NoWord,
                    renewing_txid: Some(made.txid),
                    new_expiry: Some(made.new_expiry),
                    admission: None,
                    beef: Some(made.beef),
                }),
            }
        }
        Attempt::NotMade { txid } => not_made(txid, payment_txid),
        Attempt::CreateRefused(failure) => {
            worker::console_error!("renew: createAction refused: {failure:?}");
            not_made(None, payment_txid)
        }
    }
}

/// The answer and the record of a renewal that was not made.
fn not_made(renewing_txid: Option<String>, payment_txid: Option<&str>) -> Renewed {
    let (body, status) = renewal::not_made_answer(payment_txid);
    Renewed {
        body,
        status,
        step: Some(StepRecord {
            outcome: Outcome::NotMade,
            renewing_txid,
            new_expiry: None,
            admission: None,
            beef: None,
        }),
    }
}

/// What one try of the renewing step came to.
enum Attempt {
    /// `createAction` refused, with the wallet's answer or none.
    CreateRefused(RpcFailure),
    /// Not made; the renewing txid when one was signed.
    NotMade { txid: Option<String> },
    /// Signed and handed to the wallet; no word that it was sent.
    NoWord(Made),
    /// A broadcaster took it.
    Taken(Made),
}

/// A signed renewing transaction.
struct Made {
    txid: String,
    new_expiry: u64,
    /// Its Atomic BEEF, for the overlay.
    beef: Vec<u8>,
}

/// The renewing step, and once more from the file's current advert when
/// `createAction` refused the spent advert and the re-read names the same
/// stored object ([`same_file`]). Returns the advert the last try started
/// from, and what it came to.
async fn renew_with_one_more_try(
    wallet: &Wallet<'_>,
    env: &Env,
    ctx: RenewContext,
    ledger: Option<&Ledger<'_>>,
) -> (RenewContext, Attempt) {
    let first = renew_from(wallet, env, &ctx, ledger).await;
    let again = matches!(&first, Attempt::CreateRefused(f) if renewal::spent_advert(f));
    if !again {
        return (ctx, first);
    }
    worker::Delay::from(std::time::Duration::from_millis(RE_READ_DELAY_MS)).await;
    let current = find_advert(
        wallet,
        ctx.uhrp_url.clone(),
        ctx.additional_minutes,
        ctx.limit,
        ctx.offset,
    )
    .await;
    match current {
        PreparedRenew::Ready(next) if same_file(&ctx, &next) => {
            let second = renew_from(wallet, env, &next, ledger).await;
            (next, second)
        }
        _ => (ctx, first),
    }
}

/// Whether the re-read advert `next` may carry the one more try begun from
/// `first`: it names the same stored object, of the same content length
/// (the price paid covers that size), and its expiry is not lower than the
/// first attempt's. Two uploads of the same bytes share a URL and have two
/// objects and two adverts; the try never renews the other one.
#[must_use]
fn same_file(first: &RenewContext, next: &RenewContext) -> bool {
    next.object_identifier == first.object_identifier
        && next.content_length == first.content_length
        && next.prev_expiry >= first.prev_expiry
}

/// The new advert's `createAction` request, the key that signs the old
/// advert's input, and the new expiry.
struct Built {
    request: CreateActionRequest,
    signing_key: PrivateKey,
    new_expiry: u64,
}

/// Build the renewed advert for `ctx`: the five PushDrop fields with the
/// new expiry, signed, and the `createAction` that spends the old advert.
fn build_advert(env: &Env, admin_key: &PrivateKey, ctx: &RenewContext) -> Option<Built> {
    let new_expiry = ctx.prev_expiry + ctx.additional_minutes * 60;
    let hash = uhrp_url_to_hash(&ctx.uhrp_url)?;

    // The renewed advert rebuilds its download URL from the CURRENT
    // PUBLIC_URL_BASE — renewals move adverts minted under an old base onto
    // the current one.
    let public_url_base = env.var("PUBLIC_URL_BASE").ok()?.to_string();
    let public_url = format!(
        "{}/cdn/{}",
        public_url_base.trim_end_matches('/'),
        ctx.object_identifier
    );

    let locking_pubkey = derive_child_public_key(
        admin_key,
        &uhrp_protocol_id(),
        UHRP_KEY_ID,
        UHRP_COUNTERPARTY_ANYONE,
    )
    .ok()?;
    let signing_key = derive_child_key(
        admin_key,
        &uhrp_protocol_id(),
        UHRP_KEY_ID,
        UHRP_COUNTERPARTY_ANYONE,
    )
    .ok()?;

    // The five fields with the new expiry. Field 4 (content length) is
    // carried over from the old advert's PushDrop. Sign the concat.
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
    let sig_der = signing_key.sign(&digest).ok()?.to_der();

    let new_fields = UhrpAdvertFields {
        server_identity_key_hex: bsv_rs::primitives::encoding::to_hex(&server_identity_bytes),
        hash: hash.to_vec(),
        url: public_url,
        expiry_time: new_expiry,
        content_length: ctx.content_length,
        signature: sig_der,
    };
    let new_locking_hex = build_uhrp_advert_lock(&locking_pubkey.to_hex(), &new_fields).ok()?;

    let new_tags = build_renewal_tags(
        ctx.original_uploader_tag.as_deref(),
        &ctx.uhrp_url,
        &ctx.object_identifier,
        new_expiry,
    );
    // Marked as ours, so wallet-infra makes the output spendable after
    // processAction.
    let custom_instructions = json!({
        "type": "UHRPAdvertisement",
        "protocolID": [2, "uhrp advertisement"],
        "keyID": "1",
        "counterparty": "anyone",
    })
    .to_string();
    let request = CreateActionRequest {
        outputs: vec![CreateActionOutput {
            locking_script: new_locking_hex,
            satoshis: 1,
            output_description: "UHRP advertisement token (renewed)".to_string(),
            basket: Some(UHRP_BASKET.to_string()),
            tags: new_tags,
            custom_instructions: Some(custom_instructions),
        }],
        inputs: vec![CreateActionInput {
            outpoint: format!("{}.{}", ctx.prev_txid, ctx.prev_vout),
            unlocking_script_length: PUSHDROP_UNLOCK_LEN,
            input_description: "Redeeming old advertisement".to_string(),
        }],
        // The listOutputs BEEF: the old advert's ancestry for wallet-infra's
        // input-script verification.
        input_beef: if ctx.beef.is_empty() {
            None
        } else {
            Some(ctx.beef.clone())
        },
        description: format!("Renew advertisement for uhrpUrl {}", ctx.uhrp_url),
        randomize_outputs: false,
    };
    Some(Built {
        request,
        signing_key,
        new_expiry,
    })
}

/// One try of the renewing step from `ctx`: `createAction`, the signature,
/// the Atomic BEEF, the renewal's row (`ledger`), `processAction`, and the
/// wallet's word for the txid.
async fn renew_from(
    wallet: &Wallet<'_>,
    env: &Env,
    ctx: &RenewContext,
    ledger: Option<&Ledger<'_>>,
) -> Attempt {
    let admin_key = wallet.private_key().clone();
    let Some(built) = build_advert(env, &admin_key, ctx) else {
        return Attempt::NotMade { txid: None };
    };
    let template = match wallet.create_action_answered(&built.request).await {
        Ok(template) => template,
        Err(failure) => return Attempt::CreateRefused(failure),
    };

    // ── Sign: PushDrop for input 0 (the old advert), P2PKH for the rest ──
    let unlocks: Vec<InputUnlock> = (0..template.inputs.len())
        .map(|i| {
            if i == 0 {
                InputUnlock::PushDrop {
                    key: &built.signing_key,
                }
            } else {
                InputUnlock::P2pkh
            }
        })
        .collect();
    let Ok(signed) = sign_transaction_mixed(&template, &admin_key, &unlocks) else {
        release(wallet, &template.reference).await;
        return Attempt::NotMade { txid: None };
    };
    // The overlay is given a full Atomic BEEF (the old advert's ancestry and
    // the new transaction), never a bare transaction.
    let Some(beef) = atomic_beef(&template.input_beef, &signed) else {
        release(wallet, &template.reference).await;
        return Attempt::NotMade { txid: None };
    };

    // ── The row, before the transaction is handed over: a request that ends
    // at any later point leaves it for the pass. ──
    if let Some(ledger) = ledger {
        if let Err(e) = crate::pass::open(ledger, &signed.txid, built.new_expiry, &beef).await {
            worker::console_error!("renew: the renewal's row was not written: {e}");
            release(wallet, &template.reference).await;
            return Attempt::NotMade { txid: None };
        }
    }

    // ── processAction: the wallet records the transaction and sends it now ──
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
    let answer = wallet.process_action_answered(&process_req).await;
    let made = Made {
        txid: signed.txid,
        new_expiry: built.new_expiry,
        beef,
    };
    if let Err(failure) = &answer {
        worker::console_error!("renew: processAction: {failure:?}");
    }
    // After any answer that is not a take, one read of the wallet's record.
    let word = renewal::read_process_answer(&answer, &made.txid);
    let record = if word == ProcessWord::Taken {
        Ok(None)
    } else {
        match wallet.find_proven_tx_reqs(&made.txid).await {
            Ok(rows) => Ok(renewal::read_record(&rows, &made.txid)),
            Err(failure) => {
                worker::console_error!("renew: findProvenTxReqs failed: {failure:?}");
                Err(())
            }
        }
    };
    if renewal::release_after(word, &record) {
        release(wallet, &template.reference).await;
    }
    match renewal::decide(word, &record) {
        Outcome::Taken => Attempt::Taken(made),
        Outcome::NotMade => Attempt::NotMade {
            txid: Some(made.txid),
        },
        Outcome::NoWord => Attempt::NoWord(made),
    }
}

/// Release the wallet's action: its inputs (the old advert, the
/// change) are released. A failure is logged.
async fn release(wallet: &Wallet<'_>, reference: &str) {
    let req = AbortActionRequest {
        reference: reference.to_string(),
    };
    match wallet.abort_action(&req).await {
        Ok(r) => worker::console_log!("renew: the action {reference} released: {}", r.aborted),
        Err(e) => worker::console_error!("renew: the action {reference} not released: {e}"),
    }
}

/// The Atomic BEEF of `signed` over the template's input ancestry.
fn atomic_beef(input_beef: &[u8], signed: &SignedTransaction) -> Option<Vec<u8>> {
    let mut beef = bsv_rs::transaction::Beef::from_binary(input_beef).ok()?;
    beef.merge_raw_tx(signed.raw_tx.clone(), None);
    beef.to_binary_atomic(&signed.txid).ok()
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
            limit: DEFAULT_LIMIT,
            offset: DEFAULT_OFFSET,
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
        assert_eq!(PreparedRenew::FileMissing.price_inputs(), None);
        assert_eq!(PreparedRenew::FileMismatch.price_inputs(), None);
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

    // ── The stored object ───────────────────────────────────────────────

    #[test]
    fn the_route_reads_and_writes_no_byte_of_the_stored_object() {
        let src = include_str!("renew.rs");
        let code = &src[..src.find("#[cfg(test)]\nmod tests").unwrap()];
        // The pre-payment HEAD is the route's only use of the object store.
        assert_eq!(code.matches("head_object(").count(), 1);
        // The object store is reached through a binding (`bucket`) or the
        // HEAD helper; the route names no binding, no body read and no
        // metadata write.
        for read_or_write in [
            ".bucket(",
            ".bytes()",
            ".text()",
            "array_buffer",
            "custom_time",
            "custom-time",
        ] {
            assert!(!code.contains(read_or_write), "{read_or_write}");
        }
        let head = &code[code.find("pub async fn prepare(").unwrap()..];
        let head = &head[..head.find("\n}\n").unwrap()];
        assert!(head.contains("head_object(env, UHRP_BINDING, &key)"));
        assert!(head.contains("head.size == ctx.content_length"));
        // No module of the store rewrites an object's metadata.
        let storage = include_str!("../storage/mod.rs");
        assert!(!storage.contains("custom_time"));
    }

    #[test]
    fn a_missing_or_mismatched_object_is_a_free_404() {
        let src = include_str!("renew.rs");
        let handle = &src[src.find("pub async fn handle(").unwrap()..];
        for variant in ["PreparedRenew::FileMissing", "PreparedRenew::FileMismatch"] {
            let arm = &handle[handle.find(variant).unwrap()..];
            let arm = &arm[..arm.find("))\n        }").unwrap()];
            assert!(
                arm.contains("ERR_FILE_NOT_FOUND") && arm.contains("404"),
                "{arm}"
            );
        }
    }

    // ── The renewing step ───────────────────────────────────────────────

    #[test]
    fn one_more_try_only_after_a_spent_advert_and_never_a_third() {
        let src = include_str!("renew.rs");
        let tries = &src[src.find("async fn renew_with_one_more_try(").unwrap()..];
        let tries = &tries[..tries.find("\n}\n").unwrap()];
        assert_eq!(tries.matches("renew_from(").count(), 2);
        assert_eq!(tries.matches("find_advert(").count(), 1);
        assert!(tries.contains("renewal::spent_advert(f)"));
        assert!(!tries.contains("loop") && !tries.contains("while"));
        assert_eq!(RE_READ_DELAY_MS, 2_000);
    }

    #[test]
    fn a_failure_after_create_action_releases_the_action() {
        let src = include_str!("renew.rs");
        let step = &src[src.find("async fn renew_from(").unwrap()..];
        let step = &step[..step.find("\n}\n").unwrap()];
        let sign = step.find("sign_transaction_mixed(").unwrap();
        let process = step.find("process_action_answered(").unwrap();
        // The signature's, the BEEF's and the row's failures, before
        // processAction: each releases the action.
        assert_eq!(
            step[sign..process]
                .matches("release(wallet, &template.reference)")
                .count(),
            3
        );
        // After processAction, only an error by name with no record of the
        // txid releases it: the wallet processed nothing.
        let after = &step[process..];
        let released = after.find("release(wallet, &template.reference)").unwrap();
        assert!(after[..released].contains("if renewal::release_after(word, &record) {"));
        assert_eq!(step.matches("release(").count(), 4);
    }

    /// The renewal's row is written before the renewing transaction is
    /// handed to the wallet, and a failed write hands nothing over.
    #[test]
    fn the_row_is_written_before_process_action() {
        let src = include_str!("renew.rs");
        let step = &src[src.find("async fn renew_from(").unwrap()..];
        let step = &step[..step.find("\n}\n").unwrap()];
        let open = step.find("crate::pass::open(ledger, &signed.txid").unwrap();
        let process = step.find("process_action_answered(").unwrap();
        assert!(open < process);
        let failed = &step[open..process];
        let failed = &failed[..failed
            .find("return Attempt::NotMade { txid: None };")
            .unwrap()];
        assert!(failed.contains("release(wallet, &template.reference)"));
        assert_eq!(step.matches("process_action_answered(").count(), 1);
        // The record is read after every answer that is not a take.
        let read = &step[process..];
        assert!(read.contains("let record = if word == ProcessWord::Taken {"));
        assert_eq!(read.matches("find_proven_tx_reqs(").count(), 1);
        assert!(read.contains("match renewal::decide(word, &record) {"));
    }

    fn ctx(object: &str, prev_expiry: u64, content_length: u64) -> RenewContext {
        RenewContext {
            uhrp_url: "uhrp://same-bytes".into(),
            additional_minutes: 30,
            limit: DEFAULT_LIMIT,
            offset: DEFAULT_OFFSET,
            prev_expiry,
            content_length,
            object_identifier: object.into(),
            original_uploader_tag: None,
            prev_txid: "aa".repeat(32),
            prev_vout: 0,
            beef: vec![],
        }
    }

    /// Two uploads of the same bytes: one URL, two objects, two adverts. The
    /// one more try goes on only from an advert of the first attempt's
    /// object at an expiry not lower than the first attempt's.
    #[test]
    fn the_one_more_try_never_renews_another_files_advert() {
        let first = ctx("object-a", 2_000, 1_000);
        // The first attempt's object, renewed by the other payer.
        assert!(same_file(&first, &ctx("object-a", 2_000 + 1_800, 1_000)));
        assert!(same_file(&first, &ctx("object-a", 2_000, 1_000)));
        // The other upload's advert of the same bytes, at any expiry.
        for expiry in [1_000, 2_000, 9_000] {
            assert!(!same_file(&first, &ctx("object-b", expiry, 1_000)));
        }
        // The same object at a lower expiry, or another size.
        assert!(!same_file(&first, &ctx("object-a", 1_999, 1_000)));
        assert!(!same_file(&first, &ctx("object-a", 3_000, 999)));
        let src = include_str!("renew.rs");
        let tries = &src[src.find("async fn renew_with_one_more_try(").unwrap()..];
        let tries = &tries[..tries.find("\n}\n").unwrap()];
        assert!(tries.contains("PreparedRenew::Ready(next) if same_file(&ctx, &next) =>"));
        assert!(tries.contains("_ => (ctx, first),"));
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
        // PROTOCOL.md §5 response: {status, prevExpiryTime, newExpiryTime,
        // amount}, and this Worker's `overlayAdmitted`.
        let body = RenewResponse {
            status: "success",
            prev_expiry_time: 1_000,
            new_expiry_time: 2_000,
            amount: 42,
            overlay_admitted: true,
        };
        let got = serde_json::to_string(&body).unwrap();
        assert_eq!(
            got,
            r#"{"status":"success","prevExpiryTime":1000,"newExpiryTime":2000,"amount":42,"overlayAdmitted":true}"#
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
