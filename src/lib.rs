//! bsv-storage-cloudflare — UHRP file-storage server on Cloudflare Workers.
//!
//! Protocol-compatible port of `@bsv/uhrp-storage-server` (nanostore.babbage.systems).
//! See `PROTOCOL.md` for the wire spec the Rust port must match byte-for-byte.

use bsv_middleware_cloudflare::{
    add_cors_headers,
    core::{PaymentVerdict, UnverifiableReason},
    init_panic_hook,
    middleware::{
        auth::{handle_cors_preflight, AuthSession},
        payment::payment_headers,
        process_auth_with_body_bounds, process_payment_with_storage, sign_json_response,
        AuthMiddlewareOptions, AuthResult, PaymentMiddlewareOptions, PaymentResult,
    },
    types::ErrorResponse,
    AuthCloudflareError, BodyBounds,
};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::ProtoWallet;
use serde_json::json;
use worker::*;

/// Must match `bsv-middleware-cloudflare::middleware::payment::ORIGINATOR`. Any
/// drift here makes the server issue a derivation_prefix that `verify_nonce`
/// later rejects.
const PAYMENT_ORIGINATOR: &str = "bsv-auth-cloudflare";

/// BRC-103/104 session TTL (`AuthMiddlewareOptions`). The TTL only governs
/// session records — a payment prefix's claim and its key-value record
/// ([`claims::paid_store`]) are written with **no expiry** (the challenge
/// HMAC never expires, so its claim must not either).
const SESSION_TTL_SECONDS: u64 = 3600;

/// The largest `X-BSV-Payment` header the paid routes read: 96 KiB. A larger
/// header is refused before it is parsed or decoded, with the middleware's
/// answer to a payment transaction it cannot read ([`payment_too_large`]).
pub const PAYMENT_HEADER_MAX: usize = 96 * 1024;

/// The most bytes of a request's body this Worker's auth layer reads before
/// it authenticates the caller: 2 MiB. The largest authenticated body this
/// Worker serves is a draft of at most `routes::drafts::MAX_DRAFT_BYTES`
/// (256 KiB); a payment rides in the `X-BSV-Payment` header, not the body,
/// and a file goes to the object store through its presigned URL, not
/// through the Worker. A longer body is answered by the layer: 413
/// `ERR_AUTH_BODY_TOO_LARGE`.
pub const AUTH_BODY_MAX_BYTES: u64 = 2 * 1024 * 1024;

/// The auth layer's bounds on this Worker: [`AUTH_BODY_MAX_BYTES`] for one
/// request; the total held at once in an isolate (503 `ERR_AUTH_BODIES_FULL`
/// with `Retry-After`) and the read's deadline (408 `ERR_AUTH_BODY_TIMEOUT`)
/// at the middleware's defaults.
pub fn auth_body_bounds() -> BodyBounds {
    BodyBounds::default().with_max_request_body_bytes(AUTH_BODY_MAX_BYTES)
}

pub mod claims;
mod error;
mod health;
mod overlay;
mod pass;
mod queue;
mod renewal;
mod routes;
mod storage;
mod types;
mod uhrp;
mod validation;
mod wallet;

/// Build and sign a 402 Payment Required response inline, matching the
/// reference `poc-server` /paid handler (`~/bsv/rust-middleware/poc-server/
/// src/lib.rs` around the no-payment branch of handle_paid).
///
/// **Why not use `process_payment_with_storage` + wrap the pre-built Response:**
/// The payment middleware builds `Response::from_json(&body)` and returns it.
/// If we read that Response back with `response.text().await`, parse it into
/// `serde_json::Value`, and hand that Value to `sign_json_response`, the
/// serializer re-emits different bytes (serde_json's Value uses a BTreeMap
/// and may reorder object keys). The signed payload's body bytes then differ
/// from the HTTP body sent to the client, so the server's signature fails
/// verification inside @bsv/sdk AuthFetch → MetaNet Client responds HTTP 400
/// on its verifySignature RPC → payment never fires.
///
/// **Inline build = atomic signing**: by calling `sign_json_response` with a
/// freshly-constructed `serde_json::Value`, the bytes serialized for the
/// signed payload are the exact bytes that become the response body. No
/// round-trip, no reordering, no mismatch.
async fn build_signed_402(price: u64, session: &AuthSession, server_key: &str) -> Result<Response> {
    let private_key = PrivateKey::from_hex(server_key)
        .map_err(|e| Error::from(format!("Invalid server key: {}", e)))?;
    let wallet = ProtoWallet::new(Some(private_key));
    let derivation_prefix = bsv_rs::auth::utils::create_nonce(&wallet, None, PAYMENT_ORIGINATOR)
        .await
        .map_err(|e| Error::from(format!("create_nonce: {}", e)))?;

    let body = json!({
        "status": "error",
        "code": "ERR_PAYMENT_REQUIRED",
        "satoshisRequired": price,
        "description": "A BSV payment is required to complete this request. Provide the X-BSV-Payment header."
    });

    let payment_hdrs = vec![
        (payment_headers::VERSION.to_string(), "1.0".to_string()),
        (
            payment_headers::SATOSHIS_REQUIRED.to_string(),
            price.to_string(),
        ),
        (
            payment_headers::DERIVATION_PREFIX.to_string(),
            derivation_prefix,
        ),
    ];

    signed_json_or_internal_error(&body, 402, &payment_hdrs, session)
}

/// BRC-29 payment processing with single-use derivation prefixes: the
/// middleware's `process_payment_with_storage` (the 0.7.8 door, whose
/// `internalizeAction` request is written once, through
/// `WorkerStorageClient::internalize_action_with_tx`) over the paid routes'
/// store ([`claims::PaidPrefixStore`]: the prefix claimed in the `CLAIMS` D1
/// database in one statement, the key-value record beside it).
///
/// The middleware reads the payment's subject transaction alone (output 0's
/// script and amount; no ancestry linked, no script run) and leaves the
/// payment's validity to the wallet storage server's `internalizeAction`.
/// The prefix is claimed before the wallet is called:
/// - a won claim goes on to the wallet and, accepted, to the route;
/// - the same transaction again is refused with the middleware's signed
///   `409 ERR_PAYMENT_REPLAYED`, another transaction under a bound prefix
///   with its signed `400 ERR_PAYMENT_INVALID` ([`claims::Refusal`], signed
///   by [`paid_route`]), neither touching the wallet;
/// - a store fault fails **closed** (503 `ERR_PAYMENT_UNAVAILABLE` with
///   `Retry-After`, the quote kept), never a service: signed when the gate
///   could not make the claim (its answer, signed by [`paid_route`]), and
///   the door's unsigned answer for a fault the store meets before or after
///   the gate;
/// - a wallet **error** releases the prefix to the same transaction (an
///   honest retry works); a wallet **rejection** (`accepted != true`) keeps
///   it claimed and 402s with a fresh challenge.
async fn run_payment_middleware<F: Fn(&Request) -> u64>(
    req: &Request,
    auth_context: &bsv_middleware_cloudflare::AuthContext,
    options: &PaymentMiddlewareOptions<F>,
    store: &claims::PaidStore<'_>,
) -> std::result::Result<PaymentResult, AuthCloudflareError> {
    let result = process_payment_with_storage(req, auth_context, options, store).await?;
    Ok(match result {
        PaymentResult::Required(r) => PaymentResult::Required(header_transport_only(r)),
        PaymentResult::Failed(r) => PaymentResult::Failed(header_transport_only(r)),
        other => other,
    })
}

/// The middleware's answer to a payment transaction it cannot read (400
/// `ERR_INVALID_PAYMENT`, the quote kept: nothing claimed, no fresh
/// challenge), for a header over [`PAYMENT_HEADER_MAX`].
fn payment_too_large() -> Result<Response> {
    let verdict = PaymentVerdict::Unverifiable {
        reason: UnverifiableReason::MalformedTransaction(
            "the payment transaction is too large to read".to_string(),
        ),
    };
    let body = ErrorResponse::new("ERR_INVALID_PAYMENT", verdict.to_string());
    Ok(add_cors_headers(
        Response::from_json(&body)?.with_status(400),
    ))
}

/// Whether an `X-BSV-Payment` header is over [`PAYMENT_HEADER_MAX`].
pub fn over_the_ceiling(header: &str) -> bool {
    header.len() > PAYMENT_HEADER_MAX
}

/// `payment_headers::TRANSPORTS` of the middleware.
const PAYMENT_TRANSPORTS: &str = "x-bsv-payment-transports";

/// The payment transports this Worker reads: the `X-BSV-Payment` header
/// alone. The middleware's own challenges (the fresh challenge after a
/// wallet rejection) name `x-bsv-payment-transports: header,multipart`;
/// the paid routes read no multipart body, so the name is taken off and the
/// challenge carries the header set [`build_signed_402`] sends.
fn header_transport_only(response: Response) -> Response {
    let _ = response.headers().delete(PAYMENT_TRANSPORTS);
    response
}

/// Build an UNSIGNED JSON response with CORS headers. The minimal error
/// surface for paths where no verified BRC-103 session exists (so a signed
/// response is impossible) and for last-resort fallbacks when signing fails.
fn unsigned_json_response(body: &serde_json::Value, status: u16) -> Result<Response> {
    let resp = Response::from_json(body)?.with_status(status);
    Ok(add_cors_headers(resp))
}

/// Map a typed middleware error onto the JSON error surface + HTTP status
/// the TS reference middlewares produce (the-composer #31).
///
/// Pure so `cargo test` can pin the classification: malformed handshake
/// bodies, wrong auth versions, missing/invalid identity keys, unknown
/// message types, and tampered signatures are all
/// `AuthCloudflareError::InvalidAuthentication`/`Unauthorized`/
/// `SessionNotFound` → **401**, matching `auth-express-middleware` (see
/// `bsv-middleware-cloudflare-public/src/error.rs::status_code`, whose
/// mapping is itself pinned against Express). Payment errors map to
/// 400/402/500 per `payment-express-middleware`. Previously `lib.rs`
/// discarded the typed error via `Error::from(e.to_string())`, which the
/// Workers runtime renders as an unsigned plaintext HTTP 500.
///
/// Body shape comes from `AuthCloudflareError::to_json()`: middleware-layer
/// `UNAUTHORIZED` uses a `message` field, handler-layer codes use
/// `description` — both verified against the live TS servers (see the
/// `to_json` doc comment in the middleware crate).
fn middleware_error_body(e: &AuthCloudflareError) -> (serde_json::Value, u16) {
    let body = serde_json::from_str::<serde_json::Value>(&e.to_json()).unwrap_or_else(|_| {
        json!({
            "status": "error",
            "code": e.error_code(),
            "description": e.to_string(),
        })
    });
    (body, e.status_code())
}

/// Turn a typed middleware error into an HTTP response: signed when a
/// verified session exists (payment-stage failures — the TS payment
/// middleware's errors flow through the auth middleware's response signing),
/// otherwise stable unsigned JSON (auth-stage failures happen before any
/// session is established, exactly like the TS auth middleware's own
/// unsigned 401).
fn middleware_error_response(
    e: &AuthCloudflareError,
    session: Option<&AuthSession>,
) -> Result<Response> {
    let (body, status) = middleware_error_body(e);
    console_error!(
        "middleware rejection: status={status} code={} detail={e}",
        e.error_code()
    );
    if let Some(s) = session {
        if let Ok(resp) = sign_json_response(&body, status, &[], s) {
            return Ok(resp);
        }
        console_error!("middleware rejection: signing failed; returning unsigned body");
    }
    unsigned_json_response(&body, status)
}

/// Sign the handler's `(body, status)` for the authenticated client; if
/// signing itself fails (server-key/config trouble), degrade to an unsigned
/// JSON 500 instead of the runtime's unsigned plaintext 500 (the-composer
/// #31 — "every response is signed" with a stable JSON floor).
fn signed_json_or_internal_error(
    body: &serde_json::Value,
    status: u16,
    extra_headers: &[(String, String)],
    session: &AuthSession,
) -> Result<Response> {
    match sign_json_response(body, status, extra_headers, session) {
        Ok(resp) => Ok(resp),
        Err(e) => {
            console_error!("response signing failed: {e}");
            unsigned_json_response(
                &json!({
                    "status": "error",
                    "code": "ERR_INTERNAL",
                    "description": "Failed to sign the response.",
                }),
                500,
            )
        }
    }
}

/// A paid request, authenticated and priced.
struct Paid<'a> {
    req: &'a Request,
    env: &'a Env,
    auth_context: &'a bsv_middleware_cloudflare::AuthContext,
    session: Option<&'a AuthSession>,
    server_key: &'a str,
    price: u64,
}

/// The paid routes.
enum PaidRoute {
    Upload,
    Renew(routes::renew::PreparedRenew),
}

impl PaidRoute {
    fn path(&self) -> &'static str {
        match self {
            PaidRoute::Upload => "/upload",
            PaidRoute::Renew(_) => "/renew",
        }
    }
}

/// The wallet storage server the paid routes internalize payments at: the
/// one `/advertise` draws funds from (`WALLET_STORAGE_URL`), so payments land
/// where `/advertise` can see them. The middleware's default is
/// storage.babbage.systems.
fn wallet_storage_url(env: &Env) -> String {
    env.var("WALLET_STORAGE_URL")
        .ok()
        .map(|v| v.to_string())
        .unwrap_or_else(|| "https://wallet-infra.x402agency.com".to_string())
}

/// `/upload` and `/renew` from the price on: the challenge, the header's
/// ceiling, the payment door over the paid routes' store, the route, and the
/// record of what a won claim was granted.
async fn paid_route(paid: Paid<'_>, route: PaidRoute, request_body: &[u8]) -> Result<Response> {
    let Paid {
        req,
        env,
        auth_context,
        session,
        server_key,
        price,
    } = paid;
    let header = req.headers().get(payment_headers::PAYMENT).ok().flatten();
    let store = match claims::paid_store(env) {
        Ok(store) => store,
        // The auth layer has already used `AUTH_SESSIONS`, so this is a
        // config-drift backstop, not a reachable client path.
        Err(e) => {
            return middleware_error_response(
                &AuthCloudflareError::ConfigError(format!("AUTH_SESSIONS KV not bound: {e}")),
                session,
            )
        }
    };
    // Short-circuit: if the client didn't provide `x-bsv-payment`, build
    // and sign the 402 inline (poc-server pattern). Skipping the payment
    // middleware here is intentional — wrapping its pre-built Response
    // forces a serde_json round-trip that produces body bytes ≠ what we
    // sign, which @bsv/sdk rejects via MetaNet Client's verifySignature
    // RPC. (Challenge prefixes are claimed at redemption, not issuance, so
    // bypassing the middleware for the 402 does not skip the single-use
    // claim.)
    if price > 0 && header.is_none() {
        return match session {
            Some(s) => build_signed_402(price, s, server_key).await,
            None => {
                // No session means AuthFetch wouldn't be able to verify
                // either way — fall through to middleware's unsigned 402
                // as a minimal error surface.
                let payment_options = PaymentMiddlewareOptions::new(
                    server_key.to_string(),
                    move |_: &Request| -> u64 { price },
                );
                match run_payment_middleware(req, auth_context, &payment_options, &store).await {
                    Ok(PaymentResult::Required(r) | PaymentResult::Failed(r)) => Ok(r),
                    Ok(_) => Ok(Response::from_json(&json!({"status": "error"}))?.with_status(500)),
                    // Typed 4xx/5xx JSON, not a plaintext 500 (#31).
                    Err(e) => middleware_error_response(&e, None),
                }
            }
        };
    }
    // The ceiling: a header the door would read (a priced request) that is
    // longer than 96 KiB is refused before it is parsed or decoded.
    if price > 0 && header.as_deref().is_some_and(over_the_ceiling) {
        return payment_too_large();
    }
    drop(header);
    // Annotate closure arg type explicitly so the HRTB on
    // `process_payment_with_storage::<F, S>`'s `F: Fn(&Request) -> u64`
    // bound is satisfied.
    let calc_price = move |_: &Request| -> u64 { price };
    let payment_options = PaymentMiddlewareOptions::with_storage_url(
        server_key.to_string(),
        calc_price,
        wallet_storage_url(env),
    );
    // Malformed/failed payment headers are typed 400s from the
    // middleware; sign them for the authenticated client (#31 — the TS
    // payment middleware's errors flow through auth's response signing).
    let payment_result =
        match run_payment_middleware(req, auth_context, &payment_options, &store).await {
            Ok(result) => result,
            Err(e) => return middleware_error_response(&e, session),
        };
    let path = route.path();
    let satoshis = match payment_result {
        PaymentResult::Free => None,
        PaymentResult::Verified(ref ctx) => {
            console_error!(
                "{path}: payment verified, accepted={} sats_paid={}",
                ctx.accepted,
                ctx.satoshis_paid
            );
            Some(ctx.satoshis_paid)
        }
        PaymentResult::Required(response) | PaymentResult::Failed(response) => {
            // A refused claim: the middleware's answer (409 for the same
            // transaction, 400 for another, the gate's 503 for a claim it
            // could not make), signed for the payer.
            if let Some(refusal) = store.take_refusal() {
                return match session {
                    Some(s) => signed_json_or_internal_error(
                        &refusal.body,
                        refusal.status,
                        &refusal.headers,
                        s,
                    ),
                    None => {
                        let resp = unsigned_json_response(&refusal.body, refusal.status)?;
                        for (name, value) in &refusal.headers {
                            resp.headers().set(name, value)?;
                        }
                        Ok(resp)
                    }
                };
            }
            // Required branch is handled above via build_signed_402 when the
            // client didn't send x-bsv-payment. Reaching here with Required
            // means the client DID send a payment header but the middleware
            // still returned Required — shouldn't happen in practice. Failed
            // covers the bad-payment paths: 400 for malformed payments or
            // failed verification, 503 for a fault outside the gate, 402
            // with a fresh challenge when the wallet rejected
            // (`accepted != true`).
            // Terminal from the client's perspective either way. Return
            // the unsigned Response rather than re-signing (which
            // mangles bytes).
            return Ok(response);
        }
    };
    // A won claim, its payment accepted: the first grant write. A failed
    // write is logged and changes nothing in the answer.
    let won = satoshis.and(store.won());
    let grants_db = store.ledger().db();
    if let (Some(won), Some(db), Some(satoshis)) = (&won, grants_db, satoshis) {
        if let Err(e) =
            claims::grants::paid(db, won, path, &auth_context.identity_key, satoshis).await
        {
            console_error!("{path}: the grant's first write failed: {e}");
        }
    }
    let identity_key = &auth_context.identity_key;
    let payment_txid = won.as_ref().map(|w| w.txid.as_str());
    let ((body, status), granted, renewed) = match route {
        PaidRoute::Upload => {
            let (answer, granted) =
                routes::upload::handle_granting(request_body, identity_key, price, env).await;
            (answer, granted, None)
        }
        PaidRoute::Renew(prepared) => {
            let granted = prepared.granted();
            // The renewal's row is opened before its transaction is handed
            // to the wallet, under the won claim's prefix.
            let ledger = match (&won, grants_db) {
                (Some(won), Some(db)) => Some(pass::Ledger {
                    db,
                    prefix: &won.prefix,
                    payment_txid: &won.txid,
                }),
                _ => None,
            };
            let renewed = routes::renew::handle(
                request_body,
                identity_key,
                price,
                prepared,
                payment_txid,
                ledger.as_ref(),
                env,
            )
            .await;
            // Served is the take of the renewing transaction, and nothing
            // else.
            let served = renewed
                .step
                .as_ref()
                .is_some_and(|step| step.outcome == renewal::Outcome::Taken);
            let new_expiry = renewed.step.as_ref().and_then(|step| step.new_expiry);
            let granted = granted.map(|mut g| {
                g.expiry_time = if served { new_expiry } else { None };
                g
            });
            (
                (renewed.body, renewed.status),
                granted,
                Some((served, renewed.step)),
            )
        }
    };
    if let (Some(won), Some(db)) = (&won, grants_db) {
        let granted = granted.unwrap_or_default();
        // `/renew`: the renewal's row is settled first, then the grant. A
        // request that ends between the two leaves a settled row beside a
        // grant that reads `paid`, which the pass sets `granted`; a grant is
        // never set `granted` beside a row that still reads no word.
        let recorded = match &renewed {
            Some((_, Some(step))) => {
                match pass::record(env, db, &won.prefix, &won.txid, step).await {
                    Ok(()) => true,
                    Err(e) => {
                        console_error!("{path}: the renewal's record failed: {e}");
                        false
                    }
                }
            }
            _ => true,
        };
        let written = match &renewed {
            // `/renew`: `granted` when served and its row settled; a taken
            // payment with no renewal stays `paid`, its answer recorded. A
            // served renewal whose row could not be settled leaves the grant
            // `paid` beside the row that reads no word, for the pass to ask
            // the wallet.
            Some((served, _)) if *served && !recorded => None,
            Some((served, _)) => {
                let state = if *served { "granted" } else { "paid" };
                Some(claims::grants::answered_as(db, won, state, status, &granted).await)
            }
            None => Some(claims::grants::answered(db, won, status, &granted).await),
        };
        if let Some(Err(e)) = written {
            console_error!("{path}: the grant's second write failed: {e}");
        }
    }
    match session {
        Some(s) => signed_json_or_internal_error(&body, status, &[], s),
        None => unsigned_json_response(&body, status),
    }
}

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    init_panic_hook();

    if req.method() == Method::Options {
        return handle_cors_preflight();
    }

    let path = req.path();
    let method = req.method();

    if matches!(
        (&method, path.as_str()),
        (Method::Get, "/") | (Method::Get, "/health")
    ) {
        let resp = Response::from_json(&health::body())?;
        return Ok(add_cors_headers(resp));
    }

    if method == Method::Get && path == "/.well-known/x402-info" {
        let resp = routes::manifest::handle(&env).await?;
        return Ok(add_cors_headers(resp));
    }

    // /quote is unauthenticated per PROTOCOL.md §1. Its body is read up to
    // `routes::quote::QUOTE_BODY_MAX_BYTES`; a longer one is a 413 before
    // any of it is parsed.
    if method == Method::Post && path == "/quote" {
        let (body, status) = match routes::quote::read_body(&req).await? {
            Some(body) => routes::quote::handle(&body, &env).await,
            None => routes::quote::body_too_large(),
        };
        let resp = Response::from_json(&body)?.with_status(status);
        return Ok(add_cors_headers(resp));
    }

    let server_key = env
        .secret("SERVER_PRIVATE_KEY")
        .map_err(|e| Error::from(format!("SERVER_PRIVATE_KEY not set: {}", e)))?
        .to_string();

    let auth_options = AuthMiddlewareOptions {
        server_private_key: server_key.clone(),
        allow_unauthenticated: false,
        session_ttl_seconds: SESSION_TTL_SECONDS,
        ..Default::default()
    };

    // Typed-error dispatch (the-composer #31): a failed handshake / bad
    // signature is a CLIENT error — surface the middleware's own 4xx JSON,
    // never the runtime's unsigned plaintext 500. No session exists on these
    // paths, so the body is stable unsigned JSON (the same posture as the
    // middleware's no-auth-headers 401, which mirrors the live TS servers).
    // The layer's own answers to a body it does not read (413, 503 with
    // `Retry-After`, 408) are `AuthResult::Response`, returned as they are.
    let auth_result =
        match process_auth_with_body_bounds(req, &env, &auth_options, auth_body_bounds()).await {
            Ok(result) => result,
            Err(e) => return middleware_error_response(&e, None),
        };

    let (auth_context, req, session, request_body) = match auth_result {
        AuthResult::Authenticated {
            context,
            request,
            session,
            body,
        } => (context, request, session, body),
        AuthResult::Response(response) => return Ok(response),
    };

    let identity_key = &auth_context.identity_key;
    let path = req.path();
    let method = req.method();

    // Paid route dispatch: pre-compute price, run BRC-29 middleware, then
    // enter the handler with the verified `amount`. Mirrors TS's
    // `createPaymentMiddleware({ calculateRequestPrice })` wired before
    // `/upload` in `storage-server/src/index.ts:101–132`.
    //
    // Price is computed asynchronously (WhatsOnChain rate) up-front; the
    // middleware's own `calculate_price: Fn(&Request) -> u64` callback is
    // sync, so we capture the precomputed value. `None` from
    // `parse_pricing_inputs` = free pass (matches the TS middleware's
    // `if (!fileSize || !retentionPeriod) return 0` short-circuit at
    // index.ts:105–114; the route handler then emits the correct 400).
    if method == Method::Post && path == "/upload" {
        let price = match routes::upload::parse_pricing_inputs(&request_body) {
            Some((fs, rp)) => routes::quote::compute_price_from_env(fs, rp, &env).await,
            None => 0,
        };
        let paid = Paid {
            req: &req,
            env: &env,
            auth_context: &auth_context,
            session: session.as_ref(),
            server_key: &server_key,
            price,
        };
        return paid_route(paid, PaidRoute::Upload, &request_body).await;
    }

    // `/renew` is the second paid route (PROTOCOL.md §5). `fileSize` is NOT
    // in the request body — `routes::renew::prepare` reads it from field 4
    // of the old advertisement's PushDrop (bound to on-chain data, never
    // client claims; the-composer #45) in a single pre-payment listOutputs
    // round-trip. The prepared context is threaded into the handler so the
    // lookup never runs twice. Price uses the exact `/quote` formula, and
    // the 402/payment plumbing is `/upload`'s ([`paid_route`]).
    if method == Method::Post && path == "/renew" {
        let prepared = routes::renew::prepare(&request_body, &env).await;
        // `None` = free pass (malformed body / advert not found / lookup
        // failure) — the handler then emits the correct 400/404/500 without
        // the client having paid for it.
        let price = match prepared.price_inputs() {
            Some((fs, minutes)) => routes::quote::compute_price_from_env(fs, minutes, &env).await,
            None => 0,
        };
        let paid = Paid {
            req: &req,
            env: &env,
            auth_context: &auth_context,
            session: session.as_ref(),
            server_key: &server_key,
            price,
        };
        return paid_route(paid, PaidRoute::Renew(prepared), &request_body).await;
    }

    // /drafts — composer-storage score-draft sync (NOT nanostore parity; see
    // src/routes/drafts.rs). Dispatched as a path family because the draft id
    // rides in the path; the module routes GET/PUT/DELETE internally and
    // returns the repo-standard `(Value, status)` for the signing tail below.
    if path == "/drafts" || path.starts_with("/drafts/") {
        let (body, status) =
            routes::drafts::handle(&method, &path, &request_body, identity_key, &env).await;
        return match session {
            Some(ref s) => signed_json_or_internal_error(&body, status, &[], s),
            None => unsigned_json_response(&body, status),
        };
    }

    let (body, status) = match (method, path.as_str()) {
        (Method::Get, "/find") => {
            let url = req.url().map_err(|e| Error::from(e.to_string()))?;
            routes::find::handle(&url, &request_body, identity_key, &env).await
        }
        (Method::Get, "/list") => {
            let url = req.url().map_err(|e| Error::from(e.to_string()))?;
            routes::list::handle(&url, &request_body, identity_key, &env).await
        }
        (Method::Post, "/advertise") => {
            routes::advertise::handle(&request_body, identity_key, &env).await
        }
        _ => (
            json!({
                "status": "error",
                "code": "ERR_NOT_FOUND",
                "description": "Not Found",
            }),
            404,
        ),
    };

    match session {
        Some(ref s) => signed_json_or_internal_error(&body, status, &[], s),
        None => unsigned_json_response(&body, status),
    }
}

/// R2 event-notification queue consumer. Drains the `uhrp-post-upload`
/// queue (configured in `wrangler.toml` `[[queues.consumers]]`). Each
/// message is an R2 object-create event; successful messages produce an
/// on-chain UHRP advertisement — the same output `/advertise` produces
/// on the HTTP path, just triggered automatically when the client's R2
/// PUT lands.
///
/// Per-batch error handling: the handler always returns `Ok(())`. Individual
/// messages are ack'd or retried inside `queue::handle_batch` via
/// `MessageExt::ack` / `MessageExt::retry`. Returning `Err` here would
/// trigger the whole batch to retry, which would re-advertise
/// already-successful messages — exactly the at-least-once hazard CF's
/// per-message ack API exists to avoid.
#[event(queue)]
async fn queue_handler(
    batch: MessageBatch<queue::QueueMessage>,
    env: Env,
    _ctx: Context,
) -> Result<()> {
    init_panic_hook();
    queue::handle_batch(batch, &env).await;
    Ok(())
}

/// The hourly pass (`wrangler.toml` `[triggers] crons`): the paid `/renew`'s
/// rows that wait on the overlay or on the wallet's word, at most
/// `renewal::PASS_ROWS` a run ([`pass::run`]). The Worker's only scheduled
/// act.
#[event(scheduled)]
async fn hourly_pass(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    init_panic_hook();
    pass::run(&env).await;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn a_renewal_is_granted_only_at_the_take_and_never_refused() {
        let source = include_str!("lib.rs");
        let route = &source[source.find("async fn paid_route(").unwrap()..];
        let route = &route[..route.find("\n}\n").unwrap()];
        let renew = &route[route.find("PaidRoute::Renew(prepared) =>").unwrap()..];
        assert!(renew.contains("step.outcome == renewal::Outcome::Taken"));
        assert!(renew.contains("let state = if *served { \"granted\" } else { \"paid\" };"));
        assert!(!renew.contains("\"refused\""));
        assert!(renew.contains("pass::record(env, db, &won.prefix, &won.txid, step)"));
    }

    /// The renewal's row is settled before the grant's second write, and a
    /// served renewal's grant is set `granted` only once its row is settled
    /// (the states each seam leaves: `renewal::on_sqlite`).
    #[test]
    fn the_renewals_row_is_settled_before_the_grant() {
        let source = include_str!("lib.rs");
        let route = &source[source.find("async fn paid_route(").unwrap()..];
        let route = &route[..route.find("\n}\n").unwrap()];
        let record = route
            .find("pass::record(env, db, &won.prefix, &won.txid, step)")
            .unwrap();
        let grant = route.find("claims::grants::answered_as(").unwrap();
        assert!(record < grant);
        assert!(route.contains("Some((served, _)) if *served && !recorded => None,"));
    }

    // ── #31: typed middleware errors → JSON with the TS status codes ──────
    //
    // The audit live-probed empty/truncated/garbage handshake bodies, wrong
    // versions, missing/invalid identity keys, unknown message types, and
    // tampered signatures: all previously surfaced as unsigned plaintext
    // HTTP 500. Every one of those paths produces one of the three auth
    // variants below (see `bsv-middleware-cloudflare-public/src/middleware/
    // auth.rs` + `transport/cloudflare.rs`), so pinning the mapping here
    // pins the dispatch behavior.

    #[test]
    fn invalid_authentication_maps_to_signedish_401_json() {
        let (body, status) = middleware_error_body(&AuthCloudflareError::InvalidAuthentication(
            "bad sig".into(),
        ));
        assert_eq!(status, 401);
        assert_eq!(body["status"], "error");
        assert_eq!(body["code"], "ERR_INVALID_AUTH");
        assert!(body["description"].as_str().unwrap().contains("bad sig"));
    }

    #[test]
    fn unauthorized_maps_to_401_with_ts_message_field() {
        // TS middleware-layer wire format uses `message`, not `description`
        // (verified against live TS servers — middleware error.rs::to_json).
        let (body, status) = middleware_error_body(&AuthCloudflareError::Unauthorized);
        assert_eq!(status, 401);
        assert_eq!(body["code"], "UNAUTHORIZED");
        assert_eq!(body["message"], "Mutual-authentication failed!");
        assert!(body.get("description").is_none());
    }

    #[test]
    fn session_not_found_maps_to_401() {
        let (body, status) =
            middleware_error_body(&AuthCloudflareError::SessionNotFound("02abc".into()));
        assert_eq!(status, 401);
        assert_eq!(body["code"], "ERR_SESSION_NOT_FOUND");
    }

    #[test]
    fn payment_errors_map_to_express_status_codes() {
        let (body, status) =
            middleware_error_body(&AuthCloudflareError::MalformedPayment("nope".into()));
        assert_eq!(status, 400);
        assert_eq!(body["code"], "ERR_MALFORMED_PAYMENT");

        let (body, status) =
            middleware_error_body(&AuthCloudflareError::PaymentFailed("rejected".into()));
        assert_eq!(status, 400);
        assert_eq!(body["code"], "ERR_PAYMENT_FAILED");

        let (_, status) = middleware_error_body(&AuthCloudflareError::InvalidDerivationPrefix);
        assert_eq!(status, 400);
    }

    #[test]
    fn infrastructure_errors_stay_500_but_json() {
        let (body, status) = middleware_error_body(&AuthCloudflareError::KvError("boom".into()));
        assert_eq!(status, 500);
        assert_eq!(body["status"], "error");
        assert_eq!(body["code"], "ERR_STORAGE");

        let (body, status) =
            middleware_error_body(&AuthCloudflareError::ConfigError("misconfig".into()));
        assert_eq!(status, 500);
        assert_eq!(body["code"], "ERR_CONFIG");
    }

    #[test]
    fn error_body_serializes_with_stable_field_order() {
        // The signed variant serializes this exact Value — field order must
        // be deterministic (serde_json `preserve_order` keeps parse order).
        let (body, _) =
            middleware_error_body(&AuthCloudflareError::InvalidAuthentication("x".into()));
        let text = serde_json::to_string(&body).unwrap();
        assert!(
            text.starts_with(r#"{"status":"error","code":"ERR_INVALID_AUTH""#),
            "unexpected serialization: {text}"
        );
    }

    #[test]
    fn the_paid_routes_name_the_header_transport_alone() {
        use bsv_middleware_cloudflare::middleware::payment::payment_headers;
        // The name taken off the middleware's own challenges.
        assert_eq!(PAYMENT_TRANSPORTS, payment_headers::TRANSPORTS);
        // The challenge the routes build carries the version, the price and
        // the prefix, and no transports.
        let source = include_str!("lib.rs");
        let build = &source[source.find("async fn build_signed_402(").unwrap()..];
        let build = &build[..build.find("signed_json_or_internal_error(").unwrap()];
        for name in ["VERSION", "SATOSHIS_REQUIRED", "DERIVATION_PREFIX"] {
            assert!(
                build.contains(&format!("payment_headers::{name}")),
                "{name}"
            );
        }
        assert!(!build.contains("TRANSPORTS"));
        // Every middleware answer on the paid routes passes through
        // `header_transport_only`.
        let run = &source[source.find("async fn run_payment_middleware").unwrap()..];
        let run = &run[..run.find("\n}\n").unwrap()];
        assert!(run.contains("PaymentResult::Required(header_transport_only(r))"));
        assert!(run.contains("PaymentResult::Failed(header_transport_only(r))"));
    }

    // ── the auth layer's figure for a request's body ─────────────────────

    #[test]
    fn the_auth_layer_reads_at_most_two_mib_of_a_body_on_this_worker() {
        use bsv_middleware_cloudflare::core::body_bound::{BodyLedger, BoundedBody};
        use bsv_middleware_cloudflare::{
            DEFAULT_BODY_DEADLINE, DEFAULT_MAX_HELD_BODY_BYTES, ERR_AUTH_BODY_TOO_LARGE,
        };
        assert_eq!(AUTH_BODY_MAX_BYTES, 2_097_152);
        let bounds = auth_body_bounds();
        assert_eq!(bounds.max_request_body_bytes, AUTH_BODY_MAX_BYTES);
        // The total and the deadline are the middleware's.
        assert_eq!(bounds.max_held_body_bytes, DEFAULT_MAX_HELD_BODY_BYTES);
        assert_eq!(bounds.body_deadline, DEFAULT_BODY_DEADLINE);
        assert!(bounds.max_held_body_bytes >= bounds.max_request_body_bytes);
        // The largest authenticated body this Worker serves, a draft, is
        // under the figure with room to spare.
        assert_eq!(routes::drafts::MAX_DRAFT_BYTES, 256 * 1024);
        const { assert!((routes::drafts::MAX_DRAFT_BYTES as u64) * 4 < AUTH_BODY_MAX_BYTES) };

        // The layer's reader at this Worker's bounds: a declared length over
        // the figure is its 413 with nothing read.
        let ledger = BodyLedger::new();
        let refusal = BoundedBody::admit(
            &ledger,
            Some(AUTH_BODY_MAX_BYTES + 1),
            bounds.max_request_body_bytes,
            bounds.max_held_body_bytes,
        )
        .unwrap_err();
        assert_eq!(refusal.status(), 413);
        assert_eq!(refusal.code(), ERR_AUTH_BODY_TOO_LARGE);
        assert_eq!(refusal.to_json()["budget"], AUTH_BODY_MAX_BYTES);
        assert_eq!(ledger.held(), 0);
        // A body that arrives is read up to exactly the figure, and refused
        // one byte past it.
        let mut body = BoundedBody::admit(
            &ledger,
            None,
            bounds.max_request_body_bytes,
            bounds.max_held_body_bytes,
        )
        .unwrap();
        let chunk = vec![0u8; 64 * 1024];
        for _ in 0..32 {
            body.push(&chunk).unwrap();
        }
        assert_eq!(body.len() as u64, AUTH_BODY_MAX_BYTES);
        let refusal = body.push(&[0]).unwrap_err();
        assert_eq!(refusal.status(), 413);
        assert_eq!(refusal.code(), ERR_AUTH_BODY_TOO_LARGE);
        drop(body);
        assert_eq!(ledger.held(), 0);
    }

    #[test]
    fn every_call_of_the_auth_layer_names_this_workers_bounds() {
        let source = include_str!("lib.rs");
        let code = &source[..source.find("#[cfg(test)]\nmod tests").unwrap()];
        let mut calls = Vec::new();
        let mut rest = code;
        while let Some(at) = rest.find("process_auth") {
            let tail = &rest[at..];
            let name_len = tail
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(tail.len());
            if tail[name_len..].starts_with('(') {
                calls.push(&tail[..name_len]);
            }
            rest = &tail[name_len..];
        }
        assert_eq!(calls, vec!["process_auth_with_body_bounds"]);
        assert!(code.contains(
            "process_auth_with_body_bounds(req, &env, &auth_options, auth_body_bounds())"
        ));
        // The layer's answers are returned as they are.
        assert!(code.contains("AuthResult::Response(response) => return Ok(response),"));
    }
}
