//! bsv-storage-cloudflare — UHRP file-storage server on Cloudflare Workers.
//!
//! Protocol-compatible port of `@bsv/uhrp-storage-server` (nanostore.babbage.systems).
//! See `PROTOCOL.md` for the wire spec the Rust port must match byte-for-byte.

use bsv_middleware_cloudflare::{
    add_cors_headers, init_panic_hook,
    middleware::{
        auth::{handle_cors_preflight, AuthSession},
        payment::payment_headers,
        process_auth, process_payment_with_storage, sign_json_response, AuthMiddlewareOptions,
        AuthResult, PaymentMiddlewareOptions, PaymentResult,
    },
    AuthCloudflareError, KvSessionStorage,
};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::ProtoWallet;
use serde_json::json;
use worker::*;

/// Must match `bsv-middleware-cloudflare::middleware::payment::ORIGINATOR`. Any
/// drift here makes the server issue a derivation_prefix that `verify_nonce`
/// later rejects.
const PAYMENT_ORIGINATOR: &str = "bsv-auth-cloudflare";

/// BRC-103/104 session TTL. Used both for `AuthMiddlewareOptions` and for
/// the `KvSessionStorage` handle [`payment_nonce_store`] builds, so the two
/// stay in lockstep with the storage `process_auth` constructs internally
/// (same KV binding, same `"auth"` prefix, same TTL). The TTL only governs
/// session records — consumed payment derivation prefixes are written with
/// **no expiry** (the challenge HMAC never expires, so its consumption
/// record must not either).
const SESSION_TTL_SECONDS: u64 = 3600;

mod error;
mod overlay;
mod queue;
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

/// The single-use payment-derivation-prefix store (the-composer #44/#62).
///
/// Same `AUTH_SESSIONS` KV namespace + `"auth"` prefix + TTL that the auth
/// middleware's `process_auth` builds internally, so consumed payment
/// prefixes live alongside the BRC-103/104 sessions they protect (keys:
/// `auth:nonce:payment-derivation-prefix:<prefix>`, written with no
/// expiry). `process_auth` has already used this binding by the time any
/// paid route runs, so a missing binding fails at auth — the `ConfigError`
/// here is a config-drift backstop, not a reachable client path.
fn payment_nonce_store(env: &Env) -> std::result::Result<KvSessionStorage, AuthCloudflareError> {
    let kv = env.kv("AUTH_SESSIONS").map_err(|e| {
        AuthCloudflareError::ConfigError(format!("AUTH_SESSIONS KV not bound: {}", e))
    })?;
    Ok(KvSessionStorage::new(kv, "auth", SESSION_TTL_SECONDS))
}

/// BRC-29 payment processing with single-use derivation prefixes —
/// middleware 0.3.0 `process_payment_with_storage` threaded through the
/// [`payment_nonce_store`] seam. Replaces the `#[allow(deprecated)]`
/// stateless `process_payment` shim (the-composer #62, closing #44 on the
/// live `/upload` and `/renew` routes).
///
/// Deliberate money-path deltas vs the stateless shim (both are documented
/// hardening divergences from `@bsv/payment-express-middleware` 1.2.3; the
/// middleware's own executed tests pin the ordering):
/// - a replayed `X-BSV-Payment` header is rejected with
///   `400 ERR_INVALID_DERIVATION_PREFIX` **before** touching the wallet
///   (previously: deferred to the upstream wallet's duplicate handling);
/// - a KV fault while consuming the prefix fails **closed**
///   (`Err(KvError)` → signed 500 `ERR_STORAGE` via
///   [`middleware_error_response`]), never silently disabling replay
///   protection;
/// - a wallet **error** releases the prefix (honest retry works); a wallet
///   **rejection** (`accepted != true`) keeps it consumed and 402s with a
///   fresh challenge.
async fn run_payment_middleware<F: Fn(&Request) -> u64>(
    req: &Request,
    env: &Env,
    auth_context: &bsv_middleware_cloudflare::AuthContext,
    options: &PaymentMiddlewareOptions<F>,
) -> std::result::Result<PaymentResult, AuthCloudflareError> {
    let nonce_store = payment_nonce_store(env)?;
    process_payment_with_storage(req, auth_context, options, &nonce_store).await
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

#[event(fetch)]
async fn main(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
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
        let resp = Response::from_json(&json!({
            "status": "success",
            "message": "bsv-storage-cloudflare running",
        }))?;
        return Ok(add_cors_headers(resp));
    }

    // /quote is unauthenticated per PROTOCOL.md §1.
    if method == Method::Post && path == "/quote" {
        let body = req.bytes().await?;
        let (body, status) = routes::quote::handle(&body, &env).await;
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
    let auth_result = match process_auth(req, &env, &auth_options).await {
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
        // Short-circuit: if the client didn't provide `x-bsv-payment`, build
        // and sign the 402 inline (poc-server pattern). Skipping the payment
        // middleware here is intentional — wrapping its pre-built Response
        // forces a serde_json round-trip that produces body bytes ≠ what we
        // sign, which @bsv/sdk rejects via MetaNet Client's verifySignature
        // RPC. (Challenge prefixes are consumed at redemption, not issuance,
        // so bypassing the middleware for the 402 does not skip #44's
        // single-use enforcement.)
        if price > 0
            && req
                .headers()
                .get(payment_headers::PAYMENT)
                .ok()
                .flatten()
                .is_none()
        {
            return match session {
                Some(ref s) => build_signed_402(price, s, &server_key).await,
                None => {
                    // No session means AuthFetch wouldn't be able to verify
                    // either way — fall through to middleware's unsigned 402
                    // as a minimal error surface.
                    let payment_options = PaymentMiddlewareOptions::new(
                        server_key.clone(),
                        move |_: &Request| -> u64 { price },
                    );
                    match run_payment_middleware(&req, &env, &auth_context, &payment_options).await
                    {
                        Ok(PaymentResult::Required(r) | PaymentResult::Failed(r)) => Ok(r),
                        Ok(_) => {
                            Ok(Response::from_json(&json!({"status": "error"}))?.with_status(500))
                        }
                        // Typed 4xx/5xx JSON, not a plaintext 500 (#31).
                        Err(e) => middleware_error_response(&e, None),
                    }
                }
            };
        }
        // Annotate closure arg type explicitly so the HRTB on
        // `process_payment_with_storage::<F, S>`'s `F: Fn(&Request) -> u64`
        // bound is satisfied.
        let calc_price = move |_: &Request| -> u64 { price };
        // Payment must internalize against the SAME wallet server /advertise
        // draws funds from. Middleware default is storage.babbage.systems; override
        // with our WALLET_STORAGE_URL so /upload payments land where /advertise
        // can see them.
        let wallet_url = env
            .var("WALLET_STORAGE_URL")
            .ok()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "https://wallet-infra.x402agency.com".to_string());
        let payment_options =
            PaymentMiddlewareOptions::with_storage_url(server_key.clone(), calc_price, wallet_url);
        // Malformed/failed payment headers are typed 400s from the
        // middleware; sign them for the authenticated client (#31 — the TS
        // payment middleware's errors flow through auth's response signing).
        let payment_result =
            match run_payment_middleware(&req, &env, &auth_context, &payment_options).await {
                Ok(result) => result,
                Err(e) => return middleware_error_response(&e, session.as_ref()),
            };
        match payment_result {
            PaymentResult::Free | PaymentResult::Verified(_) => {
                if let PaymentResult::Verified(ref ctx) = payment_result {
                    console_error!(
                        "upload: payment verified, accepted={} sats_paid={}",
                        ctx.accepted,
                        ctx.satoshis_paid
                    );
                }
                let (body, status) =
                    routes::upload::handle(&request_body, identity_key, price, &env).await;
                return match session {
                    Some(ref s) => signed_json_or_internal_error(&body, status, &[], s),
                    None => unsigned_json_response(&body, status),
                };
            }
            PaymentResult::Required(response) | PaymentResult::Failed(response) => {
                // Required branch is handled above via build_signed_402 when the
                // client didn't send x-bsv-payment. Reaching here with Required
                // means the client DID send a payment header but the middleware
                // still returned Required — shouldn't happen in practice. Failed
                // covers the bad-payment paths: 400 for malformed payments,
                // failed verification, or a REPLAYED derivation prefix
                // (single-use enforcement, #44/#62); 402 with a fresh
                // challenge when the wallet rejected (`accepted != true`).
                // Terminal from the client's perspective either way. Return
                // the unsigned Response rather than re-signing (which
                // mangles bytes).
                return Ok(response);
            }
        }
    }

    // `/renew` is the second paid route (PROTOCOL.md §5). `fileSize` is NOT
    // in the request body — `routes::renew::prepare` reads it from field 4
    // of the old advertisement's PushDrop (bound to on-chain data, never
    // client claims; the-composer #45) in a single pre-payment listOutputs
    // round-trip. The prepared context is threaded into the handler so the
    // lookup never runs twice. Price uses the exact `/quote` formula, and
    // the 402/payment plumbing below mirrors `/upload`'s line for line.
    if method == Method::Post && path == "/renew" {
        let prepared = routes::renew::prepare(&request_body, &env).await;
        // `None` = free pass (malformed body / advert not found / lookup
        // failure) — the handler then emits the correct 400/404/500 without
        // the client having paid for it.
        let price = match prepared.price_inputs() {
            Some((fs, minutes)) => routes::quote::compute_price_from_env(fs, minutes, &env).await,
            None => 0,
        };
        // Short-circuit: if the client didn't provide `x-bsv-payment`, build
        // and sign the 402 inline (poc-server pattern). Skipping the payment
        // middleware here is intentional — wrapping its pre-built Response
        // forces a serde_json round-trip that produces body bytes ≠ what we
        // sign, which @bsv/sdk rejects via MetaNet Client's verifySignature
        // RPC. (Challenge prefixes are consumed at redemption, not issuance,
        // so bypassing the middleware for the 402 does not skip #44's
        // single-use enforcement.)
        if price > 0
            && req
                .headers()
                .get(payment_headers::PAYMENT)
                .ok()
                .flatten()
                .is_none()
        {
            return match session {
                Some(ref s) => build_signed_402(price, s, &server_key).await,
                None => {
                    // No session means AuthFetch wouldn't be able to verify
                    // either way — fall through to middleware's unsigned 402
                    // as a minimal error surface.
                    let payment_options = PaymentMiddlewareOptions::new(
                        server_key.clone(),
                        move |_: &Request| -> u64 { price },
                    );
                    match run_payment_middleware(&req, &env, &auth_context, &payment_options).await
                    {
                        Ok(PaymentResult::Required(r) | PaymentResult::Failed(r)) => Ok(r),
                        Ok(_) => {
                            Ok(Response::from_json(&json!({"status": "error"}))?.with_status(500))
                        }
                        // Typed 4xx/5xx JSON, not a plaintext 500 (#31).
                        Err(e) => middleware_error_response(&e, None),
                    }
                }
            };
        }
        // Annotate closure arg type explicitly so the HRTB on
        // `process_payment_with_storage::<F, S>`'s `F: Fn(&Request) -> u64`
        // bound is satisfied.
        let calc_price = move |_: &Request| -> u64 { price };
        // Payment must internalize against the SAME wallet server /advertise
        // draws funds from. Middleware default is storage.babbage.systems; override
        // with our WALLET_STORAGE_URL so /renew payments land where /advertise
        // can see them.
        let wallet_url = env
            .var("WALLET_STORAGE_URL")
            .ok()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "https://wallet-infra.x402agency.com".to_string());
        let payment_options =
            PaymentMiddlewareOptions::with_storage_url(server_key.clone(), calc_price, wallet_url);
        // Malformed/failed payment headers are typed 400s from the
        // middleware; sign them for the authenticated client (#31 — the TS
        // payment middleware's errors flow through auth's response signing).
        let payment_result =
            match run_payment_middleware(&req, &env, &auth_context, &payment_options).await {
                Ok(result) => result,
                Err(e) => return middleware_error_response(&e, session.as_ref()),
            };
        match payment_result {
            PaymentResult::Free | PaymentResult::Verified(_) => {
                if let PaymentResult::Verified(ref ctx) = payment_result {
                    console_error!(
                        "renew: payment verified, accepted={} sats_paid={}",
                        ctx.accepted,
                        ctx.satoshis_paid
                    );
                }
                let (body, status) =
                    routes::renew::handle(&request_body, identity_key, price, prepared, &env).await;
                return match session {
                    Some(ref s) => signed_json_or_internal_error(&body, status, &[], s),
                    None => unsigned_json_response(&body, status),
                };
            }
            PaymentResult::Required(response) | PaymentResult::Failed(response) => {
                // Required branch is handled above via build_signed_402 when the
                // client didn't send x-bsv-payment. Reaching here with Required
                // means the client DID send a payment header but the middleware
                // still returned Required — shouldn't happen in practice. Failed
                // covers the bad-payment paths: 400 for malformed payments,
                // failed verification, or a REPLAYED derivation prefix
                // (single-use enforcement, #44/#62); 402 with a fresh
                // challenge when the wallet rejected (`accepted != true`).
                // Terminal from the client's perspective either way. Return
                // the unsigned Response rather than re-signing (which
                // mangles bytes).
                return Ok(response);
            }
        }
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
    batch: MessageBatch<queue::R2EventMessage>,
    env: Env,
    _ctx: Context,
) -> Result<()> {
    init_panic_hook();
    queue::handle_batch(batch, &env).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

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
}
