//! bsv-storage-cloudflare — UHRP file-storage server on Cloudflare Workers.
//!
//! Protocol-compatible port of `@bsv/uhrp-storage-server` (nanostore.babbage.systems).
//! See `PROTOCOL.md` for the wire spec the Rust port must match byte-for-byte.

use bsv_middleware_cloudflare::{
    add_cors_headers, init_panic_hook,
    middleware::{
        auth::{handle_cors_preflight, AuthSession},
        payment::payment_headers,
        process_auth, process_payment, sign_json_response, AuthMiddlewareOptions, AuthResult,
        PaymentMiddlewareOptions, PaymentResult,
    },
};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::ProtoWallet;
use serde_json::json;
use worker::*;

/// Must match `bsv-middleware-cloudflare::middleware::payment::ORIGINATOR`. Any
/// drift here makes the server issue a derivation_prefix that `verify_nonce`
/// later rejects.
const PAYMENT_ORIGINATOR: &str = "bsv-auth-cloudflare";

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
/// **Why not use `process_payment` + wrap the pre-built Response:**
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

    sign_json_response(&body, 402, &payment_hdrs, session).map_err(|e| Error::from(e.to_string()))
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
        session_ttl_seconds: 3600,
        ..Default::default()
    };

    let auth_result = process_auth(req, &env, &auth_options)
        .await
        .map_err(|e| Error::from(e.to_string()))?;

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
        // and sign the 402 inline (poc-server pattern). Skipping process_payment
        // here is intentional — wrapping its pre-built Response forces a
        // serde_json round-trip that produces body bytes ≠ what we sign, which
        // @bsv/sdk rejects via MetaNet Client's verifySignature RPC.
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
                    match process_payment(&req, &auth_context, &payment_options)
                        .await
                        .map_err(|e| Error::from(e.to_string()))?
                    {
                        PaymentResult::Required(r) | PaymentResult::Failed(r) => Ok(r),
                        _ => Ok(Response::from_json(&json!({"status": "error"}))?.with_status(500)),
                    }
                }
            };
        }
        // Annotate closure arg type explicitly so the HRTB on
        // `process_payment::<F>`'s `F: Fn(&Request) -> u64` bound is satisfied.
        let calc_price = move |_: &Request| -> u64 { price };
        // Payment must internalize against the SAME wallet server /advertise
        // draws funds from. Middleware default is storage.babbage.systems; override
        // with our WALLET_STORAGE_URL so /upload payments land where /advertise
        // can see them.
        let wallet_url = env
            .var("WALLET_STORAGE_URL")
            .ok()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "https://wallet-infra.invalid".to_string());
        let payment_options =
            PaymentMiddlewareOptions::with_storage_url(server_key.clone(), calc_price, wallet_url);
        let payment_result = process_payment(&req, &auth_context, &payment_options)
            .await
            .map_err(|e| Error::from(e.to_string()))?;
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
                    Some(ref s) => sign_json_response(&body, status, &[], s)
                        .map_err(|e| Error::from(e.to_string())),
                    None => {
                        let resp = Response::from_json(&body)?.with_status(status);
                        Ok(add_cors_headers(resp))
                    }
                };
            }
            PaymentResult::Required(response) | PaymentResult::Failed(response) => {
                // Required branch is handled above via build_signed_402 when the
                // client didn't send x-bsv-payment. Reaching here with Required
                // means the client DID send a payment header but the middleware
                // still returned Required — shouldn't happen in practice. Failed
                // is the bad-payment-verification path; its 400 body is terminal
                // from the client's perspective either way. Return the unsigned
                // Response rather than re-signing (which mangles bytes).
                return Ok(response);
            }
        }
    }

    // `/renew` is the second paid route (PROTOCOL.md §5). `fileSize` is NOT
    // in the request body — `routes::renew::prepare` reads it from field 4
    // of the old advertisement's PushDrop (bound to on-chain data, never
    // client claims) in a single pre-payment listOutputs round-trip. The
    // prepared context is threaded into the handler so the lookup never
    // runs twice. Price uses the exact `/quote` formula, and the
    // 402/payment plumbing below mirrors `/upload`'s line for line.
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
        // and sign the 402 inline (poc-server pattern). Skipping process_payment
        // here is intentional — wrapping its pre-built Response forces a
        // serde_json round-trip that produces body bytes ≠ what we sign, which
        // @bsv/sdk rejects via MetaNet Client's verifySignature RPC.
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
                    match process_payment(&req, &auth_context, &payment_options)
                        .await
                        .map_err(|e| Error::from(e.to_string()))?
                    {
                        PaymentResult::Required(r) | PaymentResult::Failed(r) => Ok(r),
                        _ => Ok(Response::from_json(&json!({"status": "error"}))?.with_status(500)),
                    }
                }
            };
        }
        // Annotate closure arg type explicitly so the HRTB on
        // `process_payment::<F>`'s `F: Fn(&Request) -> u64` bound is satisfied.
        let calc_price = move |_: &Request| -> u64 { price };
        // Payment must internalize against the SAME wallet server /advertise
        // draws funds from. Middleware default is storage.babbage.systems; override
        // with our WALLET_STORAGE_URL so /renew payments land where /advertise
        // can see them.
        let wallet_url = env
            .var("WALLET_STORAGE_URL")
            .ok()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "https://wallet-infra.invalid".to_string());
        let payment_options =
            PaymentMiddlewareOptions::with_storage_url(server_key.clone(), calc_price, wallet_url);
        let payment_result = process_payment(&req, &auth_context, &payment_options)
            .await
            .map_err(|e| Error::from(e.to_string()))?;
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
                    Some(ref s) => sign_json_response(&body, status, &[], s)
                        .map_err(|e| Error::from(e.to_string())),
                    None => {
                        let resp = Response::from_json(&body)?.with_status(status);
                        Ok(add_cors_headers(resp))
                    }
                };
            }
            PaymentResult::Required(response) | PaymentResult::Failed(response) => {
                // Required branch is handled above via build_signed_402 when the
                // client didn't send x-bsv-payment. Reaching here with Required
                // means the client DID send a payment header but the middleware
                // still returned Required — shouldn't happen in practice. Failed
                // is the bad-payment-verification path; its 400 body is terminal
                // from the client's perspective either way. Return the unsigned
                // Response rather than re-signing (which mangles bytes).
                return Ok(response);
            }
        }
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
        Some(ref s) => {
            sign_json_response(&body, status, &[], s).map_err(|e| Error::from(e.to_string()))
        }
        None => {
            let resp = Response::from_json(&body)?.with_status(status);
            Ok(add_cors_headers(resp))
        }
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
