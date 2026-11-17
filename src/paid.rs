//! The paid routes' payment door (`/upload`, `/renew`): BRC-29 payment
//! processing from the `X-BSV-Payment` header to the wallet storage
//! server's `internalizeAction`.
//!
//! The decision is the payment middleware's (bsv-middleware-cloudflare
//! 0.7.4, `process_payment_with_storage`), step for step and answer for
//! answer, over the middleware's own public parts: the derivation prefix's
//! HMAC (`verify_nonce`), the output check (`verify_payment_output`), the
//! subject's txid (`payment_subject_txid`) and the transaction-bound prefix
//! claim (`PaymentPrefixStore`). Two things are the storage's own:
//!
//! - **A ceiling on the header** ([`PAYMENT_HEADER_MAX`]), checked before
//!   anything is decoded: a larger header is answered as a payment the
//!   server cannot read (400 `ERR_INVALID_PAYMENT`, the quote kept: the
//!   prefix is not claimed).
//! - **The wallet call is written once** ([`internalize_call`]): the
//!   JSON-RPC body is serialized straight from the transaction's bytes into
//!   the BRC-104 payload the request is signed over, and the body sent is
//!   that payload's tail. The wire is the middleware's, byte for byte: `tx`
//!   is the array of byte values every wallet storage server reads (the TS
//!   reference's `validateInternalizeActionArgs` takes nothing else).
//!
//! From the header's arrival to the wallet call's send, a request holds at
//! most about the header's size in decoded bytes plus the serialized body
//! (about 3.6 bytes per transaction byte); `tests/heap` pins the whole path.

use std::borrow::Cow;
use std::future::Future;

use bsv_middleware_cloudflare::{
    add_cors_headers,
    client::JsonRpcResponse,
    core::{
        payment_subject_txid, verify_payment_output, PaymentFault, PaymentPrefixStore,
        PaymentVerdict, PrefixClaim,
    },
    middleware::payment::{payment_headers, PaymentResult},
    types::{ErrorResponse, PaymentContext},
    AuthCloudflareError, AuthContext, ClientSessionSnapshot, WorkerStorageClient,
};
use bsv_rs::auth::transports::HttpRequest;
use bsv_rs::auth::types::{AuthMessage, MessageType, AUTH_PROTOCOL_ID};
use bsv_rs::auth::utils::{create_nonce, verify_nonce};
use bsv_rs::primitives::hash::sha256;
use bsv_rs::primitives::{from_base64, to_base64, PrivateKey, PublicKey};
use bsv_rs::wallet::{Counterparty, CreateSignatureArgs, ProtoWallet, Protocol, SecurityLevel};
use serde::{Deserialize, Serialize};
use serde_json::Value;

type Result<T> = std::result::Result<T, AuthCloudflareError>;

/// The originator the middleware creates and verifies derivation prefixes
/// under; a prefix this door issues must verify the same way.
const ORIGINATOR: &str = "bsv-auth-cloudflare";

/// The payment transaction's output that pays the server (and is
/// internalized).
const PAYMENT_OUTPUT_INDEX: u32 = 0;

/// The largest `X-BSV-Payment` header the paid routes read: 96 KiB. Every
/// real wallet payment the estate's rows rebuild as a header that the
/// platform carries (its request headers are at most 128 KiB in all) is at
/// most 35,546 bytes, under 37% of this.
pub const PAYMENT_HEADER_MAX: usize = 96 * 1024;

/// The answer to a header over [`PAYMENT_HEADER_MAX`]: the middleware's
/// words for a payment transaction it cannot read.
pub const PAYMENT_TOO_LARGE: &str =
    "Payment not verified: payment transaction unreadable: the payment transaction is too large to read";

/// The `X-BSV-Payment` header: the middleware's `BsvPayment`, its strings
/// borrowed from the header where they carry no escape.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentHeader<'a> {
    #[serde(borrow)]
    pub derivation_prefix: Cow<'a, str>,
    #[serde(borrow)]
    pub derivation_suffix: Cow<'a, str>,
    #[serde(borrow)]
    pub transaction: Cow<'a, str>,
}

/// What the door reads of a header before anything is decoded.
#[derive(Debug)]
pub enum HeaderRead<'a> {
    /// Longer than [`PAYMENT_HEADER_MAX`].
    TooLarge,
    /// Not the payment JSON.
    Malformed,
    Read(PaymentHeader<'a>),
}

/// The header's size, then its JSON: nothing is decoded from a header over
/// [`PAYMENT_HEADER_MAX`].
pub fn read_header(header: &str) -> HeaderRead<'_> {
    if header.len() > PAYMENT_HEADER_MAX {
        return HeaderRead::TooLarge;
    }
    match serde_json::from_str(header) {
        Ok(read) => HeaderRead::Read(read),
        Err(_) => HeaderRead::Malformed,
    }
}

/// The payment the wallet storage server is asked to internalize.
#[derive(Debug)]
pub struct Remittance {
    pub derivation_prefix: String,
    pub derivation_suffix: String,
    /// The payment transaction (the header's `transaction`, decoded).
    pub tx: Vec<u8>,
}

/// The door's answer, before any `Response` is built (so that the whole
/// path runs under native `cargo test`). Each variant is the middleware's
/// `PaymentDecision` of the same name, rendered by [`into_result`] as the
/// middleware renders it.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Misconfigured,
    Free,
    Challenge {
        price: u64,
        derivation_prefix: String,
    },
    MalformedHeader,
    InvalidPrefix,
    ReplayedPrefix,
    PrefixUsedByAnotherTransaction,
    PrefixStoreUnavailable {
        detail: String,
    },
    WalletRejected {
        price: u64,
        fresh_prefix: String,
    },
    InternalizeError {
        description: String,
    },
    NotCovered {
        description: String,
    },
    InvalidPayment {
        description: String,
    },
    ServerFault {
        description: String,
    },
    HeaderServiceUnavailable {
        description: String,
    },
    Verified {
        satoshis_paid: u64,
    },
}

/// The middleware's reading of the output check's answer
/// (`judge_paying_output`).
fn judge(
    answer: std::result::Result<PaymentVerdict, PaymentFault>,
) -> std::result::Result<u64, Decision> {
    match answer {
        Ok(PaymentVerdict::Verified { satoshis }) => Ok(satoshis),
        Ok(verdict @ (PaymentVerdict::Underpaid { .. } | PaymentVerdict::WrongScript { .. })) => {
            Err(Decision::NotCovered {
                description: verdict.to_string(),
            })
        }
        Ok(verdict @ PaymentVerdict::NoHeaderService) => Err(Decision::ServerFault {
            description: verdict.to_string(),
        }),
        Ok(verdict @ PaymentVerdict::RootMismatch { .. }) => Err(Decision::InvalidPayment {
            description: verdict.to_string(),
        }),
        Ok(verdict @ PaymentVerdict::Unverifiable { .. })
            if verdict.is_server_side_unverifiable() =>
        {
            Err(Decision::HeaderServiceUnavailable {
                description: verdict.to_string(),
            })
        }
        Ok(verdict @ PaymentVerdict::Unverifiable { .. }) => Err(Decision::InvalidPayment {
            description: verdict.to_string(),
        }),
        Err(fault) => Err(Decision::ServerFault {
            description: fault.to_string(),
        }),
    }
}

/// Whether the wallet's `internalizeAction` answer affirmatively accepted
/// the payment: only a literal `"accepted": true` counts.
fn accepted(result: &Value) -> bool {
    result
        .get("accepted")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// The door's decision, in the middleware's order: auth → price → the
/// challenge → **the header's size** → its JSON → the prefix's HMAC → the
/// base64 → output 0 against the price → the subject's txid → the prefix
/// claim → `internalize` → the `accepted` gate (a wallet error releases the
/// prefix to the same transaction).
///
/// The header is owned and dropped once the transaction is decoded, so the
/// wallet call holds the decoded bytes and not the header too.
pub async fn decide<S, I, Fut>(
    auth_context: &AuthContext,
    price: u64,
    payment_header: Option<String>,
    server_private_key: &str,
    prefixes: &S,
    internalize: I,
) -> Result<Decision>
where
    S: PaymentPrefixStore + ?Sized,
    I: FnOnce(Remittance) -> Fut,
    Fut: Future<Output = Result<Value>>,
{
    if !auth_context.is_authenticated || auth_context.identity_key == "unknown" {
        return Ok(Decision::Misconfigured);
    }
    if price == 0 {
        return Ok(Decision::Free);
    }
    let private_key = PrivateKey::from_hex(server_private_key).map_err(|e| {
        AuthCloudflareError::ConfigError(format!("Invalid server private key: {}", e))
    })?;
    let wallet = ProtoWallet::new(Some(private_key));

    let Some(header) = payment_header else {
        let derivation_prefix = create_nonce(&wallet, None, ORIGINATOR).await?;
        return Ok(Decision::Challenge {
            price,
            derivation_prefix,
        });
    };

    let (derivation_prefix, derivation_suffix, tx) = {
        let payment = match read_header(&header) {
            HeaderRead::TooLarge => {
                return Ok(Decision::InvalidPayment {
                    description: PAYMENT_TOO_LARGE.to_string(),
                })
            }
            HeaderRead::Malformed => return Ok(Decision::MalformedHeader),
            HeaderRead::Read(payment) => payment,
        };
        let nonce_valid = verify_nonce(&payment.derivation_prefix, &wallet, None, ORIGINATOR)
            .await
            .unwrap_or_default();
        if !nonce_valid {
            return Ok(Decision::InvalidPrefix);
        }
        // Decoded before the prefix is claimed: a malformed payload does
        // not burn the client's prefix.
        let tx = from_base64(&payment.transaction).map_err(|_| {
            AuthCloudflareError::MalformedPayment("Invalid base64 transaction data".to_string())
        })?;
        (
            payment.derivation_prefix.into_owned(),
            payment.derivation_suffix.into_owned(),
            tx,
        )
    };
    drop(header);

    let satoshis_paid = match judge(verify_payment_output(
        server_private_key,
        &auth_context.identity_key,
        &derivation_prefix,
        &derivation_suffix,
        &tx,
        PAYMENT_OUTPUT_INDEX as usize,
        price,
    )) {
        Ok(satoshis) => satoshis,
        Err(refusal) => return Ok(refusal),
    };

    let txid = match payment_subject_txid(&tx) {
        Ok(txid) => txid,
        Err(reason) => {
            return Ok(Decision::InvalidPayment {
                description: reason.to_string(),
            })
        }
    };
    match prefixes
        .claim_prefix(&derivation_prefix, &txid, ORIGINATOR)
        .await
    {
        Err(e) => {
            return Ok(Decision::PrefixStoreUnavailable {
                detail: e.to_string(),
            })
        }
        Ok(PrefixClaim::Won) => {}
        Ok(PrefixClaim::SameTransaction | PrefixClaim::Unknown) => {
            return Ok(Decision::ReplayedPrefix)
        }
        Ok(PrefixClaim::OtherTransaction) => return Ok(Decision::PrefixUsedByAnotherTransaction),
    }

    let answer = internalize(Remittance {
        derivation_prefix: derivation_prefix.clone(),
        derivation_suffix,
        tx,
    })
    .await;
    match answer {
        Ok(result) if accepted(&result) => Ok(Decision::Verified { satoshis_paid }),
        Ok(_) => Ok(Decision::WalletRejected {
            price,
            fresh_prefix: create_nonce(&wallet, None, ORIGINATOR).await?,
        }),
        Err(e) => {
            if let Err(release) = prefixes.release_prefix(&derivation_prefix, &txid).await {
                warn_log(&format!("payment prefix release failed: {release}"));
            }
            Ok(Decision::InternalizeError {
                description: e.to_string(),
            })
        }
    }
}

fn warn_log(message: &str) {
    #[cfg(target_arch = "wasm32")]
    worker::console_warn!("{}", message);
    #[cfg(not(target_arch = "wasm32"))]
    let _ = message;
}

// ── the answers ─────────────────────────────────────────────────────────

/// The challenge's headers. The paid routes read the header transport
/// alone, so no transports header is named.
fn challenge_headers(price: u64, derivation_prefix: &str) -> worker::Headers {
    let h = worker::Headers::new();
    let _ = h.set(payment_headers::VERSION, "1.0");
    let _ = h.set(payment_headers::SATOSHIS_REQUIRED, &price.to_string());
    let _ = h.set(payment_headers::DERIVATION_PREFIX, derivation_prefix);
    h
}

fn failed(status: u16, code: &str, description: &str) -> Result<PaymentResult> {
    let response = worker::Response::from_json(&ErrorResponse::new(code, description))
        .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
        .with_status(status);
    Ok(PaymentResult::Failed(add_cors_headers(response)))
}

/// The response for each [`Decision`]: the middleware's bodies, statuses
/// and headers (`decision_into_result`), unsigned, with CORS.
pub fn into_result(decision: Decision) -> Result<PaymentResult> {
    match decision {
        Decision::Misconfigured => failed(
            500,
            "ERR_SERVER_MISCONFIGURED",
            "The payment middleware must be executed after the Auth middleware.",
        ),
        Decision::Free => Ok(PaymentResult::Free),
        Decision::Challenge {
            price,
            derivation_prefix,
        } => {
            let body = serde_json::json!({
                "status": "error",
                "code": "ERR_PAYMENT_REQUIRED",
                "satoshisRequired": price,
                "description": "A BSV payment is required to complete this request. Provide the X-BSV-Payment header."
            });
            let response = worker::Response::from_json(&body)
                .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
                .with_status(402)
                .with_headers(challenge_headers(price, &derivation_prefix));
            Ok(PaymentResult::Required(add_cors_headers(response)))
        }
        Decision::MalformedHeader => failed(
            400,
            "ERR_MALFORMED_PAYMENT",
            "The X-BSV-Payment header is not valid JSON.",
        ),
        Decision::InvalidPrefix => failed(
            400,
            "ERR_INVALID_DERIVATION_PREFIX",
            "The X-BSV-Payment-Derivation-Prefix header is not valid.",
        ),
        Decision::ReplayedPrefix => failed(
            400,
            "ERR_INVALID_DERIVATION_PREFIX",
            "The X-BSV-Payment-Derivation-Prefix header is not valid (already used).",
        ),
        Decision::PrefixUsedByAnotherTransaction => failed(
            400,
            "ERR_INVALID_DERIVATION_PREFIX",
            "The derivation prefix was already used by another transaction (BRC-105: each prefix pays once). Nothing was internalized; request a fresh challenge.",
        ),
        Decision::PrefixStoreUnavailable { detail } => {
            warn_log(&format!("payment prefix store unavailable: {detail}"));
            let body = serde_json::json!({
                "status": "error",
                "code": "ERR_PAYMENT_UNAVAILABLE",
                "description": "Payment processing is temporarily unavailable. Retry the same payment.",
                "retryable": true
            });
            let response = worker::Response::from_json(&body)?.with_status(503);
            response.headers().set("Retry-After", "5")?;
            Ok(PaymentResult::Failed(add_cors_headers(response)))
        }
        Decision::WalletRejected {
            price,
            fresh_prefix,
        } => {
            let response = worker::Response::from_json(&ErrorResponse::new(
                "ERR_PAYMENT_FAILED",
                "The BSV payment was not accepted by the wallet. A fresh payment challenge is provided in the response headers.",
            ))
            .map_err(|e| AuthCloudflareError::TransportError(e.to_string()))?
            .with_status(402)
            .with_headers(challenge_headers(price, &fresh_prefix));
            Ok(PaymentResult::Failed(add_cors_headers(response)))
        }
        Decision::InternalizeError { description } => {
            failed(400, "ERR_PAYMENT_FAILED", &description)
        }
        Decision::NotCovered { description } => failed(
            400,
            "ERR_INVALID_PAYMENT",
            &format!(
                "The BSV payment does not pay the required amount to the server ({description}). The payment challenge is unchanged: correct the payment and retry with the same derivation prefix."
            ),
        ),
        Decision::InvalidPayment { description } => {
            failed(400, "ERR_INVALID_PAYMENT", &description)
        }
        Decision::ServerFault { description } => {
            failed(500, "ERR_SERVER_MISCONFIGURED", &description)
        }
        Decision::HeaderServiceUnavailable { description } => failed(
            503,
            "ERR_HEADER_SERVICE_UNAVAILABLE",
            &format!(
                "{description}. The server could not check the payment's proof against a block header, so it was not accepted; nothing was charged and the challenge is unchanged. Retry the same payment later under the same derivation prefix."
            ),
        ),
        Decision::Verified { satoshis_paid } => Ok(PaymentResult::Verified(PaymentContext {
            satoshis_paid,
            accepted: true,
            tx: None,
        })),
    }
}

// ── the wallet call ─────────────────────────────────────────────────────

/// The `internalizeAction` JSON-RPC request, serialized from borrowed
/// parts: the JSON-RPC envelope, the `[auth, args]` params, and `tx` as the
/// array of the transaction's byte values.
#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'static str,
    method: &'static str,
    params: (RpcAuth<'a>, InternalizeArgs<'a>),
    id: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RpcAuth<'a> {
    identity_key: &'a str,
    user_id: Option<i64>,
}

#[derive(Serialize)]
struct InternalizeArgs<'a> {
    tx: &'a [u8],
    outputs: [InternalizeOutput<'a>; 1],
    description: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InternalizeOutput<'a> {
    output_index: u32,
    protocol: &'static str,
    payment_remittance: PaymentRemittance<'a>,
    insertion_remittance: Option<()>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PaymentRemittance<'a> {
    derivation_prefix: &'a str,
    derivation_suffix: &'a str,
    sender_identity_key: &'a str,
}

/// A byte count for a serialization pass that keeps nothing.
struct Count(usize);

impl std::io::Write for Count {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A Bitcoin varint (BRC-104's length prefix for a non-empty body).
fn push_varint(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

/// The BRC-104 `general` request the wallet call is signed over: request
/// ID (the first 32 bytes), `POST /`, the content type, and the JSON-RPC
/// body, which is the payload from `body_start` on.
pub struct WalletCall {
    pub payload: Vec<u8>,
    pub body_start: usize,
}

impl WalletCall {
    /// The HTTP body: the JSON-RPC request.
    pub fn body(&self) -> &[u8] {
        self.payload.get(self.body_start..).unwrap_or_default()
    }
}

/// The `internalizeAction` call for `remittance` from `sender_identity_key`,
/// as `HttpRequest::to_payload` writes it with the JSON-RPC body the
/// middleware sends (`JsonRpcRequest` over `[auth, internalize_args]`), byte
/// for byte. The body is serialized once into a buffer of its exact size
/// (a first pass counts it); the transaction is read in place.
pub fn internalize_call(
    id: u64,
    server_identity_key: &str,
    user_id: Option<i64>,
    remittance: &Remittance,
    sender_identity_key: &str,
) -> std::result::Result<WalletCall, serde_json::Error> {
    let request = RpcRequest {
        jsonrpc: "2.0",
        method: "internalizeAction",
        params: (
            RpcAuth {
                identity_key: server_identity_key,
                user_id,
            },
            InternalizeArgs {
                tx: &remittance.tx,
                outputs: [InternalizeOutput {
                    output_index: PAYMENT_OUTPUT_INDEX,
                    protocol: "wallet payment",
                    payment_remittance: PaymentRemittance {
                        derivation_prefix: &remittance.derivation_prefix,
                        derivation_suffix: &remittance.derivation_suffix,
                        sender_identity_key,
                    },
                    insertion_remittance: None,
                }],
                description: "Payment for request",
            },
        ),
        id,
    };
    let mut count = Count(0);
    serde_json::to_writer(&mut count, &request)?;
    let body_len = count.0;

    // Everything before the body, as `to_payload` writes it; an empty body
    // ends it with the 9-byte "absent" length, which the real one replaces.
    let mut head = HttpRequest {
        request_id: [0u8; 32],
        method: "POST".to_string(),
        path: "/".to_string(),
        search: String::new(),
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: Vec::new(),
    }
    .to_payload();
    head.truncate(head.len().saturating_sub(9));

    let mut payload = Vec::with_capacity(head.len() + 9 + body_len);
    payload.extend_from_slice(&head);
    push_varint(&mut payload, body_len as u64);
    let body_start = payload.len();
    serde_json::to_writer(&mut payload, &request)?;
    Ok(WalletCall {
        payload,
        body_start,
    })
}

/// The BRC-104 headers of one attempt of `call` over `session`: a fresh
/// request ID (written into the payload) and message nonce, and the
/// signature over the payload's SHA-256, as the middleware's storage client
/// signs (`send_rpc_once`).
fn sign_attempt(
    wallet: &ProtoWallet,
    session: &ClientSessionSnapshot,
    call: &mut WalletCall,
) -> Result<Vec<(String, String)>> {
    let mut request_id = [0u8; 32];
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut request_id)
        .and_then(|_| getrandom::getrandom(&mut nonce))
        .map_err(|e| AuthCloudflareError::SdkError(e.to_string()))?;
    if let Some(id) = call.payload.get_mut(..32) {
        id.copy_from_slice(&request_id);
    }

    let server_identity_key = PublicKey::from_hex(&session.server_identity_key)
        .map_err(|e| AuthCloudflareError::SdkError(e.to_string()))?;
    let mut message = AuthMessage::new(MessageType::General, wallet.identity_key());
    message.nonce = Some(to_base64(&nonce));
    let key_id = message.get_key_id(Some(&session.peer_nonce));
    let signature = wallet
        .create_signature(CreateSignatureArgs {
            data: None,
            hash_to_directly_sign: Some(sha256(&call.payload)),
            protocol_id: Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID),
            key_id,
            counterparty: Some(Counterparty::Other(server_identity_key)),
        })
        .map_err(|e| AuthCloudflareError::SdkError(e.to_string()))?
        .signature;

    Ok(vec![
        ("x-bsv-auth-version".to_string(), message.version.clone()),
        (
            "x-bsv-auth-identity-key".to_string(),
            message.identity_key.to_hex(),
        ),
        ("x-bsv-auth-message-type".to_string(), "general".to_string()),
        ("x-bsv-auth-request-id".to_string(), to_base64(&request_id)),
        ("content-type".to_string(), "application/json".to_string()),
        ("x-bsv-auth-nonce".to_string(), to_base64(&nonce)),
        (
            "x-bsv-auth-your-nonce".to_string(),
            session.peer_nonce.clone(),
        ),
        ("x-bsv-auth-signature".to_string(), hex::encode(signature)),
    ])
}

/// POST the body of `call` with `headers`; the HTTP status and body text.
async fn post(url: &str, headers: &[(String, String)], call: &WalletCall) -> Result<(u16, String)> {
    let worker_headers = worker::Headers::new();
    for (key, value) in headers {
        worker_headers
            .set(key, value)
            .map_err(|e| AuthCloudflareError::TransportError(format!("Header error: {}", e)))?;
    }
    let body = js_sys::Uint8Array::from(call.body());
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_headers(worker_headers)
        .with_body(Some(body.into()));
    let request = worker::Request::new_with_init(url, &init)
        .map_err(|e| AuthCloudflareError::TransportError(format!("Request error: {}", e)))?;
    let mut response = worker::Fetch::Request(request)
        .send()
        .await
        .map_err(|e| AuthCloudflareError::TransportError(format!("Fetch error: {}", e)))?;
    let status = response.status_code();
    let text = response.text().await.map_err(|e| {
        AuthCloudflareError::TransportError(format!("Failed to read RPC response: {}", e))
    })?;
    Ok((status, text))
}

/// The storage server's auth layer refused the request before its handler
/// ran (the middleware's storage client's test).
fn auth_layer_rejection(status: u16, body: &str) -> bool {
    status == 401
        || status == 403
        || (status == 500
            && (body.contains("Invalid authentication")
                || body.contains("Session not found")
                || body.contains("Mutual-authentication failed")))
}

/// The JSON-RPC result of a wallet call's response, or the middleware's
/// error for it.
fn rpc_result(status: u16, text: &str, id: u64) -> Result<Value> {
    if !(200..300).contains(&status) {
        return Err(AuthCloudflareError::TransportError(format!(
            "Storage server returned {}: {}",
            status, text
        )));
    }
    let response: JsonRpcResponse = serde_json::from_str(text).map_err(|e| {
        AuthCloudflareError::SerializationError(format!(
            "Failed to parse RPC response: {} - body: {}",
            e, text
        ))
    })?;
    if let Some(error) = response.error {
        return Err(AuthCloudflareError::TransportError(format!(
            "RPC error: {}",
            error
        )));
    }
    if response.id != id {
        return Err(AuthCloudflareError::TransportError(format!(
            "RPC response ID mismatch: expected {}, got {}",
            id, response.id
        )));
    }
    Ok(response.result.unwrap_or(Value::Null))
}

/// The JSON-RPC id of the wallet call: the storage client spent 1 and 2 on
/// `makeAvailable` and `findOrInsertUser`.
const INTERNALIZE_RPC_ID: u64 = 3;

/// A session with the wallet storage server at `storage_url`, as the
/// middleware opens one for each payment: the handshake (`makeAvailable`),
/// then the server's user (`findOrInsertUser`).
async fn open_session(
    wallet: &ProtoWallet,
    storage_url: &str,
    server_identity_key: &str,
) -> Result<(ClientSessionSnapshot, Option<i64>)> {
    let mut client = WorkerStorageClient::new(wallet.clone(), storage_url);
    client.make_available().await?;
    let user = client.find_or_insert_user(server_identity_key).await?;
    let session = client.export_session().ok_or_else(|| {
        AuthCloudflareError::InvalidAuthentication("no session established".into())
    })?;
    Ok((session, user.get("userId").and_then(Value::as_i64)))
}

/// `internalizeAction` for `remittance` at the wallet storage server
/// `storage_url`, signed with `server_private_key`, as the middleware calls
/// it: one session, one signed attempt, and one more on a fresh session if
/// the server's auth layer refused the first. The call is written once
/// ([`internalize_call`]) and the transaction's bytes are let go before it
/// is sent.
pub async fn internalize(
    storage_url: &str,
    server_private_key: &str,
    sender_identity_key: &str,
    remittance: Remittance,
) -> Result<Value> {
    let wallet = ProtoWallet::new(Some(PrivateKey::from_hex(server_private_key).map_err(
        |e| AuthCloudflareError::ConfigError(format!("Invalid server private key: {}", e)),
    )?));
    let server_identity_key = wallet.identity_key().to_hex();
    let url = format!("{}/", storage_url);

    let (mut session, user_id) = open_session(&wallet, storage_url, &server_identity_key).await?;
    let mut call = internalize_call(
        INTERNALIZE_RPC_ID,
        &server_identity_key,
        user_id,
        &remittance,
        sender_identity_key,
    )?;
    drop(remittance);

    let headers = sign_attempt(&wallet, &session, &mut call)?;
    let (mut status, mut text) = post(&url, &headers, &call).await?;
    if auth_layer_rejection(status, &text) {
        session = open_session(&wallet, storage_url, &server_identity_key)
            .await?
            .0;
        let headers = sign_attempt(&wallet, &session, &mut call)?;
        (status, text) = post(&url, &headers, &call).await?;
    }
    rpc_result(status, &text, INTERNALIZE_RPC_ID)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use bsv_middleware_cloudflare::client::JsonRpcRequest;
    use bsv_middleware_cloudflare::core::{expected_locking_script, MemoryStore};
    use std::cell::Cell;

    const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const PAYER: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const SUFFIX: &str = "c3VmZml4LXN1ZmZpeA==";
    const PRICE: u64 = 1000;

    fn wallet() -> ProtoWallet {
        ProtoWallet::new(Some(PrivateKey::from_hex(SERVER_KEY).unwrap()))
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        let mut f = std::pin::pin!(f);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        match f.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(out) => out,
            std::task::Poll::Pending => panic!("the door awaited something that is not ready"),
        }
    }

    fn prefix() -> String {
        block_on(create_nonce(&wallet(), None, ORIGINATOR)).unwrap()
    }

    /// A one-transaction BEEF whose output 0 pays `sats` to the server under
    /// `prefix` (one input; the door reads the subject alone).
    fn payment(prefix: &str, sats: u64, seed: u8) -> Vec<u8> {
        let script =
            hex::decode(expected_locking_script(SERVER_KEY, PAYER, prefix, SUFFIX).unwrap())
                .unwrap();
        let mut tx = 1u32.to_le_bytes().to_vec();
        tx.push(1);
        tx.extend_from_slice(&[seed; 32]);
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx.push(0);
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        tx.push(1);
        tx.extend_from_slice(&sats.to_le_bytes());
        tx.push(script.len() as u8);
        tx.extend_from_slice(&script);
        tx.extend_from_slice(&0u32.to_le_bytes());
        let mut beef = bsv_rs::transaction::Beef::new();
        let id = beef.merge_raw_tx(tx, None).txid();
        beef.to_binary_atomic(&id).unwrap()
    }

    fn header(prefix: &str, tx: &[u8]) -> String {
        serde_json::json!({
            "derivationPrefix": prefix,
            "derivationSuffix": SUFFIX,
            "transaction": to_base64(tx),
        })
        .to_string()
    }

    fn auth() -> AuthContext {
        AuthContext::authenticated(PAYER.to_string())
    }

    /// The door over `store`, with a wallet that answers `answer` and counts
    /// its calls.
    fn door(
        header: Option<String>,
        store: &MemoryStore,
        calls: &Cell<usize>,
        answer: Result<Value>,
    ) -> Decision {
        block_on(decide(&auth(), PRICE, header, SERVER_KEY, store, |r| {
            calls.set(calls.get() + 1);
            assert_eq!(r.derivation_suffix, SUFFIX);
            async move { answer }
        }))
        .unwrap()
    }

    #[test]
    fn a_header_over_the_ceiling_is_refused_before_it_is_read_and_the_quote_stands() {
        let store = MemoryStore::new();
        let calls = Cell::new(0);
        let p = prefix();
        // Not even JSON: refused for its size alone.
        let big = "x".repeat(PAYMENT_HEADER_MAX + 1);
        assert_eq!(
            door(Some(big), &store, &calls, Ok(serde_json::json!({}))),
            Decision::InvalidPayment {
                description: PAYMENT_TOO_LARGE.to_string()
            }
        );
        // A real payment padded past the ceiling: refused, nothing claimed,
        // nothing internalized; the same prefix then pays.
        let tx = payment(&p, PRICE, 1);
        let mut padded: serde_json::Value = serde_json::from_str(&header(&p, &tx)).unwrap();
        padded["memo"] = serde_json::json!("y".repeat(PAYMENT_HEADER_MAX));
        assert!(matches!(
            door(
                Some(padded.to_string()),
                &store,
                &calls,
                Ok(serde_json::json!({}))
            ),
            Decision::InvalidPayment { .. }
        ));
        assert_eq!((calls.get(), store.len()), (0, 0));
        assert_eq!(
            door(
                Some(header(&p, &tx)),
                &store,
                &calls,
                Ok(serde_json::json!({"accepted": true}))
            ),
            Decision::Verified {
                satoshis_paid: PRICE
            }
        );
        assert_eq!(calls.get(), 1);
        // At the ceiling exactly, the header is read.
        let at = "x".repeat(PAYMENT_HEADER_MAX);
        assert_eq!(
            door(Some(at), &store, &calls, Ok(serde_json::json!({}))),
            Decision::MalformedHeader
        );
    }

    #[test]
    fn the_door_answers_as_the_middleware_does() {
        let store = MemoryStore::new();
        let calls = Cell::new(0);
        let accept = || Ok(serde_json::json!({"accepted": true}));
        // No header: a challenge whose prefix verifies.
        let Decision::Challenge {
            price,
            derivation_prefix,
        } = door(None, &store, &calls, accept())
        else {
            panic!("no challenge");
        };
        assert_eq!(price, PRICE);
        assert!(block_on(verify_nonce(
            &derivation_prefix,
            &wallet(),
            None,
            ORIGINATOR
        ))
        .unwrap());
        // Not JSON; a prefix this server did not issue; a payment short of the price.
        assert_eq!(
            door(Some("{".into()), &store, &calls, accept()),
            Decision::MalformedHeader
        );
        let p = prefix();
        assert_eq!(
            door(
                Some(header("bm90IGEgbm9uY2U=", &payment(&p, PRICE, 1))),
                &store,
                &calls,
                accept()
            ),
            Decision::InvalidPrefix
        );
        assert!(matches!(
            door(
                Some(header(&p, &payment(&p, PRICE - 1, 1))),
                &store,
                &calls,
                accept()
            ),
            Decision::NotCovered { .. }
        ));
        // Bad base64 is the middleware's typed error.
        let bad = format!(
            r#"{{"derivationPrefix":"{p}","derivationSuffix":"{SUFFIX}","transaction":"%%%"}}"#
        );
        assert!(matches!(
            block_on(decide(
                &auth(),
                PRICE,
                Some(bad),
                SERVER_KEY,
                &store,
                |_| async { Ok(Value::Null) }
            )),
            Err(AuthCloudflareError::MalformedPayment(_))
        ));
        assert_eq!(calls.get(), 0);
        // Paid once; the same header again, and another transaction under
        // the prefix, are refused without a wallet call.
        let tx = payment(&p, PRICE, 1);
        assert_eq!(
            door(Some(header(&p, &tx)), &store, &calls, accept()),
            Decision::Verified {
                satoshis_paid: PRICE
            }
        );
        assert_eq!(
            door(Some(header(&p, &tx)), &store, &calls, accept()),
            Decision::ReplayedPrefix
        );
        assert_eq!(
            door(
                Some(header(&p, &payment(&p, PRICE, 2))),
                &store,
                &calls,
                accept()
            ),
            Decision::PrefixUsedByAnotherTransaction
        );
        assert_eq!(calls.get(), 1);
        // A wallet rejection keeps the prefix and gives a fresh challenge.
        let q = prefix();
        let Decision::WalletRejected { fresh_prefix, .. } = door(
            Some(header(&q, &payment(&q, PRICE, 3))),
            &store,
            &calls,
            Ok(serde_json::json!({"accepted": false})),
        ) else {
            panic!("not a rejection");
        };
        assert_ne!(fresh_prefix, q);
        // A wallet error releases the prefix to the same transaction only.
        let r = prefix();
        let tx = payment(&r, PRICE, 4);
        assert!(matches!(
            door(
                Some(header(&r, &tx)),
                &store,
                &calls,
                Err(AuthCloudflareError::TransportError("down".into()))
            ),
            Decision::InternalizeError { .. }
        ));
        assert_eq!(
            door(
                Some(header(&r, &payment(&r, PRICE, 5))),
                &store,
                &calls,
                accept()
            ),
            Decision::PrefixUsedByAnotherTransaction
        );
        assert_eq!(
            door(Some(header(&r, &tx)), &store, &calls, accept()),
            Decision::Verified {
                satoshis_paid: PRICE
            }
        );
        // A store fault serves nothing and calls no wallet.
        let before = calls.get();
        store.fail(true);
        let s = prefix();
        assert!(matches!(
            door(
                Some(header(&s, &payment(&s, PRICE, 6))),
                &store,
                &calls,
                accept()
            ),
            Decision::PrefixStoreUnavailable { .. }
        ));
        assert_eq!(calls.get(), before);
        // Price 0 is free; an unauthenticated context is the server's fault.
        assert_eq!(
            block_on(decide(&auth(), 0, None, SERVER_KEY, &store, |_| async {
                Ok(Value::Null)
            }))
            .unwrap(),
            Decision::Free
        );
        assert_eq!(
            block_on(decide(
                &AuthContext::unauthenticated(),
                PRICE,
                None,
                SERVER_KEY,
                &store,
                |_| async { Ok(Value::Null) }
            ))
            .unwrap(),
            Decision::Misconfigured
        );
    }

    /// The middleware's `internalize_args` (0.7.4), for the wire comparison.
    fn middleware_args(tx: &[u8], prefix: &str, suffix: &str, sender: &str) -> Value {
        serde_json::json!({
            "tx": tx,
            "outputs": [{
                "outputIndex": 0,
                "protocol": "wallet payment",
                "paymentRemittance": {
                    "derivationPrefix": prefix,
                    "derivationSuffix": suffix,
                    "senderIdentityKey": sender
                },
                "insertionRemittance": null
            }],
            "description": "Payment for request"
        })
    }

    #[test]
    fn the_wallet_call_is_the_middleware_s_request_byte_for_byte() {
        let server = wallet().identity_key().to_hex();
        for (tx, user_id) in [
            (payment(&prefix(), PRICE, 7), Some(42)),
            ((0..=255u8).cycle().take(70_000).collect::<Vec<u8>>(), None),
        ] {
            let remittance = Remittance {
                derivation_prefix: "p\"re/fix\u{e9}".into(),
                derivation_suffix: SUFFIX.into(),
                tx: tx.clone(),
            };
            let call = internalize_call(3, &server, user_id, &remittance, PAYER).unwrap();
            let body = serde_json::to_vec(&JsonRpcRequest::new(
                3,
                "internalizeAction",
                vec![
                    serde_json::json!({"identityKey": server, "userId": user_id}),
                    middleware_args(&tx, &remittance.derivation_prefix, SUFFIX, PAYER),
                ],
            ))
            .unwrap();
            assert_eq!(call.body(), body.as_slice());
            let mut request_id = [0u8; 32];
            request_id[0] = 9;
            let mut call = call;
            call.payload[..32].copy_from_slice(&request_id);
            let payload = HttpRequest {
                request_id,
                method: "POST".to_string(),
                path: "/".to_string(),
                search: String::new(),
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body,
            }
            .to_payload();
            assert_eq!(call.payload, payload);
            // One buffer of the payload's size (the length's varint reserved at its widest).
            assert!(call.payload.capacity() <= call.payload.len() + 8);
        }
    }

    #[test]
    fn the_wallet_call_is_signed_as_the_storage_client_signs() {
        let w = wallet();
        let server_side = PrivateKey::from_hex(&"22".repeat(32)).unwrap();
        let session = ClientSessionSnapshot {
            v: 1,
            our_nonce: "b3Vy".into(),
            peer_nonce: "cGVlcg==".into(),
            server_identity_key: server_side.public_key().to_hex(),
        };
        let remittance = Remittance {
            derivation_prefix: prefix(),
            derivation_suffix: SUFFIX.into(),
            tx: payment(&prefix(), PRICE, 8),
        };
        let mut call =
            internalize_call(3, &w.identity_key().to_hex(), Some(1), &remittance, PAYER).unwrap();
        let headers = sign_attempt(&w, &session, &mut call).unwrap();
        let get = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        assert_eq!(
            from_base64(&get("x-bsv-auth-request-id")).unwrap(),
            call.payload[..32]
        );
        assert_eq!(get("x-bsv-auth-your-nonce"), session.peer_nonce);
        assert_eq!(get("x-bsv-auth-message-type"), "general");
        // The server verifies the signature over the payload as a general
        // message from this identity.
        let server_wallet = ProtoWallet::new(Some(server_side));
        let mut message = AuthMessage::new(MessageType::General, w.identity_key());
        message.nonce = Some(get("x-bsv-auth-nonce"));
        message.payload = Some(call.payload.clone());
        let verified = server_wallet
            .verify_signature(bsv_rs::wallet::VerifySignatureArgs {
                data: Some(message.signing_data()),
                hash_to_directly_verify: None,
                signature: hex::decode(get("x-bsv-auth-signature")).unwrap(),
                protocol_id: Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID),
                key_id: message.get_key_id(Some(&session.peer_nonce)),
                counterparty: Some(Counterparty::Other(w.identity_key())),
                for_self: None,
            })
            .unwrap();
        assert!(verified.valid);
    }

    #[test]
    fn a_wallet_answer_is_read_as_the_middleware_reads_it() {
        assert_eq!(
            rpc_result(
                200,
                r#"{"jsonrpc":"2.0","result":{"accepted":true},"id":3}"#,
                3
            )
            .unwrap(),
            serde_json::json!({"accepted": true})
        );
        assert!(rpc_result(200, r#"{"jsonrpc":"2.0","result":{},"id":4}"#, 3).is_err());
        assert!(rpc_result(
            200,
            r#"{"jsonrpc":"2.0","error":{"message":"no"},"id":3}"#,
            3
        )
        .is_err());
        assert!(rpc_result(502, "bad gateway", 3).is_err());
        assert!(auth_layer_rejection(401, ""));
        assert!(auth_layer_rejection(500, "Session not found"));
        assert!(!auth_layer_rejection(500, "boom"));
        assert!(accepted(&serde_json::json!({"accepted": true})));
        assert!(!accepted(&serde_json::json!({"accepted": "true"})));
    }
}
