//! Overlay SHIP broadcaster — UHRP advert submission.
//!
//! Thin wrapper over the overlay's submit wire, reusing the `TaggedBEEF` +
//! `Steak` wire types of `bsv_rs::overlay::types` (the types the overlay's
//! engine re-exports) so this crate carries no duplicates of either.
//!
//! # Why not just `WorkerBroadcaster::broadcast_to_host` verbatim?
//!
//! `overlay_cloudflare::broadcaster::WorkerBroadcaster` POSTs the BEEF,
//! inspects only the HTTP status code, and returns `Ok(())` on 2xx. That is
//! correct for the SHIP *peer fan-out* case the Engine uses it for — a 2xx
//! from a peer means "accepted, your problem if you admit nothing".
//!
//! Our `/advertise` and `/renew` routes use the submit as a *primary*
//! admission signal: if `tm_uhrp` returns an empty `outputsToAdmit`, the
//! advertisement was silently dropped and the client must learn about it.
//! `rust-overlay`'s own `/submit` handler returns HTTP 200 with an empty
//! Steak in that exact case and only logs a WARNING
//! (`rust-overlay/crates/overlay-cloudflare/src/routes.rs:309–314`). Losing
//! that check would be silent data loss — the exact failure mode the task
//! brief flags as non-negotiable.
//!
//! So we POST the same way WorkerBroadcaster does (content-type +
//! `X-Topics` header + Uint8Array body), but also parse the Steak body and
//! treat an empty admission for our primary topic as a rejection. The
//! wire-level shape of the request is identical to `WorkerBroadcaster` —
//! same bytes on the wire, same `/submit` path suffix, same header names.

#![allow(dead_code)] // Some helpers are consumed only by /advertise or /renew.

use bsv_rs::overlay::types::{Steak, TaggedBEEF};
use worker::{Fetch, Headers, Method, Request, RequestInit};

use crate::error::ERR_OVERLAY_BROADCAST;
use crate::renewal::{reason, Admission};

/// Topic name for UHRP advertisements. Matches TS
/// `new SHIPBroadcaster(['tm_uhrp'], ...)` in `advertise.ts:85`, `renew.ts:205`.
pub const TM_UHRP_TOPIC: &str = "tm_uhrp";

/// Env var name for the overlay submit host. Host-only (no `/submit` suffix)
/// — the broadcaster appends `/submit` itself, matching `WorkerBroadcaster`.
pub const OVERLAY_SUBMIT_URL_VAR: &str = "OVERLAY_SUBMIT_URL";

/// Production default. Host only; the trailing `/submit` is added by
/// [`submit_uhrp_advert`]. Points at the user's deployed rust-overlay so
/// the port is self-hosted end-to-end by default.
pub const DEFAULT_OVERLAY_URL: &str = "https://your-worker.your-account.workers.dev";

/// Classification of overlay-submit failures, mapped 1-to-1 onto project
/// error codes at the route boundary.
#[derive(Debug)]
pub enum SubmitError {
    /// Overlay fetch / network problem (DNS, TCP, TLS).
    Transport(String),
    /// HTTP non-2xx from the overlay.
    HttpStatus { status: u16, body: String },
    /// The overlay accepted the tx (HTTP 2xx) but `outputsToAdmit` for
    /// `tm_uhrp` was empty. Semantically a rejection — the topic manager
    /// refused to admit our advertisement.
    NoOutputsAdmitted(String),
    /// Local serialization failure (unreachable in practice — typed inputs
    /// are all JSON-serializable by construction).
    Serialize(String),
}

impl SubmitError {
    /// Map to the project-wide error code constant.
    #[must_use]
    pub fn code(&self) -> &'static str {
        ERR_OVERLAY_BROADCAST
    }

    /// Short, user-safe description. Strip raw transport strings from
    /// anything that lands in an HTTP response body.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::Transport(_) | Self::Serialize(_) => "overlay broadcaster is unavailable",
            Self::HttpStatus { .. } => "overlay broadcaster rejected the transaction",
            Self::NoOutputsAdmitted(_) => "overlay broadcaster admitted no outputs for tm_uhrp",
        }
    }
}

/// Resolve the overlay submit host from env, or fall back to
/// [`DEFAULT_OVERLAY_URL`]. Extracted for testability.
#[must_use]
pub fn overlay_url_from_env(env: &worker::Env) -> String {
    env.var(OVERLAY_SUBMIT_URL_VAR)
        .ok()
        .map(|v| v.to_string())
        .unwrap_or_else(|| DEFAULT_OVERLAY_URL.to_string())
}

/// Submit a `tm_uhrp` advertisement to the overlay. Accepts a raw signed
/// transaction (BEEF or raw tx bytes — whatever our signer produces, the
/// overlay's `/submit` resolves missing inputs itself) and returns `Ok(())`
/// only if the topic manager admitted at least one output.
///
/// `overlay_host` is the host-only URL (e.g.
/// `https://your-worker.your-account.workers.dev`); `/submit` is appended by
/// this function, matching [`overlay_cloudflare::broadcaster::WorkerBroadcaster`].
///
/// After the primary submission succeeds, also fans out the same BEEF to any
/// mainnet peers discovered via SLAP-tracker `ls_ship` queries (matching the
/// TS `new SHIPBroadcaster(['tm_uhrp']).broadcast(tx)` behavior). Fan-out is
/// best-effort — every peer failure is logged but does NOT fail the overall
/// submit, because the primary admission signal has already been obtained.
pub async fn submit_uhrp_advert(
    env: &worker::Env,
    overlay_host: &str,
    raw_tx: &[u8],
) -> Result<(), SubmitError> {
    // `TaggedBEEF::new` leaves `off_chain_values = None`, which is the
    // right default for UHRP adverts — the advertisement itself has no
    // off-chain payload, only the on-chain PushDrop fields.
    let tagged = TaggedBEEF::new(raw_tx.to_vec(), vec![TM_UHRP_TOPIC.to_string()]);
    submit_tagged(env, overlay_host, &tagged).await?;

    // Mainnet propagation fan-out. Runs only after primary submission
    // succeeds. Errors are swallowed per-peer — we already have primary
    // admission. See `fan_out_to_mainnet_peers` doc for the full mechanism.
    fan_out_to_mainnet_peers(overlay_host, &tagged).await;

    Ok(())
}

/// The longest the paid `/renew` and the pass wait for the overlay's answer
/// to one submit, in milliseconds. Past it the submit is a fault.
pub const ADMISSION_DEADLINE_MS: u64 = 10_000;

/// The output of a renewing transaction that carries the renewed advert:
/// `/renew`'s `createAction` names one output, the advert, with
/// `randomizeOutputs: false`, and the wallet storage server keeps the
/// caller's outputs at their index and puts change after them
/// (wallet-infra v0.7.8 `src/storage/create_action.rs:386`, `:514-517`).
pub const RENEWED_ADVERT_VOUT: u32 = 0;

/// The statuses the overlay answers a refusal of a submit with, in its
/// error shape: 400 (the reference's `/submit`, ts-stack
/// `packages/overlays/overlay-express/src/OverlayExpress.ts:3040-3045`, at
/// 57c5f13055b555b83c1ef368fff3650abd21b6ef) and 422 (a transaction the
/// network refused, as this deployment's overlay answers it).
pub const REFUSAL_STATUSES: [u16; 2] = [400, 422];

/// The overlay's answer to one submit, as it came.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitAnswer {
    /// Nothing within the deadline.
    Deadline,
    /// No answer was read (a transport failure).
    NoAnswer(String),
    /// An HTTP answer: its status and body.
    Http { status: u16, body: String },
}

/// Submit a renewed `tm_uhrp` advertisement to the overlay and read its
/// answer ([`read_admission`]) for the advert's output
/// [`RENEWED_ADVERT_VOUT`]. After an admission the mainnet fan-out runs as
/// [`submit_uhrp_advert`]'s does, under the same deadline, and its outcome
/// is only logged.
pub async fn admit_uhrp_advert(
    env: &worker::Env,
    overlay_host: &str,
    beef: &[u8],
    deadline_ms: u64,
) -> Admission {
    let tagged = TaggedBEEF::new(beef.to_vec(), vec![TM_UHRP_TOPIC.to_string()]);
    let answer = match within(submit_answer(env, overlay_host, &tagged), deadline_ms).await {
        None => SubmitAnswer::Deadline,
        Some(Ok((status, body))) => SubmitAnswer::Http { status, body },
        Some(Err(SubmitError::Transport(why) | SubmitError::Serialize(why))) => {
            SubmitAnswer::NoAnswer(why)
        }
        Some(Err(e)) => SubmitAnswer::NoAnswer(format!("{e:?}")),
    };
    let admission = read_admission(&answer, TM_UHRP_TOPIC, RENEWED_ADVERT_VOUT);
    if admission == Admission::Admitted
        && within(fan_out_to_mainnet_peers(overlay_host, &tagged), deadline_ms)
            .await
            .is_none()
    {
        worker::console_log!("overlay fan-out: not finished within the deadline");
    }
    admission
}

/// Read the overlay's answer to the submit of an advert whose output is
/// `vout`, for `topic`:
///
/// - **admitted**: a 2xx whose body is the overlay's admission (a STEAK)
///   naming `vout` among the topic's `outputsToAdmit`;
/// - **refused**: a status in [`REFUSAL_STATUSES`] whose body is the
///   overlay's error shape, `{"status": "error", "message": …}` (or
///   `description`), not marked `retryable`; the reason is its message;
/// - **a fault**, every other answer: none, the deadline, a 5xx, a 408 or
///   429, any other 4xx or a refusal status without the error shape, a 2xx
///   that is not an admission, and an admission that does not name `vout`
///   (the reference's engine answers the same empty admission for a
///   transaction it admitted nothing of, one it already holds, and a topic
///   whose check failed: ts-stack `packages/overlays/overlay/src/Engine.ts:349-354`).
///
/// A fault's text names its kind first.
#[must_use]
pub fn read_admission(answer: &SubmitAnswer, topic: &str, vout: u32) -> Admission {
    let (status, body) = match answer {
        SubmitAnswer::Deadline => {
            return Admission::Fault("no answer within the deadline".to_string())
        }
        SubmitAnswer::NoAnswer(why) => {
            return Admission::Fault(reason(&format!("no answer: {why}")))
        }
        SubmitAnswer::Http { status, body } => (*status, body),
    };
    if (200..300).contains(&status) {
        return match serde_json::from_str::<Steak>(body) {
            Ok(steak)
                if steak
                    .get(topic)
                    .is_some_and(|a| a.outputs_to_admit.contains(&vout)) =>
            {
                Admission::Admitted
            }
            Ok(_) => Admission::Fault(reason(&format!("an empty admission: {body}"))),
            Err(_) => Admission::Fault(reason(&format!("not an admission: HTTP {status}"))),
        };
    }
    match refusal_message(body) {
        Some(message) if REFUSAL_STATUSES.contains(&status) => {
            Admission::Refused(reason(&format!("HTTP {status}: {message}")))
        }
        _ => Admission::Fault(format!("HTTP {status}")),
    }
}

/// The message of a body in the overlay's error shape: a JSON object with
/// `"status": "error"` and a string `message` (or `description`), not marked
/// `"retryable": true`.
fn refusal_message(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    if value["status"].as_str() != Some("error") || value["retryable"].as_bool() == Some(true) {
        return None;
    }
    value["message"]
        .as_str()
        .or_else(|| value["description"].as_str())
        .map(str::to_string)
}

/// `fut`'s output, or `None` when `deadline_ms` passes first.
async fn within<F: std::future::Future>(fut: F, deadline_ms: u64) -> Option<F::Output> {
    use std::future::Future as _;
    use std::task::Poll;
    let mut fut = std::pin::pin!(fut);
    let mut timer = std::pin::pin!(worker::Delay::from(std::time::Duration::from_millis(
        deadline_ms
    )));
    std::future::poll_fn(|cx| {
        if let Poll::Ready(out) = fut.as_mut().poll(cx) {
            return Poll::Ready(Some(out));
        }
        if timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        Poll::Pending
    })
    .await
}

/// Internal: POST a [`TaggedBEEF`] to `{overlay_host}/submit` with the
/// wire contract shared with `WorkerBroadcaster`, then validate the Steak.
///
/// Wire contract (identical to
/// `overlay_cloudflare::broadcaster::WorkerBroadcaster::broadcast_to_host`):
///
/// - Method: POST to `{overlay_host trim_end_matches '/'}/submit`
/// - Headers: `Content-Type: application/octet-stream`, `X-Topics: <json array>`
/// - Body: BEEF bytes as a typed `Uint8Array` (not UTF-8 string)
///
/// The extra layer on top of `WorkerBroadcaster` is the Steak-body
/// inspection — see the module docstring.
/// Name of the service binding to the rust-overlay Worker. Matches the
/// `[[services]] binding = "OVERLAY"` entry in `wrangler.toml`. Service
/// bindings use CF's internal RPC rail, not the public HTTPS edge — this
/// avoids the Worker→Worker `*.workers.dev` restriction that returns CF
/// error 1042 on direct fetches.
const OVERLAY_SERVICE_BINDING: &str = "OVERLAY";

async fn submit_tagged(
    env: &worker::Env,
    overlay_host: &str,
    tagged: &TaggedBEEF,
) -> Result<(), SubmitError> {
    let (status, body_text) = submit_answer(env, overlay_host, tagged).await?;
    read_submit(tagged, status, body_text)
}

/// POST a [`TaggedBEEF`] to `{overlay_host}/submit` and return the answer's
/// status and body; an error only when no answer was read.
async fn submit_answer(
    env: &worker::Env,
    overlay_host: &str,
    tagged: &TaggedBEEF,
) -> Result<(u16, String), SubmitError> {
    let url = format!("{}/submit", overlay_host.trim_end_matches('/'));

    let topics_header =
        serde_json::to_string(&tagged.topics).map_err(|e| SubmitError::Serialize(e.to_string()))?;

    let headers = Headers::new();
    headers
        .set("Content-Type", "application/octet-stream")
        .map_err(|e| SubmitError::Transport(e.to_string()))?;
    headers
        .set("X-Topics", &topics_header)
        .map_err(|e| SubmitError::Transport(e.to_string()))?;

    // `worker::RequestInit::with_body` takes a `JsValue`. Turn the raw tx
    // bytes into a typed Uint8Array so the Worker runtime sees them as
    // binary (not UTF-8 string), matching `application/octet-stream`. This
    // is the same pattern `WorkerBroadcaster` uses.
    let body_js = js_sys::Uint8Array::from(tagged.beef.as_slice());
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(wasm_bindgen::JsValue::from(body_js)));

    let request =
        Request::new_with_init(&url, &init).map_err(|e| SubmitError::Transport(e.to_string()))?;

    // Prefer the service binding (internal RPC, bypasses CF-1042). If the
    // binding isn't configured (e.g. local dev without the linked worker),
    // fall back to the global Fetch — works for any host, including third-
    // party overlays like `overlay-us-1.bsvb.tech`.
    let mut response = match env.service(OVERLAY_SERVICE_BINDING) {
        Ok(fetcher) => fetcher
            .fetch_request(request)
            .await
            .map_err(|e| SubmitError::Transport(e.to_string()))?,
        Err(_) => Fetch::Request(request)
            .send()
            .await
            .map_err(|e| SubmitError::Transport(e.to_string()))?,
    };

    let status = response.status_code();
    let body_text = response.text().await.unwrap_or_default();
    Ok((status, body_text))
}

/// `/advertise`'s and the upload queue's reading of a submit's answer.
fn read_submit(tagged: &TaggedBEEF, status: u16, body_text: String) -> Result<(), SubmitError> {
    if !(200..300).contains(&status) {
        return Err(SubmitError::HttpStatus {
            status,
            body: body_text,
        });
    }

    // Parse the Steak. If the server emits something that doesn't match the
    // typed shape (forward-compat surface), accept the submission — HTTP
    // 2xx is the strong signal and empty-admission detection is
    // best-effort for non-Steak payloads.
    let primary_topic = tagged
        .topics
        .first()
        .map(String::as_str)
        .unwrap_or(TM_UHRP_TOPIC);
    match serde_json::from_str::<Steak>(&body_text) {
        Ok(steak) => {
            let admitted = steak
                .get(primary_topic)
                .map(|a| !a.outputs_to_admit.is_empty())
                .unwrap_or(false);
            if admitted {
                Ok(())
            } else {
                Err(SubmitError::NoOutputsAdmitted(body_text))
            }
        }
        Err(_) => Ok(()),
    }
}

// ─── Mainnet SLAP-driven peer fan-out ────────────────────────────────────

/// Default SLAP trackers, lifted verbatim from the TS SDK's
/// `DEFAULT_SLAP_TRACKERS` at `@bsv/sdk/src/overlay-tools/LookupResolver.ts:42`.
/// These are the hosts the TS SDK's `LookupResolver({networkPreset:'mainnet'})`
/// queries to discover hosts for any lookup service. If the list ever diverges
/// upstream, mirror it here.
const DEFAULT_SLAP_TRACKERS: &[&str] = &[
    "https://overlay-us-1.bsvb.tech",
    "https://overlay-eu-1.bsvb.tech",
    "https://overlay-ap-1.bsvb.tech",
    "https://users.bapp.dev",
];

/// Fan out the just-admitted advertisement to mainnet peers so
/// default-configured `@bsv/sdk` clients (e.g. uhrp-ui) can resolve our
/// records without configuring custom hosts.
///
/// Pipeline:
/// 1. For each SLAP tracker, POST `/lookup` with `{service:"ls_ship",
///    query:{topics:[tm_X]}}` to discover peers that run that topic manager.
/// 2. Take a host from each returned output that is a SHIP advertisement
///    for the topic signed by the identity it names, for a public `https`
///    origin ([`ship_host`]); every other output is skipped and counted in
///    one log line per tracker.
/// 3. Deduplicate the hosts, leave out our primary (we already submitted
///    there), keep the first [`FAN_OUT_MAX_HOSTS`], and POST the same BEEF
///    to each one's `/submit`.
///
/// All errors are logged and swallowed — the primary submission already
/// succeeded, and partial propagation is better than none.
async fn fan_out_to_mainnet_peers(primary_host: &str, tagged: &TaggedBEEF) {
    let topic = match tagged.topics.first() {
        Some(t) => t.as_str(),
        None => return,
    };

    let mut found: Vec<String> = Vec::new();
    for tracker in DEFAULT_SLAP_TRACKERS {
        match discover_peers_from_tracker(tracker, topic).await {
            Ok(answer) => {
                if !answer.skipped.is_empty() {
                    worker::console_warn!(
                        "overlay fan-out: SLAP tracker {} ls_ship({}): {} advertisement(s) skipped ({} unverified, {} other topic, {} host refused, {} not SHIP, {} unreadable)",
                        tracker,
                        topic,
                        answer.skipped.len(),
                        answer.count(Skip::Unverified),
                        answer.count(Skip::OtherTopic),
                        answer.count(Skip::Host),
                        answer.count(Skip::NotShip),
                        answer.count(Skip::Unreadable)
                    );
                }
                found.extend(answer.hosts);
            }
            Err(e) => {
                worker::console_warn!(
                    "overlay fan-out: SLAP tracker {} ls_ship({}) failed: {}",
                    tracker,
                    topic,
                    e
                );
            }
        }
    }

    // Our own host is the primary admission step, already submitted.
    let (peers, over_cap) = fan_out_peers(&found, primary_host);
    if over_cap > 0 {
        worker::console_warn!(
            "overlay fan-out: {} host(s) past the first {} left out",
            over_cap,
            FAN_OUT_MAX_HOSTS
        );
    }

    worker::console_log!(
        "overlay fan-out: submitting {} to {} mainnet peer(s)",
        topic,
        peers.len()
    );

    for peer in peers {
        match post_beef_to_peer(&peer, tagged).await {
            Ok(()) => worker::console_log!("overlay fan-out: peer {} accepted", peer),
            Err(e) => worker::console_warn!("overlay fan-out: peer {} rejected: {}", peer, e),
        }
    }
}

/// Query a SLAP tracker for hosts that run `topic`, return their URLs.
///
/// Mirrors the TS SDK's `LookupResolver.query({service:'ls_ship',
/// query:{topics:[topic]}})`, then reads each output as `SHIPBroadcaster`
/// does: a verified SHIP advertisement for the topic names a host
/// ([`ship_hosts_from_lookup_answer`]).
async fn discover_peers_from_tracker(tracker: &str, topic: &str) -> Result<ShipHosts, String> {
    let url = format!("{}/lookup", tracker.trim_end_matches('/'));
    let body = serde_json::json!({
        "service": "ls_ship",
        "query": { "topics": [topic] }
    });
    let body_str = body.to_string();

    let headers = Headers::new();
    headers
        .set("Content-Type", "application/json")
        .map_err(|e| e.to_string())?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(wasm_bindgen::JsValue::from_str(&body_str)));

    let request = Request::new_with_init(&url, &init).map_err(|e| e.to_string())?;
    let mut response = Fetch::Request(request)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let status = response.status_code();
    if !(200..300).contains(&status) {
        return Err(format!("HTTP {}", status));
    }
    let body = read_body_bounded(&mut response, LOOKUP_ANSWER_MAX_BYTES).await?;
    ship_hosts_from_lookup_answer(&body, topic)
}

/// The most a tracker's lookup answer may carry. Real `ls_ship` answers
/// for `tm_uhrp` from the four trackers measure 67 to 417 KB, and up to
/// 592 KB for any topic (2026-11); a larger answer is skipped as an
/// unreadable one is. The answer is JSON, each BEEF byte written as a
/// decimal number; each advertisement's BEEF in it is held to
/// [`ADVERT_BEEF_MAX_BYTES`].
pub(crate) const LOOKUP_ANSWER_MAX_BYTES: usize = 4 * 1024 * 1024;

/// The most bytes of a SHIP advertisement's BEEF the fan-out parses:
/// 614,400 (600 KiB), the figure this stack's Workers hold a BEEF they
/// parse to. A longer one is skipped as an unreadable one is
/// ([`Skip::Unreadable`]), not parsed. The figure is provisional: it is read again at each bsv-rs pin of this crate and raised to the door's natural figure when a pin allows it.
pub(crate) const ADVERT_BEEF_MAX_BYTES: usize = 614_400;

/// Append `chunk` to `body` unless the body would pass `cap`.
pub(crate) fn push_bounded(body: &mut Vec<u8>, chunk: &[u8], cap: usize) -> Result<(), String> {
    if body.len().saturating_add(chunk.len()) > cap {
        return Err(format!("answer over {} bytes", cap));
    }
    body.extend_from_slice(chunk);
    Ok(())
}

/// Read a response body, refusing it once it passes `cap` bytes (a declared
/// `Content-Length` over the cap is refused before reading).
async fn read_body_bounded(response: &mut worker::Response, cap: usize) -> Result<Vec<u8>, String> {
    use wasm_bindgen::JsCast;
    use worker::ResponseBody;

    if let Ok(Some(declared)) = response.headers().get("Content-Length") {
        if declared.trim().parse::<u64>().is_ok_and(|n| n > cap as u64) {
            return Err(format!("answer over {} bytes", cap));
        }
    }
    let stream = match response.body() {
        ResponseBody::Empty => return Ok(Vec::new()),
        ResponseBody::Body(bytes) => {
            let mut body = Vec::new();
            push_bounded(&mut body, bytes, cap)?;
            return Ok(body);
        }
        ResponseBody::Stream(stream) => stream.clone(),
    };
    let reader: worker::web_sys::ReadableStreamDefaultReader = stream
        .get_reader()
        .dyn_into()
        .map_err(|_| "body reader unavailable".to_string())?;
    let mut body = Vec::new();
    loop {
        let next = wasm_bindgen_futures::JsFuture::from(reader.read())
            .await
            .map_err(|e| format!("{:?}", e))?;
        let done = js_sys::Reflect::get(&next, &"done".into())
            .ok()
            .and_then(|d| d.as_bool())
            .unwrap_or(true);
        if done {
            break;
        }
        let value = js_sys::Reflect::get(&next, &"value".into()).map_err(|e| format!("{:?}", e))?;
        let chunk = js_sys::Uint8Array::new(&value).to_vec();
        if let Err(e) = push_bounded(&mut body, &chunk, cap) {
            let _ = reader.cancel();
            return Err(e);
        }
    }
    Ok(body)
}

/// The subject transaction's output `vout` of an advertisement's BEEF of at
/// most [`ADVERT_BEEF_MAX_BYTES`]; `None` for a longer one, not parsed.
pub(crate) fn advert_output(
    beef_bytes: &[u8],
    vout: usize,
) -> Option<bsv_rs::transaction::TransactionOutput> {
    if beef_bytes.len() > ADVERT_BEEF_MAX_BYTES {
        return None;
    }
    subject_output(beef_bytes, vout)
}

/// The subject transaction's output `vout`, read without linking its
/// ancestry: `Transaction::from_beef_subject` resolves the subject as
/// `Transaction::from_beef` does (the Atomic BEEF's named transaction, else
/// the last entry) and copies that entry alone.
pub(crate) fn subject_output(
    beef_bytes: &[u8],
    vout: usize,
) -> Option<bsv_rs::transaction::TransactionOutput> {
    let mut tx = bsv_rs::transaction::Transaction::from_beef_subject(beef_bytes, None).ok()?;
    std::mem::take(&mut tx.outputs).into_iter().nth(vout)
}

/// Why a lookup answer's output names no host for the fan-out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Skip {
    /// The BEEF does not read, or it has no such output.
    Unreadable,
    /// The output is not a SHIP advertisement (not a PushDrop of the
    /// advertisement's fields, another protocol, or an identity key that is
    /// not a compressed key).
    NotShip,
    /// A SHIP advertisement without the one signature after its four data
    /// fields, or whose signature is not by the key its identity links for
    /// SHIP, or whose output that key does not lock.
    Unverified,
    /// A SHIP advertisement for another topic.
    OtherTopic,
    /// The advertised host is not a public `https` origin.
    Host,
}

/// The SHIP hosts a lookup answer names for `topic`, and what was skipped.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ShipHosts {
    /// Each host's origin (`https://name`), in the answer's order, once.
    pub hosts: Vec<String>,
    /// The outputs that named no host, and why.
    pub skipped: Vec<Skip>,
}

impl ShipHosts {
    /// How many outputs were skipped for `why`.
    pub fn count(&self, why: Skip) -> usize {
        self.skipped.iter().filter(|s| **s == why).count()
    }
}

/// BRC-43 protocol name SHIP advertisements are signed and locked under.
const SHIP_PROTOCOL_NAME: &str = "service host interconnect";

/// The host a SHIP advertisement for `topic` names, if the advertisement is
/// the one the reference defines (BRC-88, as `@bsv/sdk`'s
/// `decodeAndVerifyOverlayAdvertisement` and `@bsv/overlay-discovery-services`'
/// `isTokenSignatureCorrectlyLinked` read it):
///
/// - a PushDrop of five fields: `"SHIP"`, the advertiser's identity key
///   (compressed), the host, the topic, and a DER signature;
/// - the signature is over the SHA-256 of the four data fields concatenated,
///   by the key BRC-42 derives from the identity key for `anyone`, under the
///   protocol `[2, "service host interconnect"]` and key ID `"1"`;
/// - that same derived key locks the output;
/// - the topic is `topic`;
/// - the host is a public `https` origin ([`advertised_origin`]).
///
/// The derivation, the hash and the signature check are bsv-rs's
/// (`KeyDeriver`, `sha256`, `PublicKey::verify`), the same calls bsv-rs's own
/// SHIP discovery makes.
pub(crate) fn ship_host(
    script: &bsv_rs::script::LockingScript,
    topic: &str,
) -> Result<String, Skip> {
    use bsv_rs::overlay::{decode_overlay_admin_token, Protocol};
    use bsv_rs::primitives::{hash::sha256, Signature};
    use bsv_rs::script::templates::PushDrop;
    use bsv_rs::wallet::{Counterparty, KeyDeriver, Protocol as WalletProtocol, SecurityLevel};

    let data = decode_overlay_admin_token(script).map_err(|_| Skip::NotShip)?;
    if data.protocol != Protocol::Ship {
        return Err(Skip::NotShip);
    }
    let token = PushDrop::decode(script).map_err(|_| Skip::NotShip)?;
    let identity = data.identity_key.to_compressed();
    if token.fields.get(1).map(Vec::as_slice) != Some(identity.as_slice()) {
        return Err(Skip::NotShip);
    }
    let [fields @ .., signature] = token.fields.as_slice() else {
        return Err(Skip::Unverified);
    };
    if fields.len() != 4 {
        return Err(Skip::Unverified);
    }
    let linked = KeyDeriver::new(None)
        .derive_public_key(
            &WalletProtocol::new(SecurityLevel::Counterparty, SHIP_PROTOCOL_NAME),
            "1",
            &Counterparty::Other(data.identity_key.clone()),
            false,
        )
        .map_err(|_| Skip::Unverified)?;
    let signed = sha256(&fields.concat());
    let signed_by_linked =
        Signature::from_der(signature).is_ok_and(|signature| linked.verify(&signed, &signature));
    if !signed_by_linked || linked != token.locking_public_key {
        return Err(Skip::Unverified);
    }
    if data.topic_or_service != topic {
        return Err(Skip::OtherTopic);
    }
    advertised_origin(&data.domain).ok_or(Skip::Host)
}

/// The origin (`https://name`) of an advertised host, if it is one the
/// fan-out posts to: `https`, a DNS name (no IP literal), the default port,
/// no credentials, no path but `/`, no query and no fragment, and a public
/// name. The name rules are `@bsv/overlay-discovery-services`'
/// `isAdvertisableURI`: no `localhost`, no `.localhost`, `.local`,
/// `.internal` or `.home.arpa` name and no `xn--` label; and the name has a
/// dot.
pub(crate) fn advertised_origin(advertised: &str) -> Option<String> {
    let url = worker::Url::parse(advertised).ok()?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    // `None` for an IP literal.
    let name = url.domain()?.trim_end_matches('.');
    let private = name == "localhost"
        || [".localhost", ".local", ".internal", ".home.arpa"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
        || name.split('.').any(|label| label.starts_with("xn--"));
    if private || !name.contains('.') || name.split('.').any(str::is_empty) {
        return None;
    }
    Some(format!("https://{name}"))
}

/// The SHIP hosts a lookup answer names for `topic` ([`ship_host`]). Each
/// output's subject is read without linking its ancestry
/// ([`subject_output`]): the fan-out needs the one output, nothing linked.
/// An output whose BEEF is longer than [`ADVERT_BEEF_MAX_BYTES`] is not
/// parsed ([`advert_output`]).
/// An output that names no host is skipped and counted; an answer that is
/// not JSON is an error, and an answer of another type names none.
pub(crate) fn ship_hosts_from_lookup_answer(body: &[u8], topic: &str) -> Result<ShipHosts, String> {
    #[derive(serde::Deserialize)]
    struct LookupOutput {
        beef: Vec<u8>,
        #[serde(rename = "outputIndex")]
        output_index: u32,
    }
    #[derive(serde::Deserialize)]
    struct LookupAnswer {
        #[serde(rename = "type")]
        answer_type: String,
        #[serde(default)]
        outputs: Vec<LookupOutput>,
    }

    let answer: LookupAnswer = serde_json::from_slice(body).map_err(|e| format!("parse: {}", e))?;
    let mut found = ShipHosts::default();
    if answer.answer_type != "output-list" {
        return Ok(found);
    }
    for out in answer.outputs {
        let host = advert_output(&out.beef, out.output_index as usize)
            .ok_or(Skip::Unreadable)
            .and_then(|output| ship_host(&output.locking_script, topic));
        match host {
            Ok(host) if !found.hosts.contains(&host) => found.hosts.push(host),
            Ok(_) => {}
            Err(why) => found.skipped.push(why),
        }
    }
    Ok(found)
}

/// The most peers one advert is posted to (the reference's `SHIPBroadcaster`
/// takes at most 32 hosts from its lookup).
pub(crate) const FAN_OUT_MAX_HOSTS: usize = 32;

/// The fan-out's peers: the trackers' hosts in the order found, once each,
/// without `primary`, at most [`FAN_OUT_MAX_HOSTS`]. Returns the peers and
/// how many hosts the cap left out.
pub(crate) fn fan_out_peers(found: &[String], primary: &str) -> (Vec<String>, usize) {
    let primary = advertised_origin(primary.trim_end_matches('/'))
        .unwrap_or_else(|| primary.trim_end_matches('/').to_string());
    let mut peers: Vec<String> = Vec::new();
    for host in found {
        if *host != primary && !peers.contains(host) {
            peers.push(host.clone());
        }
    }
    let over = peers.len().saturating_sub(FAN_OUT_MAX_HOSTS);
    peers.truncate(FAN_OUT_MAX_HOSTS);
    (peers, over)
}

/// POST a BEEF to a peer's `/submit` endpoint with the standard
/// SHIP-broadcaster headers. Mirrors `submit_tagged` at the wire level but
/// does NOT parse the Steak body — fan-out targets we don't control may
/// return arbitrary shapes, and we only care whether they 2xx'd.
async fn post_beef_to_peer(peer_host: &str, tagged: &TaggedBEEF) -> Result<(), String> {
    let url = format!("{}/submit", peer_host.trim_end_matches('/'));
    let topics_header = serde_json::to_string(&tagged.topics).map_err(|e| e.to_string())?;

    let headers = Headers::new();
    headers
        .set("Content-Type", "application/octet-stream")
        .map_err(|e| e.to_string())?;
    headers
        .set("X-Topics", &topics_header)
        .map_err(|e| e.to_string())?;

    let body_js = js_sys::Uint8Array::from(tagged.beef.as_slice());
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(wasm_bindgen::JsValue::from(body_js)));

    let request = Request::new_with_init(&url, &init).map_err(|e| e.to_string())?;
    let response = Fetch::Request(request)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let status = response.status_code();
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(format!("HTTP {}", status))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn http(status: u16, body: &str) -> SubmitAnswer {
        SubmitAnswer::Http {
            status,
            body: body.to_string(),
        }
    }

    fn read(answer: &SubmitAnswer) -> Admission {
        read_admission(answer, TM_UHRP_TOPIC, RENEWED_ADVERT_VOUT)
    }

    const ERROR_SHAPE: &str =
        r#"{"status":"error","message":"the topic manager does not admit it"}"#;

    #[test]
    fn admitted_only_when_the_admission_names_this_adverts_output() {
        assert_eq!(RENEWED_ADVERT_VOUT, 0);
        for status in [200, 201] {
            assert_eq!(
                read(&http(
                    status,
                    r#"{"tm_uhrp":{"outputsToAdmit":[0],"coinsToRetain":[]}}"#
                )),
                Admission::Admitted
            );
        }
        assert_eq!(
            read(&http(
                200,
                r#"{"tm_uhrp":{"outputsToAdmit":[1,0],"coinsToRetain":[]},"tm_other":{"outputsToAdmit":[],"coinsToRetain":[]}}"#
            )),
            Admission::Admitted
        );
    }

    #[test]
    fn refused_only_when_the_overlay_answers_a_refusal_in_its_error_shape() {
        for status in REFUSAL_STATUSES {
            assert_eq!(
                read(&http(status, ERROR_SHAPE)),
                Admission::Refused(format!(
                    "HTTP {status}: the topic manager does not admit it"
                ))
            );
        }
        // The reference's coded shape carries `description`.
        assert_eq!(
            read(&http(
                400,
                r#"{"status":"error","code":"ERR_SCRIPT_REFUSED","description":"script verification failed"}"#
            )),
            Admission::Refused("HTTP 400: script verification failed".into())
        );
        // A long reason is cut.
        let long = format!(r#"{{"status":"error","message":"{}"}}"#, "y".repeat(1000));
        let Admission::Refused(why) = read(&http(400, &long)) else {
            unreachable!()
        };
        assert_eq!(why.chars().count(), crate::renewal::REASON_MAX_CHARS);
        assert!(why.starts_with("HTTP 400: yy"));
    }

    /// Every other answer is a fault, its kind first.
    #[test]
    fn every_other_answer_is_a_fault_of_its_kind() {
        let fault = |answer: SubmitAnswer, kind: &str| match read(&answer) {
            Admission::Fault(why) => assert!(why.starts_with(kind), "{answer:?}: {why}"),
            other => panic!("{answer:?}: {other:?}"),
        };
        // No answer, and the deadline.
        fault(SubmitAnswer::Deadline, "no answer within the deadline");
        fault(
            SubmitAnswer::NoAnswer("connection reset".into()),
            "no answer: connection reset",
        );
        // A 5xx, 408 and 429, with or without the error shape.
        for status in [500, 502, 503, 504, 408, 429] {
            fault(http(status, ERROR_SHAPE), &format!("HTTP {status}"));
            fault(http(status, "down"), &format!("HTTP {status}"));
        }
        // Any other 4xx, even in the error shape; a refusal status without it.
        for status in [401, 403, 404, 405, 409, 413, 421] {
            fault(http(status, ERROR_SHAPE), &format!("HTTP {status}"));
        }
        for body in [
            "Bad Request",
            "",
            r#"{"status":"ok","message":"x"}"#,
            r#"{"status":"error"}"#,
            r#"{"status":"error","message":"busy","retryable":true}"#,
            "<html>error code: 1042</html>",
        ] {
            fault(http(400, body), "HTTP 400");
            fault(http(422, body), "HTTP 422");
        }
        // A 2xx that is not an admission.
        for body in ["", "OK", "[]", r#"{"status":"success"}"#, "<html></html>"] {
            fault(http(200, body), "not an admission: HTTP 200");
        }
        // An empty admission: none for the topic, none of this advert's
        // output, or no topic at all.
        for body in [
            r#"{"tm_uhrp":{"outputsToAdmit":[],"coinsToRetain":[]}}"#,
            r#"{"tm_uhrp":{"outputsToAdmit":[1],"coinsToRetain":[]}}"#,
            r#"{"tm_other":{"outputsToAdmit":[0],"coinsToRetain":[]}}"#,
            "{}",
        ] {
            fault(http(200, body), "an empty admission: ");
        }
    }

    /// `/advertise` and the upload queue keep their own reading.
    #[test]
    fn the_upload_adverts_reading_is_unchanged() {
        let tagged = TaggedBEEF::new(vec![1], vec![TM_UHRP_TOPIC.to_string()]);
        assert!(read_submit(&tagged, 200, "OK".into()).is_ok());
        assert!(read_submit(
            &tagged,
            200,
            r#"{"tm_uhrp":{"outputsToAdmit":[0],"coinsToRetain":[]}}"#.into()
        )
        .is_ok());
        assert!(matches!(
            read_submit(&tagged, 200, "{}".into()),
            Err(SubmitError::NoOutputsAdmitted(_))
        ));
        assert!(matches!(
            read_submit(&tagged, 503, "down".into()),
            Err(SubmitError::HttpStatus { status: 503, .. })
        ));
    }

    #[test]
    fn topics_header_matches_ts_ship_broadcaster() {
        // TS: `new SHIPBroadcaster(['tm_uhrp'], ...)` → POSTs with
        // `x-topics: ["tm_uhrp"]`. Verify the JSON bytes match exactly
        // (no whitespace, no trailing newline).
        let topics = vec![TM_UHRP_TOPIC.to_string()];
        let header = serde_json::to_string(&topics).unwrap();
        assert_eq!(header, r#"["tm_uhrp"]"#);
    }

    #[test]
    fn default_overlay_url_is_host_only() {
        // The URL MUST NOT include a trailing `/submit` — we append it
        // inside `submit_tagged`, matching WorkerBroadcaster's contract.
        // A `/submit/submit` double-path would silently 404 every advert.
        assert_eq!(
            DEFAULT_OVERLAY_URL,
            "https://your-worker.your-account.workers.dev"
        );
        assert!(!DEFAULT_OVERLAY_URL.ends_with("/submit"));
    }

    #[test]
    fn submit_error_codes_collapse_to_overlay_broadcast() {
        // All variants share one code so the /advertise and /renew handlers
        // don't need to switch on SubmitError internals.
        let err = SubmitError::Transport("dns".to_string());
        assert_eq!(err.code(), ERR_OVERLAY_BROADCAST);
        let err = SubmitError::HttpStatus {
            status: 503,
            body: String::new(),
        };
        assert_eq!(err.code(), ERR_OVERLAY_BROADCAST);
        let err = SubmitError::NoOutputsAdmitted(String::new());
        assert_eq!(err.code(), ERR_OVERLAY_BROADCAST);
    }

    #[test]
    fn submit_error_descriptions_are_safe_for_http_response() {
        // Descriptions must NOT echo raw transport errors into the HTTP
        // body — they're returned to untrusted callers.
        let err = SubmitError::Transport("internal cf stack trace".to_string());
        assert!(!err.description().contains("stack"));
        let err = SubmitError::HttpStatus {
            status: 500,
            body: "secret".to_string(),
        };
        assert!(!err.description().contains("secret"));
    }

    #[test]
    fn steak_parses_outputs_to_admit() {
        // Steak is `HashMap<String, AdmittanceInstructions>` per
        // `bsv_rs::overlay::types::Steak`. Lock
        // the wire-format parity we rely on in submit_tagged.
        let body = r#"{"tm_uhrp":{"outputsToAdmit":[0],"coinsToRetain":[]}}"#;
        let parsed: Steak = serde_json::from_str(body).unwrap();
        let entry = parsed.get("tm_uhrp").unwrap();
        assert_eq!(entry.outputs_to_admit, vec![0]);
        assert!(entry.coins_to_retain.is_empty());
    }

    #[test]
    fn steak_tolerates_unknown_topics() {
        // Forward-compat: a Steak with extra topic keys (future overlay
        // multiplexing) should still parse.
        let body = r#"{"tm_uhrp":{"outputsToAdmit":[0],"coinsToRetain":[]},"tm_future":{"outputsToAdmit":[],"coinsToRetain":[]}}"#;
        let parsed: Steak = serde_json::from_str(body).unwrap();
        assert!(parsed.contains_key("tm_uhrp"));
        assert!(parsed.contains_key("tm_future"));
    }

    // ── Topic-list wire-format parity with TS (no network) ─────────────────

    #[test]
    fn multi_topic_header_preserves_order() {
        // TS `SHIPBroadcaster(['a', 'b'])` emits `["a","b"]` — order is
        // load-bearing for topic managers that use first-topic-wins.
        let topics = vec!["a".to_string(), "b".to_string()];
        let header = serde_json::to_string(&topics).unwrap();
        assert_eq!(header, r#"["a","b"]"#);
    }

    #[test]
    fn submit_uhrp_advert_wraps_raw_tx_into_tagged_beef() {
        // Behavior lock: the public helper must produce a TaggedBEEF with
        // exactly the UHRP topic, the raw bytes we passed, and no off-chain
        // values. Verifying via `TaggedBEEF::new` (no network) because
        // `submit_uhrp_advert` itself requires a Fetch runtime.
        let tagged = TaggedBEEF::new(
            vec![0xde, 0xad, 0xbe, 0xef],
            vec![TM_UHRP_TOPIC.to_string()],
        );
        assert_eq!(tagged.topics, vec!["tm_uhrp".to_string()]);
        assert_eq!(tagged.beef, vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(tagged.off_chain_values.is_none());
    }

    // ── the fan-out reads the subject alone, from a bounded answer ──────

    fn raw_tx(inputs: &[(&str, u32)], outputs: &[Vec<u8>]) -> Vec<u8> {
        let mut out = 1u32.to_le_bytes().to_vec();
        out.push(inputs.len() as u8);
        for (txid, vout) in inputs {
            let mut id = hex::decode(txid).unwrap();
            id.reverse();
            out.extend_from_slice(&id);
            out.extend_from_slice(&vout.to_le_bytes());
            out.push(0);
            out.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        }
        out.push(outputs.len() as u8);
        for script in outputs {
            out.extend_from_slice(&1000u64.to_le_bytes());
            if script.len() < 0xfd {
                out.push(script.len() as u8);
            } else {
                out.push(0xfd);
                out.extend_from_slice(&(script.len() as u16).to_le_bytes());
            }
            out.extend_from_slice(script);
        }
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }

    /// A SHIP advert (the parity fixture's script) as output 0 of a subject
    /// that spends an unproven parent's outputs many times over.
    fn ship_answer_beef() -> Vec<u8> {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/parity/fixtures/parity/ship_tm_uhrp.json"
        ))
        .unwrap();
        let ship =
            hex::decode(fixture["expected"]["locking_script_hex"].as_str().unwrap()).unwrap();
        let outside = "11".repeat(32);
        let parent = raw_tx(&[(&outside, 0)], &vec![Vec::new(); 200]);
        let mut beef = bsv_rs::transaction::Beef::new();
        let parent_id = beef.merge_raw_tx(parent, None).txid();
        let spends: Vec<(&str, u32)> = (0..200).map(|i| (parent_id.as_str(), i)).collect();
        let subject = raw_tx(&spends, &[ship]);
        let subject_id = beef.merge_raw_tx(subject, None).txid();
        beef.to_binary_atomic(&subject_id).unwrap()
    }

    fn answer(beefs: &[(Vec<u8>, u32)]) -> Vec<u8> {
        let outputs: Vec<_> = beefs
            .iter()
            .map(|(b, i)| serde_json::json!({"beef": b, "outputIndex": i}))
            .collect();
        serde_json::to_vec(&serde_json::json!({"type": "output-list", "outputs": outputs})).unwrap()
    }

    fn hosts(body: &[u8]) -> ShipHosts {
        ship_hosts_from_lookup_answer(body, TM_UHRP_TOPIC).unwrap()
    }

    #[test]
    fn the_fan_out_reads_the_subject_alone() {
        let beef = ship_answer_beef();
        // The subject's output is the one `Transaction::from_beef` returns.
        let linked = bsv_rs::transaction::Transaction::from_beef(&beef, None).unwrap();
        let unlinked = subject_output(&beef, 0).unwrap();
        assert_eq!(
            unlinked.locking_script.to_binary(),
            linked.outputs[0].locking_script.to_binary()
        );
        // The parity fixture is a SHIP advertisement `@bsv/sdk` signed.
        let found = hosts(&answer(&[(beef.clone(), 0)]));
        assert_eq!(found.hosts, vec!["https://overlay.example.com".to_string()]);
        assert!(found.skipped.is_empty());
        // An output that is not there, or a BEEF that does not parse, is skipped.
        let found = hosts(&answer(&[(beef, 3), (vec![1, 2, 3], 0)]));
        assert!(found.hosts.is_empty());
        assert_eq!(found.skipped, vec![Skip::Unreadable; 2]);
    }

    #[test]
    fn an_unreadable_lookup_answer_is_an_error_and_another_type_is_empty() {
        assert!(ship_hosts_from_lookup_answer(b"not json", TM_UHRP_TOPIC).is_err());
        assert!(ship_hosts_from_lookup_answer(&[0xff, 0xfe], TM_UHRP_TOPIC).is_err());
        let other = br#"{"type":"freeform","result":{}}"#;
        assert_eq!(hosts(other), ShipHosts::default());
    }

    // ── a host only from an advertisement its identity signed ───────────

    use bsv_rs::overlay::{create_signed_overlay_admin_token, Protocol};
    use bsv_rs::primitives::PrivateKey;
    use bsv_rs::script::templates::PushDrop;
    use bsv_rs::script::LockingScript;

    fn key(n: u8) -> PrivateKey {
        let mut k = [0u8; 32];
        k[31] = n;
        PrivateKey::from_bytes(&k).unwrap()
    }

    fn signed(n: u8, host: &str, topic: &str) -> LockingScript {
        create_signed_overlay_admin_token(&key(n), Protocol::Ship, host, topic)
    }

    /// `script`'s PushDrop, its fields changed by `edit`, locked by `lock`
    /// (the original locking key when `None`).
    fn altered(
        script: &LockingScript,
        edit: impl FnOnce(&mut Vec<Vec<u8>>),
        lock: Option<bsv_rs::primitives::PublicKey>,
    ) -> LockingScript {
        let token = PushDrop::decode(script).unwrap();
        let mut fields = token.fields.clone();
        edit(&mut fields);
        PushDrop::new(lock.unwrap_or(token.locking_public_key), fields).lock()
    }

    #[test]
    fn a_ship_advertisement_signed_by_its_identity_names_its_host() {
        let host = "https://peer.example.com";
        assert_eq!(
            ship_host(&signed(7, host, TM_UHRP_TOPIC), TM_UHRP_TOPIC),
            Ok(host.into())
        );
        // The origin is what is posted to: case and a trailing slash fold.
        assert_eq!(
            ship_host(
                &signed(7, "https://Peer.Example.COM/", TM_UHRP_TOPIC),
                TM_UHRP_TOPIC
            ),
            Ok(host.into())
        );
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/parity/fixtures/parity/ship_tm_uhrp.json"
        ))
        .unwrap();
        let ts_signed =
            LockingScript::from_hex(fixture["expected"]["locking_script_hex"].as_str().unwrap())
                .unwrap();
        assert_eq!(
            ship_host(&ts_signed, TM_UHRP_TOPIC),
            Ok("https://overlay.example.com".into())
        );
    }

    #[test]
    fn an_advertisement_its_identity_did_not_sign_names_no_host() {
        let good = signed(7, "https://peer.example.com", TM_UHRP_TOPIC);
        let other_identity = key(9).public_key().to_compressed().to_vec();
        let cases: Vec<(&str, LockingScript)> = vec![
            // Another identity named over this one's signature.
            (
                "another identity",
                altered(&good, |f| f[1] = other_identity.clone(), None),
            ),
            // The host changed after signing.
            (
                "the host changed",
                altered(
                    &good,
                    |f| f[2] = b"https://elsewhere.example.com".to_vec(),
                    None,
                ),
            ),
            // The signature dropped, or a byte of it changed.
            ("no signature", altered(&good, |f| drop(f.pop()), None)),
            (
                "a changed signature",
                altered(
                    &good,
                    |f| {
                        let last = f.last_mut().unwrap();
                        let n = last.len() - 1;
                        last[n] ^= 1;
                    },
                    None,
                ),
            ),
            // Signed, but locked by a key the identity does not link.
            (
                "locked by another key",
                altered(&good, |_| {}, Some(key(9).public_key())),
            ),
            // The identity's own key signing, not its linked key.
            (
                "signed by the identity key itself",
                altered(
                    &good,
                    |f| {
                        let data: Vec<u8> = f[..4].concat();
                        let sig = key(7)
                            .sign(&bsv_rs::primitives::hash::sha256(&data))
                            .unwrap()
                            .to_der();
                        f[4] = sig;
                    },
                    None,
                ),
            ),
        ];
        for (name, script) in cases {
            assert_eq!(
                ship_host(&script, TM_UHRP_TOPIC),
                Err(Skip::Unverified),
                "{name}"
            );
        }
        // A SLAP advertisement, and a script that is no PushDrop.
        let slap = create_signed_overlay_admin_token(
            &key(7),
            Protocol::Slap,
            "https://peer.example.com",
            "ls_uhrp",
        );
        assert_eq!(ship_host(&slap, TM_UHRP_TOPIC), Err(Skip::NotShip));
        let plain = LockingScript::from_binary(&[0x51]).unwrap();
        assert_eq!(ship_host(&plain, TM_UHRP_TOPIC), Err(Skip::NotShip));
        // Signed, for another topic.
        assert_eq!(
            ship_host(
                &signed(7, "https://peer.example.com", "tm_other"),
                TM_UHRP_TOPIC
            ),
            Err(Skip::OtherTopic)
        );
    }

    #[test]
    fn a_signed_advertisement_for_a_host_that_is_not_a_public_https_origin_names_none() {
        for host in [
            "http://peer.example.com",
            "wss://peer.example.com",
            "https+bsvauth+smf://peer.example.com",
            "https://127.0.0.1",
            "https://10.1.2.3",
            "https://169.254.169.254",
            "https://0x7f000001",
            "https://[::1]",
            "https://[fd00::1]",
            "https://localhost",
            "https://api.localhost",
            "https://printer.local",
            "https://svc.internal",
            "https://box.home.arpa",
            "https://xn--80ak6aa92e.com",
            "https://intranet",
            "https://user:secret@peer.example.com",
            "https://peer.example.com:8443",
            "https://peer.example.com/submit",
            "https://peer.example.com/?x=1",
            "https://peer.example.com/#x",
            "peer.example.com",
        ] {
            assert_eq!(
                ship_host(&signed(7, host, TM_UHRP_TOPIC), TM_UHRP_TOPIC),
                Err(Skip::Host),
                "{host}"
            );
        }
        assert_eq!(advertised_origin(""), None);
        // The default port written out is the default port.
        assert_eq!(
            advertised_origin("https://peer.example.com:443"),
            Some("https://peer.example.com".into())
        );
    }

    #[test]
    fn a_lookup_answer_counts_what_it_skips() {
        let tx = |script: &LockingScript| {
            let mut beef = bsv_rs::transaction::Beef::new();
            let id = beef
                .merge_raw_tx(
                    raw_tx(&[(&"22".repeat(32), 0)], &[script.to_binary()]),
                    None,
                )
                .txid();
            beef.to_binary_atomic(&id).unwrap()
        };
        let good = signed(7, "https://peer.example.com", TM_UHRP_TOPIC);
        let body = answer(&[
            (tx(&good), 0),
            (tx(&good), 0),
            (tx(&altered(&good, |f| drop(f.pop()), None)), 0),
            (tx(&signed(8, "https://127.0.0.1", TM_UHRP_TOPIC)), 0),
            (tx(&signed(8, "https://two.example.com", "tm_other")), 0),
            (tx(&signed(8, "https://two.example.com", TM_UHRP_TOPIC)), 0),
            (vec![9, 9], 0),
        ]);
        let found = hosts(&body);
        assert_eq!(
            found.hosts,
            vec![
                "https://peer.example.com".to_string(),
                "https://two.example.com".to_string()
            ]
        );
        assert_eq!(found.count(Skip::Unverified), 1);
        assert_eq!(found.count(Skip::Host), 1);
        assert_eq!(found.count(Skip::OtherTopic), 1);
        assert_eq!(found.count(Skip::Unreadable), 1);
        assert_eq!(found.skipped.len(), 4);
    }

    #[test]
    fn the_fan_out_posts_to_each_host_once_without_the_primary_up_to_the_cap() {
        let found: Vec<String> = ["a", "b", "a", "own", "c"]
            .iter()
            .map(|h| format!("https://{h}.example.com"))
            .collect();
        let (peers, over) = fan_out_peers(&found, "https://own.example.com/");
        assert_eq!(peers.len(), 3);
        assert_eq!(peers[0], "https://a.example.com");
        assert_eq!(over, 0);
        let many: Vec<String> = (0..40)
            .map(|i| format!("https://p{i}.example.com"))
            .collect();
        let (peers, over) = fan_out_peers(&many, "https://own.example.com");
        assert_eq!(
            (peers.len(), over),
            (FAN_OUT_MAX_HOSTS, 40 - FAN_OUT_MAX_HOSTS)
        );
        assert_eq!(peers[0], "https://p0.example.com");
    }

    #[test]
    fn the_lookup_answer_is_bounded_in_size() {
        let cap = 10;
        let mut body = Vec::new();
        push_bounded(&mut body, b"12345", cap).unwrap();
        push_bounded(&mut body, b"67890", cap).unwrap();
        assert_eq!(body, b"1234567890");
        assert!(push_bounded(&mut body, b"1", cap).is_err());
        assert_eq!(body.len(), cap, "a refused chunk is not kept");
        // Real tracker answers are under a seventh of the bound.
        assert_eq!(LOOKUP_ANSWER_MAX_BYTES, 4 * 1024 * 1024);
    }

    // ── an advertisement's BEEF is held to the figure ───────────────────

    /// The parity fixture's SHIP advert as output 0 of a subject whose one
    /// parent pads the Atomic BEEF to exactly `len` bytes.
    fn ship_beef_of(len: usize) -> Vec<u8> {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/parity/fixtures/parity/ship_tm_uhrp.json"
        ))
        .unwrap();
        let ship =
            hex::decode(fixture["expected"]["locking_script_hex"].as_str().unwrap()).unwrap();
        let outside = "22".repeat(32);
        let build = |pad: usize| {
            let mut outputs = vec![vec![0u8; 60_000]; 10];
            outputs.push(vec![0u8; pad]);
            let parent = raw_tx(&[(&outside, 0)], &outputs);
            let mut beef = bsv_rs::transaction::Beef::new();
            let parent_id = beef.merge_raw_tx(parent, None).txid();
            let subject = raw_tx(&[(parent_id.as_str(), 0)], std::slice::from_ref(&ship));
            let subject_id = beef.merge_raw_tx(subject, None).txid();
            beef.to_binary_atomic(&subject_id).unwrap()
        };
        let base = build(1_000).len();
        let beef = build(1_000 + len - base);
        assert_eq!(beef.len(), len);
        beef
    }

    /// A lookup answer of one output, written as a tracker writes it.
    fn answer_of(beef: &[u8], index: u32) -> Vec<u8> {
        use std::fmt::Write;
        let mut text = String::from(r#"{"type":"output-list","outputs":[{"beef":["#);
        for (i, byte) in beef.iter().enumerate() {
            if i > 0 {
                text.push(',');
            }
            write!(text, "{byte}").unwrap();
        }
        write!(text, r#"],"outputIndex":{index}}}]}}"#).unwrap();
        text.into_bytes()
    }

    #[test]
    fn an_advert_beef_is_parsed_up_to_the_figure_and_skipped_past_it() {
        assert_eq!(ADVERT_BEEF_MAX_BYTES, 614_400);
        const { assert!(ADVERT_BEEF_MAX_BYTES < LOOKUP_ANSWER_MAX_BYTES) };

        // Exactly the figure: parsed, and its host taken.
        let at = ship_beef_of(ADVERT_BEEF_MAX_BYTES);
        let body = answer_of(&at, 0);
        assert!(body.len() < LOOKUP_ANSWER_MAX_BYTES);
        let found = hosts(&body);
        assert_eq!(found.hosts, vec!["https://overlay.example.com".to_string()]);
        assert!(found.skipped.is_empty());

        // One byte over: the same advert, which reads when parsed, is not
        // parsed by the fan-out and is skipped as an unreadable one is.
        let over = ship_beef_of(ADVERT_BEEF_MAX_BYTES + 1);
        assert!(subject_output(&over, 0).is_some());
        assert!(advert_output(&over, 0).is_none());
        let found = hosts(&answer_of(&over, 0));
        assert!(found.hosts.is_empty());
        assert_eq!(found.skipped, vec![Skip::Unreadable]);
        assert_eq!(found.count(Skip::Unreadable), 1);
    }

    #[test]
    fn an_ordinary_advert_beef_is_far_under_the_figure() {
        // One unproven parent and the advert: under a kilobyte.
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/parity/fixtures/parity/ship_tm_uhrp.json"
        ))
        .unwrap();
        let ship =
            hex::decode(fixture["expected"]["locking_script_hex"].as_str().unwrap()).unwrap();
        let outside = "33".repeat(32);
        let parent = raw_tx(&[(&outside, 0)], &[vec![0x51]]);
        let mut beef = bsv_rs::transaction::Beef::new();
        let parent_id = beef.merge_raw_tx(parent, None).txid();
        let subject = raw_tx(&[(parent_id.as_str(), 0)], &[ship]);
        let subject_id = beef.merge_raw_tx(subject, None).txid();
        let beef = beef.to_binary_atomic(&subject_id).unwrap();
        assert!(beef.len() < 1024, "{}", beef.len());
        let found = hosts(&answer(&[(beef, 0)]));
        assert_eq!(found.hosts.len(), 1);
    }
}
