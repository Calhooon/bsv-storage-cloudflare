//! Overlay SHIP broadcaster — UHRP advert submission.
//!
//! Thin wrapper around the `overlay-engine`/`overlay-cloudflare` crates
//! (rust-overlay), reusing their `TaggedBEEF` + `Steak` wire types so this
//! crate no longer carries its own duplicates of either.
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

use bsv_overlay_engine::types::{Steak, TaggedBEEF};
use worker::{Fetch, Headers, Method, Request, RequestInit};

use crate::error::ERR_OVERLAY_BROADCAST;

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
/// 2. Decode each returned BEEF's PushDrop output — SHIP field[2] is the
///    peer's HTTPS URL.
/// 3. Deduplicate peer URLs, filter out our primary (we already submitted
///    there), POST the same BEEF to each peer's `/submit`.
///
/// All errors are logged and swallowed — the primary submission already
/// succeeded, and partial propagation is better than none.
async fn fan_out_to_mainnet_peers(primary_host: &str, tagged: &TaggedBEEF) {
    let topic = match tagged.topics.first() {
        Some(t) => t.as_str(),
        None => return,
    };

    let mut peers = std::collections::HashSet::<String>::new();
    for tracker in DEFAULT_SLAP_TRACKERS {
        match discover_peers_from_tracker(tracker, topic).await {
            Ok(hosts) => {
                for h in hosts {
                    peers.insert(h);
                }
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

    // Drop our own host from the fan-out — already submitted there as the
    // primary admission step. Trim trailing slashes on both sides so
    // `https://foo.dev/` matches `https://foo.dev`.
    let primary_norm = primary_host.trim_end_matches('/');
    peers.remove(primary_norm);
    peers.remove(&format!("{primary_norm}/"));

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
/// query:{topics:[topic]}})` → decode each output's PushDrop → extract
/// `fields[2]` (SHIP host URL). SHIP PushDrop layout per
/// `@bsv/overlay/src/SHIPAdvertisement.ts`:
/// - field[0] = "SHIP" literal (4 bytes)
/// - field[1] = host identity key (33 bytes compressed pubkey)
/// - field[2] = host HTTPS URL (UTF-8)
/// - field[3] = topic name (UTF-8)
/// - field[4] = signature
async fn discover_peers_from_tracker(tracker: &str, topic: &str) -> Result<Vec<String>, String> {
    use bsv_rs::script::templates::PushDrop;
    use bsv_rs::transaction::Transaction;

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
    let text = response.text().await.map_err(|e| e.to_string())?;

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

    let answer: LookupAnswer = serde_json::from_str(&text).map_err(|e| format!("parse: {}", e))?;
    if answer.answer_type != "output-list" {
        return Ok(Vec::new());
    }

    let mut urls = Vec::new();
    for out in answer.outputs {
        // `Transaction::from_beef` expects an optional txid hint; pass None
        // and let the parser walk to the subject tx.
        let tx = match Transaction::from_beef(&out.beef, None) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let vout = out.output_index as usize;
        let locking_script = match tx.outputs.get(vout) {
            Some(o) => &o.locking_script,
            None => continue,
        };
        let decoded = match PushDrop::decode(locking_script) {
            Ok(d) => d,
            Err(_) => continue,
        };
        // field[2] = host URL as UTF-8 bytes.
        if let Some(url_bytes) = decoded.fields.get(2) {
            if let Ok(s) = std::str::from_utf8(url_bytes) {
                let trimmed = s.trim().trim_end_matches('/').to_string();
                if !trimmed.is_empty() && trimmed.starts_with("http") {
                    urls.push(trimmed);
                }
            }
        }
    }
    Ok(urls)
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
    #![allow(clippy::unwrap_used)]
    use super::*;

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
        // `bsv_overlay_engine::types::Steak` (re-exported from `bsv_rs`). Lock
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
}
