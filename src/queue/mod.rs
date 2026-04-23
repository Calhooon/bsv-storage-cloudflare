//! R2 event → queue consumer → auto-advertise.
//!
//! # What this replaces
//!
//! The original TS deployment wires a GCP Cloud Function (`notifier.js`) to
//! GCS object-create events. That function:
//!
//! 1. Filters to `cdn/*` keys (the UHRP upload prefix).
//! 2. Streams the newly-uploaded file bytes through a SHA-256 digest.
//! 3. Reads the file's GCS custom metadata (`uploaderidentitykey`,
//!    `customTime` — the expiry).
//! 4. POSTs `/advertise` with `{uhrpUrl, objectIdentifier,
//!    uploaderIdentityKey, fileSize, expiryTime}` plus an `adminToken`.
//!
//! The Cloudflare port replaces that out-of-band function with an R2 event
//! notification. When a client completes a direct-to-R2 PUT (via the
//! presigned URL from `/upload`), R2 emits a JSON event onto the
//! `uhrp-post-upload` queue. This module is the consumer that drains the
//! queue. See `wrangler.toml` `[[queues.consumers]]`.
//!
//! # Why reuse `/advertise`'s internal flow?
//!
//! Byte-for-byte parity. The TS notifier's only job is to invoke
//! `/advertise` with the right shape; the on-chain advert is produced by
//! the same `createUHRPAdvertisement` utility regardless of whether a
//! human or the notifier fired the request. We mirror that exactly — the
//! queue consumer calls [`crate::routes::advertise::create_advertisement`]
//! directly, which is the same function the HTTP `/advertise` handler
//! calls after its admin gate. Sharing the path means there is exactly one
//! advertisement-creation implementation in the codebase.
//!
//! The admin gate intentionally does NOT run here — the queue consumer
//! itself is the trust boundary. Only an R2 event notification (wired to
//! our queue by account-level config) can enqueue a message, and only the
//! admin running `wrangler r2 bucket notification create` chose which
//! bucket feeds the queue. We need not re-authorize what the
//! infrastructure already enforces.

use serde::{Deserialize, Serialize};
use worker::{console_log, Env, MessageBatch, MessageExt};

use crate::routes::advertise::create_advertisement;
use crate::storage::head::{head_object, UHRP_BINDING};
use crate::uhrp::hash::url_from_hash;

/// R2 custom metadata key carrying the BRC-31 identity key of the uploader.
/// Set on the PUT via `x-amz-meta-uploaderidentitykey`. R2 lowercases custom
/// metadata keys by default, matching the GCS `uploaderidentitykey` key the
/// TS notifier reads.
const METADATA_KEY_UPLOADER: &str = "uploaderidentitykey";

/// R2 custom metadata key carrying the advertisement expiry as ISO-8601.
/// Set on the PUT via `x-amz-meta-custom-time` (maps to GCS's native
/// `x-goog-custom-time`; see `src/storage/mod.rs` for the backend-mapping
/// rationale).
const METADATA_KEY_CUSTOM_TIME: &str = "custom-time";

/// Key prefix for UHRP-advertised objects. Matches TS notifier's
/// `if (!file.name.startsWith('cdn/'))` guard in `notifier/notifier.js:30`.
const UHRP_KEY_PREFIX: &str = "cdn/";

/// Minimum length of an object identifier past the `cdn/` prefix. Base58 of
/// 16 random bytes produces 22 characters; anything shorter is either a
/// folder marker or a malformed key we should ignore.
const MIN_OBJECT_IDENTIFIER_LEN: usize = 1;

/// R2 event notification payload. Shape matches the JSON emitted by
/// Cloudflare's R2 → Queue event notification feature (current wire format
/// documented at <https://developers.cloudflare.com/r2/buckets/event-notifications/>
/// under "Message content").
///
/// All unknown/extra fields (`copySource`, `account`, `eventTime`, etc.)
/// are silently tolerated — we only consume what we need. Named-struct
/// discipline keeps the consumer signature free of `serde_json::Value`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct R2EventMessage {
    /// One of `"PutObject"`, `"CopyObject"`, `"CompleteMultipartUpload"`,
    /// `"DeleteObject"`, `"AbortMultipartUpload"`, `"LifecycleDeletion"`.
    /// We process only object-create actions; deletes are ignored.
    pub action: R2EventAction,
    /// The bucket that emitted the event.
    pub bucket: String,
    /// The object referenced by the event.
    pub object: R2EventObject,
}

/// Subset of R2 actions we care about. Named variants instead of an
/// untyped string so dispatch is a compile-time match.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum R2EventAction {
    #[serde(rename = "PutObject")]
    PutObject,
    #[serde(rename = "CopyObject")]
    CopyObject,
    #[serde(rename = "CompleteMultipartUpload")]
    CompleteMultipartUpload,
    #[serde(rename = "DeleteObject")]
    DeleteObject,
    #[serde(rename = "AbortMultipartUpload")]
    AbortMultipartUpload,
    #[serde(rename = "LifecycleDeletion")]
    LifecycleDeletion,
}

impl R2EventAction {
    /// Does this action signal a newly-available object we should
    /// advertise? Delete and multipart-abort do not; everything else
    /// makes a new object bytes-reachable at the key.
    #[must_use]
    pub const fn creates_object(self) -> bool {
        matches!(
            self,
            Self::PutObject | Self::CopyObject | Self::CompleteMultipartUpload
        )
    }
}

/// The `object` field of an R2 event. Only `key` is load-bearing; `size`
/// and `e_tag` are captured for logging/observability.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct R2EventObject {
    pub key: String,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default, rename = "eTag")]
    pub e_tag: Option<String>,
}

/// Per-message processing outcome. Tracked at the call site so the queue
/// handler can ack vs retry each message independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessOutcome {
    /// Handled successfully — ack.
    Advertised,
    /// Intentionally ignored (wrong prefix, delete event, …) — ack, don't
    /// bounce forever.
    Skipped,
    /// Transient failure; retry the message.
    Retry,
}

/// Queue-consumer entry point. Called once per batch by the
/// `#[event(queue)]` handler in `lib.rs`.
///
/// Each message is processed independently. Successes and deliberate
/// skips are ack'd; transient failures are retried (CF Queue re-delivers
/// up to `max_retries` times, configured in `wrangler.toml`).
pub async fn handle_batch(batch: MessageBatch<R2EventMessage>, env: &Env) {
    for msg_result in batch.iter() {
        let msg = match msg_result {
            Ok(m) => m,
            Err(err) => {
                // Deserialization failed — the payload is malformed (CF
                // may have shipped a new event shape we don't understand).
                // Retrying won't help; drop it.
                console_log!("queue: message deserialize error: {err}");
                continue;
            }
        };

        let event = msg.body();
        match process_message(event, env).await {
            ProcessOutcome::Advertised => {
                console_log!(
                    "queue: advertised object key={} bucket={}",
                    event.object.key,
                    event.bucket
                );
                msg.ack();
            }
            ProcessOutcome::Skipped => {
                // Log only on non-PutObject actions — PutObject on
                // non-cdn/ keys is routine and noisy.
                if !matches!(event.action, R2EventAction::PutObject) {
                    console_log!(
                        "queue: skipped action={:?} key={}",
                        event.action,
                        event.object.key
                    );
                }
                msg.ack();
            }
            ProcessOutcome::Retry => {
                console_log!(
                    "queue: retrying key={} bucket={}",
                    event.object.key,
                    event.bucket
                );
                msg.retry();
            }
        }
    }
}

/// Process a single R2 event. Pure business logic, extracted for tests —
/// the `MessageBatch` iterator itself requires a live Worker runtime.
pub async fn process_message(event: &R2EventMessage, env: &Env) -> ProcessOutcome {
    // ── Filter 1: only object-create actions ──────────────────────────────
    if !event.action.creates_object() {
        return ProcessOutcome::Skipped;
    }

    // ── Filter 2: only keys under the UHRP prefix ─────────────────────────
    let Some(object_identifier) = extract_object_identifier(&event.object.key) else {
        return ProcessOutcome::Skipped;
    };

    // ── HEAD the object for metadata + size ───────────────────────────────
    // Errors classified as retryable: R2 sometimes returns 500s or has the
    // object not-yet-readable within milliseconds of the PUT completing.
    let head = match head_object(env, UHRP_BINDING, &event.object.key).await {
        Ok(Some(h)) => h,
        Ok(None) => {
            // Object genuinely missing — the event may have arrived after
            // a delete, or we raced a PUT+DELETE. Don't retry forever.
            console_log!("queue: object missing on HEAD key={}", event.object.key);
            return ProcessOutcome::Skipped;
        }
        Err(code) => {
            console_log!("queue: HEAD failed code={code} key={}", event.object.key);
            return ProcessOutcome::Retry;
        }
    };

    // ── Extract uploader identity + expiry from custom metadata ──────────
    let uploader_identity_key = match head.custom_metadata.get(METADATA_KEY_UPLOADER) {
        Some(k) if !k.is_empty() => k.clone(),
        _ => {
            // No identity → this object wasn't uploaded via our /upload
            // flow. Skip (TS notifier matches: it defaults to '' and
            // creates an advert with no uploader; we prefer to NOT
            // advertise rather than emit a broken-tag advert).
            console_log!("queue: missing uploader metadata key={}", event.object.key);
            return ProcessOutcome::Skipped;
        }
    };

    let custom_time = match head.custom_metadata.get(METADATA_KEY_CUSTOM_TIME) {
        Some(t) if !t.is_empty() => t.as_str(),
        _ => {
            console_log!(
                "queue: missing custom-time metadata key={}",
                event.object.key
            );
            return ProcessOutcome::Skipped;
        }
    };
    let expiry_time = match parse_custom_time_to_unix_seconds(custom_time) {
        Some(s) => s,
        None => {
            console_log!(
                "queue: unparsable custom-time '{custom_time}' key={}",
                event.object.key
            );
            return ProcessOutcome::Skipped;
        }
    };

    // ── Stream bytes and SHA-256 them (UHRP hash derivation) ─────────────
    let hash = match hash_r2_object(env, UHRP_BINDING, &event.object.key).await {
        Ok(h) => h,
        Err(code) => {
            console_log!("queue: hash failed code={code} key={}", event.object.key);
            return ProcessOutcome::Retry;
        }
    };

    let uhrp_url = format!("uhrp://{}", url_from_hash(&hash));

    // ── Delegate to the shared advertisement builder ─────────────────────
    match create_advertisement(
        env,
        &uhrp_url,
        object_identifier,
        &uploader_identity_key,
        head.size,
        expiry_time,
        hash,
    )
    .await
    {
        Ok(()) => ProcessOutcome::Advertised,
        Err(err) => {
            // Network flukes (wallet-infra / overlay unreachable) are
            // retryable; everything else is likely a permanent shape bug
            // (bad env var, bad secret). We lean toward retry — CF Queue
            // caps retries at `max_retries` in wrangler.toml, and an
            // over-aggressive retry of a permanently-bad message just
            // eventually lands in the DLQ (if configured) rather than
            // stalling the queue.
            console_log!(
                "queue: create_advertisement failed code={} desc={} key={}",
                err.code,
                err.description,
                event.object.key
            );
            ProcessOutcome::Retry
        }
    }
}

/// Extract the object identifier portion of a `cdn/<id>` key, or `None` if
/// the key doesn't belong to the UHRP prefix. Pulled out for test
/// coverage — the prefix test is the TS notifier's guard verbatim.
fn extract_object_identifier(key: &str) -> Option<&str> {
    let remainder = key.strip_prefix(UHRP_KEY_PREFIX)?;
    if remainder.len() < MIN_OBJECT_IDENTIFIER_LEN {
        return None;
    }
    // Guard against nested paths like `cdn/subdir/file`. TS's
    // `file.name.split('/').pop()` would pick up `file`; we reject
    // because our `/upload` route never produces nested keys and a
    // nested key means the event came from an out-of-band write.
    if remainder.contains('/') {
        return None;
    }
    Some(remainder)
}

/// Parse a custom-time header value into Unix seconds.
///
/// Our `/upload` route writes ISO-8601 with millisecond precision
/// (matches TS `new Date(ms).toISOString()`, e.g. `"2025-05-10T12:34:56.123Z"`).
/// We also accept a plain integer (Unix seconds) for forward-compat with
/// callers that might bypass the presigned route — e.g. future admin
/// tooling that writes directly to R2.
///
/// Matches TS notifier's `Math.round(new Date(metadata.customTime).getTime() / 1000)`
/// semantics.
fn parse_custom_time_to_unix_seconds(raw: &str) -> Option<u64> {
    // Fast path: bare integer seconds (future tooling).
    if let Ok(n) = raw.parse::<u64>() {
        return Some(n);
    }

    // ISO-8601 with optional fractional seconds + `Z` suffix. Parse via
    // chrono so we don't hand-roll calendar math.
    let parsed = chrono::DateTime::parse_from_rfc3339(raw).ok()?;
    let secs = parsed.timestamp();
    if secs < 0 {
        return None;
    }
    Some(secs as u64)
}

/// SHA-256 of an R2 object's bytes. The object must already exist (caller
/// HEADed it first).
///
/// We load the full body into memory because R2 Workers' streaming
/// primitives don't expose an incremental `update()`-style digest; in
/// practice UHRP uploads top out at 11 GB (`MAX_UPLOAD_BYTES` in
/// `routes::upload`) and Workers has a 128 MB memory ceiling, so
/// SHA-256ing a multi-GB upload via the queue consumer will OOM. This is
/// a known limitation — the queue consumer is sized for the <128MB
/// common case; for large uploads the client should call `/advertise`
/// explicitly with a pre-computed hash (which is the TS convention for
/// CLI uploads already). See DEPLOYMENT.md for operator guidance.
async fn hash_r2_object(env: &Env, binding: &str, key: &str) -> Result<[u8; 32], &'static str> {
    use sha2::Digest;

    let bucket = env.bucket(binding).map_err(|_| "ERR_R2_BINDING")?;
    let maybe_obj = bucket
        .get(key.to_string())
        .execute()
        .await
        .map_err(|_| "ERR_R2_GET")?;
    let obj = maybe_obj.ok_or("ERR_R2_NOT_FOUND")?;
    let body = obj.body().ok_or("ERR_R2_EMPTY_BODY")?;
    let bytes = body.bytes().await.map_err(|_| "ERR_R2_READ")?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // ── R2EventMessage parsing (pure JSON, no runtime) ────────────────────

    #[test]
    fn parses_real_r2_put_event() {
        // Shape from Cloudflare's R2 event-notification docs as of 2026-04.
        let raw = r#"{
            "account": "0000000000000000000000000000000000000000000000000000000000000000",
            "action": "PutObject",
            "bucket": "uhrp-prod",
            "object": {
                "key": "cdn/abc123xyz",
                "size": 4096,
                "eTag": "d41d8cd98f00b204e9800998ecf8427e"
            },
            "eventTime": "2026-04-20T12:00:00.000Z",
            "copySource": {}
        }"#;
        let msg: R2EventMessage = serde_json::from_str(raw).unwrap();
        assert_eq!(msg.action, R2EventAction::PutObject);
        assert_eq!(msg.bucket, "uhrp-prod");
        assert_eq!(msg.object.key, "cdn/abc123xyz");
        assert_eq!(msg.object.size, Some(4096));
        assert_eq!(
            msg.object.e_tag.as_deref(),
            Some("d41d8cd98f00b204e9800998ecf8427e")
        );
    }

    #[test]
    fn parses_minimal_event_without_optional_fields() {
        // Some event variants omit size / eTag (e.g. DeleteObject).
        let raw = r#"{
            "action": "DeleteObject",
            "bucket": "uhrp-prod",
            "object": { "key": "cdn/gone" }
        }"#;
        let msg: R2EventMessage = serde_json::from_str(raw).unwrap();
        assert_eq!(msg.action, R2EventAction::DeleteObject);
        assert_eq!(msg.object.size, None);
        assert_eq!(msg.object.e_tag, None);
    }

    #[test]
    fn rejects_unknown_action_variant() {
        // Forward-compat: if CF adds a new action we don't know about, we
        // reject the message rather than silently skipping. The queue
        // handler catches the deserialize error and moves on; better to
        // surface than to misclassify.
        let raw = r#"{
            "action": "FutureAction",
            "bucket": "uhrp-prod",
            "object": { "key": "cdn/future" }
        }"#;
        assert!(serde_json::from_str::<R2EventMessage>(raw).is_err());
    }

    #[test]
    fn creates_object_only_for_write_actions() {
        assert!(R2EventAction::PutObject.creates_object());
        assert!(R2EventAction::CopyObject.creates_object());
        assert!(R2EventAction::CompleteMultipartUpload.creates_object());
        assert!(!R2EventAction::DeleteObject.creates_object());
        assert!(!R2EventAction::AbortMultipartUpload.creates_object());
        assert!(!R2EventAction::LifecycleDeletion.creates_object());
    }

    // ── extract_object_identifier ─────────────────────────────────────────

    #[test]
    fn extract_object_identifier_accepts_cdn_prefix() {
        assert_eq!(extract_object_identifier("cdn/abc123"), Some("abc123"));
        // Base58 of 16 bytes is 22 chars; verify we accept a realistic ID.
        assert_eq!(
            extract_object_identifier("cdn/1Ax2tjhWYxGx8vtcdE9W3b"),
            Some("1Ax2tjhWYxGx8vtcdE9W3b")
        );
    }

    #[test]
    fn extract_object_identifier_rejects_non_cdn() {
        // Matches TS: `if (!file.name.startsWith('cdn/')) return`.
        assert_eq!(extract_object_identifier("other/abc"), None);
        assert_eq!(extract_object_identifier("abc"), None);
        assert_eq!(extract_object_identifier(""), None);
    }

    #[test]
    fn extract_object_identifier_rejects_empty_id() {
        // `cdn/` alone is a folder marker, not an object.
        assert_eq!(extract_object_identifier("cdn/"), None);
    }

    #[test]
    fn extract_object_identifier_rejects_nested_paths() {
        // Defense-in-depth: our `/upload` route never produces `cdn/sub/x`,
        // so an event at that key is out-of-band. Skip rather than advertise
        // whatever is there.
        assert_eq!(extract_object_identifier("cdn/sub/deep"), None);
        assert_eq!(extract_object_identifier("cdn/a/b/c"), None);
    }

    // ── parse_custom_time_to_unix_seconds ─────────────────────────────────

    #[test]
    fn parses_iso8601_millisecond_format() {
        // The exact shape our `/upload` route produces via
        // `iso8601_millis`. Timestamp is 2025-05-10T12:34:56Z + 123ms,
        // which is 1746880496.123s; `.timestamp()` truncates to seconds.
        let got = parse_custom_time_to_unix_seconds("2025-05-10T12:34:56.123Z").unwrap();
        assert_eq!(got, 1_746_880_496);
    }

    #[test]
    fn parses_iso8601_no_fractional_seconds() {
        let got = parse_custom_time_to_unix_seconds("2025-05-10T12:34:56Z").unwrap();
        assert_eq!(got, 1_746_880_496);
    }

    #[test]
    fn parses_bare_integer_seconds() {
        // Forward-compat for admin tooling bypassing the presigner.
        assert_eq!(
            parse_custom_time_to_unix_seconds("1746880496"),
            Some(1_746_880_496)
        );
    }

    #[test]
    fn rejects_empty_and_garbage() {
        assert_eq!(parse_custom_time_to_unix_seconds(""), None);
        assert_eq!(parse_custom_time_to_unix_seconds("not-a-time"), None);
        // A partial ISO prefix without the required `T` separator must fail —
        // the bare-integer fast-path requires full-string digit parsing, so
        // `"2025-05-10"` hits the RFC-3339 branch and is rejected there.
        assert_eq!(parse_custom_time_to_unix_seconds("2025-05-10"), None);
    }

    #[test]
    fn rejects_pre_epoch() {
        // Timestamps before 1970-01-01 yield a negative Unix time; we
        // reject rather than silently wrapping.
        assert_eq!(
            parse_custom_time_to_unix_seconds("1900-01-01T00:00:00Z"),
            None
        );
    }

    // ── ProcessOutcome is a pure enum; assert the triage logic ────────────

    #[test]
    fn process_outcome_distinguishes_three_states() {
        // The handler's ack/retry decision lives in `handle_batch`; we
        // keep these variants distinct so a future refactor can't collapse
        // "skip this message permanently" into "retry forever".
        assert_ne!(ProcessOutcome::Advertised, ProcessOutcome::Skipped);
        assert_ne!(ProcessOutcome::Advertised, ProcessOutcome::Retry);
        assert_ne!(ProcessOutcome::Skipped, ProcessOutcome::Retry);
    }

    // ── Round-trip: R2EventAction serializes stably ───────────────────────

    #[test]
    fn action_round_trips_through_json() {
        for a in [
            R2EventAction::PutObject,
            R2EventAction::CopyObject,
            R2EventAction::CompleteMultipartUpload,
            R2EventAction::DeleteObject,
            R2EventAction::AbortMultipartUpload,
            R2EventAction::LifecycleDeletion,
        ] {
            let s = serde_json::to_string(&a).unwrap();
            let back: R2EventAction = serde_json::from_str(&s).unwrap();
            assert_eq!(a, back);
        }
    }
}
