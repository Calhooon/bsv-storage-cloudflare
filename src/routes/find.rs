//! GET /find — see PROTOCOL.md §3. BRC-31 auth required, no payment.
//!
//! Port of `src/routes/find.ts` + `src/utils/getMetadata.ts`. Looks up the
//! advertisement for a UHRP URL (filtered to the caller's identity key),
//! picks the one with the latest expiry, then HEADs the object in R2 to
//! return size + content-type + expiry.
//!
//! # Error code parity
//!
//! The TS handler only ever emits three error codes on this route:
//! `ERR_MISSING_IDENTITY_KEY`, `ERR_NO_UHRP_URL`, and the catch-all
//! `ERR_FIND` (500). `ERR_NOT_FOUND` is listed in the TS route's
//! `errors:` doc manifest (`find.ts:97`) but never actually reached —
//! `getMetadata` throws a plain `Error` when nothing matches, and the
//! `try/catch` funnels every such throw into `ERR_FIND`. We match what
//! the TS server *does*, not what its doc strings suggest.
//!
//! # Caller → admin → wallet-infra
//!
//! Same model as `/list`: wallet-infra only exposes outputs owned by the
//! authenticated wallet (the admin). We scope to the calling identity by
//! adding the `uploader_identity_key_<caller>` tag.

use crate::error::{ERR_FIND, ERR_MISSING_IDENTITY_KEY, ERR_NO_UHRP_URL};
use crate::storage::head::{head_object, UHRP_BINDING};
use crate::types::{ErrorBody, FindData, FindResponse, PaginationBody};
use crate::wallet::client::Wallet;
use crate::wallet::types::ListOutputsRequest;
use serde_json::{json, Value};
use worker::{Env, Url};

/// Wallet basket name for UHRP advertisements (PROTOCOL.md §E, verbatim).
const UHRP_BASKET: &str = "uhrp advertisements";

/// Default pagination values — `src/utils/getMetadata.ts:33–34`.
const DEFAULT_LIMIT: u32 = 200;
const DEFAULT_OFFSET: i32 = 0;

const UPLOADER_TAG_PREFIX: &str = "uploader_identity_key_";
const UHRP_URL_TAG_PREFIX: &str = "uhrp_url_";
const OBJECT_ID_TAG_PREFIX: &str = "object_identifier_";
const EXPIRY_TAG_PREFIX: &str = "expiry_time_";

pub async fn handle(url: &Url, body: &[u8], identity_key: &str, env: &Env) -> (Value, u16) {
    // TS: `if (!identityKey)` — preserved defensively.
    if identity_key.is_empty() {
        return error(
            ERR_MISSING_IDENTITY_KEY,
            "Missing authfetch identityKey.",
            400,
        );
    }

    // Query param `uhrpUrl` is required.
    let uhrp_url = extract_uhrp_url_query(url);
    let Some(uhrp_url) = uhrp_url else {
        return error(
            ERR_NO_UHRP_URL,
            "You must provide a uhrpUrl query parameter",
            400,
        );
    };

    // Body is optional; defaults match TS `getMetadata.ts:33–34`.
    let pagination: PaginationBody = serde_json::from_slice(body).unwrap_or_default();
    let limit = pagination.limit.unwrap_or(DEFAULT_LIMIT);
    let offset = pagination.offset.unwrap_or(DEFAULT_OFFSET);

    // Surface any handler-internal failure as a 500 `ERR_FIND` — matches the
    // TS `catch` block at `find.ts:71–78`.
    match inner(env, identity_key, &uhrp_url, limit, offset).await {
        Ok(data) => (
            json!(FindResponse {
                status: "success",
                data,
            }),
            200,
        ),
        Err(()) => error(
            ERR_FIND,
            "An error occurred while retrieving the file from uhrpUrl.",
            500,
        ),
    }
}

async fn inner(
    env: &Env,
    identity_key: &str,
    uhrp_url: &str,
    limit: u32,
    offset: i32,
) -> Result<FindData, ()> {
    let wallet = Wallet::from_env(env).map_err(|_| ())?;

    // Tag #1: `uhrp_url_<hex-of-utf8>` (PROTOCOL.md §E).
    // Tag #2: `uploader_identity_key_<identity>` (plaintext).
    let req = ListOutputsRequest {
        basket: UHRP_BASKET.to_string(),
        tags: vec![
            format!("{UHRP_URL_TAG_PREFIX}{}", hex::encode(uhrp_url.as_bytes())),
            format!("{UPLOADER_TAG_PREFIX}{identity_key}"),
        ],
        tag_query_mode: Some("all".to_string()),
        include: None,
        include_tags: Some(true),
        include_locking_scripts: None,
        limit: Some(limit),
        offset: Some(offset),
    };

    let result = wallet.list_outputs(&req).await.map_err(|_| ())?;

    // Find the output with the largest `expiry_time_*` and extract its
    // `object_identifier_*`. Matches the reducer at
    // `src/utils/getMetadata.ts:41–53`.
    let mut max_expiry: u64 = 0;
    let mut object_identifier: Option<String> = None;

    for out in &result.outputs {
        let Some(tags) = out.tags.as_ref() else {
            continue;
        };
        let Some(obj_id) = extract_object_identifier(tags) else {
            continue;
        };
        let Some(expiry) = extract_expiry_seconds(tags) else {
            continue;
        };
        if expiry > max_expiry {
            max_expiry = expiry;
            object_identifier = Some(obj_id);
        }
    }

    let object_identifier = object_identifier.ok_or(())?;

    // TS: `if (Date.now() > maxpiry * 1000) throw ...` (`getMetadata.ts:59`).
    let now_ms = js_sys::Date::now();
    if now_ms > (max_expiry as f64) * 1000.0 {
        return Err(());
    }

    // R2 HEAD for size + content type.
    let key = format!("cdn/{object_identifier}");
    let head = head_object(env, UHRP_BINDING, &key)
        .await
        .map_err(|_| ())?
        .ok_or(())?;

    Ok(FindData {
        // TS: `gcsMetadata.name` — on R2 the analogue is the object key,
        // which has the same `cdn/<id>` shape.
        name: head.key,
        // TS: `String(size ?? '')`. R2 always reports a u64; stringify.
        size: head.size.to_string(),
        mime_type: head.content_type,
        expiry_time: max_expiry,
    })
}

fn error(code: &'static str, description: impl Into<String>, status: u16) -> (Value, u16) {
    (json!(ErrorBody::new(code, description.into())), status)
}

/// Pull the `uhrpUrl` query parameter out of the request URL. Returns `None`
/// when the param is absent or empty (matches TS `if (!uhrpUrl)` at
/// `find.ts:47`).
fn extract_uhrp_url_query(url: &Url) -> Option<String> {
    url.query_pairs()
        .find(|(k, _)| k == "uhrpUrl")
        .map(|(_, v)| v.into_owned())
        .filter(|s| !s.is_empty())
}

/// Validate a UHRP URL's surface shape. PROTOCOL.md §A defers the exact hash
/// algorithm to `@bsv/sdk::StorageUtils`; we perform a cheap syntactic check
/// only. TS doesn't validate here either — it hands the string to
/// `StorageUtils.getHashFromURL` inside the SDK. A bogus URL will simply
/// match zero outputs and 500-out as `ERR_FIND`. We expose this helper
/// for unit tests and for future callers that want pre-flight validation.
#[allow(dead_code)]
fn is_valid_uhrp_url_shape(s: &str) -> bool {
    // Must start with `uhrp://`, must have at least one char of body, and
    // the body must look like plausible base58check (no whitespace, no
    // control chars). Length bounds are intentionally loose — task #5
    // sidesteps the SDK hash algorithm per PROTOCOL.md §A's note.
    const PREFIX: &str = "uhrp://";
    let Some(body) = s.strip_prefix(PREFIX) else {
        return false;
    };
    if body.is_empty() {
        return false;
    }
    body.chars().all(|c| !c.is_whitespace() && !c.is_control())
}

/// Decode the `object_identifier_<hex>` tag into a UTF-8 string. Returns
/// `None` if absent/invalid.
fn extract_object_identifier(tags: &[String]) -> Option<String> {
    let tag = tags.iter().find(|t| t.starts_with(OBJECT_ID_TAG_PREFIX))?;
    let hex_part = &tag[OBJECT_ID_TAG_PREFIX.len()..];
    let bytes = hex::decode(hex_part).ok()?;
    String::from_utf8(bytes).ok()
}

/// Parse the `expiry_time_<decimal>` tag. Returns `None` if missing; `Some(0)`
/// is possible for an explicit `expiry_time_0` (and will always be filtered
/// as "expired" by the `Date.now()` comparison above).
fn extract_expiry_seconds(tags: &[String]) -> Option<u64> {
    tags.iter()
        .find(|t| t.starts_with(EXPIRY_TAG_PREFIX))
        .and_then(|t| t[EXPIRY_TAG_PREFIX.len()..].parse::<u64>().ok())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // ── UHRP URL shape validation ──────────────────────────────────────────

    #[test]
    fn is_valid_uhrp_url_accepts_well_formed() {
        assert!(is_valid_uhrp_url_shape("uhrp://abc123def456"));
        assert!(is_valid_uhrp_url_shape(
            "uhrp://XUT76BxnjKMchLyNe1VuQRxkvLVSLD21QXwM4JywLKabu"
        ));
    }

    #[test]
    fn is_valid_uhrp_url_rejects_missing_scheme() {
        assert!(!is_valid_uhrp_url_shape("abc123"));
        assert!(!is_valid_uhrp_url_shape("http://abc123"));
        assert!(!is_valid_uhrp_url_shape("uhrp:abc"));
        assert!(!is_valid_uhrp_url_shape("uhrp:/abc"));
    }

    #[test]
    fn is_valid_uhrp_url_rejects_empty_body() {
        assert!(!is_valid_uhrp_url_shape("uhrp://"));
    }

    #[test]
    fn is_valid_uhrp_url_rejects_whitespace_or_control() {
        assert!(!is_valid_uhrp_url_shape("uhrp://abc def"));
        assert!(!is_valid_uhrp_url_shape("uhrp://abc\n"));
        assert!(!is_valid_uhrp_url_shape("uhrp://abc\t"));
    }

    #[test]
    fn is_valid_uhrp_url_rejects_empty_string() {
        assert!(!is_valid_uhrp_url_shape(""));
    }

    // ── Query parsing ───────────────────────────────────────────────────────

    #[test]
    fn extract_uhrp_url_query_finds_param() {
        let u = Url::parse("https://example.com/find?uhrpUrl=uhrp://abc").unwrap();
        assert_eq!(extract_uhrp_url_query(&u).as_deref(), Some("uhrp://abc"));
    }

    #[test]
    fn extract_uhrp_url_query_missing_returns_none() {
        let u = Url::parse("https://example.com/find").unwrap();
        assert!(extract_uhrp_url_query(&u).is_none());
    }

    #[test]
    fn extract_uhrp_url_query_empty_returns_none() {
        let u = Url::parse("https://example.com/find?uhrpUrl=").unwrap();
        assert!(extract_uhrp_url_query(&u).is_none());
    }

    #[test]
    fn extract_uhrp_url_query_ignores_other_params() {
        let u = Url::parse("https://example.com/find?foo=bar&uhrpUrl=uhrp://x").unwrap();
        assert_eq!(extract_uhrp_url_query(&u).as_deref(), Some("uhrp://x"));
    }

    // ── Tag parsing ────────────────────────────────────────────────────────

    #[test]
    fn extract_object_identifier_decodes_hex_utf8() {
        let tag = format!("object_identifier_{}", hex::encode("abc123".as_bytes()));
        let tags = vec![tag];
        assert_eq!(extract_object_identifier(&tags).as_deref(), Some("abc123"));
    }

    #[test]
    fn extract_object_identifier_returns_none_for_invalid_hex() {
        let tags = vec!["object_identifier_zz".to_string()];
        assert!(extract_object_identifier(&tags).is_none());
    }

    #[test]
    fn extract_object_identifier_returns_none_when_missing() {
        let tags = vec!["uhrp_url_deadbeef".to_string()];
        assert!(extract_object_identifier(&tags).is_none());
    }

    #[test]
    fn extract_expiry_parses_decimal() {
        let tags = vec!["expiry_time_1735689600".to_string()];
        assert_eq!(extract_expiry_seconds(&tags), Some(1_735_689_600));
    }

    #[test]
    fn extract_expiry_returns_none_when_missing() {
        let tags = vec!["uhrp_url_00".to_string()];
        assert!(extract_expiry_seconds(&tags).is_none());
    }

    #[test]
    fn extract_expiry_returns_none_when_malformed() {
        let tags = vec!["expiry_time_nope".to_string()];
        assert!(extract_expiry_seconds(&tags).is_none());
    }

    // ── Response shapes ─────────────────────────────────────────────────────

    #[test]
    fn find_response_serializes_with_expected_field_order() {
        // PROTOCOL.md §3: `{status, data: {name, size, mimeType, expiryTime}}`.
        let body = FindResponse {
            status: "success",
            data: FindData {
                name: "cdn/abc123".to_string(),
                size: "4096".to_string(),
                mime_type: "application/octet-stream".to_string(),
                expiry_time: 1_735_689_600,
            },
        };
        let got = serde_json::to_string(&body).unwrap();
        assert_eq!(
            got,
            r#"{"status":"success","data":{"name":"cdn/abc123","size":"4096","mimeType":"application/octet-stream","expiryTime":1735689600}}"#
        );
    }

    #[test]
    fn error_body_shape_for_err_no_uhrp_url() {
        let err = ErrorBody::new(
            ERR_NO_UHRP_URL,
            "You must provide a uhrpUrl query parameter",
        );
        let got = serde_json::to_string(&err).unwrap();
        assert_eq!(
            got,
            r#"{"status":"error","code":"ERR_NO_UHRP_URL","description":"You must provide a uhrpUrl query parameter"}"#
        );
    }

    #[test]
    fn error_body_shape_for_err_find() {
        let err = ErrorBody::new(
            ERR_FIND,
            "An error occurred while retrieving the file from uhrpUrl.",
        );
        let got = serde_json::to_string(&err).unwrap();
        assert_eq!(
            got,
            r#"{"status":"error","code":"ERR_FIND","description":"An error occurred while retrieving the file from uhrpUrl."}"#
        );
    }

    #[test]
    fn error_body_shape_for_missing_identity_key() {
        let err = ErrorBody::new(ERR_MISSING_IDENTITY_KEY, "Missing authfetch identityKey.");
        let got = serde_json::to_string(&err).unwrap();
        assert_eq!(
            got,
            r#"{"status":"error","code":"ERR_MISSING_IDENTITY_KEY","description":"Missing authfetch identityKey."}"#
        );
    }
}
