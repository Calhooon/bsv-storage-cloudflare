//! GET /list — see PROTOCOL.md §4. BRC-31 auth required, no payment.
//!
//! Port of `src/routes/list.ts`. Lists every UHRP advertisement in the admin
//! wallet's `"uhrp advertisements"` basket that is tagged with the caller's
//! identity key.
//!
//! # Caller → admin → wallet-infra
//!
//! wallet-infra only surfaces outputs owned by the authenticated wallet
//! identity — here, the admin (`ADMIN_WALLET_PRIVATE_KEY`). So the query
//! `listOutputs({ basket, tags: [...] })` runs against the **admin's**
//! basket. To scope results to the BRC-31 caller, we append the tag
//! `uploader_identity_key_<caller_identity_key>` — the same tag the
//! `/advertise` handler writes at publish time (§E). The basket is owned
//! by the admin, but each output is labeled with the real uploader.

use crate::error::{ERR_LIST, ERR_MISSING_IDENTITY_KEY};
use crate::types::{ErrorBody, ListResponse, ListUpload, PaginationBody};
use crate::wallet::client::Wallet;
use crate::wallet::types::ListOutputsRequest;
use serde_json::{json, Value};
use worker::{Env, Url};

/// Wallet basket name for UHRP advertisements (PROTOCOL.md §E, verbatim).
const UHRP_BASKET: &str = "uhrp advertisements";

/// Default `limit` if the request body omits it (TS `src/routes/list.ts:39`).
const DEFAULT_LIMIT: u32 = 200;

/// Default `offset` (TS `src/routes/list.ts:39`).
const DEFAULT_OFFSET: i32 = 0;

/// Tag prefix keying each advertisement to its uploader (PROTOCOL.md §E).
const UPLOADER_TAG_PREFIX: &str = "uploader_identity_key_";

/// Tag prefix encoding the UHRP URL as hex-UTF-8 bytes.
const UHRP_URL_TAG_PREFIX: &str = "uhrp_url_";

/// Tag prefix carrying the Unix-seconds expiry as a decimal string.
const EXPIRY_TAG_PREFIX: &str = "expiry_time_";

pub async fn handle(_url: &Url, body: &[u8], identity_key: &str, env: &Env) -> (Value, u16) {
    // TS: `if (!req.auth.identityKey)` — middleware guarantees this, but the
    // defensive check is preserved for parity with `src/routes/list.ts:29–35`.
    if identity_key.is_empty() {
        return error(
            ERR_MISSING_IDENTITY_KEY,
            "Missing authfetch identityKey.",
            400,
        );
    }

    // GET with an optional JSON body. TS reads `const { limit = 200, offset = 0 } = req.body`
    // (`list.ts:39`). A missing/empty/malformed body → both defaults apply.
    let pagination: PaginationBody = serde_json::from_slice(body).unwrap_or_default();
    let limit = pagination.limit.unwrap_or(DEFAULT_LIMIT);
    let offset = pagination.offset.unwrap_or(DEFAULT_OFFSET);

    // The "server right now" wall clock for expiry filtering. Captured once
    // so every row sees the same `now`. TS uses `Date.now()` inside the loop
    // (same semantics — within a single tick `Date.now()` is constant).
    let now_ms = js_sys::Date::now();

    let wallet = match Wallet::from_env(env) {
        Ok(w) => w,
        Err(_) => return error(ERR_LIST, "Error listing user-uploaded advertisements.", 500),
    };

    let req = ListOutputsRequest {
        basket: UHRP_BASKET.to_string(),
        tags: vec![format!("{UPLOADER_TAG_PREFIX}{identity_key}")],
        // TS: `tagQueryMode: 'all'` (`list.ts:45`). Even with a single tag we
        // pass `"all"` to match the wire exactly.
        tag_query_mode: Some("all".to_string()),
        include: None,
        include_tags: Some(true),
        limit: Some(limit),
        offset: Some(offset),
    };

    let result = match wallet.list_outputs(&req).await {
        Ok(r) => r,
        Err(_) => return error(ERR_LIST, "Error listing user-uploaded advertisements.", 500),
    };

    let mut uploads: Vec<ListUpload> = Vec::with_capacity(result.outputs.len());
    for out in result.outputs {
        let Some(tags) = out.tags.as_ref() else {
            continue;
        };

        let Some(uhrp_url) = extract_uhrp_url(tags) else {
            // Tag missing/invalid hex — skip. Matches TS where the default
            // empty string would still be pushed; we'd rather drop the row
            // than leak a malformed URL into the response.
            continue;
        };
        let expiry_time = extract_expiry_seconds(tags);

        // TS: `if (Date.now() > expiryTime * 1000) continue` (`list.ts:65`).
        if now_ms > (expiry_time as f64) * 1000.0 {
            continue;
        }

        uploads.push(ListUpload {
            uhrp_url,
            expiry_time,
        });
    }

    (
        json!(ListResponse {
            status: "success",
            uploads,
        }),
        200,
    )
}

fn error(code: &'static str, description: impl Into<String>, status: u16) -> (Value, u16) {
    (json!(ErrorBody::new(code, description.into())), status)
}

/// Decode the `uhrp_url_<hex>` tag into a UTF-8 string. Returns `None` if the
/// tag is absent or the hex payload doesn't decode to valid UTF-8.
fn extract_uhrp_url(tags: &[String]) -> Option<String> {
    let tag = tags.iter().find(|t| t.starts_with(UHRP_URL_TAG_PREFIX))?;
    let hex_part = &tag[UHRP_URL_TAG_PREFIX.len()..];
    let bytes = hex::decode(hex_part).ok()?;
    String::from_utf8(bytes).ok()
}

/// Parse the `expiry_time_<decimal>` tag into a `u64`. Missing or malformed
/// → 0, which matches TS's `parseInt(...)` → `NaN` → `0` fallback plus the
/// subsequent "expired" filter (a 0 expiry is always before `now`).
fn extract_expiry_seconds(tags: &[String]) -> u64 {
    tags.iter()
        .find(|t| t.starts_with(EXPIRY_TAG_PREFIX))
        .and_then(|t| t[EXPIRY_TAG_PREFIX.len()..].parse::<u64>().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::types::ListResponse;

    #[test]
    fn extract_uhrp_url_decodes_hex_utf8() {
        // "uhrp://abc" hex-encoded = 75687270 3a2f2f 616263 → 756872703a2f2f616263
        let tag = format!("uhrp_url_{}", hex::encode("uhrp://abc".as_bytes()));
        let tags = vec![tag];
        assert_eq!(extract_uhrp_url(&tags).as_deref(), Some("uhrp://abc"));
    }

    #[test]
    fn extract_uhrp_url_returns_none_for_missing_tag() {
        let tags = vec!["expiry_time_123".to_string()];
        assert!(extract_uhrp_url(&tags).is_none());
    }

    #[test]
    fn extract_uhrp_url_returns_none_for_invalid_hex() {
        let tags = vec!["uhrp_url_not-hex".to_string()];
        assert!(extract_uhrp_url(&tags).is_none());
    }

    #[test]
    fn extract_uhrp_url_returns_none_for_invalid_utf8() {
        // 0xff is not valid UTF-8 as a lone byte.
        let tags = vec!["uhrp_url_ff".to_string()];
        assert!(extract_uhrp_url(&tags).is_none());
    }

    #[test]
    fn extract_expiry_parses_decimal() {
        let tags = vec!["expiry_time_1735689600".to_string()];
        assert_eq!(extract_expiry_seconds(&tags), 1_735_689_600);
    }

    #[test]
    fn extract_expiry_defaults_to_zero_when_missing() {
        let tags = vec!["uhrp_url_deadbeef".to_string()];
        assert_eq!(extract_expiry_seconds(&tags), 0);
    }

    #[test]
    fn extract_expiry_defaults_to_zero_when_malformed() {
        let tags = vec!["expiry_time_notanumber".to_string()];
        assert_eq!(extract_expiry_seconds(&tags), 0);
    }

    #[test]
    fn pagination_defaults_to_200_and_0_when_body_empty() {
        let pagination: PaginationBody = serde_json::from_slice(b"").unwrap_or_default();
        assert_eq!(pagination.limit.unwrap_or(DEFAULT_LIMIT), 200);
        assert_eq!(pagination.offset.unwrap_or(DEFAULT_OFFSET), 0);
    }

    #[test]
    fn pagination_defaults_to_200_and_0_when_body_empty_object() {
        let pagination: PaginationBody = serde_json::from_slice(b"{}").unwrap_or_default();
        assert_eq!(pagination.limit.unwrap_or(DEFAULT_LIMIT), 200);
        assert_eq!(pagination.offset.unwrap_or(DEFAULT_OFFSET), 0);
    }

    #[test]
    fn pagination_parses_explicit_values() {
        let pagination: PaginationBody =
            serde_json::from_slice(br#"{"limit":5,"offset":10}"#).unwrap();
        assert_eq!(pagination.limit, Some(5));
        assert_eq!(pagination.offset, Some(10));
    }

    #[test]
    fn list_response_serializes_with_expected_field_order() {
        // PROTOCOL.md §4: `{status, uploads: [{uhrpUrl, expiryTime}]}`.
        let body = ListResponse {
            status: "success",
            uploads: vec![ListUpload {
                uhrp_url: "uhrp://abc123".to_string(),
                expiry_time: 1_735_689_600,
            }],
        };
        let got = serde_json::to_string(&body).unwrap();
        assert_eq!(
            got,
            r#"{"status":"success","uploads":[{"uhrpUrl":"uhrp://abc123","expiryTime":1735689600}]}"#
        );
    }

    #[test]
    fn list_response_empty_uploads() {
        let body = ListResponse {
            status: "success",
            uploads: vec![],
        };
        let got = serde_json::to_string(&body).unwrap();
        assert_eq!(got, r#"{"status":"success","uploads":[]}"#);
    }

    #[test]
    fn error_body_shape_for_err_list() {
        let err = ErrorBody::new(ERR_LIST, "Error listing user-uploaded advertisements.");
        let got = serde_json::to_string(&err).unwrap();
        assert_eq!(
            got,
            r#"{"status":"error","code":"ERR_LIST","description":"Error listing user-uploaded advertisements."}"#
        );
    }

    #[test]
    fn error_body_shape_for_missing_identity() {
        let err = ErrorBody::new(ERR_MISSING_IDENTITY_KEY, "Missing authfetch identityKey.");
        let got = serde_json::to_string(&err).unwrap();
        assert_eq!(
            got,
            r#"{"status":"error","code":"ERR_MISSING_IDENTITY_KEY","description":"Missing authfetch identityKey."}"#
        );
    }
}
