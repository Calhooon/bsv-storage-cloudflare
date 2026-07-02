//! POST /upload — see PROTOCOL.md §2. BRC-31 auth + BRC-29 payment required.
//!
//! Port of `src/routes/upload.ts` + `src/utils/getUploadURL.ts`. Validation
//! order, error codes, error strings, and response field order are all copied
//! verbatim from the TS source so the parity harness against
//! nanostore.babbage.systems stays green.
//!
//! **Payment ordering**: BRC-29 payment verification runs in `lib.rs` BEFORE
//! this handler. By the time we're here, the client has paid (or this is a
//! zero-price free pass, which lib.rs produces for malformed bodies — matching
//! the TS payment middleware's `if (!fileSize || !retentionPeriod) return 0`
//! short-circuit in `src/index.ts:105–114`).
//!
//! Consequence: the 400 responses below can still fire *after* a successful
//! payment if the request body was valid-enough to price but not valid-enough
//! to honor (e.g. `fileSize > 11 GB`). This matches the TS handler exactly
//! (`src/routes/upload.ts:40–69`).

use crate::error::{
    ERR_INTERNAL_UPLOAD, ERR_INVALID_RETENTION_PERIOD, ERR_INVALID_SIZE, ERR_MISSING_IDENTITY_KEY,
    ERR_NO_RETENTION_PERIOD,
};
use crate::storage::presign::{format_amz_date, presign_put, PresignParams};
use crate::types::{ErrorBody, UploadRequest, UploadResponse};
use bsv_rs::primitives::encoding::to_base58;
use getrandom::getrandom;
use serde_json::{json, Value};
use worker::Env;

/// TS `src/routes/upload.ts:63` — explicit upper bound beyond what `/quote` enforces.
const MAX_UPLOAD_BYTES: f64 = 11_000_000_000.0;

/// GCS presigned URL validity in TS (`getUploadURL.ts:59`: `Date.now() + 604000 * 1000`).
/// Preserved verbatim — note this is 604000 seconds, NOT the full 604800 (7d) S3 max.
const UPLOAD_URL_EXPIRES_SECONDS: u64 = 604_000;

/// Custom-time buffer past expiry, `getUploadURL.ts:52`. `pub(crate)`:
/// `/renew` re-stamps custom-time with the same buffer when extending an
/// object, and the queue consumer's dup-advert guard tolerates it when
/// comparing on-chain expiries against custom-time.
pub(crate) const CUSTOM_TIME_BUFFER_SECONDS: u64 = 300;

/// Handle `POST /upload`.
///
/// `amount` is pre-computed by `lib.rs` (via the payment middleware's price
/// calculation) and passed in so the handler returns the exact satoshi figure
/// the client paid. Recomputing here would risk a drift vs. the middleware if
/// the WhatsOnChain rate shifts between calls.
pub async fn handle(body: &[u8], identity_key: &str, amount: u64, env: &Env) -> (Value, u16) {
    // TS: `if (!req.auth.identityKey)` — middleware guarantees identity_key is
    // set for authenticated routes; defensive check preserved for parity.
    if identity_key.is_empty() {
        return error(
            ERR_MISSING_IDENTITY_KEY,
            "Missing authfetch identityKey.",
            400,
        );
    }

    let req: UploadRequest = serde_json::from_slice(body).unwrap_or(UploadRequest {
        file_size: None,
        retention_period: None,
    });

    // ── Validation (order matches TS upload.ts:40–69 exactly) ───────────────

    // TS: `if (!fileSize || !Number.isInteger(fileSize) || fileSize <= 0)`
    // — a single branch with a single error code. `!fileSize` covers both
    // missing and 0; `Number.isInteger` rejects fractional; `<= 0` rejects
    // negatives. One error code: `ERR_INVALID_SIZE`.
    let file_size = match req.file_size {
        Some(v) if v.is_finite() && v > 0.0 && v.fract() == 0.0 => v,
        _ => {
            return error(
                ERR_INVALID_SIZE,
                "The file size must be a positive integer.",
                400,
            );
        }
    };

    // TS: `if (!retentionPeriod)` — missing or 0.
    let retention_period = match req.retention_period {
        Some(v) if v.is_finite() && v != 0.0 => v,
        _ => {
            return error(
                ERR_NO_RETENTION_PERIOD,
                "You must specify the number of minutes to host the file.",
                400,
            );
        }
    };

    // TS: `Number(MIN_HOSTING_MINUTES) || 0`.
    let min_hosting_minutes_raw = env
        .var("MIN_HOSTING_MINUTES")
        .ok()
        .map(|v| v.to_string())
        .unwrap_or_default();
    let min_hosting_minutes: f64 = min_hosting_minutes_raw
        .parse::<f64>()
        .ok()
        .filter(|v| v.is_finite())
        .unwrap_or(0.0);

    if retention_period < min_hosting_minutes {
        return error(
            ERR_INVALID_RETENTION_PERIOD,
            format!("The retention period must be >= {min_hosting_minutes} minutes"),
            400,
        );
    }

    // TS: explicit 11 GB ceiling unique to `/upload` (§2 validation).
    if file_size > MAX_UPLOAD_BYTES {
        return error(
            ERR_INVALID_SIZE,
            "Max supported file size is 11000000000 bytes.",
            400,
        );
    }

    // ── Generate object identifier + expiry ──────────────────────────────────

    // TS: `Utils.toBase58(Array.from(crypto.randomBytes(16)))`.
    let mut obj_bytes = [0u8; 16];
    if getrandom(&mut obj_bytes).is_err() {
        return internal_error();
    }
    let object_identifier = to_base58(&obj_bytes);

    // TS: `(retentionPeriod * 60) + Math.round(Date.now() / 1000)`.
    //
    // JS `Date.now()` returns ms; `/ 1000` then `Math.round` matches what
    // `js_sys::Date::now()` gives us (an `f64` of ms since epoch).
    let now_seconds = (js_sys::Date::now() / 1000.0).round();
    let expiry_time = (retention_period * 60.0 + now_seconds) as u64;

    // ── Generate presigned URL ───────────────────────────────────────────────

    let (upload_url, required_headers) =
        match build_presigned_upload(env, &object_identifier, identity_key, expiry_time) {
            Ok(pair) => pair,
            Err(_) => return internal_error(),
        };

    // ── Success response (field order: status, uploadURL, requiredHeaders,
    // amount, description — matches TS upload.ts:83–89 exactly) ─────────────

    (
        json!(UploadResponse {
            status: "success",
            upload_url,
            required_headers,
            amount,
            description: "File can now be uploaded.",
        }),
        200,
    )
}

fn error(code: &'static str, description: impl Into<String>, status: u16) -> (Value, u16) {
    (json!(ErrorBody::new(code, description.into())), status)
}

fn internal_error() -> (Value, u16) {
    error(
        ERR_INTERNAL_UPLOAD,
        "An internal error occurred while handling upload.",
        500,
    )
}

/// Assemble R2 SigV4 params from env vars + call [`presign_put`]. Returns
/// `(uploadURL, requiredHeaders)` on success.
fn build_presigned_upload(
    env: &Env,
    object_identifier: &str,
    identity_key: &str,
    expiry_time: u64,
) -> Result<(String, serde_json::Map<String, Value>), ()> {
    // R2 credentials — set via `wrangler secret put`.
    let access_key_id = env.secret("R2_ACCESS_KEY_ID").map_err(|_| ())?.to_string();
    let secret_access_key = env
        .secret("R2_SECRET_ACCESS_KEY")
        .map_err(|_| ())?
        .to_string();
    // R2 S3-API endpoint host: `<account_id>.r2.cloudflarestorage.com`. Stored
    // as a Worker var so we don't bake the account id into code.
    let r2_host = env.var("R2_S3_ENDPOINT_HOST").map_err(|_| ())?.to_string();
    let bucket = env.var("R2_BUCKET").map_err(|_| ())?.to_string();

    let key = format!("cdn/{object_identifier}");

    // Custom time = (expiry + 300s buffer), ISO-8601 with ms = .000Z, matching
    // JS `new Date(ms).toISOString()` output for TS parity.
    let custom_time = iso8601_millis((expiry_time + CUSTOM_TIME_BUFFER_SECONDS) * 1000);

    // Headers that are part of the signature and must be echoed by the PUT.
    // Backend-mapped from TS GCS names:
    //   x-goog-meta-uploaderidentitykey → x-amz-meta-uploaderidentitykey
    //   x-goog-custom-time              → x-amz-meta-custom-time
    // See PROTOCOL.md §C and the ambiguity note in `storage/mod.rs`.
    let signed_headers = [
        (
            "x-amz-meta-uploaderidentitykey".to_string(),
            identity_key.to_string(),
        ),
        ("x-amz-meta-custom-time".to_string(), custom_time.clone()),
    ];

    let now_secs = (js_sys::Date::now() / 1000.0) as u64;
    let (amz_date, date_stamp) = format_amz_date(now_secs);

    let upload_url = presign_put(&PresignParams {
        access_key_id: &access_key_id,
        secret_access_key: &secret_access_key,
        host: &r2_host,
        bucket: &bucket,
        key: &key,
        expires_in_seconds: UPLOAD_URL_EXPIRES_SECONDS,
        amz_date: &amz_date,
        date_stamp: &date_stamp,
        signed_headers: &signed_headers,
    });

    // Use serde_json::Map to preserve insertion order for the JSON output.
    let mut required_headers = serde_json::Map::new();
    for (k, v) in signed_headers {
        required_headers.insert(k, Value::String(v));
    }

    Ok((upload_url, required_headers))
}

/// Format Unix-epoch **milliseconds** as ISO-8601 with `.NNNZ` suffix, matching
/// JS `new Date(ms).toISOString()` output. `pub(crate)`: `/renew` reuses it so
/// a renewed object's `custom-time` is byte-identical in shape to the value
/// the presigner stamps at upload time.
pub(crate) fn iso8601_millis(ms: u64) -> String {
    let secs = ms / 1000;
    let milli = (ms % 1000) as u32;
    let (amz, _) = format_amz_date(secs);
    // `amz` is "YYYYMMDDTHHMMSSZ"; rebuild as "YYYY-MM-DDTHH:MM:SS.mmmZ".
    // Positions: 0..4 yyyy, 4..6 mm, 6..8 dd, 9..11 HH, 11..13 MM, 13..15 SS.
    format!(
        "{y}-{mo}-{da}T{h}:{m}:{s}.{ms:03}Z",
        y = &amz[0..4],
        mo = &amz[4..6],
        da = &amz[6..8],
        h = &amz[9..11],
        m = &amz[11..13],
        s = &amz[13..15],
        ms = milli,
    )
}

/// Pure, synchronous pricing helper used by **both** the payment middleware
/// (in `lib.rs`) and the `/upload` handler. Extracted here so there's one
/// source of truth for "does this body parse into a price-able request?".
///
/// Returns `None` if the body is missing, malformed, or doesn't contain
/// positive `fileSize` + `retentionPeriod` fields — matching the TS payment
/// middleware's `if (!fileSize || !retentionPeriod) return 0` short-circuit.
/// Caller turns `None` into a price of 0 (a free pass for the payment
/// middleware; the handler's own validation then produces the 400 response).
pub fn parse_pricing_inputs(body: &[u8]) -> Option<(f64, f64)> {
    let req: UploadRequest = serde_json::from_slice(body).ok()?;
    let fs = req.file_size?;
    let rp = req.retention_period?;
    if !fs.is_finite() || fs <= 0.0 || !rp.is_finite() || rp <= 0.0 {
        return None;
    }
    Some((fs, rp))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn parse_pricing_inputs_happy_path() {
        let body = br#"{"fileSize":1000000,"retentionPeriod":1440}"#;
        assert_eq!(parse_pricing_inputs(body), Some((1_000_000.0, 1440.0)));
    }

    #[test]
    fn parse_pricing_inputs_missing_fields_returns_none() {
        assert_eq!(parse_pricing_inputs(br#"{}"#), None);
        assert_eq!(
            parse_pricing_inputs(br#"{"fileSize":100}"#),
            None,
            "missing retentionPeriod"
        );
        assert_eq!(
            parse_pricing_inputs(br#"{"retentionPeriod":100}"#),
            None,
            "missing fileSize"
        );
    }

    #[test]
    fn parse_pricing_inputs_zero_returns_none() {
        // JS: !0 is truthy → `if (!fileSize || !retentionPeriod) return 0`.
        assert_eq!(
            parse_pricing_inputs(br#"{"fileSize":0,"retentionPeriod":1}"#),
            None
        );
        assert_eq!(
            parse_pricing_inputs(br#"{"fileSize":1,"retentionPeriod":0}"#),
            None
        );
    }

    #[test]
    fn parse_pricing_inputs_negative_returns_none() {
        assert_eq!(
            parse_pricing_inputs(br#"{"fileSize":-1,"retentionPeriod":1}"#),
            None
        );
    }

    #[test]
    fn parse_pricing_inputs_invalid_json_returns_none() {
        assert_eq!(parse_pricing_inputs(b"not json"), None);
        assert_eq!(parse_pricing_inputs(b""), None);
    }

    #[test]
    fn iso8601_millis_matches_js_output() {
        // JS: `new Date(1746880496123).toISOString()` === "2025-05-10T12:34:56.123Z"
        assert_eq!(
            iso8601_millis(1_746_880_496_123),
            "2025-05-10T12:34:56.123Z"
        );
    }

    #[test]
    fn iso8601_millis_zero_padded_ms() {
        assert_eq!(
            iso8601_millis(1_746_880_496_007),
            "2025-05-10T12:34:56.007Z"
        );
        assert_eq!(
            iso8601_millis(1_746_880_496_000),
            "2025-05-10T12:34:56.000Z"
        );
    }
}
