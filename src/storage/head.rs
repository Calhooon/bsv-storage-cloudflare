//! R2 `HEAD` helper for object metadata — the `/find` route's GCS-replacement.
//!
//! The TS server fetches object metadata via
//! `storage.bucket(GCP_BUCKET_NAME).file(\`cdn/${objectIdentifier}\`).getMetadata()`
//! in `src/utils/getMetadata.ts:63–65`. On Cloudflare R2 the equivalent is
//! `env.bucket("UHRP_FILES")?.head(key).await`, which returns
//! [`worker::Object`] with all the metadata we need (no body).
//!
//! # Backend mapping (R2 vs GCS)
//!
//! The TS route returns `{name, size, contentType}` read from GCS. On R2:
//!
//! | TS (GCS)                       | Rust (R2)                                 |
//! |--------------------------------|-------------------------------------------|
//! | `gcsMetadata.name`             | `object.key()` (same shape: `cdn/<id>`)   |
//! | `gcsMetadata.size`             | `object.size()` (u64, stringified later)  |
//! | `gcsMetadata.contentType`      | `object.http_metadata().content_type`     |
//!
//! The mapping is lossless for the fields PROTOCOL.md §3 requires — see
//! `storage/mod.rs` for the broader backend-ambiguity note.

use std::collections::HashMap;
use worker::Env;

/// Metadata extracted from an R2 HEAD, shaped for the `/find` handler.
///
/// Owned `String`s so the caller can move them into a response body without
/// tripping the R2 binding's lifetime requirements.
#[derive(Debug, Clone)]
pub struct ObjectHead {
    /// Object key (e.g. `"cdn/abc123"`). Same shape as GCS's `name`.
    pub key: String,
    /// Size in bytes.
    pub size: u64,
    /// Content-Type, from HTTP metadata. Empty string when R2 has no
    /// `Content-Type` set (matches TS's `contentType = ''` fallback in
    /// `getMetadata.ts:70`).
    pub content_type: String,
    /// Custom user metadata (`x-amz-meta-*` on upload). Lowercased keys. The
    /// `/find` handler doesn't need these today but they're captured so
    /// future queue-consumer work (task 9) can reuse the same helper.
    #[allow(dead_code)]
    pub custom_metadata: HashMap<String, String>,
}

/// Run a HEAD on the `UHRP_FILES` binding.
///
/// Returns:
/// - `Ok(Some(head))` — object exists, metadata extracted
/// - `Ok(None)` — object does not exist (R2 returned null)
/// - `Err(msg)` — binding missing, transport error, or JS interop failure.
///   Caller maps this to HTTP 500 with `ERR_FIND`.
///
/// The error is a `&'static str` to keep it compatible with the project's
/// error-classification convention (see `wallet::client::classify_rpc_error`).
pub async fn head_object(
    env: &Env,
    binding: &str,
    key: &str,
) -> Result<Option<ObjectHead>, &'static str> {
    let bucket = env.bucket(binding).map_err(|_| "ERR_R2_BINDING")?;
    let maybe_obj = bucket
        .head(key.to_string())
        .await
        .map_err(|_| "ERR_R2_HEAD")?;

    let Some(obj) = maybe_obj else {
        return Ok(None);
    };

    // R2's `custom_metadata` can fail through JS interop (e.g. non-string
    // values); fall back to an empty map rather than propagating — matches
    // TS's loose `{}` default when the key is absent.
    let custom_metadata = obj.custom_metadata().unwrap_or_default();
    let content_type = obj.http_metadata().content_type.unwrap_or_default();

    Ok(Some(ObjectHead {
        key: obj.key(),
        size: obj.size(),
        content_type,
        custom_metadata,
    }))
}

/// R2 binding name used by the UHRP storage server. Kept as a module-level
/// constant so the `/find` route and future consumers share one source of
/// truth. Mirrors the `[[r2_buckets]] binding` in `wrangler.toml`.
pub const UHRP_BINDING: &str = "UHRP_FILES";
