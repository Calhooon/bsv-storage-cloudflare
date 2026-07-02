//! R2 custom-time extension for `/renew` — the R2 replacement of the TS
//! server's GCS `file.setMetadata({ customTime })` call (`renew.ts:212–213`).
//!
//! R2 exposes no metadata-patch API (neither the Workers binding nor the
//! S3-compat surface can update metadata in place), so the only way to
//! refresh `custom-time` is a **same-key copy**: GET the object, PUT it
//! back at the same key with the refreshed `custom-time` while preserving
//! every other custom-metadata pair (notably `uploaderidentitykey`) and
//! the HTTP metadata (Content-Type etc.).
//!
//! # Memory note
//!
//! The body round-trips through the Worker because R2 bindings have no
//! server-side copy. This shares the ~128 MB ceiling documented on
//! `queue::hash_r2_object` — acceptable for the same reason (the queue
//! consumer already buffers the full body to hash it, so any object that
//! got auto-advertised fits).
//!
//! # Event note
//!
//! The PUT re-fires the R2 object-create notification onto the
//! post-upload queue. The consumer's dup-advert guard
//! (`queue::advert_already_covers`) recognizes that an unexpired advert
//! already covers the object's custom-time horizon and skips it — see the
//! warning in the renew redesign (a copy without that guard would mint a
//! duplicate advertisement).

use worker::Env;

/// R2 custom metadata key carrying the advertisement expiry as ISO-8601.
/// Same key the `/upload` presigner signs (`x-amz-meta-custom-time`) and
/// the queue consumer reads (`queue::METADATA_KEY_CUSTOM_TIME`).
const METADATA_KEY_CUSTOM_TIME: &str = "custom-time";

/// Same-key copy of `key` in `binding` with `custom-time` replaced by
/// `custom_time` (ISO-8601, produced by `routes::upload::iso8601_millis`).
/// All other custom metadata and the HTTP metadata are preserved.
///
/// Returns:
/// - `Ok(())` — object rewritten with the refreshed custom-time
/// - `Err(code)` — binding missing, object gone, or R2 transport failure.
///   The `&'static str` code follows the project's error-classification
///   convention (see `storage::head::head_object`).
pub async fn extend_custom_time(
    env: &Env,
    binding: &str,
    key: &str,
    custom_time: &str,
) -> Result<(), &'static str> {
    let bucket = env.bucket(binding).map_err(|_| "ERR_R2_BINDING")?;

    let maybe_obj = bucket
        .get(key.to_string())
        .execute()
        .await
        .map_err(|_| "ERR_R2_GET")?;
    let obj = maybe_obj.ok_or("ERR_R2_NOT_FOUND")?;

    // Preserve HTTP metadata + every custom-metadata pair except the one
    // we're refreshing. `custom_metadata()` can fail through JS interop;
    // fall back to an empty map (same posture as `head_object`) — a lost
    // `uploaderidentitykey` only means the queue consumer skips the event,
    // which the dup-advert guard would have done anyway.
    let http_metadata = obj.http_metadata();
    let mut custom_metadata = obj.custom_metadata().unwrap_or_default();
    custom_metadata.insert(
        METADATA_KEY_CUSTOM_TIME.to_string(),
        custom_time.to_string(),
    );

    let body = obj.body().ok_or("ERR_R2_EMPTY_BODY")?;
    let bytes = body.bytes().await.map_err(|_| "ERR_R2_READ")?;

    bucket
        .put(key.to_string(), bytes)
        .http_metadata(http_metadata)
        .custom_metadata(custom_metadata)
        .execute()
        .await
        .map_err(|_| "ERR_R2_PUT")?;

    Ok(())
}
