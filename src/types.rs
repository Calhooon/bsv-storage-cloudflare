//! Shared request/response shapes. Every route body is a named struct — no
//! `serde_json::Value`-typed handlers — so drift from PROTOCOL.md is a compile error.

#![allow(dead_code)] // Scaffold: types consumed as routes land in tasks #3–#7.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorBody {
    pub status: &'static str,
    pub code: String,
    pub description: String,
}

impl ErrorBody {
    pub fn new(code: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            status: "error",
            code: code.into(),
            description: description.into(),
        }
    }
}

/// Request body for `POST /quote`. Fields are optional (`None`) so we can
/// distinguish "missing" from "invalid value" and produce the exact TS error
/// codes (`ERR_NO_SIZE` vs `ERR_INVALID_SIZE`). Deserialized as `f64` because
/// the TS handler accepts JSON numbers and explicitly checks integer-ness.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuoteRequest {
    pub file_size: Option<f64>,
    pub retention_period: Option<f64>,
}

/// Success response for `POST /quote` (PROTOCOL.md §1).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuoteResponse {
    pub quote: u64,
}

/// Request body for `POST /upload` (PROTOCOL.md §2).
///
/// Same shape as `QuoteRequest`. Kept as its own type so route-specific
/// validation (§2's 11 GB `ERR_INVALID_SIZE` ceiling vs. §1's 130-year
/// retention ceiling) doesn't cross-contaminate.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadRequest {
    pub file_size: Option<f64>,
    pub retention_period: Option<f64>,
}

/// Success response for `POST /upload` (PROTOCOL.md §2).
///
/// Field order is load-bearing — `serde_json` preserves struct field order
/// and the parity harness compares raw bytes against nanostore. TS returns
/// `{status, uploadURL, requiredHeaders, amount, description}` in that exact
/// sequence (`src/routes/upload.ts:83–89`).
#[derive(Debug, Serialize)]
pub struct UploadResponse {
    pub status: &'static str,
    #[serde(rename = "uploadURL")]
    pub upload_url: String,
    /// Metadata headers the client MUST echo on the PUT. `serde_json::Map`
    /// preserves insertion order for the JSON output.
    #[serde(rename = "requiredHeaders")]
    pub required_headers: serde_json::Map<String, serde_json::Value>,
    pub amount: u64,
    pub description: &'static str,
}

// ────────────────────────────────────────────────────────────────────────────
// /find (PROTOCOL.md §3) + /list (§4) — both use a shared pagination body.
// ────────────────────────────────────────────────────────────────────────────

/// Shared pagination body for `GET /find` and `GET /list` (PROTOCOL.md §3/§4).
///
/// The TS server reads `limit`/`offset` from `req.body` even on GET requests
/// (Express happily parses a body on any method if `Content-Type` permits).
/// Both fields are optional; `None` triggers the TS defaults (200 / 0).
#[derive(Debug, Default, Deserialize)]
pub struct PaginationBody {
    pub limit: Option<u32>,
    pub offset: Option<i32>,
}

/// Parsed `GET /find` request. `uhrpUrl` lives in the query string; `limit`
/// and `offset` come from the body per `src/routes/find.ts:45–46`.
#[derive(Debug)]
pub struct FindRequest {
    pub uhrp_url: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<i32>,
}

/// Inner `data` object of a successful `/find` response. Field order matches
/// TS (`src/routes/find.ts:64–69`): `name`, `size`, `mimeType`, `expiryTime`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindData {
    /// File path key (e.g. `"cdn/abc123def456"`). In TS: `gcsMetadata.name`;
    /// in the R2 port: the object key, which has the same shape.
    pub name: String,
    /// File size in bytes, encoded **as a string** for TS parity
    /// (`String(size ?? '')` in `getMetadata.ts:76`).
    pub size: String,
    /// Content-Type, from R2 HTTP metadata (in TS: `gcsMetadata.contentType`).
    pub mime_type: String,
    /// Advertisement expiry (Unix seconds).
    pub expiry_time: u64,
}

/// Success response for `GET /find` (PROTOCOL.md §3). Field order matches TS
/// (`src/routes/find.ts:62–70`): `status`, `data`.
#[derive(Debug, Serialize)]
pub struct FindResponse {
    pub status: &'static str,
    pub data: FindData,
}

/// One row of the `/list` response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListUpload {
    /// Decoded UHRP URL (from the `uhrp_url_<hex>` tag).
    pub uhrp_url: String,
    /// Advertisement expiry (Unix seconds, from the `expiry_time_<n>` tag).
    pub expiry_time: u64,
}

/// Success response for `GET /list` (PROTOCOL.md §4). Field order matches TS
/// (`src/routes/list.ts:75–78`): `status`, `uploads`.
#[derive(Debug, Serialize)]
pub struct ListResponse {
    pub status: &'static str,
    pub uploads: Vec<ListUpload>,
}

// ────────────────────────────────────────────────────────────────────────────
// /renew (PROTOCOL.md §5)
// ────────────────────────────────────────────────────────────────────────────

/// Request body for `POST /renew`.
///
/// `additionalMinutes` is deserialized as `f64` (mirroring `/upload`) so the
/// TS handler's integer-ness + positivity checks can be ported verbatim with
/// a single error code per branch. `limit`/`offset` mirror the shared
/// `PaginationBody` but ride on the renew body itself (`src/routes/renew.ts:45`).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenewRequest {
    pub uhrp_url: Option<String>,
    pub additional_minutes: Option<f64>,
    pub limit: Option<u32>,
    pub offset: Option<i32>,
}

/// Success response for `POST /renew` (PROTOCOL.md §5). Field order matches
/// TS (`src/routes/renew.ts:215–220`): `status, prevExpiryTime, newExpiryTime,
/// amount`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenewResponse {
    pub status: &'static str,
    pub prev_expiry_time: u64,
    pub new_expiry_time: u64,
    pub amount: u64,
}

// ────────────────────────────────────────────────────────────────────────────
// /advertise (PROTOCOL.md §6)
// ────────────────────────────────────────────────────────────────────────────

/// Request body for `POST /advertise`.
///
/// The TS server gates this route with an in-body `adminToken` string
/// (`src/routes/advertise.ts:14–23`). The Rust port replaces that with a
/// BRC-31 identity-key allowlist (`ADMIN_IDENTITY_KEYS` secret) — the caller
/// must already be authenticated, and the handler verifies their identity
/// key is in the allowlist before proceeding. `adminToken` is therefore
/// absent from the Rust request shape; this is a deliberate deviation from
/// TS (wider protocol used CF Worker patterns, not the TS admin-token scheme).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvertiseRequest {
    pub uhrp_url: Option<String>,
    pub object_identifier: Option<String>,
    pub uploader_identity_key: Option<String>,
    pub file_size: Option<f64>,
    pub expiry_time: Option<f64>,
}

/// Success response for `POST /advertise` (PROTOCOL.md §6). TS returns a bare
/// `{status: 'success'}`; we match that exactly (`src/routes/advertise.ts:60`).
#[derive(Debug, Serialize)]
pub struct AdvertiseResponse {
    pub status: &'static str,
}

// ────────────────────────────────────────────────────────────────────────────
// /drafts (composer-storage instance only — not part of nanostore parity)
// ────────────────────────────────────────────────────────────────────────────
//
// Score-draft sync for github.com/Calgooon/the-composer (issue #16). Drafts
// are small per-identity JSON blobs in the `COMPOSER_DRAFTS` KV namespace,
// scoped by the BRC-103/104-authenticated identity key. These routes only
// exist where that binding is configured (wrangler.composer.toml); on the
// primary deployment they answer 404 like any unknown path.

/// Request body for `PUT /drafts/:id` (the id rides in the path).
///
/// Every field optional at parse time so validation can name the exact
/// missing/invalid field (mirrors the `QuoteRequest` pattern). Numbers are
/// `f64` because JSON numbers arrive as doubles; integer-ness is checked in
/// `routes::drafts::validate_put_body`. `state` is the one intentionally
/// opaque interior — the builder UI owns its shape; the server only derives
/// summary counts from it when the well-known shape is recognizable.
///
/// `sectionCount`/`partCount` are client-supplied fallbacks used only when
/// the counts are NOT derivable from `state` (bound-checked: integers ≥ 0).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutDraftRequest {
    pub title: Option<String>,
    pub updated_at: Option<f64>,
    /// Opaque builder state. JSON `null` and a missing field both
    /// deserialize to `None` and are rejected — a draft without state is
    /// not worth syncing (slight tightening vs. "present" checks that
    /// admit `null`; the real client always sends an object).
    #[serde(default)]
    pub state: Option<serde_json::Value>,
    pub section_count: Option<f64>,
    pub part_count: Option<f64>,
}

/// A full draft — the stored KV value and the `GET /drafts/:id` response
/// body, byte-identical. Field order is load-bearing (serde preserves
/// struct order; the client signs/verifies exact body bytes via AuthFetch).
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftBody {
    /// Lowercase RFC 4122 UUID (client-chosen, validated server-side).
    pub id: String,
    /// Display title; may be empty. ≤ 256 UTF-8 bytes, no control chars.
    pub title: String,
    /// Client-clock ms epoch of the last edit — the conflict ordinal.
    pub updated_at: u64,
    /// Opaque builder state, echoed back verbatim.
    pub state: serde_json::Value,
}

/// One row of `GET /drafts` (sorted `updatedAt` descending).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftSummaryBody {
    pub id: String,
    pub title: String,
    pub updated_at: u64,
    pub section_count: u64,
    pub part_count: u64,
}

/// Success response for `GET /drafts`.
#[derive(Debug, Serialize)]
pub struct DraftsListResponse {
    pub drafts: Vec<DraftSummaryBody>,
}

/// A delete tombstone — the KV value at `tombstone:<identityKey>:<id>`
/// (the-composer #27; contract documented in `routes::drafts`).
///
/// `deletedAt` is the delete's last-write-wins ordinal (ms epoch): the
/// server clock at delete time, floored strictly above the deleted
/// version's `updatedAt`, so the tombstone dominates the copy it deleted
/// even against a client clock running ahead of the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftTombstone {
    pub deleted_at: u64,
}

/// Error body for `PUT /drafts/:id` refused by a strictly-newer tombstone
/// (410 `ERR_DRAFT_DELETED`). The repo error shape plus the tombstone's
/// ordinal, so the client can reconcile (drop its stale local copy, or
/// re-save the work under a fresh id).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftDeletedBody {
    pub status: &'static str,
    pub code: &'static str,
    pub description: String,
    pub deleted_at: u64,
}

/// Summary fields stored as KV metadata next to each draft so `GET /drafts`
/// lists without an N+1 read of every value. The draft id is NOT stored
/// here — it is recovered from the KV key, keeping the serialized metadata
/// comfortably under Cloudflare's 1024-byte cap (title ≤ 256 UTF-8 bytes,
/// control characters rejected so JSON escaping cannot inflate it past the
/// budget).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftKvMetadata {
    pub title: String,
    pub updated_at: u64,
    pub section_count: u64,
    pub part_count: u64,
}

// ────────────────────────────────────────────────────────────────────────────
// Overlay SHIP broadcaster types
// ────────────────────────────────────────────────────────────────────────────
//
// Historical note: earlier revisions defined `OverlaySubmitResponse` and
// `OverlayTopicAdmission` here. Task #14 dropped both — they are exactly
// `overlay_engine::types::Steak` (a re-export of `bsv_rs::overlay::types::Steak`
// = `HashMap<String, AdmittanceInstructions>`), which `src/overlay/mod.rs`
// now consumes directly via the `overlay-engine` crate.
