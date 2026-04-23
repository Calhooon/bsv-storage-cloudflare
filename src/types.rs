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
// Overlay SHIP broadcaster types
// ────────────────────────────────────────────────────────────────────────────
//
// Earlier revisions defined `OverlaySubmitResponse` and `OverlayTopicAdmission`
// here. They are exactly `bsv_rs::overlay::types::Steak`
// (= `HashMap<String, AdmittanceInstructions>`), which `src/overlay/mod.rs`
// consumes directly.
