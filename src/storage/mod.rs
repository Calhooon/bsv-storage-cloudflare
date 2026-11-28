//! R2 storage helpers for the `/upload` route.
//!
//! Generates S3 SigV4 **presigned PUT URLs** against R2's S3-compatible API.
//! This is the Rust/R2 equivalent of the TS server's GCS `getSignedUrl()` call
//! (`src/utils/getUploadURL.ts:33–73`). The URL returned to the client is a
//! direct-to-R2 URL — no proxy through the Worker — preserving the client UX
//! documented in PROTOCOL.md §2.
//!
//! Backend-specific ambiguity: the TS response wires GCS header names
//! (`x-goog-meta-uploaderidentitykey`, `x-goog-custom-time`) into
//! `requiredHeaders`. R2 speaks S3, so our port returns the S3/AWS
//! equivalents (`x-amz-meta-uploaderidentitykey`, `x-amz-meta-custom-time`).
//! Field names, types, and order in the response JSON are unchanged; only the
//! backend-specific header names inside `requiredHeaders` differ, which is
//! unavoidable when swapping the storage provider.

pub mod head;
pub mod presign;
