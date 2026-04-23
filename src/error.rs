//! Shared error codes. Strings must match TS impl verbatim for protocol parity.
//! See `PROTOCOL.md` for the canonical list.

#![allow(dead_code)] // Scaffold: constants consumed as routes land in tasks #3–#7.

pub const ERR_INTERNAL: &str = "ERR_INTERNAL";
pub const ERR_NOT_FOUND: &str = "ERR_NOT_FOUND";
pub const ERR_NOT_IMPLEMENTED: &str = "ERR_NOT_IMPLEMENTED";
pub const ERR_INVALID_REQUEST: &str = "ERR_INVALID_REQUEST";
pub const ERR_UNAUTHORIZED: &str = "ERR_UNAUTHORIZED";

// /quote (§1)
pub const ERR_NO_SIZE: &str = "ERR_NO_SIZE";
pub const ERR_NO_RETENTION_PERIOD: &str = "ERR_NO_RETENTION_PERIOD";
pub const ERR_INVALID_SIZE: &str = "ERR_INVALID_SIZE";
pub const ERR_INVALID_RETENTION_PERIOD: &str = "ERR_INVALID_RETENTION_PERIOD";

// /upload (§2)
pub const ERR_MISSING_IDENTITY_KEY: &str = "ERR_MISSING_IDENTITY_KEY";
pub const ERR_INTERNAL_UPLOAD: &str = "ERR_INTERNAL_UPLOAD";

// Wallet layer (task #6). Consumed by /renew (§5) and /advertise (§6)
// handlers when they surface wallet-infra failures as HTTP responses.
pub const ERR_WALLET_UNAVAILABLE: &str = "ERR_WALLET_UNAVAILABLE";
pub const ERR_WALLET_AUTH_FAILED: &str = "ERR_WALLET_AUTH_FAILED";
pub const ERR_BEEF_PARSE: &str = "ERR_BEEF_PARSE";
pub const ERR_BEEF_SIGN: &str = "ERR_BEEF_SIGN";

// /find (§3). TS handler wires `ERR_MISSING_IDENTITY_KEY`, `ERR_NO_UHRP_URL`,
// and a catch-all `ERR_FIND` (500). `ERR_NOT_FOUND` appears in the TS
// `errors:` doc list (`src/routes/find.ts:97`) but is never actually emitted —
// `getMetadata` throws a plain `Error` which is caught as `ERR_FIND`. We match
// the emitted-behavior, not the doc-list.
pub const ERR_NO_UHRP_URL: &str = "ERR_NO_UHRP_URL";
pub const ERR_FIND: &str = "ERR_FIND";

// /list (§4).
pub const ERR_LIST: &str = "ERR_LIST";

// /renew (§5).
pub const ERR_MISSING_FIELDS: &str = "ERR_MISSING_FIELDS";
pub const ERR_INVALID_TIME: &str = "ERR_INVALID_TIME";
pub const ERR_OLD_ADVERTISEMENT_NOT_FOUND: &str = "ERR_OLD_ADVERTISEMENT_NOT_FOUND";
pub const ERR_CREATE_ACTION_FAILED: &str = "ERR_CREATE_ACTION_FAILED";
pub const ERR_SIGNING_OLD_ADVERTISEMENT: &str = "ERR_SIGNING_OLD_ADVERTISEMENT";
pub const ERR_INTERNAL_RENEW: &str = "ERR_INTERNAL_RENEW";

// /advertise (§6). TS uses `ADMIN_TOKEN` body field; the Rust port replaces
// that with a BRC-31 identity-key allowlist (`ADMIN_IDENTITY_KEYS` secret).
// `ERR_UNAUTHORIZED` is re-used (it's already in the shared set) for the
// admin gate — TS emits the same code/description for the same failure.
pub const ERR_ADVERTISE_INTERNAL: &str = "ERR_INTERNAL";

// Overlay broadcast failures (shared by /renew and /advertise).
pub const ERR_OVERLAY_BROADCAST: &str = "ERR_OVERLAY_BROADCAST";
