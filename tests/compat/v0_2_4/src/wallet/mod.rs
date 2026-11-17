//! Admin wallet layer for UHRP storage.
//!
//! Two concerns bundled under one module:
//!
//! 1. **JSON-RPC client** ([`client::Wallet`]) — talks to `wallet-infra`
//!    (`WALLET_STORAGE_URL`) over `worker::Fetch`, wrapped in BRC-103/104
//!    auth via `bsv-middleware-cloudflare`'s [`WorkerStorageClient`]. Exposes
//!    typed methods — `create_action`, `list_outputs`, `process_action` —
//!    that the `/renew` and `/advertise` route handlers will call.
//! 2. **Local signer** ([`signer::sign_beef`]) — loads the
//!    `ADMIN_WALLET_PRIVATE_KEY` secret, consumes the unsigned transaction
//!    template returned by `createAction`, produces a BIP-143 sighash per
//!    input, and emits raw signed transaction bytes ready for
//!    `processAction`. Uses `bsv-rs` ECDSA (RFC 6979 deterministic-k) —
//!    no ad-hoc crypto.
//!
//! The Worker never uploads the admin private key to `wallet-infra`; the
//! key stays inside the Worker and is used only to produce unlocking
//! scripts over sighashes.
//!
//! [`WorkerStorageClient`]: bsv_middleware_cloudflare::WorkerStorageClient

#![allow(dead_code)] // Scaffold: routes land in tasks #7 (/advertise) and later (/renew).

pub mod brc42;
pub mod client;
pub mod signer;
pub mod types;

/// TS-SDK parity tests — verify our wallet primitives (BEEF parsing, BRC-29
/// derivation, BIP-143 sighash) produce byte-exact results matching @bsv/sdk
/// 1.10.1 fixtures generated under `tests/parity/ts-fixtures/generate.mjs`.
///
/// Fixtures live in `tests/parity/fixtures/parity/*.json` and are considered
/// CANONICAL ORACLE OUTPUT — if a test here flips red, our Rust code is wrong
/// (not the fixture). The fixture generator is pinned to the exact SDK
/// version `nanostore.babbage.systems` runs, so byte parity here is what
/// keeps our deployed worker compatible with the production TS server.
#[cfg(test)]
mod parity_tests;
