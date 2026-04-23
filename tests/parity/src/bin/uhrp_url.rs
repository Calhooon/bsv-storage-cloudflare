//! Read stdin bytes, emit the UHRP URL (raw base58check, no `uhrp://` prefix)
//! using the exact algorithm from `@bsv/sdk::StorageUtils::getURLForFile`.
//!
//! The algorithm: sha256(bytes) → prepend [0xce, 0x00] → append first 4 bytes of
//! sha256d(prefix||hash) → base58 encode. Matches the root crate's
//! `src/uhrp/hash.rs` byte-for-byte.

use bsv_rs::primitives::encoding::to_base58;
use bsv_rs::primitives::hash::{sha256, sha256d};
use std::io::Read;

const UHRP_VERSION_PREFIX: [u8; 2] = [0xce, 0x00];

fn main() {
    let mut buf = Vec::new();
    if std::io::stdin().read_to_end(&mut buf).is_err() {
        eprintln!("failed to read stdin");
        std::process::exit(1);
    }
    let hash = sha256(&buf);
    let mut payload = Vec::with_capacity(UHRP_VERSION_PREFIX.len() + hash.len() + 4);
    payload.extend_from_slice(&UHRP_VERSION_PREFIX);
    payload.extend_from_slice(&hash);
    let checksum = sha256d(&payload);
    payload.extend_from_slice(&checksum[..4]);
    println!("{}", to_base58(&payload));
}
