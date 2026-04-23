//! UHRP hash algorithm — derives a UHRP URL from raw file bytes.
//!
//! Protocol reference: PROTOCOL.md §A. The URL is `@bsv/sdk`'s
//! `StorageUtils.getURLForFile` output:
//!
//! ```text
//! url = base58( prefix || sha256(bytes) || checksum(first 4 bytes of sha256d(prefix || sha256(bytes))) )
//! prefix = 0xce 0x00   // two bytes
//! ```
//!
//! Cross-SDK parity vectors live in `tests/fixtures/uhrp_hash/*.json`, generated
//! by `scripts/gen-uhrp-hash-fixtures.mjs` from the live TS SDK.
//!
//! `StorageUtils.getURLForFile` returns the **raw base58check string** — no
//! `uhrp://` prefix. Our `derive_uhrp_url` matches that exactly so golden
//! fixtures compare byte-for-byte.

// Routes land in task #7b and later (/advertise, /find, /list). Until then
// this function is reachable only via tests; the gate runs clippy with
// `-D warnings`, so opt out of dead_code rather than keeping the symbols
// artificially consumed.
#![allow(dead_code)]

use bsv_rs::primitives::encoding::to_base58;
use bsv_rs::primitives::hash::{sha256, sha256d};

/// UHRP Base58Check version prefix (`0xce 0x00`).
///
/// Two-byte prefix per `@bsv/sdk` `StorageUtils.getURLForHash`. The `0xce` byte
/// places it outside the single-byte Base58Check address space used for
/// Bitcoin addresses, which is how the decoder distinguishes UHRP payloads.
const UHRP_VERSION_PREFIX: [u8; 2] = [0xce, 0x00];

/// Derives the UHRP URL for a file's raw bytes.
///
/// Matches TS `@bsv/sdk` `StorageUtils.getURLForFile`: SHA-256 of the bytes is
/// prefixed with `[0xce, 0x00]`, appended with the first 4 bytes of
/// `SHA256(SHA256(prefix || hash))` as checksum, and Base58-encoded. The
/// returned string does **not** include the `uhrp://` scheme — matching TS
/// behavior precisely. Callers wire the `uhrp://` prefix at URL-emission time.
pub fn derive_uhrp_url(file_bytes: &[u8]) -> String {
    let hash = sha256(file_bytes);
    url_from_hash(&hash)
}

/// Builds the Base58Check UHRP URL from an already-computed 32-byte SHA-256
/// hash. Pulled out to keep `derive_uhrp_url` free of any branching; reused
/// by tests that start from a known hash, and by the queue consumer
/// (`crate::queue`) which streams R2 bytes into a SHA-256 digest and then
/// needs the URL string.
pub(crate) fn url_from_hash(hash: &[u8; 32]) -> String {
    let mut payload = Vec::with_capacity(UHRP_VERSION_PREFIX.len() + hash.len() + 4);
    payload.extend_from_slice(&UHRP_VERSION_PREFIX);
    payload.extend_from_slice(hash);
    let checksum = sha256d(&payload);
    payload.extend_from_slice(&checksum[..4]);
    to_base58(&payload)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use serde::Deserialize;

    /// Each fixture emitted by `scripts/gen-uhrp-hash-fixtures.mjs`. Small cases
    /// carry `file_hex`; the synthetic >1 MiB case carries `file_pattern` so
    /// we don't commit a megabyte of hex into the repo.
    #[derive(Deserialize)]
    struct HashFixture {
        uhrp_url: String,
        hash_hex: String,
        #[serde(default)]
        file_hex: Option<String>,
        #[serde(default)]
        file_pattern: Option<FilePattern>,
    }

    #[derive(Deserialize)]
    struct FilePattern {
        repeat_byte: u8,
        count: usize,
    }

    impl HashFixture {
        fn materialize_bytes(&self) -> Vec<u8> {
            if let Some(p) = &self.file_pattern {
                return vec![p.repeat_byte; p.count];
            }
            let hex = self.file_hex.as_deref().unwrap_or("");
            hex_decode(hex)
        }
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        // Test helper. Avoids `hex::decode(...).unwrap()` to keep clippy
        // happy (unwrap_used = warn). A malformed fixture is a test-author
        // error; panic with an explicit message instead of unwrap.
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0;
        while i + 1 < bytes.len() {
            let hi = hex_nibble(bytes[i]);
            let lo = hex_nibble(bytes[i + 1]);
            out.push((hi << 4) | lo);
            i += 2;
        }
        assert_eq!(i, bytes.len(), "hex string has odd length");
        out
    }

    fn hex_nibble(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("invalid hex nibble: {b:#x}"),
        }
    }

    macro_rules! golden {
        ($name:ident, $path:literal) => {
            #[test]
            fn $name() {
                let raw = include_str!($path);
                let fixture: HashFixture =
                    serde_json::from_str(raw).expect("fixture JSON must parse");
                let bytes = fixture.materialize_bytes();

                let got = derive_uhrp_url(&bytes);
                assert_eq!(
                    got, fixture.uhrp_url,
                    "UHRP URL mismatch for fixture {}",
                    $path
                );

                // Secondary check: the file's SHA-256 matches the hash carried
                // by the fixture. This is what makes the fixture meaningful —
                // it pins both `sha256(bytes)` and the base58check encoding.
                let computed = sha256(&bytes);
                let expected_hash = hex_decode(&fixture.hash_hex);
                assert_eq!(
                    &computed[..],
                    expected_hash.as_slice(),
                    "SHA-256 mismatch (fixture may be stale)"
                );
            }
        };
    }

    golden!(golden_empty, "../../tests/fixtures/uhrp_hash/empty.json");
    golden!(
        golden_hello_world_ascii,
        "../../tests/fixtures/uhrp_hash/hello_world_ascii.json"
    );
    golden!(
        golden_ts_sdk_cross_vector,
        "../../tests/fixtures/uhrp_hash/ts_sdk_cross_vector.json"
    );
    golden!(
        golden_all_bytes_0_to_255,
        "../../tests/fixtures/uhrp_hash/all_bytes_0_to_255.json"
    );
    golden!(
        golden_one_mib_plus_one_byte_repeating,
        "../../tests/fixtures/uhrp_hash/one_mib_plus_one_byte_repeating.json"
    );

    #[test]
    fn deterministic_output_for_same_input() {
        let a = derive_uhrp_url(b"the quick brown fox");
        let b = derive_uhrp_url(b"the quick brown fox");
        assert_eq!(a, b);
    }

    #[test]
    fn different_inputs_produce_different_urls() {
        let a = derive_uhrp_url(b"alpha");
        let b = derive_uhrp_url(b"beta");
        assert_ne!(a, b);
    }

    #[test]
    fn output_does_not_include_uhrp_scheme() {
        // TS `getURLForFile` returns only the base58check string. Keep parity.
        let url = derive_uhrp_url(b"no scheme please");
        assert!(!url.starts_with("uhrp://"));
        assert!(!url.starts_with("web+uhrp://"));
    }
}
