//! AWS SigV4 presigned PUT URL generator for Cloudflare R2.
//!
//! Hand-rolled (no `aws-sigv4` dep — pulls the full AWS smithy tree, most of
//! which is useless to us). Uses HMAC-SHA256 from `hmac` + `sha2`, which both
//! build cleanly on `wasm32-unknown-unknown`.
//!
//! This module is **pure** — no I/O, no env reads. Callers pass credentials
//! and a timestamp in, so the logic is fully deterministic and unit-testable.
//! The `PresignParams` struct is the one entry point; everything else is
//! internal helper.
//!
//! Reference: AWS "Signature Version 4 signing" spec
//! <https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html>
//! and AWS S3 "Authenticating requests: using query parameters (AWS signature
//! version 4)"
//! <https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html>.
//!
//! Cloudflare R2 is S3-compatible for SigV4 purposes. Region is fixed as
//! `"auto"` per the R2 docs.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Cloudflare R2 SigV4 region. R2 doesn't have regions, but the SigV4 spec
/// requires one — R2 accepts `"auto"` (per the Cloudflare R2 S3-compat docs).
const R2_REGION: &str = "auto";

/// SigV4 service identifier for R2 (S3-compatible).
const S3_SERVICE: &str = "s3";

/// SHA-256 of an empty body in lowercase hex. Used as `x-amz-content-sha256`
/// value for presigned URLs where the body is not signed.
const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// Input to [`presign_put`]. Keep this struct dumb — no I/O, no defaults. All
/// fields are required; callers read env vars and assemble the struct before
/// calling.
#[derive(Debug)]
pub struct PresignParams<'a> {
    /// AWS-style access key. For R2: pull from the `R2_ACCESS_KEY_ID` secret.
    pub access_key_id: &'a str,
    /// AWS-style secret key. For R2: pull from the `R2_SECRET_ACCESS_KEY`
    /// secret.
    pub secret_access_key: &'a str,
    /// S3 endpoint host. For R2 this is
    /// `<account_id>.r2.cloudflarestorage.com`.
    pub host: &'a str,
    /// R2 bucket name (from the `UHRP_FILES` binding config).
    pub bucket: &'a str,
    /// Object key (e.g. `cdn/<objectIdentifier>`).
    pub key: &'a str,
    /// URL validity in seconds. R2 max is 604800 (7 days) — we use 604000 to
    /// match the TS server (GCS `getSignedUrl` call, `getUploadURL.ts:59`).
    pub expires_in_seconds: u64,
    /// Request timestamp in ISO-8601 basic form `YYYYMMDDTHHMMSSZ`.
    /// Caller is responsible for producing this (see `format_amz_date`).
    pub amz_date: &'a str,
    /// Date stamp `YYYYMMDD` matching `amz_date` (first 8 chars). Caller
    /// provides it rather than deriving to avoid out-of-sync bugs.
    pub date_stamp: &'a str,
    /// Extra headers that are part of the signature and MUST be echoed by the
    /// client (`x-amz-meta-*` user metadata, and `content-length` to pin the
    /// exact object size — R2 verifies every header in `X-Amz-SignedHeaders`
    /// against the actual PUT, so a mismatched body size fails the signature
    /// check server-side). `Host` is added automatically — don't include it
    /// here. Keys are lowercased when signing; values are trimmed.
    pub signed_headers: &'a [(String, String)],
}

/// Generate a SigV4 presigned PUT URL for the given R2 object.
///
/// Returns the full URL including query string. The client makes an unsigned
/// PUT to this URL — R2 validates the signature server-side from the query
/// params.
pub fn presign_put(p: &PresignParams<'_>) -> String {
    // ── Step 1: canonical headers ───────────────────────────────────────────
    // Always include `host`. Extra headers are `x-amz-meta-*` user metadata
    // (R2 accepts the same convention as S3) plus `content-length`, which
    // pins the object size into the signature (the-composer #43).
    let mut headers: Vec<(String, String)> = Vec::with_capacity(p.signed_headers.len() + 1);
    headers.push(("host".to_string(), p.host.to_string()));
    for (k, v) in p.signed_headers {
        headers.push((k.to_ascii_lowercase(), v.trim().to_string()));
    }
    headers.sort_by(|a, b| a.0.cmp(&b.0));

    let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers: String = {
        let mut names: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        names.sort_unstable();
        names.join(";")
    };

    // ── Step 2: credential scope ────────────────────────────────────────────
    let credential_scope = format!(
        "{date}/{region}/{service}/aws4_request",
        date = p.date_stamp,
        region = R2_REGION,
        service = S3_SERVICE,
    );
    let credential = format!("{}/{}", p.access_key_id, credential_scope);

    // ── Step 3: canonical query string ──────────────────────────────────────
    // SigV4 presigned URLs encode all signing params in the query string.
    // Keys MUST appear in ascending ASCII order.
    let mut query: Vec<(String, String)> = vec![
        (
            "X-Amz-Algorithm".to_string(),
            "AWS4-HMAC-SHA256".to_string(),
        ),
        ("X-Amz-Credential".to_string(), credential),
        ("X-Amz-Date".to_string(), p.amz_date.to_string()),
        (
            "X-Amz-Expires".to_string(),
            p.expires_in_seconds.to_string(),
        ),
        ("X-Amz-SignedHeaders".to_string(), signed_headers.clone()),
    ];
    query.sort_by(|a, b| a.0.cmp(&b.0));

    let canonical_query: String = query
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true)))
        .collect::<Vec<_>>()
        .join("&");

    // ── Step 4: canonical request ───────────────────────────────────────────
    // PUT /<bucket>/<key> HTTP/1.1
    let canonical_uri = format!(
        "/{}/{}",
        uri_encode(p.bucket, false),
        uri_encode(p.key, false)
    );
    let canonical_request = format!(
        "PUT\n{uri}\n{query}\n{headers}\n{signed_headers}\n{payload}",
        uri = canonical_uri,
        query = canonical_query,
        headers = canonical_headers,
        signed_headers = signed_headers,
        payload = UNSIGNED_PAYLOAD,
    );

    // ── Step 5: string to sign ──────────────────────────────────────────────
    let canonical_request_hash = hex_sha256(canonical_request.as_bytes());
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{hash}",
        amz_date = p.amz_date,
        scope = credential_scope,
        hash = canonical_request_hash,
    );

    // ── Step 6: derive signing key + compute signature ──────────────────────
    let signing_key = derive_signing_key(p.secret_access_key, p.date_stamp);
    let signature = hex_hmac_sha256(&signing_key, string_to_sign.as_bytes());

    // ── Step 7: assemble URL ────────────────────────────────────────────────
    format!(
        "https://{host}{uri}?{query}&X-Amz-Signature={sig}",
        host = p.host,
        uri = canonical_uri,
        query = canonical_query,
        sig = signature,
    )
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// SigV4 URI-encode. If `encode_slashes` is false, `/` is left unescaped —
/// used for the canonical URI (path). For query values, `/` is escaped.
///
/// Reserved set (unreserved per RFC 3986): `A-Z a-z 0-9 - _ . ~`.
fn uri_encode(input: &str, encode_slashes: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b'/' if !encode_slashes => out.push('/'),
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

fn hex_hmac_sha256(key: &[u8], msg: &[u8]) -> String {
    hex_encode(&hmac_sha256(key, msg))
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    // `Hmac::new_from_slice` cannot fail for valid keys (any length is valid
    // for HMAC-SHA256), but we guard the error path to stay within the
    // clippy::unwrap_used rule.
    match HmacSha256::new_from_slice(key) {
        Ok(mut mac) => {
            mac.update(msg);
            mac.finalize().into_bytes().to_vec()
        }
        // Unreachable: HMAC accepts any byte-slice key.
        Err(_) => Vec::new(),
    }
}

fn derive_signing_key(secret: &str, date_stamp: &str) -> Vec<u8> {
    let k_secret = format!("AWS4{secret}");
    let k_date = hmac_sha256(k_secret.as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, R2_REGION.as_bytes());
    let k_service = hmac_sha256(&k_region, S3_SERVICE.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Format a Unix epoch in seconds as `YYYYMMDDTHHMMSSZ` (ISO-8601 basic).
/// Returns `(amz_date, date_stamp)`.
///
/// Pure arithmetic — no chrono dep needed, keeps the signing code
/// self-contained. Works for any year 1970..~2106.
pub fn format_amz_date(unix_secs: u64) -> (String, String) {
    let (y, m, d, hh, mm, ss) = unix_to_civil(unix_secs);
    let amz = format!("{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z");
    let stamp = format!("{y:04}{m:02}{d:02}");
    (amz, stamp)
}

/// Convert Unix seconds to (year, month, day, hour, minute, second) UTC.
/// Algorithm from Howard Hinnant's "date algorithms" paper — used by chrono
/// internally and verified correct across the full epoch range we care about.
fn unix_to_civil(unix_secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let days = unix_secs / 86_400;
    let secs_of_day = unix_secs % 86_400;
    let hh = (secs_of_day / 3600) as u32;
    let mm = ((secs_of_day % 3600) / 60) as u32;
    let ss = (secs_of_day % 60) as u32;

    // Days from 1970-01-01 shifted so that 0000-03-01 is the era start.
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = (y + if m <= 2 { 1 } else { 0 }) as u32;
    (y, m, d, hh, mm, ss)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    use super::*;

    // ── Date formatting ──────────────────────────────────────────────────────

    #[test]
    fn format_amz_date_at_epoch() {
        let (amz, stamp) = format_amz_date(0);
        assert_eq!(amz, "19700101T000000Z");
        assert_eq!(stamp, "19700101");
    }

    #[test]
    fn format_amz_date_known_timestamp() {
        // 2025-05-10T12:34:56Z — verified against an online epoch converter.
        // Unix seconds: 1746880496
        let (amz, stamp) = format_amz_date(1_746_880_496);
        assert_eq!(amz, "20250510T123456Z");
        assert_eq!(stamp, "20250510");
    }

    #[test]
    fn format_amz_date_end_of_year() {
        // 2024-12-31T23:59:59Z = 1735689599
        let (amz, stamp) = format_amz_date(1_735_689_599);
        assert_eq!(amz, "20241231T235959Z");
        assert_eq!(stamp, "20241231");
    }

    #[test]
    fn format_amz_date_leap_day() {
        // 2024-02-29T00:00:00Z = 1709164800
        let (amz, stamp) = format_amz_date(1_709_164_800);
        assert_eq!(amz, "20240229T000000Z");
        assert_eq!(stamp, "20240229");
    }

    // ── URI encoding ─────────────────────────────────────────────────────────

    #[test]
    fn uri_encode_unreserved_passthrough() {
        assert_eq!(uri_encode("abcXYZ123-_.~", true), "abcXYZ123-_.~");
    }

    #[test]
    fn uri_encode_space_is_percent_twenty() {
        assert_eq!(uri_encode("a b", true), "a%20b");
    }

    #[test]
    fn uri_encode_slash_preserved_when_encode_slashes_false() {
        assert_eq!(uri_encode("a/b/c", false), "a/b/c");
    }

    #[test]
    fn uri_encode_slash_encoded_when_encode_slashes_true() {
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
    }

    #[test]
    fn uri_encode_special_chars() {
        assert_eq!(uri_encode("+&=", true), "%2B%26%3D");
    }

    // ── HMAC / signing-key test vectors ──────────────────────────────────────

    #[test]
    fn hex_sha256_known_vector() {
        // "abc" → SHA-256 per FIPS 180-4 test vector.
        assert_eq!(
            hex_sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hex_sha256_empty_vector() {
        // Empty string — canonical reference value.
        assert_eq!(
            hex_sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hmac_sha256_known_vector() {
        // RFC 4231 test case 1: key=0x0b*20, data="Hi There"
        let key = vec![0x0b; 20];
        assert_eq!(
            hex_hmac_sha256(&key, b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    // ── Full SigV4 vector: the AWS reference example ─────────────────────────

    /// AWS's published SigV4 signing-key test vector for `us-east-1`/`iam`:
    ///
    /// > secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    /// > date   = "20150830"
    /// > region = "us-east-1"
    /// > service = "iam"
    /// > final key hex = c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9
    ///
    /// We reimplement the scope chain with region/service overrides to verify
    /// our HMAC sequence matches AWS's reference output.
    #[test]
    fn signing_key_matches_aws_reference() {
        let k_secret = b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_vec();
        let k_date = hmac_sha256(&k_secret, b"20150830");
        let k_region = hmac_sha256(&k_date, b"us-east-1");
        let k_service = hmac_sha256(&k_region, b"iam");
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        assert_eq!(
            hex_encode(&k_signing),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }

    // ── End-to-end presign shape ────────────────────────────────────────────

    #[test]
    fn presign_put_returns_well_formed_url() {
        let extra = vec![
            (
                "x-amz-meta-uploaderidentitykey".to_string(),
                "0379abcd".to_string(),
            ),
            (
                "x-amz-meta-custom-time".to_string(),
                "2025-05-10T12:00:00.000Z".to_string(),
            ),
        ];
        let p = PresignParams {
            access_key_id: "AKIAIOSFODNN7EXAMPLE",
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            host: "acct.r2.cloudflarestorage.com",
            bucket: "uhrp-prod",
            key: "cdn/abc123",
            expires_in_seconds: 604_000,
            amz_date: "20250510T123456Z",
            date_stamp: "20250510",
            signed_headers: &extra,
        };
        let url = presign_put(&p);

        // Must start with the correct scheme + host + path.
        assert!(url.starts_with("https://acct.r2.cloudflarestorage.com/uhrp-prod/cdn/abc123?"));
        // Must carry all five canonical SigV4 query params.
        assert!(url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(url.contains(
            "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20250510%2Fauto%2Fs3%2Faws4_request"
        ));
        assert!(url.contains("X-Amz-Date=20250510T123456Z"));
        assert!(url.contains("X-Amz-Expires=604000"));
        // Signed headers must include host + the two metadata keys, alphabetically.
        assert!(url.contains(
            "X-Amz-SignedHeaders=host%3Bx-amz-meta-custom-time%3Bx-amz-meta-uploaderidentitykey"
        ));
        // And a signature of the right length (hex 64 chars).
        let sig_start = url.find("X-Amz-Signature=").expect("signature present");
        let sig = &url[sig_start + "X-Amz-Signature=".len()..];
        assert_eq!(sig.len(), 64, "signature must be 64 hex chars");
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn presign_put_binds_content_length_into_signed_headers() {
        // #43: with content-length among the signed headers, R2 verifies the
        // PUT's actual Content-Length against the signature — an oversize
        // upload fails at R2 before costing the owner anything.
        let extra = vec![
            ("content-length".to_string(), "1048576".to_string()),
            (
                "x-amz-meta-uploaderidentitykey".to_string(),
                "0379abcd".to_string(),
            ),
        ];
        let p = PresignParams {
            access_key_id: "AKIAIOSFODNN7EXAMPLE",
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            host: "acct.r2.cloudflarestorage.com",
            bucket: "uhrp-prod",
            key: "cdn/abc123",
            expires_in_seconds: 604_000,
            amz_date: "20250510T123456Z",
            date_stamp: "20250510",
            signed_headers: &extra,
        };
        let url = presign_put(&p);
        // SignedHeaders is sorted ASCII ascending: content-length < host.
        assert!(
            url.contains(
                "X-Amz-SignedHeaders=content-length%3Bhost%3Bx-amz-meta-uploaderidentitykey"
            ),
            "content-length must be part of the signed header set: {url}"
        );
    }

    #[test]
    fn different_content_lengths_produce_different_signatures() {
        // The size is load-bearing in the signature: changing only the
        // declared byte count must change the URL's X-Amz-Signature, i.e. a
        // URL presigned for 1 byte cannot admit any other size.
        let sig_for = |len: &str| {
            let extra = vec![("content-length".to_string(), len.to_string())];
            let p = PresignParams {
                access_key_id: "AKIAIOSFODNN7EXAMPLE",
                secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                host: "acct.r2.cloudflarestorage.com",
                bucket: "uhrp-prod",
                key: "cdn/abc123",
                expires_in_seconds: 604_000,
                amz_date: "20250510T123456Z",
                date_stamp: "20250510",
                signed_headers: &extra,
            };
            let url = presign_put(&p);
            let at = url.find("X-Amz-Signature=").expect("signature present");
            url[at..].to_string()
        };
        assert_ne!(sig_for("1"), sig_for("11000000000"));
    }

    #[test]
    fn presign_put_is_deterministic() {
        let p = PresignParams {
            access_key_id: "AKIAIOSFODNN7EXAMPLE",
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            host: "acct.r2.cloudflarestorage.com",
            bucket: "uhrp-prod",
            key: "cdn/abc123",
            expires_in_seconds: 604_000,
            amz_date: "20250510T123456Z",
            date_stamp: "20250510",
            signed_headers: &[],
        };
        let u1 = presign_put(&p);
        let u2 = presign_put(&p);
        assert_eq!(u1, u2, "same inputs must yield same URL");
    }
}
