//! Full-stack UHRP upload round-trip: the "does this actually work for
//! a real user" smoke test.
//!
//! Flow:
//!
//! 1. `POST /quote` → sats cost for `(file_size, retention_period)`.
//! 2. `POST /upload` with BRC-31 auth + BRC-29 payment → 402 probe →
//!    build envelope → retry → 200 with `{uploadURL, requiredHeaders,
//!    amount, description, status}`.
//! 3. `PUT <uploadURL>` with the server's required headers → 200.
//! 4. `GET <public CDN URL>` (public base plus the object key from
//!    `uploadURL`) → 200 with the exact bytes we uploaded.
//! 5. `sha256(downloaded_bytes) == sha256(original_bytes)` —
//!    proves the round-trip is content-integrity preserving.
//!
//! Every parity test in this repo pins a response *shape*; this one
//! pins the *effect*. If this passes, a real application can upload
//! a file and a different real application can fetch it. That's the
//! "users don't notice the switch" promise, proven end-to-end.
//!
//! Marked `#[ignore]` — spends real sats (quote-dependent, typically
//! the minimum floor for a tiny file) and makes a public CDN request.
//! Run with:
//!
//! ```bash
//! cargo test live_upload_roundtrip -- --ignored --nocapture
//! ```
//!
//! Defaults to nanostore as the most stringent target (hits
//! storage.babbage.systems' BRC-29 verifier + real GCS). Override:
//!
//! ```bash
//! PARITY_STORAGE_URL=https://your-worker.your-account.workers.dev \
//! PARITY_PUBLIC_URL_BASE=https://files.example.com \
//!   cargo test live_upload_roundtrip -- --ignored --nocapture
//! ```
//!
//! `PARITY_PUBLIC_URL_BASE` must match the Worker's `PUBLIC_URL_BASE`.
//! If unset, the download uses `uploadURL` with its query removed.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use crate::auth::AuthClient;
    use crate::identity;
    use crate::payment::create_payment_envelope;
    use crate::wallet;
    use sha2::{Digest, Sha256};
    use std::time::Duration;

    const DEFAULT_STORAGE_URL: &str = "https://nanostore.babbage.systems";

    fn target_url() -> String {
        std::env::var("PARITY_STORAGE_URL").unwrap_or_else(|_| DEFAULT_STORAGE_URL.to_string())
    }

    #[tokio::test]
    #[ignore]
    async fn live_upload_roundtrip() {
        let base_url = target_url();
        eprintln!("\n=== UHRP upload round-trip ===");
        eprintln!("target: {base_url}");

        // Fixed test payload so the UHRP URL we compute is stable
        // across runs. Keep it small — quote formula has a 10-sat
        // floor for tiny files, so a few bytes is the cheapest
        // real-content possible.
        let content: &[u8] = b"parity harness UHRP round-trip 2026-04-21\n";
        let expected_sha = {
            let mut h = Sha256::new();
            h.update(content);
            h.finalize()
        };
        eprintln!(
            "content: {} bytes, sha256={}",
            content.len(),
            hex::encode(expected_sha)
        );

        // ─── Step 1: quote ────────────────────────────────────────────
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();

        let quote_body = serde_json::json!({
            "fileSize": content.len(),
            "retentionPeriod": 1440u64, // 1 day — minimum-cost retention
        });
        let quote: serde_json::Value = http
            .post(format!("{base_url}/quote"))
            .json(&quote_body)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        eprintln!("quote: {quote}");
        // `/quote` returns `{quote: <sats>}` (informational); `/upload`'s
        // 402 response carries the authoritative sats-required value
        // per-request. We log the quote but the 402 header is what we
        // actually pay against.

        // ─── Step 2: BRC-31 auth + BRC-29 payment → /upload ───────────
        let id = identity::resolve().expect("resolve parity identity");
        let auth = AuthClient::new(&base_url, &id.private_key).unwrap();
        auth.prepare().await;

        // Probe /upload without payment to collect 402 headers.
        let body_bytes = serde_json::to_vec(&quote_body).unwrap();
        let probe = auth
            .request(
                "POST",
                "/upload",
                "",
                body_bytes.clone(),
                vec![("content-type".to_string(), "application/json".to_string())],
            )
            .await
            .unwrap();
        assert_eq!(
            probe.status,
            402,
            "expected 402 probe, got {}: body={}",
            probe.status,
            String::from_utf8_lossy(&probe.body)
                .chars()
                .take(200)
                .collect::<String>()
        );

        let prefix = probe
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-bsv-payment-derivation-prefix"))
            .map(|(_, v)| v.clone())
            .expect("402 missing derivation-prefix header");
        let sats: u64 = probe
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-bsv-payment-satoshis-required"))
            .map(|(_, v)| v.parse().unwrap())
            .expect("402 missing satoshis-required header");
        eprintln!("402: prefix={prefix}, sats={sats}");

        let server_id = auth.server_identity_hex().await.unwrap();
        let wallet_http = wallet::build_client().unwrap();
        let envelope =
            create_payment_envelope(&id.private_key, &server_id, &prefix, sats, &wallet_http)
                .await
                .unwrap_or_else(|e| panic!("build payment envelope: {e}"));

        let paid = auth
            .request(
                "POST",
                "/upload",
                "",
                body_bytes,
                vec![
                    ("content-type".to_string(), "application/json".to_string()),
                    ("x-bsv-payment".to_string(), envelope.to_header_value()),
                ],
            )
            .await
            .unwrap();
        assert_eq!(
            paid.status,
            200,
            "paid /upload expected 200, got {}: body={}",
            paid.status,
            String::from_utf8_lossy(&paid.body)
                .chars()
                .take(400)
                .collect::<String>()
        );
        let upload_body: serde_json::Value = serde_json::from_slice(&paid.body).unwrap();
        eprintln!(
            "/upload response keys: {:?}",
            upload_body
                .as_object()
                .map(|m| m.keys().collect::<Vec<_>>())
        );

        let upload_url = upload_body["uploadURL"]
            .as_str()
            .expect("upload response missing uploadURL")
            .to_string();
        let required_headers: Vec<(String, String)> = upload_body["requiredHeaders"]
            .as_object()
            .expect("requiredHeaders not an object")
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
            .collect();

        // ─── Step 3: PUT the file bytes ───────────────────────────────
        let mut put = http.put(&upload_url).body(content.to_vec());
        for (k, v) in &required_headers {
            put = put.header(k, v);
        }
        let put_resp = put.send().await.unwrap();
        let put_status = put_resp.status();
        let put_body = put_resp.text().await.unwrap_or_default();
        assert!(
            put_status.is_success(),
            "PUT to presigned URL failed: {put_status} body={}",
            put_body.chars().take(400).collect::<String>()
        );
        eprintln!("PUT: {put_status}");

        // ─── Step 4: GET the file back from the public CDN URL ────────
        // R2 presigned PUT URLs use /<bucket>/<object key> on the S3 host.
        // Public downloads use the Worker's public base plus the object key.
        let cdn_url = match std::env::var("PARITY_PUBLIC_URL_BASE") {
            Ok(public_base) => {
                let presigned = reqwest::Url::parse(&upload_url).unwrap();
                let (_, object_key) = presigned
                    .path()
                    .trim_start_matches('/')
                    .split_once('/')
                    .expect("presigned upload URL missing bucket/object key path");
                format!("{}/{}", public_base.trim_end_matches('/'), object_key)
            }
            Err(_) => {
                eprintln!(
                    "PARITY_PUBLIC_URL_BASE is unset; using uploadURL without its query for GET"
                );
                upload_url.split('?').next().unwrap().to_string()
            }
        };
        eprintln!("GET: {cdn_url}");
        let got = http.get(&cdn_url).send().await.unwrap();
        assert!(
            got.status().is_success(),
            "CDN GET failed: {}",
            got.status()
        );
        let got_bytes = got.bytes().await.unwrap().to_vec();

        // ─── Step 5: verify bytes + SHA-256 match ─────────────────────
        assert_eq!(
            got_bytes,
            content,
            "byte mismatch: uploaded {} bytes, got {} back",
            content.len(),
            got_bytes.len()
        );
        let got_sha = {
            let mut h = Sha256::new();
            h.update(&got_bytes);
            h.finalize()
        };
        assert_eq!(got_sha, expected_sha, "SHA-256 mismatch");

        eprintln!(
            "✓ round-trip verified: {}B content survives quote→upload→put→get→sha256",
            content.len()
        );
    }
}
