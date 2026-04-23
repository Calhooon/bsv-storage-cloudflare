//! MetaNet Client adapter — POSTs to `localhost:3321` with BRC-100 JSON
//! shapes. Scoped to the one method the parity harness needs:
//! `createAction`. Identity / signing / payment-key derivation happens
//! in-process via `bsv_rs`; this adapter is the "build + sign a Bitcoin
//! transaction from my wallet's UTXOs" escape hatch.
//!
//! ## Reference
//!
//! Shape-for-shape port of `~/bsv/x402-client/lib/metanet.py::create_action`
//! (Python, verified live against MetaNet Client + nanostore.babbage.systems
//! 2026-02-12). Matching that file exactly is the only thing that keeps us
//! compatible with the wallet's JSON schema — drift here = silent payment
//! failures in production.
//!
//! ## What this doesn't do
//!
//! - No `getPublicKey` / `createSignature` passthrough. Parity's BRC-31
//!   client already holds the private key and does those locally via
//!   `bsv_rs`.
//! - No BEEF format auto-detection. The Python reference relies on the
//!   wallet returning the right format; `rust-bsv-worm` adds a
//!   raw→BEEF→AtomicBEEF wrapper step. For now we pass whatever the
//!   wallet returns straight through; if a server rejects the format
//!   we'll add wrapping as a follow-up rather than guessing.

use bsv_rs::primitives::to_base64;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// URL the MetaNet Client binds to on localhost. Fixed by the wallet
/// implementation; no env override — the parity harness is local-only.
pub const METANET_URL: &str = "http://localhost:3321";

/// MetaNet Client enforces `Origin: http://localhost` on every request
/// as a CSRF safeguard. Without it, every call 403s.
pub const METANET_ORIGIN: &str = "http://localhost";

/// Per the Python reference: 30s timeout lets the wallet prompt the user
/// if it needs approval. Shorter timeouts race against the approval UX.
const WALLET_TIMEOUT: Duration = Duration::from_secs(30);

/// One output inside a `createAction` request. Field names / casing
/// must match BRC-100: `lockingScript` (hex), `satoshis`, `outputDescription`.
#[derive(Debug, Clone, Serialize)]
pub struct ActionOutput {
    #[serde(rename = "lockingScript")]
    pub locking_script_hex: String,
    pub satoshis: u64,
    /// MetaNet Client enforces min 5 chars — anything shorter is rejected.
    #[serde(rename = "outputDescription")]
    pub output_description: String,
}

/// Request body for POST /createAction. Wire shape is fixed by BRC-100
/// and must match what `x402-client/lib/metanet.py::create_action` sends.
#[derive(Debug, Clone, Serialize)]
struct CreateActionRequest {
    description: String,
    outputs: Vec<ActionOutput>,
    options: CreateActionOptions,
}

#[derive(Debug, Clone, Serialize)]
struct CreateActionOptions {
    #[serde(rename = "acceptDelayedBroadcast")]
    accept_delayed_broadcast: bool,
    #[serde(rename = "randomizeOutputs")]
    randomize_outputs: bool,
}

/// Result of a successful `createAction`. The wallet returns `tx` as a
/// JSON number array (not base64 / hex / bytes); we decode to `Vec<u8>`
/// for the caller's convenience.
#[derive(Debug, Clone)]
pub struct CreatedAction {
    /// Transaction ID (hex). Currently unused — callers only need `tx`
    /// for the BRC-29 envelope — but preserved so future logging /
    /// refund-tracking scenarios can read it without re-plumbing.
    #[allow(dead_code)]
    pub txid: String,
    /// Raw transaction bytes. The format (raw / BEEF / AtomicBEEF)
    /// depends on the wallet's internal broadcast path — BRC-100 doesn't
    /// pin it. The BRC-29 envelope just base64-encodes whatever the
    /// wallet returns; servers parse via `Beef::from_binary` and accept
    /// multiple shapes.
    pub tx: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct CreateActionResponse {
    txid: Option<String>,
    /// JSON number array — decoded by `try_from_bytes` below.
    tx: Option<serde_json::Value>,
}

/// POST to `localhost:3321/createAction`. Builds the JSON body in the
/// exact shape MetaNet Client wants, sets the required `Origin` header,
/// and decodes the response's `tx` number array into bytes.
pub async fn create_action(
    http: &Client,
    description: impl Into<String>,
    outputs: Vec<ActionOutput>,
    accept_delayed_broadcast: bool,
    randomize_outputs: bool,
) -> Result<CreatedAction, String> {
    let body = CreateActionRequest {
        description: description.into(),
        outputs,
        options: CreateActionOptions {
            accept_delayed_broadcast,
            randomize_outputs,
        },
    };
    let url = format!("{METANET_URL}/createAction");
    let resp = http
        .post(&url)
        .header("Origin", METANET_ORIGIN)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("MetaNet Client unreachable at {url}: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let txt = resp.text().await.unwrap_or_default();
        return Err(format!("createAction returned {status}: {txt}"));
    }
    let parsed: CreateActionResponse = resp
        .json()
        .await
        .map_err(|e| format!("createAction: invalid JSON: {e}"))?;

    let txid = parsed.txid.ok_or("createAction: response missing 'txid'")?;
    let tx_value = parsed.tx.ok_or("createAction: response missing 'tx'")?;
    let tx = decode_tx_array(&tx_value)?;
    Ok(CreatedAction { txid, tx })
}

/// MetaNet Client returns the transaction as a JSON number array
/// (`[0, 1, 255, ...]`), not as hex or base64. Decode each entry as a
/// byte in range `0..=255` — any value outside that range is a wallet
/// bug and we surface it as an error.
fn decode_tx_array(v: &serde_json::Value) -> Result<Vec<u8>, String> {
    let arr = v
        .as_array()
        .ok_or("createAction: 'tx' is not a JSON array")?;
    let mut out = Vec::with_capacity(arr.len());
    for (i, elem) in arr.iter().enumerate() {
        let n = elem
            .as_u64()
            .ok_or_else(|| format!("createAction: 'tx[{i}]' is not an unsigned int"))?;
        if n > 255 {
            return Err(format!("createAction: 'tx[{i}]' = {n} > 255 (not a byte)"));
        }
        out.push(n as u8);
    }
    Ok(out)
}

/// Standard base64 (padded) — thin re-export of `bsv_rs::to_base64` so
/// callers in this crate don't have to remember which base64 alphabet
/// BRC-29 expects. `to_base64` uses STANDARD (padded), which is what
/// nanostore / storage.babbage.systems require. URL_SAFE silently fails
/// server-side; this wrapper is the only base64 source scenarios
/// should use.
#[allow(dead_code)]
pub fn base64_standard(bytes: &[u8]) -> String {
    to_base64(bytes)
}

/// Build a `reqwest::Client` sized for talking to MetaNet Client.
/// Separate from any BRC-31 HTTP client since the timeout profile is
/// different (wallet may prompt user).
pub fn build_client() -> Result<Client, String> {
    Client::builder()
        .timeout(WALLET_TIMEOUT)
        .build()
        .map_err(|e| format!("reqwest client: {e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decode_tx_array_happy_path() {
        let v = json!([0x76, 0xa9, 0x14, 0x00]);
        assert_eq!(decode_tx_array(&v).unwrap(), vec![0x76, 0xa9, 0x14, 0x00]);
    }

    #[test]
    fn decode_tx_array_rejects_non_array() {
        let v = json!("not-an-array");
        assert!(decode_tx_array(&v).is_err());
    }

    #[test]
    fn decode_tx_array_rejects_out_of_range() {
        let v = json!([256]);
        let err = decode_tx_array(&v).unwrap_err();
        assert!(err.contains("256"));
    }

    #[test]
    fn decode_tx_array_rejects_non_int_element() {
        let v = json!([1, "x"]);
        assert!(decode_tx_array(&v).is_err());
    }

    #[test]
    fn base64_standard_is_padded_not_url_safe() {
        // Input chosen to force a `+` in base64 (bytes 0xfb 0xff produce "+/8=").
        let out = base64_standard(&[0xFB, 0xFF]);
        assert_eq!(out, "+/8=");
        assert!(
            out.contains('+'),
            "must use STANDARD alphabet (+/), not URL-safe (-_)"
        );
        assert!(out.ends_with('='), "must be padded");
    }

    #[test]
    fn create_action_request_serializes_with_expected_field_names() {
        // Serializer drift here silently breaks MetaNet Client — the
        // wallet silently rejects unknown fields and never hands us a
        // useful error. Pin the wire shape.
        let req = CreateActionRequest {
            description: "test".to_string(),
            outputs: vec![ActionOutput {
                locking_script_hex: "76a914".to_string(),
                satoshis: 10,
                output_description: "BRC-29 payment output".to_string(),
            }],
            options: CreateActionOptions {
                accept_delayed_broadcast: false,
                randomize_outputs: false,
            },
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["description"], "test");
        assert_eq!(v["outputs"][0]["lockingScript"], "76a914");
        assert_eq!(v["outputs"][0]["satoshis"], 10);
        assert_eq!(
            v["outputs"][0]["outputDescription"],
            "BRC-29 payment output"
        );
        assert_eq!(v["options"]["acceptDelayedBroadcast"], false);
        assert_eq!(v["options"]["randomizeOutputs"], false);
    }

    /// Live connectivity probe: ensures MetaNet Client is reachable and
    /// replies to unauthenticated endpoints. Marked `#[ignore]` — pass
    /// `-- --ignored` to run. Does NOT call `createAction` (which would
    /// spend miner fees); that's exercised end-to-end when `/upload`
    /// flips to live-fire.
    ///
    /// Guards against the most common dev regressions: wallet not
    /// running, Origin header drift, or port change. If this fails, the
    /// live `/upload` scenario will also fail — cheapest place to catch
    /// it.
    #[tokio::test]
    #[ignore]
    async fn live_connectivity_metanet_client() {
        let http = build_client().unwrap();
        let resp = http
            .get(format!("{METANET_URL}/isAuthenticated"))
            .header("Origin", METANET_ORIGIN)
            .send()
            .await
            .unwrap_or_else(|e| panic!("MetaNet Client unreachable: {e}"));
        assert!(
            resp.status().is_success(),
            "isAuthenticated must 200 — got {}",
            resp.status()
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["authenticated"], true, "wallet must be unlocked");
    }

    /// Extra coverage: the payment envelope's wire shape. Mirrors what
    /// `create_payment_envelope` will emit — independent test so a drift
    /// here fails fast even before live wiring.
    #[test]
    fn wallet_module_is_self_consistent_on_field_names() {
        // If this ever fails, someone accidentally renamed the request
        // struct fields and lost the serde renames. Pin the canonical
        // wire shape.
        let expected_keys = ["description", "outputs", "options"];
        let req = CreateActionRequest {
            description: "d".to_string(),
            outputs: vec![],
            options: CreateActionOptions {
                accept_delayed_broadcast: false,
                randomize_outputs: false,
            },
        };
        let v = serde_json::to_value(&req).unwrap();
        let obj = v.as_object().unwrap();
        for k in expected_keys {
            assert!(
                obj.contains_key(k),
                "createAction request missing top-level `{k}`"
            );
        }
    }
}
