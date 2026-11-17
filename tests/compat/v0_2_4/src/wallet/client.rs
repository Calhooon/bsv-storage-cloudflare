//! BRC-103/104 JSON-RPC client to `wallet-infra`.
//!
//! The Worker talks to a remote wallet storage service (default:
//! `https://wallet-infra.x402agency.com`) over authenticated JSON-RPC. The
//! authentication identity is the Worker's `ADMIN_WALLET_PRIVATE_KEY` — the
//! same key that later signs BEEFs for broadcast, so wallet-infra and the
//! Worker agree on what "our" outputs are.
//!
//! # Design
//!
//! [`Wallet`] is a thin typed façade on top of
//! [`bsv_middleware_cloudflare::WorkerStorageClient`]. The underlying client
//! already handles:
//!
//! - BRC-103 handshake at `/.well-known/auth`
//! - BRC-104 header signing on every subsequent call
//! - Nonce/session bookkeeping
//!
//! So the work here is to translate our typed request shapes into the
//! `serde_json::Value` the underlying client expects, call the RPC, and
//! translate the response back into typed results.
//!
//! # One RPC per call
//!
//! [`WorkerStorageClient`] holds session state that's mutated on every
//! `rpc_call`. In a Worker that may race across requests, we can't share
//! one client across calls safely. Each [`Wallet`] builds its storage
//! client on demand — a new handshake per wallet instance, scoped to the
//! route handler's lifetime.
//!
//! [`WorkerStorageClient`]: bsv_middleware_cloudflare::WorkerStorageClient

use bsv_middleware_cloudflare::WorkerStorageClient;
use bsv_rs::primitives::ec::PrivateKey;
use bsv_rs::wallet::ProtoWallet;
use serde_json::{json, Value};
use worker::Env;

use crate::error::{ERR_BEEF_PARSE, ERR_WALLET_AUTH_FAILED, ERR_WALLET_UNAVAILABLE};
use crate::wallet::types::{
    AbortActionRequest, AbortActionResult, CreateActionRequest, CreateActionResult,
    ListOutputsRequest, ListOutputsResult, ProcessActionRequest, ProcessActionResult,
};

/// Env var name for the wallet-infra endpoint URL. Overridable per-deploy
/// so `parity` and staging can point at different backends.
pub const WALLET_STORAGE_URL_VAR: &str = "WALLET_STORAGE_URL";

/// Production default. Mirrors the value checked in to `wrangler.toml`.
pub const DEFAULT_WALLET_STORAGE_URL: &str = "https://wallet-infra.x402agency.com";

/// Admin wallet client.
///
/// Built once per route-handler invocation via [`Wallet::from_env`]. Holds
/// the admin private key (needed for both BRC-103 auth and local BEEF
/// signing) plus the lazily-initialized [`WorkerStorageClient`].
///
/// The lifetime `'a` ties the wallet to the route handler's scope — same
/// shape as the existing `PresignParams<'a>` in `storage::presign`, matching
/// the repo's convention of short-lived, stack-borrowed config structs.
pub struct Wallet<'a> {
    /// Admin private key (32-byte secp256k1 scalar). Used for BRC-31 auth
    /// against wallet-infra **and** for local BEEF signing via
    /// [`super::signer::sign_transaction`].
    ///
    /// Not `Copy`; callers borrow via [`Wallet::private_key`].
    private_key: PrivateKey,
    /// Wallet-infra endpoint, e.g. `https://wallet-infra.x402agency.com`.
    endpoint_url: String,
    /// Phantom borrow so the type carries the env's lifetime.
    _phantom: core::marker::PhantomData<&'a ()>,
}

impl<'a> Wallet<'a> {
    /// Construct a [`Wallet`] from Worker env bindings.
    ///
    /// Reads:
    ///
    /// - `ADMIN_WALLET_PRIVATE_KEY` (secret, 64-char hex) — the admin key
    /// - `WALLET_STORAGE_URL` (var) — optional, defaults to
    ///   [`DEFAULT_WALLET_STORAGE_URL`]
    ///
    /// # Errors
    ///
    /// Returns [`ERR_WALLET_UNAVAILABLE`] if the secret is missing or if the
    /// hex is not a valid secp256k1 scalar. The caller should map this to
    /// HTTP 500.
    pub fn from_env(env: &'a Env) -> Result<Self, &'static str> {
        let secret = env
            .secret("ADMIN_WALLET_PRIVATE_KEY")
            .map_err(|_| ERR_WALLET_UNAVAILABLE)?
            .to_string();
        let private_key = PrivateKey::from_hex(&secret).map_err(|_| ERR_WALLET_UNAVAILABLE)?;

        let endpoint_url = env
            .var(WALLET_STORAGE_URL_VAR)
            .ok()
            .map(|v| v.to_string())
            .unwrap_or_else(|| DEFAULT_WALLET_STORAGE_URL.to_string());

        Ok(Self {
            private_key,
            endpoint_url,
            _phantom: core::marker::PhantomData,
        })
    }

    /// Borrow the admin private key. Used by [`super::signer`].
    #[must_use]
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Admin identity key as a 66-char compressed hex string. This is the
    /// identity wallet-infra sees on every RPC call.
    #[must_use]
    pub fn identity_key_hex(&self) -> String {
        self.private_key.public_key().to_hex()
    }

    /// Build a fresh [`WorkerStorageClient`] bound to our admin key.
    ///
    /// Each call creates a new [`ProtoWallet`] + client pair, which triggers
    /// a fresh BRC-103 handshake on first RPC use. That's by design — see
    /// the module-level doc note about per-call clients.
    fn make_storage_client(&self) -> WorkerStorageClient {
        let wallet = ProtoWallet::new(Some(self.private_key.clone()));
        WorkerStorageClient::new(wallet, &self.endpoint_url)
    }

    /// Call `createAction` on wallet-infra.
    ///
    /// Returns the unsigned transaction template (input BEEF + selected
    /// inputs + outputs + reference) that [`super::signer::sign_transaction`]
    /// will consume.
    ///
    /// # Errors
    ///
    /// - [`ERR_WALLET_UNAVAILABLE`] on transport / JSON-RPC failure
    /// - [`ERR_WALLET_AUTH_FAILED`] on BRC-31 handshake failure
    /// - [`ERR_BEEF_PARSE`] if the response is malformed
    pub async fn create_action(
        &self,
        req: &CreateActionRequest,
    ) -> Result<CreateActionResult, &'static str> {
        let args = serde_json::to_value(req).map_err(|_| ERR_BEEF_PARSE)?;
        let value = self.rpc("createAction", args).await?;
        serde_json::from_value(value).map_err(|_| ERR_BEEF_PARSE)
    }

    /// Call `listOutputs` on wallet-infra.
    ///
    /// # Errors
    ///
    /// Same variants as [`create_action`].
    ///
    /// [`create_action`]: Wallet::create_action
    pub async fn list_outputs(
        &self,
        req: &ListOutputsRequest,
    ) -> Result<ListOutputsResult, &'static str> {
        let args = serde_json::to_value(req).map_err(|_| ERR_BEEF_PARSE)?;
        let value = self.rpc("listOutputs", args).await?;
        serde_json::from_value(value).map_err(|_| ERR_BEEF_PARSE)
    }

    /// Call `abortAction` on wallet-infra to mark a pending tx failed and
    /// release its locked UTXOs.
    ///
    /// Used as the rollback path when a post-processAction step (e.g.
    /// overlay submit) fails: without this, the allocated change UTXO stays
    /// `spent_by=<abandoned_tx>` until wallet-infra's `fail_abandoned` cron
    /// releases it (>30 min). Calling `abort_action` returns the UTXO to
    /// the change basket immediately.
    ///
    /// # Errors
    ///
    /// Same variants as [`create_action`]. A `false` in the returned
    /// `AbortActionResult.aborted` is NOT an error — it just means the tx
    /// was already completed or not found.
    ///
    /// [`create_action`]: Wallet::create_action
    pub async fn abort_action(
        &self,
        req: &AbortActionRequest,
    ) -> Result<AbortActionResult, &'static str> {
        let args = serde_json::to_value(req).map_err(|_| ERR_BEEF_PARSE)?;
        let value = self.rpc("abortAction", args).await?;
        serde_json::from_value(value).map_err(|_| ERR_BEEF_PARSE)
    }

    /// Call `processAction` on wallet-infra to record and broadcast a signed
    /// transaction.
    ///
    /// # Errors
    ///
    /// Same variants as [`create_action`].
    ///
    /// [`create_action`]: Wallet::create_action
    pub async fn process_action(
        &self,
        req: &ProcessActionRequest,
    ) -> Result<ProcessActionResult, &'static str> {
        let args = serde_json::to_value(req).map_err(|_| ERR_BEEF_PARSE)?;
        let value = self.rpc("processAction", args).await?;
        serde_json::from_value(value).map_err(|_| ERR_BEEF_PARSE)
    }

    /// Execute one authenticated JSON-RPC call and return the `result`
    /// field as a `Value`.
    ///
    /// # Wire-format contract
    ///
    /// `wallet-infra`'s `extract_args` helper accepts positional arrays of
    /// the form `[auth, args]` for authenticated methods. The `auth`
    /// element is ignored (BRC-31 supplies the real identity); we set it
    /// to an empty object just to occupy the slot. See
    /// `rust-wallet-infra/src/dispatch.rs::extract_args`.
    async fn rpc(&self, method: &str, args: Value) -> Result<Value, &'static str> {
        let mut client = self.make_storage_client();
        client
            .rpc_call::<Value>(method, vec![json!({}), args])
            .await
            .map_err(|e| {
                let s = e.to_string();
                worker::console_error!("wallet-infra {} raw error: {}", method, s);
                classify_rpc_error(&s)
            })
    }
}

/// Classify an RPC error into one of our stable error codes.
///
/// `WorkerStorageClient` flattens every failure mode into a string (transport,
/// auth, serialization). We peek at it to pick the right HTTP error code —
/// handshake words (`401`, `InvalidAuthentication`) map to auth failure;
/// everything else is treated as an upstream availability issue.
fn classify_rpc_error(msg: &str) -> &'static str {
    let lower = msg.to_ascii_lowercase();
    if lower.contains("401")
        || lower.contains("invalidauthentication")
        || lower.contains("invalid_auth")
        || lower.contains("unauthorized")
    {
        ERR_WALLET_AUTH_FAILED
    } else {
        ERR_WALLET_UNAVAILABLE
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::wallet::types::{CreateActionOutput, ListOutputsRequest};

    // ── classify_rpc_error ──────────────────────────────────────────────────

    #[test]
    fn classify_auth_failures_as_auth_failed() {
        assert_eq!(
            classify_rpc_error("HTTP 401 Unauthorized"),
            ERR_WALLET_AUTH_FAILED
        );
        assert_eq!(
            classify_rpc_error("InvalidAuthentication: bad nonce"),
            ERR_WALLET_AUTH_FAILED
        );
        assert_eq!(
            classify_rpc_error("ERR_INVALID_AUTH"),
            ERR_WALLET_AUTH_FAILED
        );
    }

    #[test]
    fn classify_transport_failures_as_unavailable() {
        assert_eq!(
            classify_rpc_error("Fetch error: network down"),
            ERR_WALLET_UNAVAILABLE
        );
        assert_eq!(
            classify_rpc_error("Storage server returned 500: internal"),
            ERR_WALLET_UNAVAILABLE
        );
    }

    // ── Request serialization (wire-format golden tests) ────────────────────
    //
    // We verify the shape the Worker sends to wallet-infra without making
    // network calls. Any drift from the expected JSON would be caught here.

    #[test]
    fn create_action_request_serializes_with_camelcase() {
        let req = CreateActionRequest {
            outputs: vec![CreateActionOutput {
                locking_script: "76a914deadbeef88ac".to_string(),
                satoshis: 1,
                output_description: "UHRP advertisement".to_string(),
                basket: Some("uhrp advertisements".to_string()),
                tags: vec!["uhrp_url_abc".to_string()],
                custom_instructions: None,
            }],
            inputs: vec![],
            input_beef: None,
            description: "Publish UHRP advert".to_string(),
            randomize_outputs: false,
        };
        let v = serde_json::to_value(&req).unwrap();

        // Camel-case field names on the wire.
        assert!(v.get("outputs").is_some());
        assert!(v.get("description").is_some());
        assert_eq!(v["randomizeOutputs"], false);
        // Empty `inputs` is skipped (saves bytes; wallet-infra defaults to empty).
        assert!(v.get("inputs").is_none());
        // Empty `inputBeef` is skipped.
        assert!(v.get("inputBeef").is_none());

        // Drill into the output: lockingScript, satoshis, outputDescription.
        let output = &v["outputs"][0];
        assert_eq!(output["lockingScript"], "76a914deadbeef88ac");
        assert_eq!(output["satoshis"], 1);
        assert_eq!(output["outputDescription"], "UHRP advertisement");
        assert_eq!(output["basket"], "uhrp advertisements");
        assert_eq!(output["tags"][0], "uhrp_url_abc");
    }

    #[test]
    fn list_outputs_request_skips_none_fields() {
        let req = ListOutputsRequest {
            basket: "uhrp advertisements".to_string(),
            tags: vec!["uhrp_url_abc".to_string()],
            tag_query_mode: Some("all".to_string()),
            include: Some("entire transactions".to_string()),
            include_tags: Some(true),
            include_locking_scripts: None,
            limit: Some(200),
            offset: None,
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["basket"], "uhrp advertisements");
        assert_eq!(v["tagQueryMode"], "all");
        assert_eq!(v["include"], "entire transactions");
        assert_eq!(v["includeTags"], true);
        assert_eq!(v["limit"], 200);
        // `offset: None` must be omitted, not `null`, to avoid
        // wallet-infra's serde strict-mode tripping on the `i32` type.
        assert!(v.get("offset").is_none());
    }

    #[test]
    fn list_outputs_result_reads_uppercase_beef_key() {
        // wallet-infra sends the BRC-100 standard uppercase `BEEF` key.
        let v = json!({
            "totalOutputs": 1,
            "outputs": [],
            "BEEF": [1, 2, 3, 4]
        });
        let result: ListOutputsResult = serde_json::from_value(v).unwrap();
        assert_eq!(result.total_outputs, 1);
        assert_eq!(result.beef, vec![1, 2, 3, 4]);
    }

    #[test]
    fn list_outputs_result_reads_legacy_lowercase_beef_alias() {
        // Legacy camelCase payloads stay readable via the serde alias.
        let v = json!({
            "totalOutputs": 1,
            "outputs": [],
            "beef": [5, 6, 7]
        });
        let result: ListOutputsResult = serde_json::from_value(v).unwrap();
        assert_eq!(result.beef, vec![5, 6, 7]);
    }

    #[test]
    fn list_outputs_result_missing_beef_defaults_empty() {
        let v = json!({
            "totalOutputs": 0,
            "outputs": []
        });
        let result: ListOutputsResult = serde_json::from_value(v).unwrap();
        assert!(result.beef.is_empty());
    }

    #[test]
    fn create_action_request_preserves_input_beef_bytes() {
        let req = CreateActionRequest {
            outputs: vec![],
            inputs: vec![],
            input_beef: Some(vec![1, 2, 3, 4]),
            description: "test".to_string(),
            randomize_outputs: false,
        };
        let v = serde_json::to_value(&req).unwrap();
        // serde_json encodes Vec<u8> as a number array by default. wallet-infra
        // (via `bsv-sdk::CreateActionArgs`) expects exactly that shape.
        let arr = v["inputBeef"].as_array().unwrap();
        assert_eq!(arr.len(), 4);
        assert_eq!(arr[0], 1);
    }
}
