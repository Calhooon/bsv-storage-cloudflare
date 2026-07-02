//! Wallet-internal request/response shapes.
//!
//! These types are what the route handlers consume. They map onto — but do
//! not directly match — `wallet-infra`'s wire shapes (`CreateActionArgs`,
//! `StorageCreateActionResult`, etc.). Routes shouldn't care about the
//! difference between positional and named JSON-RPC param formats, and
//! they shouldn't handle raw `serde_json::Value` results — the client
//! layer translates those for them.
//!
//! Naming follows the project convention: `camelCase` on the wire (matching
//! the TS-derived `wallet-infra` schema), `snake_case` in Rust.

use serde::{Deserialize, Serialize};

// ────────────────────────────────────────────────────────────────────────────
// createAction
// ────────────────────────────────────────────────────────────────────────────

/// One output the caller wants the wallet to create.
///
/// Mirrors wallet-infra's `ValidCreateActionOutput` (from `bsv-sdk`) — a
/// locking script (hex), satoshis, plus optional basket/tags for wallet
/// bookkeeping. `output_description` is required (wallet-infra enforces a
/// minimum length of 5) so we surface it as non-optional here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateActionOutput {
    /// Locking script as lowercase hex.
    pub locking_script: String,
    /// Satoshis to lock under this script. UHRP advert outputs use 1.
    pub satoshis: u64,
    /// Human-readable description (>= 5 chars — wallet-infra enforces this).
    pub output_description: String,
    /// Output basket name for wallet bookkeeping. UHRP adverts use
    /// `"uhrp advertisements"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basket: Option<String>,
    /// Tags attached to the output for later filtering via `listOutputs`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub tags: Vec<String>,
    /// Opaque per-output metadata. rust-wallet-infra uses `customInstructions
    /// IS NOT NULL` (combined with `change = 1`) as its "ours" predicate
    /// when flipping outputs to `spendable = 1` post-processAction. Passing
    /// any string here marks the output as self-owned; callers that
    /// originate UHRP adverts stuff BRC-42 derivation info in here so the
    /// /renew redeem flow can rebuild the child key from the tag payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_instructions: Option<String>,
}

/// One input the caller is providing (for `/renew` — spending an existing
/// UHRP advert UTXO).
///
/// `unlocking_script_length` is the **estimated** length of the unlocking
/// script the Worker will produce after signing; wallet-infra uses it for
/// fee calculation before the signature exists. P2PKH is ~106 bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateActionInput {
    /// Outpoint in `"txid.vout"` format (matches wallet-infra's convention).
    pub outpoint: String,
    /// Estimated unlocking script length in bytes (for fee calc).
    pub unlocking_script_length: u32,
    /// Human-readable description of what this input is.
    pub input_description: String,
}

/// Arguments for [`client::Wallet::create_action`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AbortActionRequest {
    /// `reference` field returned by `createAction`. Can also be a 64-hex
    /// txid per wallet-infra's `find_transaction_for_abort`.
    pub reference: String,
}

/// Result of [`client::Wallet::abort_action`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AbortActionResult {
    /// `true` when the tx was found and marked failed. A tx that was
    /// already completed/broadcast returns `false` (nothing to abort).
    pub aborted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateActionRequest {
    /// Outputs to create.
    pub outputs: Vec<CreateActionOutput>,
    /// Inputs to consume (empty for `/advertise`, populated for `/renew`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<CreateActionInput>,
    /// If `inputs` contains outpoints **not already tracked** by wallet-infra,
    /// the caller must provide the BEEF bundle covering them so the server
    /// can verify their scripts and satoshis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_beef: Option<Vec<u8>>,
    /// Human-readable description of the overall action.
    pub description: String,
    /// `randomizeOutputs: false` — ensures the server doesn't reshuffle our
    /// outputs. Required for UHRP adverts where `outputIndex 0` is load-bearing.
    #[serde(default = "default_false")]
    pub randomize_outputs: bool,
}

fn default_false() -> bool {
    false
}

/// One input wallet-infra selected from its own UTXO set, surfaced back to
/// the signer so we can build the sighash.
///
/// This is the subset of `StorageCreateTransactionInput` the Worker actually
/// needs: a locking script (hex), satoshis, and the source outpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsignedInput {
    /// Position in the final transaction (0-indexed).
    pub vin: u32,
    /// Source transaction id (hex, display order).
    pub source_txid: String,
    /// Source output index.
    pub source_vout: u32,
    /// Source output value in satoshis. Required for the BIP-143 sighash.
    pub source_satoshis: u64,
    /// Locking script of the source output (hex). The P2PKH script pattern
    /// is `OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG`
    /// (25 bytes, `76a914...88ac`).
    pub source_locking_script: String,
    /// Raw source transaction bytes, if wallet-infra included them. Used for
    /// BEEF reassembly on the signed side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_transaction: Option<Vec<u8>>,
    /// BRC-29 derivation prefix attached to this UTXO when wallet-infra
    /// received it as a "wallet payment" (i.e. via internalizeAction).
    /// Combined with `derivation_suffix` and `sender_identity_key`, the
    /// signer derives the BRC-42 child key (protocol `[2, "3241645161d8"]`)
    /// that the sender used to construct the locking script.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derivation_prefix: Option<String>,
    /// BRC-29 derivation suffix (see [`derivation_prefix`]).
    ///
    /// [`derivation_prefix`]: Self::derivation_prefix
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derivation_suffix: Option<String>,
    /// 33-byte hex pubkey of the original payment sender. Used as the BRC-42
    /// counterparty when re-deriving the child key for spending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_identity_key: Option<String>,
}

/// One output wallet-infra placed in the transaction (either a user output
/// we requested, or a change output the wallet added).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsignedOutput {
    /// Position in the final transaction.
    pub vout: u32,
    /// Satoshi amount.
    pub satoshis: u64,
    /// Locking script (hex) exactly as it will appear on-chain.
    ///
    /// **Important:** for self-send change outputs, wallet-infra returns
    /// this as an EMPTY STRING — the Worker (us) is responsible for
    /// constructing the real P2PKH script from the BRC-29 derivation
    /// metadata (`derivation_suffix` here + tx-level `derivation_prefix` + admin identity key).
    /// See `rust-wallet-infra/src/storage/create_action.rs:505` where the field is explicitly emptied.
    ///
    /// If the Worker broadcasts the raw_tx with this field still empty,
    /// the on-chain output has a zero-byte locking script that leaves
    /// `[sig, pubkey]` on the stack when spent — a clean-stack-rule
    /// failure. Strict validators (bsvb.tech) then reject the BEEF and
    /// refuse to sync the advert. Miners may mine the carrying tx
    /// anyway (they validate inputs, not future spendability), but
    /// downstream spend txs get stuck in mempool indefinitely.
    ///
    /// `super::signer::reconstruct_change_outputs` fills this in before
    /// we serialize the raw tx.
    pub locking_script: String,
    /// BRC-29 derivation suffix attached to self-send change outputs.
    /// Combined with the tx-level `derivation_prefix` gives the keyID
    /// the Worker needs to BRC-42-derive the child pubkey used for the
    /// P2PKH script. `None` for user-requested outputs (where
    /// `locking_script` is already populated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derivation_suffix: Option<String>,
}

/// What [`client::Wallet::create_action`] returns.
///
/// This is the "template" the Worker must sign. After signing, pass it into
/// [`client::Wallet::process_action`] alongside the raw signed tx bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateActionResult {
    /// BEEF containing every ancestor of every `inputs[].source_txid`.
    /// Needed both for sighash context and so wallet-infra can reconstruct
    /// the full SPV proof after signing.
    #[serde(default)]
    pub input_beef: Vec<u8>,
    /// Inputs selected by the wallet (change UTXOs) plus any we provided.
    pub inputs: Vec<UnsignedInput>,
    /// Final output set, including any wallet-added change.
    pub outputs: Vec<UnsignedOutput>,
    /// Transaction version field.
    #[serde(default = "default_version")]
    pub version: u32,
    /// Transaction locktime field.
    #[serde(default)]
    pub lock_time: u32,
    /// Opaque reference returned by wallet-infra. Must be echoed back on
    /// `processAction`.
    pub reference: String,
    /// Tx-level BRC-29 derivation prefix. Combined with each change
    /// output's `derivation_suffix` this forms the keyID the Worker
    /// uses to derive the child pubkey for each self-send change
    /// output's P2PKH script. `String::new()` for txs with no change
    /// (all outputs are caller-provided).
    #[serde(default)]
    pub derivation_prefix: String,
}

fn default_version() -> u32 {
    1
}

// ────────────────────────────────────────────────────────────────────────────
// listOutputs
// ────────────────────────────────────────────────────────────────────────────

/// Arguments for [`client::Wallet::list_outputs`]. Used by `/renew` to find
/// the caller's existing UHRP advert UTXO, and by `/list` to enumerate all
/// adverts owned by a given identity key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListOutputsRequest {
    /// Output basket, e.g. `"uhrp advertisements"`.
    pub basket: String,
    /// Tag filters. Combined per `tag_query_mode`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// `"all"` (AND) or `"any"` (OR). Defaults to `"any"` server-side.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag_query_mode: Option<String>,
    /// `"entire transactions"` to include raw source tx bytes (needed by
    /// `/renew` when rebuilding the PushDrop unlocker), or `"locking scripts"`
    /// for a cheaper query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include: Option<String>,
    /// Include tag list on each output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_tags: Option<bool>,
    /// Include each output's locking script (wallet-toolbox
    /// `includeLockingScripts`) — /renew prices from PushDrop field 4.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_locking_scripts: Option<bool>,
    /// Max rows to return. wallet-infra caps this server-side.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Pagination offset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i32>,
}

/// One output row returned by `listOutputs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputItem {
    /// Satoshi value.
    pub satoshis: u64,
    /// `{txid, vout}` shaped as `"txid.vout"` in wallet-infra, but returned
    /// here as a structured [`Outpoint`] for stronger typing.
    pub outpoint: Outpoint,
    /// Whether the UTXO is currently spendable.
    pub spendable: bool,
    /// Tags on the output, if `include_tags: true` was set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Locking script (hex), if `include: "locking scripts"` or
    /// `"entire transactions"` was set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locking_script: Option<String>,
}

/// Structured outpoint — matches wallet-infra's `OutpointItem` shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Outpoint {
    /// Transaction id (hex, display order).
    pub txid: String,
    /// Output index.
    pub vout: u32,
}

/// What [`client::Wallet::list_outputs`] returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListOutputsResult {
    /// Total count before pagination.
    pub total_outputs: u32,
    /// Returned rows.
    #[serde(default)]
    pub outputs: Vec<OutputItem>,
    /// BEEF (raw bytes) covering every output in `outputs` when `include` is
    /// `"entire transactions"`. Empty otherwise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub beef: Vec<u8>,
}

// ────────────────────────────────────────────────────────────────────────────
// processAction
// ────────────────────────────────────────────────────────────────────────────

/// Arguments for [`client::Wallet::process_action`].
///
/// Exactly matches wallet-infra's `StorageProcessActionArgs` shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessActionRequest {
    /// `true` — we're processing a brand-new transaction (the one we just signed).
    pub is_new_tx: bool,
    /// `false` — the Worker handles the broadcast itself; wallet-infra
    /// should only record the tx.
    pub is_send_with: bool,
    /// `false` — wallet-infra should attempt broadcast.
    pub is_no_send: bool,
    /// `false` — broadcast synchronously.
    pub is_delayed: bool,
    /// Opaque reference returned by `createAction`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Final txid (display-order hex).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txid: Option<String>,
    /// Fully signed raw transaction bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_tx: Option<Vec<u8>>,
    /// Other reference strings to broadcast with this one (empty for us).
    #[serde(default)]
    pub send_with: Vec<String>,
}

/// What [`client::Wallet::process_action`] returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessActionResult {
    /// Per-tx broadcast results when `send_with` was non-empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_with_results: Option<serde_json::Value>,
    /// Non-delayed broadcast results.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_delayed_results: Option<serde_json::Value>,
    /// Optional log output from the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
}

// ────────────────────────────────────────────────────────────────────────────
// signer output
// ────────────────────────────────────────────────────────────────────────────

/// Output of [`super::signer::sign_transaction`].
///
/// After signing, the route handler knows the final `txid`, has the raw
/// signed tx bytes to hand to `processAction`, and has the BEEF bundle
/// (input BEEF + new tx) if it needs to submit to an overlay.
#[derive(Debug, Clone)]
pub struct SignedTransaction {
    /// Display-order txid, lowercase hex.
    pub txid: String,
    /// Fully signed raw tx bytes (ready for broadcast).
    pub raw_tx: Vec<u8>,
}
