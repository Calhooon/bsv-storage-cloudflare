//! Local BEEF / transaction signer for the admin wallet.
//!
//! After [`super::client::Wallet::create_action`] returns an unsigned
//! [`CreateActionResult`] template, this module walks the inputs, computes
//! a BIP-143 sighash per input, signs with the admin private key, and
//! emits a fully-signed raw transaction. The output of
//! [`sign_transaction`] is what the caller hands back to wallet-infra via
//! `processAction` and — for UHRP adverts — to the overlay `/submit`
//! endpoint.
//!
//! # Scope limitation
//!
//! Only **P2PKH** inputs are signed here. The admin wallet's change basket
//! holds plain P2PKH UTXOs, and the existing UHRP advert-spend flow
//! (§5 `/renew`) redeems a PushDrop output whose unlocking logic lives in
//! the PushDrop script template, not here — that route will call into a
//! dedicated PushDrop unlocker in task #7. Any input whose locking script
//! is not a P2PKH pattern is flagged as [`SignError::UnsupportedScript`].
//!
//! # Crypto
//!
//! All ECDSA is via [`bsv_rs::primitives::ec::PrivateKey::sign`], which
//! uses `k256`'s RFC 6979 deterministic-k implementation. Combined with the
//! low-S normalization bsv-rs applies, the same input → same signature →
//! same raw tx → same txid, every time. That determinism is what lets the
//! unit tests below assert byte-exact output.

use bsv_rs::primitives::bsv::sighash::{
    compute_sighash_for_signing, SighashParams, TxInput, TxOutput, SIGHASH_ALL, SIGHASH_FORKID,
};
use bsv_rs::primitives::bsv::tx_signature::TransactionSignature;
use bsv_rs::primitives::ec::PrivateKey;
use bsv_rs::primitives::encoding::{from_hex, Writer};
use bsv_rs::primitives::hash::sha256d;

use crate::error::{ERR_BEEF_PARSE, ERR_BEEF_SIGN};
use crate::wallet::types::{CreateActionResult, SignedTransaction, UnsignedInput, UnsignedOutput};

/// Default sequence number for newly-built inputs (`0xFFFF_FFFF`). Matches
/// the wallet-infra default.
const DEFAULT_SEQUENCE: u32 = 0xFFFF_FFFF;

/// Sighash scope for all admin signatures. `SIGHASH_ALL | SIGHASH_FORKID` —
/// the standard BSV sighash.
const SCOPE: u32 = SIGHASH_ALL | SIGHASH_FORKID;

/// P2PKH locking script length in bytes (`76 a9 14 <20> 88 ac`).
const P2PKH_LOCK_LEN: usize = 25;
/// Offset of the 20-byte pubkey hash inside a P2PKH script.
const P2PKH_HASH_OFFSET: usize = 3;

/// Failure modes surfaced by [`sign_transaction`].
#[derive(Debug, PartialEq, Eq)]
pub enum SignError {
    /// A field (txid hex, locking script hex) could not be decoded.
    ///
    /// Maps to [`ERR_BEEF_PARSE`] at the route boundary.
    Parse(&'static str),
    /// An input's locking script is not a supported pattern. Right now that
    /// means only P2PKH is accepted.
    UnsupportedScript,
    /// The admin pubkey-hash doesn't match the input's P2PKH hash — this
    /// wallet cannot spend the UTXO that wallet-infra selected. Indicates
    /// config drift.
    WrongKey,
    /// ECDSA signing itself failed. Vanishingly unlikely with a valid key.
    Crypto,
}

impl SignError {
    /// Map to our project-wide `ERR_*` code for route error responses.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            SignError::Parse(_) => ERR_BEEF_PARSE,
            _ => ERR_BEEF_SIGN,
        }
    }
}

/// Sign every input in `template` with `admin_key` and return the fully
/// signed transaction.
///
/// # Errors
///
/// - [`SignError::Parse`] — malformed hex in the template
/// - [`SignError::UnsupportedScript`] — non-P2PKH input (caller must route
///   PushDrop redeems through their own unlocker)
/// - [`SignError::WrongKey`] — admin key can't spend the input
/// - [`SignError::Crypto`] — ECDSA failure
pub fn sign_transaction(
    template: &CreateActionResult,
    admin_key: &PrivateKey,
) -> Result<SignedTransaction, SignError> {
    // ── Step 0: reconstruct any empty-script CHANGE outputs ────────────────
    // `rust-wallet-infra` explicitly leaves change-output `lockingScript`
    // fields empty in the createAction response; its comment at
    // `storage/create_action.rs:505` says `// Empty — wallet SDK will
    // generate`. If we serialize-and-broadcast the raw tx with those
    // fields still empty, the tx ends up on-chain with zero-byte
    // output scripts. Miners accept it (they validate inputs, not
    // outputs), but the spending tx fails the clean-stack rule
    // (`[sig, pubkey]` remains after an empty locking script runs),
    // gets stuck in mempool forever, and strict validators like bsvb
    // reject any BEEF that references it as an ancestor.
    //
    // Fix: BRC-29-derive the receive pubkey ourselves and fill in the
    // P2PKH script locally. For self-send change, sender==receiver==us,
    // so counterparty = our own identity and the derivation is
    // symmetric — the spend path in Step 2 below will re-derive the
    // same child via `derive_brc29_input_key(sender_identity = us)`
    // and the hash160s match.
    let outputs_patched =
        reconstruct_change_outputs(&template.outputs, &template.derivation_prefix, admin_key)?;

    // ── Step 1: decode every input's txid + locking script up-front ─────────
    // We need the decoded bytes in two places (sighash computation and the
    // final raw tx), so compute once.
    let decoded_inputs = decode_inputs(&template.inputs)?;
    let decoded_outputs = decode_outputs(&outputs_patched)?;

    // ── Step 2: derive the per-input signing key ──────────────────────────
    // Each input is either:
    //   (a) a "wallet payment" UTXO — locking script is P2PKH to a BRC-42
    //       child of the admin key (derived from the sender's identity +
    //       a derivation prefix/suffix). To spend, we must re-derive the
    //       same child via `derive_brc29_input_key` and sign with it.
    //       Mirrors `ScriptTemplateBRC29.unlock` in
    //       `@bsv/wallet-toolbox/src/signer/methods/completeSignedTransaction.ts:42-52`.
    //   (b) a plain P2PKH UTXO locked to the admin's root key (legacy /
    //       internal txs that didn't go through BRC-29).
    // We pick (a) when the wallet-infra template carries derivation
    // metadata; otherwise fall back to (b). Either way the resulting
    // child pubkey-hash MUST match the input's P2PKH hash160 — that's
    // our integrity check that we picked the right key.
    let admin_root_pubkey = admin_key.public_key();
    let admin_root_hash160 = admin_root_pubkey.hash160();

    // Pre-compute (signing_key, signing_pubkey_bytes, subscript) per input.
    //
    // The subscript may need to be RECONSTRUCTED from the derived pubkey.
    // rust-wallet-infra's `allocate_change_input` returns change UTXOs with
    // `locking_script = ""` (their locking_script column is populated at
    // processAction time for some outputs, not for change — the on-chain
    // script is recovered from raw_tx at script_offset, which isn't in the
    // response). When derivation metadata is present we can rebuild the
    // expected P2PKH script locally: `76 a9 14 <hash160(derived_pubkey)> 88 ac`.
    // This is exactly the script wallet-infra would have produced at the
    // derived address. Matches bsv-wallet-toolbox-rs's symmetric approach
    // (derive-then-sign-without-trusting-stored-script).
    let per_input_keys: Vec<(PrivateKey, Vec<u8>, Vec<u8>)> = template
        .inputs
        .iter()
        .zip(decoded_inputs.iter())
        .map(
            |(template_input, di)| -> Result<(PrivateKey, Vec<u8>, Vec<u8>), SignError> {
                // Try BRC-29 derivation if prefix+suffix are present. The
                // sender identity can be MISSING on self-send change UTXOs
                // (observed live: aborted-broadcast advert rounds left
                // change whose wallet-infra row carries derivation
                // prefix/suffix but sender=None → the old code fell back to
                // the root key and died on WrongKey). Self-change derivation
                // is symmetric (sender == receiver == us, exactly as the
                // Step-0 reconstruct above documents), so when the sender is
                // absent we try OUR OWN identity as the sender candidate.
                // The hash160-vs-script check below adjudicates — a wrong
                // guess can never sign.
                let has_derivation = template_input.derivation_prefix.is_some()
                    && template_input.derivation_suffix.is_some();

                let signing_key = if has_derivation {
                    let prefix = template_input.derivation_prefix.as_deref().unwrap_or("");
                    let suffix = template_input.derivation_suffix.as_deref().unwrap_or("");
                    let admin_self_hex = hex::encode(admin_root_pubkey.to_compressed());
                    let sender = template_input
                        .sender_identity_key
                        .as_deref()
                        .unwrap_or(&admin_self_hex);
                    crate::wallet::brc42::derive_brc29_input_key(admin_key, prefix, suffix, sender)
                        .map_err(|_| SignError::WrongKey)?
                } else {
                    admin_key.clone()
                };
                let signing_pubkey = signing_key.public_key();
                let pubkey_hash = signing_pubkey.hash160();

                // Resolve the script we'll use as subscript for sighash +
                // trust check. Three cases:
                //   1. wallet-infra gave us a non-empty P2PKH script → verify
                //      its hash matches the derived (or root) pubkey.
                //   2. wallet-infra gave us an empty script (change-UTXO
                //      edge case) but we have derivation metadata → build
                //      the P2PKH from the derived pubkey hash locally.
                //   3. neither → fall back to root key and root-hash check.
                let (final_key, subscript): (PrivateKey, Vec<u8>) = if !di.locking_script.is_empty()
                {
                    let input_hash = extract_p2pkh_hash(&di.locking_script)?;
                    if pubkey_hash == input_hash {
                        (signing_key, di.locking_script.clone())
                    } else if input_hash == admin_root_hash160 {
                        (admin_key.clone(), di.locking_script.clone())
                    } else {
                        return Err(SignError::WrongKey);
                    }
                } else if has_derivation {
                    // Rebuild the P2PKH script wallet-infra would have
                    // emitted at this derived address.
                    let mut script = Vec::with_capacity(P2PKH_LOCK_LEN);
                    script.extend_from_slice(&[0x76, 0xa9, 0x14]);
                    script.extend_from_slice(&pubkey_hash);
                    script.extend_from_slice(&[0x88, 0xac]);
                    (signing_key, script)
                } else {
                    // No script, no derivation — assume root-owned P2PKH.
                    let mut script = Vec::with_capacity(P2PKH_LOCK_LEN);
                    script.extend_from_slice(&[0x76, 0xa9, 0x14]);
                    script.extend_from_slice(&admin_root_hash160);
                    script.extend_from_slice(&[0x88, 0xac]);
                    (admin_key.clone(), script)
                };

                let pubkey_bytes = final_key.public_key().to_compressed().to_vec();
                Ok((final_key, pubkey_bytes, subscript))
            },
        )
        .collect::<Result<Vec<_>, _>>()?;

    // ── Step 3: build the parallel TxInput / TxOutput vectors bsv-rs's
    //           sighash code needs ────────────────────────────────────────
    let sighash_inputs: Vec<TxInput> = decoded_inputs
        .iter()
        .map(|di| TxInput {
            txid: di.txid_internal,
            output_index: di.vout,
            script: Vec::new(), // scriptSig placeholder — sighash doesn't read this
            sequence: DEFAULT_SEQUENCE,
        })
        .collect();
    let sighash_outputs: Vec<TxOutput> = decoded_outputs
        .iter()
        .map(|out| TxOutput {
            satoshis: out.satoshis,
            script: out.locking_script.clone(),
        })
        .collect();

    let version_i32 = i32::try_from(template.version).map_err(|_| SignError::Parse("version"))?;

    // ── Step 4: sign each input with its specific key ─────────────────────
    let mut unlocking_scripts: Vec<Vec<u8>> = Vec::with_capacity(decoded_inputs.len());
    for (i, (di, (signing_key, signing_pubkey_bytes, subscript))) in
        decoded_inputs.iter().zip(per_input_keys.iter()).enumerate()
    {
        let params = SighashParams {
            version: version_i32,
            inputs: &sighash_inputs,
            outputs: &sighash_outputs,
            locktime: template.lock_time,
            input_index: i,
            subscript,
            satoshis: di.satoshis,
            scope: SCOPE,
        };
        let sighash = compute_sighash_for_signing(&params);
        let ecdsa_sig = signing_key.sign(&sighash).map_err(|_| SignError::Crypto)?;
        let tx_sig = TransactionSignature::new(ecdsa_sig, SCOPE);
        let sig_bytes = tx_sig.to_checksig_format();

        // P2PKH unlocking script: push(sig) push(pubkey)
        let mut unlock = Vec::with_capacity(sig_bytes.len() + signing_pubkey_bytes.len() + 2);
        unlock.push(
            u8::try_from(sig_bytes.len()).map_err(|_| SignError::Parse("signature too long"))?,
        );
        unlock.extend_from_slice(&sig_bytes);
        unlock.push(
            u8::try_from(signing_pubkey_bytes.len())
                .map_err(|_| SignError::Parse("pubkey length"))?,
        );
        unlock.extend_from_slice(signing_pubkey_bytes);
        unlocking_scripts.push(unlock);
    }

    // ── Step 5: serialize the signed transaction ───────────────────────────
    let raw_tx = serialize_transaction(
        template.version,
        template.lock_time,
        &decoded_inputs,
        &unlocking_scripts,
        &decoded_outputs,
    );

    // ── Step 6: compute txid ──────────────────────────────────────────────
    let tx_hash = sha256d(&raw_tx);
    let mut reversed = tx_hash;
    reversed.reverse();
    let txid = hex_encode(&reversed);

    Ok(SignedTransaction { txid, raw_tx })
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Pre-decoded input buffers — avoid re-parsing hex on every loop.
struct DecodedInput {
    /// Txid as stored in the tx (internal / little-endian byte order).
    txid_internal: [u8; 32],
    vout: u32,
    satoshis: u64,
    locking_script: Vec<u8>,
}

struct DecodedOutput {
    satoshis: u64,
    locking_script: Vec<u8>,
}

fn decode_inputs(inputs: &[UnsignedInput]) -> Result<Vec<DecodedInput>, SignError> {
    let mut out = Vec::with_capacity(inputs.len());
    for inp in inputs {
        let locking_script =
            from_hex(&inp.source_locking_script).map_err(|_| SignError::Parse("locking script"))?;
        // Decode the display-order txid hex, then reverse to internal order.
        let display_bytes = from_hex(&inp.source_txid).map_err(|_| SignError::Parse("txid"))?;
        if display_bytes.len() != 32 {
            return Err(SignError::Parse("txid length"));
        }
        let mut txid_internal = [0u8; 32];
        for (i, b) in display_bytes.iter().enumerate() {
            txid_internal[31 - i] = *b;
        }
        out.push(DecodedInput {
            txid_internal,
            vout: inp.source_vout,
            satoshis: inp.source_satoshis,
            locking_script,
        });
    }
    Ok(out)
}

fn decode_outputs(outputs: &[UnsignedOutput]) -> Result<Vec<DecodedOutput>, SignError> {
    let mut out = Vec::with_capacity(outputs.len());
    for o in outputs {
        let locking_script =
            from_hex(&o.locking_script).map_err(|_| SignError::Parse("output locking script"))?;
        out.push(DecodedOutput {
            satoshis: o.satoshis,
            locking_script,
        });
    }
    Ok(out)
}

/// Replace empty-locking-script change outputs (as wallet-infra
/// returns them) with real P2PKH scripts to the BRC-29 self-send
/// derived child of the admin key.
///
/// `outputs` is the template's output list. For each entry whose
/// `locking_script` is empty AND `derivation_suffix` is set, we:
///
/// 1. BRC-29 derive the child pubkey with:
///    - protocol = `(2, "3241645161d8")`  (the `@bsv/wallet-toolbox`
///      "wallet payment" invoice-number prefix)
///    - keyID = `"<tx.derivation_prefix> <output.derivation_suffix>"`
///    - counterparty = admin's own identity pubkey (self-send)
/// 2. Build `OP_DUP OP_HASH160 <hash160(child_pub)> OP_EQUALVERIFY OP_CHECKSIG`
/// 3. Replace the output's `locking_script` with that hex.
///
/// Outputs where `locking_script` is already populated (caller-
/// requested outputs like UHRP PushDrops) pass through unchanged.
///
/// Invariant: the Step-2 `derive_brc29_input_key(admin_key, prefix,
/// suffix, admin_pubkey_hex)` later produces the SAME child, so when
/// this change UTXO is selected as an input in a future createAction,
/// the signer rebuilds the exact same P2PKH and signs it.
///
/// # Errors
///
/// - [`SignError::Parse`] — derivation_prefix/suffix missing when
///   `locking_script` is empty (malformed template)
/// - [`SignError::Crypto`] — BRC-42 derivation failed (astronomically
///   improbable scalar overflow)
fn reconstruct_change_outputs(
    outputs: &[UnsignedOutput],
    derivation_prefix: &str,
    admin_key: &PrivateKey,
) -> Result<Vec<UnsignedOutput>, SignError> {
    let admin_pub_hex =
        bsv_rs::primitives::encoding::to_hex(&admin_key.public_key().to_compressed());
    let mut patched = Vec::with_capacity(outputs.len());
    for o in outputs {
        if !o.locking_script.is_empty() {
            patched.push(o.clone());
            continue;
        }
        let Some(ref suffix) = o.derivation_suffix else {
            // Empty script + no derivation metadata = no way to
            // reconstruct. This is a template bug, not something we
            // should silently broadcast as a zero-byte output.
            return Err(SignError::Parse(
                "output has empty locking script but no derivation_suffix",
            ));
        };
        if derivation_prefix.is_empty() {
            return Err(SignError::Parse(
                "output needs reconstruction but tx-level derivation_prefix is empty",
            ));
        }
        let child_priv = crate::wallet::brc42::derive_brc29_input_key(
            admin_key,
            derivation_prefix,
            suffix,
            &admin_pub_hex,
        )
        .map_err(|_| SignError::Crypto)?;
        let child_hash160 = child_priv.public_key().hash160();
        let mut script = Vec::with_capacity(P2PKH_LOCK_LEN);
        script.extend_from_slice(&[0x76, 0xa9, 0x14]);
        script.extend_from_slice(&child_hash160);
        script.extend_from_slice(&[0x88, 0xac]);
        patched.push(UnsignedOutput {
            vout: o.vout,
            satoshis: o.satoshis,
            locking_script: bsv_rs::primitives::encoding::to_hex(&script),
            derivation_suffix: o.derivation_suffix.clone(),
        });
    }
    Ok(patched)
}

/// Match a 25-byte `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`
/// P2PKH script and return the 20-byte pubkey hash.
fn extract_p2pkh_hash(script: &[u8]) -> Result<[u8; 20], SignError> {
    if script.len() != P2PKH_LOCK_LEN
        || script[0] != 0x76 // OP_DUP
        || script[1] != 0xa9 // OP_HASH160
        || script[2] != 0x14 // 20-byte push
        || script[23] != 0x88 // OP_EQUALVERIFY
        || script[24] != 0xac
    // OP_CHECKSIG
    {
        return Err(SignError::UnsupportedScript);
    }
    let mut h = [0u8; 20];
    h.copy_from_slice(&script[P2PKH_HASH_OFFSET..P2PKH_HASH_OFFSET + 20]);
    Ok(h)
}

/// Serialize a fully-signed transaction in the standard BSV format.
fn serialize_transaction(
    version: u32,
    lock_time: u32,
    inputs: &[DecodedInput],
    unlocking_scripts: &[Vec<u8>],
    outputs: &[DecodedOutput],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32_le(version);

    w.write_var_int(inputs.len() as u64);
    for (i, inp) in inputs.iter().enumerate() {
        w.write_bytes(&inp.txid_internal);
        w.write_u32_le(inp.vout);
        let script = &unlocking_scripts[i];
        w.write_var_int(script.len() as u64);
        w.write_bytes(script);
        w.write_u32_le(DEFAULT_SEQUENCE);
    }

    w.write_var_int(outputs.len() as u64);
    for o in outputs {
        w.write_u64_le(o.satoshis);
        w.write_var_int(o.locking_script.len() as u64);
        w.write_bytes(&o.locking_script);
    }

    w.write_u32_le(lock_time);
    w.into_bytes()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ────────────────────────────────────────────────────────────────────────────
// Mixed P2PKH + PushDrop signer (used by /renew in task #7b)
// ────────────────────────────────────────────────────────────────────────────

/// Per-input unlock strategy selector for [`sign_transaction_mixed`].
///
/// The /renew flow has exactly one PushDrop input (the old advertisement
/// output being redeemed) and zero-or-more P2PKH change inputs. The admin
/// key signs both classes, but with different BIP-143 sighash subscripts and
/// different unlocking-script shapes:
///
/// | Variant | Subscript | Unlock shape | Key |
/// |---|---|---|---|
/// | `P2pkh` | `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG` | `<sig> <pubkey>` | admin |
/// | `PushDrop` | entire previous PushDrop locking script | `<sig>` | BRC-42-derived child |
///
/// The caller (`/renew` route handler) decides per-input which variant to
/// use based on the `source_locking_script` pattern.
pub enum InputUnlock<'a> {
    /// Sign as a standard P2PKH input with the admin key. Same semantics as
    /// [`sign_transaction`]'s default path.
    P2pkh,
    /// Sign as a PushDrop redeemer — the unlocking script is just
    /// `<signature>` per `bsv_rs::script::templates::PushDrop`'s unlock
    /// shape. `key` is the BRC-42-derived private key that matches the
    /// locking pubkey inside the old advertisement's PushDrop lock
    /// (protocol `(2, "uhrp advertisement")`, keyID `"1"`,
    /// counterparty `"anyone"` — see [`crate::wallet::brc42`]).
    PushDrop { key: &'a PrivateKey },
}

/// Sign a transaction where different inputs use different unlock strategies.
///
/// Exists solely for `/renew`, which spends a PushDrop advert UTXO alongside
/// P2PKH change. Do NOT use for `/upload` or other routes — they have
/// homogeneous P2PKH inputs and should stick with [`sign_transaction`],
/// which has tighter invariants.
///
/// # Errors
///
/// - [`SignError::Parse`] — malformed hex anywhere in the template
/// - [`SignError::UnsupportedScript`] — a `P2pkh` variant was passed for a
///   non-P2PKH locking script
/// - [`SignError::WrongKey`] — the admin pubkey-hash doesn't match a
///   `P2pkh` input's script
/// - [`SignError::Crypto`] — ECDSA failure
pub fn sign_transaction_mixed(
    template: &CreateActionResult,
    admin_key: &PrivateKey,
    unlocks: &[InputUnlock<'_>],
) -> Result<SignedTransaction, SignError> {
    if unlocks.len() != template.inputs.len() {
        return Err(SignError::Parse("unlock count mismatch"));
    }
    let decoded_inputs = decode_inputs(&template.inputs)?;
    // Reconstruct P2PKH change scripts before decoding — wallet-infra stores
    // `locking_script: ""` for change outputs and expects the signer to derive
    // them locally. Must match the outputs used when assembling the raw tx so
    // the sighash preimage and the final tx agree — otherwise peers reject
    // the signature on relay even though ARC's ingest accepts it. See the
    // same call in `sign_transaction` above.
    let outputs_patched =
        reconstruct_change_outputs(&template.outputs, &template.derivation_prefix, admin_key)?;
    let decoded_outputs = decode_outputs(&outputs_patched)?;

    // For P2PKH inputs we still enforce the admin-owns-it check so a misconfig
    // can't silently sign someone else's UTXO — but "owns" includes BRC-29
    // children of the admin key: wallet-infra freely allocates derived
    // payment/change UTXOs as fee inputs, and (observed live on the advert
    // path) their `sender` metadata can be missing on self-send change, in
    // which case the sender IS us and the derivation is symmetric. The
    // hash160 check adjudicates every candidate — a wrong key can never sign.
    let admin_hash160 = admin_key.public_key().hash160();
    let admin_self_hex = hex::encode(admin_key.public_key().to_compressed());
    let mut p2pkh_keys: Vec<Option<PrivateKey>> = vec![None; decoded_inputs.len()];
    for (i, di) in decoded_inputs.iter().enumerate() {
        if matches!(unlocks[i], InputUnlock::P2pkh) {
            let input_hash = extract_p2pkh_hash(&di.locking_script)?;
            if input_hash == admin_hash160 {
                p2pkh_keys[i] = Some(admin_key.clone());
                continue;
            }
            let template_input = &template.inputs[i];
            if let (Some(prefix), Some(suffix)) = (
                template_input.derivation_prefix.as_deref(),
                template_input.derivation_suffix.as_deref(),
            ) {
                let sender = template_input
                    .sender_identity_key
                    .as_deref()
                    .unwrap_or(&admin_self_hex);
                if let Ok(child) =
                    crate::wallet::brc42::derive_brc29_input_key(admin_key, prefix, suffix, sender)
                {
                    if child.public_key().hash160() == input_hash {
                        p2pkh_keys[i] = Some(child);
                        continue;
                    }
                }
            }
            return Err(SignError::WrongKey);
        }
    }

    let sighash_inputs: Vec<TxInput> = decoded_inputs
        .iter()
        .map(|di| TxInput {
            txid: di.txid_internal,
            output_index: di.vout,
            script: Vec::new(),
            sequence: DEFAULT_SEQUENCE,
        })
        .collect();
    let sighash_outputs: Vec<TxOutput> = decoded_outputs
        .iter()
        .map(|out| TxOutput {
            satoshis: out.satoshis,
            script: out.locking_script.clone(),
        })
        .collect();

    let version_i32 = i32::try_from(template.version).map_err(|_| SignError::Parse("version"))?;

    let mut unlocking_scripts: Vec<Vec<u8>> = Vec::with_capacity(decoded_inputs.len());
    for (i, di) in decoded_inputs.iter().enumerate() {
        let params = SighashParams {
            version: version_i32,
            inputs: &sighash_inputs,
            outputs: &sighash_outputs,
            locktime: template.lock_time,
            input_index: i,
            subscript: &di.locking_script,
            satoshis: di.satoshis,
            scope: SCOPE,
        };
        let sighash = compute_sighash_for_signing(&params);

        let unlock_bytes = match &unlocks[i] {
            InputUnlock::P2pkh => {
                let key = p2pkh_keys[i].as_ref().unwrap_or(admin_key);
                let ecdsa_sig = key.sign(&sighash).map_err(|_| SignError::Crypto)?;
                let tx_sig = TransactionSignature::new(ecdsa_sig, SCOPE);
                let sig_bytes = tx_sig.to_checksig_format();
                let pubkey_bytes = key.public_key().to_compressed().to_vec();
                build_p2pkh_unlock(&sig_bytes, &pubkey_bytes)?
            }
            InputUnlock::PushDrop { key } => {
                let ecdsa_sig = key.sign(&sighash).map_err(|_| SignError::Crypto)?;
                let tx_sig = TransactionSignature::new(ecdsa_sig, SCOPE);
                let sig_bytes = tx_sig.to_checksig_format();
                build_pushdrop_unlock(&sig_bytes)?
            }
        };
        unlocking_scripts.push(unlock_bytes);
    }

    let raw_tx = serialize_transaction(
        template.version,
        template.lock_time,
        &decoded_inputs,
        &unlocking_scripts,
        &decoded_outputs,
    );

    let mut reversed = sha256d(&raw_tx);
    reversed.reverse();
    let txid = hex_encode(&reversed);

    Ok(SignedTransaction { txid, raw_tx })
}

/// Build a P2PKH unlocking script: `<len> <sig> <len> <pubkey>`.
fn build_p2pkh_unlock(sig: &[u8], pubkey: &[u8]) -> Result<Vec<u8>, SignError> {
    let mut unlock = Vec::with_capacity(sig.len() + pubkey.len() + 2);
    unlock.push(u8::try_from(sig.len()).map_err(|_| SignError::Parse("signature too long"))?);
    unlock.extend_from_slice(sig);
    unlock.push(u8::try_from(pubkey.len()).map_err(|_| SignError::Parse("pubkey length"))?);
    unlock.extend_from_slice(pubkey);
    Ok(unlock)
}

/// Build a PushDrop unlocking script — just `<len> <sig>`. The locking script
/// already carries the pubkey (PushDrop uses a P2PK-style lock), so the
/// redeemer only pushes the signature. Matches
/// `bsv_rs::script::templates::PushDrop::unlock` exactly.
fn build_pushdrop_unlock(sig: &[u8]) -> Result<Vec<u8>, SignError> {
    let mut unlock = Vec::with_capacity(sig.len() + 1);
    unlock.push(u8::try_from(sig.len()).map_err(|_| SignError::Parse("signature too long"))?);
    unlock.extend_from_slice(sig);
    Ok(unlock)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    use super::*;

    // The classic BIP-32 test-vector key: private key = 0x000...001. Its
    // pubkey and P2PKH hash are well-known, so the whole sign-and-build
    // pipeline is fully reproducible without any secret state.
    const TEST_KEY_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    fn admin_key() -> PrivateKey {
        PrivateKey::from_hex(TEST_KEY_HEX).expect("valid test key")
    }

    /// Build a P2PKH locking script for `key`'s compressed pubkey.
    fn p2pkh_for_key(key: &PrivateKey) -> Vec<u8> {
        let hash = key.public_key().hash160();
        let mut s = Vec::with_capacity(P2PKH_LOCK_LEN);
        s.push(0x76);
        s.push(0xa9);
        s.push(0x14);
        s.extend_from_slice(&hash);
        s.push(0x88);
        s.push(0xac);
        s
    }

    /// Common test template: one P2PKH input → one P2PKH output.
    fn sample_template(key: &PrivateKey) -> CreateActionResult {
        let locking = p2pkh_for_key(key);
        let locking_hex = hex_encode(&locking);
        CreateActionResult {
            input_beef: vec![],
            inputs: vec![UnsignedInput {
                vin: 0,
                // Arbitrary but deterministic txid — byte pattern 01..32.
                source_txid: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                    .to_string(),
                source_vout: 0,
                source_satoshis: 100_000,
                source_locking_script: locking_hex.clone(),
                source_transaction: None,
                derivation_prefix: None,
                derivation_suffix: None,
                sender_identity_key: None,
            }],
            outputs: vec![UnsignedOutput {
                vout: 0,
                satoshis: 99_000,
                locking_script: locking_hex,
                derivation_suffix: None,
            }],
            version: 1,
            lock_time: 0,
            reference: "test-ref".to_string(),
            derivation_prefix: String::new(),
        }
    }

    // ── ECDSA determinism ───────────────────────────────────────────────────

    #[test]
    fn ecdsa_signature_is_deterministic_rfc6979() {
        // Two independent signings of the same digest with the same key
        // must produce identical bytes (that's RFC 6979).
        let key = admin_key();
        let digest = [0x42u8; 32];
        let s1 = key.sign(&digest).unwrap();
        let s2 = key.sign(&digest).unwrap();
        assert_eq!(s1.to_compact(), s2.to_compact());
        // And the R component has the known RFC 6979 expected value for
        // (k=1, msg=[0x42;32]) — by producing it and checking it lands in
        // low-S form, we confirm the low-S normalization is on.
        assert!(s1.is_low_s());
    }

    // ── P2PKH script matcher ────────────────────────────────────────────────

    #[test]
    fn extract_p2pkh_hash_accepts_valid_script() {
        let key = admin_key();
        let script = p2pkh_for_key(&key);
        let hash = extract_p2pkh_hash(&script).unwrap();
        assert_eq!(hash, key.public_key().hash160());
    }

    #[test]
    fn extract_p2pkh_hash_rejects_wrong_length() {
        assert_eq!(
            extract_p2pkh_hash(&[0x76; 24]),
            Err(SignError::UnsupportedScript)
        );
    }

    #[test]
    fn extract_p2pkh_hash_rejects_wrong_opcodes() {
        let mut bogus = p2pkh_for_key(&admin_key());
        bogus[0] = 0x00; // not OP_DUP
        assert_eq!(
            extract_p2pkh_hash(&bogus),
            Err(SignError::UnsupportedScript)
        );
    }

    // ── Happy-path signing ──────────────────────────────────────────────────

    #[test]
    fn sign_transaction_produces_nonzero_raw_tx() {
        let key = admin_key();
        let template = sample_template(&key);
        let signed = sign_transaction(&template, &key).unwrap();
        // Raw tx must be non-empty and carry the version prefix (01 00 00 00).
        assert!(!signed.raw_tx.is_empty());
        assert_eq!(&signed.raw_tx[0..4], &[0x01, 0x00, 0x00, 0x00]);
        // txid is 64 lowercase hex chars.
        assert_eq!(signed.txid.len(), 64);
        assert!(signed.txid.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sign_transaction_is_deterministic() {
        // Same inputs → same output, always (RFC 6979 + fixed serialization).
        let key = admin_key();
        let template = sample_template(&key);
        let s1 = sign_transaction(&template, &key).unwrap();
        let s2 = sign_transaction(&template, &key).unwrap();
        assert_eq!(s1.raw_tx, s2.raw_tx);
        assert_eq!(s1.txid, s2.txid);
    }

    #[test]
    fn sign_transaction_txid_matches_sha256d_of_raw_tx() {
        let key = admin_key();
        let template = sample_template(&key);
        let signed = sign_transaction(&template, &key).unwrap();

        // Recompute txid by hashing the raw bytes ourselves. If this
        // diverges from what sign_transaction reports, something is wrong
        // with the reversal / encoding.
        let mut h = sha256d(&signed.raw_tx);
        h.reverse();
        assert_eq!(signed.txid, hex_encode(&h));
    }

    // ── Error paths ─────────────────────────────────────────────────────────

    #[test]
    fn sign_transaction_rejects_wrong_key() {
        // Build the template under the test admin key, then try to sign
        // with a different key — we must refuse to forge unlocks for a
        // UTXO we don't own.
        let key = admin_key();
        let other = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap();
        let template = sample_template(&key);
        assert!(matches!(
            sign_transaction(&template, &other),
            Err(SignError::WrongKey)
        ));
    }

    #[test]
    fn sign_transaction_rejects_non_p2pkh_input() {
        let key = admin_key();
        let mut template = sample_template(&key);
        // Replace the input locking script with something that's not P2PKH.
        template.inputs[0].source_locking_script = "6a0401020304".to_string(); // OP_RETURN <data>
        assert!(matches!(
            sign_transaction(&template, &key),
            Err(SignError::UnsupportedScript)
        ));
    }

    #[test]
    fn sign_transaction_rejects_malformed_hex() {
        let key = admin_key();
        let mut template = sample_template(&key);
        template.inputs[0].source_locking_script = "zzzz".to_string();
        assert!(matches!(
            sign_transaction(&template, &key),
            Err(SignError::Parse(_))
        ));
    }

    #[test]
    fn sign_transaction_rejects_bad_txid_length() {
        let key = admin_key();
        let mut template = sample_template(&key);
        template.inputs[0].source_txid = "dead".to_string();
        assert!(matches!(
            sign_transaction(&template, &key),
            Err(SignError::Parse(_))
        ));
    }

    // ── SignError.code() mapping ────────────────────────────────────────────

    #[test]
    fn sign_error_codes_map_to_project_constants() {
        assert_eq!(SignError::Parse("x").code(), ERR_BEEF_PARSE);
        assert_eq!(SignError::UnsupportedScript.code(), ERR_BEEF_SIGN);
        assert_eq!(SignError::WrongKey.code(), ERR_BEEF_SIGN);
        assert_eq!(SignError::Crypto.code(), ERR_BEEF_SIGN);
    }

    // ── Mixed-unlock signer (sign_transaction_mixed) ────────────────────────

    #[test]
    fn sign_transaction_mixed_matches_pure_p2pkh_path() {
        // Feeding every input as `InputUnlock::P2pkh` must yield the exact
        // same raw tx bytes as `sign_transaction`. The determinism hooks into
        // RFC-6979 so the byte match is real, not coincidental.
        let key = admin_key();
        let template = sample_template(&key);
        let pure = sign_transaction(&template, &key).unwrap();
        let mixed = sign_transaction_mixed(&template, &key, &[InputUnlock::P2pkh]).unwrap();
        assert_eq!(pure.raw_tx, mixed.raw_tx);
        assert_eq!(pure.txid, mixed.txid);
    }

    #[test]
    fn sign_transaction_mixed_rejects_unlock_count_mismatch() {
        let key = admin_key();
        let template = sample_template(&key);
        // One input, zero unlocks → count mismatch.
        let err = sign_transaction_mixed(&template, &key, &[]).unwrap_err();
        assert!(matches!(err, SignError::Parse(_)));
    }

    #[test]
    fn pushdrop_unlock_builder_is_length_prefix_plus_sig() {
        // Sanity-check the unlocking-script builder: one length byte + sig
        // bytes, nothing else (P2PK-style redeem).
        let sig = [0x30, 0x44, 0x02, 0x20];
        let built = build_pushdrop_unlock(&sig).unwrap();
        assert_eq!(built[0], sig.len() as u8);
        assert_eq!(&built[1..], &sig);
    }

    #[test]
    fn pushdrop_unlock_rejects_oversized_signature() {
        // u8 length prefix — >255 byte signatures can't fit. BSV DER sigs
        // are ~72 bytes max, so this is purely defensive.
        let sig = vec![0u8; 256];
        let err = build_pushdrop_unlock(&sig).unwrap_err();
        assert!(matches!(err, SignError::Parse(_)));
    }

    #[test]
    fn sign_transaction_mixed_signs_pushdrop_input_with_derived_key() {
        // Build a template where the sole input's locking script is
        // arbitrary bytes (representing a PushDrop lock) and the admin key
        // must NOT own the hash. Sign with a distinct `derived_key` as
        // PushDrop — this path bypasses the admin-ownership check and
        // produces `<sig>`-only unlock bytes.
        let admin = admin_key();
        let derived = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap();
        let mut template = sample_template(&admin);
        // Non-P2PKH lock (some PushDrop-ish script). Content doesn't matter
        // for this test — we just need bytes that are not 25-byte P2PKH.
        template.inputs[0].source_locking_script =
            "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac".to_string();
        let signed = sign_transaction_mixed(
            &template,
            &admin,
            &[InputUnlock::PushDrop { key: &derived }],
        )
        .unwrap();
        assert!(!signed.raw_tx.is_empty());
        assert_eq!(signed.txid.len(), 64);
    }

    // ── Change-output reconstruction (the push-to-bsvb blocker fix) ─────────

    /// Verifies that `sign_transaction` fills in an empty change-output
    /// locking script with a valid 25-byte P2PKH before serializing the
    /// raw tx.
    ///
    /// Without this fix, wallet-infra's `locking_script: String::new()`
    /// gets broadcast as a 0-byte output script (miners accept; future
    /// spends fail the clean-stack rule with stack `[sig, pubkey]` and
    /// never confirm). Strict BEEF validators (bsvb.tech) reject our
    /// entire BEEF downstream. See
    /// `rust-wallet-infra/src/storage/create_action.rs:505` for the
    /// upstream behaviour we're compensating for.
    #[test]
    fn reconstructs_empty_change_output_as_valid_p2pkh() {
        let admin = admin_key();
        let mut template = sample_template(&admin);

        // Simulate wallet-infra's change-output shape: empty locking script,
        // but derivation_suffix present + tx-level derivation_prefix set.
        template.outputs.push(UnsignedOutput {
            vout: 1,
            satoshis: 55,
            locking_script: String::new(),
            derivation_suffix: Some("change-suffix-xyz".to_string()),
        });
        template.derivation_prefix = "tx-prefix-abc".to_string();

        let signed = sign_transaction(&template, &admin).expect("sign must succeed");

        // Parse the serialized raw_tx and inspect output[1]. We reuse
        // bsv-rs's parser rather than eyeballing bytes.
        let tx = bsv_rs::transaction::Transaction::from_hex(&hex_encode(&signed.raw_tx))
            .expect("serialized raw_tx must parse");
        assert_eq!(tx.outputs.len(), 2);
        let change_script_bytes = tx.outputs[1].locking_script.to_binary();

        // HARD assertion: change-output script is exactly 25 bytes of
        // standard P2PKH. A regression that reintroduces the empty
        // script would fail here with len=0.
        assert_eq!(
            change_script_bytes.len(),
            P2PKH_LOCK_LEN,
            "change output must be 25-byte P2PKH, got {} bytes",
            change_script_bytes.len()
        );
        assert_eq!(change_script_bytes[0], 0x76, "OP_DUP");
        assert_eq!(change_script_bytes[1], 0xa9, "OP_HASH160");
        assert_eq!(change_script_bytes[2], 0x14, "push 20 bytes");
        assert_eq!(change_script_bytes[23], 0x88, "OP_EQUALVERIFY");
        assert_eq!(change_script_bytes[24], 0xac, "OP_CHECKSIG");

        // Additional invariant: the hash160 matches what the SPEND
        // path would re-derive via `derive_brc29_input_key(sender=us)`.
        // If this equality ever breaks, the change UTXO is unspendable
        // by our own signer — a showstopper.
        let expected_child = crate::wallet::brc42::derive_brc29_input_key(
            &admin,
            "tx-prefix-abc",
            "change-suffix-xyz",
            &bsv_rs::primitives::encoding::to_hex(&admin.public_key().to_compressed()),
        )
        .unwrap();
        let expected_hash = expected_child.public_key().hash160();
        assert_eq!(
            &change_script_bytes[3..23],
            &expected_hash[..],
            "hash160 in P2PKH must match BRC-29 self-send derived pubkey hash"
        );
    }

    /// `reconstruct_change_outputs` refuses to silently produce a
    /// zero-byte output when the metadata needed to rebuild is missing.
    #[test]
    fn rejects_empty_output_without_derivation_metadata() {
        let admin = admin_key();
        let mut template = sample_template(&admin);
        template.outputs.push(UnsignedOutput {
            vout: 1,
            satoshis: 55,
            locking_script: String::new(),
            derivation_suffix: None, // missing!
        });
        template.derivation_prefix = "tx-prefix-abc".to_string();
        let err = sign_transaction(&template, &admin).expect_err("must err — no suffix");
        // Map through Parse variant; exact message is implementation detail,
        // but the variant is the stable contract.
        assert!(
            matches!(err, SignError::Parse(_)),
            "expected Parse, got {err:?}"
        );
    }

    /// A caller-provided output (non-change, explicit locking_script)
    /// must pass through `reconstruct_change_outputs` unmodified.
    #[test]
    fn non_empty_outputs_pass_through_unchanged() {
        let admin = admin_key();
        let outputs = vec![UnsignedOutput {
            vout: 0,
            satoshis: 1,
            locking_script: "76a914deadbeefcafebabe1234567890abcdef1234567888ac".to_string(),
            derivation_suffix: None,
        }];
        let patched = reconstruct_change_outputs(&outputs, "", &admin).unwrap();
        assert_eq!(patched.len(), 1);
        assert_eq!(
            patched[0].locking_script, outputs[0].locking_script,
            "explicit locking_script must pass through unchanged"
        );
    }

    /// Live regression (2026-07-02): wallet-infra hands back self-send
    /// change whose row has BRC-29 derivation prefix/suffix but NO sender
    /// identity (debris from aborted-broadcast rounds). Self-change
    /// derivation is symmetric — sender == us — so the signer must try our
    /// own identity, adjudicated by the hash160 check.
    #[test]
    fn signs_self_change_input_with_missing_sender() {
        let admin = admin_key();
        let prefix = "8nEVJp4ImG7xAruNBQhfDA==";
        let suffix = "ZGrDCR61UIOfWKemPXg3xA==";
        let self_hex = hex_encode(&admin.public_key().to_compressed());
        let child = crate::wallet::brc42::derive_brc29_input_key(&admin, prefix, suffix, &self_hex)
            .unwrap();

        let mut template = sample_template(&admin);
        template.inputs[0].source_locking_script = hex_encode(&p2pkh_for_key(&child));
        template.inputs[0].derivation_prefix = Some(prefix.to_string());
        template.inputs[0].derivation_suffix = Some(suffix.to_string());
        template.inputs[0].sender_identity_key = None; // ← the poison

        let signed = sign_transaction(&template, &admin);
        assert!(
            signed.is_ok(),
            "self-change with missing sender must sign: {:?}",
            signed.err()
        );

        // A script owned by nobody we can derive must still refuse.
        let mut foreign = sample_template(&admin);
        foreign.inputs[0].source_locking_script = {
            let mut l = vec![0x76, 0xa9, 0x14];
            l.extend_from_slice(&[0u8; 20]);
            l.extend_from_slice(&[0x88, 0xac]);
            hex_encode(&l)
        };
        foreign.inputs[0].derivation_prefix = Some(prefix.to_string());
        foreign.inputs[0].derivation_suffix = Some(suffix.to_string());
        assert!(matches!(
            sign_transaction(&foreign, &admin),
            Err(SignError::WrongKey)
        ));
    }
}
