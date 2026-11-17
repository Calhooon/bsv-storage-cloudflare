//! Reading a BEEF from another party without linking its ancestry.
//!
//! Two places hand bytes from another party to bsv-rs: the payment header's
//! `transaction` (read by the payment middleware, which links the BEEF from
//! its subject down) and a tracker's lookup answer in the mainnet fan-out.
//! This module holds the storage's own reading of both:
//!
//! - [`payment_header_link_check`]: parse the header's BEEF (no linking) and
//!   compute an upper bound on what the link the middleware performs would
//!   copy ([`link_cost`]); a payment over [`LINK_COST_CEILING`] is answered
//!   as an unreadable payment before the middleware runs;
//! - [`subject_output`]: the subject transaction's output at an index, read
//!   from the parsed BEEF without linking anything.
//!
//! The module depends on bsv-rs, serde and serde_json alone, so the tests
//! under `tests/` measure it natively with a counting allocator.

use std::collections::HashMap;

use bsv_rs::primitives::from_base64;
use bsv_rs::transaction::{Beef, MerklePath, Transaction, TransactionOutput};

/// Heap allowed per transaction copied by the link: the struct, its caches,
/// the walk's frame and memo entry. Measured natively (64-bit pointers; a
/// wasm32 build uses narrower ones), with headroom.
pub const PER_TX: u64 = 1024;
/// Heap allowed per input of a copied transaction (the input, its txid
/// string, its script wrapper).
pub const PER_INPUT: u64 = 320;
/// Heap allowed per output of a copied transaction (the output and its
/// script wrapper).
pub const PER_OUTPUT: u64 = 192;
/// Heap allowed per wire byte of a copied transaction (script bytes and the
/// serialized form the walk caches when it computes an id).
pub const PER_BYTE: u64 = 4;
/// Heap allowed per BUMP leaf carried by a copied transaction.
pub const PER_LEAF: u64 = 128;

/// The bound on the link the payment middleware performs on the payment
/// header's transaction, in the heap bytes [`LinkCost::heap_bytes`]
/// estimates.
pub const LINK_COST_CEILING: u64 = 16 * 1024 * 1024;

/// What linking a BEEF from its subject would copy, counted per copy: every
/// transaction the walk materializes, with its inputs, outputs, wire bytes
/// and BUMP leaves.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LinkCost {
    pub txs: u64,
    pub inputs: u64,
    pub outputs: u64,
    pub bytes: u64,
    pub leaves: u64,
}

impl LinkCost {
    /// The estimate in heap bytes: each count times its factor.
    pub fn heap_bytes(&self) -> u64 {
        self.txs
            .saturating_mul(PER_TX)
            .saturating_add(self.inputs.saturating_mul(PER_INPUT))
            .saturating_add(self.outputs.saturating_mul(PER_OUTPUT))
            .saturating_add(self.bytes.saturating_mul(PER_BYTE))
            .saturating_add(self.leaves.saturating_mul(PER_LEAF))
    }

    fn add_copies(&mut self, copies: u64, tx: &Transaction, wire_len: u64, leaves: u64) {
        self.txs = self.txs.saturating_add(copies);
        self.inputs = self
            .inputs
            .saturating_add(copies.saturating_mul(tx.inputs.len() as u64));
        self.outputs = self
            .outputs
            .saturating_add(copies.saturating_mul(tx.outputs.len() as u64));
        self.bytes = self.bytes.saturating_add(copies.saturating_mul(wire_len));
        self.leaves = self.leaves.saturating_add(copies.saturating_mul(leaves));
    }
}

/// The subject's txid as `Transaction::from_beef(bytes, None)` resolves it:
/// the Atomic BEEF's named transaction, else the last entry's txid.
pub fn subject_txid(beef: &Beef) -> Option<String> {
    match beef.atomic_txid.clone() {
        Some(atomic) => Some(atomic),
        None => beef.txs.last().map(|btx| btx.txid()),
    }
}

fn leaf_count(path: &MerklePath) -> u64 {
    path.path.iter().map(|level| level.len() as u64).sum()
}

/// An upper bound on what linking `beef` from its subject copies, following
/// the link walk of `Beef::find_atomic_transaction` (bsv-rs 0.4.5): the
/// subject is copied once; every transaction of the BEEF that an input of a
/// descended (unproven) transaction names is copied once in full, once as
/// the memoized stub, and once more per further input naming it; a copy
/// carries the BUMP that proves it. Only unproven transactions are
/// descended, each once. `None` when the subject is not in the BEEF (the
/// link is refused there without copying anything).
pub fn link_cost(beef: &Beef) -> Option<LinkCost> {
    let target = subject_txid(beef)?;
    let subject = beef.find_txid(&target)?.tx()?;

    // The first BUMP whose leaf level carries a hash, as the walk finds it.
    let mut bump_leaves: HashMap<&str, u64> = HashMap::new();
    for bump in &beef.bumps {
        let leaves = leaf_count(bump);
        for leaf in bump.path.first().into_iter().flatten() {
            if let Some(hash) = leaf.hash.as_deref() {
                bump_leaves.entry(hash).or_insert(leaves);
            }
        }
    }
    // A transaction's BUMP leaves, and whether the walk descends it.
    let proof = |tx: &Transaction, txid: &str| -> (u64, bool) {
        match &tx.merkle_path {
            Some(own) => (leaf_count(own), true),
            None => match bump_leaves.get(txid) {
                Some(&leaves) => (leaves, true),
                None => (0, false),
            },
        }
    };
    let wire_len = |txid: &str, tx: &Transaction| -> u64 {
        match beef.find_txid(txid).and_then(|b| b.raw_tx()) {
            Some(raw) => raw.len() as u64,
            None => tx.to_binary().len() as u64,
        }
    };

    let mut cost = LinkCost::default();
    let (subject_leaves, subject_proven) = proof(subject, &target);
    cost.add_copies(1, subject, wire_len(&target, subject), subject_leaves);

    // Inputs naming each transaction of the BEEF, over every descended one.
    let mut refs: HashMap<String, u64> = HashMap::new();
    let mut descend: Vec<&Transaction> = Vec::new();
    if !subject_proven {
        descend.push(subject);
    }
    while let Some(tx) = descend.pop() {
        for input in &tx.inputs {
            let Some(src_txid) = input.source_txid.as_deref() else {
                continue;
            };
            let Some(src) = beef.find_txid(src_txid).and_then(|b| b.tx()) else {
                continue;
            };
            match refs.get_mut(src_txid) {
                Some(n) => *n = n.saturating_add(1),
                None => {
                    refs.insert(src_txid.to_string(), 1);
                    if !proof(src, src_txid).1 {
                        descend.push(src);
                    }
                }
            }
        }
    }
    for (txid, n) in &refs {
        let Some(tx) = beef.find_txid(txid).and_then(|b| b.tx()) else {
            continue;
        };
        let (leaves, _) = proof(tx, txid);
        cost.add_copies(n.saturating_add(1), tx, wire_len(txid, tx), leaves);
    }
    Some(cost)
}

/// The payment header's fields as the payment middleware reads them
/// (`BsvPayment`: camelCase, three strings, other fields ignored).
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PaymentHeader {
    #[allow(dead_code)]
    derivation_prefix: String,
    #[allow(dead_code)]
    derivation_suffix: String,
    transaction: String,
}

/// The storage's reading of an `X-BSV-Payment` header before the payment
/// middleware reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderCheck {
    /// Go on to the middleware unchanged: the header does not decode or
    /// parse (the middleware gives its own answer), or the link is within
    /// the bound.
    Pass,
    /// The link the middleware would perform is over [`LINK_COST_CEILING`].
    OverBound { estimate: u64 },
}

/// Decode the header's transaction exactly as the payment middleware does
/// (JSON, then `from_base64`), parse it with `Beef::from_binary` (which
/// links nothing) and bound the link from the subject down.
pub fn payment_header_link_check(header: &str) -> HeaderCheck {
    let Ok(payment) = serde_json::from_str::<PaymentHeader>(header) else {
        return HeaderCheck::Pass;
    };
    let Ok(bytes) = from_base64(&payment.transaction) else {
        return HeaderCheck::Pass;
    };
    drop(payment);
    let Ok(beef) = Beef::from_binary(&bytes) else {
        return HeaderCheck::Pass;
    };
    drop(bytes);
    match link_cost(&beef) {
        Some(cost) if cost.heap_bytes() > LINK_COST_CEILING => HeaderCheck::OverBound {
            estimate: cost.heap_bytes(),
        },
        _ => HeaderCheck::Pass,
    }
}

/// The description of the refusal, in the words the payment middleware uses
/// for a payment transaction it cannot read.
pub const OVER_BOUND_DESCRIPTION: &str =
    "Payment not verified: payment transaction unreadable: the payment transaction is too large to read";

/// The subject transaction's output `vout`, read without linking: the
/// subject's entry (the same transaction `Transaction::from_beef(bytes,
/// None)` starts from), copied alone by `find_transaction_for_signing`.
pub fn subject_output(beef_bytes: &[u8], vout: usize) -> Option<TransactionOutput> {
    let beef = Beef::from_binary(beef_bytes).ok()?;
    let target = subject_txid(&beef)?;
    let mut tx = beef.find_transaction_for_signing(&target)?;
    std::mem::take(&mut tx.outputs).into_iter().nth(vout)
}
