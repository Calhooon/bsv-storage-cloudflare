//! The paid routes' door on the payment header, measured: what the payment
//! middleware allocates reading an `X-BSV-Payment` header follows the
//! header's size, with no check of the storage's own in front of it.
//!
//! The middleware (bsv-middleware-cloudflare 0.7.4, core 0.4.3) parses the
//! header's JSON, decodes its base64 `transaction`, reads the BEEF's subject
//! alone (`verify_payment_output`: output 0's script and amount; nothing
//! linked, no script run) and takes the subject's txid
//! (`payment_subject_txid`) before it claims the derivation prefix. Native
//! measurements with a counting allocator around those calls; every test
//! takes the allocator's lock, so one measurement runs at a time.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use bsv_middleware_cloudflare::core::MemoryStore;
use bsv_middleware_cloudflare::core::{
    expected_locking_script, payment_subject_txid, verify_payment_output, BsvPayment,
    PaymentVerdict, UnverifiableReason,
};
use bsv_middleware_cloudflare::AuthContext;
use bsv_rs::primitives::hash::sha256d;
use bsv_rs::primitives::{from_base64, to_base64, to_hex};
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, ATOMIC_BEEF, BEEF_V1, BEEF_V2,
};
use bsv_storage_cloudflare::paid::{
    decide, internalize_call, Decision, Remittance, PAYMENT_HEADER_MAX, PAYMENT_TOO_LARGE,
};

// ── the counting allocator ──────────────────────────────────────────────

struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            let now = CURRENT.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = System.realloc(ptr, layout, new_size);
        if !p.is_null() {
            if new_size >= layout.size() {
                let now = CURRENT.fetch_add(new_size - layout.size(), Ordering::Relaxed)
                    + (new_size - layout.size());
                PEAK.fetch_max(now, Ordering::Relaxed);
            } else {
                CURRENT.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        p
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn measure_lock() -> MutexGuard<'static, ()> {
    ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner())
}

/// The peak heap `f` adds over what was live when it started, its result
/// dropped inside the measurement.
fn peak_of<R>(f: impl FnOnce() -> R) -> usize {
    let base = CURRENT.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let r = f();
    drop(r);
    PEAK.load(Ordering::SeqCst).saturating_sub(base)
}

// ── building BEEFs ──────────────────────────────────────────────────────

fn varint(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

/// A raw transaction: inputs (source txid in display hex, vout, unlocking
/// script) and outputs (satoshis, locking script).
#[derive(Clone)]
struct RawTx {
    inputs: Vec<(String, u32, Vec<u8>)>,
    outputs: Vec<(u64, Vec<u8>)>,
    lock_time: u32,
}

impl RawTx {
    fn new() -> Self {
        RawTx {
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
        }
    }
    fn input(mut self, txid: &str, vout: u32, script: Vec<u8>) -> Self {
        self.inputs.push((txid.to_string(), vout, script));
        self
    }
    fn output(mut self, sats: u64, script: Vec<u8>) -> Self {
        self.outputs.push((sats, script));
        self
    }
    fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&1u32.to_le_bytes());
        varint(&mut out, self.inputs.len() as u64);
        for (txid, vout, script) in &self.inputs {
            let mut id = hex::decode(txid).unwrap();
            id.reverse();
            out.extend_from_slice(&id);
            out.extend_from_slice(&vout.to_le_bytes());
            varint(&mut out, script.len() as u64);
            out.extend_from_slice(script);
            out.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        }
        varint(&mut out, self.outputs.len() as u64);
        for (sats, script) in &self.outputs {
            out.extend_from_slice(&sats.to_le_bytes());
            varint(&mut out, script.len() as u64);
            out.extend_from_slice(script);
        }
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }
    fn txid(&self) -> String {
        let mut h = sha256d(&self.bytes());
        h.reverse();
        to_hex(&h)
    }
}

/// A BEEF written by hand, entries in the order given (V2 unless V1 asked).
#[derive(Default)]
struct BeefBuild {
    bumps: Vec<MerklePath>,
    txs: Vec<(Vec<u8>, Option<usize>)>,
    atomic: Option<String>,
    v1: bool,
}

impl BeefBuild {
    fn tx(&mut self, tx: &RawTx) -> String {
        self.txs.push((tx.bytes(), None));
        tx.txid()
    }
    /// A transaction proven by a BUMP whose leaf level is full: at least
    /// `extra + 2` leaves, rounded up to a power of two.
    fn proven(&mut self, tx: &RawTx, height: u32, extra: usize) -> String {
        self.proven_together(std::slice::from_ref(tx), height, extra)
            .pop()
            .unwrap()
    }
    /// Transactions mined in one block, proven by one compound BUMP whose
    /// leaf level holds each of them and `extra` other leaves (rounded up to
    /// a power of two).
    fn proven_together(&mut self, txs: &[RawTx], height: u32, extra: usize) -> Vec<String> {
        let ids: Vec<String> = txs.iter().map(RawTx::txid).collect();
        let count = (ids.len() + extra).max(2).next_power_of_two();
        let mut level = Vec::with_capacity(count);
        for (i, id) in ids.iter().enumerate() {
            level.push(MerklePathLeaf::new_txid(i as u64, id.clone()));
        }
        for i in ids.len()..count {
            level.push(MerklePathLeaf::new(
                i as u64,
                fake_txid(height as u64 * 7919 + i as u64),
            ));
        }
        let mut path = vec![level];
        for _ in 1..count.trailing_zeros() {
            path.push(Vec::new());
        }
        let bump = MerklePath::new_unchecked(height, path).unwrap();
        self.bumps.push(bump);
        for tx in txs {
            self.txs.push((tx.bytes(), Some(self.bumps.len() - 1)));
        }
        ids
    }
    fn atomic(mut self, txid: &str) -> Self {
        self.atomic = Some(txid.to_string());
        self
    }
    fn bytes_with_atomic(mut self, id: &str) -> Vec<u8> {
        self.atomic = Some(id.to_string());
        self.bytes()
    }
    fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(a) = &self.atomic {
            out.extend_from_slice(&ATOMIC_BEEF.to_le_bytes());
            let mut id = hex::decode(a).unwrap();
            id.reverse();
            out.extend_from_slice(&id);
        }
        let version = if self.v1 { BEEF_V1 } else { BEEF_V2 };
        out.extend_from_slice(&version.to_le_bytes());
        varint(&mut out, self.bumps.len() as u64);
        for b in &self.bumps {
            out.extend_from_slice(&b.to_binary());
        }
        varint(&mut out, self.txs.len() as u64);
        for (raw, bump) in &self.txs {
            if self.v1 {
                out.extend_from_slice(raw);
                match bump {
                    Some(i) => {
                        out.push(1);
                        varint(&mut out, *i as u64);
                    }
                    None => out.push(0),
                }
            } else {
                match bump {
                    Some(i) => {
                        out.push(1);
                        varint(&mut out, *i as u64);
                    }
                    None => out.push(0),
                }
                out.extend_from_slice(raw);
            }
        }
        out
    }
}

fn fake_txid(seed: u64) -> String {
    let mut h = sha256d(&seed.to_le_bytes());
    h.reverse();
    to_hex(&h)
}

fn p2pkh(seed: u8) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend_from_slice(&[seed; 20]);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

/// A P2PKH unlocking script's size: a 72-byte signature push and a 33-byte key push.
fn p2pkh_unlock(seed: u8) -> Vec<u8> {
    let mut s = vec![0x48];
    s.extend_from_slice(&[seed; 72]);
    s.push(0x21);
    s.extend_from_slice(&[seed; 33]);
    s
}

/// A funding transaction outside the BEEF, its own parent named only.
fn funded(seed: u64, outputs: usize, script: &[u8]) -> RawTx {
    let mut tx = RawTx::new().input(&fake_txid(seed), 0, p2pkh_unlock(seed as u8));
    for i in 0..outputs {
        tx = tx.output(1000 + i as u64, script.to_vec());
    }
    tx
}

// ── the payment header ──────────────────────────────────────────────────

const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const PAYER: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
/// A derivation prefix the server ([`SERVER_KEY`]) issued: its HMAC verifies.
const PREFIX: &str = "47CdLOOVbIDIvJT/IN4SfZIM/+kZVxxZsds2vDPOZWea2I7yhth9AL1xKUwhNeqa";
const SUFFIX: &str = "c3VmZml4LXN1ZmZpeA==";
const PRICE: u64 = 1000;

/// The script output 0 must carry to pay the server under [`PREFIX`] and
/// [`SUFFIX`] (BRC-29, derived from the server's side).
fn paying_script() -> Vec<u8> {
    hex::decode(expected_locking_script(SERVER_KEY, PAYER, PREFIX, SUFFIX).unwrap()).unwrap()
}

fn header_for(beef: &[u8]) -> String {
    serde_json::json!({
        "derivationPrefix": PREFIX,
        "derivationSuffix": SUFFIX,
        "transaction": to_base64(beef),
    })
    .to_string()
}

/// What the middleware reads of a header before it claims the prefix, in
/// its order: the JSON (`BsvPayment`), the base64, `verify_payment_output`
/// (the subject alone), then the subject's txid for the claim.
#[derive(Debug, PartialEq, Eq)]
enum Door {
    Malformed,
    BadBase64,
    Verdict(PaymentVerdict),
    Claims { satoshis: u64, txid: String },
}

fn door(header: &str) -> Door {
    let Ok(payment) = serde_json::from_str::<BsvPayment>(header) else {
        return Door::Malformed;
    };
    let Ok(bytes) = from_base64(&payment.transaction) else {
        return Door::BadBase64;
    };
    let verdict = verify_payment_output(
        SERVER_KEY,
        PAYER,
        &payment.derivation_prefix,
        &payment.derivation_suffix,
        &bytes,
        0,
        PRICE,
    )
    .unwrap();
    match verdict {
        PaymentVerdict::Verified { satoshis } => Door::Claims {
            satoshis,
            txid: payment_subject_txid(&bytes).unwrap(),
        },
        other => Door::Verdict(other),
    }
}

// ── the honest shapes ───────────────────────────────────────────────────

/// A payment with `n` inputs, each from a distinct parent; the parents
/// proven, or unproven over a proven grandparent. Output 0 pays the server.
fn payment_from_distinct_parents(n: usize, parents_proven: bool) -> Vec<u8> {
    let mut b = BeefBuild::default();
    let mut child = RawTx::new();
    for i in 0..n {
        let parent = if parents_proven {
            let p = funded(10_000 + i as u64, 2, &p2pkh(1));
            b.proven(&p, 800_000 + i as u32, 18);
            p
        } else {
            let g = funded(20_000 + i as u64, 2, &p2pkh(2));
            let gid = b.proven(&g, 800_000 + i as u32, 18);
            let p = RawTx::new()
                .input(&gid, 0, p2pkh_unlock(3))
                .output(900, p2pkh(4))
                .output(50, p2pkh(5));
            b.tx(&p);
            p
        };
        child = child.input(&parent.txid(), 0, p2pkh_unlock(6));
    }
    let child = child.output(PRICE, paying_script()).output(300, p2pkh(8));
    let id = b.tx(&child);
    b.atomic(&id).bytes()
}

/// `n` inputs from `n` parents mined in one block, proven by one compound
/// BUMP. Output 0 pays the server.
fn payment_from_one_block(n: usize) -> Vec<u8> {
    let mut b = BeefBuild::default();
    let parents: Vec<RawTx> = (0..n)
        .map(|i| funded(15_000 + i as u64, 2, &p2pkh(1)))
        .collect();
    let ids = b.proven_together(&parents, 805_000, 4 * n);
    let mut child = RawTx::new();
    for id in &ids {
        child = child.input(id, 0, p2pkh_unlock(6));
    }
    let child = child.output(PRICE, paying_script()).output(300, p2pkh(8));
    let id = b.tx(&child);
    b.atomic(&id).bytes()
}

/// An unconfirmed chain of `hops` transactions over one proven root, each
/// spending the change of the one before it; the last pays the server.
fn unconfirmed_chain(hops: usize) -> Vec<u8> {
    let mut b = BeefBuild::default();
    let root = funded(30_000, 2, &p2pkh(1));
    let mut prev = b.proven(&root, 810_000, 18);
    for i in 0..hops {
        let first = if i + 1 == hops {
            paying_script()
        } else {
            p2pkh(2)
        };
        let tx = RawTx::new()
            .input(&prev, 1, p2pkh_unlock(i as u8))
            .output(PRICE, first)
            .output(10_000_000 - i as u64, p2pkh(3));
        prev = b.tx(&tx);
    }
    b.atomic(&prev).bytes()
}

/// A sweep of `n` outputs of one parent (proven, or over a proven
/// grandparent) into one output that pays the server.
fn sweep(n: usize, parent_proven: bool) -> Vec<u8> {
    let mut b = BeefBuild::default();
    let parent = if parent_proven {
        let p = funded(40_000, n, &p2pkh(1));
        b.proven(&p, 820_000, 18);
        p
    } else {
        let g = funded(40_001, 1, &p2pkh(2));
        let gid = b.proven(&g, 820_001, 18);
        let mut p = RawTx::new().input(&gid, 0, p2pkh_unlock(3));
        for i in 0..n {
            p = p.output(1000 + i as u64, p2pkh(4));
        }
        b.tx(&p);
        p
    };
    let pid = parent.txid();
    let mut child = RawTx::new();
    for i in 0..n {
        child = child.input(&pid, i as u32, p2pkh_unlock(5));
    }
    let child = child.output(PRICE, paying_script());
    let id = b.tx(&child);
    b.atomic(&id).bytes()
}

fn honest_shapes() -> Vec<(String, Vec<u8>)> {
    let mut v = Vec::new();
    for n in [1, 10, 100] {
        v.push((
            format!("payment, {n} inputs from proven parents"),
            payment_from_distinct_parents(n, true),
        ));
        v.push((
            format!("payment, {n} inputs from unproven parents"),
            payment_from_distinct_parents(n, false),
        ));
    }
    for n in [20, 50, 100] {
        v.push((
            format!("payment, {n} inputs from one block, one compound BUMP"),
            payment_from_one_block(n),
        ));
    }
    for hops in [200, 500] {
        v.push((
            format!("unconfirmed chain, {hops} hops"),
            unconfirmed_chain(hops),
        ));
    }
    for n in [50, 300] {
        v.push((
            format!("sweep of {n} outputs, proven parent"),
            sweep(n, true),
        ));
        v.push((
            format!("sweep of {n} outputs, unproven parent"),
            sweep(n, false),
        ));
    }
    v
}

/// The BEEFs of the payment fixtures in the tree (the parity fixtures'
/// Atomic BEEFs, and each BRC-29 payment transaction as a one-entry BEEF).
fn fixture_beefs() -> Vec<(String, Vec<u8>)> {
    let atomic = [
        (
            "atomic_beef_1input_p2pkh",
            include_str!("../parity/fixtures/parity/atomic_beef_1input_p2pkh.json"),
        ),
        (
            "atomic_beef_2input_p2pkh",
            include_str!("../parity/fixtures/parity/atomic_beef_2input_p2pkh.json"),
        ),
        (
            "atomic_beef_1input_brc29_source",
            include_str!("../parity/fixtures/parity/atomic_beef_1input_brc29_source.json"),
        ),
    ];
    let raw = [
        (
            "brc29_payment_basic",
            include_str!("../parity/fixtures/parity/brc29_payment_basic.json"),
        ),
        (
            "brc29_payment_large_keyid",
            include_str!("../parity/fixtures/parity/brc29_payment_large_keyid.json"),
        ),
    ];
    let mut v = Vec::new();
    for (name, text) in atomic {
        let j: serde_json::Value = serde_json::from_str(text).unwrap();
        let bytes: Vec<u8> = j["beef_bytes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b.as_u64().unwrap() as u8)
            .collect();
        v.push((name.to_string(), bytes));
    }
    for (name, text) in raw {
        let j: serde_json::Value = serde_json::from_str(text).unwrap();
        let hex_tx = j["expected"]["tx_hex"].as_str().unwrap();
        let mut beef = Beef::new();
        beef.merge_raw_tx(hex::decode(hex_tx).unwrap(), None);
        v.push((name.to_string(), beef.to_binary()));
    }
    v
}

// ── the costly shapes ───────────────────────────────────────────────────

/// One unproven parent with `m` outputs (scripts of `script_len`) and a
/// subject with `n` inputs spending it (unlocking scripts of `unlock_len`).
fn wide_parent(m: usize, n: usize, script_len: usize, unlock_len: usize) -> Vec<u8> {
    let mut b = BeefBuild::default();
    let parent = funded(50_000, m, &vec![0x51; script_len]);
    let pid = b.tx(&parent);
    let mut child = RawTx::new();
    for i in 0..n {
        child = child.input(&pid, (i % m) as u32, vec![0x51; unlock_len]);
    }
    let child = child.output(1, Vec::new());
    let id = b.tx(&child);
    b.atomic(&id).bytes()
}

/// A proven parent carrying a BUMP of `leaves` leaves, spent `n` times.
fn wide_bump(leaves: usize, n: usize) -> Vec<u8> {
    let mut b = BeefBuild::default();
    let parent = funded(51_000, 2, &[]);
    let pid = b.proven(&parent, 830_000, leaves);
    let mut child = RawTx::new();
    for _ in 0..n {
        child = child.input(&pid, 0, Vec::new());
    }
    let child = child.output(1, Vec::new());
    let id = b.tx(&child);
    b.bytes_with_atomic(&id)
}

/// `levels` unproven levels, each spending every output of the level below
/// (`width` outputs per level): the diamond chain.
fn diamond(levels: usize, width: usize) -> Vec<u8> {
    let mut b = BeefBuild::default();
    let mut prev = b.tx(&funded(52_000, width, &[]));
    for l in 0..levels {
        let mut tx = RawTx::new();
        for i in 0..width {
            tx = tx.input(&prev, i as u32, Vec::new());
        }
        for i in 0..width {
            tx = tx.output(l as u64 * 100 + i as u64, Vec::new());
        }
        prev = b.tx(&tx);
    }
    b.atomic(&prev).bytes()
}

/// `k` middle transactions each spending a wide parent `n` times; the
/// subject spends every middle one.
fn fan_of_fans(m: usize, n: usize, k: usize) -> Vec<u8> {
    let mut b = BeefBuild::default();
    let pid = b.tx(&funded(53_000, m, &[]));
    let mut subject = RawTx::new();
    for j in 0..k {
        let mut mid = RawTx::new();
        for i in 0..n {
            mid = mid.input(&pid, (i % m) as u32, Vec::new());
        }
        mid = mid.output(j as u64, Vec::new());
        let mid_id = b.tx(&mid);
        subject = subject.input(&mid_id, 0, Vec::new());
    }
    let subject = subject.output(1, Vec::new());
    let id = b.tx(&subject);
    b.atomic(&id).bytes()
}

/// A small deterministic generator (xorshift64*).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

/// A random DAG: transactions referencing earlier ones (and outsiders),
/// random widths, scripts and proofs, duplicate references, V1 or V2,
/// atomic or not, subjects anywhere.
fn random_beef(seed: u64) -> Vec<u8> {
    let mut r = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let count = 1 + r.below(24) as usize;
    let mut b = BeefBuild {
        v1: r.below(4) == 0,
        ..Default::default()
    };
    let mut ids: Vec<(String, usize)> = Vec::new();
    for t in 0..count {
        let mut tx = RawTx::new();
        let wide_in = r.below(5) == 0;
        let n_in = 1 + r.below(if wide_in { 60 } else { 6 }) as usize;
        for _ in 0..n_in {
            if !ids.is_empty() && r.below(5) != 0 {
                let (id, outs) = &ids[r.below(ids.len() as u64) as usize];
                let vout = r.below(*outs as u64) as u32;
                tx = tx.input(id, vout, vec![0x51; r.below(110) as usize]);
            } else {
                tx = tx.input(&fake_txid(r.next()), 0, vec![0x51; r.below(110) as usize]);
            }
        }
        let wide_out = r.below(5) == 0;
        let n_out = 1 + r.below(if wide_out { 120 } else { 4 }) as usize;
        for _ in 0..n_out {
            tx = tx.output(r.below(1_000_000), vec![0x6a; r.below(40) as usize]);
        }
        tx.lock_time = t as u32;
        let id = if r.below(4) == 0 {
            let extra = r.below(40) as usize;
            b.proven(&tx, 700_000 + (seed as u32 % 10_000) * 32 + t as u32, extra)
        } else {
            b.tx(&tx)
        };
        ids.push((id, n_out));
    }
    match r.below(3) {
        0 if !b.v1 => {
            let (id, _) = &ids[r.below(ids.len() as u64) as usize];
            let id = id.clone();
            b.atomic(&id).bytes()
        }
        _ => b.bytes(),
    }
}

fn costly_shapes() -> Vec<(String, Vec<u8>)> {
    let mut v = Vec::new();
    for (m, n) in [(10, 10), (100, 50), (400, 100), (1000, 200), (2000, 400)] {
        v.push((format!("wide parent {m}x{n}"), wide_parent(m, n, 0, 0)));
        v.push((
            format!("wide parent {m}x{n}, scripts"),
            wide_parent(m, n, 30, 20),
        ));
    }
    for (l, n) in [(10, 10), (200, 50), (1000, 100)] {
        v.push((format!("wide bump {l}x{n}"), wide_bump(l, n)));
    }
    for (levels, width) in [(8, 2), (24, 2), (12, 8), (100, 3)] {
        v.push((
            format!("diamond {levels} levels x{width}"),
            diamond(levels, width),
        ));
    }
    for (m, n, k) in [(50, 20, 10), (300, 60, 8)] {
        v.push((format!("fan of fans {m}x{n}x{k}"), fan_of_fans(m, n, k)));
    }
    v
}

// ── the door, measured ──────────────────────────────────────────────────

/// The largest header the tests build: the platform refuses a request whose
/// headers pass 128 KiB in all.
const HEADER_MAX: usize = 128 * 1024;

/// The door's peak heap allowed per header byte, over a fixed floor: the
/// BRC-29 key derivation costs about half a MiB on every header, whatever
/// its size; the rest follows the header (JSON, base64, the BEEF's parse,
/// the subject's copy).
const DOOR_PER_HEADER_BYTE: usize = 8;
const DOOR_FLOOR: usize = 1024 * 1024;

/// What a BEEF's subject read may allocate: the parse, per wire byte.
const PARSE_PER_BYTE: usize = 24;
const PARSE_FLOOR: usize = 16 * 1024;

fn door_bound(header: &str) -> usize {
    DOOR_FLOOR + DOOR_PER_HEADER_BYTE * header.len()
}

fn all_generated() -> Vec<(String, Vec<u8>)> {
    let mut v = fixture_beefs();
    v.extend(honest_shapes());
    v.extend(costly_shapes());
    for seed in 1..=520u64 {
        v.push((format!("random {seed}"), random_beef(seed)));
    }
    v
}

/// Each family grown until its header passes [`HEADER_MAX`]; the last one
/// under it.
fn largest_headers() -> Vec<(String, String)> {
    type Family = (&'static str, usize, Box<dyn Fn(usize) -> Vec<u8>>);
    let families: Vec<Family> = vec![
        (
            "wide parent",
            400,
            Box::new(|m| wide_parent(m, (m * 9) / 41, 0, 0)),
        ),
        (
            "wide parent, scripts",
            100,
            Box::new(|m| wide_parent(m, m / 4, 30, 20)),
        ),
        ("wide bump", 64, Box::new(|n| wide_bump(n * 8, n))),
        ("diamond", 10, Box::new(|levels| diamond(levels, 3))),
        ("fan of fans", 20, Box::new(|m| fan_of_fans(m, m / 4, 8))),
        ("sweep, unproven parent", 50, Box::new(|n| sweep(n, false))),
        ("sweep, proven parent", 50, Box::new(|n| sweep(n, true))),
        (
            "one block, compound BUMP",
            20,
            Box::new(payment_from_one_block),
        ),
        (
            "distinct proven parents",
            10,
            Box::new(|n| payment_from_distinct_parents(n, true)),
        ),
        ("unconfirmed chain", 100, Box::new(unconfirmed_chain)),
    ];
    let mut out = Vec::new();
    for (name, start, build) in families {
        let mut k = start;
        let mut best = None;
        loop {
            let header = header_for(&build(k));
            if header.len() > HEADER_MAX {
                break;
            }
            best = Some((format!("{name} at {k}"), header));
            k += (k / 8).max(1);
        }
        out.push(best.unwrap_or_else(|| panic!("{name}: the first size passes the header bound")));
    }
    out
}

#[test]
fn the_payment_door_follows_the_header() {
    let _g = measure_lock();
    let mut headers: Vec<(String, String)> = all_generated()
        .into_iter()
        .map(|(name, beef)| (name, header_for(&beef)))
        .collect();
    headers.extend(largest_headers());
    let (mut largest, mut slope) = (0usize, 0f64);
    for (name, header) in &headers {
        let peak = peak_of(|| door(header));
        assert!(
            peak <= door_bound(header),
            "{name}: the door peaked at {peak} B for a {} B header",
            header.len()
        );
        largest = largest.max(peak);
        slope = slope.max(peak.saturating_sub(DOOR_FLOOR) as f64 / header.len() as f64);
    }
    assert!(
        headers.len() >= 560,
        "only {} headers measured",
        headers.len()
    );
    eprintln!(
        "payment door: {} headers, largest peak {largest} B, at most {slope:.2} B per header byte over the floor",
        headers.len()
    );
}

#[test]
fn the_largest_headers_reach_the_middleware_verdict() {
    let _g = measure_lock();
    for (name, header) in largest_headers() {
        let answer = door(&header);
        assert!(
            matches!(answer, Door::Claims { .. } | Door::Verdict(_)),
            "{name}: {answer:?}"
        );
        if let Door::Verdict(PaymentVerdict::Unverifiable { reason }) = &answer {
            panic!("{name}: unreadable: {reason:?}");
        }
    }
}

#[test]
fn honest_payments_are_verified_and_claim_their_subject() {
    let _g = measure_lock();
    for (name, beef) in honest_shapes() {
        let subject = Transaction::from_beef_subject(&beef, None).unwrap().id();
        assert_eq!(
            door(&header_for(&beef)),
            Door::Claims {
                satoshis: PRICE,
                txid: subject,
            },
            "{name}"
        );
    }
    // The fixtures pay other keys: read, and refused for their script.
    for (name, beef) in fixture_beefs() {
        assert!(
            matches!(
                door(&header_for(&beef)),
                Door::Verdict(PaymentVerdict::WrongScript { .. })
            ),
            "{name}"
        );
    }
}

#[test]
fn a_header_that_does_not_decode_is_answered_in_kind() {
    let _g = measure_lock();
    for header in [
        "",
        "not json",
        r#"{"derivationPrefix":"a","derivationSuffix":"b"}"#,
        r#"{"derivationPrefix":1,"derivationSuffix":"b","transaction":"AAAA"}"#,
    ] {
        assert_eq!(door(header), Door::Malformed, "{header}");
    }
    let bad = format!(
        r#"{{"derivationPrefix":"{PREFIX}","derivationSuffix":"{SUFFIX}","transaction":"%%%"}}"#
    );
    assert_eq!(door(&bad), Door::BadBase64);
    // Bytes that are not a BEEF, and a BEEF naming a subject it does not
    // carry, are the payer's unreadable transaction.
    let mut b = BeefBuild::default();
    b.tx(&funded(60_000, 1, &[]));
    for beef in [vec![0, 0, 0, 0], b.bytes_with_atomic(&fake_txid(1))] {
        assert!(matches!(
            door(&header_for(&beef)),
            Door::Verdict(PaymentVerdict::Unverifiable {
                reason: UnverifiableReason::MalformedTransaction(_)
            })
        ));
    }
}

// ── the paid route, from the header to the wallet call ──────────────────

/// The server's identity key (for [`SERVER_KEY`]).
const SERVER_IDENTITY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match f.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(out) => out,
        std::task::Poll::Pending => panic!("the door awaited something that is not ready"),
    }
}

/// What the paid routes do with a header, measured to the wallet call's
/// send: the storage's door (`paid::decide`, over an in-memory prefix
/// store), and for a payment that reaches the wallet, the call written
/// (`paid::internalize_call`) and held as the route holds it while it is
/// sent, the payment's bytes let go. Returns the decision and the size of
/// the call's body.
fn paid_request(header: String) -> (Decision, usize) {
    let store = MemoryStore::new();
    let auth = AuthContext::authenticated(PAYER.to_string());
    let sent = std::cell::Cell::new(0usize);
    let decision = block_on(decide(
        &auth,
        PRICE,
        Some(header),
        SERVER_KEY,
        &store,
        |remittance: Remittance| {
            let call = internalize_call(3, SERVER_IDENTITY, Some(1), &remittance, PAYER).unwrap();
            drop(remittance);
            sent.set(call.body().len());
            drop(call);
            async { Ok(serde_json::json!({"accepted": true})) }
        },
    ))
    .unwrap();
    (decision, sent.get())
}

/// A payment of one input whose unlocking script is `len` bytes,
/// output 0 paying the server: the most transaction per header byte.
fn padded_payment(len: usize) -> Vec<u8> {
    let tx = RawTx::new()
        .input(&fake_txid(70_000), 0, vec![0x51; len])
        .output(PRICE, paying_script());
    let mut b = BeefBuild::default();
    let id = b.tx(&tx);
    b.atomic(&id).bytes()
}

/// Each paying family grown until its header passes the door's ceiling;
/// the last one at or under it.
fn largest_paying_headers() -> Vec<(String, String)> {
    type Family = (&'static str, usize, Box<dyn Fn(usize) -> Vec<u8>>);
    let families: Vec<Family> = vec![
        ("one padded input", 1000, Box::new(padded_payment)),
        ("sweep, unproven parent", 50, Box::new(|n| sweep(n, false))),
        ("sweep, proven parent", 50, Box::new(|n| sweep(n, true))),
        (
            "one block, compound BUMP",
            20,
            Box::new(payment_from_one_block),
        ),
        (
            "distinct proven parents",
            10,
            Box::new(|n| payment_from_distinct_parents(n, true)),
        ),
        ("unconfirmed chain", 100, Box::new(unconfirmed_chain)),
    ];
    let mut out = Vec::new();
    for (name, start, build) in families {
        let mut k = start;
        let mut best = None;
        loop {
            let header = header_for(&build(k));
            if header.len() > PAYMENT_HEADER_MAX {
                break;
            }
            best = Some((format!("{name} at {k}"), header));
            k += (k / 16).max(1);
        }
        out.push(best.unwrap_or_else(|| panic!("{name}: the first size passes the ceiling")));
    }
    out
}

#[test]
fn the_paid_route_holds_the_door_bound_to_the_wallet_call() {
    let _g = measure_lock();
    let mut headers: Vec<(String, String)> = all_generated()
        .into_iter()
        .map(|(name, beef)| (name, header_for(&beef)))
        .collect();
    headers.extend(largest_headers());
    let paying = largest_paying_headers();
    headers.extend(paying.iter().cloned());
    let (mut largest, mut slope, mut called) = (0usize, 0f64, 0usize);
    for (name, header) in &headers {
        let len = header.len();
        let owned = header.clone();
        let mut answer = None;
        let peak = peak_of(|| answer = Some(paid_request(owned)));
        let (decision, body) = answer.unwrap();
        assert!(
            peak <= door_bound(header),
            "{name}: the paid route peaked at {peak} B for a {len} B header ({decision:?})"
        );
        if body > 0 {
            called += 1;
            assert_eq!(
                decision,
                Decision::Verified {
                    satoshis_paid: PRICE
                },
                "{name}"
            );
        }
        largest = largest.max(peak);
        slope = slope.max(peak.saturating_sub(DOOR_FLOOR) as f64 / len as f64);
    }
    // Every paying shape at the ceiling reached the wallet call.
    for (name, header) in &paying {
        let (decision, body) = paid_request(header.clone());
        assert!(body > header.len(), "{name}: {decision:?}, body {body} B");
    }
    assert!(
        called >= 15,
        "only {called} payments reached the wallet call"
    );
    eprintln!(
        "paid route to the wallet call: {} headers, {called} wallet calls, largest peak {largest} B, at most {slope:.2} B per header byte over the floor",
        headers.len()
    );
}

#[test]
fn a_header_over_the_ceiling_is_refused_before_it_is_decoded() {
    let _g = measure_lock();
    // What any header costs before it is read: the server's wallet.
    let floor = peak_of(|| paid_request("{".to_string()));
    let mut refused = 0;
    for (name, header) in largest_headers() {
        if header.len() <= PAYMENT_HEADER_MAX {
            continue;
        }
        refused += 1;
        let owned = header.clone();
        let mut answer = None;
        let peak = peak_of(|| answer = Some(paid_request(owned)));
        assert_eq!(
            answer.unwrap(),
            (
                Decision::InvalidPayment {
                    description: PAYMENT_TOO_LARGE.to_string()
                },
                0
            ),
            "{name}"
        );
        // Nothing the header's size drives: no JSON, no base64, no parse.
        assert!(peak <= floor + 4096, "{name}: {peak} B against {floor} B");
    }
    assert!(refused >= 5, "only {refused} headers over the ceiling");
}

// ── the fan-out ─────────────────────────────────────────────────────────

/// What `src/overlay/mod.rs` reads of a tracker answer's BEEF: the subject
/// alone, then `outputs[vout]`.
fn subject_output(beef: &[u8], vout: usize) -> Option<(String, u64, Vec<u8>)> {
    let tx = Transaction::from_beef_subject(beef, None).ok()?;
    let o = tx.outputs.get(vout)?;
    Some((
        tx.id(),
        o.satoshis.unwrap_or(0),
        o.locking_script.to_binary(),
    ))
}

#[test]
fn the_fan_out_reads_the_subject_from_beef_links() {
    let _g = measure_lock();
    let mut compared = 0;
    for (name, beef) in all_generated() {
        let Ok(linked) = Transaction::from_beef(&beef, None) else {
            continue;
        };
        for vout in [0usize, 1, 2, 7, 1000] {
            let theirs = linked.outputs.get(vout).map(|o| {
                (
                    linked.id(),
                    o.satoshis.unwrap_or(0),
                    o.locking_script.to_binary(),
                )
            });
            assert_eq!(subject_output(&beef, vout), theirs, "{name} vout {vout}");
        }
        compared += 1;
    }
    for bad in [&b""[..], &[1, 2, 3], &[0xef, 0xbe, 0x00, 0x02][..]] {
        assert_eq!(subject_output(bad, 0), None);
    }
    assert!(compared >= 500, "only {compared} answers compared");
}

#[test]
fn the_fan_out_read_follows_the_body() {
    let _g = measure_lock();
    for (name, beef) in all_generated() {
        let peak = peak_of(|| subject_output(&beef, 0));
        assert!(
            peak <= PARSE_FLOOR + PARSE_PER_BYTE * beef.len(),
            "{name}: subject read peaked at {peak} B for {} B",
            beef.len()
        );
    }
}
