//! The payment header's link cost is bounded before the payment middleware,
//! and the fan-out reads a tracker answer's subject alone.
//!
//! Native measurements with a counting allocator around the real bsv-rs
//! 0.4.5 calls: `Transaction::from_beef` (the link the payment middleware
//! performs through `verify_payment_output`) and the storage's own reading
//! in `src/link_cost.rs` (included here by path). Every test takes the
//! allocator's lock, so one measurement runs at a time.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[allow(dead_code)]
#[path = "../../src/link_cost.rs"]
mod link_cost;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use bsv_middleware_cloudflare::core::verify_payment_output;
use bsv_middleware_cloudflare::core::{PaymentVerdict, UnverifiableReason};
use bsv_rs::primitives::hash::sha256d;
use bsv_rs::primitives::{to_base64, to_hex};
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, ATOMIC_BEEF, BEEF_V1, BEEF_V2,
};
use link_cost::{
    link_cost, payment_header_link_check, subject_output, HeaderCheck, LINK_COST_CEILING,
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
        let txid = tx.txid();
        let count = (extra + 2).next_power_of_two();
        let mut level = vec![MerklePathLeaf::new_txid(0, txid.clone())];
        for i in 1..count {
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
        self.txs.push((tx.bytes(), Some(self.bumps.len() - 1)));
        txid
    }
    fn atomic(mut self, txid: &str) -> Self {
        self.atomic = Some(txid.to_string());
        self
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

// ── the honest shapes ───────────────────────────────────────────────────

/// A P2PKH payment with `n` inputs, each from a distinct parent; the
/// parents proven, or unproven over a proven grandparent.
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
    let child = child.output(500, p2pkh(7)).output(300, p2pkh(8));
    let id = b.tx(&child);
    b.atomic(&id).bytes()
}

/// An unconfirmed chain of `hops` transactions over one proven root, each
/// spending the change of the one before it.
fn unconfirmed_chain(hops: usize) -> Vec<u8> {
    let mut b = BeefBuild::default();
    let root = funded(30_000, 2, &p2pkh(1));
    let mut prev = b.proven(&root, 810_000, 18);
    for i in 0..hops {
        let tx = RawTx::new()
            .input(&prev, 1, p2pkh_unlock(i as u8))
            .output(100, p2pkh(2))
            .output(10_000_000 - i as u64, p2pkh(3));
        prev = b.tx(&tx);
    }
    b.atomic(&prev).bytes()
}

/// A sweep of `n` outputs of one parent (proven, or over a proven grandparent).
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
    let child = child.output(40_000, p2pkh(6));
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
    v.push(("unconfirmed chain, 200 hops".into(), unconfirmed_chain(200)));
    v.push(("sweep of 50 outputs, proven parent".into(), sweep(50, true)));
    v.push((
        "sweep of 50 outputs, unproven parent".into(),
        sweep(50, false),
    ));
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

// ── the adversarial shapes ──────────────────────────────────────────────

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

impl BeefBuild {
    fn bytes_with_atomic(mut self, id: &str) -> Vec<u8> {
        self.atomic = Some(id.to_string());
        self.bytes()
    }
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

fn adversarial_shapes() -> Vec<(String, Vec<u8>)> {
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

/// What `from_beef` may allocate at most: the parse (bounded per wire byte)
/// and the link (the estimate).
const PARSE_PER_BYTE: usize = 64;
const PARSE_FLOOR: usize = 16 * 1024;

fn predicted(beef: &[u8]) -> Option<usize> {
    let parsed = Beef::from_binary(beef).ok()?;
    let cost = link_cost(&parsed)?;
    Some(PARSE_FLOOR + PARSE_PER_BYTE * beef.len() + cost.heap_bytes() as usize)
}

fn all_generated() -> Vec<(String, Vec<u8>)> {
    let mut v = fixture_beefs();
    v.extend(honest_shapes());
    v.extend(adversarial_shapes());
    for seed in 1..=520u64 {
        v.push((format!("random {seed}"), random_beef(seed)));
    }
    v
}

#[test]
fn the_link_cost_estimate_bounds_what_from_beef_allocates() {
    let _g = measure_lock();
    let mut checked = 0;
    let mut worst_ratio = 0f64;
    for (name, beef) in all_generated() {
        let Some(limit) = predicted(&beef) else {
            continue;
        };
        let peak = peak_of(|| Transaction::from_beef(&beef, None));
        assert!(
            peak <= limit,
            "{name}: from_beef peaked at {peak} B over the predicted {limit} B"
        );
        worst_ratio = worst_ratio.max(peak as f64 / limit as f64);
        checked += 1;
    }
    assert!(checked >= 500, "only {checked} BEEFs measured");
    eprintln!("link cost bound: {checked} BEEFs, worst peak/predicted {worst_ratio:.3}");
}

// ── the payment header ──────────────────────────────────────────────────

const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const PAYER: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

fn header_for(beef: &[u8]) -> String {
    serde_json::json!({
        "derivationPrefix": "b0YxH8Zl3mJ8kQ2C0fV9yq3w5lWm3T6dYcR8nQwq2pY=",
        "derivationSuffix": "c3VmZml4LXN1ZmZpeA==",
        "transaction": to_base64(beef),
    })
    .to_string()
}

/// The payment middleware's read of a header (its JSON, its base64, then
/// `verify_payment_output`, which calls `Transaction::from_beef`).
fn middleware_read(header: &str) -> Option<PaymentVerdict> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct H {
        derivation_prefix: String,
        derivation_suffix: String,
        transaction: String,
    }
    let h: H = serde_json::from_str(header).ok()?;
    let bytes = bsv_rs::primitives::from_base64(&h.transaction).ok()?;
    verify_payment_output(
        SERVER_KEY,
        PAYER,
        &h.derivation_prefix,
        &h.derivation_suffix,
        &bytes,
        0,
        1,
    )
    .ok()
}

/// The order `src/lib.rs` runs: the storage's check, then the middleware's
/// read when the check passes. `None` is the refusal.
fn door(header: &str) -> Option<Option<PaymentVerdict>> {
    match payment_header_link_check(header) {
        HeaderCheck::OverBound { .. } => None,
        HeaderCheck::Pass => Some(middleware_read(header)),
    }
}

/// The largest header the shape fits in: 128 KiB.
const HEADER_MAX: usize = 128 * 1024;

/// The worst shape for the link per wire byte (one unproven parent with
/// empty-script outputs, every subject input spending it) at the largest
/// size that fits a 128 KiB header.
fn worst_header() -> (String, usize, usize) {
    let mut best = (String::new(), 0, 0);
    let mut m = 4000;
    loop {
        let n = (m * 9) / 41;
        let h = header_for(&wide_parent(m, n, 0, 0));
        if h.len() > HEADER_MAX {
            break;
        }
        best = (h, m, n);
        m += 50;
    }
    best
}

#[test]
fn the_payment_header_link_cost_is_bounded_before_the_middleware() {
    let _g = measure_lock();
    let (header, m, n) = worst_header();
    assert!(header.len() <= HEADER_MAX);
    let mut verdict = None;
    let peak = peak_of(|| verdict = Some(door(&header)));
    assert_eq!(verdict, Some(None), "the check refuses the {m}x{n} shape");
    // The whole check (JSON, base64, parse, estimate) stays within a band of
    // the header's own size.
    let band = 24 * header.len();
    eprintln!(
        "door: {m}x{n}, header {} B, check peak {peak} B (band {band} B)",
        header.len()
    );
    assert!(peak <= band, "check peaked at {peak} B, band {band} B");
    let parsed = Beef::from_binary(&wide_parent(m, n, 0, 0)).unwrap();
    let est = link_cost(&parsed).unwrap().heap_bytes();
    eprintln!("door: estimate {est} B, ceiling {LINK_COST_CEILING} B");
    assert!(est > 32 * LINK_COST_CEILING);
}

#[test]
fn honest_payments_reach_the_middleware_with_their_verdict() {
    let _g = measure_lock();
    let mut largest = 0u64;
    for (name, beef) in fixture_beefs().into_iter().chain(honest_shapes()) {
        let header = header_for(&beef);
        let parsed = Beef::from_binary(&beef).unwrap();
        let est = link_cost(&parsed).unwrap().heap_bytes();
        largest = largest.max(est);
        eprintln!("honest: {name}: {} B wire, estimate {est} B", beef.len());
        assert!(
            est * 8 <= LINK_COST_CEILING,
            "{name}: estimate {est} B is not far below the ceiling"
        );
        assert_eq!(
            payment_header_link_check(&header),
            HeaderCheck::Pass,
            "{name}"
        );
        assert_eq!(door(&header), Some(middleware_read(&header)), "{name}");
    }
    eprintln!("honest: largest estimate {largest} B");
}

#[test]
fn a_header_that_does_not_decode_goes_on_unchanged() {
    let _g = measure_lock();
    for header in [
        "",
        "not json",
        r#"{"derivationPrefix":"a","derivationSuffix":"b"}"#,
        r#"{"derivationPrefix":"a","derivationSuffix":"b","transaction":"%%%"}"#,
        r#"{"derivationPrefix":"a","derivationSuffix":"b","transaction":"AAAA"}"#,
        r#"{"derivationPrefix":1,"derivationSuffix":"b","transaction":"AAAA"}"#,
    ] {
        assert_eq!(payment_header_link_check(header), HeaderCheck::Pass);
        assert_eq!(door(header), Some(middleware_read(header)));
    }
    // A BEEF naming a subject it does not carry links nothing either.
    let mut b = BeefBuild::default();
    b.tx(&funded(60_000, 1, &[]));
    let bytes = b.bytes_with_atomic(&fake_txid(1));
    let header = header_for(&bytes);
    assert_eq!(payment_header_link_check(&header), HeaderCheck::Pass);
    assert!(matches!(
        middleware_read(&header),
        Some(PaymentVerdict::Unverifiable {
            reason: UnverifiableReason::MalformedTransaction(_)
        })
    ));
}

#[test]
fn the_smallest_shapes_over_the_ceiling() {
    let _g = measure_lock();
    // Grow the worst shape until the estimate passes the ceiling.
    let mut m = 10;
    loop {
        let n = (m * 9) / 41 + 1;
        let beef = wide_parent(m, n, 0, 0);
        let header = header_for(&beef);
        if let HeaderCheck::OverBound { estimate } = payment_header_link_check(&header) {
            eprintln!(
                "smallest over the ceiling: {m}x{n}, {} B wire, header {} B, estimate {estimate} B",
                beef.len(),
                header.len()
            );
            assert!(header.len() < 24 * 1024);
            break;
        }
        m += 10;
    }
}

// ── the fan-out ─────────────────────────────────────────────────────────

/// The output the fan-out read before: `from_beef`, then `outputs[vout]`.
fn linked_output(beef: &[u8], vout: usize) -> Option<(String, u64, Vec<u8>)> {
    let tx = Transaction::from_beef(beef, None).ok()?;
    let o = tx.outputs.get(vout)?;
    Some((
        tx.id(),
        o.satoshis.unwrap_or(0),
        o.locking_script.to_binary(),
    ))
}

fn unlinked_output(beef: &[u8], vout: usize) -> Option<(String, u64, Vec<u8>)> {
    let o = subject_output(beef, vout)?;
    let parsed = Beef::from_binary(beef).ok()?;
    let id = link_cost::subject_txid(&parsed)?;
    Some((id, o.satoshis.unwrap_or(0), o.locking_script.to_binary()))
}

#[test]
fn the_fan_out_reads_the_subject_alone() {
    let _g = measure_lock();
    let mut compared = 0;
    for (name, beef) in all_generated() {
        for vout in [0usize, 1, 2, 7, 1000] {
            assert_eq!(
                unlinked_output(&beef, vout),
                linked_output(&beef, vout),
                "{name} vout {vout}"
            );
        }
        compared += 1;
    }
    // Unreadable answers are unreadable to both.
    for bad in [&b""[..], &[1, 2, 3], &[0xef, 0xbe, 0x00, 0x02][..]] {
        assert_eq!(unlinked_output(bad, 0), None);
        assert_eq!(linked_output(bad, 0), None);
    }
    assert!(compared >= 500, "only {compared} answers compared");
}

#[test]
fn the_fan_out_read_follows_the_body() {
    let _g = measure_lock();
    let mut worst = 0f64;
    for (name, beef) in all_generated() {
        let peak = peak_of(|| subject_output(&beef, 0));
        let ratio = peak as f64 / beef.len().max(1) as f64;
        worst = worst.max(ratio);
        assert!(
            peak <= PARSE_FLOOR + PARSE_PER_BYTE * beef.len(),
            "{name}: subject read peaked at {peak} B for {} B",
            beef.len()
        );
    }
    eprintln!("fan-out read: worst peak per wire byte {worst:.1}");
}
