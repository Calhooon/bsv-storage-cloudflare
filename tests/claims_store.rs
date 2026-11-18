//! The paid routes' store ([`PaidPrefixStore`]: the D1 claim with the
//! key-value record in front of it and written after a win) on SQLite, with
//! the middleware's own statements: they are read from the middleware's
//! source (`payment_claims.rs` of the locked bsv-middleware-cloudflare), not
//! written here. Every backend call yields once before it runs, so the kit's
//! schedules interleave the store's steps.
//!
//! - the middleware's conformance kit, at its defaults and at raised bounds
//!   (sizes 2 to 64, a hold of 128 passes);
//! - the legacy records, each shape, and a release one of them carries
//!   surviving another transaction's attempt;
//! - the key-value record a release writes, read as the key-value store's
//!   own claim reads it, both ways;
//! - the record's write failing once after a win;
//! - the grants' columns as the routes write them;
//! - the release path: a release of a prefix no claim holds started with
//!   claims by two transactions; two releases with a re-take between them; a
//!   release of a prefix never claimed; a release racing the record's write;
//! - a carried release frees only the claim its own carry made, over every
//!   schedule of the released transaction and others at once;
//! - a won claim writes its record whatever its read of the record says.

#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bsv_middleware_core::store::conformance::{
    self, drive, schedules, txid_for, LegacySeeder, LocalFuture, Schedule,
};
use bsv_middleware_core::{PaymentPrefixStore, PrefixClaim, StoreError};
use bsv_storage_cloudflare::claims::{
    releases, ClaimLedger, Claimed, PaidPrefixStore, PrefixRecords, Recording, Stored, Unanswered,
    GRANTS_SCHEMA, GRANT_ANSWERED_SQL, GRANT_PAID_SQL, HOLDS_SQL,
};
use rusqlite::{Connection, OptionalExtension};

// ── the middleware's statements, from its source ────────────────────────

struct Statements {
    schema: String,
    claim: String,
    read: String,
    release: String,
    nonce_claim: String,
}

/// A Rust string literal's text: `\` at a line's end joins the next line
/// without its leading whitespace; `\"` and `\\` are their characters.
fn unescape(literal: &str) -> String {
    let mut out = String::new();
    let mut chars = literal.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('\n') => {
                while chars.peek().is_some_and(|c| c.is_whitespace()) {
                    chars.next();
                }
            }
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            other => panic!("an escape the reader does not know: {other:?}"),
        }
    }
    out
}

fn constant(source: &str, name: &str) -> String {
    let at = source
        .find(&format!("const {name}: &str"))
        .unwrap_or_else(|| panic!("{name} is not in the middleware's source"));
    let rest = &source[at..];
    let open = rest.find('"').unwrap() + 1;
    let mut end = open;
    let bytes = rest.as_bytes();
    while bytes[end] != b'"' || bytes[end - 1] == b'\\' {
        end += 1;
    }
    unescape(&rest[open..end])
}

fn statements() -> Statements {
    let out = std::process::Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--locked", "--offline"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo metadata");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let manifest = meta["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "bsv-middleware-cloudflare")
        .expect("the middleware is a dependency")["manifest_path"]
        .as_str()
        .unwrap()
        .to_string();
    let source = std::fs::read_to_string(
        std::path::Path::new(&manifest)
            .parent()
            .unwrap()
            .join("src/payment_claims.rs"),
    )
    .unwrap();
    let statements = Statements {
        schema: constant(&source, "PAYMENT_CLAIMS_SCHEMA"),
        claim: constant(&source, "PREFIX_CLAIM_SQL"),
        read: constant(&source, "PREFIX_READ_SQL"),
        release: constant(&source, "PREFIX_RELEASE_SQL"),
        nonce_claim: constant(&source, "CLAIM_SQL"),
    };
    // The schema read is the one the crate exports.
    assert_eq!(
        statements.schema,
        bsv_middleware_cloudflare::payment_claims::PAYMENT_CLAIMS_SCHEMA
    );
    statements
}

// ── a yield before every backend call ───────────────────────────────────

struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

fn io() -> YieldOnce {
    YieldOnce(false)
}

// ── D1 on SQLite ─────────────────────────────────────────────────────────

struct SqliteLedger {
    db: RefCell<Connection>,
    sql: Statements,
    fault: Cell<bool>,
}

impl SqliteLedger {
    fn new() -> Self {
        let sql = statements();
        let db = Connection::open_in_memory().unwrap();
        db.execute(&sql.schema, []).unwrap();
        Self {
            db: RefCell::new(db),
            sql,
            fault: Cell::new(false),
        }
    }

    fn up(&self) -> Result<(), StoreError> {
        if self.fault.get() {
            Err(StoreError::new("D1 is down"))
        } else {
            Ok(())
        }
    }

    /// The row's (txid, released), if any.
    fn row(&self, prefix: &str) -> Option<(Option<String>, bool)> {
        self.db
            .borrow()
            .query_row(
                "SELECT txid, released FROM payment_claims WHERE nonce = ?1",
                [prefix],
                |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, i64>(1)? == 1)),
            )
            .optional()
            .unwrap()
    }

    /// `D1PrefixStore`'s claim: the upsert and its read in one transaction,
    /// classified as the middleware classifies them.
    fn claim_now(&self, prefix: &str, txid: &str, agent: &str) -> Result<PrefixClaim, StoreError> {
        assert!(
            txid.len() == 64 && txid.bytes().all(|b| b.is_ascii_hexdigit()),
            "a txid the middleware's guard refuses: {txid}"
        );
        let mut db = self.db.borrow_mut();
        let t = db.transaction().unwrap();
        let changes = t.execute(&self.sql.claim, [prefix, agent, txid]).unwrap();
        let row: Option<Option<String>> = t
            .query_row(&self.sql.read, [prefix], |r| r.get(0))
            .optional()
            .unwrap();
        t.commit().unwrap();
        Ok(match (changes, row) {
            (1, _) => PrefixClaim::Won,
            (_, Some(Some(bound))) if bound == txid => PrefixClaim::SameTransaction,
            (_, Some(Some(_))) => PrefixClaim::OtherTransaction,
            (_, Some(None)) => PrefixClaim::Unknown,
            (_, None) => return Err(StoreError::new("no binding")),
        })
    }
}

impl ClaimLedger for SqliteLedger {
    async fn claim(&self, prefix: &str, txid: &str, agent: &str) -> Result<Claimed, Unanswered> {
        io().await;
        self.up()?;
        Ok(Claimed {
            claim: self.claim_now(prefix, txid, agent)?,
            refusal: None,
        })
    }

    async fn release(&self, prefix: &str, txid: &str) -> Result<(), StoreError> {
        io().await;
        self.up()?;
        self.db
            .borrow()
            .execute(&self.sql.release, [prefix, txid])
            .unwrap();
        Ok(())
    }

    async fn holds(&self, prefix: &str) -> Result<bool, StoreError> {
        io().await;
        self.up()?;
        Ok(self
            .db
            .borrow()
            .query_row(HOLDS_SQL, [prefix], |_| Ok(()))
            .optional()
            .unwrap()
            .is_some())
    }

    async fn carry_bound(
        &self,
        prefix: &str,
        txid: &str,
        agent: &str,
    ) -> Result<PrefixClaim, StoreError> {
        io().await;
        self.up()?;
        self.claim_now(prefix, txid, agent)
    }

    async fn carry_unbound(&self, prefix: &str, agent: &str) -> Result<(), StoreError> {
        io().await;
        self.up()?;
        self.db
            .borrow()
            .execute(&self.sql.nonce_claim, [prefix, agent])
            .unwrap();
        Ok(())
    }
}

// ── the key-value namespace in memory ───────────────────────────────────

/// The key-value namespace: each record's value and whether it carries the
/// store's mark. A write is a read, an await, then the write, as on the
/// Worker. `write_faults` fails that many writes, then writes again.
#[derive(Default)]
struct MemoryRecords {
    map: RefCell<HashMap<String, Stored>>,
    fault: Cell<bool>,
    write_fault: Cell<bool>,
    write_faults: Cell<usize>,
    /// Reads of a prefix answered from an earlier copy of its record (a
    /// read at an edge the last write has not reached yet): the copy and
    /// how many reads it answers.
    stale: RefCell<HashMap<String, (Option<Stored>, usize)>>,
}

impl MemoryRecords {
    fn get(&self, prefix: &str) -> Option<String> {
        self.stored(prefix).map(|s| s.value)
    }
    fn stored(&self, prefix: &str) -> Option<Stored> {
        self.map.borrow().get(prefix).cloned()
    }
    /// A record as a key-value build writes it (no mark).
    fn set(&self, prefix: &str, value: &str) {
        self.put(prefix, value, false);
    }
    fn put(&self, prefix: &str, value: &str, marked: bool) {
        self.map.borrow_mut().insert(
            prefix.to_string(),
            Stored {
                value: value.to_string(),
                marked,
            },
        );
    }
    fn writable(&self) -> Result<(), StoreError> {
        if self.fault.get() || self.write_fault.get() {
            return Err(StoreError::new("KV is down"));
        }
        if self.write_faults.get() > 0 {
            self.write_faults.set(self.write_faults.get() - 1);
            return Err(StoreError::new("KV write failed"));
        }
        Ok(())
    }
}

impl PrefixRecords for MemoryRecords {
    async fn read(&self, prefix: &str) -> Result<Option<Stored>, StoreError> {
        io().await;
        if self.fault.get() {
            return Err(StoreError::new("KV is down"));
        }
        let mut stale = self.stale.borrow_mut();
        if let Some((copy, left)) = stale.get_mut(prefix) {
            let copy = copy.clone();
            *left -= 1;
            if *left == 0 {
                stale.remove(prefix);
            }
            return Ok(copy);
        }
        Ok(self.stored(prefix))
    }

    async fn record(&self, prefix: &str, txid: &str, _agent: &str) -> Result<(), StoreError> {
        let found = self.read(prefix).await?;
        io().await;
        match Recording::judge(found.as_ref(), txid) {
            Recording::Write => {
                self.writable()?;
                self.put(prefix, txid, true);
                Ok(())
            }
            Recording::Refused => Err(StoreError::new("another claim's record")),
        }
    }

    async fn release(&self, prefix: &str, txid: &str) -> Result<(), StoreError> {
        let found = self.read(prefix).await?;
        io().await;
        if releases(found.as_ref(), txid) {
            self.writable()?;
            self.put(prefix, &format!("released:{txid}"), false);
        }
        Ok(())
    }
}

/// The key-value store's own claim of `txid` (the middleware's
/// `KvPrefixStore`): its reading of a record, and the txid it writes on a
/// win (no mark).
fn key_value_claim(records: &MemoryRecords, prefix: &str, txid: &str) -> PrefixClaim {
    let claim = match records.get(prefix) {
        None => PrefixClaim::Won,
        Some(v) if v == "1" => PrefixClaim::Unknown,
        Some(v) => match v.strip_prefix("released:") {
            Some(bound) if bound == txid => PrefixClaim::Won,
            Some(_) => PrefixClaim::OtherTransaction,
            None if v == txid => PrefixClaim::SameTransaction,
            None => PrefixClaim::OtherTransaction,
        },
    };
    if claim == PrefixClaim::Won {
        records.set(prefix, txid);
    }
    claim
}

/// The key-value store's own release of `txid`.
fn key_value_release(records: &MemoryRecords, prefix: &str, txid: &str) {
    if records.get(prefix).as_deref() == Some(txid) {
        records.set(prefix, &format!("released:{txid}"));
    }
}

type Store = PaidPrefixStore<SqliteLedger, MemoryRecords>;

fn store() -> Store {
    PaidPrefixStore::new(SqliteLedger::new(), MemoryRecords::default())
}

fn run<F: Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

// ── the kit ──────────────────────────────────────────────────────────────

fn kit(sizes: Option<&[usize]>, held: Option<usize>, namespace: &str) -> usize {
    let store = store();
    let switch = |on: bool| {
        store.ledger().fault.set(on);
        store.records().fault.set(on);
    };
    let seed: &LegacySeeder<'_> = &|prefix: String| {
        let records = store.records();
        Box::pin(async move {
            records.set(&prefix, "1");
            Ok(())
        })
    };
    let mut k = conformance::prefix_store(&store, namespace)
        .fault(&switch)
        .legacy(seed);
    if let Some(sizes) = sizes {
        k = k.sizes(sizes);
    }
    if let Some(held) = held {
        k = k.held_passes(held);
    }
    let report = run(k.run()).unwrap_or_else(|v| panic!("{v}"));
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
    println!(
        "kit on SQLite ({namespace}): {} laws pass, sizes {:?}..{:?}",
        report.checked.len(),
        report.checked.first().map(|c| c.1),
        report.checked.iter().map(|c| c.1).max()
    );
    report.checked.len()
}

#[test]
fn the_store_keeps_every_law_of_the_kit_at_its_defaults() {
    // Five concurrent laws and the fail-closed law at each N from 2 to 33,
    // the sequential law and the legacy law.
    assert_eq!(kit(None, None, "defaults"), 6 * 32 + 2);
}

#[test]
fn the_store_keeps_every_law_of_the_kit_at_raised_bounds() {
    let sizes: Vec<usize> = (2..=64).collect();
    assert_eq!(kit(Some(&sizes), Some(128), "raised"), 6 * sizes.len() + 2);
}

// ── the legacy records ──────────────────────────────────────────────────

fn tx(label: &str) -> String {
    txid_for("legacy", label)
}

#[test]
fn every_record_a_key_value_build_left_stays_refused() {
    let (a, b) = (tx("a"), tx("b"));
    // (record, claimant, answer)
    let cases = [
        ("1", &a, PrefixClaim::Unknown),
        (a.as_str(), &a, PrefixClaim::SameTransaction),
        (a.as_str(), &b, PrefixClaim::OtherTransaction),
        (&*format!("released:{a}"), &a, PrefixClaim::Won),
        (&*format!("released:{a}"), &b, PrefixClaim::OtherTransaction),
    ]
    .map(|(r, t, c)| (r.to_string(), t.clone(), c));
    for (i, (record, claimant, answer)) in cases.iter().enumerate() {
        let s = store();
        let prefix = format!("legacy-{i}");
        s.records().set(&prefix, record);
        let got = run(s.claim_prefix(&prefix, claimant, "test")).unwrap();
        assert_eq!(got, *answer, "{record} claimed by {claimant}");
        // D1 holds the prefix now, and answers it again the same way.
        assert!(s.ledger().row(&prefix).is_some());
        let again = run(s.claim_prefix(&prefix, claimant, "test")).unwrap();
        let expected_again = if *answer == PrefixClaim::Won {
            PrefixClaim::SameTransaction
        } else {
            *answer
        };
        assert_eq!(again, expected_again, "{record} claimed again");
        // No other transaction ever wins it.
        let other = tx(&format!("other-{i}"));
        let refused = run(s.claim_prefix(&prefix, &other, "test")).unwrap();
        assert!(
            matches!(
                refused,
                PrefixClaim::OtherTransaction | PrefixClaim::Unknown
            ),
            "{refused:?}"
        );
        // The record is unchanged, or the txid a won claim was bound to.
        let now = s.records().get(&prefix).unwrap();
        if *answer == PrefixClaim::Won {
            assert_eq!(&now, claimant);
        } else {
            assert_eq!(&now, record);
        }
    }
}

/// A `released:<txid>` record claimed by another transaction first: the
/// other is refused, and the released transaction re-takes once.
#[test]
fn a_released_record_survives_another_transaction_s_attempt() {
    let s = store();
    let (a, b) = (tx("released-a"), tx("released-b"));
    s.records().set("r", &format!("released:{a}"));
    assert_eq!(
        run(s.claim_prefix("r", &b, "test")).unwrap(),
        PrefixClaim::OtherTransaction
    );
    // Carried as it is: bound to `a`, released.
    assert_eq!(s.ledger().row("r"), Some((Some(a.clone()), true)));
    assert_eq!(
        run(s.claim_prefix("r", &a, "test")).unwrap(),
        PrefixClaim::Won
    );
    assert_eq!(
        run(s.claim_prefix("r", &a, "test")).unwrap(),
        PrefixClaim::SameTransaction
    );
    assert_eq!(
        run(s.claim_prefix("r", &b, "test")).unwrap(),
        PrefixClaim::OtherTransaction
    );
}

#[test]
fn a_won_claim_leaves_the_record_a_key_value_build_refuses() {
    let s = store();
    let (a, b) = (tx("won"), tx("won-b"));
    assert_eq!(
        run(s.claim_prefix("p", &a, "test")).unwrap(),
        PrefixClaim::Won
    );
    // The value a key-value build reads as bound to `a`, marked.
    let marked = Stored {
        value: a.clone(),
        marked: true,
    };
    assert_eq!(s.records().stored("p"), Some(marked));
    assert_eq!(
        key_value_claim(s.records(), "p", &a),
        PrefixClaim::SameTransaction
    );
    assert_eq!(
        key_value_claim(s.records(), "p", &b),
        PrefixClaim::OtherTransaction
    );
}

/// A release writes the record as the key-value store's own release does:
/// that store then serves the released transaction once and no other, and
/// this store refuses the prefix after it did.
#[test]
fn a_release_here_is_a_release_to_the_key_value_store_and_back() {
    let s = store();
    let (a, b) = (tx("rb-a"), tx("rb-b"));
    assert_eq!(
        run(s.claim_prefix("p", &a, "test")).unwrap(),
        PrefixClaim::Won
    );
    run(s.release_prefix("p", &a)).unwrap();
    assert_eq!(s.records().get("p"), Some(format!("released:{a}")));
    assert_eq!(s.ledger().row("p"), Some((Some(a.clone()), true)));
    // The key-value store: `a` once, then refused; another refused.
    assert_eq!(key_value_claim(s.records(), "p", &a), PrefixClaim::Won);
    assert_eq!(
        key_value_claim(s.records(), "p", &a),
        PrefixClaim::SameTransaction
    );
    assert_eq!(
        key_value_claim(s.records(), "p", &b),
        PrefixClaim::OtherTransaction
    );
    // Back here: the prefix the key-value store served is refused, though
    // D1 held the attempt released.
    assert_eq!(
        run(s.claim_prefix("p", &a, "test")).unwrap(),
        PrefixClaim::SameTransaction
    );
    assert_eq!(s.ledger().row("p"), Some((Some(a.clone()), false)));
    assert_eq!(
        run(s.claim_prefix("p", &b, "test")).unwrap(),
        PrefixClaim::OtherTransaction
    );
    // Released here and not taken there: this store serves `a` once.
    let q = "q";
    assert_eq!(
        run(s.claim_prefix(q, &a, "test")).unwrap(),
        PrefixClaim::Won
    );
    run(s.release_prefix(q, &a)).unwrap();
    assert_eq!(
        key_value_claim(s.records(), q, &b),
        PrefixClaim::OtherTransaction
    );
    assert_eq!(
        run(s.claim_prefix(q, &a, "test")).unwrap(),
        PrefixClaim::Won
    );
    assert_eq!(
        run(s.claim_prefix(q, &a, "test")).unwrap(),
        PrefixClaim::SameTransaction
    );
    // Released there: this store serves it once.
    let r = "r";
    assert_eq!(key_value_claim(s.records(), r, &a), PrefixClaim::Won);
    key_value_release(s.records(), r, &a);
    assert_eq!(
        run(s.claim_prefix(r, &a, "test")).unwrap(),
        PrefixClaim::Won
    );
    assert_eq!(
        run(s.claim_prefix(r, &a, "test")).unwrap(),
        PrefixClaim::SameTransaction
    );
}

#[test]
fn a_failed_record_write_after_a_win_releases_the_win_and_is_a_fault() {
    let s = store();
    let a = tx("fault");
    s.records().write_fault.set(true);
    assert!(run(s.claim_prefix("p", &a, "test")).is_err());
    assert!(s.won().is_none());
    // D1 bound `a` and released its attempt: the same payment retries.
    assert_eq!(s.ledger().row("p"), Some((Some(a.clone()), true)));
    assert_eq!(s.records().get("p"), None);
    s.records().write_fault.set(false);
    assert_eq!(
        run(s.claim_prefix("p", &a, "test")).unwrap(),
        PrefixClaim::Won
    );
    assert_eq!(s.records().get("p").as_deref(), Some(a.as_str()));
}

/// The record's write fails once after a win: the claim is a fault (the
/// door's 503, before the wallet), released; the same payment then wins,
/// once.
#[test]
fn a_record_write_that_fails_once_is_a_fault_and_the_retry_wins() {
    let s = store();
    let (a, b) = (tx("once"), tx("once-b"));
    s.records().write_faults.set(1);
    assert!(run(s.claim_prefix("p", &a, "test")).is_err());
    assert!(s.won().is_none());
    assert_eq!(s.records().get("p"), None);
    assert_eq!(s.ledger().row("p"), Some((Some(a.clone()), true)));
    assert_eq!(
        run(s.claim_prefix("p", &b, "test")).unwrap(),
        PrefixClaim::OtherTransaction
    );
    assert_eq!(
        run(s.claim_prefix("p", &a, "test")).unwrap(),
        PrefixClaim::Won
    );
    assert!(s.won().is_some());
    assert_eq!(
        run(s.claim_prefix("p", &a, "test")).unwrap(),
        PrefixClaim::SameTransaction
    );
}

/// A record naming another claim found at the write after a win: a fault,
/// the win released, the record left as it was.
#[test]
fn a_record_naming_another_claim_at_the_write_is_a_fault() {
    let s = store();
    let (a, b) = (tx("other-record-a"), tx("other-record-b"));
    // D1 has the prefix bound to `a` and released; the namespace names `b`.
    assert_eq!(
        run(s.claim_prefix("p", &a, "test")).unwrap(),
        PrefixClaim::Won
    );
    run(s.release_prefix("p", &a)).unwrap();
    s.records().put("p", &format!("released:{b}"), false);
    assert!(run(s.claim_prefix("p", &a, "test")).is_err());
    assert_eq!(s.records().get("p"), Some(format!("released:{b}")));
    assert_eq!(s.ledger().row("p"), Some((Some(a.clone()), true)));
}

// ── the grants ───────────────────────────────────────────────────────────

/// The grant's two writes as the routes make them: `minutes` keeps what the
/// route computed, a fraction included; `satoshis` the amount paid.
#[test]
fn the_grant_keeps_the_minutes_as_the_route_computed_them() {
    let db = Connection::open_in_memory().unwrap();
    db.execute(GRANTS_SCHEMA, []).unwrap();
    let paid = |prefix: &str| {
        db.execute(
            GRANT_PAID_SQL,
            rusqlite::params![prefix, "t", "/upload", "k", 1234i64],
        )
        .unwrap()
    };
    for (prefix, minutes) in [("whole", 90.0f64), ("fraction", 90.5)] {
        assert_eq!(paid(prefix), 1);
        db.execute(
            GRANT_ANSWERED_SQL,
            rusqlite::params![
                prefix,
                "granted",
                200i64,
                "o",
                rusqlite::types::Null,
                1000i64,
                minutes,
                1_900_000_300i64
            ],
        )
        .unwrap();
        let (kept, satoshis): (f64, i64) = db
            .query_row(
                "SELECT minutes, satoshis FROM payment_grants WHERE prefix = ?1",
                [prefix],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((kept, satoshis), (minutes, 1234));
    }
}

// ── the release path ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Claim(PrefixClaim),
    Released,
    Fault,
}

fn claim_op<'a>(s: &'a Store, prefix: &'a str, txid: &'a str) -> LocalFuture<'a, Op> {
    Box::pin(async move {
        match s.claim_prefix(prefix, txid, "test").await {
            Ok(c) => Op::Claim(c),
            Err(_) => Op::Fault,
        }
    })
}

fn release_op<'a>(s: &'a Store, prefix: &'a str, txid: &'a str) -> LocalFuture<'a, Op> {
    Box::pin(async move {
        match s.release_prefix(prefix, txid).await {
            Ok(()) => Op::Released,
            Err(_) => Op::Fault,
        }
    })
}

fn every_schedule(n: usize) -> Vec<Schedule> {
    schedules(n, conformance::RANDOM_SCHEDULES, conformance::DEFAULT_SEED)
}

/// (a) A release of a prefix no claim holds, started together with claims
/// by two different transactions: at most one transaction is ever bound.
#[test]
fn a_release_of_an_unheld_prefix_with_claims_by_two_transactions_binds_one() {
    for n in [2usize, 3, 8, 16] {
        for (k, schedule) in every_schedule(n + 1).into_iter().enumerate() {
            let s = store();
            let prefix = format!("a-{n}-{k}");
            let txids: Vec<String> = (0..n).map(|i| tx(&format!("a{i}"))).collect();
            let mut ops: Vec<LocalFuture<'_, Op>> = vec![release_op(&s, &prefix, &txids[0])];
            ops.extend(txids.iter().map(|t| claim_op(&s, &prefix, t)));
            let out = run(drive(ops, schedule));
            let winners: Vec<&String> = out[1..]
                .iter()
                .zip(&txids)
                .filter(|(o, _)| **o == Op::Claim(PrefixClaim::Won))
                .map(|(_, t)| t)
                .collect();
            // The first claim to reach D1 binds; every other transaction is
            // refused, whenever the release lands.
            assert_eq!(winners.len(), 1, "{schedule}: {out:?}");
            assert!(!out.contains(&Op::Fault), "{schedule}: {out:?}");
            let bound = s.ledger().row(&prefix).and_then(|r| r.0);
            assert_eq!(bound.as_ref(), Some(winners[0]), "{schedule}");
            // Afterwards no other transaction wins, and the record names the
            // bound transaction.
            let bound = bound.expect("one claim binds");
            for t in &txids {
                let got = run(s.claim_prefix(&prefix, t, "test")).unwrap();
                if *t != bound {
                    assert_eq!(got, PrefixClaim::OtherTransaction, "{schedule}");
                }
            }
            // The record names the bound transaction: held, or released
            // when D1 holds its attempt released.
            let released = s.ledger().row(&prefix).unwrap().1;
            let record = s.records().get(&prefix).unwrap();
            assert!(
                record == bound || (released && record == format!("released:{bound}")),
                "{schedule}: {record} released={released}"
            );
        }
    }
}

/// (b) Two releases with a re-take between them: no more wins than
/// releases that took effect, and afterwards one winner of N re-takes.
#[test]
fn two_releases_with_a_retake_between_win_no_more_than_the_contract() {
    for n in [2usize, 4, 16] {
        for (k, schedule) in every_schedule(3).into_iter().enumerate() {
            let s = store();
            let prefix = format!("b-{n}-{k}");
            let a = tx("b");
            assert_eq!(
                run(s.claim_prefix(&prefix, &a, "test")).unwrap(),
                PrefixClaim::Won
            );
            let ops = vec![
                release_op(&s, &prefix, &a),
                claim_op(&s, &prefix, &a),
                release_op(&s, &prefix, &a),
            ];
            let out = run(drive(ops, schedule));
            let wins = out
                .iter()
                .filter(|o| **o == Op::Claim(PrefixClaim::Won))
                .count();
            assert!(wins <= 1, "{schedule}: {out:?}");
            assert!(!out.contains(&Op::Fault), "{schedule}: {out:?}");
            let released = s.ledger().row(&prefix).unwrap().1;
            // N re-takes together: one wins if the attempt is free, none if
            // it is held.
            let retakes: Vec<LocalFuture<'_, Op>> =
                (0..n).map(|_| claim_op(&s, &prefix, &a)).collect();
            let out = run(drive(retakes, Schedule::Lockstep));
            let wins = out
                .iter()
                .filter(|o| **o == Op::Claim(PrefixClaim::Won))
                .count();
            assert_eq!(wins, usize::from(released), "{schedule}: {out:?}");
            assert_eq!(
                run(s.claim_prefix(&prefix, &tx("other"), "test")).unwrap(),
                PrefixClaim::OtherTransaction
            );
        }
    }
}

/// (c) A release of a prefix never claimed creates no record in D1 or in
/// the key-value namespace.
#[test]
fn a_release_of_a_prefix_never_claimed_creates_nothing() {
    let s = store();
    run(s.release_prefix("never", &tx("c"))).unwrap();
    assert_eq!(s.ledger().row("never"), None);
    assert_eq!(s.records().get("never"), None);
    // Then the prefix is a fresh claim.
    assert_eq!(
        run(s.claim_prefix("never", &tx("c2"), "test")).unwrap(),
        PrefixClaim::Won
    );
}

/// (d) A release racing the record's write after a win: the stores agree
/// on the binding (the record names the transaction D1 bound), and D1
/// decides the attempt (held, or released and open to that transaction).
#[test]
fn a_release_racing_the_record_s_write_leaves_the_stores_agreeing() {
    for (k, schedule) in every_schedule(2).into_iter().enumerate() {
        let s = store();
        let prefix = format!("d-{k}");
        let a = tx("d");
        let ops = vec![claim_op(&s, &prefix, &a), release_op(&s, &prefix, &a)];
        let out = run(drive(ops, schedule));
        assert_eq!(out[0], Op::Claim(PrefixClaim::Won), "{schedule}");
        assert_eq!(out[1], Op::Released, "{schedule}");
        let (bound, released) = s.ledger().row(&prefix).unwrap();
        assert_eq!(bound.as_deref(), Some(a.as_str()));
        let record = s.records().get(&prefix).unwrap();
        assert!(
            record == a || (released && record == format!("released:{a}")),
            "{schedule}: {record} released={released}"
        );
        // A reader of this build: D1 decides.
        let again = run(s.claim_prefix(&prefix, &a, "test")).unwrap();
        let expected = if released {
            PrefixClaim::Won
        } else {
            PrefixClaim::SameTransaction
        };
        assert_eq!(again, expected, "{schedule}");
        assert_eq!(
            run(s.claim_prefix(&prefix, &tx("d-other"), "test")).unwrap(),
            PrefixClaim::OtherTransaction
        );
    }
}

// ── a carried release ───────────────────────────────────────────────────

/// A `released:<a>` record a key-value build left, met at once by `a`'s
/// own claims and by other transactions' claims, over every schedule; then
/// `a` claimed three times more. The carry of the record releases only the
/// claim its own carry made, so `a` is won at most once in all, and no other
/// transaction is won. Each line printed: the mix, its schedules, the
/// schedules in which `a` was won more than once, and those in which it was
/// never won.
#[test]
fn a_carried_release_frees_only_its_own_claim() {
    let mut report = Vec::new();
    let (mut more_than_once, mut others_won, mut runs) = (0, 0, 0);
    for (n, mixes) in [
        (2usize, vec![(1usize, 1usize, true), (1, 1, false)]),
        (
            8,
            vec![(1, 7, true), (1, 7, false), (4, 4, true), (4, 4, false)],
        ),
    ] {
        for (na, nb, others_first) in mixes {
            let (mut twice, mut never, mut schedules_run) = (0, 0, 0);
            for (k, schedule) in every_schedule(n).into_iter().enumerate() {
                schedules_run += 1;
                let s = store();
                let prefix = format!("carried-{n}-{na}-{others_first}-{k}");
                let a = tx("carried-a");
                let others: Vec<String> = (0..nb).map(|i| tx(&format!("carried-b{i}"))).collect();
                s.records().set(&prefix, &format!("released:{a}"));
                let mine: Vec<(bool, &str)> = (0..na).map(|_| (true, a.as_str())).collect();
                let theirs: Vec<(bool, &str)> =
                    others.iter().map(|b| (false, b.as_str())).collect();
                let order = if others_first {
                    [theirs, mine].concat()
                } else {
                    [mine, theirs].concat()
                };
                let who: Vec<bool> = order.iter().map(|(is_a, _)| *is_a).collect();
                let ops: Vec<LocalFuture<'_, Op>> = order
                    .iter()
                    .map(|(_, t)| claim_op(&s, &prefix, t))
                    .collect();
                let out = run(drive(ops, schedule));
                let won = Op::Claim(PrefixClaim::Won);
                let mut a_won = out
                    .iter()
                    .zip(&who)
                    .filter(|(o, w)| **w && **o == won)
                    .count();
                others_won += out
                    .iter()
                    .zip(&who)
                    .filter(|(o, w)| !**w && **o == won)
                    .count();
                for _ in 0..3 {
                    if run(s.claim_prefix(&prefix, &a, "test")) == Ok(PrefixClaim::Won) {
                        a_won += 1;
                    }
                }
                if a_won > 1 {
                    twice += 1;
                }
                if a_won == 0 {
                    never += 1;
                }
            }
            runs += schedules_run;
            more_than_once += twice;
            report.push(format!(
                "N={n} a x{na} others x{nb} {}: {schedules_run} schedules; a won more than once in {twice}; never in {never}",
                if others_first { "others first" } else { "a first" }
            ));
        }
    }
    for line in &report {
        eprintln!("{line}");
    }
    eprintln!("{runs} schedules in all; a won more than once in {more_than_once}; another transaction won {others_won}");
    assert_eq!(more_than_once, 0, "{report:#?}");
    assert_eq!(others_won, 0, "{report:#?}");
}

/// A won claim writes its record even when its read of the record finds
/// this store's record of the same transaction (a read that does not yet
/// see the release before it): after the win, the key-value store's own
/// claim reads the prefix as bound to the transaction.
#[test]
fn a_won_claim_writes_its_record_whatever_its_read_says() {
    let s = store();
    let a = tx("record-a");
    assert_eq!(run(s.claim_prefix("p", &a, "test")), Ok(PrefixClaim::Won));
    let before = s.records().stored("p");
    run(s.release_prefix("p", &a)).unwrap();
    assert_eq!(s.records().get("p"), Some(format!("released:{a}")));
    // The next two reads of the record (the carry's, the record's) answer
    // the record as it was before the release.
    s.records()
        .stale
        .borrow_mut()
        .insert("p".into(), (before, 2));
    assert_eq!(run(s.claim_prefix("p", &a, "test")), Ok(PrefixClaim::Won));
    let after = s.records().stored("p").unwrap();
    assert_eq!((after.value.as_str(), after.marked), (a.as_str(), true));
    assert_eq!(
        key_value_claim(s.records(), "p", &a),
        PrefixClaim::SameTransaction
    );
}
