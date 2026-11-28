//! The paid routes' payment-prefix store (`/upload`, `/renew`): the claim in
//! the `CLAIMS` D1 database, the key-value record beside it, and the record
//! of what each won claim was granted.
//!
//! # Who decides
//!
//! The D1 claim decides, in one statement: [`PaidPrefixStore::claim_prefix`]
//! claims through the middleware's `payment_prefix_gate` (the upsert of
//! `D1PrefixStore` and its classifying read, in one D1 batch), and its
//! answer is the middleware's: a win is served; the same transaction again
//! is the signed `409 ERR_PAYMENT_REPLAYED`; another transaction under a
//! bound prefix is the signed `400 ERR_PAYMENT_INVALID`; a claim the gate
//! cannot make (no `CLAIMS` binding, no table, a D1 fault) is the gate's
//! signed `503 ERR_PAYMENT_UNAVAILABLE` (retryable, the quote kept). A
//! fault this store meets before or after the gate (the key-value store, the
//! read of D1 in front of the gate, a carry) is the door's own `503
//! ERR_PAYMENT_UNAVAILABLE`, which it sends unsigned. No fault is ever a
//! service.
//!
//! # The key-value record
//!
//! Each prefix has a record in the `AUTH_SESSIONS` key-value namespace (key
//! `auth:nonce:payment-derivation-prefix:<prefix>`, no expiry; value the
//! bound txid, `released:<txid>`, or `1` for a prefix consumed before
//! records were bound to a transaction), in the shape the middleware's
//! `KvPrefixStore` reads and writes. The record this store writes for a won
//! claim carries [`RECORD_MARK`] in its metadata; a bound record without it
//! is held in D1 for its transaction whenever it is read. Every claim
//! reads the record first ([`PrefixRecords::read`]) and carries what it
//! says into D1 with the middleware's own statements before the claim
//! ([`ClaimLedger::carry_bound`], [`ClaimLedger::carry_unbound`],
//! [`ClaimLedger::release`]), so the claim that follows answers it as D1
//! answers any used prefix:
//!
//! | record | carried into D1 | the claim answers |
//! |---|---|---|
//! | none | nothing | `Won` (a new prefix) |
//! | `1` | a row with no transaction, when D1 has none | `Unknown` (409) |
//! | `<txid>`, marked | bound to that txid, when D1 has no row | D1's answer |
//! | `<txid>`, not marked | bound and held for that txid, always | the same txid: `SameTransaction` (409); another: `OtherTransaction` (400) |
//! | `released:<txid>`, that txid | nothing | `Won` (its re-take), or D1's answer |
//! | `released:<txid>`, another txid | bound to the released txid, when D1 has no row, and released when that binding was this carry's own | `OtherTransaction` (400); the released txid later re-takes |
//!
//! After a claim is won, the store writes the record
//! ([`PrefixRecords::record`]): the txid, no expiry, marked, whatever its
//! read of the record found of this claim's own record. The write follows
//! the D1 win, so it never decides who wins. If it cannot be
//! written (a fault, or a record naming another claim), the won attempt is
//! released and the claim answers a fault (503) before the wallet is
//! called: the payer retries the same payment.
//!
//! # Releases
//!
//! A release ([`PaidPrefixStore::release_prefix`]) writes the key-value
//! record as the key-value store's own release writes it
//! (`released:<txid>`, same key, no expiry, [`PrefixRecords::release`],
//! when the record is this store's record of that txid), then releases in
//! D1 ([`ClaimLedger::release`]: the middleware's `D1PrefixStore` release,
//! which frees the bound transaction's attempt and keeps the binding). The
//! middleware's door calls it when the wallet storage server answers
//! `internalizeAction` with an error. A released payer pays again with the
//! same transaction, once, and with no other, whichever store the build
//! that answers claims in.

use std::cell::RefCell;
use std::future::Future;

use bsv_middleware_cloudflare::core::{PaymentPrefixStore, PrefixClaim, StoreError};
use serde_json::Value;

/// The `CLAIMS` binding: the D1 database the payment prefixes are claimed in.
pub const CLAIMS_BINDING: &str = "CLAIMS";

/// Whether D1 holds a row for a prefix (read only; the claim is the
/// middleware's statement).
pub const HOLDS_SQL: &str = "SELECT 1 AS held FROM payment_claims WHERE nonce = ?1";

/// The grants: what each won claim was granted, one row per claimed prefix.
/// `satoshis` is the amount paid (the payment's output to this server, at
/// least the price). `minutes` is the minutes the route granted, as the
/// route computed them (a fractional retention is kept as it was asked, a
/// REAL in the column). `expiry_time` is the expiry the advert carries
/// (`/upload`: the presigned PUT's expiry with the object's custom-time
/// buffer, the expiry the queue advertises; `/renew`: the new expiry).
/// `state` is `paid` when the wallet accepted the payment and the route's
/// answer is not yet recorded. `/upload` then writes `granted` (it answered
/// 2xx) or `refused` (it answered otherwise). `/renew` writes `granted` once
/// a broadcaster took the renewing transaction, and otherwise keeps `paid`
/// with its answer's `status` and `answered_at`: the payment was taken and
/// no renewal was served, and its `renewals` row says what the renewing
/// step came to. A row left `paid` with `answered_at` null is a win whose
/// second grant write failed; a win whose first write failed has no row.
pub const GRANTS_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS payment_grants (\
    prefix TEXT PRIMARY KEY, txid TEXT NOT NULL, route TEXT NOT NULL, \
    identity_key TEXT NOT NULL, satoshis INTEGER NOT NULL, paid_at INTEGER NOT NULL, \
    state TEXT NOT NULL DEFAULT 'paid', status INTEGER, object_identifier TEXT, \
    uhrp_url TEXT, file_size INTEGER, minutes INTEGER, expiry_time INTEGER, \
    answered_at INTEGER\
)";

/// The first grant write, once the wallet accepted the payment.
pub const GRANT_PAID_SQL: &str = "INSERT INTO payment_grants \
    (prefix, txid, route, identity_key, satoshis, paid_at, state) \
    VALUES (?1, ?2, ?3, ?4, ?5, unixepoch(), 'paid') ON CONFLICT(prefix) DO NOTHING";

/// The second grant write, once the route answered.
pub const GRANT_ANSWERED_SQL: &str = "UPDATE payment_grants SET state = ?2, status = ?3, \
    object_identifier = ?4, uhrp_url = ?5, file_size = ?6, minutes = ?7, expiry_time = ?8, \
    answered_at = unixepoch() WHERE prefix = ?1 AND state = 'paid'";

/// The middleware's refusal of a claim, to be signed for the payer.
#[derive(Debug, Clone, PartialEq)]
pub struct Refusal {
    pub status: u16,
    pub body: Value,
    pub headers: Vec<(String, String)>,
}

/// What the D1 claim answered.
#[derive(Debug, Clone, PartialEq)]
pub struct Claimed {
    pub claim: PrefixClaim,
    /// The middleware's answer for a claim that was not won.
    pub refusal: Option<Refusal>,
}

/// A claim the D1 side could not make: the fault, and the middleware's
/// answer to it when the middleware gave one (the gate's 503).
#[derive(Debug, Clone, PartialEq)]
pub struct Unanswered {
    pub error: StoreError,
    pub refusal: Option<Box<Refusal>>,
}

impl From<StoreError> for Unanswered {
    fn from(error: StoreError) -> Self {
        Self {
            error,
            refusal: None,
        }
    }
}

/// The D1 side of the store.
pub trait ClaimLedger {
    /// The claim: one statement, the middleware's.
    fn claim(
        &self,
        prefix: &str,
        txid: &str,
        agent: &str,
    ) -> impl Future<Output = Result<Claimed, Unanswered>>;
    /// Frees `txid`'s attempt on `prefix`; the binding stays.
    fn release(&self, prefix: &str, txid: &str) -> impl Future<Output = Result<(), StoreError>>;
    /// Whether a row exists for `prefix`.
    fn holds(&self, prefix: &str) -> impl Future<Output = Result<bool, StoreError>>;
    /// A key-value record bound to `txid`, carried into D1 as a held binding
    /// (the middleware's claim statement: a released row of the same txid is
    /// held again). The answer is the statement's: `Won` when this call
    /// created the row or held a released one again.
    fn carry_bound(
        &self,
        prefix: &str,
        txid: &str,
        agent: &str,
    ) -> impl Future<Output = Result<PrefixClaim, StoreError>>;
    /// A key-value record bound to no transaction (`1`), carried into D1 as
    /// a row with no transaction.
    fn carry_unbound(
        &self,
        prefix: &str,
        agent: &str,
    ) -> impl Future<Output = Result<(), StoreError>>;
    /// Whether the ledger is there to be asked. When it is not, the claim
    /// goes straight to [`ClaimLedger::claim`], whose answer is the fault.
    fn bound(&self) -> bool {
        true
    }
}

/// A key-value record as read: its value and whether it carries
/// [`RECORD_MARK`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub value: String,
    pub marked: bool,
}

/// The key-value side of the store.
pub trait PrefixRecords {
    /// The record under the prefix's key, if any.
    fn read(&self, prefix: &str) -> impl Future<Output = Result<Option<Stored>, StoreError>>;
    /// The record of a won claim: `txid`, no expiry, marked. Written when
    /// the key holds no record, `released:<txid>`, or this store's record
    /// of `txid` (written again); any other record is an error, as is a
    /// failed write.
    fn record(
        &self,
        prefix: &str,
        txid: &str,
        agent: &str,
    ) -> impl Future<Output = Result<(), StoreError>>;
    /// The release: `released:<txid>`, no expiry, written when the key
    /// holds this store's record of `txid`, and nothing written otherwise.
    fn release(&self, prefix: &str, txid: &str) -> impl Future<Output = Result<(), StoreError>>;
}

/// The metadata of the record this store writes for a won claim.
pub const RECORD_MARK: (&str, &str) = ("ledger", "d1");

/// What [`PrefixRecords::record`] does with the record it finds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recording {
    Write,
    Refused,
}

impl Recording {
    pub fn judge(found: Option<&Stored>, txid: &str) -> Recording {
        let Some(found) = found else {
            return Recording::Write;
        };
        match Record::parse(&found.value) {
            Record::Released(t) if t == txid => Recording::Write,
            Record::Bound(t) if t == txid && found.marked => Recording::Write,
            _ => Recording::Refused,
        }
    }
}

/// Whether [`PrefixRecords::release`] writes `released:<txid>` over the
/// record it finds.
pub fn releases(found: Option<&Stored>, txid: &str) -> bool {
    found.is_some_and(|f| f.marked && f.value == txid)
}

/// A key-value record, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// `1`: consumed, bound to no transaction.
    Unbound,
    /// The txid: held or served.
    Bound(String),
    /// `released:<txid>`: that txid's attempt was released.
    Released(String),
}

impl Record {
    pub fn parse(value: &str) -> Record {
        if value == "1" {
            return Record::Unbound;
        }
        match value.strip_prefix("released:") {
            Some(txid) => Record::Released(txid.to_string()),
            None => Record::Bound(value.to_string()),
        }
    }
}

/// The won claim of a request: the prefix and the transaction bound to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Won {
    pub prefix: String,
    pub txid: String,
}

/// The paid routes' [`PaymentPrefixStore`]: the D1 claim, the key-value
/// record read in front of it and written after a win (see the module docs).
/// One per request: it keeps the request's won claim, or the middleware's
/// refusal of it, for the answer.
pub struct PaidPrefixStore<L, R> {
    ledger: L,
    records: R,
    refusal: RefCell<Option<Refusal>>,
    won: RefCell<Option<Won>>,
}

impl<L: ClaimLedger, R: PrefixRecords> PaidPrefixStore<L, R> {
    pub fn new(ledger: L, records: R) -> Self {
        Self {
            ledger,
            records,
            refusal: RefCell::new(None),
            won: RefCell::new(None),
        }
    }

    /// The middleware's answer to this request's claim when it was refused,
    /// or when the gate could not make it (its 503).
    pub fn take_refusal(&self) -> Option<Refusal> {
        self.refusal.borrow_mut().take()
    }

    /// This request's won claim, if it was won and not released.
    pub fn won(&self) -> Option<Won> {
        self.won.borrow().clone()
    }

    pub fn ledger(&self) -> &L {
        &self.ledger
    }

    pub fn records(&self) -> &R {
        &self.records
    }

    /// The key-value record carried into D1 (see the module docs' table).
    async fn carry(
        &self,
        prefix: &str,
        txid: &str,
        agent: &str,
    ) -> Result<Option<Record>, StoreError> {
        let Some(stored) = self.records.read(prefix).await? else {
            return Ok(None);
        };
        let record = Record::parse(&stored.value);
        match &record {
            Record::Bound(bound) if !stored.marked => {
                self.ledger.carry_bound(prefix, bound, agent).await?;
            }
            Record::Released(bound) if bound == txid => {}
            _ if self.ledger.holds(prefix).await? => {}
            Record::Unbound => self.ledger.carry_unbound(prefix, agent).await?,
            Record::Bound(bound) => {
                self.ledger.carry_bound(prefix, bound, agent).await?;
            }
            // The carry releases only the binding it made itself: `Won` is
            // its own insert, or its own hold of a released row.
            Record::Released(bound) => {
                if self.ledger.carry_bound(prefix, bound, agent).await? == PrefixClaim::Won {
                    self.ledger.release(prefix, bound).await?
                }
            }
        }
        Ok(Some(record))
    }

    /// Both stores' release: the key-value record first, then D1. A failed
    /// key-value write is logged; D1's answer is the release's.
    async fn release_both(&self, prefix: &str, txid: &str) -> Result<(), StoreError> {
        if let Err(e) = self.records.release(prefix, txid).await {
            log(&format!(
                "payment prefix: the key-value release failed: {e}"
            ));
        }
        self.ledger.release(prefix, txid).await
    }
}

impl<L: ClaimLedger, R: PrefixRecords> PaymentPrefixStore for PaidPrefixStore<L, R> {
    async fn claim_prefix(
        &self,
        prefix: &str,
        txid: &str,
        agent: &str,
    ) -> Result<PrefixClaim, StoreError> {
        let record = if self.ledger.bound() {
            self.carry(prefix, txid, agent).await?
        } else {
            None
        };
        let Claimed { claim, refusal } = match self.ledger.claim(prefix, txid, agent).await {
            Ok(claimed) => claimed,
            Err(Unanswered { error, refusal }) => {
                *self.refusal.borrow_mut() = refusal.map(|r| *r);
                return Err(error);
            }
        };
        // The middleware answers a row bound to no transaction as it answers
        // the same transaction (409); a `1` record is that row.
        let claim = match (claim, &record) {
            (PrefixClaim::SameTransaction, Some(Record::Unbound)) => PrefixClaim::Unknown,
            (claim, _) => claim,
        };
        if claim != PrefixClaim::Won {
            *self.refusal.borrow_mut() = refusal;
            return Ok(claim);
        }
        if let Err(e) = self.records.record(prefix, txid, agent).await {
            if let Err(released) = self.release_both(prefix, txid).await {
                log(&format!(
                    "payment prefix: the record's write and the release both failed: {released}"
                ));
            }
            return Err(e);
        }
        *self.won.borrow_mut() = Some(Won {
            prefix: prefix.to_string(),
            txid: txid.to_string(),
        });
        Ok(PrefixClaim::Won)
    }

    async fn release_prefix(&self, prefix: &str, txid: &str) -> Result<(), StoreError> {
        self.release_both(prefix, txid).await?;
        let mut won = self.won.borrow_mut();
        if won
            .as_ref()
            .is_some_and(|w| w.prefix == prefix && w.txid == txid)
        {
            *won = None;
        }
        Ok(())
    }
}

fn log(message: &str) {
    #[cfg(target_arch = "wasm32")]
    worker::console_warn!("{}", message);
    #[cfg(not(target_arch = "wasm32"))]
    let _ = message;
}

// ── the Worker's two sides ───────────────────────────────────────────────

pub use worker_sides::{D1Ledger, KvRecords};

mod worker_sides {
    use super::*;
    use bsv_middleware_cloudflare::payment_claims::{
        claim_payment_nonce, claim_payment_prefix, payment_prefix_gate, D1PrefixStore,
        FaultPosture, PrefixGate,
    };
    use worker::kv::KvStore;
    use worker::{D1Database, Env};

    fn d1(e: impl std::fmt::Display) -> StoreError {
        StoreError::new(e.to_string())
    }

    /// The claim in the `CLAIMS` database, through the middleware's
    /// `payment_prefix_gate`.
    pub struct D1Ledger<'a> {
        env: &'a Env,
        db: Option<D1Database>,
    }

    impl<'a> D1Ledger<'a> {
        /// `CLAIMS` from `env`. Without the binding every claim is the
        /// gate's 503 and nothing is served.
        pub fn from_env(env: &'a Env) -> Self {
            Self {
                env,
                db: env.d1(CLAIMS_BINDING).ok(),
            }
        }

        /// The `CLAIMS` database, when bound.
        pub fn db(&self) -> Option<&D1Database> {
            self.db.as_ref()
        }

        fn bound_db(&self) -> Result<&D1Database, StoreError> {
            self.db
                .as_ref()
                .ok_or_else(|| StoreError::new("the CLAIMS binding is missing"))
        }
    }

    /// The middleware's gate, read as a claim. The gate answers 409 for the
    /// same transaction (and for a row with none), 400 for another
    /// transaction, and 503 for a claim it cannot make; the 503 is this
    /// store's fault, carrying the gate's answer for the payer.
    pub fn read_gate(gate: PrefixGate) -> Result<Claimed, Unanswered> {
        match gate {
            PrefixGate::Proceed => Ok(Claimed {
                claim: PrefixClaim::Won,
                refusal: None,
            }),
            PrefixGate::Refuse {
                status,
                body,
                headers,
            } => {
                let refusal = Refusal {
                    status,
                    body,
                    headers,
                };
                let claim = match status {
                    409 => PrefixClaim::SameTransaction,
                    400 => PrefixClaim::OtherTransaction,
                    _ => {
                        return Err(Unanswered {
                            error: StoreError::new(format!(
                                "the claims ledger did not answer ({status})"
                            )),
                            refusal: Some(Box::new(refusal)),
                        })
                    }
                };
                Ok(Claimed {
                    claim,
                    refusal: Some(refusal),
                })
            }
            PrefixGate::Fault { detail } => Err(StoreError::new(detail).into()),
        }
    }

    impl ClaimLedger for D1Ledger<'_> {
        async fn claim(
            &self,
            prefix: &str,
            txid: &str,
            agent: &str,
        ) -> Result<Claimed, Unanswered> {
            read_gate(
                payment_prefix_gate(self.env, prefix, txid, agent, FaultPosture::Closed).await,
            )
        }

        async fn release(&self, prefix: &str, txid: &str) -> Result<(), StoreError> {
            D1PrefixStore(self.bound_db()?)
                .release_prefix(prefix, txid)
                .await
        }

        async fn holds(&self, prefix: &str) -> Result<bool, StoreError> {
            let row = self
                .bound_db()?
                .prepare(HOLDS_SQL)
                .bind(&[prefix.into()])
                .map_err(d1)?
                .first::<Value>(None)
                .await
                .map_err(d1)?;
            Ok(row.is_some())
        }

        async fn carry_bound(
            &self,
            prefix: &str,
            txid: &str,
            agent: &str,
        ) -> Result<PrefixClaim, StoreError> {
            claim_payment_prefix(self.bound_db()?, prefix, txid, agent)
                .await
                .map_err(StoreError::new)
        }

        async fn carry_unbound(&self, prefix: &str, agent: &str) -> Result<(), StoreError> {
            claim_payment_nonce(self.bound_db()?, prefix, agent)
                .await
                .map(|_| ())
                .map_err(StoreError::new)
        }

        fn bound(&self) -> bool {
            self.db.is_some()
        }
    }

    /// The key-value record in `AUTH_SESSIONS`, under the key and in the
    /// value shape the middleware's `KvPrefixStore` reads and writes.
    pub struct KvRecords {
        kv: KvStore,
    }

    impl KvRecords {
        pub fn new(kv: KvStore) -> Self {
            Self { kv }
        }

        /// The middleware's key for a prefix's record (`KvSessionStorage`'s
        /// nonce key under the auth middleware's `"auth"` prefix).
        pub fn key(prefix: &str) -> String {
            #[allow(deprecated)]
            let scope = bsv_middleware_cloudflare::core::store::PAYMENT_NONCE_SCOPE;
            format!("auth:nonce:{scope}:{prefix}")
        }

        async fn put(&self, prefix: &str, value: &str, marked: bool) -> Result<(), StoreError> {
            let put = self.kv.put(&Self::key(prefix), value).map_err(d1)?;
            let put = if marked {
                let (name, mark) = RECORD_MARK;
                put.metadata(serde_json::json!({ name: mark }))
                    .map_err(d1)?
            } else {
                put
            };
            put.execute().await.map_err(d1)
        }
    }

    impl PrefixRecords for KvRecords {
        async fn read(&self, prefix: &str) -> Result<Option<Stored>, StoreError> {
            let (value, metadata) = self
                .kv
                .get(&Self::key(prefix))
                .text_with_metadata::<Value>()
                .await
                .map_err(d1)?;
            let (name, mark) = RECORD_MARK;
            Ok(value.map(|value| Stored {
                value,
                marked: metadata.is_some_and(|m| m[name] == mark),
            }))
        }

        async fn record(&self, prefix: &str, txid: &str, _agent: &str) -> Result<(), StoreError> {
            match Recording::judge(self.read(prefix).await?.as_ref(), txid) {
                Recording::Write => self.put(prefix, txid, true).await,
                Recording::Refused => {
                    Err(StoreError::new("the key-value record names another claim"))
                }
            }
        }

        async fn release(&self, prefix: &str, txid: &str) -> Result<(), StoreError> {
            if releases(self.read(prefix).await?.as_ref(), txid) {
                self.put(prefix, &format!("released:{txid}"), false).await?;
            }
            Ok(())
        }
    }

    /// The paid routes' store on the Worker's bindings: `CLAIMS` and
    /// `AUTH_SESSIONS`.
    pub fn paid_store(env: &Env) -> Result<PaidStore<'_>, StoreError> {
        Ok(PaidPrefixStore::new(
            D1Ledger::from_env(env),
            KvRecords::new(env.kv("AUTH_SESSIONS").map_err(d1)?),
        ))
    }
}

pub use worker_sides::{paid_store, read_gate};

/// The paid routes' store on the Worker's bindings.
pub type PaidStore<'a> = PaidPrefixStore<D1Ledger<'a>, KvRecords>;

// ── the grant ────────────────────────────────────────────────────────────

/// What a paid route granted.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Granted {
    pub object_identifier: Option<String>,
    pub uhrp_url: Option<String>,
    pub file_size: Option<u64>,
    pub minutes: Option<f64>,
    pub expiry_time: Option<u64>,
}

/// The grant's two writes, in the `CLAIMS` database. Each is logged on
/// failure and never changes the route's answer.
pub mod grants {
    use super::*;
    use worker::D1Database;

    fn num(n: Option<u64>) -> wasm_bindgen::JsValue {
        match n {
            Some(n) => wasm_bindgen::JsValue::from_f64(n as f64),
            None => wasm_bindgen::JsValue::NULL,
        }
    }

    fn text(s: Option<&str>) -> wasm_bindgen::JsValue {
        match s {
            Some(s) => wasm_bindgen::JsValue::from_str(s),
            None => wasm_bindgen::JsValue::NULL,
        }
    }

    /// The wallet accepted the payment for `won` on `route`.
    pub async fn paid(
        db: &D1Database,
        won: &Won,
        route: &str,
        identity_key: &str,
        satoshis: u64,
    ) -> Result<(), String> {
        db.prepare(GRANT_PAID_SQL)
            .bind(&[
                won.prefix.as_str().into(),
                won.txid.as_str().into(),
                route.into(),
                identity_key.into(),
                num(Some(satoshis)),
            ])
            .map_err(|e| e.to_string())?
            .run()
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// The route answered `status`, granting `granted`: `granted` for a 2xx,
    /// `refused` otherwise (`/upload`).
    pub async fn answered(
        db: &D1Database,
        won: &Won,
        status: u16,
        granted: &Granted,
    ) -> Result<(), String> {
        let state = if (200..300).contains(&status) {
            "granted"
        } else {
            "refused"
        };
        answered_as(db, won, state, status, granted).await
    }

    /// The route answered `status` and the grant's state is `state`.
    pub async fn answered_as(
        db: &D1Database,
        won: &Won,
        state: &str,
        status: u16,
        granted: &Granted,
    ) -> Result<(), String> {
        db.prepare(GRANT_ANSWERED_SQL)
            .bind(&[
                won.prefix.as_str().into(),
                state.into(),
                num(Some(u64::from(status))),
                text(granted.object_identifier.as_deref()),
                text(granted.uhrp_url.as_deref()),
                num(granted.file_size),
                granted
                    .minutes
                    .map(wasm_bindgen::JsValue::from_f64)
                    .unwrap_or(wasm_bindgen::JsValue::NULL),
                num(granted.expiry_time),
            ])
            .map_err(|e| e.to_string())?
            .run()
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn a_record_reads_in_the_three_shapes() {
        assert_eq!(Record::parse("1"), Record::Unbound);
        assert_eq!(Record::parse("ab"), Record::Bound("ab".into()));
        assert_eq!(Record::parse("released:ab"), Record::Released("ab".into()));
    }

    #[test]
    fn the_record_lives_under_the_key_value_store_s_key() {
        assert_eq!(
            KvRecords::key("p"),
            "auth:nonce:payment-derivation-prefix:p"
        );
    }

    #[test]
    fn the_migration_creates_the_middleware_s_table_and_the_grants() {
        let migration = include_str!("../migrations/0001_payment_claims.sql");
        let statements: Vec<String> = migration
            .lines()
            .filter(|l| !l.starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n")
            .split(';')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(
            statements,
            vec![
                bsv_middleware_cloudflare::payment_claims::PAYMENT_CLAIMS_SCHEMA.to_string(),
                GRANTS_SCHEMA.to_string(),
            ]
        );
    }

    #[test]
    fn the_gate_is_read_as_the_claim_it_answers() {
        use bsv_middleware_cloudflare::payment_claims::PrefixGate;
        assert_eq!(
            read_gate(PrefixGate::Proceed).unwrap().claim,
            PrefixClaim::Won
        );
        for (status, claim) in [
            (409, PrefixClaim::SameTransaction),
            (400, PrefixClaim::OtherTransaction),
        ] {
            let got = read_gate(PrefixGate::Refuse {
                status,
                body: serde_json::json!({}),
                headers: vec![],
            })
            .unwrap();
            assert_eq!(got.claim, claim);
            assert_eq!(got.refusal.unwrap().status, status);
        }
        let unavailable = read_gate(PrefixGate::Refuse {
            status: 503,
            body: serde_json::json!({ "code": "ERR_PAYMENT_UNAVAILABLE" }),
            headers: vec![("Retry-After".into(), "5".into())],
        })
        .unwrap_err();
        let refusal = unavailable.refusal.unwrap();
        assert_eq!(refusal.status, 503);
        assert_eq!(refusal.headers, vec![("Retry-After".into(), "5".into())]);
        let fault = read_gate(PrefixGate::Fault { detail: "d".into() }).unwrap_err();
        assert_eq!(fault.refusal, None);
    }

    #[test]
    fn the_record_is_written_over_nothing_its_own_release_or_itself_only() {
        let at = |value: &str, marked: bool| Stored {
            value: value.into(),
            marked,
        };
        assert_eq!(Recording::judge(None, "a"), Recording::Write);
        assert_eq!(
            Recording::judge(Some(&at("released:a", false)), "a"),
            Recording::Write
        );
        assert_eq!(
            Recording::judge(Some(&at("a", true)), "a"),
            Recording::Write
        );
        for found in [
            at("a", false),
            at("b", true),
            at("released:b", false),
            at("1", false),
        ] {
            assert_eq!(Recording::judge(Some(&found), "a"), Recording::Refused);
        }
        assert!(releases(Some(&at("a", true)), "a"));
        for found in [at("a", false), at("b", true), at("released:a", false)] {
            assert!(!releases(Some(&found), "a"));
        }
        assert!(!releases(None, "a"));
    }
}
