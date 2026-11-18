//! The paid routes' store (`src/claims.rs`, mounted as it is) on workerd's
//! D1 (`CLAIMS`) and KV (`AUTH_SESSIONS`), over HTTP for `../run.mjs`.
//! `BROKEN` is a D1 binding with no table: the fault switch hands the
//! Worker's store an environment whose `CLAIMS` is `BROKEN`, so a fault is a
//! real D1 error met by the store and the middleware's gate as they run.
//!
//! - `GET /kit?ns=&raised=` runs the middleware's conformance kit against
//!   the store as the Worker wires it, at the kit's defaults or at raised
//!   bounds (sizes 2 to 64, a hold of 128 passes).
//! - `GET /release-path?ns=` runs the release path's four mixes.
//! - `POST /claim?prefix=&txid=`, `POST /release?prefix=&txid=`: the store.
//! - `POST /kv-claim?prefix=&txid=`, `POST /kv-release?prefix=&txid=`: the
//!   key-value store's own claim and release (`KvPrefixStore`), the store a
//!   build that keeps its prefixes in the key-value namespace runs.
//! - `GET /state?prefix=`: the D1 row, the key-value record and whether it
//!   carries the store's mark.

use std::cell::Cell;

#[path = "../../../../src/claims.rs"]
#[allow(dead_code, unused_imports)]
mod claims;

use bsv_middleware_cloudflare::{KvPrefixStore, KvSessionStorage};
use bsv_middleware_core::store::conformance::{
    self, drive, schedules, txid_for, LegacySeeder, LocalFuture, Report, Schedule, Violation,
};
use bsv_middleware_core::{PaymentPrefixStore, PrefixClaim, StoreError};
use claims::{KvRecords, PaidStore, RECORD_MARK};
use serde_json::{json, Value};
use worker::js_sys::{Object, Reflect};
use worker::wasm_bindgen::JsCast;
use worker::{event, Context, Env, Request, Response, Result};

const TTL: u64 = 3600;

fn d1(e: impl std::fmt::Display) -> StoreError {
    StoreError::new(e.to_string())
}

fn store(env: &Env) -> Result<PaidStore<'_>> {
    claims::paid_store(env).map_err(|e| worker::Error::RustError(e.to_string()))
}

/// The Worker's environment with `BROKEN` bound as `CLAIMS`: the Worker's
/// store and the middleware's gate on it meet a real D1 fault.
fn broken(env: &Env) -> Result<Env> {
    let copy = Object::new();
    for (name, from) in [("AUTH_SESSIONS", "AUTH_SESSIONS"), ("CLAIMS", "BROKEN")] {
        let binding = Reflect::get(env, &from.into())?;
        Reflect::set(&copy, &name.into(), &binding)?;
    }
    Ok(copy.unchecked_into())
}

/// The Worker's store, or the same composition over `BROKEN` while on.
struct Switched<'a> {
    on: Cell<bool>,
    good: PaidStore<'a>,
    bad: PaidStore<'a>,
}

impl PaymentPrefixStore for Switched<'_> {
    async fn claim_prefix(
        &self,
        prefix: &str,
        txid: &str,
        agent: &str,
    ) -> std::result::Result<PrefixClaim, StoreError> {
        if self.on.get() {
            self.bad.claim_prefix(prefix, txid, agent).await
        } else {
            self.good.claim_prefix(prefix, txid, agent).await
        }
    }
    async fn release_prefix(
        &self,
        prefix: &str,
        txid: &str,
    ) -> std::result::Result<(), StoreError> {
        if self.on.get() {
            self.bad.release_prefix(prefix, txid).await
        } else {
            self.good.release_prefix(prefix, txid).await
        }
    }
}

fn report_json(answer: std::result::Result<Report, Violation>) -> Value {
    match answer {
        Ok(report) => json!({
            "pass": true,
            "checked": report.checked.iter().map(|(law, n)| json!([law, n])).collect::<Vec<_>>(),
            "skipped": report.skipped,
        }),
        Err(v) => json!({
            "pass": false,
            "law": v.law,
            "n": v.n,
            "schedule": v.schedule.map(|s| s.to_string()),
            "detail": v.detail,
        }),
    }
}

fn param(req: &Request, name: &str) -> Result<String> {
    req.url()?
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
        .ok_or_else(|| worker::Error::RustError(format!("missing ?{name}=")))
}

fn word(answer: std::result::Result<PrefixClaim, StoreError>) -> Value {
    match answer {
        Ok(c) => json!(format!("{c:?}")),
        Err(e) => json!(format!("fault: {e}")),
    }
}

// ── the release path ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Claim(PrefixClaim),
    Released,
    Fault,
}

fn claim_op<'a>(s: &'a PaidStore<'a>, prefix: &'a str, txid: &'a str) -> LocalFuture<'a, Op> {
    Box::pin(async move {
        match s.claim_prefix(prefix, txid, "kit").await {
            Ok(c) => Op::Claim(c),
            Err(_) => Op::Fault,
        }
    })
}

fn release_op<'a>(s: &'a PaidStore<'a>, prefix: &'a str, txid: &'a str) -> LocalFuture<'a, Op> {
    Box::pin(async move {
        match s.release_prefix(prefix, txid).await {
            Ok(()) => Op::Released,
            Err(_) => Op::Fault,
        }
    })
}

/// The D1 row's (txid, released), the key-value record and its mark.
async fn state(
    env: &Env,
    prefix: &str,
) -> Result<(Option<(Option<String>, bool)>, Option<String>, bool)> {
    let db = env.d1("CLAIMS")?;
    let row = db
        .prepare("SELECT txid, released FROM payment_claims WHERE nonce = ?1")
        .bind(&[prefix.into()])?
        .first::<Value>(None)
        .await?
        .map(|r| {
            (
                r["txid"].as_str().map(str::to_string),
                r["released"].as_f64() == Some(1.0),
            )
        });
    let (kv, metadata) = env
        .kv("AUTH_SESSIONS")?
        .get(&KvRecords::key(prefix))
        .text_with_metadata::<Value>()
        .await?;
    let (name, mark) = RECORD_MARK;
    let marked = metadata.is_some_and(|m| m[name] == mark);
    Ok((row, kv, marked))
}

/// The record names `bound`: held, or `released:<bound>` when D1 holds the
/// attempt released.
fn names(kv: Option<&str>, bound: Option<&str>, released: bool) -> bool {
    match (kv, bound) {
        (Some(kv), Some(bound)) => {
            kv == bound || (released && kv.strip_prefix("released:") == Some(bound))
        }
        _ => false,
    }
}

fn every_schedule(n: usize) -> Vec<Schedule> {
    schedules(n, conformance::RANDOM_SCHEDULES, conformance::DEFAULT_SEED)
}

async fn release_path(env: &Env, ns: &str) -> Result<Value> {
    let mut failures: Vec<String> = Vec::new();
    let mut runs = [0usize; 4];
    let s = store(env)?;
    let tx = |label: &str| txid_for(ns, label);

    // (a) A release of a prefix no claim holds, started with claims by
    // `n` different transactions: one transaction bound, the others refused.
    for n in [2usize, 3, 8] {
        for (k, schedule) in every_schedule(n + 1).into_iter().enumerate() {
            let prefix = format!("{ns}/a/{n}/{k}");
            let txids: Vec<String> = (0..n).map(|i| tx(&format!("{prefix}/{i}"))).collect();
            let mut ops = vec![release_op(&s, &prefix, &txids[0])];
            ops.extend(txids.iter().map(|t| claim_op(&s, &prefix, t)));
            let out = drive(ops, schedule).await;
            let winners: Vec<&String> = out[1..]
                .iter()
                .zip(&txids)
                .filter(|(o, _)| **o == Op::Claim(PrefixClaim::Won))
                .map(|(_, t)| t)
                .collect();
            let (row, kv, _) = state(env, &prefix).await?;
            let released = row.as_ref().is_some_and(|r| r.1);
            let bound = row.and_then(|r| r.0);
            if winners.len() != 1
                || out.contains(&Op::Fault)
                || bound.as_ref() != winners.first().copied()
                || !names(kv.as_deref(), bound.as_deref(), released)
            {
                failures.push(format!(
                    "(a) n={n} {schedule}: {out:?} bound={bound:?} kv={kv:?}"
                ));
                continue;
            }
            for t in &txids {
                let got = s.claim_prefix(&prefix, t, "kit").await;
                if Some(t) != bound.as_ref() && got != Ok(PrefixClaim::OtherTransaction) {
                    failures.push(format!("(a) n={n} {schedule}: after, {got:?}"));
                }
            }
            runs[0] += 1;
        }
    }

    // (b) Two releases with a re-take between them, then `n` re-takes.
    for n in [2usize, 4, 16] {
        for (k, schedule) in every_schedule(3).into_iter().enumerate() {
            let prefix = format!("{ns}/b/{n}/{k}");
            let a = tx(&prefix);
            if s.claim_prefix(&prefix, &a, "kit").await != Ok(PrefixClaim::Won) {
                failures.push(format!("(b) n={n}: the first claim"));
                continue;
            }
            let out = drive(
                vec![
                    release_op(&s, &prefix, &a),
                    claim_op(&s, &prefix, &a),
                    release_op(&s, &prefix, &a),
                ],
                schedule,
            )
            .await;
            let wins = out
                .iter()
                .filter(|o| **o == Op::Claim(PrefixClaim::Won))
                .count();
            let released = state(env, &prefix).await?.0.map(|r| r.1).unwrap_or(false);
            let retakes = drive(
                (0..n).map(|_| claim_op(&s, &prefix, &a)).collect(),
                Schedule::Lockstep,
            )
            .await;
            let rewins = retakes
                .iter()
                .filter(|o| **o == Op::Claim(PrefixClaim::Won))
                .count();
            let other = s
                .claim_prefix(&prefix, &tx(&format!("{prefix}/other")), "kit")
                .await;
            if wins > 1
                || out.contains(&Op::Fault)
                || rewins != usize::from(released)
                || other != Ok(PrefixClaim::OtherTransaction)
            {
                failures.push(format!("(b) n={n} {schedule}: {out:?} released={released} re-takes {retakes:?} other {other:?}"));
            }
            runs[1] += 1;
        }
    }

    // (c) A release of a prefix never claimed creates nothing.
    let prefix = format!("{ns}/c");
    s.release_prefix(&prefix, &tx(&prefix))
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;
    let (row, kv, _) = state(env, &prefix).await?;
    if row.is_some() || kv.is_some() {
        failures.push(format!("(c): row {row:?} kv {kv:?}"));
    }
    runs[2] += 1;

    // (d) A release racing the record's write after a win.
    for (k, schedule) in every_schedule(2).into_iter().enumerate() {
        let prefix = format!("{ns}/d/{k}");
        let a = tx(&prefix);
        let out = drive(
            vec![claim_op(&s, &prefix, &a), release_op(&s, &prefix, &a)],
            schedule,
        )
        .await;
        let (row, kv, _) = state(env, &prefix).await?;
        let (bound, released) = row.clone().unwrap_or((None, false));
        let again = s.claim_prefix(&prefix, &a, "kit").await;
        let expected = if released {
            PrefixClaim::Won
        } else {
            PrefixClaim::SameTransaction
        };
        let other = s
            .claim_prefix(&prefix, &tx(&format!("{prefix}/other")), "kit")
            .await;
        if out != [Op::Claim(PrefixClaim::Won), Op::Released]
            || bound.as_deref() != Some(a.as_str())
            || !names(kv.as_deref(), Some(a.as_str()), released)
            || again != Ok(expected)
            || other != Ok(PrefixClaim::OtherTransaction)
        {
            failures.push(format!(
                "(d) {schedule}: {out:?} row {row:?} kv {kv:?} again {again:?} other {other:?}"
            ));
        }
        runs[3] += 1;
    }
    Ok(json!({ "pass": failures.is_empty(), "runs": runs, "failures": failures }))
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let path = req.path();
    match path.as_str() {
        "/kit" => {
            let ns = param(&req, "ns")?;
            let raised = param(&req, "raised").map(|v| v == "1").unwrap_or(false);
            let broken_env = broken(&env)?;
            let prefixes = Switched {
                on: Cell::new(false),
                good: store(&env)?,
                bad: store(&broken_env)?,
            };
            let switch = |on: bool| prefixes.on.set(on);
            let kv = env.kv("AUTH_SESSIONS")?;
            let seed: &LegacySeeder<'_> = &|prefix: String| {
                let kv = &kv;
                Box::pin(async move {
                    kv.put(&KvRecords::key(&prefix), "1")
                        .map_err(d1)?
                        .execute()
                        .await
                        .map_err(d1)
                })
            };
            let sizes: Vec<usize> = (2..=64).collect();
            let mut kit = conformance::prefix_store(&prefixes, &ns)
                .fault(&switch)
                .legacy(seed);
            if raised {
                kit = kit.sizes(&sizes).held_passes(128);
            }
            Response::from_json(&json!({ "prefix": report_json(kit.run().await) }))
        }
        "/release-path" => Response::from_json(&release_path(&env, &param(&req, "ns")?).await?),
        "/claim" => {
            let (prefix, txid) = (param(&req, "prefix")?, param(&req, "txid")?);
            let s = store(&env)?;
            let answer = s.claim_prefix(&prefix, &txid, "kit").await;
            let refusal = s
                .take_refusal()
                .map(|r| json!({ "status": r.status, "body": r.body, "headers": r.headers }));
            Response::from_json(&json!({ "word": word(answer), "refusal": refusal }))
        }
        "/release" => {
            let (prefix, txid) = (param(&req, "prefix")?, param(&req, "txid")?);
            let answer = store(&env)?.release_prefix(&prefix, &txid).await;
            Response::from_json(&json!({ "ok": answer.is_ok() }))
        }
        "/kv-claim" => {
            let (prefix, txid) = (param(&req, "prefix")?, param(&req, "txid")?);
            let storage = KvSessionStorage::new(env.kv("AUTH_SESSIONS")?, "auth", TTL);
            let answer = KvPrefixStore(&storage)
                .claim_prefix(&prefix, &txid, "kv")
                .await;
            Response::from_json(&json!({ "word": word(answer) }))
        }
        "/kv-release" => {
            let (prefix, txid) = (param(&req, "prefix")?, param(&req, "txid")?);
            let storage = KvSessionStorage::new(env.kv("AUTH_SESSIONS")?, "auth", TTL);
            let answer = KvPrefixStore(&storage).release_prefix(&prefix, &txid).await;
            Response::from_json(&json!({ "ok": answer.is_ok() }))
        }
        "/kv-put" => {
            let (prefix, value) = (param(&req, "prefix")?, param(&req, "value")?);
            env.kv("AUTH_SESSIONS")?
                .put(&KvRecords::key(&prefix), value)?
                .execute()
                .await?;
            Response::from_json(&json!({ "ok": true }))
        }
        "/state" => {
            let (row, kv, marked) = state(&env, &param(&req, "prefix")?).await?;
            Response::from_json(&json!({
                "d1": row.map(|(txid, released)| json!({ "txid": txid, "released": released })),
                "kv": kv,
                "marked": marked,
            }))
        }
        _ => Response::error("not found", 404),
    }
}
