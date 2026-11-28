//! What a paid `/renew`'s renewing step came to, and the duties that follow
//! it: the record in the `CLAIMS` database's `renewals` table
//! (`migrations/0002_renewals.sql`), the overlay's admission of the renewed
//! advert, and the hourly pass ([`crate::pass`]) over the rows that wait.
//!
//! # The three outcomes of the renewing step
//!
//! The renewing transaction is made (`createAction`), signed, and handed to
//! the wallet storage server with `processAction` (`isNoSend: false`,
//! `isDelayed: false`: the wallet sends it now). What the wallet says of
//! that transaction decides the outcome ([`read_process_answer`],
//! [`read_req_status`]):
//!
//! - **taken** ([`Outcome::Taken`]): the wallet's word for this txid is that
//!   a broadcaster took it. The renewal is served: the signed 200, the
//!   grant `granted`.
//! - **not made** ([`Outcome::NotMade`]): the wallet refused the call with
//!   an answer, or its word for this txid is that the transaction failed.
//!   The grant stays `paid`.
//! - **no word** ([`Outcome::NoWord`]): no answer was read, the wallet holds
//!   the transaction to be sent later, its answer names no result for this
//!   txid, or names one this module does not place. The grant stays `paid`
//!   and the pass asks the wallet again, once an hour.
//!
//! wallet-infra's `processAction` answers a transaction it sends now with
//! `sendWithResults: [{txid, status: "sending"}]` whether or not the
//! broadcaster took it (the broadcaster's answer is written to the wallet's
//! own `proven_tx_reqs` row: `unmined` when it was taken). So a `sending`
//! word is followed by one read of that row (`findProvenTxReqs`), and the
//! row's status is the word.
//!
//! # The overlay's admission, after the take
//!
//! Once the renewing transaction is taken the renewal is served, whatever
//! the overlay answers. The renewed advert is then submitted to the overlay
//! ([`Admission`]): admitted; refused with an answer (the row is marked
//! `refused` with the overlay's reason, listed for an operator, and never
//! submitted again by the Worker); or a fault (no answer, a 5xx, the
//! deadline), which puts one message on the Worker's queue: the consumer
//! submits it again, at most [`QUEUE_DELIVERIES`] deliveries in all, and
//! when those are spent the row stays `not_admitted` for the pass.
//!
//! # The pass
//!
//! Once an hour, at most [`PASS_ROWS`] rows, oldest first, each touched once
//! ([`WAITING_SQL`]): a row `not_admitted` gets one submit of its advert; a
//! `paid` grant whose outcome is no word gets one question to the wallet for
//! its renewing txid. A fault, or no word, adds one to the row's `runs`; at
//! [`PASS_RUNS`] (three days of runs) the row is `stopped`, listed, and left
//! until an operator resets it (DEPLOYMENT.md).

use serde_json::{json, Value};

use crate::wallet::client::RpcFailure;
use crate::wallet::types::{ProcessActionResult, ProvenTxReqRow};

/// The most rows the pass touches in one run.
pub const PASS_ROWS: u32 = 20;

/// The runs after which a waiting row is `stopped`: 72 hourly runs, three
/// days.
pub const PASS_RUNS: i64 = 72;

/// The deliveries of one re-submit message: the queue consumer's
/// `max_retries = 3` (wrangler.toml) and the first delivery.
pub const QUEUE_DELIVERIES: i64 = 4;

/// How long a row whose re-submit is on the queue is left to the queue
/// before the pass takes it (seconds). The queue's four deliveries end well
/// inside it.
pub const QUEUE_WINDOW_SECONDS: i64 = 3600;

/// The longest overlay reason a row keeps, in characters.
pub const REASON_MAX_CHARS: usize = 200;

/// The JSON-RPC codes of a wallet-infra refusal of the call itself, made
/// before anything is sent: `-32602` (a validation error) and `-32001` (not
/// found) (wallet-infra v0.7.8 `src/door/errors.rs:19-28`). An internal
/// fault (`-32603`) can follow a broadcast in `processAction`, so it is no
/// word.
pub const REFUSAL_CODES: [i32; 2] = [-32602, -32001];

// ── the wallet's words ───────────────────────────────────────────────────

/// What the renewing step came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A broadcaster took the renewing transaction: served.
    Taken,
    /// The renewal was not made.
    NotMade,
    /// No word yet that the renewing transaction was sent.
    NoWord,
}

impl Outcome {
    /// The `renewals.outcome` column's word.
    #[must_use]
    pub const fn column(self) -> &'static str {
        match self {
            Self::Taken => "served",
            Self::NotMade => "not_made",
            Self::NoWord => "no_word",
        }
    }
}

/// What `processAction`'s answer says of the renewing transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessWord {
    /// The outcome is decided by the answer.
    Decided(Outcome),
    /// The call was refused with an answer: nothing was sent, and the
    /// action is still the wallet's to release.
    Refused,
    /// `sending`: the wallet sent it, and the broadcaster's answer is in its
    /// `proven_tx_reqs` row ([`read_req_status`]).
    Sending,
}

/// Read `processAction`'s answer for `txid`.
///
/// - an error object with a code in [`REFUSAL_CODES`]: [`ProcessWord::Refused`];
///   any other failure: no word;
/// - `notDelayedResults` (the reference wallet's broadcast review) naming
///   `txid`: `success` taken; `doubleSpend`, `invalidTx` not made; any other
///   word (`serviceError`) no word;
/// - `sendWithResults` naming `txid`: `unproven` taken; `failed` not made;
///   `sending` [`ProcessWord::Sending`]; any other word no word;
/// - neither naming `txid`: no word.
#[must_use]
pub fn read_process_answer(
    answer: &Result<ProcessActionResult, RpcFailure>,
    txid: &str,
) -> ProcessWord {
    let result = match answer {
        Ok(result) => result,
        Err(RpcFailure::Refused {
            code: Some(code), ..
        }) if REFUSAL_CODES.contains(code) => return ProcessWord::Refused,
        Err(_) => return ProcessWord::Decided(Outcome::NoWord),
    };
    if let Some(word) = word_for(result.not_delayed_results.as_ref(), txid) {
        return ProcessWord::Decided(match word.as_str() {
            "success" => Outcome::Taken,
            "doubleSpend" | "invalidTx" => Outcome::NotMade,
            _ => Outcome::NoWord,
        });
    }
    match word_for(result.send_with_results.as_ref(), txid).as_deref() {
        Some("unproven") => ProcessWord::Decided(Outcome::Taken),
        Some("failed") => ProcessWord::Decided(Outcome::NotMade),
        Some("sending") => ProcessWord::Sending,
        _ => ProcessWord::Decided(Outcome::NoWord),
    }
}

/// The `status` of the entry for `txid` in a list of `{txid, status}`.
fn word_for(results: Option<&Value>, txid: &str) -> Option<String> {
    results?
        .as_array()?
        .iter()
        .find(|r| r["txid"].as_str() == Some(txid))?["status"]
        .as_str()
        .map(str::to_string)
}

/// Read the wallet's `proven_tx_reqs` row for `txid` (`findProvenTxReqs`):
/// `unmined` (a broadcaster took it) and `completed` (proven) taken;
/// `doubleSpend` and `invalid` not made; any other status (`unsent`,
/// `sending`, `unprocessed`, …) or no row for `txid`: no word.
#[must_use]
pub fn read_req_status(rows: &[ProvenTxReqRow], txid: &str) -> Outcome {
    match rows
        .iter()
        .find(|r| r.txid == txid)
        .map(|r| r.status.as_str())
    {
        Some("unmined" | "completed") => Outcome::Taken,
        Some("doubleSpend" | "invalid") => Outcome::NotMade,
        _ => Outcome::NoWord,
    }
}

/// Whether a `createAction` refusal is the kind a spent advert gives: the
/// wallet's answer that the explicit input is unavailable (wallet-infra
/// v0.7.8 `src/storage/create_action.rs:309-312`: `createAction: explicit
/// input <txid>.<vout> is unavailable (...)`, code -32602). An outage has
/// no such answer.
#[must_use]
pub fn spent_advert(failure: &RpcFailure) -> bool {
    matches!(
        failure,
        RpcFailure::Refused { code: Some(-32602), message }
            if message.contains("explicit input") && message.contains("is unavailable")
    )
}

// ── the answers ──────────────────────────────────────────────────────────

/// The code of the answer when the renewal was not made.
pub const ERR_RENEWAL_NOT_MADE: &str = "ERR_RENEWAL_NOT_MADE";
/// The code of the answer when there is no word yet.
pub const ERR_RENEWAL_UNCONFIRMED: &str = "ERR_RENEWAL_UNCONFIRMED";
/// The status of the answer when the renewal was not made.
pub const NOT_MADE_STATUS: u16 = 500;
/// The status of the answer when there is no word yet.
pub const NO_WORD_STATUS: u16 = 502;

/// The answer when the renewal was not made. `payment_txid` is the taken
/// payment's transaction, under which the row is recorded; `None` when no
/// payment was taken.
#[must_use]
pub fn not_made_answer(payment_txid: Option<&str>) -> (Value, u16) {
    let description = match payment_txid {
        Some(txid) => format!(
            "The payment was taken. The renewal was not made. It is recorded under {txid}. A new payment renews the file."
        ),
        None => "The renewal was not made.".to_string(),
    };
    (
        answer_body(ERR_RENEWAL_NOT_MADE, &description, payment_txid),
        NOT_MADE_STATUS,
    )
}

/// The answer when this host has no word yet that the renewing transaction
/// was sent.
#[must_use]
pub fn no_word_answer(payment_txid: Option<&str>) -> (Value, u16) {
    let description = match payment_txid {
        Some(txid) => format!(
            "The payment was taken. This host has no word yet that the renewing transaction was sent. It is recorded under {txid}."
        ),
        None => "This host has no word yet that the renewing transaction was sent.".to_string(),
    };
    (
        answer_body(ERR_RENEWAL_UNCONFIRMED, &description, payment_txid),
        NO_WORD_STATUS,
    )
}

fn answer_body(code: &str, description: &str, payment_txid: Option<&str>) -> Value {
    let mut body = json!({
        "status": "error",
        "code": code,
        "description": description,
    });
    if let Some(txid) = payment_txid {
        body["paymentTxid"] = json!(txid);
    }
    body
}

// ── the overlay's admission ──────────────────────────────────────────────

/// The overlay's answer to one submit of an advert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// It admitted the advert.
    Admitted,
    /// It answered that it does not admit it, with its reason.
    Refused(String),
    /// No answer, a 5xx, or the deadline.
    Fault(String),
}

/// `s`, at most [`REASON_MAX_CHARS`] characters.
#[must_use]
pub fn reason(s: &str) -> String {
    s.chars().take(REASON_MAX_CHARS).collect()
}

// ── the record ───────────────────────────────────────────────────────────

/// The `renewals` table, as `migrations/0002_renewals.sql` creates it (the
/// migration's test reads it).
#[allow(dead_code)]
pub const RENEWALS_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS renewals (\
    prefix TEXT PRIMARY KEY, payment_txid TEXT NOT NULL, renewing_txid TEXT, \
    outcome TEXT NOT NULL, advert TEXT, runs INTEGER NOT NULL DEFAULT 0, reason TEXT, \
    new_expiry_time INTEGER, advert_beef TEXT, queued_until INTEGER, \
    queue_tries INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, \
    updated_at INTEGER NOT NULL\
)";

/// The index the pass reads its rows in.
#[allow(dead_code)]
pub const RENEWALS_INDEX: &str =
    "CREATE INDEX IF NOT EXISTS renewals_by_age ON renewals (created_at, prefix)";

/// A renewal's row, written once after the route answered.
pub const RECORD_SQL: &str = "INSERT INTO renewals \
    (prefix, payment_txid, renewing_txid, outcome, advert, reason, new_expiry_time, \
    advert_beef, queued_until, runs, queue_tries, created_at, updated_at) \
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, 0, unixepoch(), unixepoch()) \
    ON CONFLICT(prefix) DO NOTHING";

/// A row whose re-submit could not be put on the queue: the pass takes it.
pub const UNQUEUED_SQL: &str = "UPDATE renewals SET queued_until = NULL, \
    updated_at = unixepoch() WHERE prefix = ?1 AND advert = 'not_admitted'";

/// One delivery of a row's re-submit: its count, and its advert's bytes.
pub const QUEUE_TRY_SQL: &str = "UPDATE renewals SET queue_tries = queue_tries + 1, \
    updated_at = unixepoch() WHERE prefix = ?1 AND advert = 'not_admitted' \
    AND queued_until IS NOT NULL RETURNING queue_tries, advert_beef";

/// The overlay admitted or refused a `not_admitted` row's advert.
pub const ADMISSION_SQL: &str = "UPDATE renewals SET advert = ?2, reason = ?3, \
    queued_until = NULL, updated_at = unixepoch() WHERE prefix = ?1 \
    AND advert = 'not_admitted'";

/// The rows the pass touches in a run (`?1` is now, in seconds): oldest
/// first, at most [`PASS_ROWS`].
pub const WAITING_SQL: &str = "SELECT r.prefix, r.renewing_txid, r.outcome, r.advert, \
    r.runs, r.new_expiry_time FROM renewals r \
    LEFT JOIN payment_grants g ON g.prefix = r.prefix \
    WHERE (r.advert = 'not_admitted' AND (r.queued_until IS NULL OR r.queued_until <= ?1)) \
    OR (r.outcome = 'no_word' AND r.advert IS NULL AND g.state = 'paid') \
    ORDER BY r.created_at, r.prefix LIMIT 20";

/// A row's advert bytes (base64 of the Atomic BEEF).
pub const BEEF_SQL: &str = "SELECT advert_beef FROM renewals WHERE prefix = ?1";

/// A run's count of a row the pass could not move, and its stop.
pub const COUNTED_ADMIT_SQL: &str = "UPDATE renewals SET runs = ?2, advert = ?3, \
    reason = ?4, updated_at = unixepoch() WHERE prefix = ?1 AND advert = 'not_admitted'";
/// The same, for a row waiting on the wallet's word.
pub const COUNTED_WORD_SQL: &str = "UPDATE renewals SET runs = ?2, advert = ?3, \
    updated_at = unixepoch() WHERE prefix = ?1 AND outcome = 'no_word' AND advert IS NULL";

/// The wallet's word for a waiting row: a take (the advert's admission
/// with it) or not made.
pub const WORD_SQL: &str = "UPDATE renewals SET outcome = ?2, advert = ?3, reason = ?4, \
    queued_until = ?5, runs = 0, updated_at = unixepoch() WHERE prefix = ?1 \
    AND outcome = 'no_word' AND advert IS NULL";

/// A taken renewal's grant, once the pass has the word.
pub const GRANT_SERVED_SQL: &str = "UPDATE payment_grants SET state = 'granted', \
    status = 200, expiry_time = ?2, answered_at = unixepoch() WHERE prefix = ?1 \
    AND state = 'paid'";

/// The `advert` column for an admission, its reason, and whether the
/// re-submit goes on the queue.
#[must_use]
pub fn advert_column(admission: &Admission) -> (&'static str, Option<String>, bool) {
    match admission {
        Admission::Admitted => ("admitted", None, false),
        Admission::Refused(why) => ("refused", Some(reason(why)), false),
        Admission::Fault(why) => ("not_admitted", Some(reason(why)), true),
    }
}

// ── the pass ─────────────────────────────────────────────────────────────

/// What one touch of a row by the pass, or one delivery by the queue,
/// writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// The overlay admitted the advert.
    Admitted,
    /// The overlay refused the advert: never submitted again.
    Refused(String),
    /// One more run with nothing moved.
    Counted(i64),
    /// The runs are spent: listed and left until an operator resets it.
    Stopped(i64),
    /// The wallet's word for a waiting row is a take.
    Served,
    /// The wallet's word for a waiting row is a failure.
    NotMade,
}

/// The pass's step for a `not_admitted` row whose advert the overlay
/// answered with `admission`, after `runs` runs.
#[must_use]
pub fn after_submit(runs: i64, admission: &Admission) -> Step {
    match admission {
        Admission::Admitted => Step::Admitted,
        Admission::Refused(why) => Step::Refused(reason(why)),
        Admission::Fault(_) => counted(runs),
    }
}

/// The pass's step for a row waiting on the wallet's word, after `runs`
/// runs.
#[must_use]
pub fn after_word(runs: i64, word: Outcome) -> Step {
    match word {
        Outcome::Taken => Step::Served,
        Outcome::NotMade => Step::NotMade,
        Outcome::NoWord => counted(runs),
    }
}

fn counted(runs: i64) -> Step {
    let runs = runs.saturating_add(1);
    if runs >= PASS_RUNS {
        Step::Stopped(runs)
    } else {
        Step::Counted(runs)
    }
}

/// What the queue does with a re-submit's delivery number `tries` (1 for
/// the first) whose submit the overlay answered with `admission`: the step
/// written, and whether the message is delivered again.
#[must_use]
pub fn after_delivery(tries: i64, admission: &Admission) -> (Option<Step>, bool) {
    match admission {
        Admission::Admitted => (Some(Step::Admitted), false),
        Admission::Refused(why) => (Some(Step::Refused(reason(why))), false),
        Admission::Fault(_) if tries >= QUEUE_DELIVERIES => (None, false),
        Admission::Fault(_) => (None, true),
    }
}

/// The two kinds of row the pass touches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Waiting {
    /// A served renewal whose advert the overlay has not admitted.
    Admit,
    /// A `paid` grant whose renewing transaction has no word yet.
    Word,
}

/// The kind of a row [`WAITING_SQL`] returned.
#[must_use]
pub fn waiting(outcome: &str, advert: Option<&str>) -> Option<Waiting> {
    match (outcome, advert) {
        (_, Some("not_admitted")) => Some(Waiting::Admit),
        ("no_word", None) => Some(Waiting::Word),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn answer(send_with: Value, not_delayed: Option<Value>) -> ProcessActionResult {
        ProcessActionResult {
            send_with_results: Some(send_with),
            not_delayed_results: not_delayed,
            log: None,
        }
    }

    #[test]
    fn process_answer_words_one_by_one() {
        let t = "aa";
        let sw = |status: &str| answer(json!([{ "txid": t, "status": status }]), None);
        assert_eq!(
            read_process_answer(&Ok(sw("unproven")), t),
            ProcessWord::Decided(Outcome::Taken)
        );
        assert_eq!(
            read_process_answer(&Ok(sw("sending")), t),
            ProcessWord::Sending
        );
        assert_eq!(
            read_process_answer(&Ok(sw("failed")), t),
            ProcessWord::Decided(Outcome::NotMade)
        );
        for other in ["nosend", "unsent", "Sending", ""] {
            assert_eq!(
                read_process_answer(&Ok(sw(other)), t),
                ProcessWord::Decided(Outcome::NoWord),
                "{other}"
            );
        }
        // A result for another transaction only, or none at all.
        let elsewhere = answer(json!([{ "txid": "bb", "status": "unproven" }]), None);
        assert_eq!(
            read_process_answer(&Ok(elsewhere), t),
            ProcessWord::Decided(Outcome::NoWord)
        );
        let empty = ProcessActionResult {
            send_with_results: None,
            not_delayed_results: None,
            log: None,
        };
        assert_eq!(
            read_process_answer(&Ok(empty), t),
            ProcessWord::Decided(Outcome::NoWord)
        );
        // The reference wallet's broadcast review.
        let nd = |status: &str| {
            answer(
                json!([{ "txid": t, "status": "sending" }]),
                Some(json!([{ "txid": t, "status": status }])),
            )
        };
        assert_eq!(
            read_process_answer(&Ok(nd("success")), t),
            ProcessWord::Decided(Outcome::Taken)
        );
        for failed in ["doubleSpend", "invalidTx"] {
            assert_eq!(
                read_process_answer(&Ok(nd(failed)), t),
                ProcessWord::Decided(Outcome::NotMade)
            );
        }
        assert_eq!(
            read_process_answer(&Ok(nd("serviceError")), t),
            ProcessWord::Decided(Outcome::NoWord)
        );
    }

    #[test]
    fn a_refused_call_and_no_answer() {
        let t = "aa";
        for code in [-32602, -32001] {
            let refused = Err(RpcFailure::Refused {
                code: Some(code),
                message: "Cannot process transaction with status 'sending'".into(),
            });
            assert_eq!(read_process_answer(&refused, t), ProcessWord::Refused);
        }
        for none in [
            RpcFailure::Refused {
                code: Some(-32603),
                message: "An internal error has occurred.".into(),
            },
            RpcFailure::Refused {
                code: None,
                message: "x".into(),
            },
            RpcFailure::NoAnswer("Fetch error: timed out".into()),
        ] {
            assert_eq!(
                read_process_answer(&Err(none), t),
                ProcessWord::Decided(Outcome::NoWord)
            );
        }
    }

    #[test]
    fn req_status_words_one_by_one() {
        let row = |txid: &str, status: &str| ProvenTxReqRow {
            txid: txid.into(),
            status: status.into(),
        };
        for (status, outcome) in [
            ("unmined", Outcome::Taken),
            ("completed", Outcome::Taken),
            ("doubleSpend", Outcome::NotMade),
            ("invalid", Outcome::NotMade),
            ("unsent", Outcome::NoWord),
            ("sending", Outcome::NoWord),
            ("unprocessed", Outcome::NoWord),
            ("nosend", Outcome::NoWord),
            ("unknown", Outcome::NoWord),
            ("failed", Outcome::NoWord),
        ] {
            assert_eq!(
                read_req_status(&[row("aa", status)], "aa"),
                outcome,
                "{status}"
            );
        }
        assert_eq!(
            read_req_status(&[row("bb", "unmined")], "aa"),
            Outcome::NoWord
        );
        assert_eq!(read_req_status(&[], "aa"), Outcome::NoWord);
    }

    #[test]
    fn only_the_spent_advert_answer_is_the_retried_kind() {
        assert!(spent_advert(&RpcFailure::Refused {
            code: Some(-32602),
            message: "createAction: explicit input ab.0 is unavailable (already spent or locked by transaction_id 7)".into(),
        }));
        for other in [
            RpcFailure::Refused {
                code: Some(-32602),
                message: "Insufficient funds: need 1 sats".into(),
            },
            RpcFailure::Refused {
                code: Some(-32603),
                message: "An internal error has occurred.".into(),
            },
            RpcFailure::NoAnswer("Storage server returned 503: down".into()),
        ] {
            assert!(!spent_advert(&other), "{other:?}");
        }
    }

    #[test]
    fn the_answers_say_three_things() {
        let (body, status) = not_made_answer(Some("ab12"));
        assert_eq!(status, 500);
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"status":"error","code":"ERR_RENEWAL_NOT_MADE","description":"The payment was taken. The renewal was not made. It is recorded under ab12. A new payment renews the file.","paymentTxid":"ab12"}"#
        );
        let (body, status) = no_word_answer(Some("ab12"));
        assert_eq!(status, 502);
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"status":"error","code":"ERR_RENEWAL_UNCONFIRMED","description":"The payment was taken. This host has no word yet that the renewing transaction was sent. It is recorded under ab12.","paymentTxid":"ab12"}"#
        );
        for (body, _) in [not_made_answer(Some("ab12")), no_word_answer(Some("ab12"))] {
            let text = body["description"].as_str().unwrap().to_lowercase();
            assert!(!text.contains("retry") && !text.contains("re-quote"));
        }
        assert!(!no_word_answer(Some("ab12")).0["description"]
            .as_str()
            .unwrap()
            .contains("not made"));
        // No payment taken: neither says one was.
        for (body, _) in [not_made_answer(None), no_word_answer(None)] {
            assert!(!body["description"].as_str().unwrap().contains("payment"));
            assert!(body.get("paymentTxid").is_none());
        }
    }

    #[test]
    fn the_pass_counts_and_ends() {
        assert_eq!(after_submit(5, &Admission::Admitted), Step::Admitted);
        assert_eq!(
            after_submit(5, &Admission::Refused("no output admitted".into())),
            Step::Refused("no output admitted".into())
        );
        assert_eq!(
            after_submit(0, &Admission::Fault("503".into())),
            Step::Counted(1)
        );
        assert_eq!(
            after_submit(70, &Admission::Fault("503".into())),
            Step::Counted(71)
        );
        assert_eq!(
            after_submit(71, &Admission::Fault("503".into())),
            Step::Stopped(72)
        );
        assert_eq!(after_word(3, Outcome::Taken), Step::Served);
        assert_eq!(after_word(3, Outcome::NotMade), Step::NotMade);
        assert_eq!(after_word(0, Outcome::NoWord), Step::Counted(1));
        assert_eq!(after_word(71, Outcome::NoWord), Step::Stopped(72));
        // Every fault, from no runs, stops at the 72nd run and not before.
        let mut runs = 0;
        let mut stopped_at = None;
        for run in 1..=100 {
            match after_word(runs, Outcome::NoWord) {
                Step::Counted(n) => runs = n,
                Step::Stopped(n) => {
                    stopped_at = Some((run, n));
                    break;
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(stopped_at, Some((72, 72)));
        // A long reason is cut.
        let long = "x".repeat(500);
        assert_eq!(
            after_submit(0, &Admission::Refused(long)),
            Step::Refused("x".repeat(REASON_MAX_CHARS))
        );
    }

    #[test]
    fn the_queue_delivers_four_times_at_most() {
        let fault = Admission::Fault("503".into());
        assert_eq!(after_delivery(1, &fault), (None, true));
        assert_eq!(after_delivery(3, &fault), (None, true));
        assert_eq!(after_delivery(4, &fault), (None, false));
        assert_eq!(
            after_delivery(2, &Admission::Admitted),
            (Some(Step::Admitted), false)
        );
        assert_eq!(
            after_delivery(1, &Admission::Refused("r".into())),
            (Some(Step::Refused("r".into())), false)
        );
        let wrangler = include_str!("../wrangler.toml");
        let consumers = &wrangler[wrangler.find("[[queues.consumers]]").unwrap()..];
        assert!(consumers.contains("\nmax_retries = 3\n"));
        assert_eq!(QUEUE_DELIVERIES, 3 + 1);
    }

    #[test]
    fn the_pass_reads_twenty_rows_oldest_first_of_two_kinds() {
        assert_eq!(PASS_ROWS, 20);
        assert!(WAITING_SQL.ends_with("ORDER BY r.created_at, r.prefix LIMIT 20"));
        assert!(WAITING_SQL.contains("r.advert = 'not_admitted'"));
        assert!(
            WAITING_SQL.contains("r.outcome = 'no_word' AND r.advert IS NULL AND g.state = 'paid'")
        );
        assert_eq!(
            waiting("served", Some("not_admitted")),
            Some(Waiting::Admit)
        );
        assert_eq!(waiting("no_word", None), Some(Waiting::Word));
        for (outcome, advert) in [
            ("served", Some("admitted")),
            ("served", Some("refused")),
            ("served", Some("stopped")),
            ("no_word", Some("stopped")),
            ("not_made", None),
        ] {
            assert_eq!(waiting(outcome, advert), None, "{outcome} {advert:?}");
        }
        // Every statement that moves a row names the kind it moves.
        for sql in [
            COUNTED_ADMIT_SQL,
            ADMISSION_SQL,
            UNQUEUED_SQL,
            QUEUE_TRY_SQL,
        ] {
            assert!(sql.contains("advert = 'not_admitted'"), "{sql}");
        }
        for sql in [COUNTED_WORD_SQL, WORD_SQL] {
            assert!(
                sql.contains("outcome = 'no_word' AND advert IS NULL"),
                "{sql}"
            );
        }
        assert!(GRANT_SERVED_SQL.contains("AND state = 'paid'"));
    }

    #[test]
    fn the_migration_adds_the_renewals_table_and_its_index_only() {
        let migration = include_str!("../migrations/0002_renewals.sql");
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
            vec![RENEWALS_SCHEMA.to_string(), RENEWALS_INDEX.to_string()]
        );
    }

    #[test]
    fn the_columns_words() {
        assert_eq!(Outcome::Taken.column(), "served");
        assert_eq!(Outcome::NotMade.column(), "not_made");
        assert_eq!(Outcome::NoWord.column(), "no_word");
        assert_eq!(
            advert_column(&Admission::Admitted),
            ("admitted", None, false)
        );
        assert_eq!(
            advert_column(&Admission::Refused("r".into())),
            ("refused", Some("r".into()), false)
        );
        assert_eq!(
            advert_column(&Admission::Fault("f".into())),
            ("not_admitted", Some("f".into()), true)
        );
    }
}

/// The statements on SQLite (the engine D1 runs), with small figures.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod on_sqlite {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use rusqlite::{params, Connection};

    fn migrated() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(include_str!("../migrations/0001_payment_claims.sql"))
            .unwrap();
        db.execute_batch(include_str!("../migrations/0002_renewals.sql"))
            .unwrap();
        db
    }

    fn grant(db: &Connection, prefix: &str, state: &str) {
        db.execute(
            "INSERT INTO payment_grants (prefix, txid, route, identity_key, satoshis, paid_at, state) \
             VALUES (?1, 'pay', '/renew', 'k', 1000, 0, ?2)",
            params![prefix, state],
        )
        .unwrap();
    }

    fn row(
        db: &Connection,
        prefix: &str,
        outcome: &str,
        advert: Option<&str>,
        created_at: i64,
        queued_until: Option<i64>,
    ) {
        assert_eq!(
            db.execute(
                RECORD_SQL,
                params![
                    prefix,
                    "pay",
                    "renewing",
                    outcome,
                    advert,
                    None::<String>,
                    1_900_000_000i64,
                    "YmVlZg==",
                    queued_until
                ],
            )
            .unwrap(),
            1
        );
        db.execute(
            "UPDATE renewals SET created_at = ?2 WHERE prefix = ?1",
            params![prefix, created_at],
        )
        .unwrap();
    }

    fn waiting_now(db: &Connection, now: i64) -> Vec<String> {
        let mut statement = db.prepare(WAITING_SQL).unwrap();
        let rows = statement
            .query_map([now], |r| r.get::<_, String>(0))
            .unwrap();
        rows.map(Result::unwrap).collect()
    }

    fn column(db: &Connection, prefix: &str, name: &str) -> rusqlite::types::Value {
        db.query_row(
            &format!("SELECT {name} FROM renewals WHERE prefix = ?1"),
            [prefix],
            |r| r.get(0),
        )
        .unwrap()
    }

    fn text_value(s: &str) -> rusqlite::types::Value {
        rusqlite::types::Value::Text(s.to_string())
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_pass_reads_twenty_rows_of_its_two_kinds_oldest_first() {
        let db = migrated();
        // 25 adverts the overlay has not admitted, created at 1..=25.
        for i in 1..=25 {
            row(
                &db,
                &format!("a{i:02}"),
                "served",
                Some("not_admitted"),
                i,
                None,
            );
        }
        let got = waiting_now(&db, 1000);
        let expected: Vec<String> = (1..=20).map(|i| format!("a{i:02}")).collect();
        assert_eq!(got, expected);

        // Rows of no kind the pass touches.
        let db = migrated();
        row(&db, "admitted", "served", Some("admitted"), 1, None);
        row(&db, "refused", "served", Some("refused"), 2, None);
        row(&db, "stopped", "served", Some("stopped"), 3, None);
        row(&db, "not-made", "not_made", None, 4, None);
        row(&db, "word-stopped", "no_word", Some("stopped"), 5, None);
        grant(&db, "word-stopped", "paid");
        row(&db, "word-granted", "no_word", None, 6, None);
        grant(&db, "word-granted", "granted");
        row(&db, "word-no-grant", "no_word", None, 7, None);
        // On the queue for another hour.
        row(&db, "queued", "served", Some("not_admitted"), 8, Some(4600));
        assert_eq!(waiting_now(&db, 1000), Vec::<String>::new());
        // The two kinds, in age order; the queued row once its hour passed.
        row(&db, "word", "no_word", None, 10, None);
        grant(&db, "word", "paid");
        row(&db, "admit", "served", Some("not_admitted"), 9, None);
        assert_eq!(waiting_now(&db, 1000), strings(&["admit", "word"]));
        assert_eq!(
            waiting_now(&db, 4600),
            strings(&["queued", "admit", "word"])
        );
    }

    #[test]
    fn each_statement_moves_only_its_kind_and_each_ending_ends() {
        let db = migrated();
        row(&db, "admit", "served", Some("not_admitted"), 1, None);
        row(&db, "refused", "served", Some("refused"), 2, None);
        row(&db, "word", "no_word", None, 3, None);
        grant(&db, "word", "paid");
        let n = |sql: &str, p: &[&dyn rusqlite::ToSql]| db.execute(sql, p).unwrap();

        // A fault counts; the 72nd run stops it.
        assert_eq!(
            n(
                COUNTED_ADMIT_SQL,
                params!["admit", 71, "not_admitted", "HTTP 503"]
            ),
            1
        );
        assert_eq!(
            n(
                COUNTED_ADMIT_SQL,
                params!["admit", 72, "stopped", "HTTP 503"]
            ),
            1
        );
        assert_eq!(column(&db, "admit", "advert"), text_value("stopped"));
        assert_eq!(
            column(&db, "admit", "runs"),
            rusqlite::types::Value::Integer(72)
        );
        assert_eq!(waiting_now(&db, 10), strings(&["word"]));
        // A refused or stopped advert is never moved again.
        for prefix in ["refused", "admit"] {
            assert_eq!(
                n(COUNTED_ADMIT_SQL, params![prefix, 1, "not_admitted", "x"]),
                0
            );
            assert_eq!(
                n(ADMISSION_SQL, params![prefix, "admitted", None::<String>]),
                0
            );
            assert_eq!(n(UNQUEUED_SQL, params![prefix]), 0);
        }

        // The wallet's word: no word counts and stops at 72; a take serves.
        assert_eq!(n(COUNTED_WORD_SQL, params!["word", 5, None::<String>]), 1);
        assert_eq!(
            n(COUNTED_WORD_SQL, params!["refused", 5, None::<String>]),
            0
        );
        assert_eq!(
            n(
                WORD_SQL,
                params!["word", "served", "admitted", None::<String>, None::<i64>]
            ),
            1
        );
        assert_eq!(n(GRANT_SERVED_SQL, params!["word", 1_900_000_000i64]), 1);
        let (state, status, expiry): (String, i64, i64) = db
            .query_row(
                "SELECT state, status, expiry_time FROM payment_grants WHERE prefix = 'word'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            (state.as_str(), status, expiry),
            ("granted", 200, 1_900_000_000)
        );
        // Once served, neither the word nor the grant moves again.
        assert_eq!(
            n(
                WORD_SQL,
                params![
                    "word",
                    "not_made",
                    None::<String>,
                    None::<String>,
                    None::<i64>
                ]
            ),
            0
        );
        assert_eq!(n(GRANT_SERVED_SQL, params!["word", 1i64]), 0);
        assert_eq!(waiting_now(&db, 10), Vec::<String>::new());

        // A failure ends a waiting row as not made; its grant stays paid.
        row(&db, "failed", "no_word", None, 4, None);
        grant(&db, "failed", "paid");
        assert_eq!(
            n(
                WORD_SQL,
                params![
                    "failed",
                    "not_made",
                    None::<String>,
                    None::<String>,
                    None::<i64>
                ]
            ),
            1
        );
        let state: String = db
            .query_row(
                "SELECT state FROM payment_grants WHERE prefix = 'failed'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "paid");
        assert_eq!(waiting_now(&db, 10), Vec::<String>::new());
    }

    #[test]
    fn the_queue_counts_its_deliveries_and_hands_the_row_to_the_pass() {
        let db = migrated();
        row(&db, "q", "served", Some("not_admitted"), 1, Some(3601));
        let tries = |db: &Connection| -> Option<i64> {
            db.query_row(QUEUE_TRY_SQL, ["q"], |r| r.get(0)).ok()
        };
        for expected in 1..=4 {
            assert_eq!(tries(&db), Some(expected));
        }
        let beef: String = db.query_row(QUEUE_TRY_SQL, ["q"], |r| r.get(1)).unwrap();
        assert_eq!(beef, "YmVlZg==");
        // The tries spent: the pass takes it at once, the queue no more.
        assert_eq!(db.execute(UNQUEUED_SQL, ["q"]).unwrap(), 1);
        assert_eq!(tries(&db), None);
        assert_eq!(waiting_now(&db, 10), strings(&["q"]));
        // Admitted: neither the queue nor the pass touches it again.
        assert_eq!(
            db.execute(ADMISSION_SQL, params!["q", "admitted", None::<String>])
                .unwrap(),
            1
        );
        assert_eq!(waiting_now(&db, 10), Vec::<String>::new());
    }

    #[test]
    fn a_second_record_of_one_prefix_changes_nothing() {
        let db = migrated();
        row(&db, "p", "served", Some("admitted"), 1, None);
        assert_eq!(
            db.execute(
                RECORD_SQL,
                params![
                    "p",
                    "x",
                    "y",
                    "no_word",
                    None::<String>,
                    None::<String>,
                    1i64,
                    None::<String>,
                    None::<i64>
                ],
            )
            .unwrap(),
            0
        );
        assert_eq!(column(&db, "p", "outcome"), text_value("served"));
    }

    /// The statements 0.3.3 runs on `CLAIMS` (its `claims.rs` grants
    /// statements, which this build keeps byte for byte, and the
    /// middleware's `payment_claims` schema) on a database migrated to 0002,
    /// beside a row this build left `paid` with its `renewals` row.
    #[test]
    fn a_rollback_to_0_3_3_runs_on_the_migrated_database() {
        use crate::claims::{GRANTS_SCHEMA, GRANT_ANSWERED_SQL, GRANT_PAID_SQL, HOLDS_SQL};
        let db = migrated();
        grant(&db, "left-paid", "paid");
        row(&db, "left-paid", "no_word", None, 1, None);
        db.execute(
            bsv_middleware_cloudflare::payment_claims::PAYMENT_CLAIMS_SCHEMA,
            [],
        )
        .unwrap();
        db.execute(GRANTS_SCHEMA, []).unwrap();
        assert_eq!(
            db.execute(GRANT_PAID_SQL, params!["p2", "t2", "/renew", "k", 1000i64])
                .unwrap(),
            1
        );
        assert_eq!(
            db.execute(
                GRANT_ANSWERED_SQL,
                params![
                    "p2",
                    "granted",
                    200i64,
                    "o",
                    "u",
                    10i64,
                    30.0f64,
                    1_900_000_000i64
                ],
            )
            .unwrap(),
            1
        );
        // 0.3.3's second write names its own prefix: the row left `paid` is
        // untouched.
        let state: String = db
            .query_row(
                "SELECT state FROM payment_grants WHERE prefix = 'left-paid'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "paid");
        let held: Option<i64> = db.query_row(HOLDS_SQL, ["none"], |r| r.get(0)).ok();
        assert_eq!(held, None);
        // 0002 alters neither table 0.3.3 reads and writes.
        let migration: String = include_str!("../migrations/0002_renewals.sql")
            .lines()
            .filter(|l| !l.starts_with("--"))
            .collect();
        assert!(!migration.contains("payment_claims") && !migration.contains("payment_grants"));
        assert!(
            !migration.to_uppercase().contains("ALTER")
                && !migration.to_uppercase().contains("DROP")
        );
    }
}
