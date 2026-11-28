//! What a paid `/renew`'s renewing step came to, and the duties that follow
//! it: the record in the `CLAIMS` database's `renewals` table
//! (`migrations/0002_renewals.sql`), the overlay's admission of the renewed
//! advert, and the hourly pass ([`crate::pass`]) over the rows that wait.
//!
//! # The three outcomes of the renewing step
//!
//! The renewing transaction is made (`createAction`) and signed, and its row
//! is written ([`OPEN_SQL`]: the payment's txid, the renewing txid, the
//! advert's bytes, the outcome no word) before it is handed to the wallet
//! storage server with `processAction` (`isNoSend: false`, `isDelayed:
//! false`: the wallet sends it now). If that row cannot be written the
//! transaction is not handed over: the action is released and the renewal is
//! not made. So a request that ends at any later point leaves a row the pass
//! asks the wallet about.
//!
//! What the wallet says of the transaction decides the outcome
//! ([`read_process_answer`], [`read_record`], [`decide`]):
//!
//! - **taken** ([`Outcome::Taken`]): `processAction`'s answer names a take
//!   for this txid, or the wallet's record of the txid reads one. The
//!   renewal is served: the signed 200, the grant `granted`.
//! - **not made** ([`Outcome::NotMade`]): the wallet's record of the txid
//!   reads a failure, or `processAction` was refused with an error by name
//!   and the wallet holds no record of the txid. The grant stays `paid`.
//! - **no word** ([`Outcome::NoWord`]): anything else. The grant stays
//!   `paid` and the pass asks the wallet again, once an hour.
//!
//! After every answer of `processAction` that is not a take (an error, and
//! no answer, included) the route reads the wallet's record of the txid once
//! (`findProvenTxReqs`), and a record decides when there is one.
//! wallet-infra's `processAction` answers a transaction it sends now with
//! `sendWithResults: [{txid, status: "sending"}]` whether or not the
//! broadcaster took it; the broadcaster's answer is in the record (`unmined`
//! when it was taken).
//!
//! # The overlay's admission, after the take
//!
//! Once the renewing transaction is taken the renewal is served, whatever
//! the overlay answers. The renewed advert is then submitted to the overlay
//! and the answer read ([`Admission`], `crate::overlay::read_admission`):
//! admitted (the overlay's admission names this advert's output for the
//! topic); refused (the overlay answered the submit with a refusal in its
//! error shape: the row is marked `refused` with the overlay's reason,
//! listed for an operator, and never submitted again by the Worker); or a
//! fault (every other answer, and none), which puts one message on the
//! Worker's queue: the consumer submits it again, at most
//! [`QUEUE_DELIVERIES`] deliveries in all, and when those are spent the row
//! stays `not_admitted` for the pass. The row's `reason` keeps the last
//! answer that was not an admission, its kind first.
//!
//! # The pass
//!
//! Once an hour, at most [`PASS_ROWS`] rows, fewest runs first and then
//! oldest, each touched once ([`WAITING_SQL`]): a row `not_admitted` gets
//! one submit of its advert; a `paid` grant whose outcome is no word gets
//! one question to the wallet for its renewing txid; a served row whose
//! grant still reads `paid` has its grant set `granted`. A fault, or no
//! word, adds one to the row's `runs`; at [`PASS_RUNS`] (three days of
//! runs) the row is `stopped`, listed, and left until an operator resets it
//! (DEPLOYMENT.md).

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

/// The wait before the queue delivers a re-submit again, in seconds: four
/// deliveries span about a minute and a half.
pub const RESUBMIT_DELAY_SECONDS: u32 = 30;

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
    /// The answer names a take for this txid.
    Taken,
    /// The call was refused with an error by name (a code in
    /// [`REFUSAL_CODES`]).
    ErrorByName,
    /// Anything else: another word, no word for this txid, another error, no
    /// answer.
    Other,
}

/// Read `processAction`'s answer for `txid`: `sendWithResults` `unproven`
/// or `notDelayedResults` `success` for `txid` is [`ProcessWord::Taken`]; an
/// error object with a code in [`REFUSAL_CODES`] is
/// [`ProcessWord::ErrorByName`]; everything else is [`ProcessWord::Other`].
#[must_use]
pub fn read_process_answer(
    answer: &Result<ProcessActionResult, RpcFailure>,
    txid: &str,
) -> ProcessWord {
    let result = match answer {
        Ok(result) => result,
        Err(RpcFailure::Refused {
            code: Some(code), ..
        }) if REFUSAL_CODES.contains(code) => return ProcessWord::ErrorByName,
        Err(_) => return ProcessWord::Other,
    };
    let taken = word_for(result.not_delayed_results.as_ref(), txid).as_deref() == Some("success")
        || word_for(result.send_with_results.as_ref(), txid).as_deref() == Some("unproven");
    if taken {
        ProcessWord::Taken
    } else {
        ProcessWord::Other
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

/// The wallet's record of `txid` (`findProvenTxReqs`): the status of its
/// row, or `None` when the wallet holds no record of `txid`.
#[must_use]
pub fn read_record(rows: &[ProvenTxReqRow], txid: &str) -> Option<String> {
    rows.iter()
        .find(|r| r.txid == txid)
        .map(|r| r.status.clone())
}

/// The record's words that read a take: `unmined` (a broadcaster took it)
/// and `completed` (proven).
pub const RECORD_TAKEN: [&str; 2] = ["unmined", "completed"];

/// The record's words that read a failure.
pub const RECORD_FAILED: [&str; 4] = ["failed", "doubleSpend", "invalid", "invalidTx"];

/// The outcome of the renewing step from `processAction`'s answer and the
/// one read of the wallet's record (`Err(())` when the read itself failed;
/// `Ok(None)` when the wallet holds no record of the txid):
///
/// | the answer | the record | outcome |
/// |---|---|---|
/// | a take | not read | taken |
/// | any other | reads `unmined` or `completed` | taken |
/// | any other | reads `failed`, `doubleSpend`, `invalid` or `invalidTx` | not made |
/// | any other | reads another word | no word |
/// | an error by name | none for the txid | not made |
/// | anything else | none for the txid | no word |
/// | any other | the read failed | no word |
///
/// The wallet's refusal of a transaction it has already processed
/// ("Cannot process transaction with status …") is an error by name, so
/// its record decides it.
#[must_use]
pub fn decide(word: ProcessWord, record: &Result<Option<String>, ()>) -> Outcome {
    if word == ProcessWord::Taken {
        return Outcome::Taken;
    }
    match record {
        Ok(Some(status)) if RECORD_TAKEN.contains(&status.as_str()) => Outcome::Taken,
        Ok(Some(status)) if RECORD_FAILED.contains(&status.as_str()) => Outcome::NotMade,
        Ok(Some(_)) | Err(()) => Outcome::NoWord,
        Ok(None) if word == ProcessWord::ErrorByName => Outcome::NotMade,
        Ok(None) => Outcome::NoWord,
    }
}

/// Whether the route releases the action: only when the renewal is not made
/// because `processAction` was refused by name and the wallet holds no
/// record of the txid (nothing was processed).
#[must_use]
pub fn release_after(word: ProcessWord, record: &Result<Option<String>, ()>) -> bool {
    word == ProcessWord::ErrorByName && matches!(record, Ok(None))
}

/// The pass's reading of the wallet's record for `txid`: [`decide`] with no
/// answer of `processAction` in hand.
#[must_use]
pub fn read_req_status(rows: &[ProvenTxReqRow], txid: &str) -> Outcome {
    decide(ProcessWord::Other, &Ok(read_record(rows, txid)))
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
    /// Its admission names this advert's output for the topic.
    Admitted,
    /// It answered the submit with a refusal in its error shape, with its
    /// reason.
    Refused(String),
    /// Every other answer, and none; the text names its kind first.
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

/// A renewal's row, opened before the renewing transaction is handed to the
/// wallet (`?1` prefix, `?2` the payment's txid, `?3` the renewing txid,
/// `?4` the expiry it carries, `?5` its advert's bytes): the outcome no word.
/// It returns the prefix when the row was written, and nothing when a row of
/// the prefix stands.
pub const OPEN_SQL: &str = "INSERT INTO renewals \
    (prefix, payment_txid, renewing_txid, outcome, advert, reason, new_expiry_time, \
    advert_beef, queued_until, runs, queue_tries, created_at, updated_at) \
    VALUES (?1, ?2, ?3, 'no_word', NULL, NULL, ?4, ?5, NULL, 0, 0, unixepoch(), unixepoch()) \
    ON CONFLICT(prefix) DO NOTHING RETURNING prefix";

/// A renewal's row once the route has its outcome: written when none was
/// opened (a renewal not made before its transaction was handed over), and
/// otherwise the opened row settled, while it still reads no word (the pass
/// may have moved it first; then it is left as the pass wrote it).
pub const RECORD_SQL: &str = "INSERT INTO renewals \
    (prefix, payment_txid, renewing_txid, outcome, advert, reason, new_expiry_time, \
    advert_beef, queued_until, runs, queue_tries, created_at, updated_at) \
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, 0, unixepoch(), unixepoch()) \
    ON CONFLICT(prefix) DO UPDATE SET outcome = excluded.outcome, \
    advert = excluded.advert, reason = excluded.reason, \
    renewing_txid = COALESCE(excluded.renewing_txid, renewals.renewing_txid), \
    new_expiry_time = COALESCE(excluded.new_expiry_time, renewals.new_expiry_time), \
    advert_beef = COALESCE(excluded.advert_beef, renewals.advert_beef), \
    queued_until = excluded.queued_until, updated_at = unixepoch() \
    WHERE renewals.outcome = 'no_word' AND renewals.advert IS NULL";

/// A row whose re-submit could not be put on the queue: the pass takes it.
pub const UNQUEUED_SQL: &str = "UPDATE renewals SET queued_until = NULL, \
    updated_at = unixepoch() WHERE prefix = ?1 AND advert = 'not_admitted'";

/// One delivery of a row's re-submit: its count, and its advert's bytes.
pub const QUEUE_TRY_SQL: &str = "UPDATE renewals SET queue_tries = queue_tries + 1, \
    updated_at = unixepoch() WHERE prefix = ?1 AND advert = 'not_admitted' \
    AND queued_until IS NOT NULL RETURNING queue_tries, advert_beef";

/// The last answer of the overlay that was not an admission, on a
/// `not_admitted` row (`?2`, its kind first).
pub const FAULT_SQL: &str = "UPDATE renewals SET reason = ?2, updated_at = unixepoch() \
    WHERE prefix = ?1 AND advert = 'not_admitted'";

/// The overlay admitted or refused a `not_admitted` row's advert.
pub const ADMISSION_SQL: &str = "UPDATE renewals SET advert = ?2, reason = ?3, \
    queued_until = NULL, updated_at = unixepoch() WHERE prefix = ?1 \
    AND advert = 'not_admitted'";

/// The rows the pass touches in a run (`?1` is now, in seconds): fewest
/// runs first, then oldest, at most [`PASS_ROWS`]. Three kinds: an advert
/// the overlay has not admitted (off the queue); a `paid` grant whose
/// renewing transaction has no word; a served row whose grant still reads
/// `paid`.
pub const WAITING_SQL: &str = "SELECT r.prefix, r.renewing_txid, r.outcome, r.advert, \
    r.runs, r.new_expiry_time, r.queued_until, g.state AS grant_state FROM renewals r \
    LEFT JOIN payment_grants g ON g.prefix = r.prefix \
    WHERE (r.advert = 'not_admitted' AND (r.queued_until IS NULL OR r.queued_until <= ?1)) \
    OR (r.outcome = 'no_word' AND r.advert IS NULL AND g.state = 'paid') \
    OR (r.outcome = 'served' AND g.state = 'paid') \
    ORDER BY r.runs, r.created_at, r.prefix LIMIT 20";

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

/// A taken renewal's grant, once the pass has the word, or when its row
/// reads served and the grant's second write did not land.
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

/// The kinds of row the pass touches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Waiting {
    /// A served renewal whose grant still reads `paid`: set `granted`.
    Grant,
    /// A served renewal whose advert the overlay has not admitted.
    Admit,
    /// A `paid` grant whose renewing transaction has no word yet.
    Word,
}

/// What the pass does with a row [`WAITING_SQL`] returned, in order:
/// `queued` is whether its re-submit is still the queue's (`queued_until`
/// after now).
#[must_use]
pub fn waiting(
    outcome: &str,
    advert: Option<&str>,
    grant_state: Option<&str>,
    queued: bool,
) -> Vec<Waiting> {
    let mut kinds = Vec::new();
    if outcome == "served" && grant_state == Some("paid") {
        kinds.push(Waiting::Grant);
    }
    if advert == Some("not_admitted") && !queued {
        kinds.push(Waiting::Admit);
    }
    if outcome == "no_word" && advert.is_none() && grant_state == Some("paid") {
        kinds.push(Waiting::Word);
    }
    kinds
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
            ProcessWord::Taken
        );
        for other in ["sending", "failed", "nosend", "unsent", "Unproven", ""] {
            assert_eq!(
                read_process_answer(&Ok(sw(other)), t),
                ProcessWord::Other,
                "{other}"
            );
        }
        // A result for another transaction only, or none at all.
        let elsewhere = answer(json!([{ "txid": "bb", "status": "unproven" }]), None);
        assert_eq!(read_process_answer(&Ok(elsewhere), t), ProcessWord::Other);
        let empty = ProcessActionResult {
            send_with_results: None,
            not_delayed_results: None,
            log: None,
        };
        assert_eq!(read_process_answer(&Ok(empty), t), ProcessWord::Other);
        // The reference wallet's broadcast review.
        let nd = |status: &str| {
            answer(
                json!([{ "txid": t, "status": "sending" }]),
                Some(json!([{ "txid": t, "status": status }])),
            )
        };
        assert_eq!(
            read_process_answer(&Ok(nd("success")), t),
            ProcessWord::Taken
        );
        for other in ["doubleSpend", "invalidTx", "serviceError"] {
            assert_eq!(
                read_process_answer(&Ok(nd(other)), t),
                ProcessWord::Other,
                "{other}"
            );
        }
    }

    #[test]
    fn an_error_by_name_and_no_answer() {
        let t = "aa";
        for (code, message) in [
            (-32602, "Cannot process transaction with status 'unmined'"),
            (
                -32602,
                "processAction: the transaction does not match its action",
            ),
            (-32001, "not found"),
        ] {
            let refused = Err(RpcFailure::Refused {
                code: Some(code),
                message: message.into(),
            });
            assert_eq!(read_process_answer(&refused, t), ProcessWord::ErrorByName);
        }
        for other in [
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
            assert_eq!(read_process_answer(&Err(other), t), ProcessWord::Other);
        }
    }

    /// Every row of [`decide`]'s table, and the release that goes with it.
    #[test]
    fn the_decision_table_word_by_word() {
        let rec = |s: &str| -> Result<Option<String>, ()> { Ok(Some(s.to_string())) };
        let none: Result<Option<String>, ()> = Ok(None);
        let unread: Result<Option<String>, ()> = Err(());
        // A take in the answer serves, whatever the record.
        for record in [rec("invalid"), none.clone(), unread.clone()] {
            assert_eq!(decide(ProcessWord::Taken, &record), Outcome::Taken);
            assert!(!release_after(ProcessWord::Taken, &record));
        }
        for word in [ProcessWord::ErrorByName, ProcessWord::Other] {
            // The record decides when there is one.
            for taken in ["unmined", "completed"] {
                assert_eq!(
                    decide(word, &rec(taken)),
                    Outcome::Taken,
                    "{word:?} {taken}"
                );
                assert!(!release_after(word, &rec(taken)));
            }
            for failed in ["failed", "doubleSpend", "invalid", "invalidTx"] {
                assert_eq!(
                    decide(word, &rec(failed)),
                    Outcome::NotMade,
                    "{word:?} {failed}"
                );
                assert!(!release_after(word, &rec(failed)));
            }
            for other in [
                "unsent",
                "sending",
                "unprocessed",
                "nosend",
                "unknown",
                "unfail",
                "callback",
                "unconfirmed",
                "nonfinal",
                "Unmined",
                "",
            ] {
                assert_eq!(
                    decide(word, &rec(other)),
                    Outcome::NoWord,
                    "{word:?} {other}"
                );
                assert!(!release_after(word, &rec(other)));
            }
            // The read failed: no word, never a release.
            assert_eq!(decide(word, &unread), Outcome::NoWord);
            assert!(!release_after(word, &unread));
        }
        // No record: an error by name is not made (and released); anything
        // else is no word.
        assert_eq!(decide(ProcessWord::ErrorByName, &none), Outcome::NotMade);
        assert!(release_after(ProcessWord::ErrorByName, &none));
        assert_eq!(decide(ProcessWord::Other, &none), Outcome::NoWord);
        assert!(!release_after(ProcessWord::Other, &none));
        // The wallet's refusal of a transaction it has already processed is
        // never not made by itself: its record decides.
        let processed = Err(RpcFailure::Refused {
            code: Some(-32602),
            message: "Cannot process transaction with status 'unmined'. Must be 'unsigned' or 'unprocessed'".into(),
        });
        let word = read_process_answer(&processed, "aa");
        assert_eq!(decide(word, &rec("unmined")), Outcome::Taken);
        assert_eq!(decide(word, &rec("sending")), Outcome::NoWord);
        assert_eq!(decide(word, &unread), Outcome::NoWord);
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
            ("failed", Outcome::NotMade),
            ("doubleSpend", Outcome::NotMade),
            ("invalid", Outcome::NotMade),
            ("invalidTx", Outcome::NotMade),
            ("unsent", Outcome::NoWord),
            ("sending", Outcome::NoWord),
            ("unprocessed", Outcome::NoWord),
            ("nosend", Outcome::NoWord),
            ("unknown", Outcome::NoWord),
            ("made-up", Outcome::NoWord),
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
        assert_eq!(
            read_record(&[row("bb", "x"), row("aa", "unsent")], "aa").as_deref(),
            Some("unsent")
        );
        assert_eq!(read_record(&[row("bb", "x")], "aa"), None);
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
        // The consumer asks for the delay on every re-delivery.
        let queue = include_str!("queue/mod.rs");
        let arm = &queue[queue.find("QueueMessage::RenewalAdvert(r) =>").unwrap()..];
        let arm = &arm[..arm.find("continue;").unwrap()];
        assert!(arm.contains("with_delay_seconds(crate::renewal::RESUBMIT_DELAY_SECONDS)"));
        assert!(!arm.contains("msg.retry()"));
        // Four deliveries end well inside the window the pass leaves them.
        const {
            assert!(
                (QUEUE_DELIVERIES as u32 * RESUBMIT_DELAY_SECONDS) < QUEUE_WINDOW_SECONDS as u32
            )
        };
    }

    #[test]
    fn the_pass_reads_twenty_rows_fewest_runs_first_of_three_kinds() {
        assert_eq!(PASS_ROWS, 20);
        assert!(WAITING_SQL.ends_with("ORDER BY r.runs, r.created_at, r.prefix LIMIT 20"));
        assert!(WAITING_SQL.contains("r.advert = 'not_admitted'"));
        assert!(
            WAITING_SQL.contains("r.outcome = 'no_word' AND r.advert IS NULL AND g.state = 'paid'")
        );
        assert!(WAITING_SQL.contains("r.outcome = 'served' AND g.state = 'paid'"));
        let p = Some("paid");
        let g = Some("granted");
        assert_eq!(
            waiting("served", Some("not_admitted"), g, false),
            vec![Waiting::Admit]
        );
        assert_eq!(
            waiting("served", Some("not_admitted"), g, true),
            Vec::<Waiting>::new()
        );
        assert_eq!(waiting("no_word", None, p, false), vec![Waiting::Word]);
        // A served row whose grant reads paid: its grant first, then its
        // advert once it is off the queue.
        assert_eq!(
            waiting("served", Some("not_admitted"), p, false),
            vec![Waiting::Grant, Waiting::Admit]
        );
        assert_eq!(
            waiting("served", Some("not_admitted"), p, true),
            vec![Waiting::Grant]
        );
        for advert in [Some("admitted"), Some("refused"), Some("stopped")] {
            assert_eq!(waiting("served", advert, p, false), vec![Waiting::Grant]);
        }
        for (outcome, advert, grant) in [
            ("served", Some("admitted"), g),
            ("served", Some("refused"), g),
            ("served", Some("stopped"), g),
            ("served", Some("admitted"), None),
            ("no_word", Some("stopped"), p),
            ("no_word", None, g),
            ("no_word", None, None),
            ("not_made", None, p),
        ] {
            assert_eq!(
                waiting(outcome, advert, grant, false),
                Vec::<Waiting>::new(),
                "{outcome} {advert:?} {grant:?}"
            );
        }
        // Every statement that moves a row names the kind it moves.
        for sql in [
            COUNTED_ADMIT_SQL,
            ADMISSION_SQL,
            UNQUEUED_SQL,
            QUEUE_TRY_SQL,
            FAULT_SQL,
        ] {
            assert!(sql.contains("advert = 'not_admitted'"), "{sql}");
        }
        for sql in [COUNTED_WORD_SQL, WORD_SQL] {
            assert!(
                sql.contains("outcome = 'no_word' AND advert IS NULL"),
                "{sql}"
            );
        }
        assert!(
            RECORD_SQL.ends_with("WHERE renewals.outcome = 'no_word' AND renewals.advert IS NULL")
        );
        assert!(OPEN_SQL.contains("'no_word', NULL"));
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

    /// The row opened before `processAction` (`None` when a row of the
    /// prefix stands).
    fn open(db: &Connection, prefix: &str, renewing: &str) -> Option<String> {
        db.query_row(
            OPEN_SQL,
            params![prefix, "pay", renewing, 1_900_000_000i64, "YmVlZg=="],
            |r| r.get(0),
        )
        .ok()
    }

    /// The pass's kinds for each row [`WAITING_SQL`] returns at `now`.
    fn kinds_now(db: &Connection, now: i64) -> Vec<(String, Vec<Waiting>)> {
        let mut statement = db.prepare(WAITING_SQL).unwrap();
        let rows = statement
            .query_map([now], |r| {
                let outcome: String = r.get("outcome")?;
                let advert: Option<String> = r.get("advert")?;
                let grant: Option<String> = r.get("grant_state")?;
                let queued: Option<i64> = r.get("queued_until")?;
                Ok((
                    r.get::<_, String>("prefix")?,
                    waiting(
                        &outcome,
                        advert.as_deref(),
                        grant.as_deref(),
                        queued.is_some_and(|q| q > now),
                    ),
                ))
            })
            .unwrap();
        rows.map(Result::unwrap).collect()
    }

    /// A request that ends after `processAction` (the wallet's call, the
    /// overlay, the fan-out) has written only the row opened before it: the
    /// pass finds it, asks the wallet, and the wallet's record settles it.
    #[test]
    fn a_request_cut_after_process_action_leaves_a_no_word_row_the_pass_resolves() {
        let db = migrated();
        grant(&db, "cut", "paid");
        grant(&db, "cut-failed", "paid");
        assert_eq!(open(&db, "cut", "renewing-1").as_deref(), Some("cut"));
        assert_eq!(
            open(&db, "cut-failed", "renewing-2").as_deref(),
            Some("cut-failed")
        );
        // The request ends here: no second write.
        assert_eq!(column(&db, "cut", "outcome"), text_value("no_word"));
        assert_eq!(
            column(&db, "cut", "renewing_txid"),
            text_value("renewing-1")
        );
        assert_eq!(column(&db, "cut", "advert_beef"), text_value("YmVlZg=="));
        assert_eq!(column(&db, "cut", "advert"), rusqlite::types::Value::Null);
        assert_eq!(
            kinds_now(&db, 10),
            vec![
                ("cut".to_string(), vec![Waiting::Word]),
                ("cut-failed".to_string(), vec![Waiting::Word])
            ]
        );
        // The pass asks the wallet: one record reads a take, the other a
        // failure.
        let reqs = |txid: &str, status: &str| {
            vec![ProvenTxReqRow {
                txid: txid.into(),
                status: status.into(),
            }]
        };
        assert_eq!(
            after_word(
                0,
                read_req_status(&reqs("renewing-1", "unmined"), "renewing-1")
            ),
            Step::Served
        );
        assert_eq!(
            after_word(
                0,
                read_req_status(&reqs("renewing-2", "invalid"), "renewing-2")
            ),
            Step::NotMade
        );
        let n = |sql: &str, p: &[&dyn rusqlite::ToSql]| db.execute(sql, p).unwrap();
        assert_eq!(
            n(
                WORD_SQL,
                params!["cut", "served", "admitted", None::<String>, None::<i64>]
            ),
            1
        );
        assert_eq!(n(GRANT_SERVED_SQL, params!["cut", 1_900_000_000i64]), 1);
        assert_eq!(
            n(
                WORD_SQL,
                params![
                    "cut-failed",
                    "not_made",
                    None::<String>,
                    None::<String>,
                    None::<i64>
                ]
            ),
            1
        );
        assert!(kinds_now(&db, 10).is_empty());
        // A second open of a prefix writes nothing.
        assert_eq!(open(&db, "cut", "renewing-3"), None);
        assert_eq!(
            column(&db, "cut", "renewing_txid"),
            text_value("renewing-1")
        );
    }

    /// The route's second write settles the row it opened; a row the pass
    /// moved first is left as the pass wrote it; a renewal not made before
    /// its transaction was handed over is written whole.
    #[test]
    fn the_route_settles_the_row_it_opened() {
        let db = migrated();
        let settle = |prefix: &str, outcome: &str, advert: Option<&str>, beef: Option<&str>| {
            db.execute(
                RECORD_SQL,
                params![
                    prefix,
                    "pay",
                    None::<String>,
                    outcome,
                    advert,
                    None::<String>,
                    None::<i64>,
                    beef,
                    None::<i64>
                ],
            )
            .unwrap()
        };
        open(&db, "taken", "renewing-1").unwrap();
        assert_eq!(settle("taken", "served", Some("admitted"), None), 1);
        assert_eq!(column(&db, "taken", "outcome"), text_value("served"));
        assert_eq!(column(&db, "taken", "advert"), text_value("admitted"));
        // What the open wrote is kept where the second write has none.
        assert_eq!(
            column(&db, "taken", "renewing_txid"),
            text_value("renewing-1")
        );
        assert_eq!(column(&db, "taken", "advert_beef"), text_value("YmVlZg=="));
        assert_eq!(
            column(&db, "taken", "new_expiry_time"),
            rusqlite::types::Value::Integer(1_900_000_000)
        );
        // Once settled, a second settle moves nothing.
        assert_eq!(settle("taken", "no_word", None, None), 0);
        assert_eq!(column(&db, "taken", "outcome"), text_value("served"));
        // No word stays no word, for the pass.
        open(&db, "no-word", "renewing-2").unwrap();
        assert_eq!(settle("no-word", "no_word", None, None), 1);
        assert_eq!(column(&db, "no-word", "outcome"), text_value("no_word"));
        // Not made before any transaction was handed over: written whole.
        assert_eq!(settle("refused", "not_made", None, None), 1);
        assert_eq!(column(&db, "refused", "outcome"), text_value("not_made"));
        assert_eq!(
            column(&db, "refused", "renewing_txid"),
            rusqlite::types::Value::Null
        );
    }

    /// Twenty rows that keep faulting do not hold newer rows back: fewest
    /// runs first, then oldest.
    #[test]
    fn the_pass_takes_fewest_runs_first() {
        let db = migrated();
        for i in 1..=20 {
            let prefix = format!("old{i:02}");
            row(&db, &prefix, "served", Some("not_admitted"), i, None);
            db.execute("UPDATE renewals SET runs = 5 WHERE prefix = ?1", [&prefix])
                .unwrap();
        }
        row(&db, "new-admit", "served", Some("not_admitted"), 100, None);
        row(&db, "new-word", "no_word", None, 101, None);
        grant(&db, "new-word", "paid");
        let got = waiting_now(&db, 1000);
        assert_eq!(got.len(), 20);
        assert_eq!(&got[..2], &strings(&["new-admit", "new-word"])[..]);
        let expected: Vec<String> = (1..=18).map(|i| format!("old{i:02}")).collect();
        assert_eq!(&got[2..], &expected[..]);
        // A count of one more run moves a row behind those with fewer.
        assert_eq!(
            db.execute(
                COUNTED_ADMIT_SQL,
                params!["new-admit", 6, "not_admitted", "HTTP 503"]
            )
            .unwrap(),
            1
        );
        let got = waiting_now(&db, 1000);
        assert_eq!(got[0], "new-word");
        assert!(!got.contains(&"new-admit".to_string()));
    }

    /// A served row whose grant's second write did not land: the pass sets
    /// the grant `granted`, inside the same twenty, and then leaves it.
    #[test]
    fn a_served_row_whose_grant_reads_paid_is_repaired_by_the_pass() {
        let db = migrated();
        row(&db, "seam", "served", Some("admitted"), 1, None);
        grant(&db, "seam", "paid");
        row(
            &db,
            "seam-queued",
            "served",
            Some("not_admitted"),
            2,
            Some(5000),
        );
        grant(&db, "seam-queued", "paid");
        row(&db, "whole", "served", Some("admitted"), 3, None);
        grant(&db, "whole", "granted");
        assert_eq!(
            kinds_now(&db, 10),
            vec![
                ("seam".to_string(), vec![Waiting::Grant]),
                ("seam-queued".to_string(), vec![Waiting::Grant])
            ]
        );
        for prefix in ["seam", "seam-queued"] {
            assert_eq!(
                db.execute(GRANT_SERVED_SQL, params![prefix, 1_900_000_000i64])
                    .unwrap(),
                1
            );
        }
        let state: String = db
            .query_row(
                "SELECT state FROM payment_grants WHERE prefix = 'seam'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "granted");
        assert!(kinds_now(&db, 10).is_empty());
        // Its advert, once off the queue, is the pass's as any other.
        assert_eq!(
            kinds_now(&db, 5000),
            vec![("seam-queued".to_string(), vec![Waiting::Admit])]
        );
    }

    /// The last answer that was not an admission is kept on the row.
    #[test]
    fn a_fault_keeps_its_kind_on_the_row() {
        let db = migrated();
        row(&db, "q", "served", Some("not_admitted"), 1, Some(3601));
        assert_eq!(
            db.execute(FAULT_SQL, params!["q", "an empty admission: {}"])
                .unwrap(),
            1
        );
        assert_eq!(
            column(&db, "q", "reason"),
            text_value("an empty admission: {}")
        );
        row(&db, "done", "served", Some("admitted"), 2, None);
        assert_eq!(
            db.execute(FAULT_SQL, params!["done", "HTTP 503"]).unwrap(),
            0
        );
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
