//! The paid `/renew`'s duties after its answer, on the `CLAIMS` database's
//! `renewals` table ([`crate::renewal`]):
//!
//! - [`record`]: the route's row for a renewing step, and the one queue
//!   message that re-submits a renewed advert the overlay did not answer;
//! - [`deliver`]: the queue consumer's delivery of that message;
//! - [`run`]: the hourly pass, the Worker's only scheduled act.
//!
//! The pass reads at most [`renewal::PASS_ROWS`] rows a run, fewest runs
//! first and then oldest, and touches each once: a served row whose grant
//! still reads `paid` has its grant set `granted`; a `not_admitted` advert
//! gets one submit to the overlay; a `paid` grant whose renewing transaction
//! has no word gets one `findProvenTxReqs` question to the wallet (a take
//! serves the grant and submits its advert in the same run). It makes and
//! signs no transaction, reads and writes no stored object, touches no row
//! of any other kind, and no request's answer waits on it.

use base64::Engine as _;
use serde_json::Value;
use wasm_bindgen::JsValue;
use worker::{D1Database, Env};

use crate::claims::CLAIMS_BINDING;
use crate::overlay::{admit_uhrp_advert, overlay_url_from_env, ADMISSION_DEADLINE_MS};
use crate::queue::{QueueMessage, RenewalAdvert};
use crate::renewal::{self, Admission, Outcome, Step, Waiting};
use crate::routes::renew::StepRecord;
use crate::wallet::client::Wallet;

/// The queue the re-submit goes on: the post-upload queue's producer.
pub const QUEUE_BINDING: &str = "POST_UPLOAD_QUEUE";

/// The largest advert a row keeps to submit again, in bytes (its base64
/// text is a third longer). A larger one is not kept: its row is `stopped`
/// if the overlay has not admitted it.
pub const BEEF_KEPT_MAX_BYTES: usize = 512 * 1024;

/// The reason a row carries when its advert's bytes are not kept.
const NOT_KEPT: &str = "the advert's bytes are not kept";

fn text(s: Option<&str>) -> JsValue {
    s.map_or(JsValue::NULL, JsValue::from_str)
}

fn num(n: Option<i64>) -> JsValue {
    n.map_or(JsValue::NULL, |n| JsValue::from_f64(n as f64))
}

fn now_secs() -> i64 {
    (js_sys::Date::now() / 1000.0) as i64
}

async fn exec(db: &D1Database, sql: &str, values: &[JsValue]) -> Result<(), String> {
    db.prepare(sql)
        .bind(values)
        .map_err(|e| e.to_string())?
        .run()
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// The advert's bytes as a row keeps them, when they are within
/// [`BEEF_KEPT_MAX_BYTES`].
#[must_use]
pub fn kept(beef: Option<&[u8]>) -> Option<String> {
    beef.filter(|b| b.len() <= BEEF_KEPT_MAX_BYTES)
        .map(|b| base64::engine::general_purpose::STANDARD.encode(b))
}

/// The `advert`, `reason` and queue columns for an admission, given
/// whether the advert's bytes are kept to submit again.
fn advert_columns(admission: &Admission, kept: bool) -> (&'static str, Option<String>, bool) {
    match renewal::advert_column(admission) {
        ("not_admitted", _, true) if !kept => ("stopped", Some(NOT_KEPT.to_string()), false),
        other => other,
    }
}

/// Where a paid renewal's row is written: the `CLAIMS` database, the won
/// claim's prefix, and the payment's txid.
pub struct Ledger<'a> {
    pub db: &'a D1Database,
    pub prefix: &'a str,
    pub payment_txid: &'a str,
}

/// Open the renewal's row before its renewing transaction is handed to the
/// wallet ([`renewal::OPEN_SQL`]): the renewing txid, the expiry it carries,
/// the advert's bytes, the outcome no word. An error when the row was not
/// written (a row of the prefix stands, or the database failed); then the
/// transaction is not handed over.
pub async fn open(
    ledger: &Ledger<'_>,
    renewing_txid: &str,
    new_expiry: u64,
    beef: &[u8],
) -> Result<(), String> {
    let beef = kept(Some(beef));
    let written = ledger
        .db
        .prepare(renewal::OPEN_SQL)
        .bind(&[
            ledger.prefix.into(),
            ledger.payment_txid.into(),
            renewing_txid.into(),
            num(Some(new_expiry as i64)),
            text(beef.as_deref()),
        ])
        .map_err(|e| e.to_string())?
        .first::<Value>(None)
        .await
        .map_err(|e| e.to_string())?;
    match written {
        Some(_) => Ok(()),
        None => Err("a row of the prefix stands".to_string()),
    }
}

/// Record what the route's renewing step came to, under the payment's
/// `prefix`: the row opened before `processAction` is settled while it
/// still reads no word, and a renewal not made before any transaction was
/// handed over is written whole ([`renewal::RECORD_SQL`]). The re-submit
/// goes on the queue when the overlay's answer was a fault.
pub async fn record(
    env: &Env,
    db: &D1Database,
    prefix: &str,
    payment_txid: &str,
    step: &StepRecord,
) -> Result<(), String> {
    let beef = kept(step.beef.as_deref());
    let (advert, reason, queue) = match &step.admission {
        Some(admission) => {
            let (advert, reason, queue) = advert_columns(admission, beef.is_some());
            (Some(advert), reason, queue)
        }
        None => (None, None, false),
    };
    let queued_until = queue.then(|| now_secs() + renewal::QUEUE_WINDOW_SECONDS);
    exec(
        db,
        renewal::RECORD_SQL,
        &[
            prefix.into(),
            payment_txid.into(),
            text(step.renewing_txid.as_deref()),
            step.outcome.column().into(),
            text(advert),
            text(reason.as_deref()),
            num(step.new_expiry.map(|e| e as i64)),
            text(beef.as_deref()),
            num(queued_until),
        ],
    )
    .await?;
    if queue {
        enqueue(env, db, prefix).await;
    }
    Ok(())
}

/// One re-submit message for the row under `prefix`. If it cannot be sent,
/// the row is left to the pass at once.
async fn enqueue(env: &Env, db: &D1Database, prefix: &str) {
    let message = QueueMessage::RenewalAdvert(RenewalAdvert {
        renewal_advert: prefix.to_string(),
    });
    let sent = match env.queue(QUEUE_BINDING) {
        Ok(queue) => queue.send(message).await.map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    };
    if let Err(e) = sent {
        worker::console_error!("renewal {prefix}: the re-submit was not queued: {e}");
        if let Err(e) = exec(db, renewal::UNQUEUED_SQL, &[prefix.into()]).await {
            worker::console_error!("renewal {prefix}: {e}");
        }
    }
}

/// The advert's bytes a row keeps.
fn beef_of(row: &Value) -> Option<Vec<u8>> {
    let text = row["advert_beef"].as_str()?;
    base64::engine::general_purpose::STANDARD.decode(text).ok()
}

/// The queue's delivery of a re-submit: one submit of the row's advert.
/// Returns whether the message is to be delivered again.
pub async fn deliver(env: &Env, prefix: &str) -> bool {
    worker::console_log!("renewal {prefix}: a re-submit delivered");
    let Ok(db) = env.d1(CLAIMS_BINDING) else {
        worker::console_error!("renewal {prefix}: no CLAIMS binding");
        return true;
    };
    let row = match db.prepare(renewal::QUEUE_TRY_SQL).bind(&[prefix.into()]) {
        Ok(statement) => statement.first::<Value>(None).await,
        Err(e) => Err(e),
    };
    let row = match row {
        Ok(Some(row)) => row,
        // Nothing of that kind waits under the prefix.
        Ok(None) => {
            worker::console_log!("renewal {prefix}: no re-submit waits");
            return false;
        }
        Err(e) => {
            worker::console_error!("renewal {prefix}: {e}");
            return true;
        }
    };
    let tries = row["queue_tries"].as_f64().unwrap_or(0.0) as i64;
    let admission = match beef_of(&row) {
        Some(beef) => {
            admit_uhrp_advert(
                env,
                &overlay_url_from_env(env),
                &beef,
                ADMISSION_DEADLINE_MS,
            )
            .await
        }
        None => Admission::Fault(NOT_KEPT.to_string()),
    };
    let (step, again) = renewal::after_delivery(tries, &admission);
    let written = match step {
        Some(Step::Admitted) => {
            exec(
                &db,
                renewal::ADMISSION_SQL,
                &[prefix.into(), "admitted".into(), JsValue::NULL],
            )
            .await
        }
        Some(Step::Refused(why)) => {
            exec(
                &db,
                renewal::ADMISSION_SQL,
                &[prefix.into(), "refused".into(), why.as_str().into()],
            )
            .await
        }
        _ => {
            // A fault: its kind is kept on the row; when the deliveries are
            // spent the row is the pass's.
            let why = match &admission {
                Admission::Fault(why) => renewal::reason(why),
                _ => String::new(),
            };
            match exec(
                &db,
                renewal::FAULT_SQL,
                &[prefix.into(), why.as_str().into()],
            )
            .await
            {
                Ok(()) if !again => exec(&db, renewal::UNQUEUED_SQL, &[prefix.into()]).await,
                other => other,
            }
        }
    };
    if let Err(e) = written {
        worker::console_error!("renewal {prefix}: {e}");
    }
    worker::console_log!("renewal {prefix}: delivery {tries}: {admission:?}");
    again
}

/// What one run did, for its log line.
#[derive(Default)]
struct Ran {
    rows: usize,
    granted: usize,
    admitted: usize,
    refused: usize,
    counted: usize,
    stopped: usize,
    served: usize,
    not_made: usize,
}

/// The hourly pass.
pub async fn run(env: &Env) {
    let Ok(db) = env.d1(CLAIMS_BINDING) else {
        worker::console_error!("pass: no CLAIMS binding");
        return;
    };
    let rows = match db
        .prepare(renewal::WAITING_SQL)
        .bind(&[JsValue::from_f64(now_secs() as f64)])
    {
        Ok(statement) => statement.all().await,
        Err(e) => Err(e),
    };
    let rows: Vec<Value> = match rows.and_then(|r| r.results::<Value>()) {
        Ok(rows) => rows,
        Err(e) => {
            worker::console_error!("pass: the waiting rows could not be read: {e}");
            return;
        }
    };
    let overlay = overlay_url_from_env(env);
    let wallet = Wallet::from_env(env).ok();
    let now = now_secs();
    let mut ran = Ran::default();
    for row in rows.iter().take(renewal::PASS_ROWS as usize) {
        let Some(prefix) = row["prefix"].as_str() else {
            continue;
        };
        let runs = row["runs"].as_f64().unwrap_or(0.0) as i64;
        let new_expiry = row["new_expiry_time"].as_f64().map(|e| e as i64);
        let queued = row["queued_until"]
            .as_f64()
            .is_some_and(|q| (q as i64) > now);
        let kinds = renewal::waiting(
            row["outcome"].as_str().unwrap_or_default(),
            row["advert"].as_str(),
            row["grant_state"].as_str(),
            queued,
        );
        ran.rows += 1;
        for kind in kinds {
            let written = match kind {
                Waiting::Grant => {
                    // The row reads served and its grant's second write did
                    // not land: the grant is set `granted`.
                    ran.granted += 1;
                    exec(
                        &db,
                        renewal::GRANT_SERVED_SQL,
                        &[prefix.into(), num(new_expiry)],
                    )
                    .await
                }
                Waiting::Admit => {
                    let admission = match beef_of(&stored(&db, prefix).await) {
                        Some(beef) => {
                            admit_uhrp_advert(env, &overlay, &beef, ADMISSION_DEADLINE_MS).await
                        }
                        None => Admission::Fault(NOT_KEPT.to_string()),
                    };
                    let step = renewal::after_submit(runs, &admission);
                    let reason = match &admission {
                        Admission::Fault(why) => Some(renewal::reason(why)),
                        _ => None,
                    };
                    tally(&mut ran, &step);
                    admit_step(&db, prefix, &step, reason.as_deref()).await
                }
                Waiting::Word => {
                    let word = match (&wallet, row["renewing_txid"].as_str()) {
                        (Some(wallet), Some(txid)) => {
                            match wallet.find_proven_tx_reqs(txid).await {
                                Ok(reqs) => renewal::read_req_status(&reqs, txid),
                                Err(e) => {
                                    worker::console_log!("pass {prefix}: findProvenTxReqs: {e:?}");
                                    Outcome::NoWord
                                }
                            }
                        }
                        _ => Outcome::NoWord,
                    };
                    let step = renewal::after_word(runs, word);
                    tally(&mut ran, &step);
                    word_step(env, &db, &overlay, prefix, &step, new_expiry).await
                }
            };
            if let Err(e) = written {
                worker::console_error!("pass {prefix}: {e}");
            }
        }
    }
    worker::console_log!(
        "pass: {} rows; grants set granted {}, admitted {}, refused {}, counted {}, stopped {}, served {}, not made {}",
        ran.rows,
        ran.granted,
        ran.admitted,
        ran.refused,
        ran.counted,
        ran.stopped,
        ran.served,
        ran.not_made
    );
}

fn tally(ran: &mut Ran, step: &Step) {
    match step {
        Step::Admitted => ran.admitted += 1,
        Step::Refused(_) => ran.refused += 1,
        Step::Counted(_) => ran.counted += 1,
        Step::Stopped(_) => ran.stopped += 1,
        Step::Served => ran.served += 1,
        Step::NotMade => ran.not_made += 1,
    }
}

/// The row's kept advert bytes.
async fn stored(db: &D1Database, prefix: &str) -> Value {
    let row = match db.prepare(renewal::BEEF_SQL).bind(&[prefix.into()]) {
        Ok(statement) => statement.first::<Value>(None).await,
        Err(e) => Err(e),
    };
    row.ok().flatten().unwrap_or(Value::Null)
}

/// Write a `not_admitted` row's step.
async fn admit_step(
    db: &D1Database,
    prefix: &str,
    step: &Step,
    reason: Option<&str>,
) -> Result<(), String> {
    match step {
        Step::Admitted => {
            exec(
                db,
                renewal::ADMISSION_SQL,
                &[prefix.into(), "admitted".into(), JsValue::NULL],
            )
            .await
        }
        Step::Refused(why) => {
            exec(
                db,
                renewal::ADMISSION_SQL,
                &[prefix.into(), "refused".into(), why.as_str().into()],
            )
            .await
        }
        Step::Counted(runs) | Step::Stopped(runs) => {
            let advert = if matches!(step, Step::Stopped(_)) {
                "stopped"
            } else {
                "not_admitted"
            };
            exec(
                db,
                renewal::COUNTED_ADMIT_SQL,
                &[prefix.into(), num(Some(*runs)), advert.into(), text(reason)],
            )
            .await
        }
        Step::Served | Step::NotMade => Ok(()),
    }
}

/// Write the step of a row that waited on the wallet's word. A take serves
/// the grant and puts its advert to the overlay as the route does.
async fn word_step(
    env: &Env,
    db: &D1Database,
    overlay: &str,
    prefix: &str,
    step: &Step,
    new_expiry: Option<i64>,
) -> Result<(), String> {
    match step {
        Step::Served => {
            let beef = beef_of(&stored(db, prefix).await);
            let admission = match &beef {
                Some(beef) => admit_uhrp_advert(env, overlay, beef, ADMISSION_DEADLINE_MS).await,
                None => Admission::Fault(NOT_KEPT.to_string()),
            };
            let (advert, reason, queue) = advert_columns(&admission, beef.is_some());
            let queued_until = queue.then(|| now_secs() + renewal::QUEUE_WINDOW_SECONDS);
            exec(
                db,
                renewal::WORD_SQL,
                &[
                    prefix.into(),
                    "served".into(),
                    advert.into(),
                    text(reason.as_deref()),
                    num(queued_until),
                ],
            )
            .await?;
            exec(
                db,
                renewal::GRANT_SERVED_SQL,
                &[prefix.into(), num(new_expiry)],
            )
            .await?;
            if queue {
                enqueue(env, db, prefix).await;
            }
            Ok(())
        }
        Step::NotMade => {
            exec(
                db,
                renewal::WORD_SQL,
                &[
                    prefix.into(),
                    "not_made".into(),
                    JsValue::NULL,
                    JsValue::NULL,
                    JsValue::NULL,
                ],
            )
            .await
        }
        Step::Counted(runs) => {
            exec(
                db,
                renewal::COUNTED_WORD_SQL,
                &[prefix.into(), num(Some(*runs)), JsValue::NULL],
            )
            .await
        }
        Step::Stopped(runs) => {
            exec(
                db,
                renewal::COUNTED_WORD_SQL,
                &[prefix.into(), num(Some(*runs)), "stopped".into()],
            )
            .await
        }
        Step::Admitted | Step::Refused(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn the_pass_makes_no_transaction_and_touches_no_stored_object() {
        let src = include_str!("pass.rs");
        let code = &src[..src.find("#[cfg(test)]\nmod tests").unwrap()];
        for never in [
            "create_action",
            "process_action",
            "sign_transaction",
            "internalize",
            "head_object",
            ".bucket(",
            "Delay",
        ] {
            assert!(!code.contains(never), "{never}");
        }
        // The wallet is asked one thing.
        assert_eq!(code.matches("wallet.find_proven_tx_reqs(").count(), 1);
        assert_eq!(code.matches("wallet.").count(), 1);
        // One statement reads the rows, and the loop takes at most the cap.
        assert_eq!(code.matches("renewal::WAITING_SQL").count(), 1);
        assert!(code.contains(".take(renewal::PASS_ROWS as usize)"));
    }

    #[test]
    fn a_large_advert_is_not_kept_and_its_fault_stops() {
        assert!(kept(Some(&[1u8, 2, 3][..])).is_some());
        let at = vec![0u8; BEEF_KEPT_MAX_BYTES];
        assert!(kept(Some(at.as_slice())).is_some());
        let over = vec![0u8; BEEF_KEPT_MAX_BYTES + 1];
        assert!(kept(Some(over.as_slice())).is_none());
        assert!(kept(None).is_none());
        let fault = Admission::Fault("503".into());
        assert_eq!(
            advert_columns(&fault, true),
            ("not_admitted", Some("503".into()), true)
        );
        assert_eq!(
            advert_columns(&fault, false),
            ("stopped", Some(NOT_KEPT.to_string()), false)
        );
        assert_eq!(
            advert_columns(&Admission::Admitted, false),
            ("admitted", None, false)
        );
    }

    #[test]
    fn the_cron_runs_hourly() {
        let wrangler = include_str!("../wrangler.toml");
        let triggers = &wrangler[wrangler.find("[triggers]").unwrap()..];
        assert!(triggers.starts_with("[triggers]\ncrons = [\"0 * * * *\"]\n"));
        assert_eq!(wrangler.matches("crons").count(), 1);
    }
}
