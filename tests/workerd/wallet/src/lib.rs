//! The stand-in for everything the storage Worker fetches under
//! `../run.mjs` (Miniflare routes the storage Worker's outbound requests
//! here):
//!
//! - `api.whatsonchain.com`'s exchange rate: a fixed rate;
//! - the wallet storage server: the BRC-103 handshake and BRC-104 requests
//!   through the middleware's `process_auth`, and the JSON-RPC methods the
//!   payment door calls. `internalizeAction` waits `WALLET_DELAY_MS` (so
//!   simultaneous payments overlap), counts each call by its transaction
//!   (`GET /calls?txid=` answers the count), and answers `accepted: true`,
//!   an error while `/mode?fail=1` is in force, or `accepted: false` while
//!   `/mode?reject=1` is;
//! - the wallet storage server's side of `/renew`: `listOutputs` answers the
//!   advert seeded by `POST /advert` (by its `uhrp_url_` tag),
//!   `createAction` spends it (only while it is the advert's current
//!   outpoint) and `processAction` records the renewal: the advert moves to
//!   the new transaction, its script and tags (`GET /advert?tag=` answers
//!   the advert and how many of each call it saw);
//!   the release of an action frees its advert; `findProvenTxReqs`
//!   answers the broadcast request's status the last `processAction` (or
//!   `POST /req`) set for a transaction (`GET /finds?txid=` counts them);
//!   `POST /advert` also stores the advert's object (`cdn/<object>`, of
//!   the advert's size, or another `size`, or none) in the R2 bucket the
//!   storage Worker reads (`GET /object?key=` answers its etag and upload
//!   time);
//! - knobs (`/knob?create=&process=&overlay=`, each empty for the normal
//!   answer): `createAction` refuses as a spent advert does (`spent`) or
//!   answers a template the Worker cannot sign (`unsignable`), or holds its
//!   answer 1.5 s with the advert locked (`hold`), or orders two renewals of
//!   one advert (`gate`: the createAction that locks the advert answers once
//!   another createAction of it has met the lock, and the re-read
//!   `listOutputs` after that refusal answers once the lock is gone);
//!   `processAction` refuses the call by name before recording anything
//!   (`refuse`), answers `failed` (its request `invalid`), records the
//!   transaction and answers no result (`lost`, an HTTP 500), records it
//!   untaken (`untaken`: `sending`, its request `unsent`), or records it
//!   taken and answers the refusal of a transaction already processed
//!   (`processed`: its request `unmined`, the error `-32602` "Cannot process
//!   transaction with status 'unmined'…"); the overlay refuses in its error
//!   shape (`refuse`: a 400 `{"status": "error", "message": …}`), answers an
//!   empty admission (`empty`), or faults (`fault`: a 503). The outpoint
//!   `createAction` spends is locked in the isolate, so of two renewals of
//!   one advert at once one spends it and the other is refused as a spent
//!   advert;
//! - the overlay: `/submit` admits output 0 (and counts it), `/lookup`
//!   answers no outputs.

use bsv_middleware_cloudflare::middleware::{
    process_auth, sign_json_response, AuthMiddlewareOptions, AuthResult,
};
use serde_json::{json, Value};
use worker::{event, Context, Delay, Env, Request, Response, Result};

thread_local! {
    /// The outpoints an open action spends (one isolate serves the
    /// stand-in, so a check and an insert here are one step).
    static LOCKED: std::cell::RefCell<std::collections::HashSet<String>> =
        std::cell::RefCell::new(std::collections::HashSet::new());
}

thread_local! {
    /// The adverts (by tag) of which a createAction met the lock.
    static REFUSED: std::cell::RefCell<std::collections::HashSet<String>> =
        std::cell::RefCell::new(std::collections::HashSet::new());
}

fn refused(tag: &str) {
    REFUSED.with(|r| r.borrow_mut().insert(tag.to_string()));
}

fn was_refused(tag: &str) -> bool {
    REFUSED.with(|r| r.borrow().contains(tag))
}

fn is_locked(outpoint: &str) -> bool {
    LOCKED.with(|l| l.borrow().contains(outpoint))
}

/// Wait, 50 ms at a time and 20 s at most, until `done`.
async fn wait_until(done: impl Fn() -> bool) {
    for _ in 0..400 {
        if done() {
            return;
        }
        Delay::from(std::time::Duration::from_millis(50)).await;
    }
}

/// Lock `outpoint` for an action; false when another holds it.
fn lock(outpoint: &str) -> bool {
    LOCKED.with(|l| l.borrow_mut().insert(outpoint.to_string()))
}

fn unlock(outpoint: &str) {
    LOCKED.with(|l| {
        l.borrow_mut().remove(outpoint);
    });
}

/// The refusal wallet-infra answers for an explicit input it cannot lock.
fn spent(outpoint: &str) -> Value {
    json!({
        "code": -32602,
        "message": format!("createAction: explicit input {outpoint} is unavailable (already spent or locked by transaction_id 7)"),
    })
}

/// A public test key; this server's identity.
const WALLET_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000002";

/// A call's key: the payment's first 36 bytes (an Atomic BEEF's prefix and
/// the transaction's id), in hex.
fn tx_key(bytes: &[u8]) -> String {
    bytes.iter().take(36).map(|b| format!("{b:02x}")).collect()
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let url = req.url()?;
    let kv = env.kv("STAND_IN")?;
    if url.host_str() == Some("api.whatsonchain.com") {
        return Response::from_json(&json!({ "currency": "USD", "rate": 50.0 }));
    }
    match url.path() {
        "/calls" => {
            let key = url
                .query_pairs()
                .find(|(k, _)| k == "tx")
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default();
            let count = kv
                .get(&format!("calls:{key}"))
                .text()
                .await?
                .unwrap_or_default();
            return Response::from_json(&json!({ "calls": count.parse::<u64>().unwrap_or(0) }));
        }
        "/advert" if req.method() == worker::Method::Post => {
            let mut req = req;
            let advert: Value = req.json().await?;
            let tag = advert["tag"].as_str().unwrap_or_default().to_string();
            let outpoint = format!(
                "{}.{}",
                advert["txid"].as_str().unwrap_or_default(),
                advert["vout"]
            );
            kv.put(&format!("outpoint:{outpoint}"), &tag)?
                .execute()
                .await?;
            put_json(&kv, &format!("advert:{tag}"), &advert).await?;
            if let Some(key) = advert["object"].as_str() {
                let size = advert["size"].as_u64().unwrap_or(0) as usize;
                env.bucket("UHRP_FILES")?
                    .put(key, vec![0u8; size])
                    .execute()
                    .await?;
            }
            return Response::from_json(&json!({ "seeded": tag }));
        }
        "/advert" => {
            let tag = query(&url, "tag");
            let advert = get_json(&kv, &format!("advert:{tag}")).await?;
            let mut counts = json!({});
            for name in ["listOutputs", "createAction", "processAction", "release"] {
                counts[name] = json!(count(&kv, &format!("{name}:{tag}")).await?);
            }
            return Response::from_json(&json!({ "advert": advert, "calls": counts }));
        }
        "/object" => {
            let key = query(&url, "key");
            return match env.bucket("UHRP_FILES")?.head(key).await? {
                Some(o) => Response::from_json(&json!({
                    "exists": true,
                    "etag": o.etag(),
                    "uploaded": o.uploaded().as_millis(),
                    "size": o.size(),
                })),
                None => Response::from_json(&json!({ "exists": false })),
            };
        }
        "/knob" => {
            for name in ["create", "process", "overlay"] {
                if let Some(value) = url.query_pairs().find(|(k, _)| k == name).map(|(_, v)| v) {
                    kv.put(&format!("knob:{name}"), value.to_string())?
                        .execute()
                        .await?;
                }
            }
            return Response::from_json(&json!({
                "create": knob(&kv, "create").await?,
                "process": knob(&kv, "process").await?,
                "overlay": knob(&kv, "overlay").await?,
            }));
        }
        "/req" if req.method() == worker::Method::Post => {
            let txid = query(&url, "txid");
            kv.put(&format!("req:{txid}"), query(&url, "status"))?
                .execute()
                .await?;
            return Response::from_json(&json!({ "txid": txid }));
        }
        "/finds" => {
            let txid = query(&url, "txid");
            return Response::from_json(
                &json!({ "finds": count(&kv, &format!("find:{txid}")).await? }),
            );
        }
        "/submit" => {
            let n = count(&kv, "submit").await? + 1;
            kv.put("submit", n.to_string())?.execute().await?;
            return match knob(&kv, "overlay").await?.as_str() {
                "fault" => Response::error("the stand-in overlay is down", 503),
                "refuse" => Ok(Response::from_json(&json!({
                    "status": "error",
                    "code": "ERR_SCRIPT_REFUSED",
                    "message": "script verification failed (subject t): input 0: the stand-in overlay refuses this spend",
                }))?
                .with_status(400)),
                "empty" => Response::from_json(
                    &json!({ "tm_uhrp": { "outputsToAdmit": [], "coinsToRetain": [] } }),
                ),
                _ => Response::from_json(
                    &json!({ "tm_uhrp": { "outputsToAdmit": [0], "coinsToRetain": [] } }),
                ),
            };
        }
        "/submits" => {
            return Response::from_json(&json!({ "submits": count(&kv, "submit").await? }))
        }
        "/lookup" => return Response::from_json(&json!({ "type": "output-list", "outputs": [] })),
        "/mode" => {
            let fail = url.query_pairs().any(|(k, v)| k == "fail" && v == "1");
            let reject = url.query_pairs().any(|(k, v)| k == "reject" && v == "1");
            let mode = match (fail, reject) {
                (true, _) => "1",
                (_, true) => "reject",
                _ => "0",
            };
            kv.put("fail", mode)?.execute().await?;
            return Response::from_json(&json!({ "fail": fail, "reject": reject }));
        }
        _ => {}
    }
    let options = AuthMiddlewareOptions {
        server_private_key: WALLET_KEY.to_string(),
        allow_unauthenticated: false,
        session_ttl_seconds: 3600,
        ..Default::default()
    };
    let (session, body) = match process_auth(req, &env, &options).await {
        Ok(AuthResult::Response(response)) => return Ok(response),
        Ok(AuthResult::Authenticated { session, body, .. }) => (session, body),
        Err(e) => return Response::error(format!("auth: {e}"), 401),
    };
    let call: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let id = call["id"].clone();
    let result = match call["method"].as_str() {
        Some("makeAvailable") => Ok(json!({})),
        Some("findOrInsertUser") => Ok(json!({ "userId": 1, "isNew": false })),
        Some("internalizeAction") => {
            let tx: Vec<u8> = call["params"][1]["tx"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|b| b.as_u64())
                        .map(|b| b as u8)
                        .collect()
                })
                .unwrap_or_default();
            let key = format!("calls:{}", tx_key(&tx));
            let delay: u64 = env
                .var("WALLET_DELAY_MS")
                .map(|v| v.to_string().parse().unwrap_or(0))
                .unwrap_or(0);
            Delay::from(std::time::Duration::from_millis(delay)).await;
            let n: u64 = kv
                .get(&key)
                .text()
                .await?
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            kv.put(&key, (n + 1).to_string())?.execute().await?;
            match kv.get("fail").text().await?.as_deref() {
                Some("1") => {
                    Err(json!({ "code": -32000, "message": "the stand-in wallet is failing" }))
                }
                Some("reject") => Ok(json!({ "accepted": false })),
                _ => Ok(json!({ "accepted": true })),
            }
        }
        Some("listOutputs") => {
            let tag = call["params"][1]["tags"][0]
                .as_str()
                .unwrap_or_default()
                .to_string();
            bump(&kv, &format!("listOutputs:{tag}")).await?;
            if knob(&kv, "create").await? == "gate" && was_refused(&tag) {
                // The re-read after a refusal: answered once the action that
                // holds the advert is processed or released.
                let a = get_json(&kv, &format!("advert:{tag}")).await?;
                let held = format!("{}.{}", a["txid"].as_str().unwrap_or_default(), a["vout"]);
                wait_until(|| !is_locked(&held)).await;
            }
            match get_json(&kv, &format!("advert:{tag}")).await? {
                Value::Null => Ok(json!({ "totalOutputs": 0, "outputs": [] })),
                a => Ok(json!({
                    "totalOutputs": 1,
                    "outputs": [{
                        "satoshis": 1,
                        "outpoint": { "txid": a["txid"], "vout": a["vout"] },
                        "spendable": true,
                        "tags": a["tags"],
                        "lockingScript": a["lockingScript"],
                    }],
                    "BEEF": a["beef"],
                })),
            }
        }
        Some("createAction") => {
            let args = &call["params"][1];
            let outpoint = args["inputs"][0]["outpoint"].as_str().unwrap_or_default();
            let tag = kv
                .get(&format!("outpoint:{outpoint}"))
                .text()
                .await?
                .unwrap_or_default();
            bump(&kv, &format!("createAction:{tag}")).await?;
            let a = get_json(&kv, &format!("advert:{tag}")).await?;
            let create = knob(&kv, "create").await?;
            if a.is_null() {
                Err(json!({ "code": -32000, "message": "the outpoint is not spendable" }))
            } else if create == "spent"
                || format!("{}.{}", a["txid"].as_str().unwrap_or_default(), a["vout"]) != outpoint
                || !lock(outpoint)
            {
                refused(&tag);
                Err(spent(outpoint))
            } else {
                let reference = format!(
                    "ref-{}-{}",
                    tag,
                    count(&kv, &format!("createAction:{tag}")).await?
                );
                let out = &args["outputs"][0];
                put_json(
                    &kv,
                    &format!("pending:{reference}"),
                    &json!({ "tag": tag, "outpoint": outpoint, "lockingScript": out["lockingScript"], "tags": out["tags"] }),
                )
                .await?;
                if create == "hold" {
                    // The advert stays locked a while: a second renewal of
                    // it meets the lock.
                    Delay::from(std::time::Duration::from_millis(1500)).await;
                }
                if create == "gate" {
                    // The advert stays locked until a second renewal of it
                    // has met the lock.
                    wait_until(|| was_refused(&tag)).await;
                }
                let mut inputs = vec![json!({
                    "vin": 0,
                    "sourceTxid": a["txid"],
                    "sourceVout": a["vout"],
                    "sourceSatoshis": 1,
                    "sourceLockingScript": a["lockingScript"],
                })];
                if create == "unsignable" {
                    // A change input whose P2PKH key is not the Worker's.
                    inputs.push(json!({
                        "vin": 1,
                        "sourceTxid": "11".repeat(32),
                        "sourceVout": 0,
                        "sourceSatoshis": 1000,
                        "sourceLockingScript": format!("76a914{}88ac", "22".repeat(20)),
                    }));
                }
                Ok(json!({
                    "inputBeef": a["beef"],
                    "inputs": inputs,
                    "outputs": [{ "vout": 0, "satoshis": 1, "lockingScript": out["lockingScript"] }],
                    "version": 1,
                    "lockTime": 0,
                    "reference": reference,
                    "derivationPrefix": "",
                }))
            }
        }
        Some("processAction") => {
            let args = &call["params"][1];
            let reference = args["reference"].as_str().unwrap_or_default();
            let txid = args["txid"].as_str().unwrap_or_default().to_string();
            let pending = get_json(&kv, &format!("pending:{reference}")).await?;
            let tag = pending["tag"].as_str().unwrap_or_default().to_string();
            bump(&kv, &format!("processAction:{tag}")).await?;
            let mut a = get_json(&kv, &format!("advert:{tag}")).await?;
            let process = knob(&kv, "process").await?;
            let spent_outpoint = pending["outpoint"].as_str().unwrap_or_default().to_string();
            if a.is_null() || pending.is_null() {
                Err(json!({ "code": -32000, "message": "no such action" }))
            } else if process == "refuse" {
                // A refusal by name before anything is recorded.
                Err(json!({
                    "code": -32602,
                    "message": "processAction: the transaction does not match its action",
                }))
            } else if process == "failed" {
                // The wallet's own script verdict releases the inputs and
                // ends its request `invalid`.
                unlock(&spent_outpoint);
                kv.delete(&format!("pending:{reference}")).await?;
                kv.put(&format!("req:{txid}"), "invalid")?.execute().await?;
                Ok(
                    json!({ "sendWithResults": [{ "txid": txid, "status": "failed" }], "log": "input 0: script did not succeed" }),
                )
            } else {
                a["txid"] = json!(txid);
                a["vout"] = json!(0);
                a["lockingScript"] = pending["lockingScript"].clone();
                a["tags"] = pending["tags"].clone();
                let outpoint = format!("{txid}.0");
                kv.put(&format!("outpoint:{outpoint}"), &tag)?
                    .execute()
                    .await?;
                put_json(&kv, &format!("advert:{tag}"), &a).await?;
                kv.delete(&format!("pending:{reference}")).await?;
                unlock(&spent_outpoint);
                let status = match process.as_str() {
                    "untaken" => "unsent",
                    "lost" => "sending",
                    _ => "unmined",
                };
                kv.put(&format!("req:{txid}"), status)?.execute().await?;
                if process == "lost" {
                    return Response::error("the stand-in wallet lost the answer", 500);
                }
                if process == "processed" {
                    Err(json!({
                        "code": -32602,
                        "message": format!("Cannot process transaction with status '{status}'. Must be 'unsigned' or 'unprocessed'"),
                    }))
                } else {
                    Ok(json!({ "sendWithResults": [{ "txid": txid, "status": "sending" }] }))
                }
            }
        }
        Some("abortAction") => {
            let reference = call["params"][1]["reference"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let pending = get_json(&kv, &format!("pending:{reference}")).await?;
            let tag = pending["tag"].as_str().unwrap_or_default().to_string();
            bump(&kv, &format!("release:{tag}")).await?;
            if pending.is_null() {
                Ok(json!({ "aborted": false }))
            } else {
                unlock(pending["outpoint"].as_str().unwrap_or_default());
                kv.delete(&format!("pending:{reference}")).await?;
                Ok(json!({ "aborted": true }))
            }
        }
        Some("findProvenTxReqs") => {
            let txid = call["params"][1]["txids"][0]
                .as_str()
                .unwrap_or_default()
                .to_string();
            bump(&kv, &format!("find:{txid}")).await?;
            match kv.get(&format!("req:{txid}")).text().await? {
                Some(status) => Ok(
                    json!([{ "provenTxReqId": 1, "txid": txid, "status": status, "attempts": 1 }]),
                ),
                None => Ok(json!([])),
            }
        }
        other => Err(json!({ "code": -32601, "message": format!("no method {other:?}") })),
    };
    let reply = match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "result": result, "id": id }),
        Err(error) => json!({ "jsonrpc": "2.0", "error": error, "id": id }),
    };
    match session {
        Some(s) => sign_json_response(&reply, 200, &[], &s)
            .map_err(|e| worker::Error::RustError(e.to_string())),
        None => Response::from_json(&reply),
    }
}

async fn knob(kv: &worker::kv::KvStore, name: &str) -> Result<String> {
    Ok(kv
        .get(&format!("knob:{name}"))
        .text()
        .await?
        .unwrap_or_default())
}

fn query(url: &worker::Url, name: &str) -> String {
    url.query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

thread_local! {
    /// Each count as this isolate made it: a bump is one step here, so two
    /// calls at once are both counted (a key-value read and write is not).
    static COUNTS: std::cell::RefCell<std::collections::HashMap<String, u64>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

async fn count(kv: &worker::kv::KvStore, key: &str) -> Result<u64> {
    let stored = kv
        .get(key)
        .text()
        .await?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let here = COUNTS.with(|c| c.borrow().get(key).copied().unwrap_or(0));
    Ok(stored.max(here))
}

async fn bump(kv: &worker::kv::KvStore, key: &str) -> Result<()> {
    let stored = count(kv, key).await?;
    let n = COUNTS.with(|c| {
        let mut c = c.borrow_mut();
        let n = c.entry(key.to_string()).or_insert(0);
        *n = (*n).max(stored) + 1;
        *n
    });
    kv.put(key, n.to_string())?.execute().await?;
    Ok(())
}

async fn get_json(kv: &worker::kv::KvStore, key: &str) -> Result<Value> {
    Ok(match kv.get(key).text().await? {
        Some(text) => serde_json::from_str(&text).unwrap_or(Value::Null),
        None => Value::Null,
    })
}

async fn put_json(kv: &worker::kv::KvStore, key: &str, value: &Value) -> Result<()> {
    kv.put(key, value.to_string())?.execute().await?;
    Ok(())
}
