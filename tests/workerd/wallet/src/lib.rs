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
//! - the overlay: `/submit` admits output 0 (and counts it), `/lookup`
//!   answers no outputs.

use bsv_middleware_cloudflare::middleware::{
    process_auth, sign_json_response, AuthMiddlewareOptions, AuthResult,
};
use serde_json::{json, Value};
use worker::{event, Context, Delay, Env, Request, Response, Result};

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
            return Response::from_json(&json!({ "seeded": tag }));
        }
        "/advert" => {
            let tag = query(&url, "tag");
            let advert = get_json(&kv, &format!("advert:{tag}")).await?;
            let mut counts = json!({});
            for name in ["listOutputs", "createAction", "processAction"] {
                counts[name] = json!(count(&kv, &format!("{name}:{tag}")).await?);
            }
            return Response::from_json(&json!({ "advert": advert, "calls": counts }));
        }
        "/submit" => {
            let n = count(&kv, "submit").await? + 1;
            kv.put("submit", n.to_string())?.execute().await?;
            return Response::from_json(
                &json!({ "tm_uhrp": { "outputsToAdmit": [0], "coinsToRetain": [] } }),
            );
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
            if a.is_null()
                || format!("{}.{}", a["txid"].as_str().unwrap_or_default(), a["vout"]) != outpoint
            {
                Err(json!({ "code": -32000, "message": "the outpoint is not spendable" }))
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
                    &json!({ "tag": tag, "lockingScript": out["lockingScript"], "tags": out["tags"] }),
                )
                .await?;
                Ok(json!({
                    "inputBeef": a["beef"],
                    "inputs": [{
                        "vin": 0,
                        "sourceTxid": a["txid"],
                        "sourceVout": a["vout"],
                        "sourceSatoshis": 1,
                        "sourceLockingScript": a["lockingScript"],
                    }],
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
            let pending = get_json(&kv, &format!("pending:{reference}")).await?;
            let tag = pending["tag"].as_str().unwrap_or_default().to_string();
            bump(&kv, &format!("processAction:{tag}")).await?;
            let mut a = get_json(&kv, &format!("advert:{tag}")).await?;
            if a.is_null() || pending.is_null() {
                Err(json!({ "code": -32000, "message": "no such action" }))
            } else {
                a["txid"] = args["txid"].clone();
                a["vout"] = json!(0);
                a["lockingScript"] = pending["lockingScript"].clone();
                a["tags"] = pending["tags"].clone();
                let outpoint = format!("{}.0", args["txid"].as_str().unwrap_or_default());
                kv.put(&format!("outpoint:{outpoint}"), &tag)?
                    .execute()
                    .await?;
                put_json(&kv, &format!("advert:{tag}"), &a).await?;
                kv.delete(&format!("pending:{reference}")).await?;
                Ok(json!({}))
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

fn query(url: &worker::Url, name: &str) -> String {
    url.query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

async fn count(kv: &worker::kv::KvStore, key: &str) -> Result<u64> {
    Ok(kv
        .get(key)
        .text()
        .await?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0))
}

async fn bump(kv: &worker::kv::KvStore, key: &str) -> Result<()> {
    let n = count(kv, key).await? + 1;
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
