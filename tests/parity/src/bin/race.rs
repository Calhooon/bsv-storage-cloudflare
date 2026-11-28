//! Simultaneous paid requests against local builds of the storage Worker
//! (driven by `tests/workerd/run.mjs worker`, Miniflare; never a deployed
//! Worker). Usage:
//!
//!   race <storage-url> <old-storage-url> <stand-in-url> <no-binding-url> <no-table-url>
//!
//! `<stand-in-url>` is the stand-in wallet storage server both builds
//! internalize at; it counts `internalizeAction` calls per transaction.
//!
//! 1. One payment in N simultaneous requests to `/upload` (N = 2, 4, 16):
//!    exactly one service (200), every other the signed 409
//!    `ERR_PAYMENT_REPLAYED`; the wallet asked once.
//! 2. Two transactions under one prefix at once: one service, the other the
//!    signed 400 `ERR_PAYMENT_INVALID`; one wallet call.
//! 3. A prefix the old build used is refused by this one (its transaction
//!    409, another 400), and a prefix this build used is refused by the old
//!    one (no service, no wallet call).
//! 4. A wallet error releases the claim: the same transaction is served on
//!    its retry, once, and another transaction is refused. Released by the
//!    old build: another transaction here is the signed 400, the released
//!    transaction is served here once, then the signed 409. Released here,
//!    then the old build: it serves the released transaction once and
//!    refuses another; back here, the prefix is refused (409, another 400).
//!    A wallet rejection keeps the claim: the door's 402 with a fresh
//!    challenge, then the signed 409.
//! 5. `/renew`, paid: one renewal of an advert the stand-in holds (its
//!    expiry moved by the minutes paid for); the same payment again is the
//!    signed 409 and no second renewal; another transaction under the used
//!    prefix is the signed 400; one payment in N simultaneous requests
//!    (N = 2, 4, 16) is one renewal. The line `renew-grants` is the JSON of
//!    what each renewal was granted, which `run.mjs` reads against the
//!    `CLAIMS` grants, and `upload-grants` the object and custom-time of
//!    each upload this build served.
//! 6. A build without the `CLAIMS` binding, and one with the binding and
//!    no tables: a payment to `/upload` or `/renew` is the signed 503
//!    `ERR_PAYMENT_UNAVAILABLE` (the gate's), nothing is served and the
//!    wallet is not asked. On the build with no tables, a payment whose
//!    prefix has a key-value record is the door's unsigned 503, except the
//!    transaction a `released:<txid>` record names: its claim reaches the
//!    gate, and the answer is the gate's signed 503.
//! 7. A carried release frees only its own claim: a prefix the old build
//!    released, paid here at once by the released transaction and by others
//!    (12 rounds of each of six mixes), then the released transaction twice
//!    more: it is served at most once, and no other transaction is.
//!
//! Every answer is read with its verdict: signed (a BRC-104 signature that
//! verifies against the server's identity key for the session) or not. The
//! 200, the 402 challenge, the 409, the 400 `ERR_PAYMENT_INVALID` and the
//! gate's 503 are signed; the door's own answers (a malformed header, a
//! wallet error's 400, a wallet rejection's 402, a fault outside the gate's
//! 503) are not.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../auth.rs"]
#[allow(dead_code)]
mod auth;

use auth::AuthClient;
use bsv_rs::primitives::ec::{PrivateKey, PublicKey};
use bsv_rs::primitives::encoding::{to_base58, Writer};
use bsv_rs::primitives::hash::{hash160, sha256, sha256d};
use bsv_rs::primitives::to_base64;
use bsv_rs::script::templates::PushDrop;
use bsv_rs::transaction::{Beef, Transaction};
use bsv_rs::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};
use rand::RngCore;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex, OnceLock};

const UPLOAD_BODY: &str = r#"{"fileSize":1000000,"retentionPeriod":60}"#;

/// An answer: its status, its body's code (empty when served), whether it
/// served, and its signature's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Answer {
    status: u16,
    code: String,
    served: bool,
    signed: bool,
}

/// A signed 200 that served.
fn served() -> Answer {
    Answer {
        status: 200,
        code: String::new(),
        served: true,
        signed: true,
    }
}

/// The URL of the build under test, and what each upload it served
/// granted (the object identifier and the custom-time signed into the PUT).
static UNDER_TEST: OnceLock<String> = OnceLock::new();
static UPLOADS: Mutex<Vec<Value>> = Mutex::new(Vec::new());

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

fn varint(out: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        out.push(n as u8);
    } else {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    }
}

/// A payment: one input from a parent the BEEF does not carry, output 0
/// paying the server's BRC-29 key for `prefix`; as an Atomic BEEF.
fn payment(payer: &PrivateKey, server: &PublicKey, prefix: &str, sats: u64) -> (String, String) {
    let suffix = to_base64(&random32());
    let key = KeyDeriver::new(Some(payer.clone()))
        .derive_public_key(
            &Protocol::new(SecurityLevel::Counterparty, "3241645161d8"),
            &format!("{prefix} {suffix}"),
            &Counterparty::Other(server.clone()),
            false,
        )
        .unwrap();
    let mut script = vec![0x76, 0xa9, 0x14];
    script.extend_from_slice(&hash160(&key.to_compressed()));
    script.extend_from_slice(&[0x88, 0xac]);
    let mut raw = Vec::new();
    raw.extend_from_slice(&1u32.to_le_bytes());
    varint(&mut raw, 1);
    raw.extend_from_slice(&random32());
    raw.extend_from_slice(&0u32.to_le_bytes());
    varint(&mut raw, 1);
    raw.push(0x51);
    raw.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    varint(&mut raw, 1);
    raw.extend_from_slice(&sats.to_le_bytes());
    varint(&mut raw, script.len() as u64);
    raw.extend_from_slice(&script);
    raw.extend_from_slice(&0u32.to_le_bytes());
    let txid = Transaction::from_binary(&raw).unwrap().id();
    let mut beef = Beef::new();
    beef.merge_raw_tx(raw, None);
    let atomic = beef.to_binary_atomic(&txid).unwrap();
    let header = json!({
        "derivationPrefix": prefix,
        "derivationSuffix": suffix,
        "transaction": to_base64(&atomic),
    })
    .to_string();
    // The stand-in's key for the call: the Atomic BEEF's first 36 bytes.
    let key = hex::encode(&atomic[..36]);
    (header, key)
}

async fn client(url: &str, payer: &PrivateKey) -> Arc<AuthClient> {
    let c = AuthClient::new(url, payer).unwrap();
    c.prepare().await;
    Arc::new(c)
}

/// The 402's prefix and price.
async fn quote(c: &AuthClient) -> (String, u64) {
    quote_on(c, "/upload", UPLOAD_BODY).await
}

/// The 402's prefix and price for a paid route and body.
async fn quote_on(c: &AuthClient, route: &str, body: &str) -> (String, u64) {
    let r = c
        .request(
            "POST",
            route,
            "",
            body.as_bytes().to_vec(),
            vec![("content-type".into(), "application/json".into())],
        )
        .await
        .unwrap();
    assert_eq!(r.status, 402, "{}", String::from_utf8_lossy(&r.body));
    assert!(r.signed, "the 402 challenge is signed");
    let get = |n: &str| {
        r.headers
            .iter()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("no {n}"))
    };
    (
        get("x-bsv-payment-derivation-prefix"),
        get("x-bsv-payment-satoshis-required").parse().unwrap(),
    )
}

async fn pay(c: &AuthClient, header: &str) -> Answer {
    pay_on(c, "/upload", UPLOAD_BODY, header).await.0
}

/// A paid request: the answer and, when served, its body.
async fn pay_on(c: &AuthClient, route: &str, body: &str, header: &str) -> (Answer, Value) {
    let r = c
        .request(
            "POST",
            route,
            "",
            body.as_bytes().to_vec(),
            vec![
                ("content-type".into(), "application/json".into()),
                ("x-bsv-payment".into(), header.to_string()),
            ],
        )
        .await;
    let r = r.expect("an answer");
    let body: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
    let served = r.status == 200 && body["status"] == "success";
    if served && route == "/upload" && UNDER_TEST.get().map(String::as_str) == Some(c.base_url()) {
        let object = body["uploadURL"]
            .as_str()
            .and_then(|u| u.split("/cdn/").nth(1))
            .and_then(|o| o.split('?').next())
            .unwrap_or_default()
            .to_string();
        let custom_time = body["requiredHeaders"]["x-amz-meta-custom-time"].clone();
        UPLOADS
            .lock()
            .unwrap()
            .push(json!({ "object": object, "customTime": custom_time }));
    }
    let answer = Answer {
        status: r.status,
        code: if served {
            String::new()
        } else {
            body["code"].as_str().unwrap_or_default().to_string()
        },
        served,
        signed: r.signed,
    };
    (answer, body)
}

/// An advert the stand-in wallet holds for a fresh `uhrp://` URL: a
/// PushDrop of the advert's five fields and a signature (field 4 the
/// content length), output 0 of a transaction carried in a BEEF, tagged as
/// `/advertise` tags it. Returns the URL, the `uhrp_url_` tag, the expiry.
async fn seed_advert(
    stand_in: &str,
    uploader: &PublicKey,
    content_length: u64,
) -> (String, String, u64) {
    let (url, tag, expiry, _) =
        seed_advert_with(stand_in, uploader, content_length, Some(content_length)).await;
    (url, tag, expiry)
}

/// [`seed_advert`], its stored object `cdn/<object>` of `object_size` bytes
/// (none for `None`). Returns the object's key too.
async fn seed_advert_with(
    stand_in: &str,
    uploader: &PublicKey,
    content_length: u64,
    object_size: Option<u64>,
) -> (String, String, u64, String) {
    let hash = sha256(&random32());
    let mut payload = vec![0xce, 0x00];
    payload.extend_from_slice(&hash);
    let check = sha256d(&payload);
    payload.extend_from_slice(&check[..4]);
    let url = format!("uhrp://{}", to_base58(&payload));
    let expiry = 1_900_000_000u64 + u64::from(random32()[0]) * 1000;
    let object = format!("cdn-object-{}", hex::encode(&random32()[..8]));
    let field_int = |n: u64| {
        let mut w = Writer::new();
        w.write_var_int(n);
        w.into_bytes()
    };
    let lock = PushDrop::new(
        PrivateKey::random().public_key(),
        vec![
            PrivateKey::random().public_key().to_compressed().to_vec(),
            hash.to_vec(),
            format!("https://files.stand-in.test/cdn/{object}").into_bytes(),
            field_int(expiry),
            field_int(content_length),
            vec![0x30; 70],
        ],
    )
    .lock();
    let script = lock.to_binary();
    let mut raw = Vec::new();
    raw.extend_from_slice(&1u32.to_le_bytes());
    varint(&mut raw, 1);
    raw.extend_from_slice(&random32());
    raw.extend_from_slice(&0u32.to_le_bytes());
    varint(&mut raw, 1);
    raw.push(0x51);
    raw.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    varint(&mut raw, 1);
    raw.extend_from_slice(&1u64.to_le_bytes());
    varint(&mut raw, script.len() as u64);
    raw.extend_from_slice(&script);
    raw.extend_from_slice(&0u32.to_le_bytes());
    let txid = Transaction::from_binary(&raw).unwrap().id();
    let mut beef = Beef::new();
    beef.merge_raw_tx(raw, None);
    let tag = format!("uhrp_url_{}", hex::encode(url.as_bytes()));
    let tags = vec![
        format!("uploader_identity_key_{}", uploader.to_hex()),
        tag.clone(),
        format!("object_identifier_{}", hex::encode(object.as_bytes())),
        format!("expiry_time_{expiry}"),
    ];
    let seeded: Value = reqwest::Client::new()
        .post(format!("{stand_in}/advert"))
        .json(&json!({
            "tag": tag,
            "txid": txid,
            "vout": 0,
            "lockingScript": hex::encode(&script),
            "tags": tags,
            "beef": beef.to_binary(),
            "object": object_size.map(|_| format!("cdn/{object}")),
            "size": object_size,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(seeded["seeded"], tag);
    (url, tag, expiry, format!("cdn/{object}"))
}

/// Set the stand-in's knob `name` (empty for the normal answer).
async fn knob(stand_in: &str, name: &str, value: &str) {
    reqwest::get(format!("{stand_in}/knob?{name}={value}"))
        .await
        .unwrap();
}

/// The stored object's etag and upload time, as the stand-in reads them
/// from the bucket the Worker reads.
async fn object(stand_in: &str, key: &str) -> Value {
    reqwest::get(format!("{stand_in}/object?key={key}"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// The stand-in's advert for a tag as it holds it, and its call counts.
async fn advert_raw(stand_in: &str, tag: &str) -> Value {
    reqwest::get(format!("{stand_in}/advert?tag={tag}"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn releases(stand_in: &str, tag: &str) -> u64 {
    advert_raw(stand_in, tag).await["calls"]["release"]
        .as_u64()
        .unwrap()
}

async fn finds(stand_in: &str, txid: &str) -> u64 {
    let v: Value = reqwest::get(format!("{stand_in}/finds?txid={txid}"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    v["finds"].as_u64().unwrap()
}

/// Quote, pay and send one `/renew` of `uhrp` for `minutes`: the answer,
/// its body and the satoshis paid.
async fn renew_paid(
    c: &AuthClient,
    payer: &PrivateKey,
    server: &PublicKey,
    uhrp: &str,
    minutes: u64,
) -> (Answer, Value, u64) {
    let body = json!({ "uhrpUrl": uhrp, "additionalMinutes": minutes }).to_string();
    let (prefix, sats) = quote_on(c, "/renew", &body).await;
    let (h, _) = payment(payer, server, &prefix, sats);
    let (answer, value) = pay_on(c, "/renew", &body, &h).await;
    (answer, value, sats)
}

/// A request to a paid route with no payment header: the answer.
async fn unpaid_on(c: &AuthClient, route: &str, body: &str) -> Answer {
    let r = c
        .request(
            "POST",
            route,
            "",
            body.as_bytes().to_vec(),
            vec![("content-type".into(), "application/json".into())],
        )
        .await
        .expect("an answer");
    let value: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
    let served = r.status == 200 && value["status"] == "success";
    Answer {
        status: r.status,
        code: if served {
            String::new()
        } else {
            value["code"].as_str().unwrap_or_default().to_string()
        },
        served,
        signed: r.signed,
    }
}

/// The stand-in's advert for a tag: its expiry (from its tag) and the
/// number of `createAction` and `processAction` calls it saw.
async fn advert(stand_in: &str, tag: &str) -> (u64, u64, u64) {
    let v: Value = reqwest::get(format!("{stand_in}/advert?tag={tag}"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let expiry = v["advert"]["tags"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t.as_str()?.strip_prefix("expiry_time_")?.parse().ok())
        .next()
        .unwrap();
    (
        expiry,
        v["calls"]["createAction"].as_u64().unwrap(),
        v["calls"]["processAction"].as_u64().unwrap(),
    )
}

async fn submits(stand_in: &str) -> u64 {
    let v: Value = reqwest::get(format!("{stand_in}/submits"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    v["submits"].as_u64().unwrap()
}

async fn calls(stand_in: &str, key: &str) -> u64 {
    let v: Value = reqwest::get(format!("{stand_in}/calls?tx={key}"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    v["calls"].as_u64().unwrap()
}

async fn wallet_fails(stand_in: &str, on: bool) {
    reqwest::get(format!("{stand_in}/mode?fail={}", u8::from(on)))
        .await
        .unwrap();
}

/// A signed refusal.
fn refused(status: u16, code: &str) -> Answer {
    Answer {
        status,
        code: code.into(),
        served: false,
        signed: true,
    }
}

/// An unsigned refusal.
fn unsigned(status: u16, code: &str) -> Answer {
    Answer {
        signed: false,
        ..refused(status, code)
    }
}

async fn wallet_rejects(stand_in: &str, on: bool) {
    reqwest::get(format!("{stand_in}/mode?reject={}", u8::from(on)))
        .await
        .unwrap();
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (url, old_url, stand_in) = (&args[1], &args[2], &args[3]);
    let (no_binding, no_table) = (&args[4], &args[5]);
    UNDER_TEST.set(url.clone()).unwrap();
    let payer = PrivateKey::random();
    let first = client(url, &payer).await;
    let server = PublicKey::from_hex(&first.server_identity_hex().await.unwrap()).unwrap();

    // 1. One payment in N simultaneous requests.
    for n in [2usize, 4, 16] {
        let (prefix, sats) = quote(&first).await;
        let (header, key) = payment(&payer, &server, &prefix, sats);
        let mut clients = Vec::new();
        for _ in 0..n {
            let c = client(url, &payer).await;
            c.server_identity_hex().await.unwrap();
            clients.push(c);
        }
        let answers: Vec<Answer> = futures_join(clients.iter().map(|c| {
            let c = c.clone();
            let h = header.clone();
            async move { pay(&c, &h).await }
        }))
        .await;
        let served = answers.iter().filter(|a| **a == served()).count();
        let replayed = answers
            .iter()
            .filter(|a| **a == refused(409, "ERR_PAYMENT_REPLAYED"))
            .count();
        let wallet = calls(stand_in, &key).await;
        println!(
            "N={n} simultaneous requests, one payment: {served} served, {replayed} signed 409 ERR_PAYMENT_REPLAYED, {} other; wallet asked {wallet}",
            n - served - replayed
        );
        assert_eq!((served, replayed, wallet), (1, n - 1, 1), "{answers:?}");
    }

    // 2. Two transactions under one prefix at once.
    let mut rounds = 0;
    for _ in 0..8 {
        let (prefix, sats) = quote(&first).await;
        let (h1, k1) = payment(&payer, &server, &prefix, sats);
        let (h2, k2) = payment(&payer, &server, &prefix, sats);
        let (c1, c2) = (client(url, &payer).await, client(url, &payer).await);
        c1.server_identity_hex().await.unwrap();
        c2.server_identity_hex().await.unwrap();
        let (a1, a2) = tokio::join!(pay(&c1, &h1), pay(&c2, &h2));
        let mut got = [a1.clone(), a2.clone()];
        got.sort_by_key(|a| format!("{a:?}"));
        assert!(
            got.contains(&served()) && got.contains(&refused(400, "ERR_PAYMENT_INVALID")),
            "{a1:?} {a2:?}"
        );
        assert_eq!(calls(stand_in, &k1).await + calls(stand_in, &k2).await, 1);
        rounds += 1;
    }
    println!(
        "two transactions under one prefix at once, {rounds} rounds: each 1 served + 1 signed 400 ERR_PAYMENT_INVALID; wallet asked once each round"
    );

    // 3. Old build first, then this build; this build first, then the old.
    let old = client(old_url, &payer).await;
    old.server_identity_hex().await.unwrap();
    {
        let (prefix, sats) = quote(&old).await;
        let (h, k) = payment(&payer, &server, &prefix, sats);
        assert_eq!(pay(&old, &h).await, served());
        assert_eq!(pay(&first, &h).await, refused(409, "ERR_PAYMENT_REPLAYED"));
        let (h2, k2) = payment(&payer, &server, &prefix, sats);
        assert_eq!(pay(&first, &h2).await, refused(400, "ERR_PAYMENT_INVALID"));
        assert_eq!(
            (calls(stand_in, &k).await, calls(stand_in, &k2).await),
            (1, 0)
        );
        println!("a prefix the old build served: this build answers its transaction 409, another 400; no wallet call");
    }
    {
        let (prefix, sats) = quote(&first).await;
        let (h, k) = payment(&payer, &server, &prefix, sats);
        assert_eq!(pay(&first, &h).await, served());
        let again = pay(&old, &h).await;
        let (h2, k2) = payment(&payer, &server, &prefix, sats);
        let other = pay(&old, &h2).await;
        assert_eq!(again, unsigned(400, "ERR_INVALID_DERIVATION_PREFIX"));
        assert_eq!(other, unsigned(400, "ERR_INVALID_DERIVATION_PREFIX"));
        assert_eq!(
            (calls(stand_in, &k).await, calls(stand_in, &k2).await),
            (1, 0)
        );
        println!("a prefix this build served: the old build refuses its transaction ({again:?}) and another ({other:?}); no wallet call");
    }

    // 4. A wallet error releases the claim to the same transaction.
    let wallet_error = unsigned(400, "ERR_PAYMENT_FAILED");
    {
        let (prefix, sats) = quote(&first).await;
        let (h, k) = payment(&payer, &server, &prefix, sats);
        wallet_fails(stand_in, true).await;
        let failed = pay(&first, &h).await;
        wallet_fails(stand_in, false).await;
        assert_eq!(failed, wallet_error);
        assert_eq!(calls(stand_in, &k).await, 1);
        let (h2, k2) = payment(&payer, &server, &prefix, sats);
        assert_eq!(pay(&first, &h2).await, refused(400, "ERR_PAYMENT_INVALID"));
        assert_eq!(pay(&first, &h).await, served());
        assert_eq!(pay(&first, &h).await, refused(409, "ERR_PAYMENT_REPLAYED"));
        assert_eq!(
            (calls(stand_in, &k).await, calls(stand_in, &k2).await),
            (2, 0)
        );
        println!(
            "a wallet error (the door's unsigned 400 ERR_PAYMENT_FAILED): another transaction the signed 400; the same transaction served on its retry, then the signed 409; wallet asked twice for it, never for the other"
        );
    }
    // A wallet error on the old build, then this build.
    {
        let (prefix, sats) = quote(&old).await;
        let (h, k) = payment(&payer, &server, &prefix, sats);
        wallet_fails(stand_in, true).await;
        let failed = pay(&old, &h).await;
        wallet_fails(stand_in, false).await;
        assert_eq!(failed, wallet_error);
        let (h2, k2) = payment(&payer, &server, &prefix, sats);
        assert_eq!(pay(&first, &h2).await, refused(400, "ERR_PAYMENT_INVALID"));
        assert_eq!(pay(&first, &h).await, served());
        assert_eq!(pay(&first, &h).await, refused(409, "ERR_PAYMENT_REPLAYED"));
        assert_eq!(pay(&first, &h2).await, refused(400, "ERR_PAYMENT_INVALID"));
        assert_eq!(
            (calls(stand_in, &k).await, calls(stand_in, &k2).await),
            (2, 0)
        );
        println!(
            "a wallet error on the old build, then this build: another transaction under the prefix the signed 400; the released transaction served once, then the signed 409; wallet asked twice for it, never for the other"
        );
    }
    // A wallet error on this build, then the old build, then this build.
    {
        let (prefix, sats) = quote(&first).await;
        let (h, k) = payment(&payer, &server, &prefix, sats);
        wallet_fails(stand_in, true).await;
        let failed = pay(&first, &h).await;
        wallet_fails(stand_in, false).await;
        assert_eq!(failed, wallet_error);
        let (h2, k2) = payment(&payer, &server, &prefix, sats);
        assert_eq!(pay(&old, &h).await, served());
        let old_again = pay(&old, &h).await;
        let old_other = pay(&old, &h2).await;
        assert_eq!(old_again, unsigned(400, "ERR_INVALID_DERIVATION_PREFIX"));
        assert_eq!(old_other, unsigned(400, "ERR_INVALID_DERIVATION_PREFIX"));
        assert_eq!(pay(&first, &h).await, refused(409, "ERR_PAYMENT_REPLAYED"));
        assert_eq!(pay(&first, &h2).await, refused(400, "ERR_PAYMENT_INVALID"));
        assert_eq!(
            (calls(stand_in, &k).await, calls(stand_in, &k2).await),
            (2, 0)
        );
        println!(
            "a wallet error on this build, then the old build: it serves the released transaction once, then refuses it and another; back on this build the prefix is refused (signed 409, another the signed 400); wallet asked twice for it, never for the other"
        );
    }
    // A wallet rejection keeps the claim; a malformed header is the door's.
    {
        let (prefix, sats) = quote(&first).await;
        let (h, k) = payment(&payer, &server, &prefix, sats);
        wallet_rejects(stand_in, true).await;
        let rejected = pay(&first, &h).await;
        wallet_rejects(stand_in, false).await;
        assert_eq!(rejected, unsigned(402, "ERR_PAYMENT_FAILED"));
        assert_eq!(pay(&first, &h).await, refused(409, "ERR_PAYMENT_REPLAYED"));
        assert_eq!(calls(stand_in, &k).await, 1);
        assert_eq!(
            pay(&first, "not json").await,
            unsigned(400, "ERR_MALFORMED_PAYMENT")
        );
        println!(
            "a wallet rejection: the door's unsigned 402 ERR_PAYMENT_FAILED with a fresh challenge, then the signed 409; wallet asked once; a malformed payment header: the door's unsigned 400 ERR_MALFORMED_PAYMENT"
        );
    }
    // 5. /renew, paid.
    let mut granted = Vec::new();
    {
        let minutes = 90u64;
        let content_length = 2_000_000u64;
        let (uhrp, tag, expiry, key) = seed_advert_with(
            stand_in,
            &payer.public_key(),
            content_length,
            Some(content_length),
        )
        .await;
        let stored = object(stand_in, &key).await;
        assert_eq!(stored["exists"], true);
        let body = json!({ "uhrpUrl": uhrp, "additionalMinutes": minutes }).to_string();
        let (prefix, sats) = quote_on(&first, "/renew", &body).await;
        let (h, k) = payment(&payer, &server, &prefix, sats);
        let before = submits(stand_in).await;
        let (renewed, answer) = pay_on(&first, "/renew", &body, &h).await;
        assert_eq!(renewed, served(), "{answer}");
        assert_eq!(answer["overlayAdmitted"], true, "{answer}");
        // The stored object is untouched: the same etag and upload time.
        assert_eq!(object(stand_in, &key).await, stored);
        let new_expiry = expiry + minutes * 60;
        assert_eq!(answer["prevExpiryTime"].as_u64(), Some(expiry), "{answer}");
        assert_eq!(
            answer["newExpiryTime"].as_u64(),
            Some(new_expiry),
            "{answer}"
        );
        assert_eq!(answer["amount"].as_u64(), Some(sats), "{answer}");
        assert_eq!(advert(stand_in, &tag).await, (new_expiry, 1, 1));
        assert_eq!(submits(stand_in).await, before + 1);
        // The same payment again: the signed 409, no second renewal.
        let (again, _) = pay_on(&first, "/renew", &body, &h).await;
        assert_eq!(again, refused(409, "ERR_PAYMENT_REPLAYED"));
        assert_eq!(advert(stand_in, &tag).await, (new_expiry, 1, 1));
        // Another transaction under the used prefix: the signed 400.
        let (h2, k2) = payment(&payer, &server, &prefix, sats);
        let (other, _) = pay_on(&first, "/renew", &body, &h2).await;
        assert_eq!(other, refused(400, "ERR_PAYMENT_INVALID"));
        assert_eq!(advert(stand_in, &tag).await, (new_expiry, 1, 1));
        assert_eq!(
            (calls(stand_in, &k).await, calls(stand_in, &k2).await),
            (1, 0)
        );
        assert_eq!(submits(stand_in).await, before + 1);
        println!(
            "/renew paid: served once (expiry {expiry} -> {new_expiry}, {minutes} minutes, {sats} sats); the same payment again: signed 409 ERR_PAYMENT_REPLAYED, the expiry unchanged, one createAction and one processAction, overlayAdmitted true, the stored object's etag and upload time unchanged; another transaction under the prefix: signed 400 ERR_PAYMENT_INVALID; wallet asked once"
        );
        granted.push(json!({
            "uhrpUrl": uhrp, "minutes": minutes, "expiry": new_expiry,
            "satoshis": sats, "payer": payer.public_key().to_hex(), "fileSize": content_length,
            "advert": "admitted",
        }));
    }
    for n in [2usize, 4, 16] {
        let minutes = 30u64;
        let (uhrp, tag, expiry) = seed_advert(stand_in, &payer.public_key(), 1_000_000).await;
        let body = json!({ "uhrpUrl": uhrp, "additionalMinutes": minutes }).to_string();
        let (prefix, sats) = quote_on(&first, "/renew", &body).await;
        let (header, key) = payment(&payer, &server, &prefix, sats);
        let mut clients = Vec::new();
        for _ in 0..n {
            let c = client(url, &payer).await;
            c.server_identity_hex().await.unwrap();
            clients.push(c);
        }
        let answers: Vec<Answer> = futures_join(clients.iter().map(|c| {
            let c = c.clone();
            let (h, b) = (header.clone(), body.clone());
            async move { pay_on(&c, "/renew", &b, &h).await.0 }
        }))
        .await;
        let served = answers.iter().filter(|a| **a == served()).count();
        let replayed = answers
            .iter()
            .filter(|a| **a == refused(409, "ERR_PAYMENT_REPLAYED"))
            .count();
        let wallet = calls(stand_in, &key).await;
        let (now, creates, processes) = advert(stand_in, &tag).await;
        println!(
            "/renew N={n} simultaneous requests, one payment: {served} served, {replayed} signed 409 ERR_PAYMENT_REPLAYED, {} other; renewals {processes} (createAction {creates}), expiry {expiry} -> {now}; wallet asked {wallet}",
            n - served - replayed
        );
        assert_eq!((served, replayed, wallet), (1, n - 1, 1), "{answers:?}");
        assert_eq!((now, creates, processes), (expiry + minutes * 60, 1, 1));
        granted.push(json!({
            "uhrpUrl": uhrp, "minutes": minutes, "expiry": now,
            "satoshis": sats, "payer": payer.public_key().to_hex(), "fileSize": 1_000_000,
            "advert": "admitted",
        }));
    }
    let paid_rows = renew_outcomes(stand_in, url, &first, &payer, &server, &mut granted).await;

    // 6. No CLAIMS binding; the binding and no tables.
    for (name, build) in [
        ("no CLAIMS binding", no_binding),
        ("CLAIMS bound, no tables", no_table),
    ] {
        let c = client(build, &payer).await;
        let server_b = PublicKey::from_hex(&c.server_identity_hex().await.unwrap()).unwrap();
        let (prefix, sats) = quote(&c).await;
        let (h, k) = payment(&payer, &server_b, &prefix, sats);
        let upload = pay(&c, &h).await;
        let again = pay(&c, &h).await;
        let (uhrp, tag, expiry) = seed_advert(stand_in, &payer.public_key(), 1_000_000).await;
        let body = json!({ "uhrpUrl": uhrp, "additionalMinutes": 30 }).to_string();
        let (rp, rs) = quote_on(&c, "/renew", &body).await;
        let (rh, rk) = payment(&payer, &server_b, &rp, rs);
        let (renew, _) = pay_on(&c, "/renew", &body, &rh).await;
        let unavailable = refused(503, "ERR_PAYMENT_UNAVAILABLE");
        assert_eq!(
            (&upload, &again, &renew),
            (&unavailable, &unavailable, &unavailable)
        );
        assert_eq!(
            (calls(stand_in, &k).await, calls(stand_in, &rk).await),
            (0, 0)
        );
        assert_eq!(advert(stand_in, &tag).await, (expiry, 0, 0));
        println!(
            "{name}: /upload paid twice: signed 503 ERR_PAYMENT_UNAVAILABLE both times; /renew paid: signed 503 ERR_PAYMENT_UNAVAILABLE, no renewal (createAction 0); wallet asked 0; nothing served"
        );
    }
    // A prefix with a key-value record (served by this build), sent to the
    // build with no tables: the store meets the fault before the gate.
    {
        let (prefix, sats) = quote(&first).await;
        let (h, k) = payment(&payer, &server, &prefix, sats);
        assert_eq!(pay(&first, &h).await, served());
        let c = client(no_table, &payer).await;
        c.server_identity_hex().await.unwrap();
        let (h2, k2) = payment(&payer, &server, &prefix, sats);
        let unavailable = unsigned(503, "ERR_PAYMENT_UNAVAILABLE");
        assert_eq!(pay(&c, &h).await, unavailable);
        assert_eq!(pay(&c, &h2).await, unavailable);
        assert_eq!(
            (calls(stand_in, &k).await, calls(stand_in, &k2).await),
            (1, 0)
        );
        println!(
            "CLAIMS bound, no tables, a prefix with a key-value record: the door's unsigned 503 ERR_PAYMENT_UNAVAILABLE for its transaction and another; wallet asked 0"
        );
    }
    // A prefix the old build released (a wallet error there), sent to the
    // build with no tables: its own transaction reaches the gate (the gate's
    // signed 503); another transaction meets the fault before the gate (the
    // door's unsigned 503).
    {
        let (prefix, sats) = quote(&old).await;
        let (h, k) = payment(&payer, &server, &prefix, sats);
        wallet_fails(stand_in, true).await;
        assert_eq!(pay(&old, &h).await, unsigned(400, "ERR_PAYMENT_FAILED"));
        wallet_fails(stand_in, false).await;
        let c = client(no_table, &payer).await;
        c.server_identity_hex().await.unwrap();
        let (h2, k2) = payment(&payer, &server, &prefix, sats);
        assert_eq!(pay(&c, &h).await, refused(503, "ERR_PAYMENT_UNAVAILABLE"));
        assert_eq!(pay(&c, &h2).await, unsigned(503, "ERR_PAYMENT_UNAVAILABLE"));
        assert_eq!(
            (calls(stand_in, &k).await, calls(stand_in, &k2).await),
            (1, 0)
        );
        println!(
            "CLAIMS bound, no tables, a prefix with a released:<txid> record: its transaction the gate's signed 503 ERR_PAYMENT_UNAVAILABLE, another the door's unsigned 503; wallet asked 0 here"
        );
    }

    // 7. A carried release frees only its own claim.
    {
        let wallet_error = unsigned(400, "ERR_PAYMENT_FAILED");
        let rounds: usize = std::env::var("CARRIED_ROUNDS")
            .ok()
            .and_then(|r| r.parse().ok())
            .unwrap_or(12);
        let (mut total, mut more_than_once, mut others_served) = (0, 0, 0);
        for (na, nb, others_first) in [
            (1usize, 1usize, true),
            (1, 1, false),
            (1, 7, true),
            (1, 7, false),
            (4, 4, true),
            (4, 4, false),
        ] {
            let (mut twice, mut never, mut wallet) = (0, 0, 0u64);
            let mut all = Vec::new();
            for _ in 0..rounds {
                // Released by the old build: a wallet error there.
                let (prefix, sats) = quote(&old).await;
                let (h, k) = payment(&payer, &server, &prefix, sats);
                wallet_fails(stand_in, true).await;
                let failed = pay(&old, &h).await;
                wallet_fails(stand_in, false).await;
                assert_eq!(failed, wallet_error);
                let others: Vec<(String, String)> = (0..nb)
                    .map(|_| payment(&payer, &server, &prefix, sats))
                    .collect();
                let cs = clients(url, &payer, na + nb).await;
                let mine = (0..na).map(|_| (true, h.clone()));
                let theirs = others.iter().map(|(x, _)| (false, x.clone()));
                let order: Vec<(bool, String)> = if others_first {
                    theirs.chain(mine).collect()
                } else {
                    mine.chain(theirs).collect()
                };
                let answers: Vec<(bool, Answer)> =
                    futures_join(cs.iter().zip(order).map(|(c, (is_t, header))| {
                        let c = c.clone();
                        async move { (is_t, pay(&c, &header).await) }
                    }))
                    .await;
                let mut t_served = answers.iter().filter(|(t, a)| *t && a.served).count();
                others_served += answers.iter().filter(|(t, a)| !*t && a.served).count();
                all.extend(answers.into_iter().map(|(_, a)| a));
                for _ in 0..2 {
                    let a = pay(&first, &h).await;
                    if a.served {
                        t_served += 1;
                    }
                    all.push(a);
                }
                if t_served > 1 {
                    twice += 1;
                }
                if t_served == 0 {
                    never += 1;
                }
                wallet += calls(stand_in, &k).await;
                for (_, other) in &others {
                    assert_eq!(calls(stand_in, other).await, 0);
                }
            }
            total += rounds;
            more_than_once += twice;
            println!(
                "a carried release, t x{na} and others x{nb} at once ({} first): {rounds} rounds; t served more than once in {twice}, never in {never}; wallet asked for t {wallet} (the old build's {rounds} included); answers here: {}",
                if others_first { "others" } else { "t" },
                tally(&all)
            );
        }
        println!(
            "a carried release: {total} rounds; t served more than once in {more_than_once}; another transaction served {others_served}"
        );
        assert_eq!((more_than_once, others_served), (0, 0));
    }

    println!("renew-grants {}", serde_json::Value::Array(granted));
    println!("renew-paid {}", serde_json::Value::Array(paid_rows));
    println!(
        "upload-grants {}",
        serde_json::Value::Array(UPLOADS.lock().unwrap().clone())
    );
    println!("race: ok");
}

/// 5b. `/renew`'s outcomes: a stored object missing or of another size (a
/// free 404, nothing claimed); a renewal served with the overlay refusing or
/// faulting (the 200, `overlayAdmitted` false; a refusal never submitted
/// again, a fault re-submitted by the queue, four deliveries in all); a
/// renewal not made at `createAction` after the one more try, at the
/// signature (the action released) and at `processAction` (refused, or
/// `failed`); no word (the answer lost, or the transaction untaken); and
/// two payers of one file at once, both served. Returns the rows the
/// payments not served leave (`renew-paid`), each with the payment's txid
/// its answer names.
async fn renew_outcomes(
    stand_in: &str,
    url: &str,
    first: &AuthClient,
    payer: &PrivateKey,
    server: &PublicKey,
    granted: &mut Vec<Value>,
) -> Vec<Value> {
    let pk = payer.public_key();
    let mut paid_rows = Vec::new();
    let minutes = 30u64;
    let size = 1_000_000u64;
    let grant = |uhrp: &str, expiry: u64, sats: u64, advert: &str| {
        json!({
            "uhrpUrl": uhrp, "minutes": minutes, "expiry": expiry,
            "satoshis": sats, "payer": pk.to_hex(), "fileSize": size, "advert": advert,
        })
    };

    // A missing object, and an object of another size: a free 404.
    {
        let (uhrp, tag, expiry, _) = seed_advert_with(stand_in, &pk, size, None).await;
        let body = json!({ "uhrpUrl": uhrp, "additionalMinutes": minutes }).to_string();
        let answer = unpaid_on(first, "/renew", &body).await;
        assert_eq!(answer, refused(404, "ERR_FILE_NOT_FOUND"));
        // A payment sent with it is not claimed: the same payment then
        // serves the route it was quoted for.
        let (prefix, sats) = quote(first).await;
        let (h, k) = payment(payer, server, &prefix, sats);
        let (with_payment, _) = pay_on(first, "/renew", &body, &h).await;
        assert_eq!(with_payment, refused(404, "ERR_FILE_NOT_FOUND"));
        assert_eq!(calls(stand_in, &k).await, 0);
        assert_eq!(advert(stand_in, &tag).await, (expiry, 0, 0));
        assert_eq!(pay(first, &h).await, served());
        let (uhrp2, tag2, expiry2, _) = seed_advert_with(stand_in, &pk, size, Some(size - 1)).await;
        let body2 = json!({ "uhrpUrl": uhrp2, "additionalMinutes": minutes }).to_string();
        let other_size = unpaid_on(first, "/renew", &body2).await;
        assert_eq!(other_size, refused(404, "ERR_FILE_NOT_FOUND"));
        assert_eq!(advert(stand_in, &tag2).await, (expiry2, 0, 0));
        println!(
            "/renew of an advert whose object is missing: the signed 404 ERR_FILE_NOT_FOUND before any 402; with a payment header: the same 404, the wallet not asked, the payment then served on /upload (nothing claimed); an object of another size: the same 404; no createAction"
        );
    }

    // Served, the overlay refusing: never submitted again.
    {
        let (uhrp, tag, expiry) = seed_advert(stand_in, &pk, size).await;
        knob(stand_in, "overlay", "refuse").await;
        let before = submits(stand_in).await;
        let (answer, body, sats) = renew_paid(first, payer, server, &uhrp, minutes).await;
        knob(stand_in, "overlay", "").await;
        assert_eq!(answer, served(), "{body}");
        assert_eq!(body["overlayAdmitted"], false, "{body}");
        assert_eq!(advert(stand_in, &tag).await, (expiry + minutes * 60, 1, 1));
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        assert_eq!(submits(stand_in).await, before + 1);
        granted.push(grant(&uhrp, expiry + minutes * 60, sats, "refused"));
        println!(
            "/renew with the overlay refusing: the signed 200, overlayAdmitted false; one submit and no other"
        );
    }

    // Served, the overlay faulting: the queue's four deliveries, then no more.
    {
        let (uhrp, tag, expiry) = seed_advert(stand_in, &pk, size).await;
        knob(stand_in, "overlay", "fault").await;
        let before = submits(stand_in).await;
        let (answer, body, sats) = renew_paid(first, payer, server, &uhrp, minutes).await;
        assert_eq!(answer, served(), "{body}");
        assert_eq!(body["overlayAdmitted"], false, "{body}");
        assert_eq!(advert(stand_in, &tag).await, (expiry + minutes * 60, 1, 1));
        let mut waited = 0;
        while submits(stand_in).await < before + 5 && waited < 240 {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            waited += 1;
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        knob(stand_in, "overlay", "").await;
        let submitted = submits(stand_in).await - before;
        assert_eq!(submitted, 5, "the route's submit and four deliveries");
        granted.push(grant(&uhrp, expiry + minutes * 60, sats, "not_admitted"));
        println!(
            "/renew with the overlay faulting: the signed 200, overlayAdmitted false; the route's submit, then the queue's re-submit delivered {} times ({waited}s), then none",
            submitted - 1
        );
    }

    // Not made at createAction, after the one more try.
    {
        let (uhrp, tag, expiry) = seed_advert(stand_in, &pk, size).await;
        knob(stand_in, "create", "spent").await;
        let (answer, body, _) = renew_paid(first, payer, server, &uhrp, minutes).await;
        knob(stand_in, "create", "").await;
        assert_eq!(answer, refused(500, "ERR_RENEWAL_NOT_MADE"), "{body}");
        let txid = body["paymentTxid"].as_str().unwrap().to_string();
        assert_eq!(
            body["description"],
            format!("The payment was taken. The renewal was not made. It is recorded under {txid}. A new payment renews the file.")
        );
        assert_eq!(advert(stand_in, &tag).await, (expiry, 2, 0));
        paid_rows.push(
            json!({ "paymentTxid": txid, "status": 500, "outcome": "not_made", "renewing": false }),
        );
        println!(
            "/renew with createAction refusing the spent advert: the one re-read and one more try (createAction 2), then the signed 500 ERR_RENEWAL_NOT_MADE naming the payment; no processAction; the advert unchanged"
        );
    }

    // Not made at the signature: the action released.
    {
        let (uhrp, tag, expiry) = seed_advert(stand_in, &pk, size).await;
        knob(stand_in, "create", "unsignable").await;
        let (answer, body, _) = renew_paid(first, payer, server, &uhrp, minutes).await;
        knob(stand_in, "create", "").await;
        assert_eq!(answer, refused(500, "ERR_RENEWAL_NOT_MADE"), "{body}");
        assert_eq!(advert(stand_in, &tag).await, (expiry, 1, 0));
        assert_eq!(releases(stand_in, &tag).await, 1);
        paid_rows.push(json!({ "paymentTxid": body["paymentTxid"], "status": 500, "outcome": "not_made", "renewing": false }));
        // Released: a new payment renews it.
        let (again, body2, sats) = renew_paid(first, payer, server, &uhrp, minutes).await;
        assert_eq!(again, served(), "{body2}");
        assert_eq!(advert(stand_in, &tag).await, (expiry + minutes * 60, 2, 1));
        granted.push(grant(&uhrp, expiry + minutes * 60, sats, "admitted"));
        println!(
            "/renew failing at the signature: the action released once, the signed 500 ERR_RENEWAL_NOT_MADE, no processAction; a new payment then renews the advert"
        );
    }

    // Not made at processAction: refused (the action released), or failed.
    for (word, released) in [("refuse", 1u64), ("failed", 0)] {
        let (uhrp, tag, expiry) = seed_advert(stand_in, &pk, size).await;
        knob(stand_in, "process", word).await;
        let (answer, body, _) = renew_paid(first, payer, server, &uhrp, minutes).await;
        knob(stand_in, "process", "").await;
        assert_eq!(answer, refused(500, "ERR_RENEWAL_NOT_MADE"), "{body}");
        assert_eq!(advert(stand_in, &tag).await, (expiry, 1, 1));
        assert_eq!(releases(stand_in, &tag).await, released);
        paid_rows.push(json!({ "paymentTxid": body["paymentTxid"], "status": 500, "outcome": "not_made", "renewing": true }));
        println!(
            "/renew with processAction {word}: the signed 500 ERR_RENEWAL_NOT_MADE; actions released {released}; the advert unchanged"
        );
    }

    // No word: the answer lost, or the transaction not taken.
    for (word, asked) in [("lost", 0u64), ("untaken", 1)] {
        let (uhrp, tag, expiry) = seed_advert(stand_in, &pk, size).await;
        knob(stand_in, "process", word).await;
        let (answer, body, sats) = renew_paid(first, payer, server, &uhrp, minutes).await;
        knob(stand_in, "process", "").await;
        assert_eq!(answer, refused(502, "ERR_RENEWAL_UNCONFIRMED"), "{body}");
        let txid = body["paymentTxid"].as_str().unwrap().to_string();
        assert_eq!(
            body["description"],
            format!("The payment was taken. This host has no word yet that the renewing transaction was sent. It is recorded under {txid}.")
        );
        // The wallet holds the renewing transaction (the advert moved).
        assert_eq!(advert(stand_in, &tag).await, (expiry + minutes * 60, 1, 1));
        let renewing = advert_raw(stand_in, &tag).await["advert"]["txid"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(finds(stand_in, &renewing).await, asked);
        paid_rows.push(json!({
            "paymentTxid": txid, "status": 502, "outcome": "no_word", "renewing": true,
            "renewingTxid": renewing, "uhrpUrl": uhrp, "expiry": expiry + minutes * 60,
            "satoshis": sats, "word": word,
        }));
        println!(
            "/renew with processAction {word}: the signed 502 ERR_RENEWAL_UNCONFIRMED naming the payment; findProvenTxReqs {asked}"
        );
    }

    // Two payers of one file at once: both served, two extensions.
    {
        let (uhrp, tag, expiry) = seed_advert(stand_in, &pk, size).await;
        let body = json!({ "uhrpUrl": uhrp, "additionalMinutes": minutes }).to_string();
        let two = clients(url, payer, 2).await;
        let mut headers = Vec::new();
        for c in &two {
            let (prefix, sats) = quote_on(c, "/renew", &body).await;
            headers.push((payment(payer, server, &prefix, sats).0, sats));
        }
        let answers = futures_join(two.iter().zip(headers.iter()).map(|(c, (h, _))| {
            let (c, h, b) = (c.clone(), h.clone(), body.clone());
            async move { pay_on(&c, "/renew", &b, &h).await }
        }))
        .await;
        for (a, v) in &answers {
            assert_eq!(*a, served(), "{v}");
        }
        let mut expiries: Vec<u64> = answers
            .iter()
            .map(|(_, v)| v["newExpiryTime"].as_u64().unwrap())
            .collect();
        expiries.sort_unstable();
        let (one, both) = (expiry + minutes * 60, expiry + 2 * minutes * 60);
        assert_eq!(expiries, vec![one, both]);
        assert_eq!(advert(stand_in, &tag).await, (both, 3, 2));
        for (expiry, (_, sats)) in expiries.iter().zip(headers.iter()) {
            granted.push(grant(&uhrp, *expiry, *sats, "admitted"));
        }
        println!(
            "two payers of one file at once: both served (expiry {expiry} -> {one} -> {both}); createAction 3 (the second payer's one more try), processAction 2"
        );
    }
    paid_rows
}

/// `n` clients of `url`, each with its session open.
async fn clients(url: &str, payer: &PrivateKey, n: usize) -> Vec<Arc<AuthClient>> {
    let mut out = Vec::new();
    for _ in 0..n {
        let c = client(url, payer).await;
        c.server_identity_hex().await.unwrap();
        out.push(c);
    }
    out
}

/// The answers, counted by kind (`s` signed, `u` unsigned).
fn tally(answers: &[Answer]) -> String {
    let mut by: std::collections::BTreeMap<String, usize> = Default::default();
    for a in answers {
        let kind = if a.served {
            "served".to_string()
        } else {
            format!(
                "{}{} {}",
                a.status,
                if a.signed { "s" } else { "u" },
                a.code
            )
        };
        *by.entry(kind).or_default() += 1;
    }
    by.iter()
        .map(|(k, n)| format!("{k} x{n}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Every future, polled together on this task.
async fn futures_join<F: std::future::Future>(futures: impl Iterator<Item = F>) -> Vec<F::Output> {
    let handles: Vec<_> = futures.map(Box::pin).collect();
    let mut out = Vec::with_capacity(handles.len());
    let mut pending: Vec<_> = handles.into_iter().map(Some).collect();
    let mut results: Vec<Option<F::Output>> = (0..pending.len()).map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut done = true;
        for (i, slot) in pending.iter_mut().enumerate() {
            if let Some(f) = slot {
                match f.as_mut().poll(cx) {
                    std::task::Poll::Ready(v) => {
                        results[i] = Some(v);
                        *slot = None;
                    }
                    std::task::Poll::Pending => done = false,
                }
            }
        }
        if done {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    })
    .await;
    for r in results {
        out.push(r.unwrap());
    }
    out
}
