//! The storage at v0.2.4 (`old`: its modules verbatim, on bsv-rs 0.4.5 and
//! bsv-middleware-cloudflare 0.5.1) against the storage now (`new`: the
//! tree's modules on the Worker's crates), on the same inputs: what a client,
//! a payer, the overlay and the platform see must not change.
//!
//! The keys below are test scalars (1, 2, 3, 4), never used on a network.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const CLIENT_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000002";
const ADMIN_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000003";
const SENDER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000004";
/// The originator both middlewares mint session nonces and derivation
/// prefixes under.
const ORIGINATOR: &str = "bsv-auth-cloudflare";

fn pubkey_hex(private_hex: &str) -> String {
    new::bsv_rs::primitives::PrivateKey::from_hex(private_hex)
        .unwrap()
        .public_key()
        .to_hex()
}

// ── 1. the wire: BRC-103 sessions and BRC-104 general messages ──────────

macro_rules! wallet {
    ($side:ident, $key:expr) => {
        $side::bsv_rs::wallet::ProtoWallet::new(Some(
            $side::bsv_rs::primitives::PrivateKey::from_hex($key).unwrap(),
        ))
    };
}

macro_rules! binding {
    ($side:ident, $session_nonce:expr, $peer_key:expr, $peer_nonce:expr) => {
        $side::middleware::core::SessionBinding {
            session_nonce: $session_nonce.to_string(),
            peer_identity_key: $peer_key.to_string(),
            peer_nonce: Some($peer_nonce.to_string()),
        }
    };
}

/// A session record in the `AUTH_SESSIONS` KV as one side writes it.
macro_rules! stored_session {
    ($side:ident, $nonce:expr) => {
        $side::middleware::types::StoredSession {
            session_nonce: $nonce.to_string(),
            peer_identity_key: pubkey_hex(CLIENT_KEY),
            peer_nonce: Some("client-handshake-nonce".to_string()),
            is_authenticated: true,
            certificates_required: false,
            certificates_validated: false,
            created_at: 1_763_400_000_000,
            last_update: 1_763_400_060_000,
        }
    };
}

#[tokio::test]
async fn a_session_the_old_build_stored_is_read_and_served_by_the_new() {
    // The server's session nonce, minted at the handshake by the old build.
    let session_nonce =
        old::middleware::core::auth::create_session_nonce(&wallet!(old, SERVER_KEY), ORIGINATOR)
            .await
            .unwrap();
    let ours = new::bsv_rs::auth::utils::verify_nonce(
        &session_nonce,
        &wallet!(new, SERVER_KEY),
        None,
        ORIGINATOR,
    )
    .await
    .unwrap();
    assert!(
        ours,
        "the new build recognises the old build's session nonce"
    );

    // The KV record: the old build's JSON is the new build's record, byte
    // for byte both ways.
    let old_json = serde_json::to_string(&stored_session!(old, session_nonce)).unwrap();
    let read: new::middleware::types::StoredSession = serde_json::from_str(&old_json).unwrap();
    assert_eq!(serde_json::to_string(&read).unwrap(), old_json);
    let new_json = serde_json::to_string(&stored_session!(new, session_nonce)).unwrap();
    assert_eq!(new_json, old_json);
    let back: old::middleware::types::StoredSession = serde_json::from_str(&new_json).unwrap();
    assert_eq!(serde_json::to_string(&back).unwrap(), old_json);
}

/// A client's general message over a session, signed on one side's crates,
/// verified by the other side's server; the server's signed answer verified
/// by the other side's client.
macro_rules! general_message_round {
    ($client:ident, $server:ident) => {{
        let server_nonce = $server::middleware::core::auth::create_session_nonce(
            &wallet!($server, SERVER_KEY),
            ORIGINATOR,
        )
        .await
        .unwrap();
        let client_nonce = "Y2xpZW50LWhhbmRzaGFrZS1ub25jZS0wMDAwMDAwMDA=";
        let (request_id, method, path, search) = ([9u8; 32], "POST", "/upload", "");
        let headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            (
                "x-bsv-payment".to_string(),
                r#"{"derivationPrefix":"p"}"#.to_string(),
            ),
        ];
        let body = br#"{"fileSize":1024,"retentionPeriod":60}"#.to_vec();

        // The client signs the request's BRC-104 payload.
        let payload = $client::middleware::core::brc104::build_request_payload(
            &request_id,
            method,
            path,
            search,
            &headers,
            &body,
        );
        let client_id = $client::bsv_rs::primitives::PrivateKey::from_hex(CLIENT_KEY)
            .unwrap()
            .public_key();
        let mut request = $client::bsv_rs::auth::types::AuthMessage::new(
            $client::bsv_rs::auth::types::MessageType::General,
            client_id,
        );
        request.nonce = Some("cmVxdWVzdC1ub25jZQ==".to_string());
        request.your_nonce = Some(server_nonce.clone());
        request.payload = Some(payload);
        $client::middleware::core::auth::sign_message(
            &wallet!($client, CLIENT_KEY),
            &mut request,
            &binding!($client, client_nonce, pubkey_hex(SERVER_KEY), server_nonce),
        )
        .unwrap();

        // The server reads it off the wire (its JSON form) and judges it.
        let wire = serde_json::to_string(&request).unwrap();
        let read: $server::bsv_rs::auth::types::AuthMessage = serde_json::from_str(&wire).unwrap();
        let server_side = binding!($server, server_nonce, pubkey_hex(CLIENT_KEY), client_nonce);
        assert!($server::middleware::core::auth::verify_message_signature(
            &wallet!($server, SERVER_KEY),
            &read,
            &server_side,
        )
        .unwrap());

        // The server's signed answer, judged by the client.
        let answer = $server::middleware::core::auth::sign_http_response(
            &wallet!($server, SERVER_KEY),
            &server_side,
            &$server::middleware::core::HttpResponseData {
                request_id,
                status: 402,
                headers: vec![(
                    "x-bsv-payment-satoshis-required".to_string(),
                    "1000".to_string(),
                )],
                body: br#"{"status":"error","code":"ERR_PAYMENT_REQUIRED"}"#.to_vec(),
            },
        )
        .unwrap();
        let wire = serde_json::to_string(&answer).unwrap();
        let read: $client::bsv_rs::auth::types::AuthMessage = serde_json::from_str(&wire).unwrap();
        assert!($client::middleware::core::auth::verify_message_signature(
            &wallet!($client, CLIENT_KEY),
            &read,
            &binding!($client, client_nonce, pubkey_hex(SERVER_KEY), server_nonce),
        )
        .unwrap());
        (request_id, headers, body)
    }};
}

#[tokio::test]
async fn general_messages_verify_across_the_two_builds() {
    let (request_id, headers, body) = general_message_round!(old, new);
    general_message_round!(new, old);
    // The new build hashes the request as it streams; the digest is the
    // payload the old build signed over.
    let payload = old::middleware::core::brc104::build_request_payload(
        &request_id,
        "POST",
        "/upload",
        "",
        &headers,
        &body,
    );
    assert_eq!(
        new::middleware::core::brc104::request_payload_digest(
            &request_id,
            "POST",
            "/upload",
            "",
            &headers,
            &body
        ),
        new::bsv_rs::primitives::hash::sha256(&payload)
    );
}

#[test]
fn the_auth_and_payment_header_names_are_the_same() {
    use new::middleware::core::auth_headers as n;
    use old::middleware::core::auth_headers as o;
    for (a, b) in [
        (o::VERSION, n::VERSION),
        (o::IDENTITY_KEY, n::IDENTITY_KEY),
        (o::NONCE, n::NONCE),
        (o::INITIAL_NONCE, n::INITIAL_NONCE),
        (o::YOUR_NONCE, n::YOUR_NONCE),
        (o::SIGNATURE, n::SIGNATURE),
        (o::MESSAGE_TYPE, n::MESSAGE_TYPE),
        (o::REQUEST_ID, n::REQUEST_ID),
        (o::REQUESTED_CERTIFICATES, n::REQUESTED_CERTIFICATES),
    ] {
        assert_eq!(a, b);
    }
    use new::middleware::middleware::payment::payment_headers as np;
    use old::middleware::middleware::payment::payment_headers as op;
    for (a, b) in [
        (op::PAYMENT, np::PAYMENT),
        (op::VERSION, np::VERSION),
        (op::SATOSHIS_REQUIRED, np::SATOSHIS_REQUIRED),
        (op::DERIVATION_PREFIX, np::DERIVATION_PREFIX),
        (op::SATOSHIS_PAID, np::SATOSHIS_PAID),
    ] {
        assert_eq!(a, b);
    }
}

// ── 2. the paid path ────────────────────────────────────────────────────

#[tokio::test]
async fn a_derivation_prefix_from_either_build_is_honoured_by_the_other() {
    let issued_old =
        old::bsv_rs::auth::utils::create_nonce(&wallet!(old, SERVER_KEY), None, ORIGINATOR)
            .await
            .unwrap();
    assert!(new::bsv_rs::auth::utils::verify_nonce(
        &issued_old,
        &wallet!(new, SERVER_KEY),
        None,
        ORIGINATOR
    )
    .await
    .unwrap());
    let issued_new =
        new::bsv_rs::auth::utils::create_nonce(&wallet!(new, SERVER_KEY), None, ORIGINATOR)
            .await
            .unwrap();
    assert!(old::bsv_rs::auth::utils::verify_nonce(
        &issued_new,
        &wallet!(old, SERVER_KEY),
        None,
        ORIGINATOR
    )
    .await
    .unwrap());
}

#[test]
fn the_prefix_record_lives_under_the_same_kv_key() {
    #[allow(deprecated)]
    let new_scope = new::middleware::core::store::PAYMENT_NONCE_SCOPE;
    assert_eq!(old::middleware::core::PAYMENT_NONCE_SCOPE, new_scope);
}

/// A raw transaction: one input, the given outputs.
fn raw_tx(outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut out = 1u32.to_le_bytes().to_vec();
    out.push(1);
    out.extend_from_slice(&[0x11; 32]);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.push(0);
    out.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    out.push(outputs.len() as u8);
    for (sats, script) in outputs {
        out.extend_from_slice(&sats.to_le_bytes());
        out.push(script.len() as u8);
        out.extend_from_slice(script);
    }
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}

fn atomic_beef(raw: Vec<u8>) -> Vec<u8> {
    let mut beef = new::bsv_rs::transaction::Beef::new();
    let txid = beef.merge_raw_tx(raw, None).txid();
    beef.to_binary_atomic(&txid).unwrap()
}

#[test]
fn the_payment_header_reads_the_same_and_its_output_is_judged_the_same() {
    let (prefix, suffix) = ("cHJlZml4LXByZWZpeA==", "c3VmZml4LXN1ZmZpeA==");
    let payer = pubkey_hex(CLIENT_KEY);
    let script =
        old::middleware::core::expected_locking_script(SERVER_KEY, &payer, prefix, suffix).unwrap();
    assert_eq!(
        script,
        new::middleware::core::expected_locking_script(SERVER_KEY, &payer, prefix, suffix).unwrap()
    );
    let paying = hex::decode(&script).unwrap();
    let cases = [
        ("pays", raw_tx(&[(1000, paying.clone()), (5, vec![0x51])])),
        ("pays more", raw_tx(&[(4000, paying.clone())])),
        ("underpays", raw_tx(&[(999, paying.clone())])),
        ("pays another key", raw_tx(&[(1000, vec![0x51])])),
    ];
    for (name, raw) in cases {
        let header = serde_json::json!({
            "derivationPrefix": prefix,
            "derivationSuffix": suffix,
            "transaction": new::bsv_rs::primitives::to_base64(&atomic_beef(raw)),
        })
        .to_string();
        let o: old::middleware::core::BsvPayment = serde_json::from_str(&header).unwrap();
        let n: new::middleware::core::BsvPayment = serde_json::from_str(&header).unwrap();
        assert_eq!(
            (&o.derivation_prefix, &o.derivation_suffix, &o.transaction),
            (&n.derivation_prefix, &n.derivation_suffix, &n.transaction)
        );
        let bytes = old::bsv_rs::primitives::from_base64(&o.transaction).unwrap();
        assert_eq!(
            bytes,
            new::bsv_rs::primitives::from_base64(&n.transaction).unwrap()
        );
        let old_verdict = old::middleware::core::verify_payment_output(
            SERVER_KEY, &payer, prefix, suffix, &bytes, 0, 1000,
        )
        .unwrap();
        let new_verdict = new::middleware::core::verify_payment_output(
            SERVER_KEY, &payer, prefix, suffix, &bytes, 0, 1000,
        )
        .unwrap();
        assert_eq!(old_verdict.to_string(), new_verdict.to_string(), "{name}");
    }
}

// ── 3. the advert ───────────────────────────────────────────────────────

/// The advert one side builds for `(url, hash, expiry, size)`: the
/// locking key, the PushDrop fields' signature and the locking script,
/// in the steps `routes::advertise::build_advert_bundle` takes.
macro_rules! advert {
    ($side:ident, $url:expr, $hash:expr, $expiry:expr, $size:expr) => {{
        use $side::bsv_rs::primitives::encoding::Writer;
        use $side::wallet::brc42::{
            derive_child_key, derive_child_public_key, uhrp_protocol_id, UHRP_COUNTERPARTY_ANYONE,
            UHRP_KEY_ID,
        };
        let admin = $side::bsv_rs::primitives::PrivateKey::from_hex(ADMIN_KEY).unwrap();
        let protocol = uhrp_protocol_id();
        let locking =
            derive_child_public_key(&admin, &protocol, UHRP_KEY_ID, UHRP_COUNTERPARTY_ANYONE)
                .unwrap();
        let signing =
            derive_child_key(&admin, &protocol, UHRP_KEY_ID, UHRP_COUNTERPARTY_ANYONE).unwrap();
        let identity = admin.public_key().to_compressed();
        let mut data = identity.to_vec();
        data.extend_from_slice($hash);
        data.extend_from_slice($url.as_bytes());
        let mut w = Writer::new();
        w.write_var_int($expiry);
        data.extend_from_slice(&w.into_bytes());
        let mut w = Writer::new();
        w.write_var_int($size);
        data.extend_from_slice(&w.into_bytes());
        let digest = $side::bsv_rs::primitives::hash::sha256(&data);
        let signature = signing.sign(&digest).unwrap().to_der();
        let fields = $side::uhrp::pushdrop::UhrpAdvertFields {
            server_identity_key_hex: hex::encode(identity),
            hash: $hash.to_vec(),
            url: $url.to_string(),
            expiry_time: $expiry,
            content_length: $size,
            signature: signature.clone(),
        };
        let script =
            $side::uhrp::pushdrop::build_uhrp_advert_lock(&locking.to_hex(), &fields).unwrap();
        (locking.to_hex(), signature, script)
    }};
}

#[test]
fn the_advert_fields_and_locking_script_are_byte_identical() {
    let long = format!("https://storage.example.com/cdn/{}", "a".repeat(240));
    let longer = format!("https://storage.example.com/cdn/{}", "b".repeat(70_000));
    let cases: [(&str, [u8; 32], u64, u64); 5] = [
        (
            "https://storage.example.com/cdn/3x9k",
            [7; 32],
            1_790_000_000,
            1024,
        ),
        (&long, [0xab; 32], 1_790_000_000, 5_000_000_000),
        (&longer, [0; 32], 1, 0),
        ("https://s.example/c/x", [0xff; 32], u64::MAX, u64::MAX),
        ("https://s.example/c/y", [1; 32], 0xfc, 0xfd),
    ];
    for (url, hash, expiry, size) in cases {
        assert_eq!(
            advert!(old, url, &hash, expiry, size),
            advert!(new, url, &hash, expiry, size),
            "{}",
            &url[..url.len().min(40)]
        );
    }
}

fn p2pkh(pubkey: &[u8]) -> String {
    let h = new::bsv_rs::primitives::hash::hash160(pubkey);
    assert_eq!(h, old::bsv_rs::primitives::hash::hash160(pubkey));
    format!("76a914{}88ac", hex::encode(h))
}

/// The wallet's `createAction` answer for an advert: a P2PKH input of the
/// admin key, a BRC-29 input paid to it, the advert output, and a change
/// output whose script the signer derives.
fn advert_template(advert_script: &str, parent_txid: &str) -> serde_json::Value {
    let admin = new::bsv_rs::primitives::PrivateKey::from_hex(ADMIN_KEY).unwrap();
    let sender = pubkey_hex(SENDER_KEY);
    let paid = new::wallet::brc42::derive_brc29_input_key(&admin, "cHJl", "c3Vm", &sender).unwrap();
    serde_json::json!({
        "inputBeef": [],
        "inputs": [
            {
                "vin": 0,
                "sourceTxid": parent_txid,
                "sourceVout": 0,
                "sourceSatoshis": 50_000,
                "sourceLockingScript": p2pkh(&admin.public_key().to_compressed()),
            },
            {
                "vin": 1,
                "sourceTxid": "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
                "sourceVout": 0,
                "sourceSatoshis": 1_000,
                "sourceLockingScript": p2pkh(&paid.public_key().to_compressed()),
                "derivationPrefix": "cHJl",
                "derivationSuffix": "c3Vm",
                "senderIdentityKey": sender,
            }
        ],
        "outputs": [
            { "vout": 0, "satoshis": 1, "lockingScript": advert_script },
            { "vout": 1, "satoshis": 50_500, "lockingScript": "", "derivationSuffix": "Y2hhbmdl" }
        ],
        "version": 1,
        "lockTime": 0,
        "reference": "advert-ref",
        "derivationPrefix": "Y2hhbmdlLXByZWZpeA==",
    })
}

#[test]
fn the_advert_transaction_the_wallet_is_asked_for_is_byte_identical() {
    let (_, _, script) = advert!(old, "https://s.example/c/z", &[3u8; 32], 1_790_000_000, 77);
    // The wallet's input BEEF: the parent the advert's first input spends,
    // and one transaction outside the advert's ancestry.
    let admin_lock = {
        let admin = new::bsv_rs::primitives::PrivateKey::from_hex(ADMIN_KEY).unwrap();
        hex::decode(p2pkh(&admin.public_key().to_compressed())).unwrap()
    };
    let parent = raw_tx(&[(50_000, admin_lock)]);
    let unrelated = raw_tx(&[(7, vec![0x51]), (8, vec![0x52])]);
    let mut input = old::bsv_rs::transaction::Beef::new();
    let parent_txid = input.merge_raw_tx(parent, None).txid();
    let input_beef = input.to_binary();
    input.merge_raw_tx(unrelated, None);
    let input_beef_wider = input.to_binary();
    let template = advert_template(&script, &parent_txid);
    let o: old::wallet::types::CreateActionResult =
        serde_json::from_value(template.clone()).unwrap();
    let n: new::wallet::types::CreateActionResult = serde_json::from_value(template).unwrap();
    let old_admin = old::bsv_rs::primitives::PrivateKey::from_hex(ADMIN_KEY).unwrap();
    let new_admin = new::bsv_rs::primitives::PrivateKey::from_hex(ADMIN_KEY).unwrap();
    let os = old::wallet::signer::sign_transaction(&o, &old_admin).unwrap();
    let ns = new::wallet::signer::sign_transaction(&n, &new_admin).unwrap();
    assert_eq!(os.txid, ns.txid);
    assert_eq!(os.raw_tx, ns.raw_tx);

    // The AtomicBEEF submitted to the overlay: the wallet's input BEEF with
    // the signed transaction merged in, written as the subject's closure.
    let atomic = |input_beef: &[u8]| {
        let mut ob = old::bsv_rs::transaction::Beef::from_binary(input_beef).unwrap();
        ob.merge_raw_tx(os.raw_tx.clone(), None);
        let mut nb = new::bsv_rs::transaction::Beef::from_binary(input_beef).unwrap();
        nb.merge_raw_tx(ns.raw_tx.clone(), None);
        (
            ob.to_binary_atomic(&os.txid).unwrap(),
            nb.to_binary_atomic(&ns.txid).unwrap(),
        )
    };
    let (old_atomic, new_atomic) = atomic(&input_beef);
    assert_eq!(old_atomic, new_atomic);
    // An input BEEF entry outside the subject's ancestry is not written;
    // the subject and its ancestry are the same bytes.
    let (_, new_wider) = atomic(&input_beef_wider);
    assert_eq!(new_wider, new_atomic);
    let subject = new::bsv_rs::transaction::Transaction::from_beef_subject(&new_wider, None)
        .unwrap()
        .to_binary();
    assert_eq!(subject, os.raw_tx);
}

// ── 4. the fan-out ──────────────────────────────────────────────────────

fn ship_script() -> Vec<u8> {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../parity/fixtures/parity/ship_tm_uhrp.json")).unwrap();
    hex::decode(fixture["expected"]["locking_script_hex"].as_str().unwrap()).unwrap()
}

fn lookup_answer(outputs: &[(Vec<u8>, u32)]) -> Vec<u8> {
    let outputs: Vec<_> = outputs
        .iter()
        .map(|(beef, i)| serde_json::json!({"beef": beef, "outputIndex": i}))
        .collect();
    serde_json::to_vec(&serde_json::json!({"type": "output-list", "outputs": outputs})).unwrap()
}

#[test]
fn the_fan_out_takes_the_same_hosts_from_the_same_answers() {
    let ship = ship_script();
    let plain = {
        let mut beef = new::bsv_rs::transaction::Beef::new();
        beef.merge_raw_tx(raw_tx(&[(1, vec![0x51]), (1, ship.clone())]), None);
        beef.to_binary()
    };
    let atomic = atomic_beef(raw_tx(&[(1, ship.clone())]));
    let answers = [
        lookup_answer(&[(atomic.clone(), 0)]),
        lookup_answer(&[(plain.clone(), 1), (atomic.clone(), 0), (plain.clone(), 0)]),
        lookup_answer(&[(atomic.clone(), 5), (vec![1, 2, 3], 0), (Vec::new(), 0)]),
        lookup_answer(&[]),
        br#"{"type":"freeform","result":{}}"#.to_vec(),
        b"not json".to_vec(),
    ];
    for answer in &answers {
        assert_eq!(
            old::hosts_from_lookup_answer(answer),
            new::hosts_from_lookup_answer(answer)
        );
    }
    assert_eq!(
        new::hosts_from_lookup_answer(&answers[1]).unwrap(),
        vec!["https://overlay.example.com".to_string(); 2]
    );
    // The bound on a tracker's answer.
    assert_eq!(new::LOOKUP_ANSWER_MAX_BYTES, old::LOOKUP_ANSWER_MAX_BYTES);
}

// ── 5. the platform's queue message and the presigned PUT ───────────────

#[test]
fn an_r2_event_queued_for_the_old_build_is_read_the_same_by_the_new() {
    for message in [
        r#"{"account":"x","action":"PutObject","bucket":"uhrp-files","object":{"key":"cdn/3x9k","size":1024,"eTag":"e1"},"eventTime":"2026-11-17T00:00:00Z"}"#,
        r#"{"action":"CompleteMultipartUpload","bucket":"b","object":{"key":"cdn/a"}}"#,
        r#"{"action":"DeleteObject","bucket":"b","object":{"key":"cdn/a","size":null}}"#,
    ] {
        let o: old::queue::R2EventMessage = serde_json::from_str(message).unwrap();
        let n: new::queue::R2EventMessage = serde_json::from_str(message).unwrap();
        assert_eq!(
            serde_json::to_value(&o).unwrap(),
            serde_json::to_value(&n).unwrap()
        );
        assert_eq!(
            o.action.creates_object(),
            n.action.creates_object(),
            "{message}"
        );
    }
}

#[test]
fn the_presigned_put_is_the_same_url() {
    let signed = vec![
        ("content-length".to_string(), "1024".to_string()),
        (
            "x-amz-meta-uploaderidentitykey".to_string(),
            pubkey_hex(CLIENT_KEY),
        ),
    ];
    let (amz_date, date_stamp) = old::storage::presign::format_amz_date(1_763_400_000);
    assert_eq!(
        (amz_date.clone(), date_stamp.clone()),
        new::storage::presign::format_amz_date(1_763_400_000)
    );
    macro_rules! url {
        ($side:ident) => {
            $side::storage::presign::presign_put(&$side::storage::presign::PresignParams {
                access_key_id: "AKIDEXAMPLE",
                secret_access_key: "test-secret-not-a-credential",
                host: "bucket-host.example",
                bucket: "uhrp-files",
                key: "cdn/3x9k",
                expires_in_seconds: 604_000,
                amz_date: &amz_date,
                date_stamp: &date_stamp,
                signed_headers: &signed,
            })
        };
    }
    assert_eq!(url!(old), url!(new));
}
