//! Live parity proofs against the canonical `@bsv/overlay-express`
//! nodes — `users.bapp.dev` (SHIP/SLAP hub) and
//! `backend.e40be69a5b6200a8f2b23758f2174093.projects.babbage.systems`
//! (UHRP overlay).
//!
//! Every test here is `#[ignore]`-gated by default: each one spends
//! real satoshis (one funded tx per admission attempt) and requires
//! MetaNet Client running at `localhost:3321`. Run with
//! `cargo test overlay_live -- --ignored --nocapture`.
//!
//! ## Why this exists
//!
//! Byte-exact fixtures (`$VOLATILE:<kind>$` sentinels, TS-SDK goldens)
//! prove our output *matches reference bytes*. These tests prove
//! something stronger: **the reference server accepts our output**.
//! If our Rust-built SHIP advertisement is admitted by
//! `users.bapp.dev` (the canonical hub), we're byte-compatible at the
//! admission-policy layer, not just the formatting layer. Same for
//! UHRP adverts against the projects overlay.
//!
//! ## Scope
//!
//! - SHIP advert submit → `users.bapp.dev/submit` (topic `tm_ship`).
//!   Asserts our locking script is admitted to at least one `outputsToAdmit`.
//! - UHRP advert submit (`// TODO: needs UHRP PushDrop builder wired up
//!   with a file that actually exists; tracked as follow-up to avoid
//!   confusing the overlay with synthetic hashes`) — parked pending
//!   a storage-path producer.
//! - GASP initial-sync against a foreign node — parked as its own
//!   test once the first two land clean.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use bsv_rs::overlay::create_signed_overlay_admin_token;
    use bsv_rs::overlay::types::Protocol;

    use crate::identity;
    use crate::wallet::{build_client, create_action, ActionOutput};
    use serde_json::Value;

    /// Canonical SHIP/SLAP hub. Runs `@bsv/overlay-express` with the
    /// `tm_ship`, `tm_slap`, and `tm_users` topic managers (confirmed
    /// via `GET /listTopicManagers` 2026-04-21). Pinned by the bsv-rs
    /// `NetworkPreset::Mainnet` SLAP-trackers list, so submitting here
    /// is protocol-canonical. Default when `PARITY_OVERLAY_URL` isn't
    /// set.
    const USERS_BAPP_DEV: &str = "https://users.bapp.dev";

    /// Env var — when set, overrides the default hub. Used to point the
    /// live test at the local `@bsv/overlay-express` testbed
    /// (`tests/parity/overlay-express-testbed/`) so admission parity
    /// can be verified hermetically without depending on remote infra
    /// being up. See that dir's README for setup.
    const PARITY_OVERLAY_URL_ENV: &str = "PARITY_OVERLAY_URL";

    fn target_overlay_url() -> String {
        std::env::var(PARITY_OVERLAY_URL_ENV).unwrap_or_else(|_| USERS_BAPP_DEV.to_string())
    }

    /// End-to-end proof: build a SHIP advert with our in-process
    /// `bsv_rs::overlay::create_signed_overlay_admin_token` + fund via
    /// MetaNet Client's `createAction`, submit to `users.bapp.dev/submit`
    /// with `x-topics: ["tm_ship"]`, and assert the STEAK shows the
    /// output was admitted.
    ///
    /// A failure here is the highest-signal parity regression we can
    /// detect: every byte-level golden agreement wouldn't save us if
    /// the canonical validator still rejects the token (admission
    /// policy is a separate trust boundary from encoding).
    /// **Status (2026-04-21): proven against the local testbed.** Task
    /// #45 closed via #46 — running this test with
    /// `PARITY_OVERLAY_URL=http://localhost:8080` pointing at the
    /// `overlay-express-testbed/` stack produces:
    ///
    /// ```text
    /// SHIP advert ADMITTED by http://localhost:8080.
    /// txid=5366fcad463b0226183f32d82211b0b96e91df1513bcb345bdd0c70985b665b4
    /// admitted_vouts=[Number(0)]
    /// ```
    ///
    /// That's the strongest parity claim we can make for SHIP: the
    /// canonical `@bsv/overlay-express` instance (same code nanostore
    /// runs) re-derived the locking pubkey via
    /// `anyoneWallet.getPublicKey({counterparty: identityKey, ...})`,
    /// verified our signature, and admitted our output at index 0.
    /// Full admission-policy parity, not just byte-shape parity.
    ///
    /// Default (`PARITY_OVERLAY_URL` unset) still submits to
    /// `users.bapp.dev`; that path is gated on their MongoDB cluster
    /// being up, which at the time of writing is mid-migration. The
    /// local testbed removes that dependency permanently.
    #[tokio::test]
    #[ignore]
    async fn live_ship_advert_admitted_by_users_bapp_dev() {
        // Identity: the parity harness's persistent test key. Both
        // the BRC-42 child that signs the advert AND the PushDrop
        // field-1 identity key trace back to this.
        let id = identity::resolve().expect("resolve parity identity");

        // Domain + topic: values that satisfy `isAdvertisableURI` in
        // @bsv/overlay-discovery-services — it requires a full URL
        // (https:// or similar scheme) with pathname `/` and a
        // non-localhost hostname. `.invalid` is IANA-reserved so no
        // real overlay answers at this URL, keeping us from polluting
        // live infra. Topic is prefixed with `tm_parity_` so operators
        // can filter us out in their feeds if desired.
        let domain = "https://parity.harness.invalid";
        let topic = "tm_parity_test";

        let locking =
            create_signed_overlay_admin_token(&id.private_key, Protocol::Ship, domain, topic);

        // Diagnostic: print the locking script hex + decoded fields so a
        // failed submit lands with enough info to diagnose without
        // re-running.
        eprintln!("\n=== SHIP advert payload ===");
        eprintln!("domain: {domain}");
        eprintln!("topic: {topic}");
        eprintln!("identity_pubkey: {}", id.public_key_hex);
        eprintln!(
            "locking_script_hex ({}B): {}",
            locking.to_binary().len(),
            locking.to_hex()
        );
        if let Ok(decoded) = bsv_rs::overlay::decode_overlay_admin_token(&locking) {
            eprintln!(
                "decoded: protocol={:?} identity={} domain={} topic={}",
                decoded.protocol,
                decoded.identity_key_hex(),
                decoded.domain,
                decoded.topic_or_service
            );
        } else {
            eprintln!("decoded: FAILED (our own decoder rejected our own output)");
        }
        eprintln!();

        // Fund the advert: one 1-sat dust output carrying the SHIP
        // PushDrop, no change constraints, non-delayed broadcast so
        // the tx hits the network before we submit. `randomizeOutputs:
        // false` keeps our SHIP at vout[0] — canonical for SHIP
        // advertisements.
        let http = build_client().expect("reqwest client");
        let action = create_action(
            &http,
            "parity harness SHIP advert live test",
            vec![ActionOutput {
                locking_script_hex: locking.to_hex(),
                satoshis: 1,
                output_description: "parity harness SHIP advert".to_string(),
            }],
            /* accept_delayed_broadcast = */ false,
            /* randomize_outputs       = */ false,
        )
        .await
        .unwrap_or_else(|e| panic!("createAction failed (MetaNet Client at :3321 running?): {e}"));

        // Submit. `/submit` on @bsv/overlay-express takes raw body
        // bytes (BEEF or AtomicBEEF — the engine detects and dispatches)
        // plus an `x-topics` header carrying a JSON array of topics.
        let target = target_overlay_url();
        eprintln!("[overlay-live] submitting to {target}");
        let resp = http
            .post(format!("{target}/submit"))
            .header("Content-Type", "application/octet-stream")
            .header("x-topics", r#"["tm_ship"]"#)
            .body(action.tx)
            .send()
            .await
            .unwrap_or_else(|e| panic!("POST /submit: {e}"));

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        assert!(status.is_success(), "submit HTTP {status} — body: {body}");

        // STEAK shape: `{ "<topic>": { "outputsToAdmit": [int], "coinsToRetain": [...], "coinsRemoved": [...] }, ... }`
        let steak: Value =
            serde_json::from_str(&body).unwrap_or_else(|e| panic!("parse STEAK: {e}\n{body}"));
        let tm_ship = &steak["tm_ship"];
        assert!(
            !tm_ship.is_null(),
            "STEAK missing `tm_ship` key — topic manager didn't run: {steak}"
        );
        let admitted = tm_ship["outputsToAdmit"]
            .as_array()
            .unwrap_or_else(|| panic!("outputsToAdmit not an array: {tm_ship}"));
        assert!(
            !admitted.is_empty(),
            "SHIP advert was NOT admitted by {target} — submit returned empty outputsToAdmit: {steak}\n\
             This means our locking-script bytes passed BRC-31/BRC-104 wire but failed tm_ship admission policy. \
             Check the canary in overlay-discovery/tests/ts_sdk_parity.rs and the bsv-rs \
             create_signed_overlay_admin_token_matches_at_bsv_sdk_1_10_1 blocking gate.\n\
             Try the local overlay-express testbed (tests/parity/overlay-express-testbed/) \
             and re-run with PARITY_OVERLAY_URL=http://localhost:8080 to rule out remote-infra issues."
        );

        eprintln!(
            "SHIP advert ADMITTED by {target}. txid={} admitted_vouts={admitted:?}",
            action.txid
        );
    }
}
