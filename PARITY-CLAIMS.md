# Parity Claims — TS @bsv/sdk 1.10.1

_Last updated: 2026-04-21. Source-of-truth synthesis of everything we can
*currently* prove about this stack's byte-level and shape-level agreement
with the reference TS implementation (@bsv/sdk 1.10.1 + @bsv/overlay
0.6.0, the versions pinned at `nanostore.babbage.systems` +
`overlay-us-1.bsvb.tech`)._

_If a claim in this document isn't backed by (a) a committed test / vector
file, (b) a committed live-run capture, or (c) a cross-validator corpus,
it's a bug in this document. Report it._

---

## How to read this doc

Every claim below lists:

- **Evidence** — specific file paths, test function names, fixture paths,
  and/or a recorded live run. No vague handwaving.
- **Assertion** — one crisp sentence describing exactly what's proven.
- **Status** — one of:
  - `byte-exact` — output is byte-identical to TS SDK 1.10.1 reference.
  - `shape-exact` — output matches the TS contract *shape* (typed
    `$VOLATILE:<kind>$` sentinels in the fixture where value is dynamic
    but the invariant is shape; literals everywhere else). See
    `tests/parity/src/canon.rs`.
  - `cross-validator` — Rust admission logic re-evaluated against a
    corpus of TS-produced transcripts; every verdict agrees.
  - `live-fire` — a real HTTP round-trip against the production
    reference server, captured and diff'd.

Each evidence pointer is stable — `git blame` will surface the commit
that introduced it, so the provenance chain is checkable.

---

## 1. BRC-42 key derivation (private + public)

- **Evidence**
  - `~/bsv/bsv-rs/tests/cross_sdk_tests.rs` — walks
    `tests/vectors/brc42_private.json` (5 TS-generated vectors) and
    `tests/vectors/brc42_public.json` (5 vectors), asserts each derivation
    produces the expected hex byte-exact.
  - `~/bsv/bsv-storage-cloudflare/tests/parity/fixtures/parity/brc42_uhrp_anyone_locking.json`,
    `brc42_ship_anyone_locking.json`, `brc42_brc29_payment_to_admin.json` —
    @bsv/sdk 1.10.1-generated goldens consumed by
    `src/uhrp/pushdrop.rs::ts_sdk_brc42_derivation_byte_exact_goldens`.

- **Assertion** — BRC-42 private and public derivation (with `Counterparty::Self_`,
  `Anyone`, and `Other(PublicKey)` variants) produces hex-identical output
  to TS for every tested vector.

- **Status** — `byte-exact` (15 TS vectors total).

## 2. BRC-29 payment — derivation, P2PKH output, envelope JSON

- **Evidence**
  - Goldens: `tests/parity/fixtures/parity/brc29_payment_basic.json`,
    `brc29_payment_large_keyid.json` (both TS 1.10.1-generated, include
    expected `derived_pubkey_hex`, `locking_script_hex`, `tx_hex`).
  - Unit+vector tests: `tests/parity/src/payment.rs::tests` —
    `derive_recipient_pubkey_matches_ts_fixtures`,
    `p2pkh_payment_output_matches_ts_fixture_script`,
    `envelope_header_value_is_valid_json_with_expected_keys`,
    `envelope_handles_empty_transaction_bytes`.
  - Extra: `src/wallet/parity_tests.rs::brc29_payment_sender_derivation_matches_ts`
    in the worker crate covers the server-side verifier path.

- **Assertion** — Sender-side BRC-42 derivation, 25-byte P2PKH locking
  script, and the `{derivationPrefix, derivationSuffix, transaction}`
  envelope JSON shape all match TS SDK 1.10.1 byte-exact.

- **Status** — `byte-exact` at the primitive level; `live-fire` end-to-end
  via `/upload` (see §11).

## 3. BRC-31 mutual auth — handshake, General messages, certificate flow

- **Evidence**
  - Unit/integration (bsv-rs): `tests/auth_cross_sdk_tests.rs` (13 certificate
    serialization vectors), `tests/auth_integration_tests.rs` (70 tests:
    `SessionManager`, `AuthMessage`, HTTP payload codec),
    `tests/auth_peer_e2e_tests.rs` (21 tests: full BRC-31 handshake via
    channel-loopback transport).
  - Live-fire: parity harness uses `bsv_rs::auth::Peer` +
    `SimplifiedFetchTransport` (see `tests/parity/src/auth.rs`). Every
    authenticated scenario (`/find`, `/list`, `/upload`) performs a real
    handshake against `nanostore.babbage.systems` and our deployed worker
    per invocation.

- **Assertion** — Handshake (InitialRequest/Response + nonce + signature)
  and General-message signing (per-message nonce + BRC-104 header
  layout) interoperate byte-exact with the TS + Go SDKs; live runs
  against production nanostore return 200 on all signed requests.

- **Status** — `byte-exact` at vector/unit level; `live-fire` end-to-end.

## 4. PushDrop — UHRP 5-field shape + SHIP/SLAP admin tokens

- **Evidence**
  - UHRP goldens: `~/bsv/bsv-storage-cloudflare/tests/fixtures/pushdrop/*`
    (4 TS oracles) + `tests/parity/fixtures/parity/uhrp_*` (5 parity
    fixtures covering baseline, varint 253-byte boundary, varint u16
    boundary, zero-hash, past-expiry).
  - SHIP/SLAP goldens:
    `ship_tm_uhrp.json`, `ship_tm_ship.json`, `ship_long_topic.json`,
    `slap_ls_uhrp.json`, `slap_ls_ship.json` (all TS 1.10.1).
  - bsv-rs `tests/overlay_admin_token_ts_parity_tests.rs` —
    `create_signed_overlay_admin_token_matches_at_bsv_sdk_1_10_1`
    (blocking gate — fails if ever drifts) + determinism guard.
  - rust-overlay `crates/overlay-discovery/tests/ts_sdk_parity.rs` —
    `ts_sdk_ship_pushdrop_byte_exact_goldens`,
    `ts_sdk_slap_pushdrop_byte_exact_goldens`, plus a
    `deprecated_create_overlay_admin_token_still_emits_4_field_unsigned`
    canary.

- **Assertion** — UHRP 6-field (5 data + sig), SHIP/SLAP 6-field
  (5 data + sig, `counterparty=Anyone`, `for_self=true`) PushDrop locking
  scripts produce identical bytes to what `@bsv/sdk 1.10.1`'s
  `pushdrop.lock(...)` emits in `@bsv/overlay-discovery-services/src/WalletAdvertiser.ts`.

- **Status** — `byte-exact`. (This was the subject of the bsv-rs v0.3.7
  release: the bug in `create_overlay_admin_token` that emitted the wrong
  4-field unsigned shape was caught by these goldens.)

## 5. UHRP URL derivation (SHA-256 → base58check)

- **Evidence**
  - `~/bsv/bsv-storage-cloudflare/src/uhrp/hash.rs::tests` —
    `golden_empty`, `golden_hello_world_ascii`, `golden_all_bytes_0_to_255`,
    `golden_one_mib_plus_one_byte_repeating`, `golden_ts_sdk_cross_vector`.
  - Parity fixtures: `uhrp_baseline_small_cdn_url.json`,
    `uhrp_past_expiry_ts_parity.json`,
    `uhrp_url_at_253_byte_varint_boundary.json`,
    `uhrp_url_over_varint_u16_boundary.json`, `uhrp_zero_hash_edge.json`
    (all TS 1.10.1).
  - bsv-rs `tests/storage_tests.rs` — UHRP URL generation / parsing /
    validation across 70 tests.

- **Assertion** — `derive_uhrp_url(bytes)` produces a string identical to
  what TS SDK emits for the same input bytes, across baseline + every
  varint boundary.

- **Status** — `byte-exact`.

## 6. tm_uhrp admission — accept/reject verdicts (transcripts)

- **Evidence**
  - Corpus: 16 TS 1.10.1-generated transcripts in
    `~/bsv/bsv-storage-cloudflare/tests/parity/fixtures/parity/transcripts/`
    + index at `transcripts_index.json`. Each records a locking-script
    hex + expected verdict + reason, produced by running @bsv/sdk's
    `UHRPTopicManager` on the input.
  - Admit cases: `valid_admit`, `past_expiry_admits`,
    `max_content_length_admits`.
  - Reject cases (13): `zero_expiry_rejects`, `http_scheme_rejects`,
    `ftp_scheme_rejects`, `empty_signature_rejects`,
    `bad_signature_wrong_key_rejects`, `bad_linkage_rejects`,
    `too_few_fields_rejects`, `too_many_fields_rejects`,
    `bad_hash_length_31_rejects`, `bad_identity_key_32_bytes_rejects`,
    `bad_varint_expiry_rejects`, `zero_content_length_rejects`,
    `non_pushdrop_rejects`.
  - Consumers:
    `~/bsv/rust-overlay/crates/overlay-discovery/tests/ts_sdk_parity.rs`
    runs 16 per-case `transcript_*` tests + a bundle assertion
    `transcript_index_all_cases_match_ts_verdict`.

- **Assertion** — Rust `UHRPTopicManager::validate_uhrp_output` returns
  the exact same admit/reject decision (and reason category) as TS 1.10.1
  for every one of the 16 transcripts.

- **Status** — `byte-exact` on the verdicts + reasons; `cross-validator`
  on the corpus (see §12).

## 7. tm_ship / tm_slap admission

- **Evidence**
  - 5 byte-exact PushDrop goldens (§4).
  - bsv-rs `tests/overlay_integration_tests.rs` — 62 tests on
    `ShipProtocol` / `SlapProtocol` handling + reputation tracker +
    historian. `tests/overlay_http_tests.rs` — 49 tests exercising the
    HTTP facilitators (broadcast + lookup) via wiremock.
  - rust-overlay `crates/overlay-discovery/src/validation.rs::tests` — 6
    tests on `is_token_signature_correctly_linked` covering valid
    SHIP, valid SLAP, tampered-data, wrong-identity-key,
    wrong-locking-key, unknown-protocol.

- **Assertion** — SHIP/SLAP advertisement validation (field counts,
  identity-key shape, signature-linkage) produces the same
  admit/reject as TS for every exercised case.

- **Status** — `byte-exact` at the PushDrop layer; unit-tested for
  admission logic.

## 8. ls_uhrp lookup — query + opt-in expiry filter

- **Evidence**
  - `crates/overlay-discovery/src/uhrp/lookup_service.rs::tests` — 20
    tests including the task-#33 set:
    `lookup_default_hides_past_expiry_records`,
    `lookup_include_expired_returns_all`,
    `lookup_zero_expiry_is_never_filtered`,
    `lookup_by_identity_key_respects_expiry_filter`. Each uses an
    injectable `now_unix_seconds` for determinism.
  - D1 storage impl: `crates/overlay-cloudflare/src/d1_discovery.rs` —
    SQL translates the same filter semantics (expiryTime = 0 OR
    expiryTime >= now).

- **Assertion** — Default lookup hides past-expiry records; opt-in
  `includeExpired: true` reveals everything; `expiry_time = 0` is
  "never expires" per UHRP convention.

- **Status** — Unit-tested; storage-layer + lookup-layer coverage
  symmetric.

## 9. Sighash — BIP-143 preimage + digest

- **Evidence**
  - bsv-rs `tests/sighash_tests.rs` — walks `tests/vectors/sighash.json`
    (500 vectors; 499 exercised, 1 skipped per BSV-specific flags),
    asserts preimage bytes + digest match.
  - Parity fixtures (TS 1.10.1):
    `sighash_p2pkh_1input.json`,
    `sighash_p2pkh_2inputs_sign_first.json`,
    `sighash_p2pkh_2inputs_sign_second.json`,
    `sighash_pushdrop_subscript.json`.
  - Worker crate `src/wallet/parity_tests.rs::sighash_preimage_and_digest_match_ts_fixtures`
    — asserts preimage AND digest byte-exact.

- **Assertion** — BIP-143 sighash preimage bytes and double-SHA-256 digest
  match TS for every standard and subscript-context case.

- **Status** — `byte-exact` (500+ vectors + 4 parity fixtures).

## 10. AtomicBEEF — v1 magic + BEEF v2 wrapping + round-trip

- **Evidence**
  - bsv-rs `tests/transaction_tests.rs::beef_extended_tests` +
    `beef_ancestry_tests` + `cross_sdk_tests` — 103 transaction tests
    including BEEF parse/serialize/round-trip against cross-SDK vectors
    from `beef_cross_sdk.rs`.
  - Parity fixtures (TS 1.10.1):
    `atomic_beef_1input_p2pkh.json`,
    `atomic_beef_2input_p2pkh.json`,
    `atomic_beef_1input_brc29_source.json`.
  - Worker crate `src/wallet/parity_tests.rs::atomic_beef_fixtures_parse_and_match_child_txid`
    — loads each AtomicBEEF fixture, parses via
    `bsv_rs::transaction::Beef::from_binary`, asserts the embedded
    child-txid is recovered byte-exact.

- **Assertion** — AtomicBEEF magic (`0x01010101`) + 32-byte txid +
  embedded BEEF v2 round-trip cleanly; `Beef::from_binary` accepts every
  TS-emitted variant we've tested.

- **Status** — `byte-exact`.

## 11. HTTP route responses — live-fire matrix

| Route | Scenario | Status | Evidence |
|-------|----------|--------|----------|
| `/quote` | `small-file` | `shape-exact` (fixture uses `$VOLATILE:u64$` on `quote`); reference↔local byte-exact diverges by design — this deployment charges $0.05/GB-mo + 1000-sat floor vs nanostore's $0.03 + 10 (see README "Pricing") | `tests/parity/fixtures/quote.small-file.json` |
| `/find` | `nonexistent-uhrp-url` | `live-fire` | `fixtures/find.nonexistent-uhrp-url.json`, captured from nanostore 2026-04-21 sha=`c57ccf8b…`, unchanged on recapture |
| `/find` | `missing-query-param` | `live-fire` | `fixtures/find.missing-query-param.json`, sha=`6cd7bcb3…` |
| `/find` | `malformed-uhrp-url` | `live-fire` | `fixtures/find.malformed-uhrp-url.json`, sha=`9b1244fd…` |
| `/list` | `my-adverts` | `live-fire` | `fixtures/list.my-adverts.json`, recaptured 2026-04-21 |
| `/upload` | `upload-small-file` | `live-fire` + cross-backend agreement | `fixtures/upload.upload-small-file.json`; run `2026-04-21` returned `OK — reference, local, and fixture all agree` diffing `nanostore.babbage.systems` vs `your-worker.your-account.workers.dev` |
| `/advertise` | `advertise-already-uploaded` | `shape-exact` (fixture contract); live-fire blocked on admin-identity coordination | `fixtures/advertise.advertise-already-uploaded.json` + `src/routes/advertise.rs:SKIP_REASON` |
| `/renew` | `renew-our-advert` | `shape-exact` (fixture contract); live-fire blocked on `/upload+/advertise` precondition pipeline | `fixtures/renew.renew-our-advert.json` + `src/routes/renew.rs:SKIP_REASON` |

**Evidence for the `/upload` cross-backend claim**: nanostore (GCS-backed)
returns `requiredHeaders: {x-goog-*: ...}` and our worker (R2-backed)
returns `{x-amz-*: ...}`. The fixture pins the protocol invariant
(`requiredHeaders: "$VOLATILE:string_map$"` — non-empty map of string →
string) instead of a backend-specific shape, so both servers pass. See
`src/canon.rs` + 16 unit/vector tests under `canon::tests::string_map_*`.

## 12. Cross-validator — Rust admission ↔ TS `UHRPTopicManager` agreement

- **Evidence**
  - Rust driver: `~/bsv/rust-overlay/crates/overlay-discovery/tests/cross_validator.rs`
    `cross_validator_rust_vs_ts_agree`.
  - TS shim: `~/bsv/bsv-storage-cloudflare/tests/parity/ts-fixtures/cross_validate.mjs`
    + local copy of `UHRPTopicManager` at `tm_uhrp_local.mjs`.
  - Last run: **14 cases, 4 admitted, 10 rejected, 0 divergences**
    (committed under `tests/fixtures/parity/transcripts/` and exercised
    by this test automatically; the test skips cleanly if `node` or
    `node_modules` is unavailable, keeping CI hermetic).

- **Assertion** — For every case in the cross-validator corpus, the Rust
  admission pipeline and TS's `UHRPTopicManager.identifyAdmissibleOutputs`
  return identical verdicts.

- **Status** — `cross-validator`; 0 divergences.

---

## Current gaps (no asterisks)

1. **`/advertise` live-fire vs our worker**. Blocked on adding the parity
   identity's pubkey to our worker's `ADMIN_IDENTITY_KEYS` secret.
   Intrinsically ours-only regardless — nanostore's admin is a private
   shared token. Fixture shape is pinned; scenario carries a precise
   `skip_reason`. **Tracked: task #22**.

2. **`/renew` live-fire**. Needs (a) `/upload`+`/advertise` precondition
   pipeline so the parity identity owns something to renew, (b) ours-only
   for the same reason. Fixture shape is pinned. **Tracked: task #22**.

3. **rust-overlay outbound push (#31)**. CloudflareAdvertiser does not
   push new adverts to non-GASP peers; relies on GASP sync. Reframed as
   "best-effort courtesy" — not a protocol gap.

4. **Peer-lookup crawler wiring (#32)**. `peer_crawler.rs` exists
   (280 lines + 7 unit tests) but isn't wired into the scheduled cron.
   Ingress-only parity; doesn't affect wire-contract correctness.

None of these are hidden behind `$VOLATILE:object$` or similar
loose-sentinel slop in fixtures. Where parity isn't proven, it's because
the infrastructure to prove it (admin identity coordination, precondition
pipelines) hasn't been built yet — not because the code is wrong.

---

## How to regenerate the byte goldens

All TS-facing fixtures are regenerated from one generator:

```bash
cd ~/bsv/bsv-storage-cloudflare/tests/parity/ts-fixtures
npm ci               # pinned @bsv/sdk 1.10.1 + @bsv/overlay 0.6.0
node generate.mjs    # writes every fixture in tests/parity/fixtures/parity/
node validate-transcripts.mjs    # re-runs TS tm_uhrp over each transcript,
                                 # asserts our recorded verdict is what TS emits today
```

After regeneration:

```bash
# In bsv-storage-cloudflare
./scripts/check.sh   # fmt + clippy + test --lib + worker-build
cargo test --bin parity
cd tests/parity && cargo test

# In rust-overlay
cargo test -p overlay-discovery --lib
cargo test -p overlay-discovery --test ts_sdk_parity
cargo test -p overlay-discovery --test cross_validator
```

If the generator regenerates bytes and our tests still pass, TS ↔ Rust
parity is unchanged. If the generator regenerates different bytes, TS
changed on us — bump the @bsv/sdk pin, re-diff, update anything that
drifts.

## Version alignment

- `bsv-rs` 0.4.5: pinned exactly in both workspace manifests,
  https://crates.io/crates/bsv-rs .
- The workspace lock resolves one registry `bsv-rs` 0.4.5 shared by the Worker,
  parity harness, middleware 0.5.1 (core 0.2.1), and `bsv-overlay-engine` 0.1.0.
  No path dependencies or sibling checkout are required.
- TS SDK reference: `@bsv/sdk` 1.10.1 + `@bsv/overlay` 0.6.0, matching
  `nanostore.babbage.systems` + `overlay-us-1.bsvb.tech` production.

## Related documents

- `PARITY-ROADMAP.md` — the 5-phase plan this work follows.
- `PARITY-PROGRESS.md` — living evidence log (commit hash per milestone).
- `PROTOCOL.md` — wire-level protocol spec for the UHRP storage worker.
- `tests/parity/CLAUDE.md` — parity harness internals.
- `tests/parity/src/canon.rs` — `$VOLATILE:<kind>$` sentinel system +
  RFC 8785 JCS implementation (explains the shape-exact vs byte-exact
  machinery).
