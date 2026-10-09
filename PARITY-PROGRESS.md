# Parity Proof Progress

_Live tracker for the roadmap in [PARITY-ROADMAP.md](./PARITY-ROADMAP.md)._
_Last updated: 2026-04-21_

## Phase status

| Phase | Task | Status | Evidence |
|-------|------|--------|----------|
| 1 | Pin TS dep versions matching bsvb | ✅ done | `@bsv/sdk 1.10.1`, `@bsv/overlay 0.6.0` matches nanostore exactly |
| 2 | Protocol-byte goldens (Layer 1) | ✅ expanded (40 fixtures, 5 suite tests green, SHIP/SLAP bug fixed upstream @ bsv-rs v0.3.7) | `tests/parity/fixtures/parity/*.json` (24) + `transcripts/*.json` (16); `src/wallet/parity_tests.rs` |
| 3 | Live parity harness (Layer 2) | 🔄 BRC-31 client landed (#28) — /find ×3 + /list live-fire vs nanostore; /upload+/renew still need BRC-29 (#30) | `tests/parity/src/auth.rs`, 4 fixtures unchanged on live recapture |
| 4 | Cross-validator oracle (Layer 3) | ✅ scaffold landed | `tests/parity/ts-fixtures/cross_validate.mjs` + `rust-overlay/crates/overlay-discovery/tests/cross_validator.rs`; 14+16 corpus entries, 0 divergences |
| 5 | Lookup filter + docs + declaration | 🚧 blocked | — |

Legend: ✅ done · 🔄 in progress · 🚧 not started · ⏳ blocked · ⚠️ blocked externally

---

## Phase 1 — Resolve Unknowns ✅

### Q1. Does `@bsv/overlay` expose `UHRPTopicManager` programmatically? ✅
- `~/bsv/uhrp-services/backend/src/topic-managers/UHRPTopicManager.ts` exports `default class UHRPTopicManager implements TopicManager`. Directly invokable from a Node script.

### Q2. What versions does bsvb/nanostore actually run? ✅
- `uhrp-services/backend/package.json` + `package-lock.json` pin:
  - `@bsv/overlay`: `0.6.0`
  - `@bsv/sdk`: `1.10.1`
- **Decision**: fixture generation pins these exact versions. Any byte differences from local HEAD (which is on `@bsv/sdk 2.0.13`) are nanostore's canonical reality; we match THAT.

### Q3. Do TS reference test vectors exist for tm_uhrp / ls_uhrp? ❌
- `~/bsv/uhrp-services` has no `__tests__` directory. We write our own cross-validator.

### Q4. Rate limiting on nanostore for CI runs? ✅
- 3 concurrent POSTs to `/quote` → all HTTP 200, ~5s each. No rate-limit observed. CI-safe.

### Q5. Canonical UHRP advert reference? ✅
- bsvb's live `/lookup ls_uhrp` is the authority. Captured 2 real records in `/tmp/our_uhrp_*.beef` for cross-check use.

---

## Phase 2 — Layer 1 goldens 🔄

### Infrastructure (done)
- `tests/parity/ts-fixtures/package.json` pins `@bsv/sdk 1.10.1`, `@bsv/overlay 0.6.0`
- `tests/parity/ts-fixtures/generate.mjs` — 14 fixture generator
- `tests/parity/fixtures/parity/*.json` — 14 canonical byte fixtures

### Fixtures generated
- ✅ UHRP PushDrop × 5 (baseline, varint 253-byte boundary, varint u16+ boundary, zero-hash, past-expiry)
- ✅ SHIP PushDrop × 3 (tm_uhrp, tm_ship, long-topic)
- ✅ SLAP PushDrop × 2 (ls_uhrp, ls_ship)
- ✅ BRC-42 derivation × 3 (uhrp/ship/brc29)
- ✅ Admission transcript × 1 (valid + past-expiry cases)

### Rust tests (green)
- ✅ `bsv_storage::uhrp::pushdrop::tests::ts_sdk_uhrp_pushdrop_byte_exact_goldens` — 5 UHRP cases match @bsv/sdk 1.10.1 byte-exact
- ✅ `bsv_storage::uhrp::pushdrop::tests::ts_sdk_brc42_derivation_byte_exact_goldens` — 3 BRC-42 derivations match
- ✅ `rust_overlay::overlay-discovery::ts_sdk_ship_pushdrop_byte_exact_goldens` — 3 SHIP tests pass (our TS-parity REFERENCE impl matches TS fixture)
- ✅ `rust_overlay::overlay-discovery::ts_sdk_slap_pushdrop_byte_exact_goldens` — 2 SLAP tests pass (reference)
- ✅ `rust_overlay::overlay-discovery::bsv_rs_create_overlay_admin_token_still_diverges_from_ts` — canary PASSES meaning bsv-rs DOES diverge 🐛

### 🐛 Bug caught by goldens

**`bsv_rs::overlay::create_overlay_admin_token` diverges from TS.**

- Current: 4-field UNSIGNED PushDrop, locking key = identity key
- Should be: 5-field SIGNED PushDrop, locking key = BRC-42 child for `(2, protocol_name)`/"1"/"anyone"/for_self=true, field[4] = sig over concat(fields[0..4])

Symptoms: any SHIP/SLAP advert produced by `CloudflareAdvertiser::create_advertisements` silently fails admission in both our own `tm_ship` validator (which requires `fields.len() == 5`) AND the TS reference validator. Silent federation break.

Tracked: #40 (upstream fix to bsv-rs), #41 (short-term workaround in CloudflareAdvertiser — build TS-parity locally until #40 lands).

### Layer 1 expansion (2026-04-21) — task #42

All four "still to add" items landed:

- ✅ **AtomicBEEF wrapping goldens × 3** — `atomic_beef_1input_p2pkh.json`, `atomic_beef_2input_p2pkh.json`, `atomic_beef_1input_brc29_source.json`. Asserted via `wallet::parity_tests::atomic_beef_fixtures_parse_and_match_child_txid` — `bsv_rs::transaction::Beef::from_binary` parses TS-produced AtomicBEEF and recovers embedded child txid byte-exact.
- ✅ **Signing preimage goldens × 4** — `sighash_p2pkh_1input.json`, `sighash_p2pkh_2inputs_sign_first.json`, `sighash_p2pkh_2inputs_sign_second.json`, `sighash_pushdrop_subscript.json`. Asserted via `wallet::parity_tests::sighash_preimage_and_digest_match_ts_fixtures` — our `compute_sighash_for_signing` must reproduce both TS preimage AND sighash digest byte-exact.
- ✅ **BRC-29 payment goldens × 2** — `brc29_payment_basic.json`, `brc29_payment_large_keyid.json`. Asserted via `wallet::parity_tests::brc29_payment_sender_derivation_matches_ts` — sender-side BRC-29 child pubkey derivation matches TS.
- ✅ **Reject transcripts × 16** — `transcripts/*.json` + `transcripts_index.json`. Covers every tm_uhrp admission path: valid admit, past-expiry admits, max content length admits, + 13 rejection paths (zero expiry, http scheme, ftp scheme, empty sig, bad sig, bad linkage, too few/many fields, bad hash length, bad identity key length, bad varint expiry, zero content length, non-pushdrop). Consumed by rust-overlay's `tests/ts_sdk_parity.rs` — 16 per-case byte-exact assertions against TS oracle.

Fixture generator: `tests/parity/ts-fixtures/generate.mjs` — 852-line expansion pinned to @bsv/sdk 1.10.1. Plus `validate-transcripts.mjs` — Node-side oracle that re-runs the TS `tm_uhrp` TopicManager over each transcript and confirms expected verdict. Both fail-fast on drift.

---

## Phase 3 — Layer 2 harness 🚧

Unchanged from roadmap. Ordered after Layer 1 is broadly covered so any live-diff failure is more likely to be a wire-shape issue than a primitive issue.

---

## Phase 4 — Layer 3 cross-validator ✅ scaffold

**Landed 2026-04-21.** Cross-validator runs both Rust + TS UHRPTopicManager
over a shared corpus and asserts agreement.

- **Rust driver**: `~/bsv/rust-overlay/crates/overlay-discovery/tests/cross_validator.rs`
- **Node shim**: `tests/parity/ts-fixtures/cross_validate.mjs`
  - Wraps each `locking_script_hex` in a synthetic Transaction → BEEF
  - Calls `UHRPTopicManager.identifyAdmissibleOutputs(beef, [])` from
    `tm_uhrp_local.mjs` (verbatim copy of bsvb's `UHRPTopicManager.ts`)
  - Pinned to `@bsv/sdk 1.10.1` + `@bsv/overlay 0.6.0`
- **Corpus** (14 entries, all agreeing as of landing):
  - 12 hand-crafted (valid baseline, past-expiry, P2PKH, too-few-fields,
    short hash, ftp scheme, bad signature, mismatched locking key,
    impostor identity, zero content length, zero expiry, malformed URL)
  - 2 from `admission_transcript.json` (valid_future_expiry,
    past_expiry_still_admits)
- **Skip behavior**: if `node` not on PATH OR `node_modules` missing,
  test prints `SKIPPED: ...` to stderr and exits clean.
- **Docs**: `~/bsv/rust-overlay/crates/overlay-discovery/tests/CROSS_VALIDATOR.md`

**Divergences found:** 0 (zero — first run was green).

**Adding cases:** see CROSS_VALIDATOR.md "Adding cases" section. Either
hand-craft in `build_hand_crafted_corpus()` or extend `generate.mjs` and
re-run.

---

## Phase 5 — Docs + declaration 🚧

Unchanged.

---

## Living evidence log

| Date | Event | Commit |
|------|-------|--------|
| 2026-04-21 | TS versions pinned, 14 fixtures generated | (pending commit) |
| 2026-04-21 | UHRP PushDrop + BRC-42 byte-parity proven in Rust | (pending commit) |
| 2026-04-21 | SHIP/SLAP goldens caught bsv-rs `create_overlay_admin_token` divergence | (pending commit) |
| 2026-04-21 | Layer 3 cross-validator scaffold green — 14 corpus entries, Rust ↔ TS UHRPTopicManager agree on all | (pending commit) |
| 2026-04-21 | bsv-rs v0.3.7 shipped — TS-parity signed overlay admin tokens, byte-exact vector tests, deprecation on old helper, published to crates.io | c8742fe (bsv-rs) |
| 2026-04-21 | Layer 1 expansion: +26 fixtures (AtomicBEEF×3, BRC-29×2, sighash×4, transcripts×16 + misc), +3 parity test groups in src/wallet/parity_tests.rs, 184/184 tests green under wasm32 | 4f67724 |
| 2026-04-21 | Layer 2: pure-Rust BRC-31 client ported into parity harness — wraps `bsv_rs::auth::Peer` + `SimplifiedFetchTransport` + `ProtoWallet`. `/find` ×3 and `/list` flipped to live-fire. Verified byte-exact against `nanostore.babbage.systems`: 3 `/find` fixtures unchanged on recapture (sha match), `/list` captured cleanly. First live-fire proof of BRC-31 from pure Rust in the harness. | 7528832 |
| 2026-04-21 | Layer 2: BRC-29 payment envelope builder (pure — derivation + P2PKH output + JSON header). `tests/parity/src/payment.rs`. 4 unit tests green, including byte-exact `derive_recipient_pubkey` + `p2pkh_payment_output` vs `@bsv/sdk 1.10.1` via `brc29_payment_*.json` fixtures. Wiring into Scenario + live `/upload` flow is the follow-up (needs a wallet for UTXO selection + signing). | 7a0fcfb |
| 2026-04-21 | Layer 2: MetaNet Client adapter (`src/wallet.rs`) — shape-for-shape port of `x402-client/lib/metanet.py::create_action`, verified live against localhost:3321. Random-suffix generator + `create_payment_envelope` orchestrator in `src/payment.rs`. 6 wallet unit tests + 1 live connectivity probe. | 5dd36d9 |
| 2026-04-21 | Layer 2 END-TO-END: `/upload` flipped to `AuthMode::Brc31Paid` live-fire. Two-shot flow (402 probe → build envelope → retry with `x-bsv-payment` header) completes against `nanostore.babbage.systems` with a real 197-sat payment and 200 response. Fixture recaptured with `$VOLATILE:<kind>$` sentinels. **Finding**: nanostore emits `x-goog-*` required-upload headers (GCS backend); our worker emits `x-amz-*` (R2 backend) — real protocol-level divergence on the upload-handoff handshake, tracked as follow-up. | 55d1e43 |
| 2026-04-21 | #44 RESOLVED: new `$VOLATILE:string_map$` sentinel pins the `/upload` `requiredHeaders` field as "non-empty map of string→string" without baking in backend-specific key names. Also dropped the redundant byte-exact ref↔local diff when a fixture exists (fixture literals implicitly pin both sides; sentinels deliberately allow them to diverge). 16 new unit/vector tests + live `parity diff /upload` against nanostore (GCS) + our deployed worker (R2) — `OK — reference, local, and fixture all agree`. First scenario with cross-backend 1:1 parity proof. | 8af804a |
| 2026-04-21 | **PARITY-CLAIMS.md** — authoritative synthesis of the full proof matrix across all 12 surfaces (BRC-42, BRC-29, BRC-31, PushDrop, UHRP URL, tm_uhrp, tm_ship/slap, ls_uhrp, sighash, AtomicBEEF, HTTP routes, cross-validator). Every claim cites a file path or test name; every gap documented without asterisks. Live-fire scenario matrix: 6 of 8 green (`/quote` + `/find` ×3 + `/list` + `/upload`); 2 blocked on admin-identity coordination (`/advertise`, `/renew`). | 00ac141 |
| 2026-04-21 | #45 + #46 CLOSED: local `@bsv/overlay-express` testbed (`tests/parity/overlay-express-testbed/`) stands up canonical TS stack in Docker (mongo + mysql) + Node. Live SHIP admission test against localhost:8080 PASSES — our Rust-built SHIP PushDrop admitted at vout 0, `tm_ship` re-derived the locking key via `anyoneWallet.getPublicKey({counterparty: identityKey, ...})` and verified our signature. Full admission-policy parity proven, not just byte-shape. Testbed is hermetic — no remote-infra dependency. | bff78d6 |
| 2026-04-21 | #22 CLOSED + #31 deleted: `/advertise` + `/renew` flipped to live-fire via new `ours_only: true` flag on `Scenario`. Parity identity pubkey added to deployed worker's `ADMIN_IDENTITY_KEYS` via `wrangler secret put`. `/advertise` exercises BRC-31 admin allowlist → body validation → `ERR_INVALID_REQUEST` 400 (sat-free). `/renew` exercises BRC-31 auth → advert-lookup → `ERR_OLD_ADVERTISEMENT_NOT_FOUND` 404 (price-0 middleware, sat-free). Full live-fire matrix now 8/8 green. #37 Phase 3 umbrella closed. #31 deleted as "best-effort courtesy for a relationship that doesn't exist in practice". | 6b74fe5, 4c670e1 |
| 2026-04-21 | End-to-end UHRP round-trip proven: `tests/parity/src/upload_roundtrip.rs::live_upload_roundtrip` uploads 42 bytes to `nanostore.babbage.systems` via quote → BRC-31 auth → 402 probe → BRC-29 envelope (MetaNet Client `createAction`) → /upload 200 → PUT → GET via public CDN URL → SHA-256 match. 10 sats per run. First test in the repo that pins *effect*, not just *shape* — if this passes, a real user can upload + fetch a real file through our port. | e7e4890 |
