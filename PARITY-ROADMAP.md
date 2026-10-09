# 1:1 Parity Roadmap — `bsv-storage-cloudflare` + `rust-overlay`

_Last reviewed: 2026-04-21_

## What "1:1 parity" means here

Our implementations are protocol-compatible with the TS reference stack
if and only if:

1. **Protocol bytes match.** The PushDrop bytes, BEEF bytes, BRC-42
   derivations, BRC-29 payment payloads, signature preimages, and
   script templates are byte-identical to what `@bsv/sdk` /
   `@bsv/wallet-toolbox` / `@bsv/overlay` produce for the same
   logical inputs.

2. **Wire responses match.** Every HTTP route on
   `bsv-storage-cloudflare` returns the same JSON shape,
   status codes, and error codes as the TS
   `storage-server` for the same request. Deliberate
   divergences are documented in `PROTOCOL.md`.

3. **Overlay admission rules match.** `tm_uhrp`,
   `ls_uhrp` on `rust-overlay` make the same admit/reject
   decisions on the same PushDrop outputs as the TS
   `uhrp-services` topic manager.

**What parity does NOT require:**

- That `overlay-us-1.bsvb.tech` accept BEEFs we build. Their
  overlay's SPV/script-validation layer is **stricter than the
  spec** — they enforce clean-stack on every ancestor input
  spend in the BEEF, which is not a UHRP or overlay-spec
  behaviour. Our `rust-overlay` correctly runs `tm_uhrp`
  against the PushDrop **output** and admits. Bsvb's refusal
  to accept pushed BEEFs is bsvb-policy, not our protocol
  bug.
- That we use a specific UTXO set, run a specific selector,
  or maintain a "clean" wallet. The wallet's job is to sign
  what the overlay wants admitted; as long as our PushDrop
  output is correct, the overlay is happy. Input-selection
  concerns belong in wallet ops, not in parity.

---

## Closed gaps (green)

| # | Area | Summary | Commit |
|---|------|---------|--------|
| 19 | rust-overlay | `CloudflareAdvertiser` produces real on-chain SHIP/SLAP tokens via wallet-infra createAction + local signer + AtomicBEEF. Replaces the `None` advertiser. | `279e20c` |
| 20 | rust-overlay | 15-min cron calls `sync_advertisements` + `start_gasp_sync`. `sync_configuration` pre-populated for the topics we carry. | `a8b945f` |
| 23 | bsv-storage | `/find` auth policy divergence from nanostore (their `allowUnauthenticated: true` vs our `false`) documented in `PROTOCOL.md` §3. Deliberate, preserved. | `fde90cb` |
| 24 | rust-overlay | `tm_uhrp` expiry check relaxed from `expiry ≤ now()` to `expiry < 1` — matches TS `UHRPTopicManager.ts:55`. Past-expiry admits. | `3e957b9` |
| 25 | bsv-storage | Diagnostic logging retention decided: keep both blocks, downgrade the per-build dump from `console_error` to `console_log`. | `fde90cb` |
| 26 | rust-overlay | PR #51 opened: https://github.com/Calgooon/rust-overlay/pull/51 | `a8b945f` |
| — | bsv-storage | **Signer fix** (`reconstruct_change_outputs`) fills in empty change-output locking scripts via BRC-29 self-send derivation. Byte-exact match for `@bsv/wallet-toolbox`'s `buildSignableTransaction.ts::makeChangeLock:167-183`. Every new advert has a standard 25-byte P2PKH change output. | `18979a7` |
| — | rust-overlay | `tm_uhrp` wasm32 panic fix (cfg-gated `js_sys::Date`); TS-parity URL check (https scheme only, no BRC-101 `is_advertisable_uri`); `/submit` diag logging on zero-admit. | `0a703e8` |
| — | bsv-storage | Two focused unit tests proving on-chain bytes are validator-admissible (`validator_admits_our_advert`, `on_chain_advert_parses_and_linkage_check`). | `91b9a04` |

---

## Open gaps

### P0 — parity harness can't actually diff live today

`tests/parity` is a scaffold, not a client. `src/auth.rs` is an empty
stub, the `Scenario` struct has no `headers` field, `execute()` sends
unsigned HTTP. Five of six routes `skip_reason = ...` because the
infrastructure to make authenticated + paid requests doesn't exist
yet.

**Required to unblock CI-automated cross-server diffing:**

- **#28** Port BRC-31 client into parity harness. Handshake +
  session cache + general-message signing. Reference:
  `~/bsv/x402-client/scripts/brc31_helpers.py`. Drop-in
  replacement for the current `auth.rs` stub.
- **#29** Extend `Scenario` struct with `headers:
  HashMap<String,String>` + `required_auth: AuthMode` enum.
  `execute()` needs to sign requests + merge scenario
  headers + handle 402 retry loop.
- **#30** BRC-29 payment builder. Given a 402 response,
  construct `x-bsv-payment` body (derivationPrefix,
  derivationSuffix, signed tx). Required for `/upload` +
  `/renew`.

**Then:**

- **#22** Flip `skip_reason = None` on every scenario that
  can run live. Exception: `/advertise` (admin auth model
  differs intentionally — see §Documented divergences). CI
  runs the diff on every PR.

Scope: ~400-600 LOC + tests, single focused session.

### P1 — overlay-side lookup correctness

- **#33** Add expired-record filter at `ls_uhrp` query
  layer. tm_uhrp now admits past-expiry (TS parity), so
  the "hide stale" responsibility is at the lookup layer.
  TS reference doesn't filter either, but we can opt into
  stricter behaviour behind a `{includeExpired: true}`
  query flag. Scope: ~50 LOC + 2-3 tests.

### P2 — optional convenience bridges

These exist only because `overlay-us-1.bsvb.tech` doesn't speak
GASP. Drop when they do, or when a second GASP peer
appears. Not required for parity.

- **#31** CloudflareAdvertiser mirrors new TaggedBEEFs to
  configured external `/submit` endpoints (best-effort,
  fail-soft).
- **#32** Scheduled peer_crawler wiring (module already
  written at `overlay-cloudflare/src/peer_crawler.rs` with
  8 unit tests — just needs invocation from `lib.rs` cron
  handler + `/admin/crawlPeers` route).

---

## Documented divergences (intentional — not bugs)

Preserved in `PROTOCOL.md` and/or source comments:

1. **`/find` requires auth.** Nanostore uses
   `allowUnauthenticated: true`; we require BRC-31.
   Stricter-by-design; clearer error codes (401 vs 500).
   Flippable by changing `allow_unauthenticated:` in
   `src/lib.rs:63`.

2. **`/advertise` admin model.** Nanostore gates on a shared
   `ADMIN_TOKEN` string; we gate on a comma-separated
   pubkey allowlist (`ADMIN_IDENTITY_KEYS`). Strictly
   stronger.

3. **`/find` response when unauth.** By side-effect of (1), we
   return `401 ERR_UNAUTHORIZED`; they return `500
   ERR_FIND` after hitting the scoped-identity empty-result
   path. Both surface "no data for you", different codes.

---

## Proof plan — "how do we demonstrate 1:1?"

The goal is **CI-automated evidence**, not manual spot checks.

### Layer 1 — unit + golden tests (already green)

- PushDrop byte-exact fixtures in `tests/fixtures/pushdrop/*.json`
- BRC-42 cross-SDK vectors in `bsv-rs`
- Signer roundtrip + deterministic-k tests
- `tm_uhrp`'s full 43-test suite + `validator_admits_our_advert`

### Layer 2 — live parity harness (blocked by P0)

Once #28 + #29 + #30 + #22 land, every PR runs:

```
for route in /quote /find /list /upload /advertise /renew:
  our_response  = POST your-worker.your-account.workers.dev/<route>
  their_response = POST nanostore.babbage.systems/<route>
  diff(our_response, their_response, volatile_sentinels)
```

Any drift surfaces as a CI failure with field-level diff.

### Layer 3 — overlay admission parity

A test that:

1. Builds a UHRP advert using our stack.
2. Extracts the PushDrop output.
3. Runs BOTH `tm_uhrp` implementations (ours in
   `overlay-discovery`, theirs in `uhrp-services`) over
   the same output bytes.
4. Asserts both return `admitted = true`.

Can live as an integration test that vendors the TS validator
or shells out to Node. Scope: ~150 LOC + a small Node companion.
Doesn't need any network / signed tx.

---

## Ordering

Do in this order, no side-quests:

1. **P0 bundle** (#28 → #29 → #30 → #22). Single session. ~6-8h.
2. **#33** ls_uhrp expiry filter. Small, standalone. ~1h.
3. **Layer 3 proof test** (overlay admission parity). Standalone. ~2h.
4. **P2 convenience** (#31, #32) — only if there's actual demand.

At the end of step 3, "CI green" is a provable statement that our
protocol layer and our overlay admission logic match the TS
reference byte-exact and behaviorally.

---

## What this roadmap explicitly does NOT include

- Anything about the admin wallet's UTXO set. A UTXO is
  spendable or it isn't. If the signer can sign it, we can
  build valid adverts. The overlay validates the resulting
  PushDrop output, not the ancestor spend chain.
- Anything about `overlay-us-1.bsvb.tech` accepting our
  BEEFs. Their script-validation strictness is outside the
  UHRP spec; our adherence to the spec is independent of
  their policy.
- Manual ops tasks like "fund the wallet", "run
  fund-admin.py", "relinquish outputs". Those are deploy
  maintenance, not parity.
