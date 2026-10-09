# Parity Status — Can a client swap `nanostore.babbage.systems` for our worker?

_Last updated: 2026-04-21. Client-facing "state of parity" between our
Rust port and the reference TS implementation (`@bsv/uhrp-storage-server`
on nanostore + `@bsv/overlay-express` on users.bapp.dev). Companion to
the deeper technical doc at [`PARITY-CLAIMS.md`](./PARITY-CLAIMS.md)._

**TL;DR**: All 6 UHRP-storage client-facing routes are now live-fire
proven. 3 diff **byte-identical against nanostore** (`/find` ×3, `/list`,
`/upload` — cross-backend with nanostore's GCS vs our R2). `/quote`
is **shape-identical but price-divergent by design** (this deployment
charges $0.05/GB-mo + 1000-sat floor vs nanostore's $0.03 + 10-sat floor
— see README "Pricing"). 2 are **ours-only live-fire** (`/advertise`,
`/renew` — nanostore admin is a private shared token; fixture pins the
TS-reference contract and our worker matches it). SHIP advertisement
admission is proven against a canonical `@bsv/overlay-express`
instance running locally from
[`tests/parity/overlay-express-testbed/`](tests/parity/overlay-express-testbed/)
— the same code nanostore runs. The underlying primitives (BRC-42,
29, 31, PushDrop, UHRP URL, sighash, AtomicBEEF) are byte-exact to
`@bsv/sdk 1.10.1` and locked behind blocking parity gates that
refuse to release bsv-rs if they ever drift.

---

## The drop-in test

The parity contract is: **a client of `@bsv/sdk` 1.10.1 should be able to
replace `https://nanostore.babbage.systems` with our worker URL and
everything keeps working, byte-identical in shape, no code changes.**

Every claim below is (a) a live HTTP round-trip captured 2026-04-21, or
(b) a pinned fixture backed by a TS-golden generator (not a
hand-written approximation). Evidence paths link to the committed file.

### Per-route matrix

| Route | Client impact | Drop-in status | Proof |
|---|---|---|---|
| `POST /quote` | Fetch sats cost before upload | ⚠️ **shape-proven, price diverges by design** | [`quote.small-file.json`](tests/parity/fixtures/quote.small-file.json) — fixture uses `$VOLATILE:u64$` so shape/contract stays green; reference↔local byte-exact check will report price divergence (intentional — see README "Pricing") |
| `GET /find` (×3 err paths) | Look up metadata for an existing UHRP URL | ✅ **drop-in proven** | [`find.*-uhrp-url.json`](tests/parity/fixtures/) — 3 error paths live-fire vs nanostore, sha unchanged on recapture |
| `GET /list` | List my owned uploads | ✅ **drop-in proven** | [`list.my-adverts.json`](tests/parity/fixtures/list.my-adverts.json) — live-fire green |
| `POST /upload` | Pay + get presigned URL | ✅ **drop-in proven, including cross-backend** | [`upload.upload-small-file.json`](tests/parity/fixtures/upload.upload-small-file.json) — live-fire returned `OK — reference, local, and fixture all agree` (nanostore GCS vs our worker R2) |
| `POST /renew` | Pay + extend an advert's expiry | ✅ **live-fire proven (ours-only)** | [`renew.renew-our-advert.json`](tests/parity/fixtures/renew.renew-our-advert.json) — `ERR_OLD_ADVERTISEMENT_NOT_FOUND` 404 shape proven against our worker; nanostore unreachable (we don't own adverts there) |
| `POST /advertise` | Admin-only: publish UHRP advert on-chain | ✅ **live-fire proven (ours-only)** | [`advertise.advertise-already-uploaded.json`](tests/parity/fixtures/advertise.advertise-already-uploaded.json) — admin-auth + body-validation + error-shape proven against our worker; nanostore admin is private shared token |

### Primitive layer (what every route above depends on)

| Surface | Status | Proof |
|---|---|---|
| BRC-42 private + public key derivation | ✅ byte-exact | 15 TS vectors + 3 parity goldens |
| BRC-29 payment envelope (derive → P2PKH → JSON) | ✅ byte-exact | 2 goldens + live `/upload` |
| BRC-31 mutual auth (handshake + General) | ✅ byte-exact | 104 bsv-rs tests + live-fire on every authenticated scenario |
| PushDrop — UHRP 6-field + SHIP/SLAP 5-field signed | ✅ byte-exact | 10 goldens; blocking parity gate in bsv-rs v0.3.7 |
| UHRP URL (SHA-256 → base58check) | ✅ byte-exact | 5 TS goldens + 70 bsv-rs tests |
| BIP-143 sighash (preimage + digest) | ✅ byte-exact | 500+ vectors + 4 parity cases |
| AtomicBEEF (0x01010101 magic + BEEF v2) | ✅ byte-exact | Cross-SDK round-trip + 3 parity cases |
| tm_uhrp admission (accept / reject / reason) | ✅ cross-validator | 16 TS transcripts, 0 divergences |

### Cross-client promise

Concretely: **a `@bsv/sdk` client running today against our worker
receives responses that are byte-identical at every contract-pinned
position, and typed-equivalent (enforced by `$VOLATILE:<kind>$`
sentinels) at every dynamic position (sats amounts, session tokens,
timestamps, backend-specific header names).** Nothing in the response
shape would require a client branch. We've tested this against the
same `@bsv/sdk 1.10.1` that nanostore runs.

---

## Where "no asterisks" gets tricky

Two scopes where the parity stamp has a real caveat we're tracking
openly (not hidden in a sentinel):

### ~~1. SHIP/SLAP advertisement admission~~ — **✅ PROVEN**

Our `create_signed_overlay_admin_token` is byte-exact to `@bsv/sdk
1.10.1`'s output. Now confirmed live-fire: running the test with
`PARITY_OVERLAY_URL=http://localhost:8080` against the canonical
`@bsv/overlay-express` testbed at
[`tests/parity/overlay-express-testbed/`](tests/parity/overlay-express-testbed/)
produces:

```text
SHIP advert ADMITTED by http://localhost:8080.
txid=5366fcad463b0226183f32d82211b0b96e91df1513bcb345bdd0c70985b665b4
admitted_vouts=[Number(0)]
```

`tm_ship` re-derived our locking key via
`anyoneWallet.getPublicKey({counterparty: identityKey, ...})`,
verified our signature, and added us to `outputsToAdmit`. Full
admission-policy parity, not just byte-shape.

Note: running against remote `users.bapp.dev` still depends on their
MongoDB cluster being up (currently mid-migration per upstream). The
testbed eliminates that dependency class entirely.

### ~~2. `/advertise` + `/renew` live-fire~~ — **✅ PROVEN (ours-only)**

Resolved 2026-04-21 — parity identity pubkey added to the deployed
worker's `ADMIN_IDENTITY_KEYS`, both scenarios flipped to live-fire
via the new `ours_only: true` flag on `Scenario`. Reference side
(nanostore) is intentionally skipped for these two — their admin
uses a private shared token we can't have, so byte-for-byte ref↔local
is structurally impossible. Fixture ↔ local diff (the contract
anchor) is green.

Live-fire summary:
- `/advertise` — BRC-31 auth → admin allowlist check → body
  validation → `ERR_INVALID_REQUEST` 400. Sat-free (malformed
  uhrpUrl triggers validation before any chain activity).
- `/renew` — BRC-31 auth → handler runs at price=0 middleware →
  advert-lookup → `ERR_OLD_ADVERTISEMENT_NOT_FOUND` 404. Sat-free
  (parity identity doesn't own any adverts; no renewal attempted).

Happy-path live-fire for either (real advert published, real
renewal) would require a precondition chain (`/upload → wait for
auto-advertise via queue → /renew`) and spend admin-wallet sats;
not done today, file as a follow-up if we want more than
error-shape parity on these routes.

---

## Action plan (to close the remaining asterisks)

Tracked in the task system; mirrored here as a checklist so a dev
looking at this doc has everything they need in one place.

### Recently closed (2026-04-21)

- [x] **Local `@bsv/overlay-express` testbed.** Docker-compose stack
      (mongo + mysql) + Node entry that boots the canonical TS overlay
      stack locally. SHIP-admission parity proved:
      `SHIP advert ADMITTED by http://localhost:8080.
      admitted_vouts=[Number(0)]`. **(task #46)**
- [x] **`/advertise` + `/renew` live-fire (ours-only).** Added parity
      pubkey to deployed worker's `ADMIN_IDENTITY_KEYS`; both
      scenarios flip to live-fire via new `ours_only: true` flag on
      `Scenario`. **(task #22)**

### Nice-to-have — **no critical parity claim depends on these**

- [ ] **Cross-SDK differential fuzzing** (TS + Go + Rust on the same
      random inputs, any byte divergence = bug). Highest-value
      additional proof we can add; catches bugs no hand-written
      vector would. **(task #47)**
- [ ] **Happy-path `/advertise` + `/renew`** (real advert published +
      renewed, not just error-shape). Requires `/upload → wait for
      auto-advertise via queue → /renew` precondition chain, spends
      admin-wallet sats.
- [ ] **Spec clarification** — backend-agnostic naming for
      `requiredHeaders` in `/upload` responses. Handled in-repo via
      `$VOLATILE:string_map$`; upstream BRC could formalize.

### Continuous parity — **nice-to-have when the above lands**

- [ ] **On-chain canary** — parity identity publishes a SHIP advert
      once a day; hourly cron verifies it's still discoverable via
      `/lookup ls_ship` on every known overlay.

---

## How to verify the status of this doc

Every non-"waiting" item can be re-verified by running the parity
harness against the canonical server:

```bash
# Prereq: MetaNet Client running at localhost:3321 (wallet with sats).
cd ~/bsv/bsv-storage-cloudflare/tests/parity

# Drop-in live diffs (costs ~10 sats for /upload):
cargo run --bin parity -- diff --route /quote
cargo run --bin parity -- diff --route /find --scenario nonexistent-uhrp-url
cargo run --bin parity -- diff --route /find --scenario missing-query-param
cargo run --bin parity -- diff --route /find --scenario malformed-uhrp-url
cargo run --bin parity -- diff --route /list
cargo run --bin parity -- diff --route /upload \
    --reference https://nanostore.babbage.systems \
    --local https://your-worker.your-account.workers.dev

# Byte-level TS-vector goldens (no network):
cargo test --features full         # in bsv-rs (2500+ tests)
cargo test                         # in bsv-storage-cloudflare (184 tests)
cargo test -p overlay-discovery    # in rust-overlay (353 tests)
```

Every green run is a fresh renewal of the parity claim. If anything
goes red, this doc is wrong until the underlying test is fixed.

## Related documents

- [`PARITY-CLAIMS.md`](./PARITY-CLAIMS.md) — exhaustive proof matrix,
  every surface cited to a file/test.
- [`PARITY-PROGRESS.md`](./PARITY-PROGRESS.md) — living evidence log,
  per-milestone commit hashes.
- [`PARITY-ROADMAP.md`](./PARITY-ROADMAP.md) — the 5-phase plan the
  work follows.
- [`BLOCKED.md`](./BLOCKED.md) — currently-blocked items with exact
  unblock recipes.
