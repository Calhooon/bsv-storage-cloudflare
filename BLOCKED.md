# Blocked / In-Flight — Parity Work

_Tasks that are built-out but can't be fully verified right now,
usually because of an external dependency. Source-of-truth doc so we
don't lose track of what's ready to re-attempt when blockers clear._

_Last updated: 2026-04-21._

## Why this file exists

Some parity claims can't be closed in-session because they depend on
external infra that's currently unavailable or requires a coordinated
config change we haven't authorized yet. Rather than mark these as
"done with asterisks" or leave stale `skip_reason` strings, we list
them here with the exact blocker and the exact unblock recipe.

---

## ~~1. SHIP advert admission vs `users.bapp.dev`~~ — **CLOSED 2026-04-21**

Resolved via task #46 (local overlay-express testbed). Running
`PARITY_OVERLAY_URL=http://localhost:8080 cargo test live_ship --
--ignored --nocapture` against
`tests/parity/overlay-express-testbed/` produces:

```
SHIP advert ADMITTED by http://localhost:8080.
txid=5366fcad… admitted_vouts=[Number(0)]
```

Full admission-policy parity proven against a canonical
`@bsv/overlay-express` (same code nanostore runs), not just
byte-shape. The remote `users.bapp.dev` path can re-run the moment
their MongoDB migration completes, but that's no longer on the
critical path — the testbed gives us hermetic reproducibility
forever.

## 2. `/advertise` + `/renew` live-fire (task #22 residual)

**What we built**

- BRC-31 + BRC-29 harness (tasks #28 + #30) fully green for
  `/find`/`/list`/`/upload`.
- `src/routes/advertise.rs` and `src/routes/renew.rs` scenarios
  committed with concrete `skip_reason` strings documenting the
  remaining blockers.
- `fixtures/advertise.advertise-already-uploaded.json` +
  `fixtures/renew.renew-our-advert.json` pin the TS-reference
  response shape with `$VOLATILE:<kind>$` sentinels.

**Blockers**

- **`/advertise`** — our worker gates on `ADMIN_IDENTITY_KEYS` env
  secret; the parity identity
  (`027c0f60f2c5f70788a4b2331c58cc37515fa3ff4ee7acaa16593764e334edde0a`)
  isn't in that allowlist yet. Adding it modifies shared infra on
  `your-worker.your-account.workers.dev`, so it needs
  explicit authorization. Nanostore's admin auth uses a private
  shared token we can't access either way, making this scenario
  intrinsically ours-only regardless.
- **`/renew`** — BRC-31 identity of the caller must *own* the advert
  being renewed. The parity identity has no owned adverts on our
  worker. Needs a precondition pipeline: `/upload` → (auto) advert
  → `/renew` — which threads three signed/paid requests through the
  harness. Additive-but-manageable work once `/advertise` clears.

**Unblock recipe**

1. Export `CLOUDFLARE_API_TOKEN` from `~/bsv/bsv-storage-cloudflare/secrets.md`.
2. `wrangler secret put ADMIN_IDENTITY_KEYS` (paste existing value
   appended with `,027c0f60f2c5f70788a4b2331c58cc37515fa3ff4ee7acaa16593764e334edde0a`).
3. Flip `src/routes/advertise.rs` `skip_reason: None`, `auth:
   AuthMode::Brc31`. Capture + commit fixture. Ours-only diff.
4. For `/renew`: add a short chained scenario runner that does
   `/upload` → poll until advert exists → `/renew`. Scope = ~60
   lines in `src/routes/renew.rs`.

## 3. Task #31 — CloudflareAdvertiser push to non-GASP peers

Already reframed in task notes as "best-effort courtesy, not a
production blocker". Left `pending` deliberately. Not blocked by
external infra; just unwired because there's no real need today.
Ready whenever a non-GASP peer surfaces that needs push.

## 4. Task #32 — peer_crawler cron wiring

Fully implemented at
`~/bsv/rust-overlay/crates/overlay-cloudflare/src/peer_crawler.rs`
(280 lines + 7 unit tests, all green on wasm32). Just needs a
two-line addition to the scheduled cron handler. Not blocked by
external infra.

---

## How to triage this file

When something changes (external infra recovers, a config is granted,
a blocker dissolves), *replace* the section with a link to the commit
that closes it and update `PARITY-PROGRESS.md`'s living log. Don't
just delete — the audit trail from "blocked because X" to "unblocked
by Y" is part of the proof matrix.
