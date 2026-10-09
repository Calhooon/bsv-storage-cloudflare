# Overlay Mainnet Integration — Plan

> **Goal**: `@bsv/sdk` clients with default config (uhrp-ui, nanostore tools, any BRC-105 consumer) discover and download files hosted by `bsv-storage-cloudflare` without any client-side configuration. Parity with how nanostore + Babbage's own overlays behave.

> **Status on 2026-04-22**: upload path fully working end-to-end. Download path broken: our UHRP adverts are isolated on `your-worker.your-account.workers.dev`, invisible to mainnet SLAP trackers, so default `@bsv/sdk` `LookupResolver({networkPreset:'mainnet'})` returns `[]` → `"No one currently hosts this file!"`.

## Current state vs target state

| Wire | Current | Target |
|---|---|---|
| `bsv-storage-cloudflare` POST of `tm_uhrp` advert | → `rust-overlay` (ours, 1 target) | → `rust-overlay` + `overlay-us-1.bsvb.tech` + `overlay-ap-1.bsvb.tech` + `overlay-eu-1.bsvb.tech` (fan-out) |
| `rust-overlay` self-announce SHIP/SLAP | on-chain via ARC every 15 min, nothing else | on-chain AND POST-submit to `users.bapp.dev/submit` with `tm_slap` and `tm_ship` |
| Our host discoverable via `ls_slap` on mainnet | no | yes (appears alongside `overlay-{us,eu,ap}-1.bsvb.tech`) |
| Client `StorageDownloader.download(uhrp://…)` | throws "No one currently hosts this file!" | resolves, fetches from our R2, hash-verifies, returns bytes |

## Phase 0 — Reference confirmed (2026-04-22)

The mechanism is **`SHIPBroadcaster`**, which is a peer-discovery-driven fan-out, not a hardcoded list. Concretely:

- `overlay-express/src/OverlayExpress.ts` on boot calls `syncAdvertisements()` (engine) which builds SHIP/SLAP PushDrop transactions, on-chain-broadcasts them via ARC, **AND** hands them to `SHIPBroadcaster` to POST to peers.
- `SHIPBroadcaster(['tm_X']).broadcast(tx)` internally:
  1. Queries mainnet `ls_ship` via `LookupResolver` to discover all hosts that run `tm_X`
  2. POSTs the signed BEEF to each discovered host's `/submit` endpoint with `x-topics: ['tm_X']`
- Default SLAP trackers the `LookupResolver` queries: `overlay-us-1.bsvb.tech`, `overlay-eu-1.bsvb.tech`, `overlay-ap-1.bsvb.tech`, `users.bapp.dev` (hardcoded in `@bsv/sdk/src/overlay-tools/LookupResolver.ts:42`).
- `storage-server/src/utils/createUHRPAdvertisement.ts:85` uses exactly this: `new SHIPBroadcaster(['tm_uhrp']).broadcast(tx)`. No hardcoded target URL.

**So the correct fix is NOT "POST to a hardcoded list of mainnet URLs". It's: port `SHIPBroadcaster`'s peer-discovery+fan-out behavior to Rust, and use it for both UHRP and SHIP/SLAP submissions.**

Phases 2 and 3 below are updated to match.

## Phase 1 — Live probe (no code, no destructive action)

Prove the mainnet endpoints actually accept un-announced submissions. Two probes:

1. **SLAP probe**: construct ONE valid `tm_slap` PushDrop advertising `your-worker.your-account.workers.dev` as an `ls_uhrp` + `tm_uhrp` host, signed by `ADMIN_WALLET_PRIVATE_KEY`, broadcast on-chain via ARC, wrap in AtomicBEEF, POST to `users.bapp.dev/submit` with `x-topics: ["tm_slap"]`. Expected response: 200. Secondary check: query `ls_slap` 60s later and confirm our URL is in the output list.
2. **UHRP probe**: take ONE of our existing in-flight `tm_uhrp` adverts (already broadcast on-chain, already has a BEEF), POST it to `overlay-us-1.bsvb.tech/submit` with `x-topics: ["tm_uhrp"]`. Expected response: 200. Secondary check: query `ls_uhrp` on that host and confirm our record appears.

**Acceptance criterion for Phase 1**: both probes return 200 and the respective `ls_*` queries return our records within 60s. If either rejects us, stop and surface the error — may need Babbage cooperation.

## Phase 2 — Implement `SHIPBroadcaster` in Rust (shared helper)

**Scope**: new helper crate-or-module usable by both `bsv-storage-cloudflare` and `rust-overlay`.

API sketch:
```rust
pub struct ShipBroadcaster {
    topics: Vec<String>,           // e.g. ["tm_uhrp"] or ["tm_ship"]
    slap_trackers: Vec<String>,    // default: DEFAULT_SLAP_TRACKERS (see TS SDK)
}

impl ShipBroadcaster {
    pub async fn broadcast(&self, beef_bytes: &[u8]) -> BroadcastResult;
}
```

Behavior for `broadcast(beef)`:
1. For each `slap_tracker`, POST `/lookup` with `{service:"ls_ship", query:{topics: self.topics}}` → returns list of peer URLs.
2. Deduplicate peer URLs across trackers.
3. POST the BEEF to every peer's `/submit` with `x-topics: self.topics` header, in parallel.
4. Return per-target {host, status, body} so callers can log.

Defaults lifted from TS SDK:
```
DEFAULT_SLAP_TRACKERS = [
  "https://overlay-us-1.bsvb.tech",
  "https://overlay-eu-1.bsvb.tech",
  "https://overlay-ap-1.bsvb.tech",
  "https://users.bapp.dev",
]
```

**Tests**: Mocked tracker responses; live integration test that queries `ls_ship` with topic `tm_uhrp` and confirms at least 1 peer is returned.

## Phase 3 — Wire `ShipBroadcaster` into both workers

**`bsv-storage-cloudflare/src/overlay/mod.rs`**: after signing the `tm_uhrp` advert BEEF, call `ShipBroadcaster::new(["tm_uhrp"]).broadcast(beef)` INSTEAD OF POSTing to the hardcoded `OVERLAY_SUBMIT_URL`. Keep `OVERLAY_SUBMIT_URL` fallback for one release as `additional_peer` option, so our own `rust-overlay` still gets a copy (useful for GASP sync downstream).

**`rust-overlay/src/advertiser.rs`**: inside `CloudflareAdvertiser::sync_advertisements()` cron tick:
1. (existing) Build SHIP/SLAP PushDrops, broadcast on-chain via ARC → produces BEEF.
2. **NEW**: For each SHIP advert, call `ShipBroadcaster::new(["tm_ship"]).broadcast(beef)`.
3. **NEW**: For each SLAP advert, call `ShipBroadcaster::new(["tm_slap"]).broadcast(beef)`.
4. Log per-peer results; cron does not fail on partial success.

**Tests**: live check after deploy that `users.bapp.dev/lookup` with `{service:"ls_slap", query:{service:"ls_uhrp"}}` includes our `your-worker.your-account.workers.dev` in the result.

## Phase 4 — End-to-end verification

1. Fresh upload to `bsv-storage-cloudflare` produces a UHRP URL.
2. Query `overlay-us-1.bsvb.tech/lookup` with `ls_uhrp` and that URL → returns our advert.
3. Query `users.bapp.dev/lookup` with `ls_slap` and `service:"ls_uhrp"` → includes our rust-overlay URL.
4. From uhrp-ui in a clean browser tab, paste the UHRP URL into Download tab → file downloads successfully, SHA-256 matches.
5. Mirror test with Python `@bsv/sdk` equivalent or raw `StorageDownloader` script — proves zero client config needed.

**Acceptance criterion for Phase 4**: all 5 checks green from a fresh client session.

## Phase 5 — Close out

- Update `PARITY-STATUS.md`: UHRP + SLAP propagation green against mainnet.
- Update `PARITY-CLAIMS.md`: add rows for `ls_slap` self-registration + cross-host UHRP fan-out.
- Update `~/bsv/bsv-storage-cloudflare/FUZZ-PLAN.md` or the fuzz repo if any new byte-exact goldens are worth adding (probably the SHIP/SLAP PushDrop shape vs TS reference).
- Remove the `wrangler.toml` comment that says *"round-trip is entirely Calgooon-owned"* — that was a deliberate choice that broke client parity, and the correction is worth documenting for the next person who reads it.

## Risks

- **Acceptance gate at `users.bapp.dev`**: Unverified. Phase 1 probe is designed to find out cheaply.
- **Rate limits** once we're fan-out posting per-upload: real traffic volume is low today, but worth instrumenting.
- **Mainnet hosts may drop us silently** during migrations (Brayden mentioned MongoDB migration was in progress weeks ago). Our `rust-overlay` cron re-submits every 15 min, so transient drops self-heal.
- **Signing identity**: mainnet SLAP trackers may eventually allowlist/denylist by pubkey. Document our `ADMIN_WALLET_PRIVATE_KEY` pubkey so Babbage has a known entity to contact if ever needed.

## Open questions for phase 0

- Does `@bsv/overlay-express` have a `slapTrackers` config with default `["https://users.bapp.dev"]` that auto-submits on boot?
- Does `@bsv/uhrp-storage-server` ship with a default list of `tm_uhrp` submission targets?
- Is there an implicit registration mechanism (e.g., nanostore's `storage.babbage.systems` got onto SLAP because Babbage literally `ssh`'d into `users.bapp.dev` and seeded it, i.e., not a protocol path) that we can't replicate without their cooperation?

---

_Owner: whoever picks this up next. Last updated 2026-04-22._
