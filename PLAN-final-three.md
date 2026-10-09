# Plan: close the last three items

Three items remain before `bsv-storage-cloudflare` is a full-stack Calgooon deployment with CI-gated parity enforcement.

**Dropped**: a `bsv-middleware-cloudflare 0.1.2` publish for a debug-log addition. Not worth a crates.io version. Roll it into the next real change.

---

## Overview

| # | Item | Target | Wall time | Agent? |
|---|---|---|---|---|
| 1 | Port `tm_uhrp` + `ls_uhrp` to `rust-overlay` | `~/bsv/rust-overlay/crates/overlay-discovery/uhrp/` | 4–6h | Wave 1, single agent |
| 2 | Wire R2 event notifications → Queue | CF dashboard + `wrangler r2 bucket notification create` | 30 min | Wave 2, parallel |
| 3 | Parity harness covers all 6 routes | `~/bsv/bsv-storage-cloudflare/tests/parity/` | 3–4h | Wave 2, parallel |

**Ordering rationale**: (1) finishes first because (3) gets a real target (`your-worker.your-account.workers.dev` running `tm_uhrp`) to add a parity scenario against. (2) and (3) don't touch each other's files so they run concurrently once (1) lands.

---

## Item 1 — Port `tm_uhrp` + `ls_uhrp` to rust-overlay

### Context & constraints

- **No TS reference on disk or npm**. `@bsv/overlay-discovery-services` ships SHIP + SLAP only. So the port is from `~/bsv/bsv-storage-cloudflare/PROTOCOL.md` §B plus observation of the live `tm_uhrp` at `overlay-us-1.bsvb.tech`.
- **SHIP is the structural pattern** — `~/bsv/rust-overlay/crates/overlay-discovery/src/ship/topic_manager.rs` and `ship/lookup_service.rs` are the shape we copy. SHIP uses an `OverlayAdminTokenTemplate` + `PushDrop::decode`. UHRP uses `PushDrop::decode` directly with different field shape.
- **Byte-parity oracle**: `overlay-us-1.bsvb.tech` already runs UHRP admittance. We submit known BEEFs built by our `bsv-storage-cloudflare` `/advertise` flow; if bsvb admits them, our topic manager must admit the same bytes. If bsvb rejects ours, they're protocol-compliant and we do too.

### Reference implementations on disk

| File | What it gives us |
|---|---|
| `~/bsv/bsv-storage-cloudflare/PROTOCOL.md` §B | 5-field layout + signature field + script shape (`push_6` + `OP_2DROP × 3`) |
| `~/bsv/bsv-storage-cloudflare/src/uhrp/pushdrop.rs` | Our own lock-side implementation — the unlock-side admittance logic is the inverse |
| `~/bsv/bsv-storage-cloudflare/tests/fixtures/pushdrop/*.json` | 4 byte-equal goldens generated from `@bsv/sdk v1.8.2` — these are our fixture library for the topic manager's validator |
| `~/bsv/storage-server/src/utils/createUHRPAdvertisement.ts` | TS author-side field construction — confirms field order/encoding |
| `~/bsv/rust-overlay/crates/overlay-discovery/src/ship/topic_manager.rs` | SHIP TopicManager — copy the skeleton, swap the field checks |
| `~/bsv/rust-overlay/crates/overlay-discovery/src/ship/lookup_service.rs` | SHIP LookupService — copy, swap indexing (uhrp_url → host URL instead of topic_name → host URL) |
| `~/bsv/rust-overlay/crates/overlay-discovery/src/validation.rs` | `is_advertisable_uri`, `is_token_signature_correctly_linked`, etc. — reuse as-is |

### Files to create

```
~/bsv/rust-overlay/crates/overlay-discovery/src/uhrp/
├── mod.rs                       # pub mod topic_manager; pub mod lookup_service;
├── topic_manager.rs             # UHRPTopicManager: validates 5-field PushDrop + signature
├── lookup_service.rs            # UHRPLookupService: indexes by uhrp_url hash
└── storage.rs (trait)           # UHRPStorage trait (paralleling ShipStorage)
```

### Validation logic (the core of topic_manager.rs)

For each output in the submitted BEEF's tx:

1. `PushDrop::decode(locking_script)?` → 5 data fields + locking pubkey
2. `field[0]` = 33-byte compressed pubkey (server identity)
3. `field[1]` = 32 bytes (SHA-256 of file)
4. `field[2]` = non-empty UTF-8 URL (validate via `is_advertisable_uri` from `validation.rs`)
5. `field[3]` = `Writer::read_var_int_num` → positive u64 → must be `>= now()`
6. `field[4]` = `Writer::read_var_int_num` → positive u64 (content length, `> 0`)
7. `field[5]` (appended by `PushDrop::lock(…, includeSignature=true)`) = ECDSA signature over `concat(field[0..4])` that verifies against `field[0]`'s pubkey
8. Verify `is_token_signature_correctly_linked(locking_pubkey, field[0])` — the PushDrop locker is a BRC-42 child of the identity in field 0 (matches SHIP's linkage check)

Any failure → skip that output (don't admit). Success → add to `AdmittanceInstructions.outputsToAdmit`.

### Lookup service (lookup_service.rs)

Parallels SHIP's structure. Key query: given a `uhrpUrl`, return the list of hosting endpoints (field[2] values). D1 schema:

```sql
CREATE TABLE IF NOT EXISTS uhrp_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  txid TEXT NOT NULL,
  output_index INTEGER NOT NULL,
  uhrp_url TEXT NOT NULL,        -- indexed for lookups
  identity_key TEXT NOT NULL,
  download_url TEXT NOT NULL,
  expiry_time INTEGER NOT NULL,
  content_length INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(txid, output_index)
);
CREATE INDEX IF NOT EXISTS idx_uhrp_url ON uhrp_records(uhrp_url);
CREATE INDEX IF NOT EXISTS idx_uhrp_identity ON uhrp_records(identity_key);
```

Append to the `OVERLAY_MIGRATIONS` const in `~/bsv/rust-overlay/crates/overlay-cloudflare/src/d1/mod.rs` — since migrations run idempotently at every worker startup, no separate migration command.

### Registration

Patch `~/bsv/rust-overlay/crates/overlay-cloudflare/src/lib.rs:173-181`:

```rust
managers.insert("tm_uhrp".to_string(), Box::new(UHRPTopicManager::new()));
// and in the lookup services map:
services.insert("ls_uhrp".to_string(), Box::new(UHRPLookupService::new(storage.clone())));
```

### Tests

- **Unit tests** — mirror SHIP's test suite: valid advert → admit, wrong field count → reject, bad signature → reject, non-pubkey field[0] → reject, expired advert → reject (optional per spec — decide on policy).
- **Fixture tests** — `tests/fixtures/uhrp_advert_valid.beef` (one byte-equal advert we built from `/advertise`). Assert topic manager admits. Add a synthetically-corrupted version, assert rejects.
- **Live smoke test** (gated on an env var like the SHIP suite) — submit the same fixture BEEF to both `overlay-us-1.bsvb.tech/submit` and `your-worker.your-account.workers.dev/submit`, assert both return an identical Steak shape (admitted/rejected, same reason). This is the canonical byte-parity proof.

### Deploy

```bash
cd ~/bsv/rust-overlay/crates/overlay-cloudflare
source ~/bsv/rust-chaintracks/secrets.md   # or export CF token manually
wrangler deploy
curl https://your-worker.your-account.workers.dev/listTopicManagers | jq '.tm_uhrp'
# expect: {"name":"Universal Hash Resolution Protocol","shortDescription":"..."}
```

### Flip `bsv-storage-cloudflare` back

Once rust-overlay admits our `/advertise` fixture:

```toml
# ~/bsv/bsv-storage-cloudflare/wrangler.toml
OVERLAY_SUBMIT_URL = "https://your-worker.your-account.workers.dev"
```

Deploy, run `/advertise` end-to-end, confirm 200 + `/list` shows + `/find` returns metadata + public URL serves — same sequence we just completed against bsvb.

### Success criteria (Item 1)

- [ ] `~/bsv/rust-overlay/` has `crates/overlay-discovery/src/uhrp/{topic_manager,lookup_service,storage}.rs`
- [ ] Unit tests + at least one fixture test pass (`cargo test -p overlay-discovery uhrp`)
- [ ] Deployed to `https://your-worker.your-account.workers.dev`
- [ ] `/listTopicManagers` includes `tm_uhrp` with name + shortDescription
- [ ] Submitting a known advert to both `bsvb.tech` and our rust-overlay produces admitted-true on both
- [ ] `OVERLAY_SUBMIT_URL` flipped in `bsv-storage-cloudflare`; `/advertise` round-trip still green
- [ ] Commit message references: PROTOCOL.md §B, the SHIP topic manager it mirrors, the npm ecosystem gap it fills
- [ ] Optionally: open an issue on `@bsv/overlay-discovery-services` offering a TS port (community upstream)

### Agent brief (Wave 1)

- **Scope**: `~/bsv/rust-overlay/` only. Do NOT touch `bsv-storage-cloudflare` except the final `OVERLAY_SUBMIT_URL` flip commit (separate PR/commit).
- **Start with**: read `~/bsv/rust-overlay/CLAUDE.md`, `crates/overlay-discovery/src/ship/{topic_manager,lookup_service}.rs`, and `~/bsv/bsv-storage-cloudflare/src/uhrp/pushdrop.rs`.
- **Reference oracle**: the 4 golden fixtures at `~/bsv/bsv-storage-cloudflare/tests/fixtures/pushdrop/*.json` AND the live overlay at `overlay-us-1.bsvb.tech`.
- **Quality gate**: rust-overlay's own `cargo test --workspace`, plus the live smoke test against both overlays returning identical Steak shapes.
- **Commit style**: match rust-overlay's existing commit cadence (see `git log`).
- **Deploy + publish checklist** in the commit message.

---

## Item 2 — Wire R2 event notifications → Queue

### Goal

When a client PUTs a file to R2 (via our `/upload` presigned URL), CF R2 emits an `object-create` event onto the `uhrp-post-upload` queue; our `#[event(queue)]` consumer in `bsv-storage-cloudflare/src/lib.rs` fires; it calls `queue::process_message` which calls `routes::advertise::create_advertisement` to auto-publish the UHRP advert on-chain.

The consumer code is already written and committed. All that remains is the CF-side wiring.

### Exact commands

```bash
# From ~/bsv/bsv-storage-cloudflare/, CF token in env:
export CLOUDFLARE_API_TOKEN=<from secrets.md>
export CLOUDFLARE_ACCOUNT_ID=ea3e6d176ed3893258fe34281f710c7f

# Create the event-notification rule
npx wrangler r2 bucket notification create uhrp-prod \
  --event-types object-create \
  --queue uhrp-post-upload \
  --prefix cdn/

# (the --prefix cdn/ filters to uploads landed by /upload's presigned URL path;
# avoids firing for any admin-uploaded R2 objects outside the UHRP flow)

# Verify
npx wrangler r2 bucket notification list uhrp-prod
```

Flags confirmed against wrangler 3.114.17:
- `--event-types`: `object-create` or `object-delete` (array)
- `--queue <name>`: accepts queue NAME not UUID
- `--prefix`: literal string, no regex
- `--description`: optional human label

### Smoke test — end-to-end auto-advertise

1. Tail `wrangler tail` on our worker.
2. Run `/x402 pay /upload` for a file different from the test.html we already advertised.
3. PUT bytes to the presigned URL.
4. Watch the tail for `[queue]` log lines from `src/queue/mod.rs::process_message`.
5. Watch for a `[advertise]` / `create_advertisement` log indicating auto-advert fired.
6. Run `/find?uhrpUrl=uhrp://<new_hash>` — should return metadata without ever having hit `/advertise` manually.

### Idempotency check (risk mitigation)

CF Queues deliver **at-least-once**. Our `create_advertisement` must be safe to call twice for the same (uhrp_url, uploader, expiry). Currently: re-calling builds a new tx with fresh UTXOs, wastes ~200 sats, both adverts land on-chain + overlay indexes both. **Not ideal but not catastrophic** — `/list` returns both, `/find` picks max-expiry.

**Recommended mitigation** (optional, can be Item 2.1 if we care): before `create_advertisement` in the queue consumer, `listOutputs` for tag `uhrp_url_<hex>` + `uploader_identity_key_<caller>` — if any non-expired advert already exists, skip. One extra RPC per message. Order-of-10-ms cost.

### Success criteria (Item 2)

- [ ] `wrangler r2 bucket notification list uhrp-prod` shows our rule
- [ ] Upload a new file via `/x402 pay /upload` + PUT; wait < 30s; `/find` by its uhrp URL returns metadata without a manual `/advertise` call
- [ ] On-chain tx exists for the advert (verify via WoC)
- [ ] Idempotency test: trigger the same R2 object twice (re-PUT same bytes to same key, or replay message manually); at most one `/find`-visible advert persists OR both land and `/find` picks the latest

### Agent brief (Wave 2a)

- **Scope**: run the `wrangler r2 bucket notification create` command, verify via `list`, then run the end-to-end smoke test. If the idempotency check doesn't hold and we care, add the dedupe `list_outputs` guard in `src/queue/mod.rs` as a small commit.
- **No new code** unless the idempotency guard is needed.
- **30-min task**.

---

## Item 3 — Extend parity harness to all 6 routes

### Current state

`~/bsv/bsv-storage-cloudflare/tests/parity/` covers `/quote` only, byte-exact vs nanostore. Infrastructure:
- `src/identity.rs` — persistent BRC-31 identity (gitignored file, chmod 600, auto-generated)
- `src/canon.rs` — RFC 8785 JCS canonicalization for byte-exact JSON diff
- `src/fixture.rs` — contract-only fixture format, append-only `.captures.log`
- `src/routes/` — one module per route, currently just `quote.rs`

### Add scenarios

One module per remaining route. For each: define input(s), canonicalize both nanostore + ours responses, assert byte-exact (for pure-shape scenarios) or schema-equal (for state-dependent scenarios).

| Route | Scenarios | Byte-exact or shape-equal? |
|---|---|---|
| `/find` | 3 new: `nonexistent-uhrp-url`, `missing-query-param`, `malformed-uhrp-url` | **byte-exact** (all error paths) |
| `/list` | 1 new: `my-adverts` with MetaNet identity | **shape-equal** (nanostore has 96 adverts, we have 1) — assert both return `{status, uploads: [{uhrpUrl, expiryTime}]}` with same JSON key order |
| `/upload` | 1 new: `upload-small-file` | **schema-equal** (uploadURL target + signing keys differ nan→GCS, ours→R2 S3, but field names/types/order must match). Skip against nanostore due to known GCP 8KB header 413 issue — hit ours only, assert shape matches the frozen TS spec fixture. |
| `/advertise` | 1 new: `advertise-already-uploaded` | **ours-only** (nanostore's admin isn't us). Assert `{status: "success"}` exactly, then verify observable side effects: tx on-chain (WoC) + `/list` reflects + `/find` returns metadata |
| `/renew` | 1 new: `renew-our-advert` | **ours-only** (renew requires existing advert; same logic — assert side effects) |

### Markers for dynamic values

Contract fixtures stay byte-stable across captures unless the **shape** changed. Dynamic values use sentinel tags:

```json
{
  "route": "/quote",
  "scenario": "small-file",
  "request": {"fileSize": 1048576, "retentionPeriod": 43200},
  "response": {
    "status_code": 200,
    "body": {"quote": "$VOLATILE:u64$"}
  }
}
```

Update `src/canon.rs` + `src/routes/resolve.rs`:
- A field whose fixture value is `"$VOLATILE:<rust-type>$"` is typechecked (live value must be of that type) but not equality-compared.
- Allowed types: `u64`, `string`, `iso8601`, `hex32`, `hex66`, `uhrp_url`, `array`, `object`.

### CI gate

GitHub Actions job `parity-smoke` already runs `cargo run -p parity --bin parity -- diff --route /quote`. Extend:

```yaml
- name: parity diff — all routes
  env:
    PARITY_IDENTITY_KEY: ${{ secrets.PARITY_IDENTITY_KEY }}
    PARITY_REFERENCE_URL: https://nanostore.babbage.systems
    PARITY_LOCAL_URL: https://your-worker.your-account.workers.dev
  run: |
    set -e
    for route in /quote /find /list /upload /advertise /renew; do
      cargo run -p parity --bin parity -- diff --route "$route"
    done
```

The harness exit code is already non-zero on any mismatch; CI fails the job.

### Success criteria (Item 3)

- [ ] All 6 routes have ≥1 scenario committed under `tests/parity/fixtures/`
- [ ] `cargo run -p parity --bin parity -- diff --route <any-route>` exits 0 on green, non-zero on drift
- [ ] Dynamic-field sentinel `$VOLATILE:<type>$` syntax documented in `tests/parity/CLAUDE.md`
- [ ] CI workflow iterates all 6 routes; failing any one fails the deploy gate
- [ ] Running the harness against our live worker + nanostore produces all-green

### Agent brief (Wave 2b)

- **Scope**: `~/bsv/bsv-storage-cloudflare/tests/parity/` + `.github/workflows/ci.yml` only
- **Reference fixtures**: capture from both nanostore and our worker; commit the contract-only shape
- **Don't touch** `src/` of `bsv-storage-cloudflare`
- **Follow existing code style** in `tests/parity/src/` — previous parity work is the quality bar
- **3–4h task**

---

## Execution plan

### Wave 1 (now) — Item 1

Spawn one agent with the Item-1 brief. Run in background. Expected 4–6h.

Gate before Wave 2: rust-overlay `tm_uhrp` is live, our `OVERLAY_SUBMIT_URL` is back on rust-overlay, `/advertise` end-to-end green against rust-overlay.

### Wave 2 (after Wave 1) — Items 2 + 3 in parallel

Spawn two agents with disjoint scopes:
- Wave-2a: Item 2 (R2 wiring). `~/bsv/bsv-storage-cloudflare/wrangler.toml` + CF dashboard commands, possibly `src/queue/mod.rs` idempotency guard. ~30 min.
- Wave-2b: Item 3 (parity harness). `~/bsv/bsv-storage-cloudflare/tests/parity/` + `.github/workflows/ci.yml`. ~3–4h.

Both merge independently into `main`. No file overlap.

### Acceptance ceremony

After all three land:
1. Fire `/advertise` against our worker; verify it goes through rust-overlay
2. Upload a file via `/x402 pay /upload`; verify queue consumer auto-advertises within 60s; verify `/find` returns metadata without manual intervention
3. Run `cargo run -p parity --bin parity -- diff --route /quote /find /list /upload /advertise /renew` and see 6 greens
4. Push a trivial change to `main`; verify GitHub Actions runs all 6 parity scenarios and deploys only if green

When all three boxes check, this repo is ready for the boss with nothing in the "still has an issue" column.

---

## Open decisions for you

Before we kick off Wave 1, four steers:

1. **For the topic-manager port**: should UHRP adverts with `expiryTime < now()` be **admitted** (we index them, clients filter on `/lookup`) or **rejected** at the topic manager (strict, matches SHIP's approach of rejecting expired SHIP advert UTXOs)? Reference: `~/bsv/rust-overlay/crates/overlay-discovery/src/ship/topic_manager.rs` doesn't reject by expiry — SHIP adverts don't carry expiry. UHRP does. Pick: **strict reject** or **admit + filter at lookup**.

2. **Queue idempotency**: ship Item 2 without dedupe guard and accept 2× advert cost per double-delivered event, or add the `listOutputs` dedupe guard up front? I lean: **skip up front, add only if double-delivery observed in production**.

3. **Parity harness against nanostore for /advertise + /renew**: we skip nanostore for these (no admin access). Confirm: **ours-only, side-effect-based**.

4. **Wave 1 agent**: run in background (you get notified on completion) or foreground (I block on it)? I lean: **background, I chain Wave 2 on completion**.

Answer inline and I'll spawn the Wave-1 agent.
