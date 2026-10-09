# Deployment Runbook — bsv-storage-cloudflare

Operator guide for a first deploy, DNS cutover from `nanostore.babbage.systems`, and rollback. Every step states the **success criterion first**, then the command(s).

> **Convention**: all commands assume you've run `source secrets.md`'s shell block (or otherwise exported `CLOUDFLARE_API_TOKEN`). Never commit `secrets.md` — it's gitignored.

---

## Prerequisites

- **Cloudflare account** with R2 enabled (paid tier — R2 storage is not on the Workers free plan).
- **CF API token** with these scopes: `Workers Scripts:Edit`, `Workers KV Storage:Edit`, `Workers R2 Storage:Edit`, `Queues:Edit`. Store in `secrets.md` (gitignored). The token value lives there; this doc only references `CLOUDFLARE_API_TOKEN` by name.
- **Tools**:
  - Rust stable + the `wasm32-unknown-unknown` target: `rustup target add wasm32-unknown-unknown`
  - `worker-build` 0.1.x: `cargo install worker-build`
  - Node + `wrangler` 3.x: `npm install` (this repo's `devDependencies` pins it)
  - `jq` (for `deploy-setup.sh` output parsing)

Success: `wrangler --version` prints `⛅️ wrangler 3.x.x`, `worker-build --version` prints `worker-build 0.1.x`, and `cargo check --target wasm32-unknown-unknown` succeeds at the repo root.

---

## Step 1 — Create CF resources

**Success**: `wrangler r2 bucket list` shows `uhrp-prod`; `wrangler kv namespace list | jq '.[] | select(.title=="bsv-storage-cloudflare-AUTH_SESSIONS")'` returns a non-empty object; `wrangler queues list` shows `uhrp-post-upload`.

```bash
source secrets.md                      # or export CLOUDFLARE_API_TOKEN manually
./scripts/deploy-setup.sh
```

The script is idempotent — it prints `already exists` and skips any resource that's already present. On success it prints the KV namespace ID and queue ID. **You must paste these into `wrangler.toml`** (the script prints the exact line numbers):

- `[[kv_namespaces]]` → `id = "<KV ID>"` (currently line 37)
- The queue ID does not go into `wrangler.toml` (wrangler resolves by queue name), but save it for Step 5.

Manual fallback (if you prefer step-by-step):

```bash
wrangler r2 bucket create uhrp-prod
# Expected: "Creating bucket 'uhrp-prod' ... Created bucket 'uhrp-prod'."

wrangler kv namespace create AUTH_SESSIONS
# Expected: '{ binding = "AUTH_SESSIONS", id = "<KV ID>" }'
# Copy <KV ID> into wrangler.toml.

wrangler queues create uhrp-post-upload
# Expected: "Creating queue uhrp-post-upload. Created queue uhrp-post-upload."
```

---

## Step 2 — Generate R2 API keys (dashboard only)

R2's S3-compatible API keys are not creatable via `wrangler` CLI. Generate in the dashboard:

1. Cloudflare dashboard → **R2** → **Manage R2 API Tokens** → **Create API Token**.
2. **Permissions**: Object Read & Write.
3. **Specify bucket**: `uhrp-prod` (not account-wide — scope down).
4. **TTL**: none (rotate manually).
5. Click **Create API Token**.

**Success**: you see a page with `Access Key ID` and `Secret Access Key`. **Copy both immediately — the secret is shown once.** Paste into your password manager; they'll be consumed as Worker secrets in Step 3.

---

## Step 3 — Set Worker secrets

**Success**: `wrangler secret list` shows all five names below. Values never leave your shell — they're encrypted by CF.

```bash
echo "<hex-32-bytes>"                | npx wrangler secret put SERVER_PRIVATE_KEY
echo "<hex-32-bytes>"                | npx wrangler secret put ADMIN_WALLET_PRIVATE_KEY
echo "<comma-separated-hex-pubkeys>" | npx wrangler secret put ADMIN_IDENTITY_KEYS
echo "<r2-access-key-id>"            | npx wrangler secret put R2_ACCESS_KEY_ID
echo "<r2-secret-access-key>"        | npx wrangler secret put R2_SECRET_ACCESS_KEY
```

Reference values (key derivations, BRC-31 identity pubkey):
- `SERVER_PRIVATE_KEY` — BRC-31 server identity. 64-char hex, one-shot generation: `openssl rand -hex 32`.
- `ADMIN_WALLET_PRIVATE_KEY` — wallet-infra admin wallet, signs UHRP PushDrop adverts. Must match an identity wallet-infra has funded.
- `ADMIN_IDENTITY_KEYS` — lowercase hex pubkeys (33-byte compressed, 66 chars) of admins allowed to call `/advertise`. Comma-separated, no whitespace required.
- `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY` — from Step 2.

---

## Step 4 — Populate `wrangler.toml` placeholders

**Success**: `grep -n '""' wrangler.toml` in the `[vars]` block returns no quoted-empty lines; `PUBLIC_URL_BASE` and `R2_S3_ENDPOINT_HOST` both have real URLs.

Edit `wrangler.toml`:

| Line (approx) | Var | Value |
|---|---|---|
| 20 | `PUBLIC_URL_BASE` | Your R2 custom-domain origin — e.g. `"https://storage.example.com"`. Until you cut DNS in Step 9, you can leave this as the R2-default `https://pub-<hash>.r2.dev/uhrp-prod` which R2 gives you when you enable the public bucket — **but only for non-prod testing**. Production must be a custom domain you control. |
| 23 | `R2_S3_ENDPOINT_HOST` | `"<account_id>.r2.cloudflarestorage.com"` — e.g. `"ea3e6d176ed3893258fe34281f710c7f.r2.cloudflarestorage.com"`. The account ID is also in `secrets.md`. |
| 37 | `kv_namespaces[].id` | From Step 1's output. |

---

## Step 5 — Wire R2 event notifications to the queue

R2 → Queue event notifications are a newer CF feature. As of April 2026, **the CLI command `wrangler r2 bucket notification create` works**; the dashboard equivalent is under R2 → bucket → **Settings** → **Event notifications** → **Add notification**. If the CLI flags have changed by the time you read this, fall back to the dashboard.

**Success**: `wrangler r2 bucket notification list uhrp-prod` shows one rule with `event-types: [object-create]` and `queue: uhrp-post-upload`.

```bash
wrangler r2 bucket notification create uhrp-prod \
  --event-types object-create \
  --queue uhrp-post-upload
# Expected: "Added notification rule to bucket 'uhrp-prod'."
```

Why `object-create` specifically: our queue consumer (`src/queue/mod.rs`) only advertises newly-created objects (`PutObject`, `CopyObject`, `CompleteMultipartUpload`). Delete events are skipped at the consumer, but wiring them to the queue just burns CPU. Keep the subscription narrow.

---

## Step 6 — First deploy

**Success**: `npm run deploy` prints `Uploaded bsv-storage-cloudflare` and a URL of the form `https://bsv-storage-cloudflare.<account>.workers.dev`. Save that URL.

```bash
./scripts/deploy.sh
# or equivalently:
export CLOUDFLARE_API_TOKEN="<from secrets.md>"
worker-build --release
npm run deploy
```

---

## Step 7 — Smoke test

**Success**: `curl` returns HTTP 200 and the expected JSON body.

```bash
WORKER_URL="https://bsv-storage-cloudflare.<account>.workers.dev"

# Health check — unauthenticated.
curl -sS "$WORKER_URL/"
# Expected: {"status":"success","message":"bsv-storage-cloudflare running"}

# Quote — unauthenticated, pricing round-trip.
curl -sS -X POST "$WORKER_URL/quote" \
  -H 'content-type: application/json' \
  -d '{"fileSize":1048576,"retentionPeriod":43200}'
# Expected: {"quote":<positive-integer>}
```

A 500 on `/quote` is almost always a `SERVER_PRIVATE_KEY` problem — it runs after auth in `lib.rs` only if the URL path is wrong, but the secret is loaded after the public-route dispatch. Check `wrangler tail` for the error.

---

## Step 8 — Parity against nanostore

**Success**: `parity diff` exits 0 on `/quote` (the only currently-ported route with a parity harness — see `tests/parity/src/main.rs`).

```bash
# Identity is auto-generated on first run at tests/parity/.identity.json
# (gitignored). For CI, override via PARITY_IDENTITY_KEY (see secrets.md).
cargo run -p parity --bin parity -- diff \
  --route /quote \
  --local "https://bsv-storage-cloudflare.<account>.workers.dev"
# Expected: "parity diff: /quote ✅ match" (exact text per the harness).
```

If the diff fails, the output includes the differing JSON fields. The most common drift points are `quote` rounding (exchange-rate fetch timing) and header casing.

---

## Step 9 — DNS cutover to the user-facing domain

> **User decision — do not execute until ready.** This is the step that flips production traffic off `nanostore.babbage.systems`.

**Success**: `dig +short storage.example.com` resolves to a Cloudflare edge IP; `curl https://storage.example.com/` returns the same health body as Step 7; the parity harness is green against the new domain.

1. **Create R2 custom domain** (dashboard only): R2 → `uhrp-prod` → **Settings** → **Custom Domains** → **Connect domain**. Enter `storage.example.com`. CF adds the CNAME automatically if the zone is on CF.
2. **Update `wrangler.toml`**:
   ```toml
   routes = [
     { pattern = "storage.example.com", custom_domain = true }
   ]
   ```
   and set `PUBLIC_URL_BASE = "https://storage.example.com"`.
3. **Redeploy**: `./scripts/deploy.sh`.
4. **TTL guidance**: drop the existing `nanostore.babbage.systems` CNAME TTL to 300s at least 24h before cutover so rollback (Step 11) propagates in five minutes, not an hour.
5. **Watch `wrangler tail`** for the first 10 minutes post-cutover. A flood of 5xx means roll back.

---

## Step 10 — GCS → R2 data migration plan

Since UHRP URLs are content-addressed (`cdn/<id>` is stable across backends), a bulk copy preserves every URL. We do this with `rclone` in one shot.

**Success**: `rclone size gcs-prod:<bucket>/cdn` equals `rclone size r2-prod:uhrp-prod/cdn` after migration.

`scripts/migrate-gcs-to-r2.sh` is a copy-paste-ready template. **It's guarded by an `exit 1` at the top** — remove that only after reviewing the source/destination paths. Key flags:

- `--transfers 16` — parallelism. R2 handles this fine; GCS egress is the limiter.
- `--checksum` — MD5-checksum both sides. Required: a corrupted copy would silently serve wrong bytes for that UHRP URL.
- `--no-update-modtime` — preserves GCS's upload time as R2's. Custom time is what matters for expiry, not modtime, but leaving modtime undefined on R2 is ugly.
- `--metadata` — copies `x-goog-meta-*` → `x-amz-meta-*` (rclone handles the translation).

GCS → R2 bandwidth charges: GCS egress is ~$0.12/GB to the internet. R2 ingress is free. Budget accordingly — a 1 TB backlog is ~$120.

---

## Step 11 — Rollback plan

**Success**: `dig +short storage.example.com` resolves to Google/GCS again; `curl https://storage.example.com/quote` returns the familiar nanostore response.

If the cutover goes bad:

1. **DNS**: flip `storage.example.com` CNAME back to the GCP load balancer (or whatever it pointed at before). TTL of 300s means 5 min propagation.
2. **Stop R2 writes**: disable the R2 event notification (Step 5) — `wrangler r2 bucket notification delete uhrp-prod <rule-id>`. New uploads during the rollback window would otherwise land in R2 but not be advertised.
3. **Drain the queue**: the queue consumer will still advertise anything already enqueued. Either let it drain (safe — adverts are idempotent at the PushDrop level), or `wrangler queues purge uhrp-post-upload` if you're sure you want to lose pending messages.
4. **Clients are unaffected**: UHRP URLs are content-addressed, so URLs minted while R2 was primary still resolve to the same bytes in GCS (both backends hold the same object at `cdn/<id>`).

---

## Appendix A — Environment variable reference

| Var | Type | Source | Purpose |
|---|---|---|---|
| `CLOUDFLARE_API_TOKEN` | Shell env | `secrets.md` | wrangler auth — never OAuth in CI. |
| `CLOUDFLARE_ACCOUNT_ID` | Shell env | `secrets.md` | account-scoping for `wrangler`. |
| `PARITY_IDENTITY_KEY` | Shell env | generated | overrides `tests/parity/.identity.json` for CI. |

Worker-side vars and secrets are listed in Step 3 and `wrangler.toml`'s `[vars]` block.

---

## Appendix B — Worker resource limits

| Limit | Value | Relevance |
|---|---|---|
| Worker CPU per request | 30s | Queue batch of 10 × ~3s/msg = 30s — no slack. Do not raise `max_batch_size` above 10 without empirical measurement. |
| Worker memory | 128 MB | The queue consumer loads full object bytes into memory to SHA-256 them. 11 GB uploads (our `MAX_UPLOAD_BYTES`) will OOM the queue consumer — they must be advertised via explicit `/advertise` call with client-computed hash. See `src/queue/mod.rs` `hash_r2_object` rationale. |
| Queue message size | 128 KB | R2 event payloads are <1 KB; no issue. |

---

## Appendix C — When things go wrong

| Symptom | Cause | Fix |
|---|---|---|
| `/quote` 500 with `ERR_INTERNAL` | WhatsOnChain fetch timed out | Automatic fallback to 30 USD/BSV applies after retry; just refresh. |
| `/upload` returns URL, but client PUT 403s | R2 API token wrong or scoped to a different bucket | Redo Step 2 + Step 3; ensure bucket name in token matches `R2_BUCKET` var. |
| New uploads never get adverted | Step 5 skipped (no event notification) or queue consumer errored | `wrangler r2 bucket notification list uhrp-prod` to verify; `wrangler tail --format pretty` to watch the queue handler. |
| Queue consumer OOMs | File >128 MB hit `hash_r2_object` | Mitigate: client calls `/advertise` directly with the precomputed hash; disable R2 event for that key prefix if it recurs. |
| `/advertise` returns 401 | Caller's BRC-31 identity not in `ADMIN_IDENTITY_KEYS` | `wrangler secret put ADMIN_IDENTITY_KEYS` with the correct comma-separated list. |
