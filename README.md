# bsv-storage-cloudflare

UHRP file-storage service **0.2.3** on Cloudflare Workers, written in Rust
and compiled to WASM. It implements the six client routes of
[`@bsv/uhrp-storage-server`](https://github.com/bsv-blockchain/storage-server)
with Cloudflare R2 for file bytes and a post-upload Queue consumer for
advertisements. See the [wire specification](./PROTOCOL.md).

## Client routes

| Method | Path | Access | Purpose |
|---|---|---|---|
| POST | `/quote` | Public | Return the satoshi cost for a file size and retention period. |
| POST | `/upload` | BRC-31 + BRC-29 payment | Return a presigned R2 PUT URL and required headers for the paid upload. |
| GET | `/find` | BRC-31 | Look up metadata for a UHRP URL. |
| GET | `/list` | BRC-31 | List the caller's uploaded files. |
| POST | `/advertise` | BRC-31 + admin allowlist | Publish a UHRP advertisement for an uploaded object. |
| POST | `/renew` | BRC-31 + BRC-29 payment | Redeem the old advertisement and publish one with an extended expiry. |

The authenticated routes use the BRC-31 handshake through
`bsv-middleware-cloudflare`. On the paid routes, `/upload` and `/renew`,
a priced request without payment receives a signed **402 Payment Required**
challenge; the middleware verifies the BRC-29 payment before the handler runs.
See [request dispatch](./src/lib.rs) and the [route handlers](./src/routes/).

The router also dispatches `/drafts` and `/drafts/:id` (GET, PUT, DELETE,
BRC-31) for the Composer's score-draft sync. These routes are not part of the
nanostore surface; they answer only on deployments that bind the
`COMPOSER_DRAFTS` KV namespace (`wrangler.composer.toml`), and the 404 of any
unknown path otherwise. See the [drafts module](./src/routes/drafts.rs).

After `/upload`, the client PUTs bytes directly to R2 using the returned URL
and required headers, including the signed content length. Downloads are
public GETs at the configured public file URL. R2 object-create events feed
`POST_UPLOAD_QUEUE`; the consumer hashes the uploaded object and reuses the
advertisement creation flow to sign a UHRP PushDrop advertisement and submit
it to `tm_uhrp` on the bound overlay. Wallet storage supplies transaction
construction and storage. See the [upload handler](./src/routes/upload.rs),
[queue consumer](./src/queue/mod.rs) and [overlay submitter](./src/overlay/mod.rs).
The queue currently buffers file bytes for hashing; multi-GB hashing can
exceed Worker memory, as recorded in the queue source.

## Health and release status

Public GET `/health` and `/` retain the success status and message and add a
`build` object since 0.2.1: `lib_rev`, `dirty`, `built_at` (UTC), and `crates`
with five locked crate versions. This describes the build, rather than
establishing wallet, overlay or storage readiness. See the
[health implementation](./src/health.rs) and [0.2.1 release notes](./CHANGELOG.md#021).

Public tags exist up to
[`v0.2.2`](https://github.com/Calhooon/bsv-storage-cloudflare/releases/tag/v0.2.2);
0.2.3 is this manifest's version, released by its `v0.2.3` tag. A live upload, public GET, hash check, advertisement and renewal round
trip on the current line is pending. The historical checks below do not
establish current deployment readiness.

## Discovery

Public GET `/.well-known/x402-info` returns the fleet's JSON discovery shape
without authentication, payment or a response signature. It uses the same
CORS headers as `/health`, `Content-Type: application/json`, and
`Cache-Control: public, max-age=300`.

The manifest describes BRC-103/104 authentication at `/.well-known/auth`,
the server's compressed public identity key, capabilities, and the seven
health and client routes with their access, payment and delivery fields.
`/upload` and `/renew` advertise dynamic BRC-29 payment through the
`x-bsv-payment` header and the signed 402 challenge flow. `/advertise`
also requires the configured admin allowlist. Discovery itself is unsigned.

`SERVICE_NAME` supplies the name, defaulting to `bsv-storage-cloudflare`.
`SERVER_PRIVATE_KEY` supplies only the derived public identity in the JSON.
`PRICE_PER_GB_MO` and `MIN_HOSTING_MINUTES` supply the pricing configuration.
The manifest shares the quote's 1,000-satoshi floor and rate fetch, including
the 15 USD/BSV fallback, and computes one-year examples at that request's
rate. `margin: "0%"` means no extra multiplier beyond `PRICE_PER_GB_MO`.
Use `/quote` for a current amount; discovery may be cached for five minutes.

Limits identify their enforcement route: `/upload` caps file size at
11,000,000,000 bytes; `/quote` caps retention at 69,000,000 minutes.
The quote does not enforce that upload size cap, and upload does not enforce
the quote's retention maximum or integer-retention rule.

`publicUrlFormat.pattern` is `PUBLIC_URL_BASE` with trailing slashes removed,
plus `/cdn/{base58id}`. The x402 upload helper replaces `{base58id}` with
the last segment of the object key in the presigned `uploadURL`. The ID
encodes 16 random bytes, not the content hash. Set `PUBLIC_URL_BASE` to
the public file-serving base; changing it requires no source edit.

See [protocol discovery](./PROTOCOL.md#d1-service-discovery) and the
[fallback-rate golden](./tests/fixtures/manifest/fallback.json), which uses
synthetic configuration and a public test key. Native tests supply the rate
directly and perform no HTTP requests. The health test is also a native
body test; this repository has no HTTP harness for `/health`.

The offline mirror check scans added `src/` lines against the pinned 0.2.1
base, including unstaged and untracked additions, for hostnames and account
identifiers. Run `python3 tests/scan_source_hosts.py` from a clone containing
that base. Existing source literals are outside this check. Scanner regressions
run with `python3 -m unittest discover -s tests -p test_scan_source_hosts.py`.

## Releases

The tag (`vX.Y.Z`) is the release of record; the repository's Releases page
carries a Release per tag. From 0.2.3 on, a tag push runs
[the release workflow](./.github/workflows/release.yml), which publishes the
crate `bsv-storage-cloudflare` to crates.io at the same version through
trusted publishing. The Worker in production is deployed from the tag by the
stack's infra, not by this repository's workflows. Earlier crates.io entries
under this name: 0.1.0 (2026-04-23) and 0.2.0 (2026-07-02); the tags 0.2.1
and 0.2.2 were not published there.

## Recorded parity (2026-04-21)

The [per-route matrix](./PARITY-STATUS.md#per-route-matrix) records all six
client routes as live-fire exercised, with distinct evidence scopes:

- `/find` (three error paths), `/list` and `/upload` were byte-identical
  against nanostore in the recorded comparisons, including the cross-backend
  upload response comparison.
- `/quote` was shape-identical, with pricing divergent by design.
- `/advertise` and `/renew` were checked against this service only, using
  pinned reference-contract fixtures. These checked admin authentication,
  validation and error shapes, rather than successful advertisement or renewal.

The [advertise and renew record](./PARITY-STATUS.md#2-advertise--renew-live-fire--proven-ours-only)
explicitly leaves their happy paths pending. The
[primitive layer](./PARITY-STATUS.md#primitive-layer-what-every-route-above-depends-on)
records SDK 1.10.1 vector evidence for BRC-42, BRC-29, BRC-31, PushDrop,
UHRP URL derivation, sighash and AtomicBEEF. The
[SHIP admission record](./PARITY-STATUS.md#1-shipslap-advertisement-admission--proven)
records admission against a local canonical overlay-express testbed.
These are dated, scoped records, not a blanket compatibility guarantee.
[PARITY-CLAIMS.md](./PARITY-CLAIMS.md) supplies detailed evidence pointers;
its older gap list is superseded for the two error-path checks by the dated
PARITY-STATUS record.

## Pricing

Protocol-compatible ≠ price-identical. This deployment sets its own rates:

| | This deployment | nanostore |
|---|---|---|
| `PRICE_PER_GB_MO` | $0.05 | $0.03 |
| Minimum sat price per upload | 1000 | 10 |
| Fallback exchange rate | 15 USD/BSV | 30 USD/BSV |

The higher `PRICE_PER_GB_MO` pockets R2's zero-egress advantage as margin. The
1000-sat minimum covers the ~500-sat overlay broadcast miner fee that every
upload incurs. See [`PROTOCOL.md §D`](./PROTOCOL.md#d-pricing-formula) for the
formula.

## Build and dependencies

The [manifest](./Cargo.toml) pins registry dependencies:

| Crate | Exact version |
|---|---|
| `bsv-rs` | `=0.4.5` |
| `bsv-middleware-cloudflare` | `=0.5.1` |
| `bsv-overlay-engine` | `=0.1.0` |
| `bsv-worker-build-info` | `=0.1.0` |

The lock resolves middleware core 0.2.1. No sibling checkout or path dependency
is required, as recorded in the [0.2.0 de-path notes](./CHANGELOG.md#020-unreleased-registry-de-path-e0c7971).

```bash
npm install
npm run dev                  # local Worker on :8787
```

The [local quality gate](./scripts/check.sh) and
[hosted gate](./.github/workflows/ci.yml) define formatting, clippy, tests,
WASM checks and the release Worker build. The hosted test job covers the
Worker and parity harness with the committed registry lock.
When the release keeper owns the Worker build, `scripts/check.sh --cargo-only`
runs the five cargo workflow legs. The default gate still includes the
Worker build.

For resource setup, R2 event notification wiring, deployment and rollback,
see [DEPLOYMENT.md](./DEPLOYMENT.md). Use your own service URL, for example
`https://your-worker.your-account.workers.dev`.
