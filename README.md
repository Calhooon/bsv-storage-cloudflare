# bsv-storage-cloudflare

**A UHRP file-storage server on Cloudflare Workers — byte-for-byte
protocol-compatible with [`@bsv/uhrp-storage-server`][ts-server]. Rust, compiled
to WebAssembly. Content-addressed, host-blind, and run-anywhere.**

[ts-server]: https://github.com/bsv-blockchain/storage-server

---

## What this is

A drop-in replacement for the reference TypeScript UHRP host
([`nanostore.babbage.systems`][nanostore]) that runs entirely on Cloudflare
primitives — Workers (WASM) + R2 + Queues + KV. Every HTTP response shape,
UHRP URL, PushDrop advertisement byte, and error code matches the TS original
at wire level. A client can point its storage URL at your deployment instead
of nanostore without changing a line of code.

[nanostore]: https://nanostore.babbage.systems

```
┌──────────┐   BRC-31 auth   ┌───────────────────────┐   SigV4 presign   ┌────────┐
│  Client  │────────────────▶│  Cloudflare Worker    │──────────────────▶│   R2   │
│ (bsv-sdk)│ /upload /find   │  (Rust → WASM)        │                   │ bucket │
└──────────┘ /list /renew    │                       │                   └────┬───┘
                             │  /quote  /advertise   │                        │
                             └────┬──────────────┬───┘                        │
                                  │              │  R2 PutObject event        │
                                  │              ▼                            │
                     tm_uhrp SHIP │       ┌──────────────┐                    │
                       PushDrop   │       │  CF Queue    │                    │
                                  ▼       └──────┬───────┘                    │
                     ┌────────────────────┐      │ consumer                   │
                     │  Overlay (SHIP)    │◀─────┘ re-indexes, advertises     │
                     │  /submit tm_uhrp   │                                   │
                     └────────────────────┘                                   │
                                                                              ▼
                                                                     Public HTTPS
                                                                     (custom domain)
```

---

## Why UHRP

UHRP (Universal Hash Resolution Protocol) flips the file-hosting model. A URL
is a hash, not an address. That tiny change unlocks properties a traditional
storage host cannot offer:

- **Content-addressed URLs.** Every file is `uhrp://<base58check(sha256)>`.
  The URL *is* the content hash. If host A disappears and host B has the bytes,
  the URL keeps working. You never update links. Files outlive their hosts.

- **Host-blind storage.** Clients can encrypt bytes *before* upload. The host
  just stores opaque bytes matching a hash. It literally can't read your data,
  can't selectively serve it, can't comply with a takedown it doesn't
  understand. Content-addressing only cares about the bytes, not their meaning.

- **Multi-peer economic coordination.** Hosts publish on-chain PushDrop
  advertisements ("I host hash X until time Y for Z sats"). Clients find hosts
  via `ls_uhrp` lookups and pay via BSV micropayments. Competitive pricing
  emerges without a middleman.

- **Integrity without trust.** The client hashes the downloaded bytes and
  compares against the URL. Match? The data is authentic. No match? Ask another
  peer. A malicious host cannot serve corrupted content that passes
  verification — the URL contains the proof.

- **Graceful degradation.** Take one host down → the file stays reachable
  via any peer that still holds the bytes. Jurisdiction shopping becomes
  trivial. Single-host takedowns become meaningless when multi-peer coverage
  is the default.

This server implementation contributes one more host to that peer network, on
the highest-availability edge infrastructure available.

## Why run this on Cloudflare

This is the first UHRP host built entirely on Cloudflare primitives. Every
piece runs at the edge:

- **Workers (WASM)** for the HTTP handlers, BRC-31 authentication, and
  PushDrop signing — compiled from Rust, no cold-start overhead.
- **R2** for object storage. Zero egress fees — downloads cost the operator
  nothing beyond storage.
- **Queues** for R2-event → SHIP-broadcast pipelines — async advertisement
  submission without blocking the upload path.
- **KV** for BRC-31 session caching.
- **Custom domains** for user-visible public file URLs.

No origin server. No VMs. No per-request backend bills. Deploy to a single
Cloudflare account and you have a geographically distributed UHRP host with
Cloudflare's TLS termination, DDoS protection, and global cache built in.

Content-addressed distributed storage running on the edge turns Cloudflare
into something it's never quite been before: a node in a peer-to-peer data
network. The bytes are still under user control (content hashes, on-chain
advertisements, overlay-mediated discovery) — Cloudflare is the substrate,
not the custodian.

## Why this helps the BSV overlay ecosystem

The BSV overlay network needs more independent UHRP hosts. Every additional
host improves redundancy, reduces centralisation risk on the canonical
`babbage.systems` deployment, and broadens the set of providers competing on
`/quote` prices.

Running one has historically meant provisioning a VM, GCS bucket, GCP Cloud
Function, Postgres, and a custody-grade key manager. This repo collapses that
to a `wrangler deploy` against a Cloudflare account. A single operator can
stand up a new host in ~15 minutes and start advertising into `tm_uhrp`.

## Portability guarantee

**Every route is byte-for-byte identical to the TS original at the JSON-shape
and PushDrop-encoding level.** A client that works against `nanostore.babbage.systems`
works against this server with a URL swap and nothing else. The parity
harness under `tests/parity/` runs live diffs against the reference host and
byte-equality checks against captured TS fixtures; keeping it green is a
precondition of every commit.

The only intentional divergence is `/quote`: this deployment chooses its own
prices (see below). The client doesn't care — it just pays whatever `/quote`
returns.

---

## HTTP API

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/` or `/health` | none | Liveness probe |
| `POST` | `/quote` | none | Sats cost for a given file size + retention |
| `POST` | `/upload` | BRC-31 + BRC-29 | Presigned R2 PUT URL + required headers |
| `GET`  | `/find` | BRC-31 | Metadata for a UHRP URL |
| `GET`  | `/list` | BRC-31 | Files owned by caller |
| `POST` | `/renew` | BRC-31 + BRC-29 | Extend file expiry (new PushDrop) |
| `POST` | `/advertise` | BRC-31 admin | Create on-chain UHRP advertisement |

Full wire spec: [`PROTOCOL.md`](./PROTOCOL.md).

## Architecture

```
src/
├── lib.rs                  # #[event(fetch)] entry, CORS, auth, routing
├── routes/
│   ├── quote.rs           # public pricing
│   ├── upload.rs          # R2 SigV4 presign
│   ├── find.rs            # metadata lookup
│   ├── list.rs            # caller's files
│   ├── renew.rs           # BRC-29-paid expiry extension, priced from the on-chain advert
│   └── advertise.rs       # admin-gated tm_uhrp SHIP broadcast
├── uhrp/
│   ├── hash.rs            # UHRP URL derivation (PROTOCOL.md §A)
│   └── pushdrop.rs        # PushDrop field construction (§B)
├── storage/
│   ├── presign.rs         # R2 S3-compatible SigV4 signer
│   ├── custom_time.rs     # /renew extends R2 custom-time via same-key copy
│   └── head.rs            # R2 HEAD → metadata
├── wallet/
│   ├── client.rs          # JSON-RPC to wallet-infra (createAction)
│   ├── signer.rs          # ECDSA signing via bsv-rs (WASM-safe)
│   └── brc42.rs           # BRC-42 key derivation
├── overlay/mod.rs          # SHIP /submit with Steak-body admission check
├── queue/mod.rs            # R2 event → post-upload processing (dup-advert guard)
├── validation.rs           # request validation; never trust raw bytes
├── types.rs                # every wire shape is a named struct
└── error.rs                # project-wide error codes
```

### Signing pipeline (PushDrop + SHIP)

1. Worker builds PushDrop locking script locally via `bsv_rs::script::templates::PushDrop`.
2. Worker calls `wallet-infra` `createAction` JSON-RPC → unsigned BEEF + UTXO selection.
3. Worker signs locally with `ADMIN_WALLET_PRIVATE_KEY` (ECDSA in WASM, never leaves the Worker).
4. Worker POSTs signed BEEF to `OVERLAY_SUBMIT_URL` with `x-topics: ["tm_uhrp"]`.
5. Overlay `/submit` returns a Steak; we reject any response that admits no outputs to `tm_uhrp`.
6. Best-effort fan-out to canonical mainnet SLAP trackers so `@bsv/sdk`
   `LookupResolver` can discover this host.

---

## Quickstart

```bash
npm install
./scripts/install-hooks.sh    # pre-commit quality gate (optional)
npm run dev                   # local worker on :8787, R2 emulated
```

## Deploy

See [`DEPLOYMENT.md`](./DEPLOYMENT.md) for the full setup — KV namespace,
R2 bucket, queue, secrets, and domain wiring. Short version:

```bash
# 1. Fill in wrangler.toml placeholders (account ID, KV namespace, public URL).
# 2. Set secrets:
npx wrangler secret put SERVER_PRIVATE_KEY
npx wrangler secret put ADMIN_WALLET_PRIVATE_KEY
npx wrangler secret put ADMIN_IDENTITY_KEYS
npx wrangler secret put R2_ACCESS_KEY_ID
npx wrangler secret put R2_SECRET_ACCESS_KEY
# 3. Deploy.
npm run deploy
```

## Cloudflare bindings

| Binding | Type | Purpose |
|---|---|---|
| `AUTH_SESSIONS` | KV | BRC-31 session cache (1h TTL) |
| `UHRP_FILES` | R2 | File storage |
| `POST_UPLOAD_QUEUE` | Queue | R2 event → advertise + index |
| `OVERLAY` | Service | Cross-worker RPC to rust-overlay |
| `BSV_NETWORK` | Var | `mainnet` or `testnet` |
| `WALLET_STORAGE_URL` | Var | rust-wallet-infra JSON-RPC endpoint |
| `OVERLAY_SUBMIT_URL` | Var | rust-overlay `/submit` for SHIP broadcast |
| `PUBLIC_URL_BASE` | Var | R2 custom-domain origin for file URLs |
| `R2_S3_ENDPOINT_HOST` | Var | `<account>.r2.cloudflarestorage.com` |
| `R2_BUCKET` | Var | Bucket name used in SigV4 paths |
| `PRICE_PER_GB_MO` | Var | USD/GB-mo pricing floor |
| `MIN_HOSTING_MINUTES` | Var | Minimum retention a client can request |
| `SERVER_PRIVATE_KEY` | Secret | BRC-31 server identity (hex) |
| `ADMIN_WALLET_PRIVATE_KEY` | Secret | Signs UHRP PushDrop advertisements |
| `ADMIN_IDENTITY_KEYS` | Secret | Pubkeys allowed to `/advertise` |
| `R2_ACCESS_KEY_ID` | Secret | R2 S3-API access key (for presigner) |
| `R2_SECRET_ACCESS_KEY` | Secret | R2 S3-API secret key (for presigner) |

## Pricing (your call, not nanostore's)

Protocol-compatible ≠ price-identical. Set your own rates in `wrangler.toml`:

| | This deployment (default) | nanostore.babbage.systems |
|---|---|---|
| `PRICE_PER_GB_MO` | `0.05` | `0.03` |
| Minimum sat price per upload | 1000 | 10 |
| Fallback exchange rate | 15 USD/BSV | 30 USD/BSV |

The higher `PRICE_PER_GB_MO` pockets R2's zero-egress advantage as margin.
The 1000-sat minimum covers the ~500-sat overlay broadcast miner fee every
upload incurs. Formula: [`PROTOCOL.md §D`](./PROTOCOL.md#d-pricing-formula).

## Quality gates

Every commit must pass:

```bash
./scripts/check.sh   # runs all of the below
```

Individual gates:

```bash
cargo fmt --all -- --check
cargo clippy --target wasm32-unknown-unknown --all-targets -- -D warnings
cargo check  --target wasm32-unknown-unknown
cargo test   --lib
cargo install -q worker-build@0.8.4 && worker-build --release
```

Non-negotiables:

- `#![forbid(unsafe_code)]` at crate root.
- No route handler accepts `serde_json::Value` — every shape is a typed
  struct, so protocol drift becomes a compile error.
- No `.unwrap()` / `.expect()` in `src/routes/` or `src/uhrp/`.
- No mocks in parity tests — they hit the real reference host.

## Testing

| Layer | What | How |
|---|---|---|
| **Unit** | types, validation, UHRP hash, PushDrop encoding | `cargo test --lib` |
| **Golden** | PushDrop hex byte-equal vs captured TS fixtures | `tests/parity/fixtures/parity/*.json` |
| **Integration** | Full HTTP stack, R2 + wallet-infra | `npm run dev` + curl |
| **Parity** | JSON response shape matches reference host | `cargo run -p parity --bin parity -- diff --route /quote` |

## Docs

- [`PROTOCOL.md`](./PROTOCOL.md) — wire-level protocol spec.
- [`DEPLOYMENT.md`](./DEPLOYMENT.md) — step-by-step Cloudflare setup.
- [`CLAUDE.md`](./CLAUDE.md) — architecture notes for developers.

## License

Dual-licensed under your choice of:

- **MIT** — [`LICENSE-MIT`](./LICENSE-MIT)
- **Apache 2.0** — [`LICENSE-APACHE`](./LICENSE-APACHE)

Same dual-license pattern used across the Rust ecosystem (`bsv-rs`,
`bsv-middleware-cloudflare`, etc.) for maximum compatibility.
