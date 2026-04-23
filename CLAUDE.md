# bsv-storage-cloudflare — developer notes

Rust/WASM UHRP file-storage server on Cloudflare Workers. Protocol-compatible
port of [`@bsv/uhrp-storage-server`][ts-server] (reference deployment:
[`nanostore.babbage.systems`][nanostore]).

[ts-server]: https://github.com/bsv-blockchain/storage-server
[nanostore]: https://nanostore.babbage.systems

This file is for contributors. Start with [`README.md`](./README.md) for the
pitch, architecture diagram, and deploy steps.

## Docs in reading order

- [`README.md`](./README.md) — what this is, why it matters, how to run it.
- [`PROTOCOL.md`](./PROTOCOL.md) — wire-level protocol spec. Every typed struct
  in `src/types.rs` corresponds to a section here.
- [`DEPLOYMENT.md`](./DEPLOYMENT.md) — step-by-step Cloudflare setup.

## Build & run

```bash
npm install              # installs wrangler
npm run dev              # local dev server (R2 emulated)
worker-build --release   # build WASM binary
npm run deploy           # deploy to Cloudflare
```

Build target: `wasm32-unknown-unknown`. Output: `build/worker/shim.mjs`.

## Architecture

```
Request → lib.rs (fetch) → BRC-31 auth → route dispatch → R2 + wallet-infra
/upload written → R2 event → POST_UPLOAD_QUEUE → consumer → tm_uhrp SHIP advert
```

- **`lib.rs`** — `#[event(fetch)]` entry. CORS preflight, public `/quote`,
  then BRC-31 auth and route dispatch for `/upload`, `/find`, `/list`,
  `/renew`, `/advertise`. Also hosts `#[event(queue)]` for the post-upload
  consumer.
- **`routes/`** — one file per route, handler signature matches auth mode.
- **`uhrp/hash.rs`** — UHRP URL derivation from bytes (PROTOCOL.md §A).
- **`uhrp/pushdrop.rs`** — PushDrop field construction for UHRP adverts (§B).
- **`wallet/`** — JSON-RPC client to wallet-infra + local signer using
  `ADMIN_WALLET_PRIVATE_KEY` (via `bsv-rs`). Worker never exposes the key.
- **`overlay/mod.rs`** — SHIP `/submit` client with the Steak-body admission
  check (an overlay that HTTP-200s with an empty `outputsToAdmit` for your
  topic has silently dropped you, and the client must learn about it).
- **`validation.rs`** — request-body validation; never trust raw bytes in
  handlers.
- **`types.rs`** — every request/response shape is a named struct (no
  untyped `serde_json::Value` handlers — protocol drift becomes a compile
  error).

## Cloudflare bindings

See [`README.md`](./README.md#cloudflare-bindings) for the full table.

## HTTP API

See [`README.md`](./README.md#http-api) for the route table. Full wire spec:
[`PROTOCOL.md`](./PROTOCOL.md).

## Signing pipeline (PushDrop + SHIP)

1. Worker builds PushDrop locking script locally via
   `bsv_rs::script::templates::PushDrop` (WASM-safe).
2. Worker calls wallet-infra `createAction` JSON-RPC → unsigned BEEF + UTXO
   selection.
3. Worker signs locally with `ADMIN_WALLET_PRIVATE_KEY` (bsv-rs ECDSA).
4. Worker POSTs signed BEEF to `OVERLAY_SUBMIT_URL` with
   `x-topics: ["tm_uhrp"]` via `worker::Fetch`.
5. The overlay returns a Steak (`HashMap<String, AdmittanceInstructions>`);
   we reject any response that admits no outputs to `tm_uhrp` — that's silent
   data loss, not success.
6. Best-effort fan-out to canonical mainnet SLAP trackers so `@bsv/sdk`
   `LookupResolver` can discover this host.

## Quality gates (enforced before every commit)

```bash
./scripts/check.sh   # runs all of the below
```

Individual gates:

```bash
cargo fmt --all -- --check                                            # 1. Format
cargo clippy --target wasm32-unknown-unknown --all-targets -- -D warnings  # 2. Zero warnings
cargo check --target wasm32-unknown-unknown                           # 3. Compiles to WASM
cargo test --lib                                                      # 4. Unit tests
worker-build --release                                                # 5. WASM binary builds
```

Install the pre-commit hook once:

```bash
./scripts/install-hooks.sh
```

## Non-negotiables

- `#![forbid(unsafe_code)]` at crate root.
- No route handler accepts `serde_json::Value` — every shape is typed
  (enforces parity with [`PROTOCOL.md`](./PROTOCOL.md)).
- No `.unwrap()` / `.expect()` in `src/routes/` or `src/uhrp/`
  (clippy-warned; warnings are errors).
- No `TODO` / `FIXME` merged to `main`.
- No mocks in parity tests — they hit the real reference host
  (`nanostore.babbage.systems`).
- Round-trip test (upload → fetch public URL → SHA-256 match original) is a
  pre-cutover gate for any change touching `/upload` or storage.

## Testing

| Layer | What | How |
|---|---|---|
| **Unit** | types, validation, UHRP hash, PushDrop encoding | `cargo test --lib` |
| **Golden** | PushDrop hex byte-equal vs captured TS fixtures | `tests/parity/fixtures/parity/*.json` |
| **Integration** | Full HTTP stack, R2 + wallet-infra | `npm run dev` + curl |
| **Parity** | JSON response shape matches reference host | `cargo run -p parity --bin parity -- diff --route /quote` |
| **Round-trip** | upload → R2 fetch → SHA-256 | `tests/parity/` live suite with `--ignored` |

## Dependencies

All from crates.io:

- [`bsv-rs`](https://crates.io/crates/bsv-rs) — BSV primitives (PushDrop,
  transaction, signing, overlay wire types).
- [`bsv-middleware-cloudflare`](https://crates.io/crates/bsv-middleware-cloudflare) —
  BRC-31 / BRC-29 middleware for Cloudflare Workers.
- [`worker`](https://crates.io/crates/worker) — Cloudflare `workers-rs` runtime.

External services referenced by env vars:

- `WALLET_STORAGE_URL` → a rust-wallet-infra deployment of your own.
- `OVERLAY_SUBMIT_URL` → a rust-overlay deployment, or the canonical BSVA
  mainnet overlay as a fallback.
