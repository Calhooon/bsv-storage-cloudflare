# Changelog

## 0.3.1 (2026-11-17)

- The paid routes run the storage's own payment door (`src/paid.rs`): the
  payment middleware's decision, step for step and answer for answer, over
  the middleware's public parts (the prefix's HMAC, the output check, the
  subject's txid, the transaction-bound prefix claim).
- A payment header longer than 96 KiB is answered before it is read:
  `400 ERR_INVALID_PAYMENT`, "Payment not verified: payment transaction
  unreadable: the payment transaction is too large to read". The derivation
  prefix is not claimed, so the payer retries under it. Every real wallet
  payment the estate's rows rebuild as a header the platform carries is at
  most 35,546 bytes.
- The `internalizeAction` call is written once: the JSON-RPC body is
  serialized from the payment's bytes straight into the BRC-104 payload it
  is signed over, and the body sent is that payload's tail. The request is
  the middleware's, byte for byte, with `tx` the array of byte values every
  wallet storage server reads. `tests/heap` measures each paid request from
  the header to the call's send, on every shape up to the ceiling: its peak
  stays within 1 MiB plus 8 bytes per header byte.
- The fan-out posts an advert only to hosts named by tracker outputs that
  are SHIP advertisements for the topic, signed by the identity key they
  name under BRC-88's derivation and locked by that identity's linked key
  (as `@bsv/sdk`'s `SHIPBroadcaster` reads them), for a public `https`
  origin: a DNS name (no IP literal, no `localhost`, `.localhost`, `.local`,
  `.internal` or `.home.arpa` name, no `xn--` label), the default port, and
  no credentials, path, query or fragment. Each host once, the primary left
  out, at most 32. A tracker's outputs that name no host are skipped and
  counted in one log line per tracker; the upload's answer is unchanged.
- No binding, wrangler or route change, and no stored-data migration.

## 0.3.0 (2026-11-17)

- bsv-rs `0.8.11` (a caret requirement) and bsv-middleware-cloudflare
  `=0.7.4` (core 0.4.3); the lock holds one bsv-rs. The parity harness moves
  with them. `bsv-overlay-engine` is no longer a dependency: `TaggedBEEF` and
  `Steak` come from `bsv_rs::overlay::types`, the types the engine
  re-exports. `/health`'s `build.crates` names four crates.
- The paid routes' payment check reads the payment's subject transaction
  alone (output 0's script and amount; nothing linked, no script run), so
  `/upload` and `/renew` hand the header to the middleware with no check of
  their own in front of it. `tests/heap` measures that door on every shape
  up to a 128 KiB header: its peak stays within 1 MiB plus 8 bytes per
  header byte.
- A derivation prefix is claimed in the `AUTH_SESSIONS` KV under the same
  key (`auth:nonce:payment-derivation-prefix:<prefix>`, no expiry), now
  holding the subject txid it pays for: a prefix consumed earlier stays
  refused, and another transaction under a claimed prefix is refused with
  `400 ERR_INVALID_DERIVATION_PREFIX`. A KV fault while claiming answers
  `503 ERR_PAYMENT_UNAVAILABLE` with `Retry-After`, the quote kept.
- The middleware's own challenge (after a wallet rejection) carries the
  same payment headers as the routes' 402; responses expose `Retry-After`
  to browsers.
- A payment's BEEF and a tracker answer's BEEF are read by bsv-rs 0.8:
  bytes after the last transaction and non-canonical varints are refused (an
  unreadable payment, `400 ERR_INVALID_PAYMENT`; a tracker output skipped).
  The advert's AtomicBEEF holds its transaction and that transaction's
  ancestry.
- `tests/compat` runs v0.2.4's modules (a verbatim copy) against the current
  ones on the same inputs: sessions and general messages, derivation
  prefixes, the payment header and its verdict, the advert's fields, script
  and transaction, the fan-out's hosts, the R2 event and the presigned PUT.
  CI runs it with fmt and clippy.
- No binding, wrangler or route change, and no stored-data migration.

## 0.2.4 (2026-11-17)

- The payment header's transaction is checked before the payment middleware
  reads it on `/upload` and `/renew`; one too large to read is answered as an
  unreadable payment (`400 ERR_INVALID_PAYMENT`, the derivation prefix kept).
- The mainnet fan-out reads a tracker answer's subject alone and bounds the
  answer's size.
- The memory pins live in `tests/heap`; CI runs them.
- No dependency moves: bsv-rs `=0.4.5`, bsv-middleware-cloudflare `=0.5.1`
  (core 0.2.1), the same lock.

## 0.2.3 (2026-10-18)

- Publish the crate `bsv-storage-cloudflare` to crates.io from a `v*` tag
  through `.github/workflows/release.yml`: crates.io trusted publishing, no
  token in the repository, the tag checked against the manifest and lock
  version and against `main`, the `ci.yml` jobs called before a native
  `cargo publish --dry-run`. `ci.yml` gains `workflow_call` for that call.
- `Cargo.toml` names the README, keywords, category and an `include` list
  (sources, build script, lock, wrangler template, README, licence and
  changelog); the repository URL is corrected to `Calhooon`.
- Refresh the README to this release, with a Releases section.
- No dependency, route, binding or wrangler change.

## 0.2.2 (2026-10-13)

- Add public, unsigned GET `/.well-known/x402-info` with fleet discovery
  fields, seven endpoint descriptions, BRC-103/104 identity and BRC-29
  header payment capabilities, CORS and a five-minute cache policy.
- Derive the public download pattern from `PUBLIC_URL_BASE`; the upload
  helper substitutes the object key's final base58 segment. `SERVICE_NAME`
  optionally overrides the default service name.
- Share the quote's rate fetch, fallback, minimum, USD and satoshi arithmetic
  with discovery. Publish the existing upload and quote limits with their
  enforcement scope and deterministic one-year examples.
- Add an offline golden, configuration and pricing tests, dispatch checks,
  and a source-addition hostname and account scanner against the pinned base.
  Existing source literals are outside this change's mirror gate.
- Align the local gate with all five cargo workflow legs. Keep the Worker
  build in the default gate; `--cargo-only` leaves it to the release keeper.
- No dependency or version move, caller migration, or stored-data change.
  The keeper sets the release version and verifies the Worker runtime.

## 0.2.1

- Add build provenance to GET `/health` and `/`: the checkout's full revision,
  dirty flag, UTC build time and five crate versions from Cargo.lock, through
  `bsv-worker-build-info = "=0.1.0"`. Retain status, message and CORS.
- No caller, stored-data or resource migration. Health describes a build;
  it does not establish wallet, overlay or storage readiness.

## 0.2.0: unreleased registry de-path (e0c7971)

The Worker builds without sibling checkouts: `bsv-middleware-cloudflare = "=0.5.1"`
(locked core 0.2.1), `bsv-overlay-engine = "=0.1.0"`, and `bsv-rs = "=0.4.5"`
in both workspace manifests. The lock contains one registry SDK and one registry
engine, with no path or patch dependencies. The crate version stays 0.2.0.

- The engine import becomes `bsv_overlay_engine::types`; the `Steak` and
  `TaggedBEEF` wire types remain the SDK's re-exports. Existing endpoint values,
  request construction and response handling stay unchanged.
- bsv-rs 0.4.5 accepts a lone hashed Merkle leaf only at offset 0 and adds an
  opt-in LOCAL script work bound. This Worker constructs no Merkle paths in
  memory and sets no work bound; no resource match needs another arm.
- The machine gate uses the committed registry lock and tests the parity crate
  alongside the Worker. No private sibling repository is cloned in CI.

## Unreleased: the 0.4 line

The Worker moves to the 0.4 line of the stack: `bsv-middleware-cloudflare = "=0.5.0"` (on
`bsv-middleware-core` 0.2.0) and `bsv-rs` 0.4.1 in both workspace manifests (`Cargo.toml`, and
`tests/parity/Cargo.toml`, whose `bsv-rs` was a path dependency on `../../../bsv-rs` and is the
registry's 0.4.1 now). The crate version stays 0.2.0.

- No source line changed. Every middleware and SDK item the Worker names keeps its name, path and
  signature: the middleware's 0.5.0 breaking moves are in `PaymentVerifyError` and the
  `verify_brc29_payment*` family, which this Worker does not call.
- What a caller of `/upload` and `/renew` sees move, all of it the middleware's own (its
  `CHANGELOG.md`, 0.5.0): a payment whose bytes are refused for the payer's reason is
  `400 ERR_INVALID_PAYMENT` with the quote kept; a `PaymentFault` (the server's own key) is
  `500 ERR_SERVER_MISCONFIGURED` (0.4.x answered 400).
- bsv-rs 0.4.1 reads a transaction with no input as invalid bytes; no fixture of this repository
  is one (the suite is green unchanged).
- That alignment retained the legacy engine path pin and its separate SDK copy.
  The registry dependency entry above supersedes that build requirement.
