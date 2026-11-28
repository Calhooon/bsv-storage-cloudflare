# Changelog

## 0.3.4 (2026-11-28)

- bsv-rs `0.8.15` (a caret requirement, the floor): the release the
  published advisories GHSA-f2rq-878r-pgxv, GHSA-jx5m-j63r-7fgw,
  GHSA-pfv3-7r7f-mhgh, GHSA-jjhc-7hvh-c3hm, GHSA-mp9c-g2q9-q3qw and
  GHSA-jgrp-wvcx-vxf3 name as patched. Every lock moves to it (the root,
  `tests/heap`, `tests/compat`'s `new`, `tests/workerd/kit`,
  `tests/workerd/wallet`), and in each lock nothing moves but bsv-rs and,
  where the lock carries it, this package's own version;
  bsv-middleware-cloudflare stays `=0.7.8` (core 0.4.7). `/health`'s
  `build.crates` names 0.3.4 and 0.8.15.
- No source change (the version guard in `src/health.rs`'s test only), no
  binding, wrangler or route change, and no stored-data migration.
- The advertisement figure of 0.3.3 (`ADVERT_BEEF_MAX_BYTES`, 614,400 bytes)
  was read again at this pin and stays as it is; it is read again at each
  bsv-rs pin of this crate.

## 0.3.3 (2026-11-28)

- bsv-middleware-cloudflare `=0.7.8` (core 0.4.7), still an exact pin;
  bsv-rs stays `0.8.14`. Every lock moves to it (the root, `tests/heap`,
  `tests/compat`'s `new`, `tests/workerd/kit`, `tests/workerd/wallet`), and
  in each lock the two middleware crates alone move. The Worker compiles at
  the new pins with no change of its own. `/health`'s `build.crates` names
  0.3.3, 0.7.8 and 0.4.7.
- The auth layer runs through `process_auth_with_body_bounds` with this
  Worker's bounds (`auth_body_bounds()`): it reads at most
  `AUTH_BODY_MAX_BYTES`, 2 MiB, of a request's body before the caller is
  authenticated, and answers a longer one 413 `ERR_AUTH_BODY_TOO_LARGE`.
  The largest authenticated body the Worker serves is a draft of at most
  256 KiB (`MAX_DRAFT_BYTES`); a payment rides in the `X-BSV-Payment`
  header, and a file goes to the object store through its presigned URL.
  The total the layer holds at once in an isolate (503
  `ERR_AUTH_BODIES_FULL` with `Retry-After`) and the read's deadline (408
  `ERR_AUTH_BODY_TIMEOUT`) are the middleware's defaults. The layer's
  answers reach the caller as the layer wrote them.
- `/quote` reads at most `QUOTE_BODY_MAX_BYTES`, 4 KiB, of its body. A
  quote's request is two JSON numbers, `fileSize` and `retentionPeriod`,
  under 100 bytes as JSON; the figure leaves room for whitespace and fields
  the route does not read. A declared `Content-Length` over the figure is
  refused with nothing read, and the read stops at the chunk that would pass
  it; both are 413 in the Worker's error shape, before any of the body is
  parsed:
  `{"status":"error","code":"ERR_QUOTE_TOO_LARGE","description":"A quote's request is at most 4096 bytes."}`.
- The paid routes' payment door is the middleware's
  `process_payment_with_storage`, which answers a payment longer than
  614,400 bytes 413 `ERR_PAYMENT_SIZE`, not judged; the Worker returns the
  door's answers as the door wrote them. The Worker's own ceiling on the
  `X-BSV-Payment` header (96 KiB, read first) carries a payment well under
  that figure. The Worker maps no payment verification error of its own.
- The fan-out parses at most `ADVERT_BEEF_MAX_BYTES`, 614,400 bytes, of
  each SHIP advertisement's BEEF in a tracker's lookup answer; a longer one
  is skipped and counted as an unreadable one is, not parsed. The lookup
  answer itself stays bounded at 4 MiB (`LOOKUP_ANSWER_MAX_BYTES`). The
  figure is provisional: it is read again at this crate's next bsv-rs pin
  and raised to the door's natural figure then.
- Tests pin each figure: the auth bounds (2 MiB, the middleware's total and
  deadline) and the layer's reader at them (a declared length one byte over
  refused with nothing read; exactly the figure read, one byte more
  refused), every call of the auth layer naming them, `/quote`'s figure
  and its refusal before the parse, and an advertisement's BEEF of exactly
  614,400 bytes read and one of 614,401 skipped. A Worker `Request` cannot
  be built in a native test, so the auth entry point itself is not called
  there.
- No binding, wrangler, route, price or stored-data change.

## 0.3.2 (2026-11-28)

- bsv-rs `0.8.14` (a caret requirement, the floor): it closes, among the
  published advisories, those reaching the features this crate enables
  (`auth`, `wallet`, `transaction`, `script`, `overlay`, `wasm`):
  GHSA-56fp-4337-6vfh, GHSA-wh67-gjx6-4qqh, GHSA-7vx5-cf5p-5c48,
  GHSA-grrj-gwrr-v7r3, GHSA-63w6-rpmj-r9gg, GHSA-33px-hj7f-4cpj,
  GHSA-mqr8-3gvc-hhg3, GHSA-fm3p-cmwv-rf6h and GHSA-4gp5-q4cj-4qjf. Every
  lock moves to it (the root, `tests/heap`, `tests/compat`,
  `tests/workerd/kit`, `tests/workerd/wallet`); bsv-middleware-cloudflare
  stays `=0.7.5` (core 0.4.4). `/health`'s `build.crates` names 0.3.2 and
  0.8.14.
- CI: every workflow action is pinned at a full commit sha; the test job
  fetches the locked dependency graph before the tests (`claims_store`
  reads the middleware's source through an offline `cargo metadata`); the
  wasm32 job's `worker-build --release` runs `--locked`.
- No source change (the version guard in `src/health.rs`'s test only), no
  binding, wrangler or route change, and no stored-data migration.

## 0.3.1 (2026-11-17)

- The paid routes (`/upload`, `/renew`) claim each payment's derivation
  prefix in the `CLAIMS` D1 database, in one statement: the middleware's
  own (`payment_prefix_gate`, the upsert of `D1PrefixStore` and its
  classifying read in one D1 batch), before the wallet is called. Its
  answers are the middleware's: a won claim is served; the same
  transaction again is the signed `409 ERR_PAYMENT_REPLAYED`; another
  transaction under a bound prefix is the signed `400 ERR_PAYMENT_INVALID`;
  a store fault is `503 ERR_PAYMENT_UNAVAILABLE` (retryable, `Retry-After`,
  the quote kept), and nothing is served on a fault. The 503 is signed for
  an authenticated payer when the gate could not make the claim (no
  `CLAIMS` binding, no tables, a D1 fault in the claim); a fault the store
  meets outside the gate (the `AUTH_SESSIONS` record's read or write, the
  read of D1 in front of the claim, the record's carry into D1) is the
  door's own 503, unsigned. The door is the
  middleware's `process_payment_with_storage` (0.7.5), which writes the
  `internalizeAction` request once (`internalize_action_with_tx`). A
  wallet error releases the claim to the same transaction, which is served
  on its retry; no other transaction can take the prefix
  (`src/claims.rs`).
- The `AUTH_SESSIONS` record of a prefix (key
  `auth:nonce:payment-derivation-prefix:<prefix>`, no expiry) is read
  before each claim and carried into D1 with the middleware's statements
  as what it says: a prefix it names bound stays refused; a prefix released
  there to its transaction is carried released, so another transaction is
  refused and the released transaction is served once. A carry releases
  only the claim the carry itself made in D1. After each won claim the
  record is written as the key-value store's own claim writes it (the
  txid, no expiry), with `{"ledger":"d1"}` in its metadata, whatever the
  claim's read of the record found; the D1
  claim alone decides who wins. A bound record without that metadata is
  held in D1 for its transaction. If the record cannot be written after a
  win, the claim is released, the wallet is not called, and the request is
  answered 503: the same payment is served on its retry.
- A release (a wallet error) writes the record as the key-value store's own
  release writes it (`released:<txid>`, same key, no expiry), then releases
  the attempt in D1: the released transaction is served once on its retry,
  and no other transaction is.
- What each won claim was granted is recorded in `CLAIMS`
  (`payment_grants`): the route, the prefix and txid, the payer's identity
  key, the satoshis paid, the object identifier (and the `uhrp://` URL on
  a renewal), the size, the minutes as the route computed them (a fraction
  kept), the expiry the advert carries (on `/upload`, the presigned PUT's
  expiry with the object's custom-time buffer), the route's status and the
  times. The row is written `paid` when the wallet accepts and
  `granted` (or `refused`) when the route answers; a row left `paid`, with
  `answered_at` null, is a won claim whose grant write failed. The record
  never changes the answer, and carries nothing of the payment's bytes.
- `migrations/0001_payment_claims.sql` creates both tables
  (`PAYMENT_CLAIMS_SCHEMA` as the middleware states it, and
  `payment_grants`). `wrangler.toml` and `wrangler.composer.toml` bind
  `CLAIMS` (placeholder ids).
- **Deploy order.** Before this release is deployed, each instance's
  `CLAIMS` D1 database is created, bound in the config being deployed,
  and migrated (`wrangler d1 migrations apply CLAIMS --remote`); then the
  Worker is deployed (`DEPLOYMENT.md`, Step 1 and Step 6). Without the
  binding, or with the binding and no tables, every payment to `/upload`
  or `/renew` is answered `503 ERR_PAYMENT_UNAVAILABLE` (`Retry-After`):
  the wallet is not called and nothing is served. The gate's 503 (no
  binding; no tables, for a prefix with no `AUTH_SESSIONS` record or for
  the transaction a `released:<txid>` record names) is signed for an
  authenticated payer; with no tables, any other payment whose prefix has
  a record is the door's 503, unsigned. The 402 challenge is still issued,
  and the routes that take no payment are unaffected. The cutover from a
  release before 0.3.1 is two deploys (`DEPLOYMENT.md`, "The cutover").
- A payment header longer than 96 KiB is refused before it is parsed or
  decoded, with the middleware's answer to a payment transaction it cannot
  read: `400 ERR_INVALID_PAYMENT`, "Payment not verified: payment
  transaction unreadable: the payment transaction is too large to read".
  Nothing is claimed, so the quote stands.
- The fan-out posts an advert only to hosts named by tracker outputs that
  are SHIP advertisements for the topic, signed by the identity key they
  name under BRC-88's derivation and locked by that identity's linked key,
  for a public `https` origin: a DNS name (no IP literal, no `localhost`,
  `.localhost`, `.local`, `.internal` or `.home.arpa` name, no `xn--`
  label), the default port, and no credentials, path, query or fragment.
  Each host once, the primary left out, at most 32.
- bsv-rs `0.8.13` (the patched version of GHSA-j4w5-4g84-q3f4; `0.8.12`
  is the patched version of GHSA-33fm-jcm5-4m3m), in every lock the
  repository tracks; bsv-middleware-cloudflare `=0.7.5` (feature
  `d1-claims`), bsv-middleware-core 0.4.4. `/health`'s `build.crates`
  names them. The Worker does not enable bsv-rs's `kvstore` feature, so
  the `GlobalKVStore` code 0.8.13 changes is not in its build.
- Tests: the middleware's conformance kit runs against the store as the
  routes wire it, on SQLite with the middleware's statements
  (`tests/claims_store.rs`) and on workerd's D1 and KV in Miniflare
  (`tests/workerd`), at the kit's defaults and at raised bounds (sizes 2 to
  64, a hold of 128 passes); with the release path's mixes the kit runs no
  law for. `tests/workerd` also runs the Worker: one payment in 2, 4 and 16
  simultaneous requests to `/upload` is served once; two transactions under
  one prefix at once are served once. `/renew` is driven the same way: a
  paid renewal is served once and its grant row recorded; the same payment
  again is the signed 409 with no second renewal; another transaction
  under the prefix is the signed 400; one payment in 2, 4 and 16
  simultaneous requests is one renewal. A wallet error's release is served
  once on its retry, against the previous release's Worker in both orders
  on one key-value namespace; a prefix the previous release released,
  paid at once by its transaction and by others, is served to that
  transaction at most once and to no other (on SQLite over the kit's
  schedules, on workerd's store, and through both Workers). The Worker
  without its `CLAIMS` binding, and
  with the binding and no tables, answers the 503 on both paid routes and
  serves nothing. The race client reads each answer's signature: the 200,
  the 402 challenge, the 409, the 400 `ERR_PAYMENT_INVALID` and the gate's
  503 are signed; the door's own 400s, its 402 after a wallet rejection and
  its 503 are not. `tests/heap` holds the paid path to
  the middleware's stated bound (1.25 MiB plus 4 bytes per header byte).

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
