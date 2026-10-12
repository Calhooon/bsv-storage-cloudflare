# Changelog

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
