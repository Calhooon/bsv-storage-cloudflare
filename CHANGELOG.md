# Changelog

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
- `overlay-engine` still comes from `../rust-overlay` by path and takes `bsv-rs` from `../bsv-rs`
  by path; with `v0.4.1` checked out there the lock holds that path copy of 0.4.1 beside the
  registry's. Closing it is `rust-overlay`'s manifest, not this one.
