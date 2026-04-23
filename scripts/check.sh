#!/usr/bin/env bash
# Local quality gate. Runs the same commands CI runs. Must pass before every commit.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> cargo fmt --check"
# Scope fmt to the workspace members we own (root crate + parity harness).
# `cargo fmt --all` additionally recurses into path-dep sibling crates
# (bsv-rs, bsv-middleware-cloudflare-public, rust-overlay, rust-middleware),
# which have their own CI contracts and must not be formatted here.
cargo fmt -p bsv-storage-cloudflare -p parity -- --check

echo "==> cargo clippy (wasm32-unknown-unknown, -D warnings)"
cargo clippy --target wasm32-unknown-unknown --all-targets -- -D warnings

echo "==> cargo check (wasm32-unknown-unknown)"
cargo check --target wasm32-unknown-unknown

echo "==> cargo test --lib"
cargo test --lib

echo "==> worker-build --release"
worker-build --release

echo "all gates green"
