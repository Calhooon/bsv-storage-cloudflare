#!/usr/bin/env bash
# Local quality gate. Runs the same commands CI runs. Must pass before every commit.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> cargo fmt --check"
# Scope fmt to the workspace members we own (root crate + parity harness).
# Registry dependencies have their own formatting contracts.
cargo fmt -p bsv-storage-cloudflare -p parity -- --check

echo "==> cargo clippy (wasm32-unknown-unknown, -D warnings)"
cargo clippy --locked --target wasm32-unknown-unknown --all-targets -- -D warnings

echo "==> cargo check (wasm32-unknown-unknown)"
cargo check --locked --target wasm32-unknown-unknown

echo "==> cargo test --lib"
cargo test --locked --lib

echo "==> worker-build --release"
cargo install -q worker-build@0.8.4 --locked && worker-build --release

echo "all gates green"
