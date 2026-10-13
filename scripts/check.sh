#!/usr/bin/env bash
# Local quality gate. Use --cargo-only when the release keeper owns Worker builds.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ $# -gt 1 || ( $# -eq 1 && "$1" != --cargo-only ) ]]; then
  echo "usage: scripts/check.sh [--cargo-only]" >&2
  exit 2
fi

echo "==> cargo fmt --check"
# Scope fmt to the workspace members we own (root crate + parity harness).
# Registry dependencies have their own formatting contracts.
cargo fmt -p bsv-storage-cloudflare -p parity -- --check

echo "==> cargo clippy (workspace, -D warnings)"
cargo clippy --locked --workspace --all-targets -- -D warnings

echo "==> cargo clippy (wasm32-unknown-unknown, -D warnings)"
cargo clippy --locked --target wasm32-unknown-unknown --all-targets -- -D warnings

echo "==> cargo check (wasm32-unknown-unknown)"
cargo check --locked --target wasm32-unknown-unknown

echo "==> cargo test (workspace)"
cargo test --locked --workspace --no-fail-fast

if [[ "${1:-}" == --cargo-only ]]; then
  echo "all five cargo gates green; Worker build remains with the release keeper"
  exit 0
fi

echo "==> worker-build --release"
cargo install -q worker-build@0.8.4 --locked && worker-build --release

echo "all gates green"
