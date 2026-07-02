#!/usr/bin/env bash
# Thin deploy wrapper for bsv-storage-cloudflare.
#
# Guarantees:
#   - CLOUDFLARE_API_TOKEN is set (force-auth via token, NOT OAuth —
#     matches the user's "never deploy with OAuth" rule).
#   - Fresh WASM build before deploy (no stale artifacts).
#   - Worker URL printed at the end so the caller can smoke-test.
#
# Usage:
#   source secrets.md     # or export CLOUDFLARE_API_TOKEN=...
#   ./scripts/deploy.sh

set -euo pipefail

if [[ -z "${CLOUDFLARE_API_TOKEN:-}" ]]; then
  echo "error: CLOUDFLARE_API_TOKEN not set." >&2
  echo "       Run 'source secrets.md' (or 'export CLOUDFLARE_API_TOKEN=...') first." >&2
  echo "       Deploying with OAuth is forbidden (see BSV project rules)." >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Defensive: never deploy with unchecked code. Gate must be green first.
echo "==> Pre-deploy quality gates"
./scripts/check.sh

echo "==> worker-build --release"
cargo install -q worker-build@0.8.4 && worker-build --release

echo "==> wrangler deploy"
# Capture output so we can extract the worker URL and echo it back.
deploy_out="$(npx wrangler deploy 2>&1)"
printf '%s\n' "$deploy_out"

# Worker URL appears in wrangler output like:
#   Published bsv-storage-cloudflare (0.87 sec)
#     https://bsv-storage-cloudflare.<account>.workers.dev
worker_url="$(printf '%s\n' "$deploy_out" \
  | grep -oE 'https://[^ ]*\.workers\.dev' \
  | head -n1 || true)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [[ -n "$worker_url" ]]; then
  echo "Deployed: $worker_url"
  echo ""
  echo "Smoke test:"
  echo "  curl -sS $worker_url/"
  echo "  curl -sS -X POST $worker_url/quote -H 'content-type: application/json' \\"
  echo "    -d '{\"fileSize\":1048576,\"retentionPeriod\":43200}'"
else
  echo "Deployed (could not parse worker URL from wrangler output)."
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
