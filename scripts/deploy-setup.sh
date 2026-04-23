#!/usr/bin/env bash
# Idempotent CF resource provisioner for bsv-storage-cloudflare.
#
# Creates (or skips if already present):
#   - R2 bucket      `uhrp-prod`
#   - KV namespace   `AUTH_SESSIONS` (bound as `AUTH_SESSIONS` in wrangler.toml)
#   - Queue          `uhrp-post-upload`
#
# Prints the KV namespace ID and queue ID at the end. **You must paste the
# KV ID into `wrangler.toml`** — the script tells you where.
#
# Usage:
#   source secrets.md              # exports CLOUDFLARE_API_TOKEN
#   ./scripts/deploy-setup.sh
#
# Safe to re-run: every step checks for an existing resource first and
# prints "already exists" rather than failing.

set -euo pipefail

if [[ -z "${CLOUDFLARE_API_TOKEN:-}" ]]; then
  echo "error: CLOUDFLARE_API_TOKEN not set." >&2
  echo "       Run 'source secrets.md' (or 'export CLOUDFLARE_API_TOKEN=...') first." >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

R2_BUCKET_NAME="uhrp-prod"
KV_NAMESPACE_TITLE="AUTH_SESSIONS"
QUEUE_NAME="uhrp-post-upload"
WRANGLER="npx wrangler"

# ── R2 bucket ────────────────────────────────────────────────────────────────
echo "==> R2 bucket: $R2_BUCKET_NAME"
if $WRANGLER r2 bucket list 2>/dev/null | grep -q "^${R2_BUCKET_NAME}$"; then
  echo "    already exists, skipping"
else
  $WRANGLER r2 bucket create "$R2_BUCKET_NAME"
  echo "    created"
fi

# ── KV namespace ─────────────────────────────────────────────────────────────
echo "==> KV namespace: $KV_NAMESPACE_TITLE"
# `wrangler kv namespace list` returns JSON with {id, title}. We look for the
# full title `<worker-name>-<binding>` which is wrangler's convention.
#
# jq is required; if missing, fall back to a grep for the binding name
# (less precise but still idempotent).
KV_FULL_TITLE="bsv-storage-cloudflare-${KV_NAMESPACE_TITLE}"
KV_ID=""
if command -v jq >/dev/null 2>&1; then
  KV_ID="$($WRANGLER kv namespace list 2>/dev/null \
    | jq -r --arg t "$KV_FULL_TITLE" '.[] | select(.title==$t) | .id' \
    | head -n1)"
else
  # Parse-free fallback: the create command is idempotent at the API level
  # (returns existing namespace) but the CLI rejects duplicates — so we run
  # it and tolerate the "already exists" error message.
  echo "    (jq not installed — falling back to create-and-tolerate)"
fi

if [[ -n "$KV_ID" ]]; then
  echo "    already exists, id = $KV_ID, skipping"
else
  create_out="$($WRANGLER kv namespace create "$KV_NAMESPACE_TITLE" 2>&1 || true)"
  echo "$create_out"
  # Extract id from the TOML-ish output wrangler prints. Example line:
  #   id = "c22bbbbcade14868a970638672258594"
  KV_ID="$(printf '%s\n' "$create_out" \
    | grep -oE 'id = "[0-9a-f]{32}"' \
    | head -n1 \
    | sed -E 's/id = "([0-9a-f]{32})"/\1/')"
  if [[ -z "$KV_ID" ]]; then
    # Fallback: if create failed because it exists, re-query.
    if command -v jq >/dev/null 2>&1; then
      KV_ID="$($WRANGLER kv namespace list 2>/dev/null \
        | jq -r --arg t "$KV_FULL_TITLE" '.[] | select(.title==$t) | .id' \
        | head -n1)"
    fi
  fi
fi

# ── Queue ────────────────────────────────────────────────────────────────────
echo "==> Queue: $QUEUE_NAME"
if $WRANGLER queues list 2>/dev/null | grep -qE "^\|? *${QUEUE_NAME}\\b"; then
  echo "    already exists, skipping"
else
  create_out="$($WRANGLER queues create "$QUEUE_NAME" 2>&1 || true)"
  echo "$create_out"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Next manual steps (edit wrangler.toml):"
if [[ -n "$KV_ID" ]]; then
  echo "  1. Paste KV ID into [[kv_namespaces]] 'id' (around line 37):"
  echo "         id = \"$KV_ID\""
else
  echo "  1. Look up the KV namespace ID with 'npx wrangler kv namespace list'"
  echo "     and paste it into [[kv_namespaces]] 'id' (around line 37)."
fi
echo "  2. Set PUBLIC_URL_BASE (R2 custom-domain origin) — see DEPLOYMENT.md §4."
echo "  3. Set R2_S3_ENDPOINT_HOST = '<account_id>.r2.cloudflarestorage.com'."
echo "  4. Step 3 of DEPLOYMENT.md: 'wrangler secret put' each secret."
echo "  5. Step 5 of DEPLOYMENT.md: wire R2 events to '$QUEUE_NAME'."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
