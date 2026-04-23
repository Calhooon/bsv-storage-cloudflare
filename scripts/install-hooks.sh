#!/usr/bin/env bash
# Install the pre-commit hook into this repo's .git/hooks.
# Run once after cloning.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -d .git ]; then
  echo "error: .git not found — run this inside the repo root after 'git init'" >&2
  exit 1
fi

cp .githooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
echo "installed .git/hooks/pre-commit"
