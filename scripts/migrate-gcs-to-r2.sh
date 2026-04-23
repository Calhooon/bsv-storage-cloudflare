#!/usr/bin/env bash
# GCS → R2 bulk migration template for the `cdn/` prefix.
#
# ══════════════════════════════════════════════════════════════════════════
# DO NOT RUN AS-IS. This script is a template.
#
# The first line below is an `exit 1`. Remove it ONLY after you have:
#   1. Confirmed the GCS bucket name (`GCS_BUCKET` below).
#   2. Confirmed R2 is empty or that overwrites are acceptable (`--no-replace`
#      on by default, but double-check).
#   3. Reviewed the rclone flags — some of them control checksumming and
#      parallelism, and the wrong values silently corrupt or throttle.
#   4. Read DEPLOYMENT.md §10 for the full rationale.
# ══════════════════════════════════════════════════════════════════════════

exit 1  # ← remove this line after reviewing everything below.

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
#
# Both rclone remotes must be configured via `rclone config` beforehand.
#   - `gcs-prod`: Google Cloud Storage remote, service-account creds.
#   - `r2-prod`:  S3 remote, endpoint = https://<account>.r2.cloudflarestorage.com,
#                 access key + secret from DEPLOYMENT.md §2.
#
# Verify with:
#   rclone lsd gcs-prod:
#   rclone lsd r2-prod:
GCS_REMOTE="gcs-prod"
GCS_BUCKET="<your-gcs-bucket-name>"   # e.g. "nanostore-prod"

R2_REMOTE="r2-prod"
R2_BUCKET="uhrp-prod"

# ── Dry run first ────────────────────────────────────────────────────────────
#
# Prints what would be copied without moving bytes. Sanity-check the
# counts against `gcloud storage du gs://${GCS_BUCKET}/cdn/` before the
# real run.
echo "==> Dry run"
rclone copy \
  "${GCS_REMOTE}:${GCS_BUCKET}/cdn" \
  "${R2_REMOTE}:${R2_BUCKET}/cdn" \
  --dry-run \
  --progress \
  --stats 10s

read -rp "Proceed with the real copy? [y/N] " ans
[[ "$ans" =~ ^[Yy]$ ]] || exit 0

# ── Real copy ────────────────────────────────────────────────────────────────
#
# Flag rationale (consult `rclone help` for the full reference):
#
#   --transfers 16
#     Parallel uploads. R2 can sustain well over this; GCS egress is the
#     limiter (~1 Gbps per connection). Higher values help WAN, hurt CPU.
#
#   --checksum
#     MD5 both sides before skip. REQUIRED for content-addressed storage —
#     a silent single-bit flip would mean a UHRP URL serves the wrong bytes.
#
#   --metadata
#     Copies x-goog-meta-* → x-amz-meta-*. rclone does the key translation
#     automatically. Must-have: our queue consumer reads
#     `uploaderidentitykey` and `custom-time` from custom metadata.
#
#   --no-update-modtime
#     Don't touch destination modtime. R2's modtime is set to upload time
#     anyway; explicit here to avoid rclone's default of syncing modtime.
#
#   --ignore-existing
#     Skip objects already in R2. Lets you run-resume without re-uploading.
#     If you're re-running after a source change, use `rclone sync` instead.
#
#   --log-level INFO --log-file=migrate.log
#     Audit trail. Preserve `migrate.log` post-migration.
#
# Budget check (as of 2026-04): GCS egress is ~$0.12/GB. R2 ingress is free.
# 1 TB migration ≈ $120 of GCS egress. Add 10% for retries.
echo "==> Real copy starting"
rclone copy \
  "${GCS_REMOTE}:${GCS_BUCKET}/cdn" \
  "${R2_REMOTE}:${R2_BUCKET}/cdn" \
  --transfers 16 \
  --checkers 32 \
  --checksum \
  --metadata \
  --no-update-modtime \
  --ignore-existing \
  --progress \
  --stats 30s \
  --log-level INFO \
  --log-file=migrate.log

# ── Verification ─────────────────────────────────────────────────────────────
#
# Byte-count parity is a weak check (a two-byte-identical file produces the
# same count), so we also do a spot-check: pick 10 random keys, download
# from both backends, compare SHA-256. If `cdn/` is millions of objects,
# scale `--ratio` on the `rclone check` command.
echo "==> Source size"
rclone size "${GCS_REMOTE}:${GCS_BUCKET}/cdn"
echo "==> Destination size"
rclone size "${R2_REMOTE}:${R2_BUCKET}/cdn"

echo "==> 1% spot-check with hashes"
rclone check \
  "${GCS_REMOTE}:${GCS_BUCKET}/cdn" \
  "${R2_REMOTE}:${R2_BUCKET}/cdn" \
  --one-way \
  --size-only=false \
  --checkers 16
