#!/usr/bin/env bash
# scrub: the public tree carries no deployment identifier, hostname, key or token.
# Runs on every pull request (the `scrub` check of ci.yml) and by hand before one:
#   tools/scrub.sh            # exit 0 clean, exit 2 with every miss named by file and line
# The shapes are the release scan's (the private canonical's scripts/release-public.sh,
# retired when this repository became the code of record): the same rule, now a check.
set -u
cd "$(dirname "$0")/.."
FAIL=0
# the scan reads the committed tree through git grep, so build/, target/ and the ignored files never count
SELF=':!tools/scrub.sh'
hit() { echo "SCRUB: $1"; echo "$2" | sed 's/^/  /'; FAIL=1; }

# 1. an id-shaped value in a wrangler file: a 32-hex or a uuid in quotes (account, database, namespace).
#    A placeholder is <your-...>; every id lives in the operator's private infra repository.
RE_ID='"[0-9a-f]{32}"|"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"'
H=$(git grep -n -I -E -- "$RE_ID" -- 'wrangler*.toml' '**/wrangler*.toml' 2>/dev/null | cut -d: -f1,2 || true)
[ -z "$H" ] || hit "an id-shaped value in a wrangler file" "$H"

# 2. a deployment hostname: <worker>.<account>.workers.dev or <project>.pages.dev that is not a placeholder
#    (a placeholder starts with your- or <your-).
RE_HOST='(^|[^A-Za-z0-9.<-])[A-Za-z0-9-]+\.[A-Za-z0-9-]+\.workers\.dev|(^|[^A-Za-z0-9.<-])[A-Za-z0-9-]+\.pages\.dev'
H=$(git grep -n -I -o -E -- "$RE_HOST" -- . "$SELF" 2>/dev/null | grep -v -E ':[^A-Za-z0-9]?(your-|<your-)' | cut -d: -f1,2 || true)
[ -z "$H" ] || hit "a deployment hostname that is not a placeholder" "$H"

# 3. a key-shaped string: an AWS access key id, a Slack token, a PEM private key header,
#    a 64-hex pair, an api key assignment, a bearer of thirty or more characters.
#    AWS's two documented example access keys (public documentation, ending in EXAMPLE; the
#    SigV4 vectors in src/r2_presign.rs) are allowed by that ending, as the release scan allowed them.
#    The PEM shape is assembled from parts so this file never carries it whole.
PEM="-----BEGIN [A-Z ]*PRIVATE"" KEY-----"
RE_KEY="AKIA[0-9A-Z]{16}|xox[bp]-[0-9A-Za-z-]+|$PEM|[0-9a-f]{64}:[0-9a-f]{64}|api[_-]?key[[:space:]]*[:=][[:space:]]*\"[A-Za-z0-9_-]{20,}\"|Bearer [A-Za-z0-9_.-]{30,}"
H=$(git grep -n -I -E -- "$RE_KEY" -- . "$SELF" 2>/dev/null | grep -v 'notpem' | grep -v -E 'AKIA[0-9A-Z]{9}EXAMPLE' | cut -d: -f1,2 || true)
[ -z "$H" ] || hit "a key-shaped string" "$H"

# 4. a token-shaped assignment: a name ending in TOKEN set to thirty or more characters that are not a placeholder
#    and not a reference to the environment (process.env, os.environ, a shell variable).
RE_TOKEN='TOKEN[A-Za-z_]*[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9_.-]{30,}'
H=$(git grep -n -I -E -- "$RE_TOKEN" -- . "$SELF" 2>/dev/null | grep -v -E 'TOKEN[A-Za-z_]*[[:space:]]*[:=][[:space:]]*["'"'"']?(your-|<|\$|process\.env|os\.environ)' | cut -d: -f1,2 || true)
[ -z "$H" ] || hit "a token-shaped assignment" "$H"

# 5. a private deployment file: a secrets file or a dotenv. A second wrangler config (another Worker of the
#    same tree, a staging copy) is allowed by name and judged by its content under 1 and 2.
H=$(git ls-files | grep -i -E '(^|/)secrets[^/]*\.md$|(^|/)\.dev\.vars$|(^|/)\.env$' || true)
[ -z "$H" ] || hit "a private deployment file in the tree" "$H"

# 6. the two private programs are never named here (the stack's rule 5).
for n in btg-token zk-notes nullifier; do
  H=$(git grep -l -i -I -F -- "$n" -- . "$SELF" 2>/dev/null || true)
  [ -z "$H" ] || hit "the private program name '$n'" "$H"
done

if [ "$FAIL" = 0 ]; then echo "scrub: clean"; exit 0; fi
echo "scrub: FAILED"; exit 2
