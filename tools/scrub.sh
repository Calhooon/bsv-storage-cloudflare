#!/usr/bin/env bash
# scrub: the public tree carries no deployment identifier, hostname, key or token.
# Runs on every pull request, push and tag (the `scrub` check of ci.yml) and by hand before one:
#   tools/scrub.sh            # the tracked tree
#   tools/scrub.sh <base>     # the tree, then every commit's added lines since <base> and the net diff
#   tools/scrub.sh --tag      # the tree, then every commit's added lines since the previous release tag
#   tools/scrub.sh --all      # the tree, then every commit's added lines from the root
# A release answers for what it adds: on a tag the scan reads every commit since the previous release tag, and the tree.
# Exit 0 clean, exit 2 with every miss named by file, line and kind, never by value.
set -u
cd "$(dirname "$0")/.."
FAIL=0
MODE="${1:-}"
hit() { echo "SCRUB: $1"; echo "$2" | sed 's/^/  /'; FAIL=1; }

# This repository's allowances, the only ones; the program below is the same in every public
# repository of this seat. KEY_DOOR: the tracked test vectors the key shapes are not judged in (a
# path ending in / holds the files under it, a path ending in #cfg(test) only that Rust file's real
# #[cfg(test)] items); tokens are judged there too. A change to this list shows in the diff.
KEY_DOOR='
src/storage/presign.rs#cfg(test)
src/wallet/brc42.rs#cfg(test)
tests/compat/v0_2_4/src/storage/presign.rs#cfg(test)
tests/compat/v0_2_4/src/wallet/brc42.rs#cfg(test)
'
# AWS_EXAMPLE: yes allows AWS's two documented example access keys (ending in EXAMPLE), which the SigV4 vectors here use.
AWS_EXAMPLE=yes
# NOTPEM: the files where a PEM private-key header on a line that also says notpem is allowed; none here.
NOTPEM=''
# RELEASE_TAGS: this repository's release tag patterns (--tag reads from the previous one).
RELEASE_TAGS='v*'

# 1. an id-shaped value in a wrangler file: a 32-hex or a uuid in quotes (account, database, namespace).
#    A placeholder is <your-...>; every id lives in the operator's private infra repository.
RE_ID='"[0-9a-f]{32}"|"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"'
H=$(git grep -n -I -E -- "$RE_ID" -- 'wrangler*.toml' '**/wrangler*.toml' 2>/dev/null | cut -d: -f1,2 || true)
[ -z "$H" ] || hit "an id-shaped value in a wrangler file" "$H"

# 2. a deployment hostname: <worker>.<account>.workers.dev or <project>.pages.dev that is not a placeholder
#    (a placeholder starts with your- or <your-).
RE_HOST='(^|[^A-Za-z0-9.<-])[A-Za-z0-9-]+\.[A-Za-z0-9-]+\.workers\.dev|(^|[^A-Za-z0-9.<-])[A-Za-z0-9-]+\.pages\.dev'
H=$(git grep -n -I -o -E -- "$RE_HOST" 2>/dev/null | grep -v -E ':[^A-Za-z0-9]?(your-|<your-)' | cut -d: -f1,2 || true)
[ -z "$H" ] || hit "a deployment hostname that is not a placeholder" "$H"

# 3. a private deployment file: a secrets file or a dotenv. A second wrangler config (another Worker of the
#    same tree, a staging copy) is allowed by name and judged by its content under 1 and 2.
H=$(git ls-files | grep -i -E '(^|/)secrets[^/]*\.md$|(^|/)\.dev\.vars$|(^|/)\.env$' || true)
[ -z "$H" ] || hit "a private deployment file in the tree" "$H"

# 4. the two private programs are never named here (the stack's rule 5); each name is written in two
#    parts so this file never carries it whole and is scanned like every other file.
for n in btg""-token zk""-notes nulli""fier; do
  H=$(git grep -l -i -I -F -- "$n" 2>/dev/null || true)
  [ -z "$H" ] || hit "the private program name '$n'" "$H"
done

# 5. a key or a token: the rule is the comment at the head of the program below (python3 over the
#    tracked files and, given a base or --all, every commit's added lines).
read -r -d '' KEYSCAN <<'PY' || true
import os
import re
import subprocess
import sys

# The key and token rule, the same program in every public repository of this seat; only the
# allowances in the lines above it (KEY_DOOR, AWS_EXAMPLE, NOTPEM) belong to one repository.
# It reports file, line and the kind of match, never the value.
#
# 1. A token fails wherever it stands: Cloudflare (cfut_), sk-, Replicate (r8_), GitHub (gh*_,
#    github_pat_), Google (AIza), npm (npm_), cio, an AWS access key id, a Slack token, a PEM
#    private-key block, a 64-hex pair, an api key or a *TOKEN* assignment of thirty or more
#    characters (not a placeholder or a reference to the environment), a Bearer of thirty or more,
#    also when a line continuation (a trailing backslash) runs it on to the next line.
# 2. A key-like name is one containing priv, secret, seed, wif or mnemonic, or ending in key,
#    keys, keyhex or key_hex, in any case (rootKey, root_key, ADMIN_KEY, masterKeyHex); a name that
#    says pub or public (pubkey, publicKey, identityPubKey) is not one. A 64-hex value (with or
#    without 0x, in any case, or 66 hex: 64 and the 01 compression flag, or 00 and 64) fails on a
#    line that carries a key-like name, on the line after one when the value has no name of its
#    own, and in a list opened under one, whatever else those lines say. Under a key-like name the
#    value also fails as 32 bytes in base64 or base58, as hex split into quoted pieces or pairs, as
#    a byte array, and as 12 to 24 lower-case words under a name containing mnemonic, seed or
#    phrase. A WIF and an xprv fail under any name.
# 3. Any other 64-hex value that is quoted, assigned, a call's argument or alone on its line, with
#    8 or more distinct digits, fails unless its own name says what it is: the name it is assigned
#    to or the key of its field (txid, hash, root, merkle, checksum, checkpoint, digest, sha*, id,
#    integrity, pub/public), or, for a value with no name on its line, the name on the line it
#    continues, the line that opens its list (and the one before that) or its table's header.
#    A word in a comment is not a name. A value inside a URL is judged by its parameter's name.
# 4. The only door is KEY_DOOR: tracked paths whose test vectors (keys under key-like names among
#    them) the key shapes of 2 and 3 do not judge; a path ending in / holds every file under it, a
#    path ending in #cfg(test) holds only the real #[cfg(test)] items of that Rust file. A new file
#    under a door shows in the pull request's tree; a new door shows in this list. Tokens are
#    judged everywhere. A file is read whole: UTF-16 is decoded, a NUL byte is dropped.
# Scope: argument '' reads the tracked tree; a revision reads the tree, then every commit's added
# lines since it and the net diff; --all reads the tree and every commit's added lines from the
# root (each added line judged in its file at that revision). No value is allowed by listing it.
# --tag reads the tree and every commit's added lines since the previous release tag: the nearest
# tag matching RELEASE_TAGS (the fifth argument) that is an ancestor of HEAD and does not point at
# HEAD; with none, every commit from the root. A shallow clone, an unreadable tag or an empty range
# fails, never passes.

MODE, DOOR, AWS_EXAMPLE, NOTPEM, RELEASE_TAGS = (sys.argv[1:] + ['', '', '', '', ''])[:5]
DOORS = DOOR.split()
REMEDY = ('If a match is a secret, take it out and tell the repository\'s owner: it is public the moment '
          'it is pushed, so it must be revoked or rotated, not only deleted. If it is a hash, a txid or an '
          'id, give the value a name that says so (txid, block_hash, merkle_root, checksum, digest, ..._id). '
          'If it is a public key, name it as one (pubkey, public_key, ..._pub). If it is a test vector, add '
          'its tracked path to the KEY_DOOR list at the head of this script (a path ending #cfg(test) holds '
          'only that Rust file\'s test items; a path ending / holds the files under it).')

B58 = '1-9A-HJ-NP-Za-km-z'
PEM_HEAD = '-----BEGIN [A-Z ]*PRIVATE' + ' KEY-----'
TOKEN_SHAPES = [
    ('a Cloudflare token', re.compile(r'(?<![A-Za-z0-9_])cfut_[A-Za-z0-9_-]{20,}')),
    ('an sk- API key', re.compile(r'(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{20,}')),
    ('a Replicate token', re.compile(r'(?<![A-Za-z0-9_])r8_[A-Za-z0-9]{20,}')),
    ('a GitHub token', re.compile(r'(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{30,}')),
    ('a GitHub fine-grained token', re.compile(r'(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{40,}')),
    ('a Google API key', re.compile(r'(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}')),
    ('an npm token', re.compile(r'(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])')),
    ('a cio token', re.compile(r'(?<![A-Za-z0-9_])cio[A-Za-z0-9]{32}(?![A-Za-z0-9])')),
    ('an AWS access key id', re.compile(r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])')),
    ('a Slack token', re.compile(r'xox[bp]-[0-9A-Za-z-]+')),
    ('a PEM private-key block', re.compile(PEM_HEAD)),
    ('a 64-hex pair', re.compile(r'[0-9a-f]{64}:[0-9a-f]{64}')),
    ('an api key assignment', re.compile(r'''(?i:api[_-]?key)\s*[:=]\s*["'][A-Za-z0-9_-]{20,}["']''')),
    ('a token assignment', re.compile(r'''TOKEN[A-Za-z_]*["']?\s*[:=]\s*["']?(?!your-|<|\$|process\.env|os\.environ)[A-Za-z0-9_.-]{30,}''')),
    ('a Bearer token', re.compile(r'Bearer [A-Za-z0-9_.-]{30,}')),
]
B58_SHAPES = [
    ('a WIF private key', re.compile(r'(?<![%s])(?:5[HJK][%s]{49}|[KLc][%s]{51}|9[%s]{50})(?![%s])' % ((B58,) * 5))),
    ('an extended private key', re.compile(r'(?<![%s])[xt]prv[%s]{100,108}(?![%s])' % ((B58,) * 3))),
]
HEXRUN = re.compile(r'(?:(?<![0-9A-Za-z_])0[xX]|(?<=\\[nrtx])|(?<![0-9A-Za-z_]))([0-9a-fA-F]{64,66})(?![0-9A-Za-z_]|\.\d)')
IDENT = re.compile(r'[A-Za-z_$][A-Za-z0-9_$-]*')
ASSIGN = r'(?<![:=!<>])(?::=|=>|\+=|[:=])(?![:=])'
OPENER = re.compile(r'''(?<![\w$.-])([A-Za-z_$][\w$.-]*)["'`]?\s*\]?\s*''' + ASSIGN)
TYPED = re.compile(r'''([A-Za-z_$][\w$]*)\s*:\s*[^:=,"'`{}()]*$''')
GLUE = r'''\s*(?:[\w:.!]*[\[({&*]\s*)*(?:b|r|br)?["'`]?\s*'''
STRIP = re.compile(r'''(["'`])(?:0[xX])?[0-9a-fA-F]{64,66}\1|(?:0[xX])?[0-9a-fA-F]{64,66}|"[^"]*"|'[^']*'|`[^`]*`|\b[0-9][0-9_]*\b|\.[a-z_]+\(\)|\b(?:Some|None|Ok|Err|true|false|null|vec!)''')
LIST_REST = re.compile(r'^[\s,;()\[\]{}*.-]*$')
COMMENT = re.compile(r'(?:^|\s)(?:#|//|<!--|/\*).*$|^\s*\*.*$')
PUBLIC_WORD = re.compile(r'(?i:hash|txid|merkle|checksum|checkpoint|digest|integrity|public|pubkey|sha(?:-?(?:1|224|256|384|512))?(?![a-z])|(?<![a-z])root|(?<![a-z])ids?(?![a-z])|(?<![a-z])pub(?![a-z]))|[a-z](?:Ids?|Root|Pub)(?![a-z])|[A-Z]IDS?(?![A-Za-z])')
MNEMONIC = re.compile(r'''^\s*["'`]?([a-z]{3,8}(?: [a-z]{3,8}){11,23})["'`]?\s*[,;)]?\s*$''')
BASE_32 = re.compile(r'''^\s*["'`]([A-Za-z0-9+/]{43}=|[A-Za-z0-9_-]{43}|[%s]{43,44})["'`]''' % B58)
SPLIT = re.compile(r'''0[xX]|[\s"'`+:_,;\[\](){}\\-]''')
CFG_TEST = re.compile(r'^\s*#\[cfg\((?:all\()?test\b')
WINDOW = 240
PROSE = ('.md', '.txt', '.rst')
OPENERS = {}
PUBKEY_PHRASE = re.compile(r'(?i)\b(pub(?:lic)?)[\s_-]+(keys?)\b')
# A name that announces a service credential: a token, a password, a credential, a bearer, a
# secret, a private thing, an api key or an auth key (x-auth-key among them), or a name ending in
# key. This is the token rule's name set; the key/seed/mnemonic names stay with rules 2 and 3.
B2_WORD = re.compile(r'(?i)token|password|passwd|credential|bearer|api[_-]?key|auth[_-]?key|secret|private')
# Compiled-source file suffixes. The two NAME heuristics (a bare root, a credential under a
# secret-like name) do not fire here: in compiled source a `key`/`token`/`secret`/`root` identifier
# is overwhelmingly a map key, a struct field, a merkle root or a test fixture, not a pasted secret.
# The precise shapes (64-hex, byte arrays, WIF, xprv, mnemonics, vendor tokens) still judge them.
COMPILED = ('.rs', '.go', '.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp', '.java', '.kt', '.kts',
            '.swift', '.scala', '.cs', '.m', '.mm', '.rb')
# A value that is not a credential however it is named: a placeholder or an example.
PLACEHOLDER = re.compile(r'(?i)^(?:your[-_]|change[-_]?me|example|placeholder|redacted|dummy|sample|'
                         r'test[-_]?(?:token|key|secret|value)|insert[-_]|put[-_]|todo|fixme|replace[-_]|xxx|\.\.\.|\*\*\*)')
# The words that qualify a 'root' as a hash's, not a wallet's (merkle_root, tx_root, state_root).
ROOT_QUAL = {'merkle', 'tx', 'state', 'block', 'world', 'storage', 'receipt', 'account', 'header',
             'witness', 'utxo', 'trie', 'tree', 'commitment', 'transaction', 'transactions', 'sub'}
HEIGHT = re.compile(r'(?i)(?<![a-z])height(?![a-z])')


def words(name):
    return [w.lower() for w in re.findall(r'[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+', name)]


def key_like(name):
    low = name.lower()
    if re.search(r'priv|secret|seed|mnemonic', low) or any(w.startswith('wif') for w in words(name)):
        return True
    if not re.search(r'keys?(?:_?hex)?$', low.replace('-', '_')):
        return False
    return not ('pub' in words(name) or 'public' in low or 'pubkey' in low)


def public_name(name):
    return bool(name) and not key_like(name) and bool(PUBLIC_WORD.search(name))


def secret_name(name):
    # A name that calls for a service credential: token/password/credential/bearer/secret/private/
    # api-key/auth-key, or a name ending in key. A pub/public name is never one.
    low = name.lower()
    if not name or 'pub' in words(name) or 'public' in low or 'pubkey' in low:
        return False
    return bool(B2_WORD.search(name)) or bool(re.search(r'keys?(?:_?hex)?$', low.replace('-', '_')))


def root_name(name):
    # A bare 'root' name (root, ROOT, walletRoot, WALLET_ROOT, wallet_root): the wallet's master
    # key in BRC-100, not a hash root. False when a hash word qualifies it (merkle_root, tx_root).
    w = words(name)
    if 'root' not in w:
        return False
    idx = w.index('root')
    return not (idx > 0 and w[idx - 1] in ROOT_QUAL)


def credential(rest):
    # The value after an assignment or header is a real credential only if it is one unbroken token
    # of 20 or more credential characters (no whitespace): not a placeholder, an environment
    # reference, a plain word, a path, a URL, a public key, a 64/66-hex value (the key rule judges
    # those), nor a hash digest of a standard length.
    rest = rest.lstrip()
    if not rest:
        return False
    if rest[0] in '"\'`':
        end = rest.find(rest[0], 1)
        v = rest[1:end] if end > 1 else rest[1:]
    else:
        m = re.match(r'[A-Za-z0-9._+/~=-]+', rest)
        v = m.group(0) if m else ''
    if len(v) < 20 or re.search(r'\s', v) or not re.fullmatch(r'[A-Za-z0-9._+/~=-]+', v):
        return False
    low = v.lower()
    if PLACEHOLDER.search(v) or 'process.env' in low or 'os.environ' in v or 'import.meta' in low or 'secrets.' in low:
        return False
    if v[0] in '/~.' or v[:2] == '\\\\':                       # a path
        return False
    if re.fullmatch(r'[A-Za-z][A-Za-z._/-]*', v):              # a plain word, kebab or dotted name (no digit)
        return False
    if '/' in v and not re.fullmatch(r'[A-Za-z0-9+/]{40,}={0,2}', v):   # a path or object key (not base64)
        return False
    if re.fullmatch(r'0[234][0-9a-fA-F]{64}|04[0-9a-fA-F]{128}', v):   # a public key
        return False
    if re.fullmatch(r'(?:0[xX])?[0-9a-fA-F]{64}|[0-9a-fA-F]{66}', v):  # the key rule owns 64/66-hex
        return False
    if re.match(r'(?i)(?:mainnet|testnet)_', v) and re.search(r'\d', v):
        return True
    if re.fullmatch(r'[0-9a-fA-F]+', v):                       # pure hex: a credential unless a hash length
        return len(v) not in (40, 56, 64, 96, 128)
    if len(set(v)) >= 16:
        return True
    return bool(re.search(r'[A-Za-z]', v) and re.search(r'\d', v))


CFG_SUFFIX = ('.sh', '.bash', '.zsh', '.env', '.toml', '.yaml', '.yml', '.json', '.ini', '.cfg',
              '.conf', '.properties', '.mk', '.npmrc', '.dev.vars')


def config_file(path):
    base = path.rsplit('/', 1)[-1]
    return path.endswith(CFG_SUFFIX) or path.endswith(PROSE) or '.env' in base or 'wrangler' in base \
        or base in ('Dockerfile', 'Makefile', '.dev.vars') or '.dev.vars' in base


def named_secret(path, line):
    # A credential assigned to, exported as, or sent under a secret-like name, or piped to a
    # `wrangler secret put`. An unquoted value counts only in a config, shell, env or doc file
    # (where bare credentials live); in code a bare right-hand side is an expression, not a secret.
    # Not in compiled source, where such names are identifiers, not pasted secrets.
    if path.endswith(COMPILED):
        return None
    cfg = config_file(path)
    for m in OPENER.finditer(line):
        if not secret_name(m.group(1)):
            continue
        rest = line[m.end():].lstrip()
        if (rest[:1] in ('"', "'", '`') or cfg) and credential(rest):
            return 'a service token or secret under a secret-like name'
    mp = re.search(r'(?i)\bsecret\s+put\b', line)
    if mp:
        head = line[:mp.start()]   # the echoed/piped value sits before `secret put`, not the name after it
        for m in re.finditer(r'[A-Za-z0-9_./+=~-]{20,}', head):
            if m.start() and head[m.start() - 1] == '<':   # a <placeholder>
                continue
            if credential(m.group(0)):
                return 'a secret on a wrangler secret put line'
    return None


def array_key(path, lines, i):
    # A key-like or sk name assigned an array/tuple literal: its name and the joined text between
    # the outer brackets, so a byte key spread over many lines (after rustfmt) reads as one.
    text = code(lines[i], path)
    m = re.search(r'''(?<![\w$.-])([A-Za-z_$][\w$.-]*)\s*(?::[^=\n]*?)?=\s*(?:&\s*)?\[''', text)
    if not m or not (key_like(m.group(1)) or 'sk' in words(m.group(1))):
        return None
    depth, buf, j, col = 0, [], i, m.end() - 1
    while j < len(lines) and j - i <= 64:
        s = code(lines[j], path)
        k = col if j == i else 0
        while k < len(s):
            c = s[k]
            if c == '[':
                depth += 1
                if depth > 1:
                    buf.append(c)
            elif c == ']':
                depth -= 1
                if depth == 0:
                    return m.group(1), ''.join(buf)
                buf.append(c)
            elif depth >= 1:
                buf.append(c)
            k += 1
        if depth >= 1:
            buf.append(' ')
        j += 1
    return None


def judge_array(name, inner):
    # Under a key-like/sk array: 32 one-byte values (hex 0x.. or decimal 0-255) or hex in pieces.
    elems = re.findall(r'0[xX][0-9a-fA-F]{1,2}|(?<![0-9a-fA-FxX.])\d{1,3}(?![0-9a-fA-F.])', inner)
    vals = [e for e in elems if e[:2].lower() == '0x' or e.isdigit() and int(e) <= 255]
    if len(elems) == 32 and len(vals) == 32:
        return 'a 32-byte key array under a key-like name'
    joined = SPLIT.sub('', inner)
    for m in re.finditer(r'(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])', joined):
        if len(set(m.group(0).lower())) >= 8 and m.group(0) not in inner:
            return 'a 64-hex value in pieces under a key-like name'
    return None


def row_delim(path, line):
    # The delimiter of a tabular row: a CSV/TSV file by name, or a markdown pipe row.
    if path.endswith('.csv'):
        return ','
    if path.endswith(('.tsv', '.tab')):
        return '\t'
    if line.lstrip().startswith('|') and line.count('|') >= 2:
        return '|'
    return None


def header_cell(path, lines, i, delim, pos):
    # The header text naming the column of the value at character `pos` of row i.
    if delim == '|':
        idx = lines[i][:pos].count('|') - 1
        hdr, j = None, i
        while j >= 0 and lines[j].lstrip().startswith('|'):
            if re.fullmatch(r'\s*\|?[\s:|-]*-[\s:|-]*\|?\s*', lines[j]):
                hdr = lines[j - 1] if j > 0 else None
                break
            j -= 1
        if hdr is None:
            hdr = next((r for r in lines[:i + 1] if r.lstrip().startswith('|')), None)
        cells = [c.strip(' `*') for c in hdr.strip().strip('|').split('|')] if hdr else []
    else:
        idx = lines[i][:pos].count(delim)
        header = next((r for r in lines if r.strip()), None)
        cells = [c.strip(' `*"\'') for c in header.split(delim)] if header else []
    return cells[idx] if 0 <= idx < len(cells) else None


def code(line, path):
    # The line without a trailing comment (a markdown or text file is prose: all of it counts).
    text = line if path.endswith(PROSE) else COMMENT.sub('', line)
    return PUBKEY_PHRASE.sub(lambda m: m.group(1) + m.group(2), text)


def key_names(text):
    return [n for n in IDENT.findall(text) if key_like(n)]


def assigned_name(prefix):
    # The name a value is assigned to, or the key of its field: the identifier before the
    # nearest assignment that only call or quote punctuation separates from the value.
    for op in re.finditer(ASSIGN + '(?=' + GLUE + '$)', prefix):
        lhs = prefix[:op.start()]
        if op.group(0) == '=':
            typed = TYPED.search(lhs)
            if typed and ':' in lhs[typed.start():]:
                return typed.group(1)
        found = re.search(r'''(?<![\w$.-])([A-Za-z_$][\w$.-]*)["'`]?\s*\]?\s*$''', lhs)
        return found.group(1).split('.')[-1] if found else None
    return None


def nearest_name(prefix):
    # A value with no assignment: the last identifier before it that is not a call or a path.
    names = [m for m in IDENT.finditer(prefix) if not re.match(r'\s*(?:!?\(|\.|::|<)', prefix[m.end():])]
    return names[-1].group(0) if names else None


def is_list_line(line):
    return bool(LIST_REST.match(STRIP.sub('', line)))


def rust_test_lines(lines):
    # The lines of real #[cfg(test)] items, by brace depth outside strings, chars and comments.
    held, i = set(), 0
    while i < len(lines):
        if not CFG_TEST.match(lines[i]):
            i += 1
            continue
        depth, opened, j, in_block = 0, False, i, False
        while j < len(lines):
            held.add(j)
            k, s = 0, lines[j]
            if j == i:
                k = s.index(']') + 1
            in_str = False
            while k < len(s):
                c = s[k]
                if in_block:
                    if s.startswith('*/', k):
                        in_block, k = False, k + 1
                elif in_str:
                    if c == '\\':
                        k += 1
                    elif c == '"':
                        in_str = False
                elif s.startswith('//', k):
                    break
                elif s.startswith('/*', k):
                    in_block = True
                elif c == '"':
                    in_str = True
                elif c == "'" and re.match(r"'(?:\\.|[^\\'])'", s[k:]):
                    k += len(re.match(r"'(?:\\.|[^\\'])'", s[k:]).group(0)) - 1
                elif c == '{':
                    depth, opened = depth + 1, True
                elif c == '}':
                    depth -= 1
                elif c == ';' and not opened and depth == 0:
                    opened = None
                    break
                k += 1
            if opened is None or opened and depth <= 0:
                break
            j += 1
        i = j + 1
    return held


def held_lines(path, lines):
    # None: the whole file is a door; else the set of lines held (real test items of a door).
    if any(path == d or d.endswith('/') and path.startswith(d) for d in DOORS):
        return None
    if path + '#cfg(test)' in DOORS:
        return rust_test_lines(lines)
    return set()


def token_findings(path, lines, judged):
    found = []
    for i, line in enumerate(lines):
        if not judged(i):
            continue
        matched = False
        for kind, shape in TOKEN_SHAPES:
            for m in shape.finditer(line):
                if kind == 'an AWS access key id' and AWS_EXAMPLE == 'yes' and m.group(0).endswith('EXAMPLE'):
                    continue
                if kind == 'a PEM private-key block' and path in NOTPEM.split() and 'notpem' in line:
                    continue
                found.append((i + 1, kind))
                matched = True
                break
            if matched:
                break
        if not matched:
            hit = named_secret(path, line)
            if hit:
                found.append((i + 1, hit))
    for i in range(len(lines) - 1):
        if not lines[i].rstrip().endswith('\\') or not (judged(i) or judged(i + 1)):
            continue
        joined = lines[i].rstrip()[:-1] + lines[i + 1].lstrip()
        for text in (joined, re.sub(r'''(["'])\s*\1''', '', joined)):
            hits = [k for k, s in TOKEN_SHAPES if s.search(text) and not s.search(lines[i]) and not s.search(lines[i + 1])]
            if hits:
                found.append((i + 1, hits[0] + ' run on by a line continuation'))
                break
    return found


def key_findings(path, lines, judged):
    found = []
    OPENERS.clear()
    held = held_lines(path, lines)
    if held is None:
        return found
    for i, line in enumerate(lines):
        if not judged(i) or i in held:
            continue
        for kind, shape in B58_SHAPES:
            if any(re.search(r'[^0-9a-fA-F]', m.group(0)) for m in shape.finditer(line)):
                found.append((i + 1, kind))
        text = code(line, path)
        before = code(lines[i - 1], path) if i else ''
        ak = array_key(path, lines, i)
        if ak:
            enc = judge_array(*ak)
            if enc:
                found.append((i + 1, enc))
        hit = judge_hex(path, lines, i, line, text, before)
        if not hit:
            hit = judge_encoded(text, before, lines[i + 1] if i + 1 < len(lines) else '')
        if hit:
            found.append((i + 1, hit))
    return found


def candidates(line):
    for m in HEXRUN.finditer(line):
        digits = m.group(1)
        if len(digits) == 66:
            low = digits.lower()
            if low[:2] in ('02', '03') or not (low.endswith('01') or low.startswith('00')):
                continue
            core = digits[2:] if low.startswith('00') else digits[:64]
        else:
            core = digits
        if len(set(core.lower())) >= 8:
            yield m


def opener(path, lines, i):
    # For a value alone on its line: the line that opens its list, past items, blanks and comments.
    j = i - 1
    while j >= 0:
        if j in OPENERS:
            j = OPENERS[j]
            break
        text = code(lines[j], path)
        if text.strip() and not (len(text) <= WINDOW * 2 and is_list_line(text)):
            break
        j -= 1
    OPENERS[i] = j
    return [lines[j], lines[j - 1] if j > 0 else ''] if j >= 0 else []


def judge_hex(path, lines, i, line, text, before):
    whole = len(line) <= WINDOW * 2
    lone = whole and bool(text.strip()) and is_list_line(text)
    line_keys = whole and bool(key_names(text))
    context = None
    for m in candidates(line):
        start = m.start()
        if line[max(0, start - 2):start] in ('\\n', '\\r', '\\t', '\\x'):
            start -= 2
        # A long line (minified or one-line data) is read as the statement around the value.
        prefix, rest = line[max(0, m.start() - WINDOW):m.start()], line[m.end():m.end() + WINDOW]
        near = text if whole else code(prefix + m.group(0) + rest, path)
        url = re.search(r'://\S*$|[?&][A-Za-z_][\w.-]*=$', prefix)
        quoted = start > 0 and line[start - 1] in '"\'`' and rest[:1] == line[start - 1]
        assigned = bool(re.search(r'[:=]\s*$', prefix))
        argument = bool(re.search(r'[(,]\s*$', prefix) and re.match(r'\s*[),]', rest))
        own = assigned_name(prefix)
        delim = row_delim(path, line)
        if own is None and delim:
            own = header_cell(path, lines, i, delim, start)
        if own is None and not lone:
            own = nearest_name(prefix[:len(prefix) - (m.start() - start)])
        prose = path.endswith(PROSE) or whole and len(text.rstrip()) <= m.start()
        if own is None and not lone and i and prose and not IDENT.search(prefix[:len(prefix) - (m.start() - start)]):
            own = nearest_name(lines[i - 1][-WINDOW:] + ' ')
        continued = None
        if own is None:
            dangling = re.search(r'''(?<![\w$.-])([A-Za-z_$][\w$.-]*)["'`]?\s*''' + ASSIGN + r'''\s*[\[({]?\s*\\?\s*$''', before)
            continued = dangling.group(1) if dangling else None
        if lone and context is None:
            context = opener(path, lines, i)
        context = context or []
        if url:
            if own and key_like(own):
                return 'a 64-hex value under a key-like name'
            continue
        if (own and key_like(own)) or (not public_name(own) and (line_keys if whole else key_names(near))) \
                or (own is None and key_names(before)) or any(key_names(code(c, path)) for c in context):
            return 'a 64-hex value under a key-like name'
        if own and root_name(own) and not path.endswith(COMPILED) \
                and not (HEIGHT.search(near) or HEIGHT.search(before) or any(HEIGHT.search(c) for c in context)):
            return 'a 64-hex value under a bare root name (not a hash root)'
        if not (quoted or assigned or argument or lone):
            continue
        if public_name(own) or public_name(continued):
            continue
        if own is None and any(PUBLIC_WORD.search(c) for c in context):
            continue
        return 'a private-key-shaped literal with no name that says hash or id'
    return None


def judge_encoded(text, before, after):
    # Under a key-like name: 32 bytes in base64 or base58, hex in pieces, a byte array, a mnemonic.
    phrase = re.compile(r'(?i)mnemonic|seed|phrase')
    spots = [(m.group(1), text[m.end():m.end() + WINDOW]) for m in OPENER.finditer(text) if key_like(m.group(1)) or phrase.search(m.group(1))]
    dangling = re.search(r'''(?<![\w$.-])([A-Za-z_$][\w$.-]*)["'`]?\s*''' + ASSIGN + r'''\s*[\[({]?\s*\\?\s*$''', before)
    if dangling and (key_like(dangling.group(1)) or phrase.search(dangling.group(1))) and not OPENER.search(text):
        spots.append((dangling.group(1), text))
    for name, value in spots:
        if phrase.search(name):
            m = MNEMONIC.match(value if value.strip() else after)
            if m and len(m.group(1).split()) in (12, 15, 18, 21, 24):
                return 'a mnemonic under a key-like name'
        if not key_like(name):
            continue
        enc = BASE_32.match(re.sub(r'^[^"\'`]*', '', value, count=1))
        if enc and all(re.search(c, enc.group(1)) for c in ('[0-9]', '[A-Z]', '[a-z]')):
            return 'a 32-byte base64 or base58 value under a key-like name'
        joined = SPLIT.sub('', value)
        for m in re.finditer(r'(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])', joined):
            if len(set(m.group(0).lower())) >= 8 and m.group(0) not in value:
                return 'a 64-hex value in pieces under a key-like name'
    return None


def decode(data):
    if data[:2] in (b'\xff\xfe', b'\xfe\xff'):
        return data.decode('utf-16', errors='replace')
    head = data[:8000]
    if b'\0' in head and len(head) > 3:
        for codec, zeros in (('utf-16-le', head[1::2]), ('utf-16-be', head[0::2])):
            if zeros.count(0) * 4 >= len(zeros) * 3:
                return data.decode(codec, errors='replace')
        data = data.replace(b'\0', b'')
    return data.decode('utf-8', errors='replace')


def judge(label, path, lines, only=None):
    judged = (lambda i: True) if only is None else (lambda i: i + 1 in only)
    return [(label, n, k) for n, k in sorted(set(token_findings(path, lines, judged) + key_findings(path, lines, judged)))]


def git(*args):
    return subprocess.check_output(['git', '-c', 'core.quotePath=false', '-c', 'diff.noprefix=false',
                                    '-c', 'diff.mnemonicPrefix=false', '-c', 'color.diff=never', *args])


def unquote(path):
    if path.startswith('"') and path.endswith('"'):
        return path[1:-1].encode('latin-1', 'backslashreplace').decode('unicode_escape').encode('latin-1').decode('utf-8', 'replace')
    return path


def added_lines(patch):
    # {path: {new line number}} of the added lines of a --text --unified=0 patch. The file of each
    # section is taken from its '+++ ' header (a trailing TAB, which git appends to a name with a
    # space, is stripped; a quoted name is unquoted), only while reading the header; inside a hunk
    # the added lines are counted from the '@@' numbers, so an added line that itself begins '++ '
    # (which would read as a '+++ ' header) or '-' is never mistaken for one.
    added, path, number = {}, None, 0
    pending = removing = 0
    in_hunk = False
    for line in patch.decode('utf-8', errors='replace').split('\n'):
        if line.startswith('diff --git '):
            path, in_hunk = None, False
            continue
        if not in_hunk:
            if line.startswith('+++ '):
                name = line[4:]
                if name.endswith('\t'):
                    name = name[:-1]
                name = unquote(name)
                path = name[2:] if name.startswith('b/') else None
                continue
            if not line.startswith('@@'):
                continue
            in_hunk = True
        if line.startswith('@@'):
            m = re.search(r'@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', line)
            removing = int(m.group(1)) if m and m.group(1) is not None else (0 if m else removing)
            number = int(m.group(2)) if m else number
            pending = (int(m.group(3)) if m.group(3) is not None else 1) if m else pending
            continue
        if removing > 0 and line.startswith('-'):
            removing -= 1
            continue
        if pending > 0 and line.startswith('+'):
            if path is not None:
                added.setdefault(path, set()).add(number)
            number += 1
            pending -= 1
    return added


def judge_patch(label, patch, read):
    # Only new text can leak: a removed line is already on the base. Each added line is judged in
    # its file at that side, read whole from the object store. A path or a blob that cannot be read
    # is not skipped: it ends the scan as a failure, naming the path and the commit, so no added
    # line goes unread (a name with a space, a non-UTF-8 name, a vanished object all fail closed).
    out = []
    for path, numbers in added_lines(patch).items():
        try:
            data = read(path)
        except (subprocess.CalledProcessError, OSError):
            print(f'{label} {path}: a changed path could not be read; nothing is passed')
            sys.exit(1)
        out += judge(f'{label} {path}', path, decode(data).splitlines(), numbers)
    return out


def worktree(path):
    with open(path, 'rb') as source:
        return source.read()


def release_range():
    # (the commits since the previous release tag, which tag), or every commit from the root when
    # no release tag is an ancestor of HEAD. Any error and any empty range end the scan as a failure.
    def closed(why):
        print(f'keys and tokens: the tag range cannot be read ({why}); nothing is passed')
        sys.exit(1)
    if git('rev-parse', '--is-shallow-repository').decode().strip() != 'false':
        closed('a shallow clone')
    head = git('rev-parse', '--verify', 'HEAD^{commit}').decode().strip()
    best = None
    # A release tag is a version: a RELEASE_TAGS prefix (the trailing * dropped, e.g. 'v' or
    # 'core-v') followed by <digits>.<digits>.<digits> and an optional pre-release/build suffix. A
    # tag that merely starts with the prefix but is not a version (vendor-snapshot) does not count,
    # so it never shortens a release's range; a pre-release (v1.2.3-rc1) is a version and does.
    prefixes = [p[:-1] if p.endswith('*') else p for p in RELEASE_TAGS.split()]
    semver = re.compile(r'(?:%s)\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$' % '|'.join(re.escape(p) for p in prefixes)) if prefixes else None
    all_names = git('tag', '--merged', head).decode().split() if prefixes else []
    names = [n for n in all_names if semver.match(n)]
    for name in sorted(names):
        commit = git('rev-parse', '--verify', f'refs/tags/{name}^{{commit}}').decode().strip()
        if commit == head:
            continue
        count = int(git('rev-list', '--count', f'{commit}..{head}').decode())
        if best is None or count < best[0]:
            best = (count, name, commit)
    if best is None:
        commits, since = git('rev-list', head).decode().split(), 'from the root (no earlier release tag)'
    else:
        commits, since = git('rev-list', f'{best[2]}..{head}').decode().split(), f'since {best[1]}'
    if not commits:
        closed('an empty range')
    return commits, since


findings = []
for path in filter(None, git('ls-files', '-z').decode('utf-8', 'replace').split('\0')):
    if os.path.islink(path):
        findings += judge(path, path, [os.readlink(path)])
    elif os.path.isfile(path):
        findings += judge(path, path, decode(worktree(path)).splitlines())
scope = 'tracked tree'
if MODE:
    # A shallow clone cannot answer for the range it hides: it fails in every range mode, not only
    # on a tag. CI fetches the whole history (fetch-depth: 0) in every scan job.
    if git('rev-parse', '--is-shallow-repository').decode().strip() != 'false':
        print('keys and tokens: a shallow clone cannot be read; nothing is passed')
        sys.exit(1)
    if MODE == '--all':
        commits = git('rev-list', 'HEAD').decode().split()
    elif MODE == '--tag':
        commits, since = release_range()
    else:
        git('rev-parse', '--verify', '--quiet', MODE + '^{commit}')
        commits = git('rev-list', f'{MODE}..HEAD').decode().split()
    for commit in commits:
        patch = git('show', '--format=', '-p', '--text', '--diff-merges=first-parent', '--no-ext-diff',
                    '--no-textconv', '--unified=0', commit)
        findings += judge_patch(f'commit {commit[:12]}', patch,
                                lambda p, c=commit: git('cat-file', 'blob', f'{c}:{p}'))
    if MODE not in ('--all', '--tag'):
        findings += judge_patch('branch diff', git('diff', '--no-ext-diff', '--text', '--no-textconv', '--unified=0', f'{MODE}...HEAD'),
                                lambda p: git('cat-file', 'blob', f'HEAD:{p}'))
    findings += judge_patch('working diff', git('diff', '--no-ext-diff', '--text', '--no-textconv', '--unified=0', 'HEAD'), worktree)
    scope = f'tracked tree and the added lines of {len(commits)} commits' + (f' {since}' if MODE == '--tag' else '')
for label, number, kind in findings:
    print(f'{label}:{number}: {kind}')
if findings:
    print(REMEDY)
    sys.exit(1)
print(f'keys and tokens: {scope} clean')
PY
if H=$(python3 -c "$KEYSCAN" "$MODE" "$KEY_DOOR" "$AWS_EXAMPLE" "$NOTPEM" "$RELEASE_TAGS" 2>&1); then echo "$H"; else hit "a key or a token" "$H"; fi

if [ "$FAIL" = 0 ]; then echo "scrub: clean"; exit 0; fi
echo "scrub: FAILED"; exit 2
