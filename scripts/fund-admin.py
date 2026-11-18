#!/usr/bin/env python3
"""
Fund the admin wallet on wallet-infra.x402agency.com from a BRC-100 wallet
running on localhost:3322. Uses confirmed UTXOs so spendable=1 immediately.

Flow per BRC-29:
  1. Ask 3322's /createAction to build a tx with an output paying admin's
     BRC-42-derived address. Derivation: protocolID=[2,"3241645161d8"],
     keyID="<base64 prefix> <base64 suffix>", counterparty=<admin pubkey>.
     3322 derives the corresponding sender-side pubkey internally via
     BRC-42, locks the output as P2PKH to it, signs, and returns the
     AtomicBEEF.
  2. POST wallet-infra.x402agency.com/internalizeAction as the admin
     (BRC-31 auth with admin privkey). Payload:
       { tx: <atomic beef bytes>,
         outputs: [{
            outputIndex: 0,
            protocol: "wallet payment",
            paymentRemittance: {
              derivationPrefix, derivationSuffix,
              senderIdentityKey: <3322 pubkey>
         } }],
         description: "fund-admin helper",
         labels: []
       }
  3. Wallet-infra inserts the UTXO into admin's default basket with
     spendable=1 (matches its internalize_action logic for wallet-payment
     outputs from already-broadcast txs).

Usage:
    ADMIN_WALLET_PRIVATE_KEY_FILE=<file> python3 scripts/fund-admin.py <satoshis>
    # defaults to 5000 sats if omitted.

The admin key comes from a file: ADMIN_WALLET_PRIVATE_KEY_FILE is the path
of a file that holds its 64 hex
digits (whitespace around them is ignored). Set it in place for the one
command, as above, so the key is in neither the tree, the shell's history nor
the shell's environment afterwards. ADMIN_WALLET_PRIVATE_KEY (the digits
themselves) is still read when it is set, but only from a file inside the
command, never typed:
    ADMIN_WALLET_PRIVATE_KEY="$(cat <file>)" python3 scripts/fund-admin.py <satoshis>
Both variables are removed from this process's environment as soon as they
are read, so no child process (openssl, the auth helper) inherits them; the
auth helper alone is handed the key, as below. A missing or malformed key is
refused by the variable's name; its value is never printed. The admin's
public key is derived from it.

The BRC-31 auth comes from the sibling x402 skill's helpers: we run its
brc31_helpers.py from X402_SKILL_DIR (default: the plugin cache's
~/.claude/plugins/cache/calgooon-x402/x402/09b016215354/skills/x402), with the
admin key handed to it in its environment as PARITY_IDENTITY_KEY.
"""
from __future__ import annotations

import base64
import json
import os
import re
import secrets
import subprocess
import sys
import urllib.parse
import urllib.request

# secp256k1: the curve's prime, order and generator (SEC 2, section 2.4.1).
_P = 2**256 - 2**32 - 977
_N = 2**256 - 0x14551231950B75FC4402DA1732FC9BEBF
_G = (
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424,
)


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % _P == 0:
        return None
    if a == b:
        m = 3 * a[0] * a[0] * pow(2 * a[1], -1, _P) % _P
    else:
        m = (b[1] - a[1]) * pow(b[0] - a[0], -1, _P) % _P
    x = (m * m - a[0] - b[0]) % _P
    return x, (m * (a[0] - x) - a[1]) % _P


def compressed_public_key_hex(private_key_hex: str) -> str:
    """The compressed SEC1 public key (33 bytes, hex) of a secp256k1 scalar."""
    d, point, result = int(private_key_hex, 16), _G, None
    while d:
        if d & 1:
            result = _add(result, point)
        point, d = _add(point, point), d >> 1
    return ("03" if result[1] & 1 else "02") + format(result[0], "064x")


def load_admin_private_key() -> str:
    """The admin key from ADMIN_WALLET_PRIVATE_KEY or the file named by
    ADMIN_WALLET_PRIVATE_KEY_FILE. Every refusal names the variable and
    never the value."""
    # Popped, not read: no child process this script starts inherits either.
    inline = os.environ.pop("ADMIN_WALLET_PRIVATE_KEY", None)
    named = os.environ.pop("ADMIN_WALLET_PRIVATE_KEY_FILE", None)
    if inline and named:
        sys.exit("fund-admin: set ADMIN_WALLET_PRIVATE_KEY or "
                 "ADMIN_WALLET_PRIVATE_KEY_FILE, not both")
    if named:
        source = "the file named by ADMIN_WALLET_PRIVATE_KEY_FILE"
        try:
            with open(os.path.expanduser(named), encoding="ascii") as f:
                value = f.read().strip()
        except (OSError, UnicodeDecodeError):
            sys.exit(f"fund-admin: {source} cannot be read")
    elif inline:
        source = "ADMIN_WALLET_PRIVATE_KEY"
        value = inline.strip()
    else:
        sys.exit("fund-admin: no admin key: set ADMIN_WALLET_PRIVATE_KEY "
                 "or ADMIN_WALLET_PRIVATE_KEY_FILE (see the docstring)")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value) or not 0 < int(value, 16) < _N:
        sys.exit(f"fund-admin: {source} is not a private key "
                 "(64 hex digits, a scalar below the curve order)")
    return value.lower()


ADMIN_PRIVKEY_HEX = load_admin_private_key()
ADMIN_PUBKEY_HEX = compressed_public_key_hex(ADMIN_PRIVKEY_HEX)
WALLET_INFRA_URL = "https://wallet-infra.x402agency.com"
LOCAL_WALLET_URL = "http://localhost:3322"
LOCAL_ADMIN_ORIGIN = "http://admin.com"  # bypasses admin-only basket restriction


def random_base64_nonce(n_bytes: int = 16) -> str:
    """Match wallet-toolbox's `createNonce` convention: random bytes, base64."""
    return base64.b64encode(secrets.token_bytes(n_bytes)).decode("ascii")


def http_post(url: str, body: dict, headers: dict) -> tuple[int, dict]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={**headers, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8") or "{}")


def local_wallet_create_action(satoshis: int) -> dict:
    """Ask 3322 to build a BRC-29 payment output to the admin. 3322 handles
    BRC-42 derivation internally given the counterparty + keyID."""
    derivation_prefix = random_base64_nonce()
    derivation_suffix = random_base64_nonce()
    key_id = f"{derivation_prefix} {derivation_suffix}"

    # First: derive the admin-facing receive pubkey on 3322 side.
    # 3322's getPublicKey lets us derive a pubkey for a given
    # (protocol, keyID, counterparty) — we ask for the locker pubkey
    # as seen by the SENDER (that's us, 3322).
    status, body = http_post(
        f"{LOCAL_WALLET_URL}/getPublicKey",
        {
            "protocolID": [2, "3241645161d8"],
            "keyID": key_id,
            "counterparty": ADMIN_PUBKEY_HEX,
            "forSelf": False,
        },
        headers={"Origin": LOCAL_ADMIN_ORIGIN},
    )
    if status != 200:
        raise RuntimeError(
            f"3322 getPublicKey failed: HTTP {status} body={body}"
        )
    derived_pubkey_hex = body["publicKey"]

    # Build a standard P2PKH lock for the derived pubkey. BRC-29 receivers
    # expect the sender's createAction to construct this locking script
    # from the derived pubkey's hash160.
    #
    # We don't have hash160 in stdlib, so we use openssl + ripemd via shell.
    sha256_hash = subprocess.check_output(
        ["openssl", "dgst", "-sha256", "-binary"],
        input=bytes.fromhex(derived_pubkey_hex),
    )
    hash160 = subprocess.check_output(
        ["openssl", "dgst", "-ripemd160", "-binary"],
        input=sha256_hash,
    )
    if len(hash160) != 20:
        raise RuntimeError(f"hash160 wrong length: {len(hash160)}")

    locking_script_hex = (
        "76a914" + hash160.hex() + "88ac"
    )  # OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG

    # createAction on 3322 — it will fund, sign, and broadcast the tx.
    status, body = http_post(
        f"{LOCAL_WALLET_URL}/createAction",
        {
            "description": "fund admin wallet on wallet-infra",
            "outputs": [
                {
                    "lockingScript": locking_script_hex,
                    "satoshis": satoshis,
                    "outputDescription": "BRC-29 payment to admin",
                }
            ],
        },
        headers={"Origin": LOCAL_ADMIN_ORIGIN},
    )
    if status != 200:
        raise RuntimeError(
            f"3322 createAction failed: HTTP {status} body={body}"
        )

    return {
        "txid": body["txid"],
        "atomic_beef": body["tx"],  # array of byte values
        "derivation_prefix": derivation_prefix,
        "derivation_suffix": derivation_suffix,
        "sender_pubkey": body.get("_senderIdentityKey"),
    }


def internalize_as_admin(
    atomic_beef: list[int],
    derivation_prefix: str,
    derivation_suffix: str,
    sender_pubkey: str,
) -> dict:
    """POST to wallet-infra's internalizeAction as admin, via the x402 skill
    helper (which handles BRC-31 auth against any server)."""

    # Point the brc31_helpers script at wallet-infra using the admin privkey
    # as PARITY_IDENTITY_KEY (its environment, never its argv). We invoke the
    # skill's CLI as a subprocess.
    skill_dir = os.path.expanduser(os.environ.get(
        "X402_SKILL_DIR",
        "~/.claude/plugins/cache/calgooon-x402/x402/09b016215354/skills/x402",
    ))
    env = os.environ.copy()  # holds neither ADMIN_WALLET_PRIVATE_KEY variable (popped at load)
    env["PARITY_IDENTITY_KEY"] = ADMIN_PRIVKEY_HEX
    # The skill's auth path is /.well-known/auth + JSON-RPC `POST /`.
    # wallet-infra uses positional params: [authObj, args].
    args = {
        "tx": atomic_beef,
        "outputs": [
            {
                "outputIndex": 0,
                "protocol": "wallet payment",
                "paymentRemittance": {
                    "derivationPrefix": derivation_prefix,
                    "derivationSuffix": derivation_suffix,
                    "senderIdentityKey": sender_pubkey,
                },
            }
        ],
        "description": "fund-admin helper",
        "labels": ["fund-admin"],
    }
    rpc_body = {
        "jsonrpc": "2.0",
        "method": "internalizeAction",
        "params": [{}, args],
        "id": 1,
    }

    # Use the skill's auth helper to sign the RPC call.
    cmd = [
        "python3",
        f"{skill_dir}/scripts/brc31_helpers.py",
        "auth",
        "POST",
        f"{WALLET_INFRA_URL}/",
        json.dumps(rpc_body),
    ]
    out = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=60)
    return {"stdout": out.stdout, "stderr": out.stderr, "returncode": out.returncode}


def main() -> int:
    satoshis = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    if satoshis < 1000 or satoshis > 20000:
        print(f"sats {satoshis} outside safety range [1000, 20000]", file=sys.stderr)
        return 1

    # Sanity
    status, body = http_post(
        f"{LOCAL_WALLET_URL}/getPublicKey",
        {"identityKey": True},
        {"Origin": LOCAL_ADMIN_ORIGIN},
    )
    if status != 200:
        print(f"localhost:3322 not responding: HTTP {status}", file=sys.stderr)
        return 1
    sender_pubkey = body["publicKey"]
    print(f"sender (3322) identity: {sender_pubkey}")
    print(f"admin (receiver) identity: {ADMIN_PUBKEY_HEX}")
    print(f"requesting {satoshis} sats…")

    created = local_wallet_create_action(satoshis)
    created["sender_pubkey"] = sender_pubkey  # not always set on 3322 response
    print(f"3322 broadcast tx {created['txid']} (atomic-BEEF {len(created['atomic_beef'])} bytes)")

    print("calling wallet-infra internalizeAction as admin…")
    result = internalize_as_admin(
        atomic_beef=created["atomic_beef"],
        derivation_prefix=created["derivation_prefix"],
        derivation_suffix=created["derivation_suffix"],
        sender_pubkey=sender_pubkey,
    )
    print("internalizeAction stdout:")
    print(result["stdout"])
    if result["stderr"].strip():
        print("stderr:", result["stderr"], file=sys.stderr)
    print(f"returncode: {result['returncode']}")
    return result["returncode"]


if __name__ == "__main__":
    sys.exit(main())
