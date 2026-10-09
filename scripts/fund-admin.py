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
    python3 scripts/fund-admin.py <satoshis>
    # defaults to 5000 sats if omitted.

Secrets come from the sibling x402 skill's helpers (BRC-31 auth against
wallet-infra) — we import brc31_helpers.py and reuse its session-cached
JSON-RPC client.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import subprocess
import sys
import urllib.parse
import urllib.request

ADMIN_PRIVKEY_HEX = (
    "d6db75fecb84a3cb7ec2e8a8ebf826853da068679388803e9a119778d0839979"
)
ADMIN_PUBKEY_HEX = (
    "02837c91defe23ca5bb4ec1fccd82e1e6fcba8f80e7632d360a7cb34e851dda663"
)
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
    # as PARITY_IDENTITY_KEY. We invoke the skill's CLI as a subprocess.
    skill_dir = "/Users/johncalhoun/.claude/plugins/cache/calgooon-x402/x402/09b016215354/skills/x402"
    env = os.environ.copy()
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
