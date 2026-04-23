// validate-transcripts.mjs — runs each transcripts/*.json fixture through the
// same logic UHRPTopicManager.identifyAdmissibleOutputs uses, and verifies the
// `expected_admit` label we produced matches what the TS SDK actually returns.
//
// If a label is wrong, regenerate will flag it here before Rust tests ever run.

import {
  LockingScript,
  PushDrop,
  ProtoWallet,
  Utils,
  PublicKey,
} from '@bsv/sdk';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const TRANSCRIPTS = join(HERE, '..', 'fixtures', 'parity', 'transcripts');

// Ported verbatim from ~/bsv/uhrp-services/backend/src/topic-managers/isTokenSignatureCorrectlyLinked.ts
async function isTokenSignatureCorrectlyLinked(lockingPublicKey, fields) {
  const signature = fields.pop();
  const protocolID = [2, 'uhrp advertisement'];
  const identityKey = Utils.toHex(fields[0]);
  const data = fields.reduce((a, e) => [...a, ...e], []);
  const anyoneWallet = new ProtoWallet('anyone');
  try {
    const { valid } = await anyoneWallet.verifySignature({
      data, signature, counterparty: identityKey, protocolID, keyID: '1',
    });
    if (!valid) return false;
  } catch (e) { return false; }
  const { publicKey: expected } = await anyoneWallet.getPublicKey({
    counterparty: identityKey, protocolID, keyID: '1',
  });
  return expected === lockingPublicKey.toString();
}

// Ported from UHRPTopicManager.identifyAdmissibleOutputs but operating on a
// single locking script rather than a BEEF.
async function identifyAdmits(lockingScriptHex) {
  try {
    const lockingScript = LockingScript.fromHex(lockingScriptHex);
    const result = PushDrop.decode(lockingScript);
    if (result.fields.length < 5) throw new Error('Invalid UHRP token');
    const isLinked = await isTokenSignatureCorrectlyLinked(result.lockingPublicKey, result.fields.slice());
    if (!isLinked) throw new Error('Signature is not properly linked');
    if (result.fields[1].length !== 32) throw new Error('Invalid hash length');
    const fileLocationString = Utils.toUTF8(result.fields[2]);
    const fileLocationURL = new URL(fileLocationString);
    if (fileLocationURL.protocol !== 'https:') throw new Error('Advertisement must be on HTTPS');
    const expiryTime = new Utils.Reader(result.fields[3]).readVarIntNum();
    const fileSize = new Utils.Reader(result.fields[4]).readVarIntNum();
    if (expiryTime < 1 || fileSize < 1) throw new Error('Invalid expiry time or file size');
    return { admit: true, reason: 'admitted' };
  } catch (e) {
    return { admit: false, reason: e.message };
  }
}

const files = readdirSync(TRANSCRIPTS).filter((f) => f.endsWith('.json'));
let ok = 0, failures = 0;
for (const f of files) {
  const raw = JSON.parse(readFileSync(join(TRANSCRIPTS, f), 'utf8'));
  const got = await identifyAdmits(raw.locking_script_hex);
  if (got.admit === raw.expected_admit) {
    ok++;
    console.log(`  OK  ${f}  (admit=${got.admit}) ${got.reason}`);
  } else {
    failures++;
    console.log(`  !!  ${f}  expected admit=${raw.expected_admit} got admit=${got.admit}  reason=${got.reason}`);
  }
}
console.log(`\n${ok}/${files.length} labels correct; ${failures} mismatches`);
process.exit(failures === 0 ? 0 : 1);
