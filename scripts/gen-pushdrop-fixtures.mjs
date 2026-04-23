#!/usr/bin/env node
// Generates golden PushDrop UHRP-advertisement fixtures from @bsv/sdk.
//
// For each case we construct the same five UHRP fields that
// `src/utils/createUHRPAdvertisement.ts:40–51` builds, then call
// `new PushDrop(wallet).lock(fields, [2, 'uhrp advertisement'], '1', 'anyone', true)`
// to get the canonical locking-script hex. `true` = include signature — and we
// record that signature separately so the Rust port (which does NOT sign) can
// be handed the signature as an input and still produce an identical script.
//
// Wallet: a `ProtoWallet` built from a fixed private key. ECDSA signatures
// under @bsv/sdk are deterministic (RFC 6979), so output is stable across
// runs — an essential property for a golden fixture.
//
// Run from the repo root:
//     node scripts/gen-pushdrop-fixtures.mjs

import { writeFileSync, mkdirSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const __dirname = dirname(fileURLToPath(import.meta.url))
const outDir = resolve(__dirname, '..', 'tests', 'fixtures', 'pushdrop')
mkdirSync(outDir, { recursive: true })

// Load the ESM build directly so named exports like `PrivateKey` are reachable
// (the CJS build nests everything under `sdk.default` under dynamic import).
const sdkDir = resolve(__dirname, '..', '..', 'chaintracks-server', 'node_modules', '@bsv', 'sdk')
const sdkPath = resolve(sdkDir, 'dist', 'esm', 'mod.js')
const sdk = await import(sdkPath)
const { PushDrop, ProtoWallet, PrivateKey, Utils } = sdk

const sdkPkg = require(resolve(sdkDir, 'package.json'))

// Deterministic keys. NEVER use these for real value; they are test-only.
const SERVER_PRIV_HEX = '0000000000000000000000000000000000000000000000000000000000000003'
// A second key stands in for the "uploader" identity used in one variant where
// the advertisement's server_identity_key field does not match the locker.
const UPLOADER_PRIV_HEX = '0000000000000000000000000000000000000000000000000000000000000007'

const serverPriv = PrivateKey.fromHex(SERVER_PRIV_HEX)
const serverPubHex = serverPriv.toPublicKey().toString()
const uploaderPriv = PrivateKey.fromHex(UPLOADER_PRIV_HEX)
const uploaderPubHex = uploaderPriv.toPublicKey().toString()

const wallet = new ProtoWallet(serverPriv)

// The PushDrop TS impl pushes the locking pubkey that the wallet returns for
// protocol `[2, 'uhrp advertisement']`, keyID `'1'`, counterparty `'anyone'`.
// We ask the wallet for it so the fixture can carry the exact value — the Rust
// port treats this as an input (callers that talk to a real wallet will also
// have to fetch it).
const lockProtocolID = [2, 'uhrp advertisement']
const lockKeyID = '1'
const lockCounterparty = 'anyone'

const { publicKey: lockingPubHex } = await wallet.getPublicKey({
  protocolID: lockProtocolID,
  keyID: lockKeyID,
  counterparty: lockCounterparty
})

// VarInt encode a non-negative integer using the TS `Writer.varIntNum` formula
// (matches bitcoin-style VarInt for positive values). Used to cross-check the
// expected VarInt bytes independently of what PushDrop emits.
function varIntNum(n) {
  if (n < 253) return [n]
  if (n < 0x10000) return [0xfd, n & 0xff, (n >> 8) & 0xff]
  if (n < 0x100000000) return [0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]
  const low = n & 0xffffffff
  const high = Math.floor(n / 0x100000000) & 0xffffffff
  return [0xff,
    low & 0xff, (low >> 8) & 0xff, (low >> 16) & 0xff, (low >> 24) & 0xff,
    high & 0xff, (high >> 8) & 0xff, (high >> 16) & 0xff, (high >> 24) & 0xff]
}

function hex(bytesOrArray) {
  const a = Array.isArray(bytesOrArray) ? bytesOrArray : Array.from(bytesOrArray)
  return a.map(b => (b & 0xff).toString(16).padStart(2, '0')).join('')
}

// Cases: a baseline plus deliberate edge cases that could bite the Rust port.
const cases = [
  {
    name: 'baseline_small_cdn_url',
    serverIdentityKey: serverPubHex,
    // SHA-256 of "hello world" as raw 32 bytes.
    hashHex: 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9',
    url: 'https://storage.example.com/cdn/abc123',
    expiryTime: 1735689600,
    contentLength: 1048576
  },
  {
    name: 'mismatched_server_and_uploader_keys',
    // Field 0 is the host identity; the locking pubkey (from the wallet) is
    // distinct. Exercise the case where callers pass a different value here.
    serverIdentityKey: uploaderPubHex,
    hashHex: '1a5ec49a3f32cd56d19732e89bde5d81755ddc0fd8515dc8b226d47654139dca',
    url: 'https://s.example/cdn/xyz',
    expiryTime: 1,
    contentLength: 0
  },
  {
    name: 'url_over_253_bytes_varint_boundary',
    serverIdentityKey: serverPubHex,
    hashHex: '0000000000000000000000000000000000000000000000000000000000000000',
    // 260 bytes — trips OP_PUSHDATA2 (>= 256). This is the case where a one-
    // off-by-one in the minimal-encoding logic ruins every future advert.
    url: 'https://very-long.example.com/cdn/' + 'a'.repeat(260 - 'https://very-long.example.com/cdn/'.length),
    expiryTime: 1999999999,
    contentLength: 253
  },
  {
    name: 'large_content_length_over_u32_max',
    serverIdentityKey: serverPubHex,
    hashHex: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    url: 'https://storage.example.com/cdn/big',
    expiryTime: 4294967295, // exactly u32::MAX — 0xfe marker, 4 LE bytes
    contentLength: 0x1_0000_0000 // exactly 2^32 — forces 0xff marker + 8 LE bytes
  }
]

const results = []
for (const c of cases) {
  const hashBytes = Array.from(Buffer.from(c.hashHex, 'hex'))
  if (hashBytes.length !== 32) throw new Error(`${c.name}: hash must be 32 bytes, got ${hashBytes.length}`)

  const serverPubBytes = Utils.toArray(c.serverIdentityKey, 'hex')
  const urlBytes = Utils.toArray(c.url, 'utf8')
  const expiryBytes = new Utils.Writer().writeVarIntNum(c.expiryTime).toArray()
  const contentLengthBytes = new Utils.Writer().writeVarIntNum(c.contentLength).toArray()

  // Sanity: our locally-computed VarInt matches the SDK's.
  if (hex(expiryBytes) !== hex(varIntNum(c.expiryTime))) {
    throw new Error(`${c.name}: expiry VarInt mismatch`)
  }
  if (hex(contentLengthBytes) !== hex(varIntNum(c.contentLength))) {
    throw new Error(`${c.name}: content-length VarInt mismatch`)
  }

  const fields = [serverPubBytes, hashBytes, urlBytes, expiryBytes, contentLengthBytes]

  // Build the signature exactly the way PushDrop.lock does so we can hand it
  // to the Rust port. PushDrop signs `fields.reduce((a, e) => [...a, ...e], [])`
  // via wallet.createSignature BEFORE appending, and the resulting signature
  // becomes the last PushDrop field.
  const dataToSign = fields.reduce((a, e) => a.concat(e), [])
  const { signature: sigArr } = await wallet.createSignature({
    data: dataToSign,
    protocolID: lockProtocolID,
    keyID: lockKeyID,
    counterparty: lockCounterparty
  })

  const pushdrop = new PushDrop(wallet)
  const lockingScript = await pushdrop.lock(
    fields,
    lockProtocolID,
    lockKeyID,
    lockCounterparty,
    false,   // forSelf
    true,    // includeSignature — matches createUHRPAdvertisement.ts:65
    'before' // lockPosition (default)
  )
  const scriptHex = lockingScript.toHex()

  const fixture = {
    name: c.name,
    description: `oracle: @bsv/sdk v${sdkPkg.version} PushDrop.lock with [2, 'uhrp advertisement']`,
    // Inputs Rust receives:
    locking_public_key_hex: lockingPubHex,
    server_identity_key_hex: c.serverIdentityKey,
    hash_hex: c.hashHex,
    url: c.url,
    expiry_time: c.expiryTime,
    content_length: c.contentLength,
    signature_hex: hex(sigArr),
    // Expected output:
    expected_locking_script_hex: scriptHex,
    // Intermediate inspection aid (byte-equal comparisons here are non-load-bearing):
    field_bytes_hex: {
      server_identity_key: hex(serverPubBytes),
      hash: hex(hashBytes),
      url: hex(urlBytes),
      expiry_time_varint: hex(expiryBytes),
      content_length_varint: hex(contentLengthBytes),
      signature: hex(sigArr)
    }
  }
  const path = resolve(outDir, `${c.name}.json`)
  writeFileSync(path, JSON.stringify(fixture, null, 2) + '\n')
  results.push({ name: c.name, bytes: scriptHex.length / 2 })
}

console.log('PushDrop fixtures written to', outDir)
console.log('  locking pubkey (wallet-derived):', lockingPubHex)
for (const r of results) {
  console.log(`  ${r.name.padEnd(48)}  ${r.bytes.toString().padStart(6)}-byte script`)
}
