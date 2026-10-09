#!/usr/bin/env node
// Generates golden UHRP URL fixtures from @bsv/sdk.
//
// Oracle: @bsv/sdk's `StorageUtils.getURLForFile`. The produced JSON files are
// committed to `tests/fixtures/uhrp_hash/*.json` and read at compile time by
// the Rust test suite — any Rust-side drift from the TS implementation fails
// the build.
//
// Run:
//     cd /Users/johncalhoun/bsv/bsv-storage-cloudflare
//     node scripts/gen-uhrp-hash-fixtures.mjs
//
// Requires @bsv/sdk. We resolve it from a sibling project that already has it
// installed (chaintracks-server) — no deps for this repo itself.

import { writeFileSync, mkdirSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const __dirname = dirname(fileURLToPath(import.meta.url))
const outDir = resolve(__dirname, '..', 'tests', 'fixtures', 'uhrp_hash')
mkdirSync(outDir, { recursive: true })

// Resolve @bsv/sdk from a sibling tree (chaintracks-server installs it). We
// load the ESM build directly (`dist/esm/mod.js`) so named exports like
// `PrivateKey` are reachable — the package's CJS build, which `require.resolve`
// prefers, nests everything under `sdk.default` when loaded via dynamic import.
const sdkDir = resolve(__dirname, '..', '..', 'chaintracks-server', 'node_modules', '@bsv', 'sdk')
const sdkPath = resolve(sdkDir, 'dist', 'esm', 'mod.js')
const sdk = await import(sdkPath)
const { StorageUtils } = sdk

// Read SDK version (for provenance in fixture JSON).
const sdkPkg = require(resolve(sdkDir, 'package.json'))

function u8FromHex(h) {
  if (h.length % 2 !== 0) throw new Error('odd hex length')
  const a = new Uint8Array(h.length / 2)
  for (let i = 0; i < a.length; i++) a[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16)
  return a
}
function u8ToHex(a) {
  return Array.from(a, b => b.toString(16).padStart(2, '0')).join('')
}

// Intentionally varied: empty file, tiny ASCII, exact-1MiB chunk boundary, a
// random-looking binary blob. Each case is checked in both directions.
//
// Fixture JSON encodes the file either as `file_hex` (small cases) or as
// `file_pattern = { repeat: <byte>, count: <n> }` (large synthetic cases so we
// don't commit megabytes of hex). The Rust loader knows both encodings.
const cases = [
  { name: 'empty', fileHex: '' },
  { name: 'hello_world_ascii', fileHex: Buffer.from('hello world', 'utf8').toString('hex') },
  // Match the cross-SDK vector bsv-rs carries in src/storage/utils.rs tests.
  {
    name: 'ts_sdk_cross_vector',
    fileHex: '687da27f04a112aa48f1cab2e7949f1eea4f7ba28319c1e999910cd561a634a05a3516e6db'
  },
  // One byte per value 0..255 — exercises every possible byte in the hash input.
  { name: 'all_bytes_0_to_255', fileHex: Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0')).join('') },
  // Just over 1 MiB (1,048,577 bytes) — crosses the streaming-chunk boundary in
  // StorageUtils.getURLForFile (chunkSize = 1 MiB). Same byte repeated; we
  // store a pattern, not the raw hex, to keep the fixture JSON small.
  {
    name: 'one_mib_plus_one_byte_repeating',
    filePattern: { repeat_byte: 0xa3, count: 1024 * 1024 + 1 }
  }
]

const results = []
for (const c of cases) {
  let bytes
  if (c.filePattern) {
    bytes = new Uint8Array(c.filePattern.count)
    bytes.fill(c.filePattern.repeat_byte)
  } else {
    bytes = u8FromHex(c.fileHex)
  }
  const uhrpUrl = StorageUtils.getURLForFile(Array.from(bytes))
  const hash = StorageUtils.getHashFromURL(uhrpUrl)
  const fixture = {
    name: c.name,
    description: `oracle: @bsv/sdk v${sdkPkg.version} StorageUtils.getURLForFile`,
    uhrp_url: uhrpUrl,
    hash_hex: u8ToHex(Uint8Array.from(hash))
  }
  if (c.filePattern) fixture.file_pattern = c.filePattern
  else fixture.file_hex = c.fileHex
  const path = resolve(outDir, `${c.name}.json`)
  writeFileSync(path, JSON.stringify(fixture, null, 2) + '\n')
  results.push({ name: c.name, uhrpUrl, bytes: bytes.length })
}

console.log('UHRP hash fixtures written to', outDir)
for (const r of results) {
  console.log(`  ${r.name.padEnd(32)}  ${r.bytes.toString().padStart(8)} bytes  ${r.uhrpUrl}`)
}
