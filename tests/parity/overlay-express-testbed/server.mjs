#!/usr/bin/env node
// Hermetic @bsv/overlay-express instance for the parity harness.
//
// Boots the stock SHIP/SLAP topic managers + lookup services against
// an in-process SQLite (Knex) + container-local MongoDB. Our Rust
// test in tests/parity/src/overlay_live.rs points at this instead of
// users.bapp.dev when the env var PARITY_OVERLAY_URL=http://localhost:8080
// is set, closing the external-infra dependency class forever.
//
// # Why SPV skip mode
//
// `engine.submit('current-tx')` on a fresh-broadcast tx fails merkle-path
// verification because there IS no merkle path yet (subject tx is in
// mempool, not yet mined). The canonical TS server behind nanostore +
// users.bapp.dev works around this with either historical-tx-no-spv or
// a chainTracker that accepts unproven txs. For the testbed we use
// 'scripts only' — the engine validates scripts but skips SPV entirely.
// Perfect for admission-parity tests (we want to know if our token
// passes tm_ship's field checks, not if the tx is mined).
//
// # Usage
//
//   docker compose up -d      # start mongo
//   npm ci                    # pinned versions per package.json
//   npm start                 # HTTP on :8080
//
// Then in Rust:
//   PARITY_OVERLAY_URL=http://localhost:8080 \
//     cargo test live_ship -- --ignored --nocapture
//
// Stop with Ctrl-C; `docker compose down -v` wipes mongo state.

import { default as OverlayExpress } from '@bsv/overlay-express'
import { PrivateKey } from '@bsv/sdk'

// Fixed identity for reproducibility. Not a secret — anyone reading
// this can compute the pubkey. Use a fresh key if you ever point this
// testbed at anything real. (Same key used in
// bsv-rs/tests/vectors/overlay_admin_token_ts_parity.json, so adverts
// we build in the bsv-rs byte-exact gates can round-trip here.)
const PRIV_HEX = '0000000000000000000000000000000000000000000000000000000000000001'

const main = async () => {
  const priv = PrivateKey.fromHex(PRIV_HEX)
  const fqdn = process.env.PARITY_OVERLAY_FQDN ?? 'localhost:8080'

  const server = new OverlayExpress(
    'parity-testbed',
    priv.toHex(),
    fqdn,
    'parity-testbed-admin-token' // fixed so curl --header "Authorization: Bearer parity-testbed-admin-token" works
  )

  server.configurePort(Number(process.env.PORT ?? 8080))
  server.configureNetwork('main')
  // Scripts-only chain tracker: skip merkle-path SPV so we can admit
  // fresh-broadcast subject txs (our harness builds + submits in one
  // shot; no wait-for-confirmation loop).
  server.configureChainTracker('scripts only')

  // Docker-hosted MySQL. We'd prefer :memory: SQLite but the native
  // bindings for both `better-sqlite3` and `sqlite3` keep failing to
  // link on recent Node/darwin-arm64. MySQL in a container is the
  // most portable path. Connection string is overridable for CI.
  const mysqlUrl =
    process.env.PARITY_OVERLAY_MYSQL ??
    'mysql://root@localhost:13306/overlay'
  await server.configureKnex(mysqlUrl)
  const mongoURL = process.env.PARITY_OVERLAY_MONGO ?? 'mongodb://localhost:27018'
  await server.configureMongo(mongoURL)

  // configureEngine(true) auto-registers tm_ship, tm_slap, ls_ship,
  // ls_slap using the canonical @bsv/overlay-discovery-services
  // implementations — exactly what nanostore's users.bapp.dev runs.
  // Add UHRP topic manager + lookup service if/when the discovery
  // services package ships them.
  await server.configureEngine(true)

  // Start listening.
  await server.start()
  console.log('[parity-testbed] ready at http://' + fqdn)
  console.log('[parity-testbed] admin token: parity-testbed-admin-token')
}

main().catch((e) => {
  console.error('[parity-testbed] failed to start:', e)
  process.exit(1)
})
