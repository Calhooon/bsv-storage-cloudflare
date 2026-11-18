// The paid routes' store on workerd's D1 and KV, fully local (Miniflare;
// Miniflare is disposed on every exit path, nothing is deployed).
//
//   node run.mjs store    the store (kit/, src/claims.rs mounted as it is):
//     1. the middleware's conformance kit against the store as the Worker
//        wires it, at the kit's defaults and at raised bounds (sizes 2 to 64,
//        a hold of 128 passes);
//     2. the release path's four mixes;
//     3. the middleware's answers to a refused claim (the gate's 409 and 400);
//     4. both directions against the key-value store's own claim
//        (`KvPrefixStore`, the store a build keeping its prefixes in the
//        key-value namespace runs): a prefix it used is refused here, and a
//        prefix used here is refused by it; a release on either side serves
//        the released transaction once, on either side, and no other;
//     5. a carried release frees only its own claim: a released record met at
//        once by its transaction and by others, 240 rounds.
//   node run.mjs worker   the storage Worker itself (../../build/worker,
//     built from this tree) beside a build of v0.3.0 (OLD_BUILD, a
//     build/worker directory), sharing one key-value namespace, with
//     wallet/ standing in for the wallet storage server and the exchange
//     rate; ../parity's `race` client drives them (RACE_BIN):
//     6. one payment in N simultaneous requests to /upload (N = 2, 4, 16):
//        one service, every other the signed 409; two transactions under one
//        prefix at once: one service, the other the signed 400;
//     7. both directions between the two builds; a wallet error's release,
//        on this build, on the old build then this one, and on this build
//        then the old one then this one; a wallet rejection; every answer
//        with its signature's verdict;
//     8. /renew, paid, with the stand-in holding an advert: one renewal and
//        its grant row (route, uhrpUrl, minutes, the new expiry, satoshis,
//        payer, state granted); the same payment again: the signed 409 and
//        the expiry unchanged; another transaction under the prefix: the
//        signed 400; one payment in N simultaneous requests (N = 2, 4, 16):
//        one renewal; each /upload grant's expiry is the custom-time the
//        client was served (the expiry the advert carries);
//     9. the Worker without its CLAIMS binding, and with the binding and no
//        tables: a payment to /upload or /renew is the gate's signed 503
//        ERR_PAYMENT_UNAVAILABLE, nothing served, the wallet not asked; a
//        prefix with a key-value record on the build with no tables: the
//        door's unsigned 503, except the transaction a released:<txid>
//        record names (the gate's signed 503);
//     10. a carried release frees only its own claim: a prefix the old
//        build released, paid here at once by its transaction and by others,
//        72 rounds: that transaction served at most once, no other.
//
// Build first (worker-build 0.8.4, --release): kit/, wallet/ and the
// repository root. Then `npm ci && node run.mjs store` (or `worker`).
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import assert from 'node:assert/strict'

const { Miniflare } = await import(process.env.MINIFLARE_MODULE ?? 'miniflare')

const here = dirname(fileURLToPath(import.meta.url))
const stage = process.argv[2] ?? 'store'
const ns = `run-${Date.now()}-${randomBytes(4).toString('hex')}`
const hex64 = () => randomBytes(32).toString('hex')
const modulesRules = [
  { type: 'ESModule', include: ['**/*.js', '**/*.mjs'] },
  { type: 'CompiledWasm', include: ['**/*.wasm'] },
]

/// The migration's statements, for a fresh local D1.
const migration = readFileSync(resolve(here, '../../migrations/0001_payment_claims.sql'), 'utf8')
  .split('\n')
  .filter(l => !l.startsWith('--'))
  .join('\n')
  .split(';')
  .map(s => s.trim())
  .filter(Boolean)

async function migrate(db) {
  for (const statement of migration) await db.prepare(statement).run()
}

const lines = []
const t0 = Date.now()
const log = line => {
  const at = `${((Date.now() - t0) / 1000).toFixed(1)}s`
  lines.push(line)
  console.log(`[${at}] ${line}`)
}

async function storeStage() {
  const mf = new Miniflare({
    modules: true,
    scriptPath: resolve(here, 'kit/build/worker/shim.mjs'),
    modulesRules,
    compatibilityDate: '2024-01-01',
    d1Databases: ['CLAIMS', 'BROKEN'],
    kvNamespaces: ['AUTH_SESSIONS'],
  })
  try {
    await migrate(await mf.getD1Database('CLAIMS'))
    const call = async (method, path) => {
      const response = await mf.dispatchFetch(`http://kit.local${path}`, { method })
      const text = await response.text()
      assert.equal(response.status, 200, `${path}: ${text}`)
      return JSON.parse(text)
    }
    const q = o => new URLSearchParams(o).toString()

    // 1. The kit, at the defaults and raised.
    for (const [raised, sizes] of [['0', 32], ['1', 63]]) {
      const kit = await call('GET', `/kit?${q({ ns: `${ns}-kit${raised}`, raised })}`)
      assert.equal(kit.prefix.pass, true, JSON.stringify(kit.prefix))
      assert.deepEqual(kit.prefix.skipped, [])
      assert.equal(kit.prefix.checked.length, 6 * sizes + 2)
      const max = Math.max(...kit.prefix.checked.map(([, n]) => n))
      log(`kit (${raised === '1' ? 'raised: sizes 2..64, hold 128' : 'defaults: sizes 2..33, hold 64'}) on workerd's D1 and KV: ${kit.prefix.checked.length} laws pass, largest N ${max}`)
    }

    // 2. The release path.
    const path = await call('GET', `/release-path?${q({ ns: `${ns}-rp` })}`)
    assert.equal(path.pass, true, JSON.stringify(path.failures))
    log(`release path on workerd: (a) ${path.runs[0]} runs, (b) ${path.runs[1]}, (c) ${path.runs[2]}, (d) ${path.runs[3]}: every one as the contract states`)

    // 3. The middleware's answers to a refused claim.
    const claim = (prefix, txid) => call('POST', `/claim?${q({ prefix, txid })}`)
    const kvClaim = (prefix, txid) => call('POST', `/kv-claim?${q({ prefix, txid })}`)
    const state = prefix => call('GET', `/state?${q({ prefix })}`)
    {
      const p = `${ns}/answers`
      const [a, b] = [hex64(), hex64()]
      assert.deepEqual(await claim(p, a), { word: 'Won', refusal: null })
      const same = await claim(p, a)
      assert.equal(same.word, 'SameTransaction')
      assert.equal(same.refusal.status, 409)
      assert.equal(same.refusal.body.code, 'ERR_PAYMENT_REPLAYED')
      const other = await claim(p, b)
      assert.equal(other.word, 'OtherTransaction')
      assert.equal(other.refusal.status, 400)
      assert.equal(other.refusal.body.code, 'ERR_PAYMENT_INVALID')
      for (const r of [same.refusal, other.refusal]) assert.ok(!JSON.stringify(r.body).includes(a) && !JSON.stringify(r.body).includes(b))
      log(`the gate's answers: won; the same transaction 409 ${same.refusal.body.code}; another 400 ${other.refusal.body.code}; no txid in either body`)
    }

    // 4. Both directions against the key-value store's own claim.
    {
      // A prefix the key-value store bound (served there) stays refused here.
      const p = `${ns}/kv-first`
      const [a, b] = [hex64(), hex64()]
      assert.equal((await kvClaim(p, a)).word, 'Won')
      assert.equal((await claim(p, a)).refusal.status, 409)
      assert.equal((await claim(p, b)).refusal.status, 400)
      // Released there after a wallet error: the same transaction re-takes
      // here, and no other.
      const r = `${ns}/kv-released`
      assert.equal((await kvClaim(r, a)).word, 'Won')
      await call('POST', `/kv-release?${q({ prefix: r, txid: a })}`)
      assert.equal((await state(r)).kv, `released:${a}`)
      assert.equal((await claim(r, b)).refusal.status, 400)
      assert.deepEqual((await state(r)).d1, { txid: a, released: true })
      assert.equal((await claim(r, a)).word, 'Won')
      assert.equal((await claim(r, a)).refusal.status, 409)
      assert.equal((await claim(r, b)).refusal.status, 400)
      const r2 = `${ns}/kv-released-2`
      assert.equal((await kvClaim(r2, a)).word, 'Won')
      await call('POST', `/kv-release?${q({ prefix: r2, txid: a })}`)
      assert.equal((await claim(r2, a)).word, 'Won')
      assert.equal((await claim(r2, b)).refusal.status, 400)
      // A prefix consumed before records were bound (`1`).
      const u = `${ns}/kv-unbound`
      await call('POST', `/kv-put?${q({ prefix: u, value: '1' })}`)
      assert.equal((await claim(u, a)).word, 'Unknown')
      log('a prefix the key-value store used: its transaction 409, another 400; released there: another 400, then its transaction re-takes once (then 409); a "1" record: 409')

      // A prefix bound here is refused by the key-value store's claim.
      const n = `${ns}/d1-first`
      assert.equal((await claim(n, a)).word, 'Won')
      const st = await state(n)
      assert.equal(st.kv, a)
      assert.equal(st.marked, true)
      assert.deepEqual(st.d1, { txid: a, released: false })
      assert.equal((await kvClaim(n, a)).word, 'SameTransaction')
      assert.equal((await kvClaim(n, b)).word, 'OtherTransaction')
      // Released here (a wallet error): the record is the key-value store's
      // own release; that store serves the transaction once and no other,
      // and this store then refuses the prefix.
      assert.equal((await call('POST', `/release?${q({ prefix: n, txid: a })}`)).ok, true)
      const rel = await state(n)
      assert.deepEqual([rel.kv, rel.marked, rel.d1], [`released:${a}`, false, { txid: a, released: true }])
      assert.equal((await kvClaim(n, b)).word, 'OtherTransaction')
      assert.equal((await kvClaim(n, a)).word, 'Won')
      assert.equal((await kvClaim(n, a)).word, 'SameTransaction')
      assert.equal((await claim(n, a)).refusal.status, 409)
      assert.equal((await claim(n, b)).refusal.status, 400)
      assert.deepEqual((await state(n)).d1, { txid: a, released: false })
      // Released here and retried here: served once.
      const h = `${ns}/d1-retry`
      assert.equal((await claim(h, a)).word, 'Won')
      assert.equal((await call('POST', `/release?${q({ prefix: h, txid: a })}`)).ok, true)
      assert.equal((await claim(h, b)).refusal.status, 400)
      assert.equal((await claim(h, a)).word, 'Won')
      assert.equal((await claim(h, a)).refusal.status, 409)
      log(`a prefix used here: the key-value record is the txid, marked (${st.kv === a && st.marked}); the key-value store answers its transaction SameTransaction and another OtherTransaction; released here: the record reads released:<txid>, the key-value store serves that transaction once and no other, and this store then refuses it (409, another 400); released and retried here: served once`)

      // N simultaneous claims of one prefix: one winner each way.
      for (const k of [2, 8, 32]) {
        const one = `${ns}/n/${k}`
        const t = hex64()
        const words = (await Promise.all(Array.from({ length: k }, () => claim(one, t)))).map(x => x.word)
        assert.equal(words.filter(w => w === 'Won').length, 1, words.join())
        assert.equal(words.filter(w => w === 'SameTransaction').length, k - 1, words.join())
        const many = `${ns}/m/${k}`
        const ts = Array.from({ length: k }, hex64)
        const ws = (await Promise.all(ts.map(t => claim(many, t)))).map(x => x.word)
        assert.equal(ws.filter(w => w === 'Won').length, 1, ws.join())
        assert.equal(ws.filter(w => w === 'OtherTransaction').length, k - 1, ws.join())
        log(`N=${k} simultaneous requests to the store: one txid 1 Won + ${k - 1} SameTransaction; ${k} txids 1 Won + ${k - 1} OtherTransaction`)
      }
    }

    // 5. A carried release frees only its own claim: a released:<t> record
    // the key-value store left, met at once by t's claims and by other
    // transactions' claims (both orders of starting), then t claimed twice
    // more. t is won at most once in each round, and no other transaction.
    {
      const rounds = 40
      let total = 0, moreThanOnce = 0, othersWon = 0
      for (const [na, nb, othersFirst] of [[1, 1, true], [1, 1, false], [1, 7, true], [1, 7, false], [4, 4, true], [4, 4, false]]) {
        let twice = 0, never = 0
        for (let r = 0; r < rounds; r++) {
          const p = `${ns}/carried/${na}/${nb}/${othersFirst}/${r}`
          const t = hex64()
          const others = Array.from({ length: nb }, hex64)
          await call('POST', `/kv-put?${q({ prefix: p, value: `released:${t}` })}`)
          const mine = Array.from({ length: na }, () => [true, t])
          const theirs = others.map(b => [false, b])
          const order = othersFirst ? [...theirs, ...mine] : [...mine, ...theirs]
          const out = await Promise.all(order.map(([isT, x]) => claim(p, x).then(o => [isT, o.word])))
          let tWon = out.filter(([isT, w]) => isT && w === 'Won').length
          othersWon += out.filter(([isT, w]) => !isT && w === 'Won').length
          for (let i = 0; i < 2; i++) if ((await claim(p, t)).word === 'Won') tWon++
          if (tWon > 1) twice++
          if (tWon === 0) never++
        }
        total += rounds
        moreThanOnce += twice
        log(`a carried release, t x${na} and others x${nb} at once (${othersFirst ? 'others' : 't'} first): ${rounds} rounds; t won more than once in ${twice}; never in ${never}`)
      }
      log(`a carried release: ${total} rounds; t won more than once in ${moreThanOnce}; another transaction won ${othersWon}`)
      assert.equal(moreThanOnce, 0)
      assert.equal(othersWon, 0)
    }
  } finally {
    await mf.dispose()
  }
}

async function workerStage() {
  const root = resolve(here, '../..')
  const oldBuild = process.env.OLD_BUILD
  const raceBin = process.env.RACE_BIN
  assert.ok(oldBuild && raceBin, 'OLD_BUILD and RACE_BIN')
  const vars = {
    BSV_NETWORK: 'mainnet',
    WALLET_STORAGE_URL: 'https://wallet.stand-in.test',
    OVERLAY_SUBMIT_URL: 'https://overlay.stand-in.test',
    PUBLIC_URL_BASE: 'https://files.stand-in.test',
    R2_S3_ENDPOINT_HOST: 'r2.stand-in.test',
    R2_BUCKET: 'uhrp-test',
    PRICE_PER_GB_MO: '0.05',
    MIN_HOSTING_MINUTES: '15',
    // Public test values, not secrets.
    SERVER_PRIVATE_KEY: '0000000000000000000000000000000000000000000000000000000000000001',
    ADMIN_WALLET_PRIVATE_KEY: '0000000000000000000000000000000000000000000000000000000000000003',
    ADMIN_IDENTITY_KEYS: '',
    R2_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
    R2_SECRET_ACCESS_KEY: 'stand-in-r2-secret',
  }
  const storage = (name, dir, extra) => ({
    name,
    modules: true,
    scriptPath: resolve(dir, 'shim.mjs'),
    modulesRoot: resolve(dir, '..'),
    modulesRules,
    compatibilityDate: '2024-01-01',
    bindings: vars,
    kvNamespaces: { AUTH_SESSIONS: 'sessions' },
    r2Buckets: { UHRP_FILES: 'files' },
    queueProducers: { POST_UPLOAD_QUEUE: 'uhrp-post-upload' },
    serviceBindings: { OVERLAY: 'wallet' },
    outboundService: 'wallet',
    unsafeDirectSockets: [{ host: '127.0.0.1', port: 0 }],
    ...extra,
  })
  const mf = new Miniflare({
    workers: [
      storage('storage', resolve(root, 'build/worker'), { d1Databases: { CLAIMS: 'claims' } }),
      storage('storage-old', oldBuild, {}),
      storage('storage-no-binding', resolve(root, 'build/worker'), {}),
      storage('storage-no-table', resolve(root, 'build/worker'), { d1Databases: { CLAIMS: 'claims-empty' } }),
      {
        name: 'wallet',
        modules: true,
        scriptPath: resolve(here, 'wallet/build/worker/shim.mjs'),
        modulesRoot: resolve(here, 'wallet/build'),
        modulesRules,
        compatibilityDate: '2024-01-01',
        bindings: { WALLET_DELAY_MS: '150' },
        kvNamespaces: { AUTH_SESSIONS: 'wallet-sessions', STAND_IN: 'stand-in' },
        unsafeDirectSockets: [{ host: '127.0.0.1', port: 0 }],
      },
    ],
  })
  try {
    await mf.ready
    await migrate(await mf.getD1Database('CLAIMS', 'storage'))
    const urls = {}
    for (const name of ['storage', 'storage-old', 'storage-no-binding', 'storage-no-table', 'wallet']) urls[name] = (await mf.unsafeGetDirectURL(name)).toString().replace(/\/$/, '')
    const health = await (await fetch(`${urls.storage}/health`)).json()
    log(`the storage Worker under test: ${JSON.stringify(health.build.crates)}`)
    const old = await (await fetch(`${urls['storage-old']}/health`)).json()
    log(`the old build beside it: ${JSON.stringify(old.build.crates)}`)
    const run = spawnSync(raceBin, [urls.storage, urls['storage-old'], urls.wallet, urls['storage-no-binding'], urls['storage-no-table']], { encoding: 'utf8', timeout: 8 * 60 * 1000 })
    let renewals = null
    let uploads = null
    for (const line of (run.stdout ?? '').split('\n').filter(Boolean)) {
      if (line.startsWith('renew-grants ')) renewals = JSON.parse(line.slice('renew-grants '.length))
      else if (line.startsWith('upload-grants ')) uploads = JSON.parse(line.slice('upload-grants '.length))
      else log(line)
    }
    if (run.status !== 0) throw new Error(`race: exit ${run.status} ${run.signal ?? ''}\n${run.stderr}`)
    const db = await mf.getD1Database('CLAIMS', 'storage')
    const grants = await db.prepare('SELECT route, state, status, satoshis, file_size, minutes, expiry_time IS NOT NULL AS expiry, object_identifier IS NOT NULL AS object, answered_at IS NOT NULL AS answered FROM payment_grants').all()
    const claims = await db.prepare('SELECT COUNT(*) AS n, SUM(released) AS released FROM payment_claims').first()
    log(`CLAIMS after the run: ${claims.n} claims (${claims.released} released); ${grants.results.length} grants: ${JSON.stringify(grants.results.reduce((a, g) => { const k = `${g.route} ${g.state} ${g.status}`; a[k] = (a[k] ?? 0) + 1; return a }, {}))}`)
    for (const g of grants.results) {
      assert.equal(g.state, 'granted')
      assert.ok(g.object && g.expiry && g.answered && g.file_size > 0 && g.minutes > 0 && g.satoshis > 0, JSON.stringify(g))
    }
    // Each renewal's grant: one row, as the race client saw it served.
    assert.ok(renewals && renewals.length === 4, 'renew-grants')
    for (const r of renewals) {
      const rows = (await db.prepare("SELECT route, uhrp_url, minutes, expiry_time, satoshis, identity_key, state, status, file_size FROM payment_grants WHERE route = '/renew' AND uhrp_url = ?").bind(r.uhrpUrl).all()).results
      assert.equal(rows.length, 1, JSON.stringify(rows))
      const [g] = rows
      assert.deepEqual(
        [g.route, g.uhrp_url, g.minutes, g.expiry_time, g.satoshis, g.identity_key, g.state, g.status, g.file_size],
        ['/renew', r.uhrpUrl, r.minutes, r.expiry, r.satoshis, r.payer, 'granted', 200, r.fileSize],
      )
    }
    // Each upload's grant: its expiry is the custom-time signed into the PUT.
    assert.ok(uploads && uploads.length > 0, 'upload-grants')
    for (const u of uploads) {
      const rows = (await db.prepare("SELECT expiry_time FROM payment_grants WHERE route = '/upload' AND object_identifier = ?").bind(u.object).all()).results
      assert.equal(rows.length, 1, JSON.stringify(u))
      assert.equal(rows[0].expiry_time, Date.parse(u.customTime) / 1000, JSON.stringify(u))
    }
    log(`the /upload grants: ${uploads.length} rows, each expiry_time the custom-time the client was served`)
    log(`the /renew grants: ${renewals.length} rows, one per renewal, each (route /renew, its uhrpUrl, minutes ${renewals.map(r => r.minutes).join('/')}, the new expiry, satoshis, the payer's key, state granted, status 200) as the client was served`)
    const empty = await mf.getD1Database('CLAIMS', 'storage-no-table')
    const tables = (await empty.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '_cf%' AND name NOT LIKE 'sqlite%'").all()).results
    assert.deepEqual(tables, [])
    log('the build with CLAIMS bound and no tables: its database still holds no table after the run')
  } finally {
    await mf.dispose()
  }
}

try {
  if (stage === 'store') await storeStage()
  else if (stage === 'worker') await workerStage()
  else throw new Error(`no stage ${stage}`)
} catch (e) {
  console.error('FAIL', e?.stack ?? e)
  process.exitCode = 1
}
if (!process.exitCode) console.log(`workerd ${stage}: ok`)
