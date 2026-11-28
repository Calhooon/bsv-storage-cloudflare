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
//     8b. /renew's outcomes (the stand-in told to answer otherwise, its
//        knobs): an advert whose stored object is missing or of another
//        size is a free 404 ERR_FILE_NOT_FOUND, nothing claimed; served
//        with the overlay admitting (overlayAdmitted true, the stored
//        object's etag and upload time unchanged), refusing (false, never
//        submitted again) and faulting (false, the queue's re-submit
//        delivered four times); not made at createAction after the one more
//        try, at the signature (the action released) and at processAction
//        (refused by name with no record, failed): the signed 500
//        ERR_RENEWAL_NOT_MADE, the grant paid; served when processAction
//        refuses a transaction it already processed and its record reads a
//        take; no word (the answer lost, the transaction untaken): the
//        signed 502 ERR_RENEWAL_UNCONFIRMED, the grant paid; two payers of
//        one file at once, in the order the stand-in enforces: both served,
//        two extensions; each grant and renewals row read against what the
//        client was served;
//     11. the hourly pass (the scheduled handler, fired by hand): the race's
//        waiting rows, each ending of each kind, the cap of 20 fewest runs
//        first and then oldest, a run with the overlay down and the next
//        one, a served row's grant left paid set granted, rows of other
//        kinds left alone, no stored object touched.
//
// Build first (worker-build 0.8.4, --release): kit/, wallet/ and the
// repository root. Then `npm ci && node run.mjs store` (or `worker`).
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readFileSync, readdirSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { spawn } from 'node:child_process'
import assert from 'node:assert/strict'

const { Miniflare, Log, LogLevel } = await import(process.env.MINIFLARE_MODULE ?? 'miniflare')

const here = dirname(fileURLToPath(import.meta.url))
const stage = process.argv[2] ?? 'store'
const ns = `run-${Date.now()}-${randomBytes(4).toString('hex')}`
const hex64 = () => randomBytes(32).toString('hex')
const modulesRules = [
  { type: 'ESModule', include: ['**/*.js', '**/*.mjs'] },
  { type: 'CompiledWasm', include: ['**/*.wasm'] },
]

/// The migrations' statements, in order, for a fresh local D1.
const migrationsDir = resolve(here, '../../migrations')
const migration = readdirSync(migrationsDir)
  .filter(f => f.endsWith('.sql'))
  .sort()
  .flatMap(f => readFileSync(resolve(migrationsDir, f), 'utf8')
    .split('\n')
    .filter(l => !l.startsWith('--'))
    .join('\n')
    .split(';')
    .map(s => s.trim())
    .filter(Boolean))

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
    // The scheduled handler is fired by hand (stage 11).
    unsafeTriggerHandlers: true,
    // The queue's deliveries (each batch's acks) in the log.
    log: new Log(LogLevel.INFO),
    workers: [
      storage('storage', resolve(root, 'build/worker'), {
        d1Databases: { CLAIMS: 'claims' },
        // The consumer of the post-upload queue (wrangler.toml's figures).
        queueConsumers: { 'uhrp-post-upload': { maxBatchSize: 10, maxBatchTimeout: 1, maxRetries: 3 } },
      }),
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
        // The bucket the storage Worker reads: the stand-in seeds each
        // advert's object in it.
        r2Buckets: { UHRP_FILES: 'files' },
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
    // Spawned, not run synchronously: Miniflare's loopback (its log, which
    // the queue broker awaits after each batch) is served from this
    // process's event loop while the race runs.
    const run = await new Promise(done => {
      const child = spawn(raceBin, [urls.storage, urls['storage-old'], urls.wallet, urls['storage-no-binding'], urls['storage-no-table']], { stdio: ['ignore', 'pipe', 'pipe'] })
      let stdout = ''
      let stderr = ''
      child.stdout.on('data', d => { stdout += d })
      child.stderr.on('data', d => { stderr += d })
      const limit = setTimeout(() => child.kill('SIGKILL'), 15 * 60 * 1000)
      child.on('close', (status, signal) => { clearTimeout(limit); done({ status, signal, stdout, stderr }) })
    })
    let renewals = null
    let uploads = null
    let unserved = null
    for (const line of (run.stdout ?? '').split('\n').filter(Boolean)) {
      if (line.startsWith('renew-grants ')) renewals = JSON.parse(line.slice('renew-grants '.length))
      else if (line.startsWith('renew-paid ')) unserved = JSON.parse(line.slice('renew-paid '.length))
      else if (line.startsWith('upload-grants ')) uploads = JSON.parse(line.slice('upload-grants '.length))
      else log(line)
    }
    if (run.status !== 0) throw new Error(`race: exit ${run.status} ${run.signal ?? ''}\n${run.stderr}`)
    const db = await mf.getD1Database('CLAIMS', 'storage')
    const grants = await db.prepare('SELECT route, state, status, satoshis, file_size, minutes, expiry_time IS NOT NULL AS expiry, object_identifier IS NOT NULL AS object, answered_at IS NOT NULL AS answered FROM payment_grants').all()
    const claims = await db.prepare('SELECT COUNT(*) AS n, SUM(released) AS released FROM payment_claims').first()
    log(`CLAIMS after the run: ${claims.n} claims (${claims.released} released); ${grants.results.length} grants: ${JSON.stringify(grants.results.reduce((a, g) => { const k = `${g.route} ${g.state} ${g.status}`; a[k] = (a[k] ?? 0) + 1; return a }, {}))}`)
    for (const g of grants.results) {
      if (g.state === 'granted') {
        assert.ok(g.object && g.expiry && g.answered && g.file_size > 0 && g.minutes > 0 && g.satoshis > 0, JSON.stringify(g))
      } else {
        // A taken payment with no renewal served: `paid`, its answer recorded.
        assert.equal(g.state, 'paid', JSON.stringify(g))
        assert.equal(g.route, '/renew', JSON.stringify(g))
        assert.ok(g.answered && [500, 502].includes(g.status), JSON.stringify(g))
      }
    }
    assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM payment_grants WHERE route = '/renew' AND state = 'refused'").first()).n, 0)
    // Each renewal served: its grant and its renewals row, as the race
    // client saw it served (two payers of one file: two rows, two expiries).
    assert.ok(renewals && renewals.length === 10, 'renew-grants')
    const byUrl = new Map()
    for (const r of renewals) byUrl.set(r.uhrpUrl, [...(byUrl.get(r.uhrpUrl) ?? []), r])
    for (const [url, expected] of byUrl) {
      const rows = (await db.prepare("SELECT g.route, g.uhrp_url, g.minutes, g.expiry_time, g.satoshis, g.identity_key, g.state, g.status, g.file_size, r.outcome, r.advert, r.queue_tries, r.queued_until FROM payment_grants g JOIN renewals r ON r.prefix = g.prefix WHERE g.route = '/renew' AND g.uhrp_url = ? AND g.state = 'granted' ORDER BY g.expiry_time").bind(url).all()).results
      expected.sort((a, b) => a.expiry - b.expiry)
      assert.equal(rows.length, expected.length, JSON.stringify(rows))
      rows.forEach((g, i) => {
        const r = expected[i]
        assert.deepEqual(
          [g.route, g.uhrp_url, g.minutes, g.expiry_time, g.satoshis, g.identity_key, g.state, g.status, g.file_size, g.outcome, g.advert],
          ['/renew', r.uhrpUrl, r.minutes, r.expiry, r.satoshis, r.payer, 'granted', 200, r.fileSize, 'served', r.advert],
        )
        // The overlay's fault: the queue's four deliveries, then the pass's.
        if (r.advert === 'not_admitted') assert.deepEqual([g.queue_tries, g.queued_until], [4, null])
      })
    }
    // Each payment taken with no renewal served: `paid`, and its renewals row.
    assert.ok(unserved && unserved.length === 6, 'renew-paid')
    for (const u of unserved) {
      const row = await db.prepare('SELECT g.state, g.status, g.answered_at IS NOT NULL AS answered, g.expiry_time, r.outcome, r.renewing_txid, r.payment_txid, r.advert, r.new_expiry_time FROM payment_grants g JOIN renewals r ON r.prefix = g.prefix WHERE g.txid = ?').bind(u.paymentTxid).first()
      assert.ok(row, JSON.stringify(u))
      assert.deepEqual(
        [row.state, row.status, row.answered, row.expiry_time, row.outcome, row.payment_txid, row.advert, row.renewing_txid !== null],
        ['paid', u.status, 1, null, u.outcome, u.paymentTxid, null, u.renewing],
        JSON.stringify(u),
      )
      if (u.renewingTxid) assert.deepEqual([row.renewing_txid, row.new_expiry_time], [u.renewingTxid, u.expiry])
    }
    log(`the /renew grants: ${renewals.length} served (granted, status 200, each with its renewals row: served, the overlay's answer ${[...new Set(renewals.map(r => r.advert))].join('/')}); ${unserved.length} taken and not served (paid, status 500/502, the renewals row not_made/no_word with the payment's txid); no /renew grant refused`)
    // Each upload's grant: its expiry is the custom-time signed into the PUT.
    assert.ok(uploads && uploads.length > 0, 'upload-grants')
    for (const u of uploads) {
      const rows = (await db.prepare("SELECT expiry_time FROM payment_grants WHERE route = '/upload' AND object_identifier = ?").bind(u.object).all()).results
      assert.equal(rows.length, 1, JSON.stringify(u))
      assert.equal(rows[0].expiry_time, Date.parse(u.customTime) / 1000, JSON.stringify(u))
    }
    log(`the /upload grants: ${uploads.length} rows, each expiry_time the custom-time the client was served`)
    await passStage(mf, urls, db, unserved)
    const empty = await mf.getD1Database('CLAIMS', 'storage-no-table')
    const tables = (await empty.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '_cf%' AND name NOT LIKE 'sqlite%'").all()).results
    assert.deepEqual(tables, [])
    log('the build with CLAIMS bound and no tables: its database still holds no table after the run')
  } finally {
    await mf.dispose()
  }
}

// 11. The hourly pass (the storage Worker's scheduled handler), fired here
// by hand: the rows the race left (an advert the queue could not get
// admitted, two renewals with no word), then rows written for it: each
// ending of each kind, the cap of 20 fewest runs first and then oldest, a
// run with the overlay down and the next, a served row whose grant reads
// paid, rows of other kinds and rows still on the queue left alone, and no
// stored object touched.
async function passStage(mf, urls, db, unserved) {
  const wallet = urls.wallet
  const storageWorker = await mf.getWorker('storage')
  const runPass = async () => {
    if (typeof storageWorker.scheduled === 'function') {
      const result = await storageWorker.scheduled({ cron: '0 * * * *' })
      assert.equal(result.outcome, 'ok', JSON.stringify(result))
    } else {
      const response = await mf.dispatchFetch('http://localhost/cdn-cgi/handler/scheduled?cron=0+*+*+*+*')
      assert.ok(response.ok, `${response.status} ${await response.text()}`)
    }
  }
  const knob = q => fetch(`${wallet}/knob?${q}`).then(r => r.json())
  const setReq = (txid, status) => fetch(`${wallet}/req?txid=${txid}&status=${status}`, { method: 'POST' }).then(r => r.json())
  const submits = async () => (await (await fetch(`${wallet}/submits`)).json()).submits
  const finds = async txid => (await (await fetch(`${wallet}/finds?txid=${txid}`)).json()).finds
  const renewal = prefix => db.prepare('SELECT * FROM renewals WHERE prefix = ?').bind(prefix).first()
  const grantOf = prefix => db.prepare('SELECT state, status, expiry_time FROM payment_grants WHERE prefix = ?').bind(prefix).first()
  const waiting = async () => (await db.prepare("SELECT r.prefix FROM renewals r LEFT JOIN payment_grants g ON g.prefix = r.prefix WHERE (r.advert = 'not_admitted' AND (r.queued_until IS NULL OR r.queued_until <= unixepoch())) OR (r.outcome = 'no_word' AND r.advert IS NULL AND g.state = 'paid') OR (r.outcome = 'served' AND g.state = 'paid')").all()).results.map(r => r.prefix)
  const bucket = await mf.getR2Bucket('UHRP_FILES', 'storage')
  const objects = async () => {
    const listed = await bucket.list({ limit: 1000 })
    return listed.objects.map(o => `${o.key} ${o.etag} ${o.uploaded.getTime()}`).sort()
  }
  const objectsBefore = await objects()

  // The race's rows: the advert the queue's four deliveries left, the
  // renewal whose answer was lost (now taken) and the one not taken (now a
  // double spend).
  const queued = (await db.prepare("SELECT prefix FROM renewals WHERE advert = 'not_admitted'").all()).results
  assert.equal(queued.length, 1, JSON.stringify(queued))
  const lost = unserved.find(u => u.word === 'lost')
  const untaken = unserved.find(u => u.word === 'untaken')
  const prefixOf = async txid => (await db.prepare('SELECT prefix FROM payment_grants WHERE txid = ?').bind(txid).first()).prefix
  const [lostPrefix, untakenPrefix] = [await prefixOf(lost.paymentTxid), await prefixOf(untaken.paymentTxid)]
  assert.deepEqual(new Set(await waiting()), new Set([queued[0].prefix, lostPrefix, untakenPrefix]))
  await setReq(lost.renewingTxid, 'unmined')
  await setReq(untaken.renewingTxid, 'doubleSpend')
  const [s0, fl0, fu0] = [await submits(), await finds(lost.renewingTxid), await finds(untaken.renewingTxid)]
  await runPass()
  assert.equal((await renewal(queued[0].prefix)).advert, 'admitted')
  const lostRow = await renewal(lostPrefix)
  assert.deepEqual([lostRow.outcome, lostRow.advert], ['served', 'admitted'])
  assert.deepEqual(await grantOf(lostPrefix), { state: 'granted', status: 200, expiry_time: lost.expiry })
  assert.equal((await renewal(untakenPrefix)).outcome, 'not_made')
  assert.equal((await grantOf(untakenPrefix)).state, 'paid')
  assert.equal(await submits(), s0 + 2)
  assert.deepEqual([await finds(lost.renewingTxid), await finds(untaken.renewingTxid)], [fl0 + 1, fu0 + 1])
  assert.deepEqual(await waiting(), [])
  await runPass()
  assert.equal(await submits(), s0 + 2)
  assert.deepEqual([await finds(lost.renewingTxid), await finds(untaken.renewingTxid)], [fl0 + 1, fu0 + 1])
  log("the pass on the race's rows: the advert the queue's four deliveries left admitted; the lost answer's renewal, now taken: granted (status 200, its expiry), its advert admitted, in the same run; the untaken one, now a double spend: not_made, the grant paid; 2 submits and 1 wallet question each; a second run: nothing")

  // Rows written for the pass.
  let n = 0
  const row = async (o) => {
    const prefix = `pass-${++n}`
    await db.prepare("INSERT INTO renewals (prefix, payment_txid, renewing_txid, outcome, advert, runs, reason, new_expiry_time, advert_beef, queued_until, queue_tries, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, 'YmVlZg==', ?8, 0, ?9, 1)")
      .bind(prefix, `pay-${n}`, o.txid ?? `renewing-${n}`, o.outcome ?? 'served', o.advert ?? null, o.runs ?? 0, 1_950_000_000, o.queuedUntil ?? null, o.createdAt ?? n).run()
    await db.prepare("INSERT INTO payment_grants (prefix, txid, route, identity_key, satoshis, paid_at, state) VALUES (?1, ?2, '/renew', 'k', 1000, 0, ?3)")
      .bind(prefix, `pay-${n}`, o.grant ?? (o.outcome === 'no_word' ? 'paid' : 'granted')).run()
    return prefix
  }
  const end = async prefixes => { for (const p of prefixes) await db.prepare("UPDATE renewals SET advert = 'admitted', outcome = 'served' WHERE prefix = ?").bind(p).run() }

  // The cap: 25 adverts waiting, none with runs, oldest first, 20 a run.
  {
    const rows = []
    for (let i = 0; i < 25; i++) rows.push(await row({ advert: 'not_admitted', createdAt: 1000 + i }))
    const s = await submits()
    await runPass()
    assert.equal(await submits(), s + 20)
    const states = []
    for (const p of rows) states.push((await renewal(p)).advert)
    assert.deepEqual(states, [...Array(20).fill('admitted'), ...Array(5).fill('not_admitted')])
    await runPass()
    assert.equal(await submits(), s + 25)
    log('the pass, 25 adverts waiting: a run submits the 20 oldest (admitted), the next run the other 5')
  }

  // The overlay down: 20 submits, each counted; then no more than 20 a run.
  {
    await knob('overlay=fault')
    const rows = []
    for (let i = 0; i < 25; i++) rows.push(await row({ advert: 'not_admitted', createdAt: 2000 + i }))
    const s = await submits()
    await runPass()
    assert.equal(await submits(), s + 20)
    const runs = []
    for (const p of rows) runs.push((await renewal(p)).runs)
    assert.deepEqual(runs, [...Array(20).fill(1), ...Array(5).fill(0)])
    assert.equal((await renewal(rows[0])).reason, 'HTTP 503')
    // The next run takes the 5 with fewer runs first, then 15 of the rest.
    await runPass()
    assert.equal(await submits(), s + 40)
    const again = []
    for (const p of rows) again.push((await renewal(p)).runs)
    assert.deepEqual(again, [...Array(15).fill(2), ...Array(5).fill(1), ...Array(5).fill(1)])
    await knob('overlay=')
    await end(rows)
    log('the pass with the overlay down: 25 adverts waiting, 20 submits in the run, each a fault counted (runs 1, reason HTTP 503), 5 left; the next run takes those 5 first (fewest runs), then the 15 oldest of the rest')
  }

  // The endings of an advert waiting: a refusal (never submitted again), and
  // the 72nd run (stopped).
  {
    const refusedRow = await row({ advert: 'not_admitted', createdAt: 3000 })
    await knob('overlay=refuse')
    let s = await submits()
    await runPass()
    await knob('overlay=')
    const r = await renewal(refusedRow)
    assert.equal(r.advert, 'refused')
    assert.equal(r.reason, 'HTTP 400: script verification failed (subject t): input 0: the stand-in overlay refuses this spend')
    assert.equal(await submits(), s + 1)
    await runPass()
    assert.equal(await submits(), s + 1)
    const tired = await row({ advert: 'not_admitted', runs: 71, createdAt: 3001 })
    await knob('overlay=fault')
    s = await submits()
    await runPass()
    assert.deepEqual([(await renewal(tired)).advert, (await renewal(tired)).runs], ['stopped', 72])
    await runPass()
    await knob('overlay=')
    assert.equal(await submits(), s + 1)
    log("the pass's endings for an advert: the overlay's refusal (refused, its reason kept, never submitted again); a fault at the 72nd run (stopped, runs 72, tried no more)")
  }

  // The endings of a renewal with no word: no word (counted), then a take
  // (granted, its advert admitted); a failure (not_made); the 72nd run.
  {
    const word = await row({ outcome: 'no_word', txid: 'word-1', createdAt: 4000 })
    const failed = await row({ outcome: 'no_word', txid: 'word-2', createdAt: 4001 })
    const tired = await row({ outcome: 'no_word', txid: 'word-3', runs: 71, createdAt: 4002 })
    await setReq('word-1', 'unsent')
    await setReq('word-2', 'invalid')
    await runPass()
    assert.deepEqual([(await renewal(word)).outcome, (await renewal(word)).runs], ['no_word', 1])
    assert.equal((await renewal(failed)).outcome, 'not_made')
    assert.equal((await grantOf(failed)).state, 'paid')
    assert.deepEqual([(await renewal(tired)).advert, (await renewal(tired)).runs], ['stopped', 72])
    await setReq('word-1', 'completed')
    const s = await submits()
    await runPass()
    assert.deepEqual([(await renewal(word)).outcome, (await renewal(word)).advert], ['served', 'admitted'])
    assert.deepEqual(await grantOf(word), { state: 'granted', status: 200, expiry_time: 1_950_000_000 })
    assert.equal(await submits(), s + 1)
    const f3 = await finds('word-3')
    await runPass()
    assert.equal(await finds('word-3'), f3)
    log("the pass's endings for no word: unsent (counted, runs 1), then completed (granted, status 200, its expiry; its advert admitted in the same run); invalid (not_made, the grant paid); the 72nd run (stopped, asked no more)")
  }

  // A served row whose grant's second write did not land: the pass sets the
  // grant granted, and submits nothing for it.
  {
    const seam = await row({ advert: 'admitted', grant: 'paid', createdAt: 4500 })
    const s = await submits()
    await runPass()
    assert.deepEqual(await grantOf(seam), { state: 'granted', status: 200, expiry_time: 1_950_000_000 })
    assert.equal(await submits(), s)
    assert.deepEqual(await waiting(), [])
    log("the pass on a served row whose grant reads paid: the grant granted (status 200, the row's expiry), no submit")
  }

  // Rows of other kinds, and a row still on the queue: left alone.
  {
    const alone = [
      await row({ advert: 'admitted' }),
      await row({ advert: 'refused' }),
      await row({ advert: 'stopped' }),
      await row({ outcome: 'not_made' }),
      await row({ outcome: 'no_word', grant: 'granted' }),
      await row({ advert: 'not_admitted', queuedUntil: 4_000_000_000 }),
    ]
    const s = await submits()
    await runPass()
    assert.equal(await submits(), s)
    for (const p of alone) assert.equal((await renewal(p)).updated_at, 1, p)
    log('the pass leaves alone: admitted, refused, stopped, not_made, a no-word row whose grant is not paid, and an advert still on the queue')
  }

  assert.deepEqual(await objects(), objectsBefore)
  log(`the pass touched no stored object (${objectsBefore.length} objects: the same keys, etags and upload times)`)
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
