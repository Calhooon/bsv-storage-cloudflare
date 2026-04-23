# Parity testbed — canonical @bsv/overlay-express, local

Docker-compose + Node server that boots a hermetic
`@bsv/overlay-express` instance at `http://localhost:8080`. Used by
the parity harness to prove SHIP/SLAP admission without depending on
any remote overlay staying up.

## Why this exists

`tests/parity/src/overlay_live.rs::live_ship_advert_admitted_by_users_bapp_dev`
needs a canonical `@bsv/overlay-express` endpoint to submit SHIP
advertisements to and observe `outputsToAdmit`. The public hubs
(`users.bapp.dev`, various project overlays) regularly have upstream
infra events (MongoDB migrations, cluster moves) that leave their
`/lookup` returning `getaddrinfo ENOTFOUND`. When that happens, we
can't tell if our adverts are being rejected or just silently
dropped by a broken DB write.

Running the testbed removes that class of failure entirely: canonical
TS code, pinned versions, in-container storage, nothing external can
break it.

## One-time setup

```bash
cd tests/parity/overlay-express-testbed
npm ci
```

## Run

```bash
# Start MongoDB (background)
docker compose up -d

# Boot the overlay (foreground)
npm start
```

You should see:

```
parity-testbed constructed 🎉
🔗 Network set to main
🔗 ChainTracker has been configured.
📦 Knex successfully configured.
🍃 MongoDB successfully configured and connected.
🗂️ Configured topic manager tm_ship
🗂️ Configured topic manager tm_slap
🔍 Configured lookup service ls_ship
🔍 Configured lookup service ls_slap
...
[parity-testbed] ready at http://localhost:8080
[parity-testbed] admin token: parity-testbed-admin-token
```

Sanity check:

```bash
curl -s http://localhost:8080/listTopicManagers | jq .
# { "tm_ship": {...}, "tm_slap": {...} }
```

## Run the Rust parity test against it

```bash
cd ../..          # back to tests/parity
PARITY_OVERLAY_URL=http://localhost:8080 \
  cargo test live_ship_advert_admitted_by_users_bapp_dev \
  -- --ignored --nocapture
```

Expected: the test constructs a SHIP advert, funds it via MetaNet
Client, submits to the local overlay, and asserts at least one output
is in `outputsToAdmit`. If the local overlay admits our bytes, we're
byte-compatible with the canonical TS stack at the admission-policy
layer — the strongest parity claim in the repo.

## Stop + wipe

```bash
# Ctrl-C the `npm start` process
docker compose down -v    # removes mongo container + its tmpfs volume
```

## Version pinning

`package.json` pins:

| Package | Version | Matches |
|---|---|---|
| `@bsv/sdk` | `1.10.1` | nanostore.babbage.systems + users.bapp.dev |
| `@bsv/overlay` | `0.6.0` | same |
| `@bsv/overlay-discovery-services` | `^0.1.16` | canonical SHIPTopicManager + SLAPTopicManager |

When nanostore bumps their deployed versions, bump these first, run
the Layer-1 golden generator (`tests/parity/ts-fixtures/generate.mjs`)
against the new version, and confirm the parity bytes still match
before promoting any downstream Rust changes.

## Ports

- `8080` — overlay HTTP (configurable via `PORT` env var)
- `27018` — local MongoDB (avoids clashing with a default `27017`
  you may have running for other projects)

## Troubleshooting

**`MongoNetworkError: connect ECONNREFUSED`** — MongoDB container
isn't up. `docker compose up -d` and wait 2-3 seconds.

**`Error: Unable to verify SPV information`** on submit — the
`scripts only` chain tracker config isn't being picked up. Confirm
`server.mjs` line `server.configureChainTracker('scripts only')` is
present and the console log `🔗 ChainTracker has been configured.`
appeared during boot.

**`EADDRINUSE :::8080`** — port in use. Set `PORT=8090 npm start`
and add `PARITY_OVERLAY_URL=http://localhost:8090` to your Rust
test invocation.
