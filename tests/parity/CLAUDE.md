# Parity harness

Rust CLI that diffs our Cloudflare Worker's JSON responses against the
reference TS server (`nanostore.babbage.systems`) byte-for-byte. Guardrails
the protocol port.

## Layout

```
tests/parity/
├── Cargo.toml              # native-only crate; not compiled to wasm
├── .identity.json          # gitignored, chmod 600 — test BRC-31 identity
├── .captures.log           # gitignored forensic log of capture runs
├── fixtures/               # one JSON file per (route, scenario)
│   ├── quote.small-file.json
│   ├── find.nonexistent-uhrp-url.json
│   ├── find.missing-query-param.json
│   ├── find.malformed-uhrp-url.json
│   ├── list.my-adverts.json
│   ├── upload.upload-small-file.json
│   ├── advertise.advertise-already-uploaded.json
│   └── renew.renew-our-advert.json
└── src/
    ├── main.rs             # CLI: identity / capture / diff
    ├── auth.rs             # (stub) BRC-31 client hook point — see below
    ├── canon.rs            # JCS + $VOLATILE:<type>$ sentinel matcher
    ├── diff.rs             # unified-diff-ish renderer
    ├── fixture.rs          # on-disk fixture schema + write-if-changed
    ├── identity.rs         # persistent test identity (bsv-rs PrivateKey)
    ├── routes/             # one module per HTTP route
    │   ├── mod.rs
    │   ├── quote.rs
    │   ├── find.rs
    │   ├── list.rs
    │   ├── upload.rs
    │   ├── advertise.rs
    │   └── renew.rs
    └── bin/
        ├── keygen.rs       # emit a fresh test keypair to stdout
        └── uhrp_url.rs     # bytes → UHRP URL (stdin → stdout)
```

## CLI

```bash
cargo run -p parity --bin parity -- identity
cargo run -p parity --bin parity -- capture --route /quote [--scenario <name>]
cargo run -p parity --bin parity -- diff    --route /find  [--scenario <name>]
```

CI runs `diff` across all 6 routes with each route's default scenario. The
block reads exactly:

```yaml
- name: parity — all routes
  env:
    PARITY_IDENTITY_KEY: ${{ secrets.PARITY_IDENTITY_KEY }}
    PARITY_REFERENCE_URL: https://nanostore.babbage.systems
    PARITY_LOCAL_URL:     https://your-worker.your-account.workers.dev
  run: |
    set -e
    for route in /quote /find /list /upload /advertise /renew; do
      cargo run -p parity --bin parity -- diff --route "$route"
    done
```

## Scenario matrix (Item 3 deliverable)

| Route       | Scenario                   | Live-fire | Notes |
|-------------|----------------------------|-----------|-------|
| `/quote`    | `small-file`               | yes       | Byte-exact against nanostore (task #0). |
| `/find`     | `nonexistent-uhrp-url`     | deferred  | Error path; needs BRC-31 auth in harness. |
| `/find`     | `missing-query-param`      | deferred  | Error path; needs BRC-31 auth in harness. |
| `/find`     | `malformed-uhrp-url`       | deferred  | Error path; needs BRC-31 auth in harness. |
| `/list`     | `my-adverts`               | deferred  | Shape-equal via `$VOLATILE:array$` on `uploads`. |
| `/upload`   | `upload-small-file`        | deferred  | Ours-only (nanostore 413s our 65KB payment header). |
| `/advertise`| `advertise-already-uploaded` | deferred | Ours-only (nanostore admin is private). |
| `/renew`    | `renew-our-advert`         | deferred  | Ours-only + needs spendable admin UTXOs. |

`deferred` scenarios ship their fixture as a contract document; `diff` runs
a shape/syntax check against the on-disk fixture and emits a `SKIPPED` line
but exits 0, so CI iterates all six routes without red-flagging known-unwired
ones. Removing a scenario's `skip_reason` flips it into live-fire mode without
any other code change.

## `$VOLATILE:<type>$` sentinel

Contract fixtures pin response **shape**, not response values. When a field's
content is time-dependent (BSV/USD rate, expiry timestamps, randomly-generated
URLs, txids), writing a literal value would force us to re-capture on every
rate move. Instead, fixtures substitute:

```json
{"quote": "$VOLATILE:u64$"}
```

At `diff` time, `canon::volatile_aware_equal` typechecks the live value
against the declared kind and ignores the specific content.

### Supported kinds

| Kind       | Live value must be |
|------------|--------------------|
| `u64`, `satoshis` | JSON number parseable as `u64` (non-negative integer) |
| `i64`      | JSON number parseable as `i64` |
| `number`   | Any JSON number |
| `string`   | Any JSON string |
| `bool`     | JSON `true` or `false` |
| `iso8601`  | String of the form `YYYY-MM-DDTHH:MM:SS[.NNN]Z` |
| `hex32`    | Lowercase hex, 32 chars (16 bytes) |
| `hex64`    | Lowercase hex, 64 chars (32 bytes — e.g. txid, sha256) |
| `hex66`    | Lowercase hex, 66 chars (33 bytes — compressed secp256k1 pubkey) |
| `uhrp_url` | String starting with `uhrp://` followed by a non-empty body |
| `array`    | Any JSON array (length + element types not constrained) |
| `object`   | Any JSON object (key set not constrained) |
| `null`     | JSON `null` |

Unknown kind names are a hard error (fixture bug), not a silent pass. Add new
kinds in `canon::VolatileKind`.

### When to use which

- **Prefer a literal** (`200`, `"ERR_FIND"`, `"success"`) wherever the value
  is a stable protocol constant. That pins the contract.
- **Use `$VOLATILE:<kind>$`** only for fields whose content genuinely varies
  run-to-run. Typing the variation (e.g. `$VOLATILE:hex64$` vs
  `$VOLATILE:string$`) keeps the contract as strict as possible.
- **Never use `$VOLATILE:array$` or `$VOLATILE:object$` at the top level** of
  a response — that reduces the diff to "server responded with JSON", which
  is too weak to catch a regression.

### Scoped semantics

Sentinels only apply when **comparing against the on-disk fixture**:

- Fixture ↔ reference: volatile-aware. `$VOLATILE` positions accept any
  type-matched value.
- Fixture ↔ local: volatile-aware, same rules.
- Reference ↔ local: **byte-exact JCS equality**. Both sides are live, so any
  drift is real drift.

## Capturing a new scenario

1. Add a `Scenario { … }` entry under `src/routes/<route>.rs`.
2. Run `cargo run -p parity --bin parity -- capture --route <route> --scenario <name>`.
3. Hand-edit the fixture to introduce `$VOLATILE:<kind>$` where the captured
   value is dynamic — common targets: timestamps, quotes, URLs with session
   tokens, txids.
4. Run `cargo run -p parity --bin parity -- diff --route <route> --scenario <name>`
   once against nanostore + once against a fresh capture to confirm the
   sentinels hold.

## Identity

The harness needs a stable BRC-31 identity for authenticated routes. Source
of truth (first hit wins):

1. `PARITY_IDENTITY_KEY` env var — hex-encoded 32-byte secp256k1 private key.
2. `.identity.json` on disk (chmod 600). Auto-generated on first run.
3. Generate fresh + persist to disk.

Never logs the private key. The CI workflow sets `PARITY_IDENTITY_KEY` from
the `PARITY_IDENTITY_KEY` repo secret.

## Quality gates

The parity crate is exempt from the repo's wasm32 target — it's native Rust
that makes real HTTP calls. It is still subject to:

- `#![forbid(unsafe_code)]`
- No `.unwrap()` / `.expect()` outside `#[cfg(test)]` (clippy-warned)
- `cargo test -p parity` must pass
- `cargo fmt` + `cargo clippy` clean under the workspace config

## Open follow-ups

- Wire BRC-31 auth in `src/auth.rs`: use `bsv_rs::auth::Peer` +
  `SimplifiedFetchTransport`. Once in place, flip `skip_reason` to `None`
  on `/find`'s three scenarios + `/list`'s one. Items 8b or 19, TBD.
- Wire BRC-29 payment — same pattern. Required for `/upload` and `/renew`.
- Wire admin identity reuse so `/advertise` can hit our worker as the
  admin. Requires coordinating `ADMIN_IDENTITY_KEYS` + harness identity.
