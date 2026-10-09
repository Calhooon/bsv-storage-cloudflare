# bsv-storage-cloudflare

UHRP file-storage server on Cloudflare Workers. Rust/WASM.

Protocol-compatible Rust port of [`@bsv/uhrp-storage-server`](https://github.com/bsv-blockchain/storage-server)
(a.k.a. [nanostore.babbage.systems](https://nanostore.babbage.systems)).
HTTP request/response shapes, UHRP hash derivation, PushDrop advertisement
encoding, and public file URLs are byte-for-byte identical to the TS original —
clients switch with zero code changes.

Backs storage with Cloudflare R2 instead of Google Cloud Storage; replaces the
GCP notifier Cloud Function with a Cloudflare Queue consumer.

## Pricing

Protocol-compatible ≠ price-identical. This deployment sets its own rates:

| | This deployment | nanostore |
|---|---|---|
| `PRICE_PER_GB_MO` | $0.05 | $0.03 |
| Minimum sat price per upload | 1000 | 10 |
| Fallback exchange rate | 15 USD/BSV | 30 USD/BSV |

The higher `PRICE_PER_GB_MO` pockets R2's zero-egress advantage as margin. The
1000-sat minimum covers the ~500-sat overlay broadcast miner fee that every
upload incurs. See [`PROTOCOL.md §D`](./PROTOCOL.md#d-pricing-formula) for the
formula.

See [`PROTOCOL.md`](./PROTOCOL.md) for the wire spec and [`CLAUDE.md`](./CLAUDE.md)
for architecture, bindings, and quality gates.

## Quickstart

```bash
npm install
./scripts/install-hooks.sh   # pre-commit quality gate
npm run dev                  # local worker on :8787
```

## Status

Scaffold only. Routes return `501 ERR_NOT_IMPLEMENTED`. See open tasks.
