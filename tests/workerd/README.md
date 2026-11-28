# The paid routes' store and the Worker on workerd (Miniflare)

Fully local: Miniflare runs workerd with local D1, KV and R2, nothing leaves
the process, and Miniflare is disposed on every exit path. No deploy.

- `kit/` mounts `src/claims.rs` as it is and exposes the store over HTTP on
  workerd's D1 (`CLAIMS`, migrated from `../../migrations`) and KV
  (`AUTH_SESSIONS`); `BROKEN` is a D1 binding with no table, bound as
  `CLAIMS` for the kit's fault law.
- `wallet/` stands in for what the storage Worker fetches: the wallet
  storage server (BRC-103/104 through the middleware's `process_auth`;
  `makeAvailable`, `findOrInsertUser`, `internalizeAction`, which it counts
  per transaction and can be told to fail; for `/renew`, `listOutputs`,
  `createAction`, `processAction`, `abortAction` and `findProvenTxReqs`
  over an advert the race client seeds, with its stored object in the R2
  bucket the Worker reads, which it moves to the renewal's transaction and
  counts; its knobs, `/knob?create=&process=&overlay=`, make `createAction`
  refuse as a spent advert does or answer a template the Worker cannot
  sign, `processAction` refuse, fail, lose its answer or leave the
  transaction untaken, and the overlay refuse or fault), the overlay's
  `/submit` and `/lookup`, and the exchange rate.
- `../parity`'s `race` binary is the client of the Worker stage.

`node run.mjs store` runs the middleware's conformance kit against the store
as the routes wire it (the D1 claim, the key-value record read in front and
written after a win), at the kit's defaults and at raised bounds (sizes 2 to
64, a hold of 128 passes; its fault law on the Worker's store and the
middleware's gate with `BROKEN` bound as `CLAIMS`); the release path's four mixes (a release of an
unheld prefix started with claims by several transactions; two releases with
a re-take between them; a release of a prefix never claimed; a release
racing the record's write); the middleware's answers to a refused claim; both
directions against the key-value store's own claim (`KvPrefixStore`),
releases on either side included; and
N = 2, 8, 32 simultaneous claims; and a carried release freeing only its
own claim (a `released:<txid>` record met at once by its transaction and by
others, six mixes of 40 rounds).

`node run.mjs worker` runs the storage Worker built from this tree (the
consumer of the post-upload queue), beside a build of v0.3.0, the release
that keeps its prefixes in the key-value namespace, sharing that namespace
(`OLD_BUILD`, a `build/worker` directory), with `wallet/` behind both: one payment in 2, 4
and 16 simultaneous `/upload` requests (one service, every other the signed
409); two transactions under one prefix at once (one service, the other the
signed 400); a prefix either build served refused by the other; a wallet
error's release (the same transaction served on its retry, once, no other),
made on this build, on the old build before this one (another transaction
here the signed 400, the released transaction served here once, then the
signed 409), and on this build before the old one (the old build serves the
released transaction once and refuses another; back here the prefix is
refused); a wallet rejection (the door's 402 with a fresh challenge, then
the signed 409); a paid `/renew` (one renewal; the same payment again the
signed 409 and the expiry unchanged; another transaction under the prefix
the signed 400; one payment in 2, 4 and 16 simultaneous requests one
renewal); `/renew`'s outcomes: an advert whose stored object is missing
or of another size (a free 404 `ERR_FILE_NOT_FOUND`, nothing claimed),
served with the overlay admitting (the stored object's etag and upload
time unchanged), refusing (never submitted again) and faulting (the
queue's re-submit, four deliveries), not made at `createAction` after the
one more try, at the signature (the action released) and at
`processAction` (the signed 500 `ERR_RENEWAL_NOT_MADE`), no word (the
signed 502 `ERR_RENEWAL_UNCONFIRMED`), and two payers of one file at once,
both served; the grants and renewals rows recorded in `CLAIMS`, each
`/renew` row read against what the client was served and each `/upload`
row's expiry against the custom-time it was served; the hourly pass (the
scheduled handler, fired by hand): the race's waiting rows, each ending of
each kind, the cap of 20 oldest first, a run with the overlay down, rows of
other kinds left alone, no stored object touched; and the Worker without its `CLAIMS` binding and
with the binding and no tables (two more Workers of the same build): a
payment to `/upload` or `/renew` is the gate's signed 503
`ERR_PAYMENT_UNAVAILABLE`, nothing served, the wallet not asked; and, on
the Worker with no tables, a prefix with a key-value record the door's
unsigned 503, except the transaction a `released:<txid>` record names,
which is the gate's signed 503; and a carried release freeing only its
own claim: a prefix the previous release's Worker released, paid here at
once by the released transaction and by others (six mixes, 12 rounds
each), the released transaction served at most once and no other.

The race client reads every answer with its signature's verdict (a BRC-104
signature that verifies against the server's identity key for the session):
the 200, the 402 challenge, the 409, the 400 `ERR_PAYMENT_INVALID` and the
gate's 503 are signed; the door's own answers (a malformed payment header's
400, a wallet error's 400, a wallet rejection's 402, the 503 for a fault the
store meets outside the gate) are not.

    # worker-build 0.8.4, --release, in kit/, wallet/, the repository root
    # and a checkout of v0.3.0
    cargo build --locked -p parity --bin race
    npm ci
    node run.mjs store
    OLD_BUILD=<v0.3.0>/build/worker RACE_BIN=<target>/debug/race node run.mjs worker

The `workerd` job of `.github/workflows/ci.yml` runs these steps on the
hosted runner.
