-- 0.3.4: what each paid /renew's renewing step came to (renewals): the
-- renewing transaction, its outcome (served, not_made, no_word), the renewed
-- advert's admission by the overlay (admitted, not_admitted, refused,
-- stopped) with the runs of the hourly pass and the overlay's reason, the
-- advert's bytes to submit again, and the index the pass reads rows in.
-- Additive: no statement touches payment_claims or payment_grants.
-- Applied before the deploy: wrangler d1 migrations apply CLAIMS --remote
CREATE TABLE IF NOT EXISTS renewals (prefix TEXT PRIMARY KEY, payment_txid TEXT NOT NULL, renewing_txid TEXT, outcome TEXT NOT NULL, advert TEXT, runs INTEGER NOT NULL DEFAULT 0, reason TEXT, new_expiry_time INTEGER, advert_beef TEXT, queued_until INTEGER, queue_tries INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS renewals_by_age ON renewals (created_at, prefix);
