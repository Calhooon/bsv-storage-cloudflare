-- The CLAIMS database (binding CLAIMS): the payment prefixes the paid routes
-- claim (the middleware's payment_claims table, PAYMENT_CLAIMS_SCHEMA as it
-- is), and what each won claim was granted (payment_grants).
-- Applied before the deploy: wrangler d1 migrations apply CLAIMS --remote
CREATE TABLE IF NOT EXISTS payment_claims (nonce TEXT PRIMARY KEY, agent TEXT, created_at INTEGER, txid TEXT, released INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS payment_grants (prefix TEXT PRIMARY KEY, txid TEXT NOT NULL, route TEXT NOT NULL, identity_key TEXT NOT NULL, satoshis INTEGER NOT NULL, paid_at INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'paid', status INTEGER, object_identifier TEXT, uhrp_url TEXT, file_size INTEGER, minutes INTEGER, expiry_time INTEGER, answered_at INTEGER);
