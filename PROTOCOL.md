# UHRP Storage Server – Wire Protocol Specification

**Version**: 2.0 (from TS nanostore.babbage.systems)  
**Date**: 2025-04-20  
**SDK Dependencies**: @bsv/sdk ^2.0.7, @bsv/auth-express-middleware ^2.0.4, @bsv/payment-express-middleware ^2.0.1

---

## Overview

This document specifies the exact wire-level protocol for the UHRP file-storage server (also known as nanostore.babbage.systems). It is required reading for any port to a different language or runtime (e.g., Cloudflare Workers in Rust).

The server implements **6 routes** across two security tiers:
- **Pre-auth (unauthenticated)**: `/quote`, `/advertise`
- **Post-auth (BRC-31 authenticated)**: `/upload`, `/find`, `/list`, `/renew`

For `/upload` and `/renew`, the client must also prove payment via BRC-29 (`@bsv/payment-express-middleware`).

---

## Route Specifications

### 1. `/quote` (POST, unauthenticated)

**Purpose**: Returns satoshi price for hosting a file at a given size and retention period.

**Request**
```json
{
  "fileSize": number,        // Bytes, required, positive integer
  "retentionPeriod": number  // Minutes, required, positive integer
}
```

**Query Parameters**: None  
**Headers**: None (beyond standard HTTP)  
**Authentication**: Not required (unauthenticated)

**Response on Success** (HTTP 200)
```json
{
  "quote": number  // Satoshis (integer, minimum MIN_SATOSHI_PRICE — 1000 on this deployment, 10 on nanostore)
}
```

**Response on Error** (HTTP 400 or 500)
```json
{
  "status": "error",
  "code": "ERR_NO_SIZE" | "ERR_INVALID_SIZE" | "ERR_NO_RETENTION_PERIOD" | "ERR_INVALID_RETENTION_PERIOD" | "ERR_INTERNAL",
  "description": "Human-readable error message"
}
```

**Validation Rules**
- `fileSize`: Must be integer, must be > 0
- `retentionPeriod`: Must be integer, must be >= MIN_HOSTING_MINUTES (env var), must be <= 69,000,000 minutes (~130 years)

**Side Effects**
- HTTP call to `https://api.whatsonchain.com/v1/bsv/main/exchangerate` to fetch BSV/USD (fallback: 15 USD/BSV on this deployment if API fails; nanostore uses 30)
- No persistence, no blockchain writes

**Pricing Formula** (line refs: `src/utils/getPriceForFile.ts:16–56`)
```
fileSizeGB = fileSize / 1,000,000,000
retentionPeriodMonths = retentionPeriod / (60 * 24 * 30)
usdPrice = fileSizeGB * retentionPeriodMonths * PRICE_PER_GB_MO

exchangeRate = whatsOnChain.rate  # USD/BSV
exchangeRateInSatoshis = 1 / (exchangeRate / 100,000,000)

satPrice = max(MIN_SATOSHI_PRICE, floor(usdPrice * exchangeRateInSatoshis))
```

**Constants** (this deployment; nanostore legacy values in parens)
- `PRICE_PER_GB_MO`: Environment variable (USD per GB per month). This deployment: **0.05** (nanostore: 0.03)
- Minimum satoshi price: **1000** (nanostore: 10). Covers the ~500-sat overlay broadcast miner fee with margin.
- Fallback exchange rate: **15 USD/BSV** (nanostore: 30) if whatsOnChain fails

**Line References**
- Route handler: `src/routes/quote.ts:22–88`
- Price calculation: `src/utils/getPriceForFile.ts:16–56`

---

### 2. `/upload` (POST, BRC-31 authenticated, BRC-29 payment required)

**Purpose**: Allocates a 16-byte random `objectIdentifier`, returns a GCS presigned PUT URL and required headers, and calculates the payment amount due.

**Request**
```json
{
  "fileSize": number,        // Bytes, required, positive integer
  "retentionPeriod": number  // Minutes, required, positive integer
}
```

**Query Parameters**: None  
**Headers**: 
- `Authorization` (BRC-31, from authfetch middleware; sets `req.auth.identityKey`)  
- BRC-29 payment proof headers (from payment middleware; middleware validates based on calculated satPrice)

**Authentication**: BRC-31 required (via `@bsv/auth-express-middleware`)  
**Payment**: BRC-29 required (via `@bsv/payment-express-middleware`); satoshis = result of `/quote` with same fileSize + retentionPeriod

**Response on Success** (HTTP 200)
```json
{
  "status": "success",
  "uploadURL": "string",        // GCS presigned PUT URL (valid 7 days)
  "requiredHeaders": {
    "x-goog-meta-uploaderidentitykey": "string",  // The BRC-31 identityKey
    "x-goog-custom-time": "ISO-8601 timestamp"    // Expiry as ISO string
  },
  "amount": number,             // Satoshis due (same as /quote)
  "description": "File can now be uploaded."
}
```

**Response on Error** (HTTP 400 or 500)
```json
{
  "status": "error",
  "code": "ERR_MISSING_IDENTITY_KEY" | "ERR_INVALID_SIZE" | "ERR_NO_RETENTION_PERIOD" | "ERR_INVALID_RETENTION_PERIOD" | "ERR_INTERNAL_UPLOAD",
  "description": "Human-readable error message"
}
```

**Validation Rules**
- `fileSize`: Must be integer, must be > 0, must be <= 11,000,000,000 bytes (~10.2 GB)
- `retentionPeriod`: Must be positive integer >= MIN_HOSTING_MINUTES
- `req.auth.identityKey`: Must be present (set by auth middleware)

**Side Effects**
1. Generates random 16-byte `objectIdentifier` (encoded base58): `Utils.toBase58(Array.from(crypto.randomBytes(16)))`
2. Calculates `expiryTime` (Unix seconds): `(retentionPeriod * 60) + Math.round(Date.now() / 1000)`
3. Calls GCS API to generate presigned PUT URL with extension headers
4. **No blockchain write yet** — that happens in `/advertise` after file is uploaded
5. **No GCS file created yet** — client must PUT the file to `uploadURL` with the required headers

**URL & Header Construction** (line refs: `src/utils/getUploadURL.ts:33–73`)
```
customTime = new Date((expiryTime + 300) * 1000).toISOString()  // +300 seconds buffer
uploadURL = bucketFile.getSignedUrl({
  version: 'v4',
  action: 'write',
  expires: Date.now() + 604000 * 1000,  // 1 week from now
  extensionHeaders: {
    'x-goog-meta-uploaderidentitykey': uploaderIdentityKey,
    'x-goog-custom-time': customTime
  }
})
```

**Line References**
- Route handler: `src/routes/upload.ts:29–98`
- URL generation: `src/utils/getUploadURL.ts:33–73`

**Rust-port hardening deviation (the-composer #43)**: the R2 presigned PUT
additionally signs `content-length = fileSize`, and `requiredHeaders` gains a
third `content-length` entry. The TS reference signs nothing about body size,
so a client could pay for `fileSize=1` and PUT up to 11 GB; with the size in
`X-Amz-SignedHeaders`, R2 rejects any PUT whose `Content-Length` differs from
the quoted-and-paid byte count. Wire shape is otherwise unchanged (parity
fixtures treat `requiredHeaders` as a volatile string map).

---

### 3. `/find` (GET, BRC-31 authenticated)

**Purpose**: Looks up metadata for a file by its UHRP URL.

**Request**
```
GET /find?uhrpUrl=uhrp://...
```

**Query Parameters**
- `uhrpUrl` (required): The UHRP URL, e.g. `uhrp://abc123def456` (exact format defined in cross-cutting spec A)

**Request Body**
```json
{
  "limit": number,   // Optional, defaults to 200
  "offset": number   // Optional, defaults to 0
}
```

**Headers**: 
- `Authorization` (BRC-31, sets `req.auth.identityKey`)

**Authentication**: BRC-31 required

> **Documented divergence from nanostore.babbage.systems** — verified
> 2026-04-21. The TS reference mounts `/find` in the `postAuth` routes
> list (`storage-server/src/routes/index.ts:17`), but its auth middleware
> is configured with `allowUnauthenticated: true`
> (`storage-server/src/index.ts:98`). Net effect on the deployed server:
> an unauthenticated GET `/find?uhrpUrl=…` is accepted and reaches the
> handler with an empty `identityKey`, which then scopes the tag query
> to `uploader_identity_key_` (empty string) — effectively returning no
> results, surfaced as a generic `ERR_FIND` 500.
>
> Our CF Worker middleware (`process_auth` at `src/lib.rs:63`) is
> configured with `allow_unauthenticated: false`, so unauthenticated
> callers are rejected at the middleware layer with `401
> ERR_UNAUTHORIZED` before the handler runs. This is intentional: the
> stricter posture gives clearer error codes (401 vs 500) and avoids
> the small-but-real probe surface of letting any caller touch the
> metadata path. Callers that expect public `/find` must authenticate;
> the functional answer (no data for unknown identities) is identical.
>
> This divergence is NOT a parity bug — it's a security-first deviation
> we are choosing to keep. If a future integration requires byte-exact
> response parity (not just semantic), flip `allow_unauthenticated`
> to `true` at `src/lib.rs:63` and handle `identityKey == ""` inside
> each route handler. All routes already contain the defensive
> `if identity_key.is_empty()` check, so the change is localised.

**Response on Success** (HTTP 200)
```json
{
  "status": "success",
  "data": {
    "name": "string",              // File path in GCS, e.g., "cdn/abc123def456"
    "size": "string",              // File size in bytes as string, e.g., "4096"
    "mimeType": "string",          // Content-Type from GCS metadata, e.g., "application/octet-stream"
    "expiryTime": number           // Unix seconds when file expires
  }
}
```

**Response on Error** (HTTP 400, 404, or 500)
```json
{
  "status": "error",
  "code": "ERR_MISSING_IDENTITY_KEY" | "ERR_NO_UHRP_URL" | "ERR_NOT_FOUND" | "ERR_FIND",
  "description": "Human-readable error message"
}
```

**Validation Rules**
- `uhrpUrl` (query param): Required, non-empty string
- `req.auth.identityKey`: Required (set by auth middleware)

**Side Effects**
1. Queries wallet (`listOutputs`) for outputs in basket `'uhrp advertisements'` matching both:
   - Tag: `uhrp_url_{hexEncodedUrl}`
   - Tag: `uploader_identity_key_{identityKey}`
2. Finds output with highest (most recent) `expiryTime`
3. Extracts `objectIdentifier` from tag `object_identifier_{hexEncoded}`
4. Fetches GCS metadata for file `cdn/{objectIdentifier}`
5. **No write**

**Lookup Flow** (line refs: `src/utils/getMetadata.ts:26–80`)
```
outputs = wallet.listOutputs({
  basket: 'uhrp advertisements',
  tags: [
    `uhrp_url_${Utils.toHex(Utils.toArray(uhrpUrl, 'utf8'))}`,
    `uploader_identity_key_${uploaderIdentityKey}`
  ],
  tagQueryMode: 'all',
  includeTags: true,
  limit, offset
})

# Find output with max expiryTime
for each output:
  expiryTag = output.tags.find(t => t.startsWith('expiry_time_'))
  expiryNum = parseInt(expiryTag.substring('expiry_time_'.length), 10)
  if expiryNum > maxpiry:
    maxpiry = expiryNum
    objectIdentifier = extract from output.tags['object_identifier_*']

# Fetch GCS metadata
gcsMetadata = storage.bucket(GCP_BUCKET_NAME).file(`cdn/${objectIdentifier}`).getMetadata()
```

**Line References**
- Route handler: `src/routes/find.ts:34–79`
- Metadata lookup: `src/utils/getMetadata.ts:26–80`

---

### 4. `/list` (GET, BRC-31 authenticated)

**Purpose**: Lists all UHRP advertisements (files) belonging to the authenticated user.

**Request**
```
GET /list
```

**Query Parameters**: None

**Request Body**
```json
{
  "limit": number,   // Optional, defaults to 200
  "offset": number   // Optional, defaults to 0
}
```

**Headers**: 
- `Authorization` (BRC-31, sets `req.auth.identityKey`)

**Authentication**: BRC-31 required

**Response on Success** (HTTP 200)
```json
{
  "status": "success",
  "uploads": [
    {
      "uhrpUrl": "string",        // e.g., "uhrp://abc123def456"
      "expiryTime": number        // Unix seconds
    }
  ]
}
```

**Response on Error** (HTTP 400 or 500)
```json
{
  "status": "error",
  "code": "ERR_MISSING_IDENTITY_KEY" | "ERR_LIST",
  "description": "Human-readable error message"
}
```

**Validation Rules**
- `req.auth.identityKey`: Required (set by auth middleware)
- `limit`: Defaults to 200 if not provided
- `offset`: Defaults to 0 if not provided

**Side Effects**
1. Queries wallet for outputs in basket `'uhrp advertisements'` with tag: `uploader_identity_key_{identityKey}`
2. Iterates outputs and extracts:
   - `uhrpUrl` from tag `uhrp_url_{hexEncoded}` (decoded from hex to UTF-8)
   - `expiryTime` from tag `expiry_time_{seconds}` (parsed as base-10 integer)
3. Filters out expired items (if `expiryTime * 1000 < Date.now()`)
4. **No write**

**Listing Flow** (line refs: `src/routes/list.ts:26–87`)
```
outputs = wallet.listOutputs({
  basket: 'uhrp advertisements',
  tags: [`uploader_identity_key_${identityKey}`],
  includeTags: true,
  limit, offset
})

result = []
for each output in outputs:
  uhrpUrlTag = output.tags.find(t => t.startsWith('uhrp_url_'))
  expiryTimeTag = output.tags.find(t => t.startsWith('expiry_time_'))
  
  uhrpUrl = Utils.toUTF8(Utils.toArray(uhrpUrlTag.substring('uhrp_url_'.length), 'hex'))
  expiryTime = parseInt(expiryTimeTag.substring('expiry_time_'.length), 10)
  
  if Date.now() <= expiryTime * 1000:  // Not expired
    result.push({ uhrpUrl, expiryTime })
```

**Line References**
- Route handler: `src/routes/list.ts:26–87`

---

### 5. `/renew` (POST, BRC-31 authenticated, BRC-29 payment required)

**Purpose**: Extends the expiry time of an existing advertisement by consuming the old output and creating a new one with updated expiry.

**Request**
```json
{
  "uhrpUrl": "string",            // UHRP URL of the file to renew, required
  "additionalMinutes": number,    // Minutes to add to expiry, required, positive
  "limit": number,                // Optional, defaults to 200
  "offset": number                // Optional, defaults to 0
}
```

**Query Parameters**: None  
**Headers**: 
- `Authorization` (BRC-31, sets `req.auth.identityKey`)  
- BRC-29 payment proof (validated by middleware; satoshis = result of pricing file for `additionalMinutes`)

**Authentication**: BRC-31 required  
**Payment**: BRC-29 required; satoshis = `getPriceForFile({ fileSize: sizeFromAdvertisement, retentionPeriod: additionalMinutes })`

**Response on Success** (HTTP 200)
```json
{
  "status": "success",
  "prevExpiryTime": number,       // Previous expiry (Unix seconds)
  "newExpiryTime": number,        // New expiry after renewal (Unix seconds)
  "amount": number                // Satoshis charged
}
```

**Response on Error** (HTTP 400, 404, or 500)
```json
{
  "status": "error",
  "code": "ERR_MISSING_IDENTITY_KEY" | "ERR_MISSING_FIELDS" | "ERR_INVALID_TIME" | "ERR_OLD_ADVERTISEMENT_NOT_FOUND" | "ERR_CREATE_ACTION_FAILED" | "ERR_SIGNING_OLD_ADVERTISEMENT" | "ERR_INTERNAL_RENEW",
  "description": "Human-readable error message"
}
```

**Validation Rules**
- `uhrpUrl`: Required, non-empty string
- `additionalMinutes`: Required, must be positive integer (> 0)
- `req.auth.identityKey`: Required

**Side Effects**
1. Fetches metadata (objectIdentifier, size, prevExpiryTime) by querying advertisements with `uhrpUrl` + `identityKey` tags
2. Looks up **old output** in the wallet: outputs tagged with `uhrp_url_{hex}` + `object_identifier_{hex}`, retrieves its transaction from BEEF
3. **Extracts PushDrop fields** from old output's locking script (5 fields: pubkey, hash, url, expiryTime, contentLength)
4. **Creates new PushDrop output** with same fields[0–2] and fields[4], but updates fields[3] = `newExpiryTime` (VarInt encoded)
5. **Creates blockchain action**: 
   - Input: old advertisement output (unlocking via PushDrop)
   - Output: new advertisement output (1 satoshi, basket `'uhrp advertisements'`)
6. **Signs and broadcasts** transaction via SHIP broadcaster (topic: `'tm_uhrp'`)
7. **Updates GCS metadata**: Sets `customTime` on file `cdn/{objectIdentifier}` to new expiry (ISO-8601)

**Renewal Flow** (line refs: `src/routes/renew.ts:34–229`)
```
# 1. Fetch current metadata
{ objectIdentifier, size, expiryTime: prevExpiryTime } = getMetadata(uhrpUrl, identityKey)

# 2. Calculate new expiry
newExpiryTimeSeconds = prevExpiryTime + (additionalMinutes * 60)

# 3. Calculate price
amount = getPriceForFile({ fileSize: parseInt(size), retentionPeriod: additionalMinutes })

# 4. Fetch old advertisement output
{ outputs, BEEF } = wallet.listOutputs({
  basket: 'uhrp advertisements',
  tags: [
    `uhrp_url_${Utils.toHex(Utils.toArray(uhrpUrl, 'utf8'))}`,
    `object_identifier_${Utils.toHex(Utils.toArray(objectIdentifier, 'utf8'))}`
  ],
  tagQueryMode: 'all',
  includeTags: true,
  include: 'entire transactions',
  limit, offset
})

# 5. Find output with max expiryTime
prevAdvertisement = outputs.reduce((maxOut, out) => {
  expiryTag = out.tags.find(t => t.startsWith('expiry_time_'))
  expiryNum = parseInt(expiryTag.substring('expiry_time_'.length), 10)
  return expiryNum > maxpiry ? out : maxOut
})

# 6. Parse old locking script
parsedTx = Transaction.fromBEEF(BEEF, prevTxid)
prevLockingScript = parsedTx.outputs[outputIndex].lockingScript
{ fields: prevFields } = PushDrop.decode(prevLockingScript)

# 7. Build new fields (same as old, except index 3)
fields = [
  prevFields[0],                                                    // Server pubkey
  prevFields[1],                                                    // Hash
  prevFields[2],                                                    // URL
  new Utils.Writer().writeVarIntNum(newExpiryTimeSeconds).toArray(), // NEW expiry
  prevFields[4]                                                     // Content length
]

# 8. Create new locking script
newLockingScript = pushdrop.lock(
  fields,
  [2, 'uhrp advertisement'],
  '1',
  'anyone',
  true
)

# 9. Create & broadcast action
signableTransaction = wallet.createAction({
  inputBEEF: BEEF,
  inputs: [{
    outpoint: prevAdvertisement.outpoint,
    unlockingScriptLength: 74,
    inputDescription: 'Redeeming old advertisement'
  }],
  outputs: [{
    lockingScript: newLockingScript.toHex(),
    satoshis: 1,
    basket: 'uhrp advertisements',
    tags: [
      `uploader_identity_key_${uploaderIdentityKey}`,  // Preserve
      `uhrp_url_${Utils.toHex(Utils.toArray(uhrpUrl, 'utf8'))}`,
      `object_identifier_${Utils.toHex(Utils.toArray(objectIdentifier, 'utf8'))}`,
      `expiry_time_${newExpiryTimeSeconds}`
    ]
  }],
  options: { randomizeOutputs: false }
})

# 10. Sign via PushDrop
unlocker = pushdrop.unlock([2, 'uhrp advertisement'], '1', 'anyone')
partialTx = Transaction.fromAtomicBEEF(signableTransaction.tx)
unlockingScript = await unlocker.sign(partialTx, 0)
{ tx, txid } = await wallet.signAction({ reference, spends: { 0: { unlockingScript } } })

# 11. Broadcast
broadcaster = new SHIPBroadcaster(['tm_uhrp'], { networkPreset: BSV_NETWORK })
await broadcaster.broadcast(Transaction.fromAtomicBEEF(tx))

# 12. Update GCS
newCustomTimeIso = new Date(newExpiryTimeSeconds * 1000).toISOString()
storage.bucket(GCP_BUCKET_NAME).file(`cdn/${objectIdentifier}`).setMetadata({
  customTime: newCustomTimeIso
})
```

**Line References**
- Route handler: `src/routes/renew.ts:34–229`

---

### 6. `/advertise` (POST, admin-only)

**Purpose**: Administrative endpoint to create a new UHRP advertisement for a file. Called by internal notifier service after file is uploaded to GCS.

**Request**
```json
{
  "adminToken": "string",             // Server admin token, required
  "uhrpUrl": "string",                // UHRP URL, required
  "objectIdentifier": "string",       // 16-byte ID (base58), required
  "uploaderIdentityKey": "string",    // BRC-31 identity key, required
  "fileSize": number                  // File size in bytes, required
  "expiryTime": number                // Expiry as Unix seconds, required
}
```

**Query Parameters**: None  
**Headers**: None (beyond standard HTTP)  
**Authentication**: Admin token in request body (checked against `ADMIN_TOKEN` env var)

**Response on Success** (HTTP 200)
```json
{
  "status": "success"
}
```

**Response on Error** (HTTP 401 or 500)
```json
{
  "status": "error",
  "code": "ERR_UNAUTHORIZED" | "ERR_INTERNAL",
  "description": "Human-readable error message"
}
```

**Validation Rules**
- `adminToken`: Must match `ADMIN_TOKEN` env var exactly
- `ADMIN_TOKEN` validation: Must be string, length > 10, and match request body value

**Side Effects**
1. Calls `createUHRPAdvertisement()` utility (blocking blockchain operation):
   - Creates PushDrop locking script with 5 fields (server pubkey, hash, url, expiryTime as VarInt, contentLength as VarInt)
   - Creates wallet action with output to basket `'uhrp advertisements'` with 4 tags:
     - `uhrp_url_{hexEncodedUrl}`
     - `object_identifier_{hexEncodedObjectId}`
     - `uploader_identity_key_{identityKey}` (no hex encoding for this one)
     - `expiry_time_{unixSeconds}` (no hex encoding)
   - Signs and broadcasts via SHIP broadcaster (topic: `'tm_uhrp'`)
2. Sets GCS file metadata: `customTime` = `new Date((expiryTime + 300) * 1000).toISOString()` (+300 second buffer)
3. Returns immediately (no wait for confirmation)

**Advertisement Creation Flow** (line refs: `src/utils/createUHRPAdvertisement.ts:23–93`, `src/routes/advertise.ts:31–69`)
```
# 1. Derive hash from UHRP URL
hash = StorageUtils.getHashFromURL(uhrpUrl)

# 2. Extract server public key
key = PrivateKey.fromHex(SERVER_PRIVATE_KEY)
serverPublicKey = key.toPublicKey().toString()

# 3. Build PushDrop fields (UHRP Protocol compliance)
fields = [
  Utils.toArray(serverPublicKey, 'hex'),                    // Field 0: Host pubkey
  hash,                                                     // Field 1: Hash of content
  Utils.toArray(url, 'utf8'),                              // Field 2: URL (UTF-8)
  new Utils.Writer().writeVarIntNum(expiryTime).toArray(), // Field 3: Expiry (VarInt)
  new Utils.Writer().writeVarIntNum(contentLength).toArray() // Field 4: Size (VarInt)
]

# 4. Create locking script
lockingScript = pushdrop.lock(
  fields,
  [2, 'uhrp advertisement'],
  '1',
  'anyone',
  true
)

# 5. Create action
createResult = wallet.createAction({
  outputs: [{
    lockingScript: lockingScript.toHex(),
    satoshis: 1,
    basket: 'uhrp advertisements',
    tags: [
      `uhrp_url_${Utils.toHex(Utils.toArray(uhrpURL, 'utf8'))}`,
      `object_identifier_${Utils.toHex(Utils.toArray(objectIdentifier, 'utf8'))}`,
      `uploader_identity_key_${uploaderIdentityKey}`,       // NO hex encoding
      `expiry_time_${expiryTime}`                          // NO hex encoding
    ]
  }]
})

# 6. Sign and broadcast
transaction = Transaction.fromAtomicBEEF(createResult.tx)
broadcaster = new SHIPBroadcaster(['tm_uhrp'], { networkPreset: BSV_NETWORK })
await broadcaster.broadcast(transaction)

# 7. Update GCS metadata
storageFile.setMetadata({
  customTime: new Date((expiryTime + 300) * 1000).toISOString()
})
```

**Line References**
- Route handler: `src/routes/advertise.ts:31–69`
- Advertisement creation: `src/utils/createUHRPAdvertisement.ts:23–93`

---

## Cross-Cutting Specifications

### A. UHRP Hash Algorithm

**TL;DR**: Delegated to `@bsv/sdk/StorageUtils.getHashFromURL()` and `StorageUtils.getURLForHash()`. The SDK implements UHRP-compliant hashing, but the exact algorithm is **not exposed in the storage-server codebase**. Based on UHRP spec (implied by "UHRP Protocol" compliance comments), it is SHA-256 of the file contents, encoded in base58check.

**Usage in Code** (line refs: `src/utils/createUHRPAdvertisement.ts:31–32`, `src/routes/advertise.ts:44`)
```typescript
// From advertise.ts line 44
hash: StorageUtils.getHashFromURL(req.body.uhrpUrl)

// From createUHRPAdvertisement.ts line 31–32
if (typeof hash === 'string') {
  hash = StorageUtils.getHashFromURL(hash)
}

// Then stored in PushDrop field[1]
fields: number[][] = [
  Utils.toArray(serverPublicKey, 'hex'),  // Field 0
  hash,                                    // Field 1 <- This is the UHRP hash
  Utils.toArray(url, 'utf8'),              // Field 2
  ...
]

// And converted back to URL
const uhrpURL = StorageUtils.getURLForHash(hash)
```

**Format of UHRP URL**
- Pattern: `uhrp://` followed by base58check-encoded hash
- Example from code: `uhrp://abc123def456...` (exact prefix length unknown without SDK source)
- Decoded by `StorageUtils.getHashFromURL()` to number[] (byte array)
- Re-encoded by `StorageUtils.getURLForHash()` to string

**Storage in Tags**
- Tag key prefix: `uhrp_url_`
- Value: Hex-encoded UTF-8 bytes of the UHRP URL string
- Example: `uhrp_url_7572687073` (hex of "uhrps")

**Key Insight for Port**: 
The UHRP hash is a black box provided by `@bsv/sdk`. To port this to Rust, you **must**:
1. Implement or use a UHRP library that provides `getHashFromURL(uhrpUrl: string) -> [u8; 32]` and vice versa
2. Match the exact encoding (likely SHA-256 + base58check per UHRP spec)
3. Verify against test vectors from existing clients

---

### B. PushDrop Advertisement Encoding

**TL;DR**: The advertisement output uses PushDrop with 5 fields in strict order. Fields are byte arrays; integers are VarInt-encoded.

**PushDrop Locking Script Structure** (line refs: `src/utils/createUHRPAdvertisement.ts:40–51`)
```typescript
const fields: number[][] = [
  // Field 0: Server's public key (host identity)
  Utils.toArray(serverPublicKey, 'hex'),
  
  // Field 1: Hash of the file content (UHRP hash, as byte array)
  hash,
  
  // Field 2: URL where file can be found (UTF-8 encoded)
  Utils.toArray(url, 'utf8'),
  
  // Field 3: Expiry timestamp (Unix seconds, encoded as VarInt)
  new Utils.Writer().writeVarIntNum(expiryTimeSeconds).toArray(),
  
  // Field 4: Content length (file size in bytes, encoded as VarInt)
  new Utils.Writer().writeVarIntNum(contentLength).toArray()
]

// PushDrop action type: [2, 'uhrp advertisement']
const lockingScript = await pushdrop.lock(
  fields,
  [2, 'uhrp advertisement'],  // Action code: 2, Action name: 'uhrp advertisement'
  '1',                        // Key derivation path segment
  'anyone',                   // Unlock authorization (anyone can spend)
  true                        // Include signature in unlock
)
```

**Field Byte Encoding Reference**
| Field | Index | Type | Encoding | Example |
|-------|-------|------|----------|---------|
| Server pubkey | 0 | Public key (hex) | 33-byte compressed ECDSA pubkey | `0279...` |
| Hash | 1 | Byte array | Raw bytes (SHA-256 hash) | 32 bytes |
| URL | 2 | String | UTF-8 | `https://...` |
| Expiry time | 3 | VarInt | Bitcoin VarInt (LEB128) | Seconds as compact integer |
| Content length | 4 | VarInt | Bitcoin VarInt (LEB128) | Bytes as compact integer |

**VarInt Encoding** (used for fields 3 & 4):
- 0–252: 1 byte (the value itself)
- 253–65535: 0xfd followed by 2 little-endian bytes
- 65536–4294967295: 0xfe followed by 4 little-endian bytes
- 4294967296+: 0xff followed by 8 little-endian bytes

**Example Construction**:
```typescript
// Expire in 1 year (approx 31,536,000 seconds)
const expiryTime = 1735689600  // Example Unix timestamp
const expiryBytes = new Utils.Writer().writeVarIntNum(expiryTime).toArray()
// Result: [0x80, 0xce, 0x93, 0x06] (example, little-endian VarInt)

// File size: 1,048,576 bytes (1 MB)
const contentLength = 1048576
const sizeBytes = new Utils.Writer().writeVarIntNum(contentLength).toArray()
// Result: [0xfe, 0x00, 0x00, 0x10, 0x00] (0xfe prefix + 4 LE bytes)
```

**Renewal (Field Update)** (line refs: `src/routes/renew.ts:131–137`)
When renewing, the server:
1. Parses the old locking script: `{ fields: prevFields } = PushDrop.decode(prevLockingScript)`
2. Copies fields 0, 1, 2, 4 unchanged
3. **Replaces field 3** with new expiry time (as VarInt)
4. Re-locks with updated fields

**Tag Encoding** (separate from PushDrop fields; stored in wallet output tags):

| Tag | Encoding | Example |
|-----|----------|---------|
| `uhrp_url_*` | Hex of UTF-8 bytes | `uhrp_url_7572687078` |
| `object_identifier_*` | Hex of UTF-8 bytes | `object_identifier_616263313233` |
| `uploader_identity_key_*` | Plaintext (no hex) | `uploader_identity_key_0379abcd...` |
| `expiry_time_*` | Decimal string (no hex) | `expiry_time_1735689600` |

**Line References**
- Field construction: `src/utils/createUHRPAdvertisement.ts:40–51`
- Renewal field update: `src/routes/renew.ts:131–137`
- Tag construction: `src/utils/createUHRPAdvertisement.ts:76`

---

### C. Public URL Format

**TL;DR**: Files are served directly from GCS via a CDN load balancer. No intermediate URL translation. The upload presigned URL points to the file, and clients download directly from GCS (`/cdn/...` path).

**URL Construction** (line refs: `src/utils/getUploadURL.ts:49`, `src/routes/advertise.ts:46`)
```typescript
// In getUploadURL.ts (line 49)
const bucketFile = bucket.file(`cdn/${objectIdentifier}`)
const uploadURL = await bucketFile.getSignedUrl(...)  // GCS presigned PUT URL

// In advertise.ts (line 46)
url: `${HOSTING_DOMAIN}/cdn/${req.body.objectIdentifier}`
// Example: https://storage.example.com/cdn/abc123def456xyz

// This URL is stored in PushDrop field[2]
```

**Download Path**
- Path pattern: `https://{HOSTING_DOMAIN}/cdn/{objectIdentifier}`
- Routing via load balancer (line refs: `README.md:276–281`):
  - Host rule: `*` path `/cdn/*` → backend bucket (GCS)
  - All other paths → Cloud Run (API)
- GCS file stored at: `gs://{GCP_BUCKET_NAME}/cdn/{objectIdentifier}`

**Metadata Headers** (set during upload)
```
x-goog-meta-uploaderidentitykey: {identityKey}  // Custom metadata header
x-goog-custom-time: {ISO-8601 timestamp}         // GCS lifecycle expiry
```

**Example Flow**
1. Client calls `/upload` → receives `uploadURL` (GCS presigned PUT) and `requiredHeaders`
2. Client PUTs file to `uploadURL` with headers:
   ```
   PUT {uploadURL}
   Content-Length: {fileSize}
   x-goog-meta-uploaderidentitykey: 0379abcd...
   x-goog-custom-time: 2025-05-01T12:00:00Z
   
   [binary file data]
   ```
3. GCS stores file at `gs://my-bucket/cdn/{objectIdentifier}`
4. Internal notifier calls `/advertise` (admin-only) to create blockchain advertisement
5. User can now download: `GET https://storage.example.com/cdn/{objectIdentifier}`
   - Load balancer routes to backend bucket
   - GCS serves file with metadata headers

**Line References**
- URL construction: `src/utils/getUploadURL.ts:49`
- Advertisement URL: `src/routes/advertise.ts:46`
- Load balancer routing: `README.md:276–281`

---

### D. Pricing Formula

**TL;DR**: Price = max(MIN_SATOSHI_PRICE, floor(USD price * exchange rate in sats)). Exchange rate from whatsOnChain; fallback to 15 USD/BSV on this deployment (nanostore uses 30) if API fails. MIN_SATOSHI_PRICE is 1000 on this deployment (nanostore: 10).

**Formula** (line refs: `src/routes/quote.rs:179–197`; mirrors TS `src/utils/getPriceForFile.ts:16–56`)
```javascript
// Parameters — worked example uses this deployment's defaults
const PRICE_PER_GB_MO = parseFloat(process.env.PRICE_PER_GB_MO)  // 0.05 USD/GB/month here
const MIN_SATOSHI_PRICE = 1000                                    // this deployment; nanostore: 10
const fileSize = 1_000_000                                        // Bytes
const retentionPeriod = 1440                                      // Minutes (1 day)

// Step 1: Convert file size to GB
const fileSizeGB = fileSize / 1_000_000_000
// Result: 0.001 GB

// Step 2: Convert retention period to months
const retentionPeriodMonths = retentionPeriod / (60 * 24 * 30)
// = 1440 / 43200 = 0.0333... months

// Step 3: Calculate USD price
const usdPrice = fileSizeGB * retentionPeriodMonths * PRICE_PER_GB_MO
// = 0.001 * 0.0333 * 0.05 = 0.00000167 USD

// Step 4: Fetch exchange rate
const exchangeRate = whatsOnChain.rate  // USD per BSV (e.g., 15)
// Fallback: 15 if API fails (this deployment); nanostore falls back to 30

// Step 5: Convert exchange rate to satoshis per USD
const exchangeRateInSatoshis = 1 / (exchangeRate / 100_000_000)
// = 1 / (15 / 100_000_000) = 100_000_000 / 15 = 6_666_666.67 sats/USD

// Step 6: Calculate satoshi price
const satPrice = Math.max(MIN_SATOSHI_PRICE, Math.floor(usdPrice * exchangeRateInSatoshis))
// = max(1000, floor(0.00000167 * 6_666_666.67)) = max(1000, 11) = 1000 sats (minimum)
```

**Constants & Environment Variables**

| Constant | This deployment | nanostore | Source | Purpose |
|----------|-----------------|-----------|--------|---------|
| `PRICE_PER_GB_MO` | 0.05 | 0.03 | env var | Monthly USD price per GB |
| `MIN_HOSTING_MINUTES` | 15 | 15 | env var | Minimum retention period (minutes) |
| Minimum satoshi price | 1000 | 10 | hardcoded | Floor; covers overlay broadcast miner fee |
| Maximum retention | 69,000,000 minutes | same | hardcoded | ~130 years |
| Exchange rate API | whatsOnChain | same | https://api.whatsonchain.com/v1/bsv/main/exchangerate | Live BSV/USD |
| Exchange rate fallback | 15 USD/BSV | 30 USD/BSV | hardcoded | If API fails |

**Example Prices** (this deployment: PRICE_PER_GB_MO = 0.05, exchange rate fallback = 15 USD/BSV)

| File Size | Retention | USD Price | Sats |
|-----------|-----------|-----------|------|
| 1 MB (1e6 bytes) | 1 day (1440 min) | ~0.0000017 | 1,000 (min) |
| 100 MB (1e8 bytes) | 1 month (43200 min) | 0.005 | 33,333 |
| 1 GB (1e9 bytes) | 1 year (525600 min) | 0.608 | 4,055,555 |
| 10 GB (1e10 bytes) | 1 year | 6.083 | 40,555,555 |

**Line References**
- Price calculation: `src/utils/getPriceForFile.ts:16–56`
- Quote route (uses above): `src/routes/quote.ts:78–79`
- Upload payment: `src/index.ts:105–114` (middleware calls `getPriceForFile`)
- Renew payment: `src/index.ts:115–125`

---

### D.1 Service Discovery

`GET /.well-known/x402-info` is public, unpaid and unsigned. Dispatch occurs
before the BRC-103/104 adapter, with the same CORS headers as `/health`.
A configured service returns status 200, `Content-Type: application/json`
and `Cache-Control: public, max-age=300`.

The JSON has `name`, `description`, `authProtocol` (`brc-103/104`),
`authEndpoint` (`/.well-known/auth`), `serverIdentityKey`, `capabilities`,
`endpoints`, `pricing` and `publicUrlFormat`. The name comes from
`SERVICE_NAME` (default `bsv-storage-cloudflare`); the identity is the
compressed public key derived from `SERVER_PRIVATE_KEY`, with no private
material in the response. A discovery identity is an unsigned hint for the
authenticated protocol, not a signed discovery document.

Each of the seven endpoint entries has `method`, `path`, `description`,
`auth`, `payment` and `delivery: "instant"`. Health lists `/health` and
describes `/` as an alias. Health and quote require neither auth nor payment.
Upload and renew require auth and advertise payment with `protocol: "brc-29"`,
`dynamic: true`, `transport: "header-only"` and the 402 retry flow. Find,
list and advertise require auth and have `payment: null`; advertise also
checks the admin allowlist. Any authenticated identity may pay for renewal.
Capabilities report BRC-103/104 auth, BRC-29 payment, `refunds: false` and
header-only payment, including the note that body payment is unsupported.

Pricing reports `model: "per-GB-month"`, `currency: "USD"`, `margin: "0%"`,
`PRICE_PER_GB_MO`, `bsv_usd`, `rates`, `formula`, `formula_notes`, `examples`,
`note`, and these bounds:

| Key | Source and enforcement |
|---|---|
| `minimum_satoshis` | Shared `quote::MIN_SATOSHI_PRICE`, 1,000. |
| `minimum_retention_minutes` | `MIN_HOSTING_MINUTES`, using quote's parser; missing, unparseable or NaN values yield zero. |
| `maximum_file_size_bytes`, `maximum_file_size_human` | Shared `upload::MAX_UPLOAD_BYTES`, 11,000,000,000 bytes; enforced by `/upload`. |
| `maximum_retention_minutes`, `maximum_retention_human` | Shared `quote::MAX_RETENTION_MINUTES`, 69,000,000 minutes; enforced by `/quote`. |

`src/validation.rs` contains no validators. Quote requires integer, positive
file sizes and integer, nonzero retention; upload has a size cap but no
integer-retention check or maximum-retention check. These existing differences
are described in the manifest rather than introducing new validation.

`bsv_usd` comes from one call to the quote's WhatsOnChain fetch per discovery
request, with the same 15 USD/BSV fallback on failure or an invalid rate.
The source and fallback are named in `pricing.note`. `rates.USD_per_GB_month`
equals `PRICE_PER_GB_MO`; `margin` adds no multiplier. Each of `1_MB_1_year`,
`10_MB_1_year`, `100_MB_1_year` and `1_GB_1_year` contains `usd` and `satoshis`
computed by the quote's helpers for 525,600 minutes. USD is the amount before
the satoshi minimum. The rate is a trusted external price, not chain evidence.

`publicUrlFormat` has `pattern` and `note`. The pattern is the configured
`PUBLIC_URL_BASE`, with trailing slashes removed, followed by
`/cdn/{base58id}`. The upload helper substitutes the last segment of the
object key in `uploadURL`. The identifier encodes 16 random bytes; it is
separate from the UHRP content hash. Public bytes are available after the
object upload. No deployment hostname is embedded by the discovery builder.

The fallback JSON fixture is `tests/fixtures/manifest/fallback.json`.
Native unit tests inject the exchange rate, derive a public key from an
in-memory test scalar, and compare the full JSON to that fixture. Route
source checks guard dispatch before auth, CORS, one rate fetch, and headers.
There is no Worker HTTP harness for health or discovery; status and actual
edge header behavior require the keeper's runtime gate.

---

### E. Output Tags on Advertisement Outputs

**TL;DR**: 4 tags per advertisement output. Three use hex encoding for values; one (uploader identity) does not.

**Tag Format**

| Tag | Prefix | Value Encoding | Example | Parsed By |
|-----|--------|-----------------|---------|-----------|
| UHRP URL | `uhrp_url_` | Hex of UTF-8 bytes | `uhrp_url_7572687078616263` | `/find`, `/list` (hex→UTF-8) |
| Object ID | `object_identifier_` | Hex of UTF-8 bytes | `object_identifier_616263313233` | `/find`, `/list`, `/renew` (hex→UTF-8) |
| Uploader key | `uploader_identity_key_` | Plaintext (hex pubkey) | `uploader_identity_key_0379abcd...` | `/list`, `/find` (exact match query) |
| Expiry time | `expiry_time_` | Decimal string | `expiry_time_1735689600` | `/list`, `/find`, `/renew` (parse base-10) |

**Tag Construction** (line refs: `src/utils/createUHRPAdvertisement.ts:76`)
```typescript
const tags = [
  `uhrp_url_${Utils.toHex(Utils.toArray(uhrpURL, 'utf8'))}`,
  `object_identifier_${Utils.toHex(Utils.toArray(objectIdentifier, 'utf8'))}`,
  `uploader_identity_key_${uploaderIdentityKey}`,
  `expiry_time_${expiryTimeSeconds}`
]
```

**Tag Parsing Examples**

```typescript
// Parsing uhrp_url tag
const uhrpUrlTag = 'uhrp_url_7572687078616263'
const hexPart = uhrpUrlTag.substring('uhrp_url_'.length)  // '7572687078616263'
const bytesArray = Utils.toArray(hexPart, 'hex')           // [117, 114, 104, 112, ...]
const uhrpUrl = Utils.toUTF8(bytesArray)                  // 'urhpxabc'

// Parsing object_identifier tag
const objTag = 'object_identifier_616263313233'
const hexPart = objTag.substring('object_identifier_'.length)
const bytesArray = Utils.toArray(hexPart, 'hex')
const objectId = Utils.toUTF8(bytesArray)  // 'abc123'

// Parsing expiry_time tag
const expiryTag = 'expiry_time_1735689600'
const expiryNum = parseInt(expiryTag.substring('expiry_time_'.length), 10)  // 1735689600

// Parsing uploader_identity_key tag
const uploaderTag = 'uploader_identity_key_0379abcd...'
const identityKey = uploaderTag.substring('uploader_identity_key_'.length)  // '0379abcd...'
// (no conversion needed)
```

**Tag Query Operations** (line refs: `src/routes/list.ts:43`, `src/routes/find.ts:30`, `src/routes/renew.ts:84`)

```typescript
// Query 1: Find by uploader key (list all files for user)
wallet.listOutputs({
  basket: 'uhrp advertisements',
  tags: [`uploader_identity_key_${identityKey}`],
  tagQueryMode: 'any'  // Or 'all' if multiple tags
})

// Query 2: Find by UHRP URL + uploader key (find specific file for user)
wallet.listOutputs({
  basket: 'uhrp advertisements',
  tags: [
    `uhrp_url_${Utils.toHex(Utils.toArray(uhrpUrl, 'utf8'))}`,
    `uploader_identity_key_${identityKey}`
  ],
  tagQueryMode: 'all'  // Must match both tags
})

// Query 3: Find by UHRP URL + object ID (for renewal, no user filter)
wallet.listOutputs({
  basket: 'uhrp advertisements',
  tags: [
    `uhrp_url_${Utils.toHex(Utils.toArray(uhrpUrl, 'utf8'))}`,
    `object_identifier_${Utils.toHex(Utils.toArray(objectIdentifier, 'utf8'))}`
  ],
  tagQueryMode: 'all'
})
```

**Basket Name** (constant across all operations)
```typescript
basket: 'uhrp advertisements'  // Literal string
```

**Line References**
- Tag construction: `src/utils/createUHRPAdvertisement.ts:76`
- List tag extraction: `src/routes/list.ts:54–63`
- Find tag parsing: `src/utils/getMetadata.ts:43–51`
- Renewal tag queries: `src/routes/renew.ts:84`

---

## Authentication & Authorization

### BRC-31 Authentication

**Middleware**: `@bsv/auth-express-middleware` v2.0.4

**Flow**
1. Client includes authorization header (exact format: BRC-31)
2. Middleware validates signature and extracts `identityKey` (hex-encoded public key)
3. Sets `req.auth.identityKey` for use in route handlers
4. All authenticated routes check for presence of `req.auth.identityKey` and return 400 if missing

**Routes Requiring BRC-31**
- `/upload` (POST)
- `/find` (GET)
- `/list` (GET)
- `/renew` (POST)

**Routes NOT Requiring BRC-31**
- `/quote` (POST) — unauthenticated
- `/advertise` (POST) — admin token only

### BRC-29 Payment

**Middleware**: `@bsv/payment-express-middleware` v2.0.1

**Flow**
1. Client includes BRC-29 payment proof in request
2. Middleware calculates expected satoshi cost using `calculateRequestPrice` callback
3. Validates that payment covers the cost
4. If payment valid, proceeds; otherwise returns 402 Payment Required

**Routes Requiring BRC-29**
- `/upload` (POST) — price = `getPriceForFile(fileSize, retentionPeriod)`
- `/renew` (POST) — price = `getPriceForFile(fileSize from advertisement, additionalMinutes)`

**Price Calculation** (line refs: `src/index.ts:103–129`)
```typescript
const paymentMiddleware = createPaymentMiddleware({
  wallet,
  calculateRequestPrice: async (req) => {
    if (req.url === '/upload') {
      const { fileSize, retentionPeriod } = req.body
      return getPriceForFile({ fileSize, retentionPeriod })
    }
    if (req.url === '/renew') {
      const { uhrpUrl, additionalMinutes } = req.body
      const { size } = await getMetadata(uhrpUrl, req.auth.identityKey)
      return getPriceForFile({ fileSize: +size, retentionPeriod: additionalMinutes })
    }
    return 0
  }
})
```

---

## Error Handling

### Standard Error Response Format
```json
{
  "status": "error",
  "code": "ERROR_CODE",
  "description": "Human-readable message"
}
```

### HTTP Status Codes
| Code | Meaning | Typical Error Codes |
|------|---------|-------------------|
| 200 | Success | — |
| 400 | Bad request (validation, missing auth) | `ERR_INVALID_SIZE`, `ERR_MISSING_FIELDS`, `ERR_MISSING_IDENTITY_KEY` |
| 401 | Unauthorized (admin auth failed) | `ERR_UNAUTHORIZED` |
| 402 | Payment required | (returned by middleware, not routes) |
| 404 | Not found (file doesn't exist) | `ERR_NOT_FOUND`, `ERR_OLD_ADVERTISEMENT_NOT_FOUND` |
| 500 | Internal server error | `ERR_INTERNAL`, `ERR_INTERNAL_UPLOAD`, `ERR_INTERNAL_RENEW` |

### Error Codes by Route

**`/quote`**
- `ERR_NO_SIZE`
- `ERR_NO_RETENTION_PERIOD`
- `ERR_INVALID_SIZE`
- `ERR_INVALID_RETENTION_PERIOD`
- `ERR_INTERNAL`

**`/upload`**
- `ERR_MISSING_IDENTITY_KEY`
- `ERR_INVALID_SIZE`
- `ERR_NO_RETENTION_PERIOD`
- `ERR_INVALID_RETENTION_PERIOD`
- `ERR_INTERNAL_UPLOAD`

**`/find`**
- `ERR_MISSING_IDENTITY_KEY`
- `ERR_NO_UHRP_URL`
- `ERR_NOT_FOUND`
- `ERR_FIND`

**`/list`**
- `ERR_MISSING_IDENTITY_KEY`
- `ERR_LIST`

**`/renew`**
- `ERR_MISSING_IDENTITY_KEY`
- `ERR_MISSING_FIELDS`
- `ERR_INVALID_TIME`
- `ERR_OLD_ADVERTISEMENT_NOT_FOUND`
- `ERR_CREATE_ACTION_FAILED`
- `ERR_SIGNING_OLD_ADVERTISEMENT`
- `ERR_INTERNAL_RENEW`

**`/advertise`**
- `ERR_UNAUTHORIZED`
- `ERR_INTERNAL`

---

## Environment Variables (Required for All Operations)

| Variable | Default | Type | Purpose |
|----------|---------|------|---------|
| `SERVER_PRIVATE_KEY` | (required) | hex string (32 bytes) | Server identity key for signing advertisements |
| `PRICE_PER_GB_MO` | (required) | float | Monthly USD price per GB |
| `MIN_HOSTING_MINUTES` | 0 | integer | Minimum retention period (minutes) |
| `BSV_NETWORK` | (required) | `'mainnet'` \| `'testnet'` | Bitcoin SV network |
| `ADMIN_TOKEN` | (required) | string (>10 chars) | Admin token for `/advertise` |
| `GCP_BUCKET_NAME` | (required) | string | Google Cloud Storage bucket name |
| `GCP_PROJECT_ID` | (required) | string | GCP project ID |
| `GCP_STORAGE_CREDS` | (required) | JSON string | GCP service account key (JSON) |
| `HOSTING_DOMAIN` | (required) | URL | Public domain for downloads (e.g., `https://storage.example.com`) |
| `WALLET_STORAGE_URL` | (required) | URL | Wallet toolbox storage server URL |
| `HTTP_PORT` | 8080 | integer | Port to listen on |
| `NODE_ENV` | (required) | `'production'` \| `'staging'` | Environment |

---

## Middleware Stack & Request Flow

**Route Registration Order** (line refs: `src/index.ts:49–147`):

1. **Pre-auth unauthenticated routes** (no HTTPS required):
   - `/quote` (POST)
   - `/advertise` (POST) — admin token check only

2. **HTTPS redirect** (enforce secure connection)

3. **Pre-auth authenticated routes** (HTTPS + optional auth):
   - (none in current implementation; all post-auth routes require both auth & payment)

4. **Auth middleware** (BRC-31):
   - Validates signature, extracts `identityKey`, allows unauthenticated pass-through

5. **Payment middleware** (BRC-29):
   - Calculates price per route
   - Validates payment proof
   - Blocks if insufficient payment

6. **Post-auth routes** (HTTPS + BRC-31 + BRC-29):
   - `/upload` (POST)
   - `/find` (GET)
   - `/list` (GET)
   - `/renew` (POST)

---

## Notes for Rust Port

1. **UHRP Hash**: The hash algorithm is opaque (provided by @bsv/sdk). Ensure your port uses a compatible UHRP implementation or re-implements SHA-256 + base58check exactly as spec'd.

2. **VarInt Encoding**: Bitcoin-style LEB128 integers used for expiry and content length in PushDrop fields. Test against test vectors.

3. **PushDrop Format**: The locking script structure is strict: 5 fields in order, action code [2, 'uhrp advertisement'], anyone-unlock. Use a PushDrop library for Rust (if available) or implement from the spec.

4. **Tag Encoding**: Hex encoding for values but NOT for uploader_identity_key. This asymmetry is deliberate and must be preserved.

5. **Wallet Integration**: Requires a working wallet interface to:
   - `listOutputs()` with tag filtering
   - `createAction()` and `signAction()` with basket routing
   - SHIP broadcast capability

6. **GCS Integration**: If keeping GCS backend, the presigned URL generation, custom metadata headers, and bucket structure are all GCS-specific. R2 or other backends will require adaptation.

7. **Payment Middleware**: The payment calculation (price based on file size + retention) must be synchronized between client and server. No server-side cache; always recalculate.

8. **Exchange Rate**: Fetched live from whatsOnChain. If porting to Rust, decide whether to cache or fetch fresh per request.

9. **Expiry Buffer**: GCS file expiry is set to `expiryTime + 300` seconds (5-minute buffer). This is a deliberate safeguard.

10. **Renewal UTXO Handling**: The `/renew` route assumes a single output per file, but comments indicate "TODO handle edge case with multiple outputs". Decide how to handle this (e.g., pick highest expiry, error, or merge).

---

## Test Vectors & Examples

### Example: Quote Calculation
```
Request:
{
  "fileSize": 1000000,
  "retentionPeriod": 1440
}

Calculation (this deployment: PRICE_PER_GB_MO=0.05, fallback exchange rate=15, MIN_SATOSHI_PRICE=1000):
fileSizeGB = 1000000 / 1e9 = 0.001
retentionMonths = 1440 / 43200 = 0.0333
usdPrice = 0.001 * 0.0333 * 0.05 = 0.00000167
exchangeRateSats = 1 / (15 / 1e8) = 6666666.67
satPrice = max(1000, floor(0.00000167 * 6666666.67)) = max(1000, 11) = 1000

Response:
{
  "quote": 1000
}
```

### Example: Upload Request & Response
```
Request (POST /upload, with BRC-31 auth header):
{
  "fileSize": 5000000,
  "retentionPeriod": 10080
}

Response:
{
  "status": "success",
  "uploadURL": "https://storage.googleapis.com/bucket/cdn/abc123?signature=...",
  "requiredHeaders": {
    "x-goog-meta-uploaderidentitykey": "0379abcdef...",
    "x-goog-custom-time": "2025-05-10T12:00:00.000Z"
  },
  "amount": 42,
  "description": "File can now be uploaded."
}
```

### Example: List Response
```
GET /list (BRC-31 authenticated)

Response:
{
  "status": "success",
  "uploads": [
    {
      "uhrpUrl": "uhrp://abc123def456",
      "expiryTime": 1735689600
    },
    {
      "uhrpUrl": "uhrp://xyz789uvw012",
      "expiryTime": 1735776000
    }
  ]
}
```

---

## References

- **@bsv/sdk**: https://github.com/bitcoin-sv/bsv-sdk/
- **@bsv/auth-express-middleware**: https://github.com/bitcoin-sv/auth-express-middleware
- **@bsv/payment-express-middleware**: https://github.com/bitcoin-sv/payment-express-middleware
- **UHRP Spec**: (assumed public, referenced as "UHRP Protocol" in comments)
- **PushDrop Protocol**: (part of BSV SDK, referenced for locking script structure)
- **VarInt Format**: Bitcoin protocol (Satoshi Nakamoto, 2008)

---

**Document generated**: 2025-04-20  
**Source codebase**: `/Users/johncalhoun/bsv/storage-server/` (TS v0.2.1)  
**Target port**: Cloudflare Workers (Rust)
