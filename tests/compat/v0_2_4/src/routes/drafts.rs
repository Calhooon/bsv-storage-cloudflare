//! /drafts — score-draft sync for the Composer (composer-storage instance).
//!
//! NOT part of nanostore parity: these routes serve
//! github.com/Calgooon/the-composer (issue #16) and exist only on
//! deployments that bind the `COMPOSER_DRAFTS` KV namespace
//! (`wrangler.composer.toml`). On deployments without the binding every
//! `/drafts*` request answers the same 404 the catch-all produced before
//! this module existed, so the primary (nanostore-parity) worker is
//! behaviorally unchanged.
//!
//! # Surface (all behind BRC-103/104 mutual auth, responses signed)
//!
//! | Method | Path          | Success                                            |
//! |--------|---------------|----------------------------------------------------|
//! | GET    | /drafts       | 200 `{drafts:[{id,title,updatedAt,sectionCount,partCount}]}` sorted `updatedAt` desc, ≤ 200 rows |
//! | GET    | /drafts/:id   | 200 `{id,title,updatedAt,state}` / 404             |
//! | PUT    | /drafts/:id   | 200 `{"status":"success"}` upsert / 409 stored draft as body / 410 deleted / 413 caps |
//! | DELETE | /drafts/:id   | 200 `{"status":"success"}` (idempotent)            |
//!
//! # Deletion tombstones (the-composer #27) — contract for the app client
//!
//! Without tombstones, deleted drafts resurrect: KV `list()` lags writes by
//! up to ~60 s, so a sync pass inside that window pulls the stale summary
//! back — permanently — and a stale device pushing its old copy re-creates
//! the draft outright. The server-side half of the fix:
//!
//! - **DELETE** writes `tombstone:<identityKey>:<id>` with value
//!   `{"deletedAt": <ms epoch>}` and a [`TOMBSTONE_TTL_SECONDS`] TTL,
//!   *then* deletes the draft row (that order: a failed second step only
//!   over-hides, never resurrects). `deletedAt = max(server now,
//!   stored.updatedAt + 1)` — it strictly dominates the version it
//!   deleted, even when the client's clock runs ahead of the server's.
//!   A retried DELETE reuses the existing tombstone's `deletedAt`
//!   (idempotent; a retry never steamrolls a concurrent recreate).
//! - **GET /drafts/:id** answers the ordinary 404 `ERR_NOT_FOUND` while a
//!   tombstone exists, even if the draft row is still readable (delete
//!   raced, or lag). The client can therefore treat "remote summary whose
//!   body GET is `not_found`" as a server tombstone and drop the row —
//!   exactly issue #27's reconcile rule.
//! - **GET /drafts** excludes tombstoned ids, so a lagged summary row is
//!   never listed back into the client's index.
//! - **PUT /drafts/:id** over a tombstone: if `deletedAt > updatedAt` the
//!   delete is strictly newer → **410** `ERR_DRAFT_DELETED` with
//!   `{status,code,description,deletedAt}` (client should discard its
//!   stale copy or re-save under a fresh id); otherwise the PUT is a
//!   genuine recreate/newer edit → it wins, the tombstone is cleared, and
//!   the draft is stored (work is never lost — the same
//!   equal-timestamps-overwrite rule as the 409 gate). A corrupt tombstone
//!   hides reads but never blocks writes: any PUT clears it.
//! - After the TTL (30 days) the id behaves as never-deleted; the safe
//!   failure direction is resurrection, not loss.
//!
//! # Caps (the-composer #42)
//!
//! The API is authenticated-but-public (any key that completes a BRC-103
//! handshake is accepted), so every write and read is bounded:
//!
//! - **Body**: 256 KB per draft ([`MAX_DRAFT_BYTES`], 413
//!   `ERR_DRAFT_TOO_LARGE`), 256-byte titles.
//! - **Count**: [`MAX_DRAFTS_PER_IDENTITY`] drafts per identity — a PUT to
//!   a NEW id beyond the cap is 413 `ERR_DRAFT_LIMIT`; updates and deletes
//!   of existing drafts always work.
//! - **List**: `GET /drafts` materializes at most
//!   [`MAX_DRAFTS_PER_IDENTITY`] rows over at most [`MAX_LIST_PAGES`] KV
//!   pages — non-lossy in steady state because of the count cap.
//!
//! 413 (not 409) for both caps: 409 is reserved for the
//! conflict-carries-stored-draft contract below, which the client parses
//! as a draft body.
//!
//! # Why DELETE answers 200, not 204
//!
//! Every response here is signed via `sign_json_response` so AuthFetch
//! clients can verify it. A bodyless 204 cannot be signed correctly with
//! the current middleware/SDK pair: the middleware's
//! `HttpResponseData::to_payload` encodes an empty body as the `-1` marker
//! (9 bytes of 0xFF), while @bsv/sdk's `SimplifiedFetchTransport` (v1.10.x)
//! reconstructs the response payload with `writeVarIntNum(0)` for an empty
//! body — the signature can never verify. (CF Workers additionally forbids
//! a body on a 204.) A signed `200 {"status":"success"}` keeps the
//! idempotent-delete semantics; the client only checks `response.ok`.
//!
//! # Identity isolation by construction
//!
//! Every KV key is `draft:<identityKey>:<id>` where `identityKey` comes from
//! the verified BRC-103 session (never from the request) and `id` is a
//! validated lowercase UUID (so neither segment can contain `:` or escape
//! its slot). List uses the prefix `draft:<identityKey>:` — a different
//! identity's drafts are unreachable from any input this module accepts.
//!
//! # Conflict rule (last-write-wins with a floor)
//!
//! PUT carries the client-clock `updatedAt` (ms epoch). If the stored draft
//! is strictly newer, the write is refused with 409 and the stored draft as
//! the response body — the client reconciles and retries; nothing is
//! overwritten. Equal timestamps overwrite (the same logical edit retried).
//!
//! # List without N+1
//!
//! Summary fields ride in KV metadata (see [`DraftKvMetadata`]); `GET
//! /drafts` is pure `list()` pagination, no per-key `get`. Rows whose
//! metadata is missing or malformed are skipped rather than guessed at —
//! the same drop-don't-leak posture as `/list`'s tag parsing.

use crate::error::{
    ERR_DRAFT_DELETED, ERR_DRAFT_LIMIT, ERR_DRAFT_TOO_LARGE, ERR_INTERNAL, ERR_INVALID_REQUEST,
    ERR_MISSING_IDENTITY_KEY, ERR_NOT_FOUND,
};
use crate::routes::drafts_store::{DraftStore, KvDraftStore};
use crate::types::{
    DraftBody, DraftDeletedBody, DraftKvMetadata, DraftSummaryBody, DraftTombstone,
    DraftsListResponse, ErrorBody, PutDraftRequest,
};
use serde_json::{json, Value};
use worker::kv::KvStore;
use worker::{Env, Method};

/// KV binding name (wrangler.composer.toml `[[kv_namespaces]]`).
const DRAFTS_KV_BINDING: &str = "COMPOSER_DRAFTS";

/// KV key prefix; full key is `draft:<identityKey>:<id>`.
const KEY_PREFIX: &str = "draft:";

/// Tombstone key prefix; full key is `tombstone:<identityKey>:<id>`
/// (the-composer #27). A separate namespace from `draft:` so draft
/// listings and quota counts never see tombstones structurally.
const TOMBSTONE_PREFIX: &str = "tombstone:";

/// Tombstone lifetime, in seconds (30 days). Requirements pulling in
/// opposite directions:
///
/// - MUST comfortably exceed Cloudflare KV's list/read propagation lag
///   (~60 s) — that lag is the resurrect window the tombstone closes.
/// - SHOULD be long enough that a device coming back from a long offline
///   stretch still hits the tombstone when it pushes its stale copy of a
///   deleted draft (the durable multi-device undo in issue #27).
/// - Bounded, so deleted-id markers are not a permanent per-key cost.
///
/// 30 days ≈ "any device that syncs at least monthly gets the delete";
/// beyond it, a stale offline copy resurrects as a plain draft again —
/// the safe failure direction (work is never lost).
const TOMBSTONE_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Hard cap on a PUT body (the full draft JSON), in bytes. Matches the
/// client cap in the-composer's draftsApi.
pub const MAX_DRAFT_BYTES: usize = 256 * 1024;

/// Hard cap on a draft title, in UTF-8 bytes.
pub const MAX_TITLE_BYTES: usize = 256;

/// Largest integer exactly representable in a JSON number (2^53 − 1); the
/// bound for `updatedAt` and the count fields.
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// Per-page row limit for KV listings (Cloudflare's maximum; also its
/// default). Made explicit so the storage seam sees the same page size the
/// old inline code implied.
const LIST_PAGE_LIMIT: u64 = 1000;

/// Per-identity draft-count quota (the-composer #42). Generous — the folio
/// UI is built around dozens of drafts, not hundreds — while turning
/// "unbounded identities × unbounded drafts × 256 KB" into a bounded owner
/// cost. NEW draft ids beyond the cap are refused with 413
/// `ERR_DRAFT_LIMIT`; updates and deletes of existing drafts always work,
/// so nobody can be locked out of their own data by the cap.
pub const MAX_DRAFTS_PER_IDENTITY: usize = 200;

/// Upper bound on KV list pages any single request will walk (quota count,
/// `GET /drafts`). `MAX_LIST_PAGES × LIST_PAGE_LIMIT` = 10 000 keys — far
/// beyond anything the quota admits, so hitting the guard means a
/// degenerate store (or a KV cursor bug); loops stop rather than spin.
const MAX_LIST_PAGES: usize = 10;

/// Dispatch a `/drafts*` request. `path` is the URL path (starts with
/// `/drafts`); auth has already happened — `identity_key` is the verified
/// BRC-103 peer identity. Returns the repo-standard `(body, status)` pair
/// for lib.rs's signing tail.
///
/// The KV binding is resolved here (and only here); everything below runs
/// against the [`DraftStore`] seam so `cargo test` executes the handlers
/// (the-composer #29). On deployments without the binding, every `/drafts*`
/// request — including malformed ones — answers the catch-all 404, exactly
/// as the module docs promise.
pub async fn handle(
    method: &Method,
    path: &str,
    body: &[u8],
    identity_key: &str,
    env: &Env,
) -> (Value, u16) {
    let Some(kv) = drafts_store(env) else {
        return not_found();
    };
    let store = KvDraftStore::new(kv);
    handle_with_store(method, path, body, identity_key, &store).await
}

/// Storage-generic dispatch — the executed-test entry point.
async fn handle_with_store<S: DraftStore>(
    method: &Method,
    path: &str,
    body: &[u8],
    identity_key: &str,
    store: &S,
) -> (Value, u16) {
    // Defensive parity with /list's identity check — the middleware
    // guarantees a non-empty key on this path, but trusting that silently
    // would turn a future middleware regression into cross-user reads.
    if identity_key.is_empty() {
        return error(
            ERR_MISSING_IDENTITY_KEY,
            "Missing authfetch identityKey.",
            400,
        );
    }

    let Some(rest) = path.strip_prefix("/drafts") else {
        return not_found(); // unreachable: lib.rs only routes /drafts* here
    };

    match (method, rest) {
        (Method::Get, "") => handle_list(identity_key, store).await,
        (Method::Get, _) => handle_get(item_id(rest), identity_key, store).await,
        (Method::Put, _) if !rest.is_empty() => {
            handle_put(item_id(rest), body, identity_key, store).await
        }
        (Method::Delete, _) if !rest.is_empty() => {
            handle_delete(item_id(rest), identity_key, store).await
        }
        // PUT/DELETE on the collection, POST anywhere, etc. — same shape the
        // lib.rs catch-all emits for unknown routes.
        _ => not_found(),
    }
}

/// `GET /drafts` — list the caller's drafts, newest first.
///
/// Bounded (the-composer #42): at most [`MAX_DRAFTS_PER_IDENTITY`] rows are
/// materialized and at most [`MAX_LIST_PAGES`] KV pages walked. The PUT-time
/// quota keeps identities at or under the cap, so in steady state the bound
/// is not lossy; for a legacy over-cap identity the lexicographically-first
/// `MAX_DRAFTS_PER_IDENTITY` ids are returned (defensive bound, not a
/// pagination API — the client caps itself well below this).
async fn handle_list<S: DraftStore>(identity_key: &str, store: &S) -> (Value, u16) {
    // Tombstoned ids are dropped from the listing — the whole point of the
    // tombstone (#27): a KV-lagged row must not be pulled back into the
    // client's index after a delete.
    let tombstoned = match tombstoned_ids(identity_key, store).await {
        Ok(ids) => ids,
        Err(()) => return error(ERR_INTERNAL, "Error listing drafts.", 500),
    };

    let prefix = format!("{KEY_PREFIX}{identity_key}:");
    let mut summaries: Vec<DraftSummaryBody> = Vec::new();
    let mut cursor: Option<String> = None;

    for _ in 0..MAX_LIST_PAGES {
        let page = match store
            .list_page(&prefix, cursor.take().as_deref(), LIST_PAGE_LIMIT)
            .await
        {
            Ok(page) => page,
            Err(_) => return error(ERR_INTERNAL, "Error listing drafts.", 500),
        };

        for key in &page.keys {
            if summaries.len() >= MAX_DRAFTS_PER_IDENTITY {
                break;
            }
            let Some(id) = key.name.strip_prefix(&prefix) else {
                continue; // KV honored the prefix filter; defensive only.
            };
            if !is_draft_id(id) {
                continue;
            }
            if tombstoned.contains(id) {
                continue; // deleted; the row is KV lag (or a raced delete)
            }
            // Missing/malformed metadata: drop the row rather than emit a
            // half-summary (matches /list's malformed-tag posture). Writes
            // always attach metadata, so this is corruption insurance.
            let Some(meta) = key
                .metadata
                .as_ref()
                .and_then(|m| serde_json::from_value::<DraftKvMetadata>(m.clone()).ok())
            else {
                continue;
            };
            summaries.push(DraftSummaryBody {
                id: id.to_string(),
                title: meta.title,
                updated_at: meta.updated_at,
                section_count: meta.section_count,
                part_count: meta.part_count,
            });
        }

        if summaries.len() >= MAX_DRAFTS_PER_IDENTITY || page.list_complete {
            break;
        }
        match page.cursor {
            Some(next) => cursor = Some(next),
            None => break, // defensive: incomplete page without a cursor
        }
    }

    sort_newest_first(&mut summaries);
    (json!(DraftsListResponse { drafts: summaries }), 200)
}

/// The identity's currently-tombstoned draft ids (#27). Page-bounded like
/// every listing here; tombstones are TTL-bounded and each delete leaves at
/// most one, so the [`MAX_LIST_PAGES`] guard (10 000 rows) is unreachable
/// in practice — if it ever trips, the collected subset still filters
/// best-effort.
async fn tombstoned_ids<S: DraftStore>(
    identity_key: &str,
    store: &S,
) -> Result<std::collections::HashSet<String>, ()> {
    let prefix = format!("{TOMBSTONE_PREFIX}{identity_key}:");
    let mut ids = std::collections::HashSet::new();
    let mut cursor: Option<String> = None;

    for _ in 0..MAX_LIST_PAGES {
        let page = store
            .list_page(&prefix, cursor.take().as_deref(), LIST_PAGE_LIMIT)
            .await
            .map_err(|_| ())?;
        for key in &page.keys {
            if let Some(id) = key.name.strip_prefix(&prefix) {
                if is_draft_id(id) {
                    ids.insert(id.to_string());
                }
            }
        }
        if page.list_complete {
            break;
        }
        match page.cursor {
            Some(next) => cursor = Some(next),
            None => break, // defensive: incomplete page without a cursor
        }
    }
    Ok(ids)
}

/// Is the identity at (or beyond) its draft-count quota? Counts real draft
/// rows under the identity's key prefix, short-circuiting as soon as the
/// cap is reached; page-bounded like every listing here. If the page guard
/// is exhausted before the listing completes (impossible under the quota —
/// it would take >10 000 keys), fail CLOSED: this is a cost/DoS guard, and
/// an identity in that state is already past any legitimate use.
async fn identity_at_draft_cap<S: DraftStore>(identity_key: &str, store: &S) -> Result<bool, ()> {
    let prefix = format!("{KEY_PREFIX}{identity_key}:");
    let mut count: usize = 0;
    let mut cursor: Option<String> = None;

    for _ in 0..MAX_LIST_PAGES {
        let page = store
            .list_page(&prefix, cursor.take().as_deref(), LIST_PAGE_LIMIT)
            .await
            .map_err(|_| ())?;
        count += page
            .keys
            .iter()
            .filter(|key| key.name.strip_prefix(&prefix).is_some_and(is_draft_id))
            .count();
        if count >= MAX_DRAFTS_PER_IDENTITY {
            return Ok(true);
        }
        if page.list_complete {
            return Ok(false);
        }
        match page.cursor {
            Some(next) => cursor = Some(next),
            None => return Ok(false), // defensive: incomplete page, no cursor
        }
    }
    Ok(true) // page guard exhausted — fail closed (see doc comment)
}

/// `GET /drafts/:id` — one full draft.
async fn handle_get<S: DraftStore>(id: &str, identity_key: &str, store: &S) -> (Value, u16) {
    if !is_draft_id(id) {
        return invalid_id();
    }

    match store.get_text(&draft_key(identity_key, id)).await {
        Ok(Some(text)) => {
            // A tombstone hides even a still-readable row (#27) — the
            // delete raced its second step, or this edge's KV is lagging.
            // Presence alone decides for reads; `deletedAt` only matters
            // to the PUT gate.
            match store.get_text(&tombstone_key(identity_key, id)).await {
                Ok(Some(_)) => return error(ERR_NOT_FOUND, "Draft not found.", 404),
                Ok(None) => {}
                Err(_) => return error(ERR_INTERNAL, "Error reading draft.", 500),
            }
            match serde_json::from_str::<DraftBody>(&text) {
                Ok(draft) => (json!(draft), 200),
                // Stored bytes that no longer parse as a draft: surface a
                // 500, not a silent 404 — the record exists and losing it
                // quietly would defeat the client's sync reconciliation.
                Err(_) => error(ERR_INTERNAL, "Stored draft is unreadable.", 500),
            }
        }
        Ok(None) => error(ERR_NOT_FOUND, "Draft not found.", 404),
        Err(_) => error(ERR_INTERNAL, "Error reading draft.", 500),
    }
}

/// `PUT /drafts/:id` — upsert with a strictly-newer-wins conflict check.
async fn handle_put<S: DraftStore>(
    id: &str,
    body: &[u8],
    identity_key: &str,
    store: &S,
) -> (Value, u16) {
    if !is_draft_id(id) {
        return invalid_id();
    }
    let validated = match validate_put_body(body) {
        Ok(v) => v,
        Err(outcome) => return outcome,
    };

    let key = draft_key(identity_key, id);
    let tomb_key = tombstone_key(identity_key, id);

    // Tombstone gate (#27) — before the conflict check: a strictly-newer
    // delete outranks whatever is (or is not) stored.
    let tombstone_text = match store.get_text(&tomb_key).await {
        Ok(text) => text,
        Err(_) => return error(ERR_INTERNAL, "Error reading draft.", 500),
    };
    let clear_tombstone = match tombstone_gate(tombstone_text.as_deref(), validated.updated_at) {
        TombstoneGate::Absent => false,
        TombstoneGate::Newer { deleted_at } => {
            return (
                json!(DraftDeletedBody {
                    status: "error",
                    code: ERR_DRAFT_DELETED,
                    description: "This draft was deleted more recently than this edit.".to_string(),
                    deleted_at,
                }),
                410,
            )
        }
        TombstoneGate::Superseded => true,
    };

    // Conflict check — a KV read error is a 500; skipping the check on a
    // live store could overwrite a newer draft.
    let stored_text = match store.get_text(&key).await {
        Ok(text) => text,
        Err(_) => return error(ERR_INTERNAL, "Error reading draft.", 500),
    };
    if let PutGate::Conflict(stored) = put_gate(stored_text.as_deref(), validated.updated_at) {
        return (json!(stored), 409);
    }

    // Quota (the-composer #42): only NEW ids consume quota — an id with any
    // stored value (even a corrupt one being self-healed) already occupies
    // its slot, so updates keep working at the cap and nobody is locked out
    // of their own data.
    if stored_text.is_none() {
        match identity_at_draft_cap(identity_key, store).await {
            Ok(true) => {
                return error(
                    ERR_DRAFT_LIMIT,
                    format!(
                        "Draft limit reached ({MAX_DRAFTS_PER_IDENTITY} per identity). \
                         Delete a draft before creating another."
                    ),
                    413,
                )
            }
            Ok(false) => {}
            Err(()) => return error(ERR_INTERNAL, "Error listing drafts.", 500),
        }
    }

    let draft = DraftBody {
        id: id.to_string(),
        title: validated.title,
        updated_at: validated.updated_at,
        state: validated.state,
    };
    let metadata = DraftKvMetadata {
        title: draft.title.clone(),
        updated_at: draft.updated_at,
        section_count: validated.section_count,
        part_count: validated.part_count,
    };
    let value = match serde_json::to_string(&draft) {
        Ok(v) => v,
        Err(_) => return error(ERR_INTERNAL, "Error encoding draft.", 500),
    };

    if store.put_draft(&key, &value, &metadata).await.is_err() {
        return error(ERR_INTERNAL, "Error storing draft.", 500);
    }

    // Recreate wins: the tombstone is cleared AFTER the draft is stored, so
    // a failure here leaves {draft + tombstone} — reads stay hidden (the
    // safe direction) and the client's retried PUT converges (the gate
    // passes again, the write is equal-timestamp-idempotent, and this
    // delete runs again).
    if clear_tombstone && store.delete(&tomb_key).await.is_err() {
        return error(ERR_INTERNAL, "Error storing draft.", 500);
    }

    (json!({ "status": "success" }), 200)
}

/// `DELETE /drafts/:id` — idempotent; deleting an absent draft is success.
/// 200 with a signed JSON body, not 204 — see the module docs.
///
/// Writes the delete tombstone (#27) BEFORE removing the draft row: if the
/// second step fails, the draft is only over-hidden (retryable), never
/// resurrectable. See the module docs for the full contract.
async fn handle_delete<S: DraftStore>(id: &str, identity_key: &str, store: &S) -> (Value, u16) {
    if !is_draft_id(id) {
        return invalid_id();
    }
    let key = draft_key(identity_key, id);
    let tomb_key = tombstone_key(identity_key, id);

    // A retried DELETE reuses the existing tombstone's ordinal — advancing
    // `deletedAt` on every retry could steamroll a concurrent recreate.
    let existing = match store.get_text(&tomb_key).await {
        Ok(text) => text,
        Err(_) => return error(ERR_INTERNAL, "Error deleting draft.", 500),
    };
    let existing_deleted_at = existing
        .as_deref()
        .and_then(|text| serde_json::from_str::<DraftTombstone>(text).ok())
        .map(|tombstone| tombstone.deleted_at);

    let deleted_at = match existing_deleted_at {
        Some(at) => at,
        None => {
            // The ordinal must strictly dominate the version being deleted
            // even if the client's clock (which minted `updatedAt`) runs
            // ahead of the server's — hence the `stored.updatedAt + 1`
            // floor. An unreadable/absent row contributes 0.
            let stored_updated_at = match store.get_text(&key).await {
                Ok(Some(text)) => serde_json::from_str::<DraftBody>(&text)
                    .map(|draft| draft.updated_at)
                    .unwrap_or(0),
                Ok(None) => 0,
                Err(_) => return error(ERR_INTERNAL, "Error deleting draft.", 500),
            };
            store.now_ms().max(stored_updated_at.saturating_add(1))
        }
    };

    let tombstone = match serde_json::to_string(&DraftTombstone { deleted_at }) {
        Ok(value) => value,
        Err(_) => return error(ERR_INTERNAL, "Error deleting draft.", 500),
    };
    if store
        .put_expiring(&tomb_key, &tombstone, TOMBSTONE_TTL_SECONDS)
        .await
        .is_err()
    {
        return error(ERR_INTERNAL, "Error deleting draft.", 500);
    }

    match store.delete(&key).await {
        Ok(()) => (json!({ "status": "success" }), 200),
        Err(_) => error(ERR_INTERNAL, "Error deleting draft.", 500),
    }
}

// ─── conflict decision (pure — unit-tested below) ───────────────────────────

/// Outcome of comparing an incoming PUT against the stored draft.
#[derive(Debug, PartialEq)]
enum PutGate {
    /// No conflict — write the incoming draft.
    Write,
    /// The stored draft is strictly newer: refuse with 409 and hand the
    /// stored copy back as the response body (the data-integrity core of
    /// sync — the client reconciles and retries; nothing is overwritten).
    Conflict(DraftBody),
}

/// The last-write-wins-with-a-floor rule, lifted out of `handle_put` so the
/// decision itself is unit-testable (the-composer #29):
///
/// - absent stored value → write;
/// - stored value that no longer parses as a draft → write (the incoming
///   PUT self-heals the corruption);
/// - stored strictly newer (`stored.updatedAt > incoming`) → conflict;
/// - equal timestamps → write (the same logical edit retried).
fn put_gate(stored_text: Option<&str>, incoming_updated_at: u64) -> PutGate {
    let Some(text) = stored_text else {
        return PutGate::Write;
    };
    match serde_json::from_str::<DraftBody>(text) {
        Ok(stored) if stored.updated_at > incoming_updated_at => PutGate::Conflict(stored),
        _ => PutGate::Write,
    }
}

/// Outcome of checking an incoming PUT against a delete tombstone (#27).
#[derive(Debug, PartialEq, Eq)]
enum TombstoneGate {
    /// No tombstone — proceed normally.
    Absent,
    /// The delete is strictly newer than this edit: refuse with 410 and
    /// hand back `deletedAt` so the client can reconcile.
    Newer { deleted_at: u64 },
    /// The edit is at least as new as the delete (a genuine recreate), or
    /// the tombstone is corrupt: the PUT wins and must clear the marker.
    Superseded,
}

/// The tombstone half of the LWW rule, mirroring [`put_gate`]'s
/// strictly-newer-wins / equal-overwrites semantics: only a tombstone with
/// `deletedAt > updatedAt` blocks the write. A corrupt tombstone never
/// blocks a write (it hides reads until any PUT self-heals it) — a marker
/// that can't be parsed must not brick the id for its whole TTL.
fn tombstone_gate(tombstone_text: Option<&str>, incoming_updated_at: u64) -> TombstoneGate {
    let Some(text) = tombstone_text else {
        return TombstoneGate::Absent;
    };
    match serde_json::from_str::<DraftTombstone>(text) {
        Ok(tombstone) if tombstone.deleted_at > incoming_updated_at => TombstoneGate::Newer {
            deleted_at: tombstone.deleted_at,
        },
        _ => TombstoneGate::Superseded,
    }
}

// ─── validation (pure — unit-tested below) ──────────────────────────────────

/// A `PUT /drafts/:id` body after every check has passed.
#[derive(Debug, PartialEq)]
struct ValidatedPut {
    title: String,
    updated_at: u64,
    state: Value,
    section_count: u64,
    part_count: u64,
}

/// Size-cap, parse, and field-validate a PUT body.
///
/// Order matters: the byte cap is enforced on the raw wire bytes BEFORE any
/// JSON parsing (a 10 MB body must not cost a 10 MB parse). Counts are
/// derived from `state` when its well-known shape is present; otherwise the
/// client-supplied fields are used after bound-checking (integer ≥ 0,
/// default 0).
fn validate_put_body(body: &[u8]) -> Result<ValidatedPut, (Value, u16)> {
    if body.len() > MAX_DRAFT_BYTES {
        return Err(error(
            ERR_DRAFT_TOO_LARGE,
            format!("Drafts are capped at {MAX_DRAFT_BYTES} bytes."),
            413,
        ));
    }

    let request: PutDraftRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => {
            return Err(error(
                ERR_INVALID_REQUEST,
                "Body must be a JSON object.",
                400,
            ))
        }
    };

    let Some(title) = request.title else {
        return Err(error(ERR_INVALID_REQUEST, "title is required.", 400));
    };
    if title.len() > MAX_TITLE_BYTES {
        return Err(error(
            ERR_INVALID_REQUEST,
            format!("title must be at most {MAX_TITLE_BYTES} UTF-8 bytes."),
            400,
        ));
    }
    // Control characters (Unicode Cc — includes DEL and the C1 range) have
    // no place in a display title, and their 6-byte \uXXXX JSON escapes
    // could push the KV metadata past the platform's 1024-byte cap.
    if title.chars().any(char::is_control) {
        return Err(error(
            ERR_INVALID_REQUEST,
            "title must not contain control characters.",
            400,
        ));
    }

    let updated_at = match request.updated_at {
        Some(value) if is_positive_safe_integer(value) => to_u64(value),
        _ => {
            return Err(error(
                ERR_INVALID_REQUEST,
                "updatedAt must be a positive integer (ms epoch).",
                400,
            ))
        }
    };

    let Some(state) = request.state else {
        return Err(error(ERR_INVALID_REQUEST, "state is required.", 400));
    };

    let (section_count, part_count) = match derive_counts(&state) {
        Some(counts) => counts,
        None => {
            let section_count = validate_count(request.section_count, "sectionCount")?;
            let part_count = validate_count(request.part_count, "partCount")?;
            (section_count, part_count)
        }
    };

    Ok(ValidatedPut {
        title,
        updated_at,
        state,
        section_count,
        part_count,
    })
}

/// Bound-check a client-supplied count: absent → 0, else integer ≥ 0.
fn validate_count(value: Option<f64>, field: &str) -> Result<u64, (Value, u16)> {
    match value {
        None => Ok(0),
        Some(v) if is_safe_non_negative_integer(v) => Ok(to_u64(v)),
        Some(_) => Err(error(
            ERR_INVALID_REQUEST,
            format!("{field} must be a non-negative integer."),
            400,
        )),
    }
}

/// Derive `(sectionCount, partCount)` from the builder-state shape
/// `{ sections: [{ slots: { vocals, treble, bass } }] }`.
///
/// Returns `None` when `state` is not an object carrying a `sections`
/// array — the caller then falls back to client-supplied counts. When the
/// shape IS recognized:
///
/// - `sectionCount` = `sections.length`.
/// - `partCount` = distinct placed parts across all slots: a slot object's
///   string `outpoint` (`txid.vout`, the part's stable on-chain identity)
///   keys distinctness; filled slots without one are conservatively counted
///   one each (they cannot be deduplicated).
fn derive_counts(state: &Value) -> Option<(u64, u64)> {
    let sections = state.as_object()?.get("sections")?.as_array()?;

    let mut outpoints: Vec<&str> = Vec::new();
    let mut anonymous: u64 = 0;
    for section in sections {
        let Some(slots) = section
            .as_object()
            .and_then(|s| s.get("slots")?.as_object())
        else {
            continue;
        };
        for slot in slots.values() {
            let Some(part) = slot.as_object() else {
                continue; // empty slot (null) or unrecognized scalar
            };
            match part.get("outpoint").and_then(Value::as_str) {
                Some(outpoint) => {
                    if !outpoints.contains(&outpoint) {
                        outpoints.push(outpoint);
                    }
                }
                None => anonymous += 1,
            }
        }
    }

    Some((sections.len() as u64, outpoints.len() as u64 + anonymous))
}

/// Newest-first by `updatedAt`; id ascending as a deterministic tiebreak.
fn sort_newest_first(summaries: &mut [DraftSummaryBody]) {
    summaries.sort_by(|a, b| {
        b.updated_at
            .cmp(&a.updated_at)
            .then_with(|| a.id.cmp(&b.id))
    });
}

// ─── key + id helpers (pure) ─────────────────────────────────────────────────

/// KV key for one draft: `draft:<identityKey>:<id>`.
fn draft_key(identity_key: &str, id: &str) -> String {
    format!("{KEY_PREFIX}{identity_key}:{id}")
}

/// KV key for one delete tombstone: `tombstone:<identityKey>:<id>` (#27).
/// Same identity/id isolation argument as [`draft_key`].
fn tombstone_key(identity_key: &str, id: &str) -> String {
    format!("{TOMBSTONE_PREFIX}{identity_key}:{id}")
}

/// Lowercase RFC 4122 UUID (8-4-4-4-12, lowercase hex) — the only accepted
/// draft id. Lowercase is required, not just canonical, so the KV key and
/// the stored id are byte-identical with no case folding anywhere.
/// `crypto.randomUUID()` — the client's id source — always emits this form.
fn is_draft_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    bytes.iter().enumerate().all(|(i, &b)| match i {
        8 | 13 | 18 | 23 => b == b'-',
        _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
    })
}

/// The `:id` segment of `/drafts/<id>` (caller strips the `/drafts` prefix;
/// `rest` is `"/<id>"`). Trailing content after another `/` stays in the
/// returned slice and fails UUID validation — `/drafts/a/b` is a 400.
fn item_id(rest: &str) -> &str {
    rest.strip_prefix('/').unwrap_or(rest)
}

/// True when `value` is a JSON number representing an integer in
/// `1..=2^53−1`.
fn is_positive_safe_integer(value: f64) -> bool {
    value.is_finite() && (1.0..=MAX_SAFE_INTEGER).contains(&value) && value.fract() == 0.0
}

/// True when `value` is a JSON number representing an integer in
/// `0..=2^53−1`.
fn is_safe_non_negative_integer(value: f64) -> bool {
    value.is_finite() && (0.0..=MAX_SAFE_INTEGER).contains(&value) && value.fract() == 0.0
}

/// Lossless f64 → u64 for values already vetted by the predicates above.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn to_u64(value: f64) -> u64 {
    value as u64
}

// ─── plumbing ────────────────────────────────────────────────────────────────

/// The drafts KV store, or `None` on deployments without the binding
/// (`/drafts*` then answers 404 — the route effectively does not exist).
fn drafts_store(env: &Env) -> Option<KvStore> {
    env.kv(DRAFTS_KV_BINDING).ok()
}

fn error(code: &'static str, description: impl Into<String>, status: u16) -> (Value, u16) {
    (json!(ErrorBody::new(code, description.into())), status)
}

fn invalid_id() -> (Value, u16) {
    error(
        ERR_INVALID_REQUEST,
        "Draft ids must be lowercase UUIDs.",
        400,
    )
}

fn not_found() -> (Value, u16) {
    error(ERR_NOT_FOUND, "Not Found", 404)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    const ID: &str = "01234567-89ab-4cde-8f01-23456789abcd";
    const IDENTITY: &str = "02f29b6a3c2f1f1a9c1e7d2b0a4b8c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c";

    fn put_err(body: &[u8]) -> (Value, u16) {
        match validate_put_body(body) {
            Err((value, status)) => (value, status),
            Ok(v) => panic!("expected rejection, got {v:?}"),
        }
    }

    fn code_of(value: &Value) -> &str {
        value.get("code").and_then(Value::as_str).unwrap()
    }

    // ── draft id validation ──────────────────────────────────────────────

    #[test]
    fn accepts_lowercase_uuid() {
        assert!(is_draft_id(ID));
    }

    #[test]
    fn rejects_uppercase_uuid() {
        assert!(!is_draft_id("01234567-89AB-4CDE-8F01-23456789ABCD"));
    }

    #[test]
    fn rejects_wrong_length_and_shape() {
        assert!(!is_draft_id(""));
        assert!(!is_draft_id("0123456789ab4cde8f0123456789abcd")); // no dashes
        assert!(!is_draft_id("01234567-89ab-4cde-8f01-23456789abc")); // 35
        assert!(!is_draft_id("01234567-89ab-4cde-8f01-23456789abcde")); // 37
        assert!(!is_draft_id("01234567_89ab_4cde_8f01_23456789abcd")); // bad seps
        assert!(!is_draft_id("g1234567-89ab-4cde-8f01-23456789abcd")); // non-hex
    }

    #[test]
    fn rejects_traversal_shaped_ids() {
        assert!(!is_draft_id("../../../../etc/passwd"));
        assert!(!is_draft_id("01234567-89ab-4cde-8f01-23456789abcd/x"));
    }

    #[test]
    fn item_id_strips_single_leading_slash() {
        assert_eq!(item_id("/abc"), "abc");
        assert_eq!(item_id("/"), "");
        // A nested path keeps its slash and therefore fails UUID validation.
        assert!(!is_draft_id(item_id(&format!("/{ID}/sub"))));
    }

    // ── key construction / isolation ─────────────────────────────────────

    #[test]
    fn draft_key_is_prefix_identity_id() {
        assert_eq!(draft_key(IDENTITY, ID), format!("draft:{IDENTITY}:{ID}"),);
    }

    #[test]
    fn different_identities_share_no_key_prefix() {
        let a = format!("draft:{IDENTITY}:");
        let b = "draft:03aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:";
        // Neither list-prefix is a prefix of the other (identity keys are
        // fixed-length hex and the validated id cannot contain ':').
        assert!(!a.starts_with(b) && !b.starts_with(&a));
    }

    // ── PUT body validation ──────────────────────────────────────────────

    fn valid_body() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "title": "Sonata",
            "updatedAt": 1_750_000_000_000_u64,
            "state": {
                "title": "Sonata",
                "sections": [
                    { "id": "s1", "slots": { "vocals": null, "treble": { "outpoint": "aa.0" }, "bass": null } },
                    { "id": "s2", "slots": { "vocals": { "outpoint": "bb.1" }, "treble": { "outpoint": "aa.0" }, "bass": null } }
                ]
            }
        }))
        .unwrap()
    }

    #[test]
    fn accepts_valid_body_and_derives_counts() {
        let v = validate_put_body(&valid_body()).unwrap_or_else(|_| panic!("should validate"));
        assert_eq!(v.title, "Sonata");
        assert_eq!(v.updated_at, 1_750_000_000_000);
        assert_eq!(v.section_count, 2);
        assert_eq!(v.part_count, 2); // aa.0 deduplicated across sections
    }

    #[test]
    fn rejects_oversized_body_before_parsing() {
        let body = vec![b'x'; MAX_DRAFT_BYTES + 1];
        let (value, status) = put_err(&body);
        assert_eq!(status, 413);
        assert_eq!(code_of(&value), ERR_DRAFT_TOO_LARGE);
    }

    #[test]
    fn accepts_body_exactly_at_cap() {
        // Pad the state with a string that brings the body to the cap.
        let base = serde_json::to_vec(&json!({
            "title": "t", "updatedAt": 1, "state": {"pad": ""}
        }))
        .unwrap();
        let pad = "x".repeat(MAX_DRAFT_BYTES - base.len());
        let body = serde_json::to_vec(&json!({
            "title": "t", "updatedAt": 1, "state": {"pad": pad}
        }))
        .unwrap();
        assert_eq!(body.len(), MAX_DRAFT_BYTES);
        assert!(validate_put_body(&body).is_ok());
    }

    #[test]
    fn rejects_malformed_json() {
        let (value, status) = put_err(b"not json");
        assert_eq!(status, 400);
        assert_eq!(code_of(&value), ERR_INVALID_REQUEST);
    }

    #[test]
    fn rejects_missing_title() {
        let body = serde_json::to_vec(&json!({"updatedAt": 1, "state": {}})).unwrap();
        let (value, status) = put_err(&body);
        assert_eq!(status, 400);
        assert!(value["description"].as_str().unwrap().contains("title"));
    }

    #[test]
    fn accepts_empty_title() {
        let body = serde_json::to_vec(&json!({"title": "", "updatedAt": 1, "state": {}})).unwrap();
        let v = validate_put_body(&body).unwrap_or_else(|_| panic!("should validate"));
        assert_eq!(v.title, "");
    }

    #[test]
    fn title_cap_is_bytes_not_chars() {
        // 86 three-byte chars = 258 bytes > 256, though only 86 chars.
        let title = "\u{266B}".repeat(86);
        assert_eq!(title.len(), 258);
        let body =
            serde_json::to_vec(&json!({"title": title, "updatedAt": 1, "state": {}})).unwrap();
        let (_, status) = put_err(&body);
        assert_eq!(status, 400);

        // 85 chars = 255 bytes is fine.
        let title = "\u{266B}".repeat(85);
        let body =
            serde_json::to_vec(&json!({"title": title, "updatedAt": 1, "state": {}})).unwrap();
        assert!(validate_put_body(&body).is_ok());
    }

    #[test]
    fn rejects_control_characters_in_title() {
        for title in ["a\nb", "a\tb", "\u{0}", "\u{7f}"] {
            let body =
                serde_json::to_vec(&json!({"title": title, "updatedAt": 1, "state": {}})).unwrap();
            let (_, status) = put_err(&body);
            assert_eq!(status, 400, "title {title:?} should be rejected");
        }
    }

    #[test]
    fn rejects_bad_updated_at() {
        for updated_at in [json!(0), json!(-5), json!(1.5), json!(1e16)] {
            let body =
                serde_json::to_vec(&json!({"title": "t", "updatedAt": updated_at, "state": {}}))
                    .unwrap();
            let (value, status) = put_err(&body);
            assert_eq!(status, 400, "updatedAt {updated_at} should be rejected");
            assert!(value["description"].as_str().unwrap().contains("updatedAt"));
        }
        // A non-numeric updatedAt fails serde's typed parse outright — same
        // 400, generic body-shape description.
        let body =
            serde_json::to_vec(&json!({"title": "t", "updatedAt": "now", "state": {}})).unwrap();
        let (_, status) = put_err(&body);
        assert_eq!(status, 400);
    }

    #[test]
    fn rejects_missing_or_null_state() {
        for body in [
            serde_json::to_vec(&json!({"title": "t", "updatedAt": 1})).unwrap(),
            serde_json::to_vec(&json!({"title": "t", "updatedAt": 1, "state": null})).unwrap(),
        ] {
            let (value, status) = put_err(&body);
            assert_eq!(status, 400);
            assert!(value["description"].as_str().unwrap().contains("state"));
        }
    }

    #[test]
    fn falls_back_to_supplied_counts_when_state_is_opaque() {
        let body = serde_json::to_vec(&json!({
            "title": "t", "updatedAt": 1, "state": {"v2": true},
            "sectionCount": 3, "partCount": 5
        }))
        .unwrap();
        let v = validate_put_body(&body).unwrap_or_else(|_| panic!("should validate"));
        assert_eq!((v.section_count, v.part_count), (3, 5));
    }

    #[test]
    fn supplied_counts_default_to_zero() {
        let body =
            serde_json::to_vec(&json!({"title": "t", "updatedAt": 1, "state": {"v2": true}}))
                .unwrap();
        let v = validate_put_body(&body).unwrap_or_else(|_| panic!("should validate"));
        assert_eq!((v.section_count, v.part_count), (0, 0));
    }

    #[test]
    fn rejects_out_of_bounds_supplied_counts() {
        for counts in [
            json!({"sectionCount": -1}),
            json!({"sectionCount": 1.5}),
            json!({"partCount": -3}),
            json!({"partCount": 1e16}),
        ] {
            let mut body = json!({"title": "t", "updatedAt": 1, "state": {"v2": true}});
            for (k, v) in counts.as_object().unwrap() {
                body[k] = v.clone();
            }
            let (_, status) = put_err(&serde_json::to_vec(&body).unwrap());
            assert_eq!(status, 400, "counts {counts} should be rejected");
        }
    }

    #[test]
    fn derived_counts_win_over_supplied_ones() {
        // state has the canonical shape, so the body's counts are ignored.
        let mut body: Value = serde_json::from_slice(&valid_body()).unwrap();
        body["sectionCount"] = json!(99);
        body["partCount"] = json!(99);
        let v = validate_put_body(&serde_json::to_vec(&body).unwrap())
            .unwrap_or_else(|_| panic!("should validate"));
        assert_eq!((v.section_count, v.part_count), (2, 2));
    }

    // ── derive_counts ────────────────────────────────────────────────────

    #[test]
    fn derive_counts_none_for_unrecognized_shapes() {
        assert!(derive_counts(&json!(null)).is_none());
        assert!(derive_counts(&json!(42)).is_none());
        assert!(derive_counts(&json!({})).is_none());
        assert!(derive_counts(&json!({"sections": "nope"})).is_none());
    }

    #[test]
    fn derive_counts_empty_sections() {
        assert_eq!(derive_counts(&json!({"sections": []})), Some((0, 0)));
    }

    #[test]
    fn derive_counts_dedupes_outpoints_across_sections() {
        let state = json!({"sections": [
            {"slots": {"vocals": {"outpoint": "a.0"}, "treble": null, "bass": null}},
            {"slots": {"vocals": null, "treble": {"outpoint": "a.0"}, "bass": {"outpoint": "b.1"}}},
        ]});
        assert_eq!(derive_counts(&state), Some((2, 2)));
    }

    #[test]
    fn derive_counts_counts_anonymous_filled_slots_individually() {
        let state = json!({"sections": [
            {"slots": {"vocals": {"title": "no outpoint"}, "treble": {"title": "another"}, "bass": null}},
        ]});
        assert_eq!(derive_counts(&state), Some((1, 2)));
    }

    #[test]
    fn derive_counts_tolerates_malformed_sections() {
        let state = json!({"sections": [42, {"noslots": true}, {"slots": "scalar"}]});
        assert_eq!(derive_counts(&state), Some((3, 0)));
    }

    // ── sorting ──────────────────────────────────────────────────────────

    #[test]
    fn sorts_newest_first_with_id_tiebreak() {
        let row = |id: &str, updated_at: u64| DraftSummaryBody {
            id: id.to_string(),
            title: String::new(),
            updated_at,
            section_count: 0,
            part_count: 0,
        };
        let mut rows = vec![row("b", 5), row("a", 9), row("c", 5)];
        sort_newest_first(&mut rows);
        let order: Vec<&str> = rows.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(order, vec!["a", "b", "c"]);
    }

    // ── wire shapes (exact bytes — AuthFetch signs/verifies body bytes) ──

    #[test]
    fn draft_body_serializes_in_contract_field_order() {
        let draft = DraftBody {
            id: ID.to_string(),
            title: "Sonata".to_string(),
            updated_at: 1_750_000_000_000,
            state: json!({"sections": []}),
        };
        assert_eq!(
            serde_json::to_string(&draft).unwrap(),
            format!(
                r#"{{"id":"{ID}","title":"Sonata","updatedAt":1750000000000,"state":{{"sections":[]}}}}"#
            )
        );
    }

    #[test]
    fn draft_body_round_trips_through_kv_text() {
        let draft = DraftBody {
            id: ID.to_string(),
            title: "T".to_string(),
            updated_at: 7,
            state: json!({"any": ["thing", 1, null]}),
        };
        let text = serde_json::to_string(&draft).unwrap();
        let back: DraftBody = serde_json::from_str(&text).unwrap();
        assert_eq!(back.id, draft.id);
        assert_eq!(back.title, draft.title);
        assert_eq!(back.updated_at, draft.updated_at);
        assert_eq!(back.state, draft.state);
    }

    #[test]
    fn list_response_serializes_in_contract_field_order() {
        let body = DraftsListResponse {
            drafts: vec![DraftSummaryBody {
                id: ID.to_string(),
                title: "Sonata".to_string(),
                updated_at: 3,
                section_count: 2,
                part_count: 1,
            }],
        };
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            format!(
                r#"{{"drafts":[{{"id":"{ID}","title":"Sonata","updatedAt":3,"sectionCount":2,"partCount":1}}]}}"#
            )
        );
    }

    #[test]
    fn empty_list_response_shape() {
        let body = DraftsListResponse { drafts: vec![] };
        assert_eq!(serde_json::to_string(&body).unwrap(), r#"{"drafts":[]}"#);
    }

    #[test]
    fn kv_metadata_round_trips_and_stays_under_the_platform_cap() {
        // Worst-case JSON inflation: 256 bytes of '"' escape to 2 bytes each.
        let title = "\"".repeat(MAX_TITLE_BYTES);
        let meta = DraftKvMetadata {
            title,
            updated_at: 9_007_199_254_740_991,
            section_count: 9_007_199_254_740_991,
            part_count: 9_007_199_254_740_991,
        };
        let text = serde_json::to_string(&meta).unwrap();
        assert!(
            text.len() <= 1024,
            "metadata must fit Cloudflare's 1024-byte cap, got {}",
            text.len()
        );
        let back: DraftKvMetadata = serde_json::from_str(&text).unwrap();
        assert_eq!(back.updated_at, meta.updated_at);
    }

    #[test]
    fn kv_metadata_parses_from_list_value() {
        let raw = json!({"title": "T", "updatedAt": 5, "sectionCount": 1, "partCount": 2});
        let meta: DraftKvMetadata = serde_json::from_value(raw).unwrap();
        assert_eq!(meta.title, "T");
        assert_eq!(meta.updated_at, 5);
        assert_eq!((meta.section_count, meta.part_count), (1, 2));
    }

    #[test]
    fn malformed_kv_metadata_is_rejected_not_guessed() {
        for raw in [
            json!(null),
            json!({"title": "T"}),
            json!({"title": "T", "updatedAt": "soon", "sectionCount": 1, "partCount": 2}),
        ] {
            assert!(
                serde_json::from_value::<DraftKvMetadata>(raw.clone()).is_err(),
                "metadata {raw} should fail to parse"
            );
        }
    }

    // ── put_gate (the lifted conflict decision, the-composer #29) ─────────

    fn stored_draft_text(updated_at: u64) -> String {
        serde_json::to_string(&DraftBody {
            id: ID.to_string(),
            title: "Stored".to_string(),
            updated_at,
            state: json!({"stored": true}),
        })
        .unwrap()
    }

    #[test]
    fn put_gate_writes_when_nothing_is_stored() {
        assert_eq!(put_gate(None, 100), PutGate::Write);
    }

    #[test]
    fn put_gate_conflicts_when_stored_is_strictly_newer() {
        let text = stored_draft_text(101);
        match put_gate(Some(&text), 100) {
            PutGate::Conflict(stored) => {
                assert_eq!(stored.updated_at, 101);
                assert_eq!(stored.title, "Stored");
            }
            PutGate::Write => panic!("expected conflict"),
        }
    }

    #[test]
    fn put_gate_overwrites_equal_and_older_stored_copies() {
        // Equal timestamps = the same logical edit retried.
        let text = stored_draft_text(100);
        assert_eq!(put_gate(Some(&text), 100), PutGate::Write);
        let text = stored_draft_text(99);
        assert_eq!(put_gate(Some(&text), 100), PutGate::Write);
    }

    #[test]
    fn put_gate_self_heals_unparsable_stored_values() {
        assert_eq!(put_gate(Some("corrupt{"), 1), PutGate::Write);
    }

    // ── tombstone_gate (the PUT half of the #27 delete contract) ──────────

    #[test]
    fn tombstone_gate_absent_when_no_tombstone() {
        assert_eq!(tombstone_gate(None, 100), TombstoneGate::Absent);
    }

    #[test]
    fn tombstone_gate_blocks_strictly_newer_deletes_only() {
        let tombstone = r#"{"deletedAt":101}"#;
        assert_eq!(
            tombstone_gate(Some(tombstone), 100),
            TombstoneGate::Newer { deleted_at: 101 }
        );
        // Equal or older delete: the PUT wins — same rule as put_gate.
        assert_eq!(
            tombstone_gate(Some(tombstone), 101),
            TombstoneGate::Superseded
        );
        assert_eq!(
            tombstone_gate(Some(tombstone), 102),
            TombstoneGate::Superseded
        );
    }

    #[test]
    fn tombstone_gate_never_lets_a_corrupt_tombstone_block_writes() {
        assert_eq!(
            tombstone_gate(Some("corrupt{"), 1),
            TombstoneGate::Superseded
        );
        assert_eq!(tombstone_gate(Some("{}"), 1), TombstoneGate::Superseded);
    }

    #[test]
    fn tombstone_serializes_in_contract_shape() {
        // The KV value the app-side client half will read.
        let text = serde_json::to_string(&crate::types::DraftTombstone { deleted_at: 7 }).unwrap();
        assert_eq!(text, r#"{"deletedAt":7}"#);
    }

    #[test]
    fn tombstone_key_is_prefix_identity_id() {
        assert_eq!(
            tombstone_key(IDENTITY, ID),
            format!("tombstone:{IDENTITY}:{ID}")
        );
    }

    // ── executed handler tests (the-composer #29) ─────────────────────────
    //
    // These drive the real `handle_list`/`handle_get`/`handle_put`/
    // `handle_delete` through the dispatch in `handle_with_store`, against
    // the deterministic in-memory store. The 401-without-auth-headers
    // behavior lives a layer up (middleware `process_auth`; the dispatch
    // mapping for its typed errors is pinned by `lib.rs`'s own tests).

    mod handlers {
        use super::*;
        use crate::routes::drafts_store::{block_on_ready, MemoryDraftStore};

        /// A second verified identity, for isolation tests.
        const IDENTITY_B: &str =
            "03aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        fn body_with(title: &str, updated_at: u64) -> Vec<u8> {
            serde_json::to_vec(&json!({
                "title": title,
                "updatedAt": updated_at,
                "state": {"v2": true},
            }))
            .unwrap()
        }

        fn put_as(store: &MemoryDraftStore, identity: &str, id: &str, body: &[u8]) -> (Value, u16) {
            block_on_ready(handle_with_store(
                &Method::Put,
                &format!("/drafts/{id}"),
                body,
                identity,
                store,
            ))
        }

        fn put(store: &MemoryDraftStore, id: &str, body: &[u8]) -> (Value, u16) {
            put_as(store, IDENTITY, id, body)
        }

        fn get_as(store: &MemoryDraftStore, identity: &str, id: &str) -> (Value, u16) {
            block_on_ready(handle_with_store(
                &Method::Get,
                &format!("/drafts/{id}"),
                b"",
                identity,
                store,
            ))
        }

        fn get(store: &MemoryDraftStore, id: &str) -> (Value, u16) {
            get_as(store, IDENTITY, id)
        }

        fn list_as(store: &MemoryDraftStore, identity: &str) -> (Value, u16) {
            block_on_ready(handle_with_store(
                &Method::Get,
                "/drafts",
                b"",
                identity,
                store,
            ))
        }

        fn list(store: &MemoryDraftStore) -> (Value, u16) {
            list_as(store, IDENTITY)
        }

        fn delete_as(store: &MemoryDraftStore, identity: &str, id: &str) -> (Value, u16) {
            block_on_ready(handle_with_store(
                &Method::Delete,
                &format!("/drafts/{id}"),
                b"",
                identity,
                store,
            ))
        }

        fn delete(store: &MemoryDraftStore, id: &str) -> (Value, u16) {
            delete_as(store, IDENTITY, id)
        }

        /// A distinct lowercase-UUID draft id per index.
        fn uuid(i: usize) -> String {
            format!("{i:08x}-0000-4000-8000-000000000000")
        }

        #[test]
        fn put_then_get_round_trips_the_draft() {
            let store = MemoryDraftStore::new();
            let (body, status) = put(&store, ID, &body_with("Sonata", 100));
            assert_eq!(status, 200);
            assert_eq!(body, json!({"status": "success"}));

            let (body, status) = get(&store, ID);
            assert_eq!(status, 200);
            assert_eq!(body["id"], ID);
            assert_eq!(body["title"], "Sonata");
            assert_eq!(body["updatedAt"], 100);
            assert_eq!(body["state"], json!({"v2": true}));
        }

        #[test]
        fn get_absent_draft_is_404() {
            let store = MemoryDraftStore::new();
            let (body, status) = get(&store, ID);
            assert_eq!(status, 404);
            assert_eq!(code_of(&body), ERR_NOT_FOUND);
        }

        #[test]
        fn list_returns_metadata_summaries_newest_first() {
            let store = MemoryDraftStore::new();
            put(&store, &uuid(1), &body_with("Old", 10));
            put(&store, &uuid(2), &body_with("New", 30));
            put(&store, &uuid(3), &body_with("Mid", 20));

            let (body, status) = list(&store);
            assert_eq!(status, 200);
            let drafts = body["drafts"].as_array().unwrap();
            assert_eq!(drafts.len(), 3);
            let titles: Vec<&str> = drafts
                .iter()
                .map(|d| d["title"].as_str().unwrap())
                .collect();
            assert_eq!(titles, vec!["New", "Mid", "Old"]);
            assert_eq!(drafts[0]["sectionCount"], 0);
            assert_eq!(drafts[0]["partCount"], 0);
        }

        #[test]
        fn conflict_409_carries_the_stored_draft_and_stores_nothing() {
            // The data-integrity core of sync: a stale PUT must lose, and
            // the loser must receive the authoritative copy to reconcile.
            let store = MemoryDraftStore::new();
            put(&store, ID, &body_with("Newer", 200));
            let before = store.value_of(&draft_key(IDENTITY, ID)).unwrap();

            let (body, status) = put(&store, ID, &body_with("Stale", 199));
            assert_eq!(status, 409);
            assert_eq!(body["id"], ID);
            assert_eq!(body["title"], "Newer");
            assert_eq!(body["updatedAt"], 200);
            assert_eq!(body["state"], json!({"v2": true}));

            // Nothing was overwritten.
            assert_eq!(store.value_of(&draft_key(IDENTITY, ID)).unwrap(), before);
        }

        #[test]
        fn equal_timestamp_put_overwrites() {
            let store = MemoryDraftStore::new();
            put(&store, ID, &body_with("First", 100));
            let (_, status) = put(&store, ID, &body_with("Retry", 100));
            assert_eq!(status, 200);
            let (body, _) = get(&store, ID);
            assert_eq!(body["title"], "Retry");
        }

        #[test]
        fn newer_put_overwrites() {
            let store = MemoryDraftStore::new();
            put(&store, ID, &body_with("Old", 100));
            let (_, status) = put(&store, ID, &body_with("New", 101));
            assert_eq!(status, 200);
            let (body, _) = get(&store, ID);
            assert_eq!(body["title"], "New");
            assert_eq!(body["updatedAt"], 101);
        }

        #[test]
        fn corrupt_stored_value_is_self_healed_by_put() {
            let store = MemoryDraftStore::new();
            store.insert_raw(&draft_key(IDENTITY, ID), "corrupt{", None);
            let (_, status) = put(&store, ID, &body_with("Healed", 100));
            assert_eq!(status, 200);
            let (body, status) = get(&store, ID);
            assert_eq!(status, 200);
            assert_eq!(body["title"], "Healed");
        }

        #[test]
        fn corrupt_stored_value_get_is_500_not_silent_404() {
            let store = MemoryDraftStore::new();
            store.insert_raw(&draft_key(IDENTITY, ID), "corrupt{", None);
            let (body, status) = get(&store, ID);
            assert_eq!(status, 500);
            assert_eq!(code_of(&body), ERR_INTERNAL);
        }

        #[test]
        fn kv_read_error_is_500_on_get_and_put() {
            let store = MemoryDraftStore::new();
            store.fail_gets(true);
            let (body, status) = get(&store, ID);
            assert_eq!(status, 500);
            assert_eq!(code_of(&body), ERR_INTERNAL);
            // The PUT conflict check must NOT be skipped on a read error —
            // that could overwrite a newer draft.
            let (body, status) = put(&store, ID, &body_with("T", 1));
            assert_eq!(status, 500);
            assert_eq!(code_of(&body), ERR_INTERNAL);
            assert!(!store.contains(&draft_key(IDENTITY, ID)));
        }

        #[test]
        fn kv_write_error_is_500() {
            let store = MemoryDraftStore::new();
            store.fail_puts(true);
            let (body, status) = put(&store, ID, &body_with("T", 1));
            assert_eq!(status, 500);
            assert_eq!(code_of(&body), ERR_INTERNAL);
        }

        #[test]
        fn kv_list_error_is_500() {
            let store = MemoryDraftStore::new();
            store.fail_lists(true);
            let (body, status) = list(&store);
            assert_eq!(status, 500);
            assert_eq!(code_of(&body), ERR_INTERNAL);
        }

        #[test]
        fn kv_delete_error_is_500() {
            let store = MemoryDraftStore::new();
            store.fail_deletes(true);
            let (body, status) = delete(&store, ID);
            assert_eq!(status, 500);
            assert_eq!(code_of(&body), ERR_INTERNAL);
        }

        #[test]
        fn list_paginates_across_cursor_pages() {
            let store = MemoryDraftStore::new();
            for i in 0..5 {
                put(
                    &store,
                    &uuid(i),
                    &body_with(&format!("D{i}"), 10 + i as u64),
                );
            }
            store.force_page_size(2); // 3 pages: 2 + 2 + 1
            let (body, status) = list(&store);
            assert_eq!(status, 200);
            assert_eq!(body["drafts"].as_array().unwrap().len(), 5);
        }

        #[test]
        fn delete_removes_the_draft_and_is_idempotent() {
            let store = MemoryDraftStore::new();
            put(&store, ID, &body_with("T", 1));
            let (body, status) = delete(&store, ID);
            assert_eq!(status, 200);
            assert_eq!(body, json!({"status": "success"}));
            let (_, status) = get(&store, ID);
            assert_eq!(status, 404);

            // Deleting an absent draft is still success.
            let (body, status) = delete(&store, ID);
            assert_eq!(status, 200);
            assert_eq!(body, json!({"status": "success"}));
        }

        // ── #27: delete tombstones ────────────────────────────────────────

        fn tombstone_of(store: &MemoryDraftStore, id: &str) -> Option<u64> {
            store
                .value_of(&tombstone_key(IDENTITY, id))
                .and_then(|text| serde_json::from_str::<crate::types::DraftTombstone>(&text).ok())
                .map(|t| t.deleted_at)
        }

        #[test]
        fn delete_writes_a_tombstone_that_dominates_the_deleted_version() {
            // Client clock ahead of the server: updatedAt=1000, server
            // now=500 → the ordinal must still beat the deleted version.
            let store = MemoryDraftStore::new();
            store.set_now_ms(500);
            put(&store, ID, &body_with("T", 1000));
            delete(&store, ID);
            assert_eq!(tombstone_of(&store, ID), Some(1001));

            // Server clock ahead: plain server time wins.
            let store = MemoryDraftStore::new();
            store.set_now_ms(5000);
            put(&store, ID, &body_with("T", 1000));
            delete(&store, ID);
            assert_eq!(tombstone_of(&store, ID), Some(5000));
        }

        #[test]
        fn delete_retry_reuses_the_tombstone_ordinal() {
            let store = MemoryDraftStore::new();
            store.set_now_ms(5000);
            put(&store, ID, &body_with("T", 1000));
            delete(&store, ID);
            store.advance_ms(60_000);
            let (_, status) = delete(&store, ID);
            assert_eq!(status, 200);
            // Still the original delete's ordinal, not now+60s.
            assert_eq!(tombstone_of(&store, ID), Some(5000));
        }

        #[test]
        fn deleting_an_absent_draft_still_tombstones_it() {
            // Protects against the delete racing an in-flight PUT the KV
            // read hasn't surfaced yet.
            let store = MemoryDraftStore::new();
            store.set_now_ms(7000);
            let (_, status) = delete(&store, ID);
            assert_eq!(status, 200);
            assert_eq!(tombstone_of(&store, ID), Some(7000));
        }

        #[test]
        fn tombstone_hides_a_lagged_row_from_get() {
            // Issue #27 path 2: the draft row is still readable after the
            // delete (KV lag / raced second step) — GET must answer the
            // ordinary not-found the client maps to "server tombstone".
            let store = MemoryDraftStore::new();
            put(&store, ID, &body_with("Ghost", 100));
            delete(&store, ID);
            store.insert_raw(
                &draft_key(IDENTITY, ID),
                &format!(r#"{{"id":"{ID}","title":"Ghost","updatedAt":100,"state":{{}}}}"#),
                None,
            );
            let (body, status) = get(&store, ID);
            assert_eq!(status, 404);
            assert_eq!(code_of(&body), ERR_NOT_FOUND);
        }

        #[test]
        fn tombstone_hides_a_lagged_row_from_list() {
            let store = MemoryDraftStore::new();
            put(&store, ID, &body_with("Ghost", 100));
            delete(&store, ID);
            // Simulate KV list lag: the stale row (with metadata) is still
            // returned by list() after the delete.
            store.insert_raw(
                &draft_key(IDENTITY, ID),
                &format!(r#"{{"id":"{ID}","title":"Ghost","updatedAt":100,"state":{{}}}}"#),
                Some(json!({"title":"Ghost","updatedAt":100,"sectionCount":0,"partCount":0})),
            );
            let (body, status) = list(&store);
            assert_eq!(status, 200);
            assert_eq!(body["drafts"].as_array().unwrap().len(), 0);
        }

        #[test]
        fn stale_put_over_a_newer_tombstone_is_410_with_deleted_at() {
            // The durable multi-device undo: device B pushes its old copy
            // of a draft deleted on device A — the delete must win.
            let store = MemoryDraftStore::new();
            store.set_now_ms(5000);
            put(&store, ID, &body_with("T", 1000));
            delete(&store, ID); // deletedAt = 5000

            let (body, status) = put(&store, ID, &body_with("Stale push", 4999));
            assert_eq!(status, 410);
            assert_eq!(code_of(&body), ERR_DRAFT_DELETED);
            assert_eq!(body["deletedAt"], 5000);
            assert!(!store.contains(&draft_key(IDENTITY, ID)));
        }

        #[test]
        fn newer_put_recreates_and_clears_the_tombstone() {
            let store = MemoryDraftStore::new();
            store.set_now_ms(5000);
            put(&store, ID, &body_with("T", 1000));
            delete(&store, ID); // deletedAt = 5000

            // Strictly newer edit (and, per the equal-overwrites rule, an
            // exactly-equal one) wins: work is never lost.
            let (_, status) = put(&store, ID, &body_with("Recreated", 5000));
            assert_eq!(status, 200);
            assert_eq!(tombstone_of(&store, ID), None);
            assert!(!store.contains(&tombstone_key(IDENTITY, ID)));
            let (body, status) = get(&store, ID);
            assert_eq!(status, 200);
            assert_eq!(body["title"], "Recreated");
            // And the recreated draft is listed again.
            let (body, _) = list(&store);
            assert_eq!(body["drafts"].as_array().unwrap().len(), 1);
        }

        #[test]
        fn corrupt_tombstone_hides_reads_but_yields_to_any_put() {
            let store = MemoryDraftStore::new();
            store.insert_raw(&tombstone_key(IDENTITY, ID), "corrupt{", None);
            store.insert_raw(
                &draft_key(IDENTITY, ID),
                &format!(r#"{{"id":"{ID}","title":"T","updatedAt":100,"state":{{}}}}"#),
                None,
            );
            let (_, status) = get(&store, ID);
            assert_eq!(status, 404);

            // Any PUT self-heals: a marker that can't be parsed must not
            // brick the id for its whole TTL.
            let (_, status) = put(&store, ID, &body_with("Healed", 100));
            assert_eq!(status, 200);
            assert!(!store.contains(&tombstone_key(IDENTITY, ID)));
            let (_, status) = get(&store, ID);
            assert_eq!(status, 200);
        }

        #[test]
        fn expired_tombstone_no_longer_blocks_or_hides() {
            let store = MemoryDraftStore::new();
            store.set_now_ms(5000);
            put(&store, ID, &body_with("T", 1000));
            delete(&store, ID); // deletedAt = 5000, TTL 30 days
            store.advance_ms(TOMBSTONE_TTL_SECONDS * 1000);

            // Even an edit OLDER than the delete is admitted once the
            // tombstone lapses — resurrection is the documented safe
            // failure direction after the TTL.
            let (_, status) = put(&store, ID, &body_with("Post-TTL", 500));
            assert_eq!(status, 200);
            let (_, status) = get(&store, ID);
            assert_eq!(status, 200);
        }

        #[test]
        fn delete_is_500_and_keeps_the_draft_if_the_tombstone_cannot_be_written() {
            // Tombstone-before-delete ordering: a failed first step must
            // abort the delete (retryable), never leave a resurrectable
            // deleted row.
            let store = MemoryDraftStore::new();
            put(&store, ID, &body_with("T", 100));
            store.fail_puts(true);
            let (body, status) = delete(&store, ID);
            assert_eq!(status, 500);
            assert_eq!(code_of(&body), ERR_INTERNAL);
            assert!(store.contains(&draft_key(IDENTITY, ID)));
        }

        #[test]
        fn tombstones_are_identity_scoped() {
            // A's delete of an id must not hide B's draft under the same id.
            let store = MemoryDraftStore::new();
            put_as(&store, IDENTITY_B, ID, &body_with("B's draft", 100));
            delete(&store, ID); // identity A tombstones the (absent) id
            let (body, status) = get_as(&store, IDENTITY_B, ID);
            assert_eq!(status, 200);
            assert_eq!(body["title"], "B's draft");
            let (body, _) = list_as(&store, IDENTITY_B);
            assert_eq!(body["drafts"].as_array().unwrap().len(), 1);
        }

        // ── #42: per-identity quota + bounded list ────────────────────────

        /// Fill the identity's quota with distinct draft ids.
        fn fill_to_cap(store: &MemoryDraftStore) {
            for i in 0..MAX_DRAFTS_PER_IDENTITY {
                let (_, status) = put(store, &uuid(i), &body_with("D", 10));
                assert_eq!(status, 200, "draft {i} should be admitted under the cap");
            }
        }

        #[test]
        fn quota_refuses_a_new_draft_beyond_the_cap() {
            let store = MemoryDraftStore::new();
            fill_to_cap(&store);
            let (body, status) = put(
                &store,
                &uuid(MAX_DRAFTS_PER_IDENTITY),
                &body_with("One too many", 10),
            );
            assert_eq!(status, 413);
            assert_eq!(code_of(&body), ERR_DRAFT_LIMIT);
            // Nothing was written.
            assert!(!store.contains(&draft_key(IDENTITY, &uuid(MAX_DRAFTS_PER_IDENTITY))));
        }

        #[test]
        fn quota_still_allows_updates_at_the_cap() {
            let store = MemoryDraftStore::new();
            fill_to_cap(&store);
            let (_, status) = put(&store, &uuid(0), &body_with("Updated", 11));
            assert_eq!(status, 200);
            let (body, _) = get(&store, &uuid(0));
            assert_eq!(body["title"], "Updated");
        }

        #[test]
        fn quota_frees_capacity_after_delete() {
            let store = MemoryDraftStore::new();
            fill_to_cap(&store);
            delete(&store, &uuid(0));
            let (_, status) = put(
                &store,
                &uuid(MAX_DRAFTS_PER_IDENTITY),
                &body_with("Replacement", 10),
            );
            assert_eq!(status, 200);
        }

        #[test]
        fn quota_is_per_identity() {
            let store = MemoryDraftStore::new();
            fill_to_cap(&store);
            // A full quota for identity A does not affect identity B.
            let (_, status) = put_as(&store, IDENTITY_B, ID, &body_with("B's first", 10));
            assert_eq!(status, 200);
        }

        #[test]
        fn quota_check_counts_across_cursor_pages() {
            let store = MemoryDraftStore::new();
            fill_to_cap(&store);
            store.force_page_size(7); // cap-counting must survive pagination
            let (body, status) = put(
                &store,
                &uuid(MAX_DRAFTS_PER_IDENTITY),
                &body_with("Over", 10),
            );
            assert_eq!(status, 413);
            assert_eq!(code_of(&body), ERR_DRAFT_LIMIT);
        }

        #[test]
        fn list_is_hard_capped_for_legacy_over_cap_identities() {
            let store = MemoryDraftStore::new();
            // Plant MORE than the cap directly (pre-quota data shape).
            let over = MAX_DRAFTS_PER_IDENTITY + 5;
            for i in 0..over {
                let id = uuid(i);
                let meta = json!({
                    "title": "T", "updatedAt": 1, "sectionCount": 0, "partCount": 0
                });
                store.insert_raw(
                    &draft_key(IDENTITY, &id),
                    &format!(r#"{{"id":"{id}","title":"T","updatedAt":1,"state":{{}}}}"#),
                    Some(meta),
                );
            }
            let (body, status) = list(&store);
            assert_eq!(status, 200);
            assert_eq!(
                body["drafts"].as_array().unwrap().len(),
                MAX_DRAFTS_PER_IDENTITY
            );
        }

        #[test]
        fn cross_identity_isolation_end_to_end() {
            let store = MemoryDraftStore::new();
            put(&store, ID, &body_with("A's draft", 100));

            // B cannot read A's draft…
            let (_, status) = get_as(&store, IDENTITY_B, ID);
            assert_eq!(status, 404);
            // …cannot see it in a listing…
            let (body, _) = list_as(&store, IDENTITY_B);
            assert_eq!(body["drafts"].as_array().unwrap().len(), 0);
            // …and B's (idempotent-success) delete does not touch it.
            let (_, status) = delete_as(&store, IDENTITY_B, ID);
            assert_eq!(status, 200);
            let (body, status) = get(&store, ID);
            assert_eq!(status, 200);
            assert_eq!(body["title"], "A's draft");
        }

        #[test]
        fn empty_identity_key_is_rejected_with_400() {
            let store = MemoryDraftStore::new();
            let (body, status) = put_as(&store, "", ID, &body_with("T", 1));
            assert_eq!(status, 400);
            assert_eq!(code_of(&body), ERR_MISSING_IDENTITY_KEY);
        }

        #[test]
        fn unknown_routes_and_methods_are_404() {
            let store = MemoryDraftStore::new();
            for (method, path) in [
                (Method::Post, format!("/drafts/{ID}")),
                (Method::Put, "/drafts".to_string()),
                (Method::Delete, "/drafts".to_string()),
            ] {
                let (body, status) =
                    block_on_ready(handle_with_store(&method, &path, b"", IDENTITY, &store));
                assert_eq!(status, 404, "{method:?} {path} should be 404");
                assert_eq!(code_of(&body), ERR_NOT_FOUND);
            }
        }

        #[test]
        fn invalid_ids_are_400_through_dispatch() {
            let store = MemoryDraftStore::new();
            for id in ["not-a-uuid", "01234567-89AB-4CDE-8F01-23456789ABCD"] {
                let (body, status) = get(&store, id);
                assert_eq!(status, 400, "id {id:?} should be rejected");
                assert_eq!(code_of(&body), ERR_INVALID_REQUEST);
            }
        }
    }

    // ── error shapes ─────────────────────────────────────────────────────

    #[test]
    fn error_bodies_use_the_repo_error_shape() {
        let (value, status) = not_found();
        assert_eq!(status, 404);
        assert_eq!(
            serde_json::to_string(&value).unwrap(),
            r#"{"status":"error","code":"ERR_NOT_FOUND","description":"Not Found"}"#
        );

        let (value, status) = invalid_id();
        assert_eq!(status, 400);
        assert_eq!(code_of(&value), ERR_INVALID_REQUEST);
    }
}
