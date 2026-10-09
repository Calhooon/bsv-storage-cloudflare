//! Storage seam for the `/drafts` routes (the-composer #29).
//!
//! `worker::kv::KvStore` only functions on a live Workers runtime, which is
//! why the four `/drafts` handlers historically had zero executed tests —
//! only their pure helpers were covered. [`DraftStore`] abstracts exactly
//! the KV operations the handlers perform:
//!
//! - [`KvDraftStore`] is the production implementation over the
//!   `COMPOSER_DRAFTS` binding (thin, no logic — every branch it wraps is a
//!   one-line KV call).
//! - [`MemoryDraftStore`] (test-only) is a deterministic in-memory fake
//!   with TTL support, fault injection, forced page sizes, and a settable
//!   clock, so every handler branch — 409-carries-stored-copy, cursor
//!   pagination, KV-error 500s, tombstone TTL — executes under
//!   `cargo test`.
//!
//! The trait is `pub(crate)` and uses native `async fn` (single-threaded
//! Workers runtime; no `Send` bounds needed or wanted — KV futures are
//! `!Send`).

use crate::types::DraftKvMetadata;
use worker::kv::KvStore;

/// Opaque storage failure. Handlers map every storage error to the same
/// HTTP 500 the previous inline-KV code produced; carrying backend detail
/// here would only tempt handlers into leaking it to clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StoreError;

/// One key row of a prefix listing.
pub(crate) struct ListedKey {
    pub name: String,
    /// KV metadata as stored (already JSON-decoded by the runtime).
    pub metadata: Option<serde_json::Value>,
}

/// One page of a prefix listing. Mirrors the fields the handlers consume
/// from `worker::kv`'s list response.
pub(crate) struct ListedPage {
    pub keys: Vec<ListedKey>,
    pub cursor: Option<String>,
    pub list_complete: bool,
}

/// The KV surface `/drafts` needs, and nothing more.
pub(crate) trait DraftStore {
    /// Read a value as text. `Ok(None)` = key absent (or expired).
    async fn get_text(&self, key: &str) -> Result<Option<String>, StoreError>;

    /// Upsert a draft value with its list metadata (no expiry).
    async fn put_draft(
        &self,
        key: &str,
        value: &str,
        metadata: &DraftKvMetadata,
    ) -> Result<(), StoreError>;

    /// Upsert a value with a TTL in seconds (tombstones, #27).
    async fn put_expiring(
        &self,
        key: &str,
        value: &str,
        ttl_seconds: u64,
    ) -> Result<(), StoreError>;

    /// Delete a key. Deleting an absent key succeeds (KV semantics).
    async fn delete(&self, key: &str) -> Result<(), StoreError>;

    /// One page of keys under `prefix`, at most `limit` rows, resuming from
    /// `cursor` (an opaque token from the previous page).
    async fn list_page(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: u64,
    ) -> Result<ListedPage, StoreError>;

    /// Server clock, ms since epoch — injected so tombstone ordinals are
    /// deterministic in tests.
    fn now_ms(&self) -> u64;
}

/// Production [`DraftStore`] over the `COMPOSER_DRAFTS` KV binding.
pub(crate) struct KvDraftStore {
    kv: KvStore,
}

impl KvDraftStore {
    pub(crate) fn new(kv: KvStore) -> Self {
        Self { kv }
    }
}

impl DraftStore for KvDraftStore {
    async fn get_text(&self, key: &str) -> Result<Option<String>, StoreError> {
        self.kv.get(key).text().await.map_err(|_| StoreError)
    }

    async fn put_draft(
        &self,
        key: &str,
        value: &str,
        metadata: &DraftKvMetadata,
    ) -> Result<(), StoreError> {
        self.kv
            .put(key, value)
            .and_then(|builder| builder.metadata(metadata))
            .map_err(|_| StoreError)?
            .execute()
            .await
            .map_err(|_| StoreError)
    }

    async fn put_expiring(
        &self,
        key: &str,
        value: &str,
        ttl_seconds: u64,
    ) -> Result<(), StoreError> {
        self.kv
            .put(key, value)
            .map_err(|_| StoreError)?
            .expiration_ttl(ttl_seconds)
            .execute()
            .await
            .map_err(|_| StoreError)
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.kv.delete(key).await.map_err(|_| StoreError)
    }

    async fn list_page(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: u64,
    ) -> Result<ListedPage, StoreError> {
        let mut request = self.kv.list().prefix(prefix.to_string()).limit(limit);
        if let Some(c) = cursor {
            request = request.cursor(c.to_string());
        }
        let page = request.execute().await.map_err(|_| StoreError)?;
        Ok(ListedPage {
            keys: page
                .keys
                .into_iter()
                .map(|k| ListedKey {
                    name: k.name,
                    metadata: k.metadata,
                })
                .collect(),
            cursor: page.cursor,
            list_complete: page.list_complete,
        })
    }

    fn now_ms(&self) -> u64 {
        js_sys::Date::now() as u64
    }
}

// ─── test doubles ────────────────────────────────────────────────────────────

/// Deterministic in-memory [`DraftStore`] for executed handler tests.
///
/// Semantics mirror Cloudflare KV where the handlers depend on them:
/// lexicographic key order in listings, opaque page cursors, TTL expiry
/// (lazy, relative to the injected clock). Extras for test control:
/// per-operation fault injection, a forced page-size ceiling (to exercise
/// cursor loops with small datasets), and raw insertion (to plant corrupt
/// values or simulate list-lag ghosts).
#[cfg(test)]
pub(crate) struct MemoryDraftStore {
    entries: std::cell::RefCell<std::collections::BTreeMap<String, MemoryEntry>>,
    now_ms: std::cell::Cell<u64>,
    page_max: std::cell::Cell<Option<usize>>,
    fail_gets: std::cell::Cell<bool>,
    fail_puts: std::cell::Cell<bool>,
    fail_deletes: std::cell::Cell<bool>,
    fail_lists: std::cell::Cell<bool>,
}

#[cfg(test)]
#[derive(Debug, Clone)]
struct MemoryEntry {
    value: String,
    metadata: Option<serde_json::Value>,
    /// Absolute expiry (ms epoch); `None` = never expires.
    expires_at_ms: Option<u64>,
}

#[cfg(test)]
impl MemoryDraftStore {
    pub(crate) fn new() -> Self {
        Self {
            entries: std::cell::RefCell::new(std::collections::BTreeMap::new()),
            // Arbitrary fixed "wall clock"; tests can move it.
            now_ms: std::cell::Cell::new(1_750_000_000_000),
            page_max: std::cell::Cell::new(None),
            fail_gets: std::cell::Cell::new(false),
            fail_puts: std::cell::Cell::new(false),
            fail_deletes: std::cell::Cell::new(false),
            fail_lists: std::cell::Cell::new(false),
        }
    }

    pub(crate) fn set_now_ms(&self, now: u64) {
        self.now_ms.set(now);
    }

    pub(crate) fn advance_ms(&self, delta: u64) {
        self.now_ms.set(self.now_ms.get() + delta);
    }

    /// Force every listing page to at most `n` rows regardless of the
    /// requested limit — exercises the handlers' cursor loops.
    pub(crate) fn force_page_size(&self, n: usize) {
        self.page_max.set(Some(n));
    }

    pub(crate) fn fail_gets(&self, fail: bool) {
        self.fail_gets.set(fail);
    }

    pub(crate) fn fail_puts(&self, fail: bool) {
        self.fail_puts.set(fail);
    }

    pub(crate) fn fail_deletes(&self, fail: bool) {
        self.fail_deletes.set(fail);
    }

    pub(crate) fn fail_lists(&self, fail: bool) {
        self.fail_lists.set(fail);
    }

    /// Plant a raw entry, bypassing the trait — corrupt values, list-lag
    /// ghosts, foreign rows.
    pub(crate) fn insert_raw(&self, key: &str, value: &str, metadata: Option<serde_json::Value>) {
        self.entries.borrow_mut().insert(
            key.to_string(),
            MemoryEntry {
                value: value.to_string(),
                metadata,
                expires_at_ms: None,
            },
        );
    }

    /// The stored value for `key`, honoring expiry (test assertions).
    pub(crate) fn value_of(&self, key: &str) -> Option<String> {
        let entries = self.entries.borrow();
        entries
            .get(key)
            .filter(|e| !self.expired(e))
            .map(|e| e.value.clone())
    }

    pub(crate) fn contains(&self, key: &str) -> bool {
        self.value_of(key).is_some()
    }

    fn expired(&self, entry: &MemoryEntry) -> bool {
        entry
            .expires_at_ms
            .is_some_and(|at| at <= self.now_ms.get())
    }
}

#[cfg(test)]
impl DraftStore for MemoryDraftStore {
    async fn get_text(&self, key: &str) -> Result<Option<String>, StoreError> {
        if self.fail_gets.get() {
            return Err(StoreError);
        }
        Ok(self.value_of(key))
    }

    async fn put_draft(
        &self,
        key: &str,
        value: &str,
        metadata: &DraftKvMetadata,
    ) -> Result<(), StoreError> {
        if self.fail_puts.get() {
            return Err(StoreError);
        }
        let meta = serde_json::to_value(metadata).map_err(|_| StoreError)?;
        self.entries.borrow_mut().insert(
            key.to_string(),
            MemoryEntry {
                value: value.to_string(),
                metadata: Some(meta),
                expires_at_ms: None,
            },
        );
        Ok(())
    }

    async fn put_expiring(
        &self,
        key: &str,
        value: &str,
        ttl_seconds: u64,
    ) -> Result<(), StoreError> {
        if self.fail_puts.get() {
            return Err(StoreError);
        }
        self.entries.borrow_mut().insert(
            key.to_string(),
            MemoryEntry {
                value: value.to_string(),
                metadata: None,
                expires_at_ms: Some(self.now_ms.get() + ttl_seconds * 1000),
            },
        );
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        if self.fail_deletes.get() {
            return Err(StoreError);
        }
        self.entries.borrow_mut().remove(key);
        Ok(())
    }

    async fn list_page(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: u64,
    ) -> Result<ListedPage, StoreError> {
        if self.fail_lists.get() {
            return Err(StoreError);
        }
        let effective = {
            let requested = usize::try_from(limit).unwrap_or(usize::MAX).max(1);
            match self.page_max.get() {
                Some(forced) => requested.min(forced.max(1)),
                None => requested,
            }
        };

        let entries = self.entries.borrow();
        let mut keys = Vec::new();
        let mut more_after = false;
        for (name, entry) in entries.range::<String, _>((
            match cursor {
                // Cursor = last key of the previous page; resume strictly after.
                Some(c) => std::ops::Bound::Excluded(c.to_string()),
                None => std::ops::Bound::Unbounded,
            },
            std::ops::Bound::Unbounded,
        )) {
            if !name.starts_with(prefix) {
                // BTreeMap range is global; prefix rows are contiguous, so
                // once past them (with any collected) we can stop.
                if keys.is_empty() && name.as_str() < prefix {
                    continue;
                }
                break;
            }
            if self.expired(entry) {
                continue;
            }
            if keys.len() == effective {
                more_after = true;
                break;
            }
            keys.push(ListedKey {
                name: name.clone(),
                metadata: entry.metadata.clone(),
            });
        }

        let cursor = if more_after {
            keys.last().map(|k| k.name.clone())
        } else {
            None
        };
        Ok(ListedPage {
            list_complete: !more_after,
            keys,
            cursor,
        })
    }

    fn now_ms(&self) -> u64 {
        self.now_ms.get()
    }
}

/// Drive a handler future to completion on the current thread.
///
/// The handlers' async-ness exists for the KV boundary; against
/// [`MemoryDraftStore`] every await point is immediately ready, so a single
/// poll with a no-op waker completes the future — no async runtime needed
/// (and none that would have to compile for the wasm32 clippy gate).
#[cfg(test)]
pub(crate) fn block_on_ready<F: std::future::Future>(fut: F) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    match fut.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => {
            unreachable!("in-memory store futures are always immediately ready")
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn meta() -> DraftKvMetadata {
        DraftKvMetadata {
            title: "T".to_string(),
            updated_at: 1,
            section_count: 0,
            part_count: 0,
        }
    }

    #[test]
    fn memory_store_round_trips_values_and_metadata() {
        let store = MemoryDraftStore::new();
        block_on_ready(store.put_draft("a", "v1", &meta())).unwrap();
        assert_eq!(
            block_on_ready(store.get_text("a")).unwrap().as_deref(),
            Some("v1")
        );
        let page = block_on_ready(store.list_page("a", None, 10)).unwrap();
        assert_eq!(page.keys.len(), 1);
        assert!(page.keys[0].metadata.is_some());
        assert!(page.list_complete);
    }

    #[test]
    fn memory_store_lists_lexicographically_with_cursor_pages() {
        let store = MemoryDraftStore::new();
        for key in ["p:c", "p:a", "p:b", "q:z"] {
            block_on_ready(store.put_draft(key, "v", &meta())).unwrap();
        }
        store.force_page_size(2);

        let first = block_on_ready(store.list_page("p:", None, 100)).unwrap();
        let names: Vec<&str> = first.keys.iter().map(|k| k.name.as_str()).collect();
        assert_eq!(names, vec!["p:a", "p:b"]);
        assert!(!first.list_complete);

        let second = block_on_ready(store.list_page("p:", first.cursor.as_deref(), 100)).unwrap();
        let names: Vec<&str> = second.keys.iter().map(|k| k.name.as_str()).collect();
        assert_eq!(names, vec!["p:c"]);
        assert!(second.list_complete);
        assert!(second.cursor.is_none());
    }

    #[test]
    fn memory_store_expires_ttl_entries_relative_to_clock() {
        let store = MemoryDraftStore::new();
        store.set_now_ms(1_000_000);
        block_on_ready(store.put_expiring("tomb", "{}", 60)).unwrap();
        assert!(store.contains("tomb"));
        store.advance_ms(59_999);
        assert!(store.contains("tomb"));
        store.advance_ms(1);
        assert!(!store.contains("tomb"));
        assert_eq!(block_on_ready(store.get_text("tomb")).unwrap(), None);
        let page = block_on_ready(store.list_page("tomb", None, 10)).unwrap();
        assert!(page.keys.is_empty());
    }

    #[test]
    fn memory_store_fault_injection_fails_the_right_ops() {
        let store = MemoryDraftStore::new();
        store.fail_gets(true);
        assert_eq!(block_on_ready(store.get_text("x")), Err(StoreError));
        store.fail_gets(false);
        store.fail_puts(true);
        assert_eq!(
            block_on_ready(store.put_draft("x", "v", &meta())),
            Err(StoreError)
        );
        store.fail_puts(false);
        store.fail_deletes(true);
        assert_eq!(block_on_ready(store.delete("x")), Err(StoreError));
        store.fail_deletes(false);
        store.fail_lists(true);
        assert!(block_on_ready(store.list_page("x", None, 1)).is_err());
    }
}
