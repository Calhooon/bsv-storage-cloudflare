//! Fixture file format — **contract-only** artifact.
//!
//! Each fixture at `tests/parity/fixtures/<route>.<scenario>.json` is a
//! committed contract that asserts what the reference server returns for a
//! given request. It must be **stable unless the server contract changes**.
//!
//! # Shape (exactly these fields, in this order)
//!
//! ```json
//! {
//!   "route": "/quote",
//!   "scenario": "small-file",
//!   "request": { "method": "POST", "path": "/quote", "body": { ... } },
//!   "response": { "status_code": 200, "body": { "quote": 193 } }
//! }
//! ```
//!
//! # What's deliberately absent
//!
//! * No `captured_from` — a single fixture can be compared against any
//!   implementation; the source URL is a runtime parameter.
//! * No `captured_at_utc` — the fixture is not a log. Freshness lives in
//!   `tests/parity/.captures.log` (gitignored).
//! * No headers — PROTOCOL.md §1 (`/quote`) asserts nothing about headers.
//!   Adding them would be pure noise. Routes that DO make header assertions
//!   can extend this struct with a typed `assertions` sub-object later.
//!
//! # Why `body` is `serde_json::Value`, not a canonical string
//!
//! We keep the raw parsed body here and canonicalize it on read/write via
//! JCS ([`crate::canon::jcs`]). On-disk we serialize the whole fixture
//! through JCS too, so the file bytes are deterministic regardless of
//! serde key order.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Top-level fixture schema. Field order matters: the on-disk file is
/// serialized via [`crate::canon::jcs`], which sorts by key alphabetically,
/// so the source-level declaration order is only a readability hint for the
/// next human.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Fixture {
    pub route: String,
    pub scenario: String,
    pub request: RecordedRequest,
    pub response: CapturedResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapturedResponse {
    pub status_code: u16,
    pub body: serde_json::Value,
}

/// Outcome of writing a fixture. `Unchanged` means the on-disk JCS bytes
/// already matched what we would have written; we leave the file alone and
/// the working tree stays clean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    Unchanged,
    Created,
    Updated,
}

impl Fixture {
    /// Canonical on-disk bytes: the entire fixture run through RFC 8785 JCS.
    ///
    /// This is what we compare byte-for-byte on capture and what we hash
    /// into `.captures.log`. Because JCS sorts object keys recursively, the
    /// file is stable no matter which serde version produced the intermediate
    /// `Value`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        let value = serde_json::to_value(self).map_err(|e| format!("fixture to value: {e}"))?;
        crate::canon::jcs(&value)
    }

    /// Write the fixture only if its JCS bytes would differ from the
    /// on-disk file. Returns [`WriteOutcome`] so the caller can report
    /// "unchanged" vs "updated" without reading the file twice.
    pub fn write_if_changed(&self, path: &Path) -> Result<WriteOutcome, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        let new_bytes = self.canonical_bytes()?;

        let existing = std::fs::read(path).ok();
        let outcome = match existing {
            Some(old) if old == new_bytes => return Ok(WriteOutcome::Unchanged),
            Some(_) => WriteOutcome::Updated,
            None => WriteOutcome::Created,
        };
        std::fs::write(path, &new_bytes).map_err(|e| format!("write {}: {e}", path.display()))?;
        Ok(outcome)
    }
}

/// Absolute path to `tests/parity/fixtures/`.
pub fn fixtures_dir() -> PathBuf {
    let crate_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(crate_dir).join("fixtures")
}

/// Absolute path to `tests/parity/.captures.log` — a gitignored, append-only
/// operational log of every capture run. Not a contract; a forensics trail.
pub fn captures_log_path() -> PathBuf {
    let crate_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(crate_dir).join(".captures.log")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Fixture {
        Fixture {
            route: "/quote".into(),
            scenario: "small-file".into(),
            request: RecordedRequest {
                method: "POST".into(),
                path: "/quote".into(),
                body: Some(json!({ "fileSize": 1_048_576u64, "retentionPeriod": 43_200u64 })),
            },
            response: CapturedResponse {
                status_code: 200,
                body: json!({ "quote": 193 }),
            },
        }
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let f = sample();
        assert_eq!(f.canonical_bytes().unwrap(), f.canonical_bytes().unwrap());
    }

    #[test]
    fn canonical_bytes_sort_keys() {
        let f = sample();
        let s = String::from_utf8(f.canonical_bytes().unwrap()).unwrap();
        // Top-level keys come out in alphabetical order: request, response,
        // route, scenario.
        let pos_request = s.find("\"request\"").unwrap();
        let pos_response = s.find("\"response\"").unwrap();
        let pos_route = s.find("\"route\"").unwrap();
        let pos_scenario = s.find("\"scenario\"").unwrap();
        assert!(pos_request < pos_response);
        assert!(pos_response < pos_route);
        assert!(pos_route < pos_scenario);
    }

    #[test]
    fn write_if_changed_reports_unchanged_on_second_run() {
        let tmp =
            std::env::temp_dir().join(format!("parity-fixture-test-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&tmp);

        let f = sample();
        assert_eq!(f.write_if_changed(&tmp).unwrap(), WriteOutcome::Created);
        assert_eq!(f.write_if_changed(&tmp).unwrap(), WriteOutcome::Unchanged);

        // Mutate and expect Updated.
        let mut f2 = f.clone();
        f2.response.body = json!({ "quote": 194 });
        assert_eq!(f2.write_if_changed(&tmp).unwrap(), WriteOutcome::Updated);

        let _ = std::fs::remove_file(&tmp);
    }
}
