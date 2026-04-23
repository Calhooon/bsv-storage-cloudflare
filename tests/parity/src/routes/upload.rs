//! `/upload` scenarios — see PROTOCOL.md §2.
//!
//! **Ours-only**: nanostore's GCP signing URL rejects the 65 KiB BRC-29
//! `x-bsv-payment` header with an 8 KiB header limit (413). Our R2 backend
//! accepts it. So we don't run this one against nanostore — we assert our
//! worker's response matches the frozen TS spec fixture (PROTOCOL.md §2
//! "Example: Upload Request & Response") using `$VOLATILE:<type>$` sentinels
//! for the dynamic parts (`uploadURL`, `x-goog-custom-time` equivalent,
//! `amount` — which depends on the live exchange rate).
//!
//! # Auth + payment note
//!
//! `/upload` requires BRC-31 auth **and** BRC-29 payment. The harness would
//! need to pay a quote before hitting the route. Until wired, the scenario
//! is committed as a contract document.

use super::{AuthMode, Method, Scenario};

// Fully wired as of task #30 phase 2. BRC-31 + BRC-29 payment both
// go through the harness (src/auth.rs + src/payment.rs + src/wallet.rs).
// The old "65KB payment header" blocker was a hack artifact of the
// broken Python-era envelope; the new envelope is ~1-2KB.
//
// Live-fire against both nanostore.babbage.systems and our worker.
// Sats cost per run: one tx paying the quoted amount (~tens of sats
// for a 1 MiB / 30-day file; depends on live exchange rate).
//
// ## `requiredHeaders` — backend-specific (task #44)
//
// The fixture's `requiredHeaders` field is pinned as
// `$VOLATILE:string_map$` — non-empty JSON object with all string
// values. Nanostore (GCS-backed) returns `x-goog-*` keys; our worker
// (R2-S3-backed) returns `x-amz-*` keys. Both are spec-compliant:
// clients iterate the map dynamically and don't hardcode names. The
// sentinel pins the actual wire contract ("map of headers to echo")
// without picking a winner on the storage backend. See
// `canon::VolatileKind::StringMap` docs + the task-#44-tagged tests
// in canon.rs for the full argument.

pub fn scenarios() -> Vec<Scenario> {
    vec![Scenario {
        route: "/upload",
        name: "upload-small-file",
        method: Method::Post,
        body: Some(serde_json::json!({
            // Same size + retention as /quote small-file so the pricing
            // path is identical to the /quote small-file capture.
            "fileSize": 1_048_576u64,
            "retentionPeriod": 43_200u64,
        })),
        query: None,
        skip_reason: None,
        auth: AuthMode::Brc31Paid,
        ours_only: false,
    }]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn single_scenario_registered() {
        assert_eq!(scenarios().len(), 1);
    }

    #[test]
    fn scenario_is_live_fire_paid() {
        let s = &scenarios()[0];
        assert!(s.skip_reason.is_none());
        assert_eq!(s.auth, AuthMode::Brc31Paid);
    }
}
