//! `/find` scenarios — see PROTOCOL.md §3.
//!
//! All three scenarios here are **error paths** — nonexistent / missing
//! / malformed — which makes them byte-exact candidates: the server's
//! happy-path response is state-dependent (depends on indexed files), but
//! an error is just a fixed `ErrorBody` shape with a known code/description.
//!
//! # Auth
//!
//! `/find` is BRC-31-authenticated. As of task #28 the harness owns a
//! pure-Rust BRC-31 client (`src/auth.rs`, wrapping `bsv_rs::auth::Peer` +
//! `SimplifiedFetchTransport`) so these scenarios run live-fire against
//! both nanostore.babbage.systems and our worker.

use super::{AuthMode, Method, Scenario};

pub fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            route: "/find",
            name: "nonexistent-uhrp-url",
            method: Method::Get,
            body: None,
            // A well-formed UHRP URL that no uploader has advertised. Nanostore's
            // `getMetadata` throws → route returns `ERR_FIND` 500. We use a
            // deterministic base58check string; the specific value doesn't matter
            // as long as it's stably "not in the index".
            query: Some(
                "uhrpUrl=uhrp%3A%2F%2FXUT76BxnjKMchLyNe1VuQRxkvLVSLD21QXwM4JywLKabu".to_string(),
            ),
            skip_reason: None,
            auth: AuthMode::Brc31,
            ours_only: false,
        },
        Scenario {
            route: "/find",
            name: "missing-query-param",
            method: Method::Get,
            body: None,
            // No `uhrpUrl` query — handler emits `ERR_NO_UHRP_URL` 400.
            query: None,
            skip_reason: None,
            auth: AuthMode::Brc31,
            ours_only: false,
        },
        Scenario {
            route: "/find",
            name: "malformed-uhrp-url",
            method: Method::Get,
            body: None,
            // Neither `uhrp://` nor base58check — the TS SDK's
            // `StorageUtils.getHashFromURL` throws inside `getMetadata`, so
            // the handler catches and emits `ERR_FIND` 500.
            query: Some("uhrpUrl=not-a-valid-uhrp-url".to_string()),
            skip_reason: None,
            auth: AuthMode::Brc31,
            ours_only: false,
        },
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn three_scenarios_registered() {
        assert_eq!(scenarios().len(), 3);
    }

    #[test]
    fn all_are_live_fire_brc31() {
        for s in scenarios() {
            assert!(
                s.skip_reason.is_none(),
                "{}: should be live-fire now that src/auth.rs is implemented",
                s.name,
            );
            assert_eq!(
                s.auth,
                AuthMode::Brc31,
                "{}: /find requires BRC-31 auth",
                s.name
            );
        }
    }

    #[test]
    fn every_scenario_stem_unique() {
        let stems: Vec<String> = scenarios().iter().map(|s| s.fixture_stem()).collect();
        let mut sorted = stems.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), stems.len(), "duplicate scenario stems");
    }
}
