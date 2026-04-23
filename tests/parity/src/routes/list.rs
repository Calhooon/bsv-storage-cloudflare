//! `/list` scenarios — see PROTOCOL.md §4.
//!
//! `/list` is BRC-31-authenticated and state-dependent: nanostore has ~96
//! adverts in its admin wallet, our worker has 1 (or 0). Byte-exact diff is
//! impossible; we use **shape-equal** with `$VOLATILE:<type>$` sentinels
//! for the row values, so drift in the envelope (key names, field order,
//! row schema) still fails the harness.
//!
//! # Auth
//!
//! `/list` is BRC-31-authenticated; live-fire as of task #28 (BRC-31 client
//! port). The caller's identity key scopes the query — our parity identity
//! typically has 0 owned adverts, matching nanostore's listing-for-this-key
//! path. The fixture's `uploads` field uses `$VOLATILE:array$` because
//! content depends on who runs the harness and when.

use super::{AuthMode, Method, Scenario};

pub fn scenarios() -> Vec<Scenario> {
    vec![Scenario {
        route: "/list",
        name: "my-adverts",
        method: Method::Get,
        // GET /list carries no body — pagination lives in optional query
        // params (`limit`, `skip`). nanostore runs behind Cloudflare's edge,
        // which rejects GET+body as malformed (HTTP 400) before the handler
        // ever sees it. Matching the TS SDK caller: `AuthFetch.fetch("/list")`
        // sends GET with no body.
        body: None,
        query: None,
        skip_reason: None,
        auth: AuthMode::Brc31,
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
    fn scenario_is_live_fire_brc31() {
        let s = &scenarios()[0];
        assert!(s.skip_reason.is_none());
        assert_eq!(s.auth, AuthMode::Brc31);
    }
}
