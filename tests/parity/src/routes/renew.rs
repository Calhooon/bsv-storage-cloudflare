//! `/renew` scenarios — see PROTOCOL.md §5.
//!
//! **Ours-only**: `/renew` requires the caller to OWN the advertisement
//! being renewed. Our parity identity has no adverts on nanostore (their
//! admin wallet is separate), so live-fire against nanostore is
//! structurally unreachable. We live-fire against the locally-deployed
//! worker (`PARITY_STORAGE_URL`) instead, exercising the "advert not
//! found" error path with a well-formed uhrpUrl that doesn't correspond
//! to anything in the local R2.
//!
//! # Payment
//!
//! Our worker currently pins `/renew`'s price at 0 sats at the
//! middleware layer (`src/lib.rs` — "flat 0 price into the payment
//! middleware so the client can reach the handler without payment"),
//! so the scenario uses `AuthMode::Brc31` (no payment retry) and still
//! reaches the handler. If the worker's pricing flips to non-zero,
//! switch this to `Brc31Paid` and wire the `/upload → poll → /renew`
//! precondition chain (sat-spending; needs a known-owned uhrpUrl).

use super::{AuthMode, Method, Scenario};

pub fn scenarios() -> Vec<Scenario> {
    vec![Scenario {
        route: "/renew",
        name: "renew-our-advert",
        method: Method::Post,
        body: Some(serde_json::json!({
            // Well-formed UHRP URL that the parity identity does NOT own
            // on our worker's D1. Triggers the
            // `ERR_OLD_ADVERTISEMENT_NOT_FOUND` 404 path cleanly — no
            // sats spent, no chain activity, no queue side effects.
            "uhrpUrl": "uhrp://XUT76BxnjKMchLyNe1VuQRxkvLVSLD21QXwM4JywLKabu",
            // 30 days. Small + round so the pricing doesn't trigger weird
            // boundary conditions in the formula.
            "additionalMinutes": 43_200u64,
        })),
        query: None,
        skip_reason: None,
        auth: AuthMode::Brc31,
        ours_only: true,
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
    fn scenario_is_live_fire_ours_only() {
        let s = &scenarios()[0];
        assert!(s.skip_reason.is_none());
        assert_eq!(s.auth, AuthMode::Brc31);
        assert!(
            s.ours_only,
            "/renew is ours-only — parity identity doesn't own any adverts on nanostore"
        );
    }
}
