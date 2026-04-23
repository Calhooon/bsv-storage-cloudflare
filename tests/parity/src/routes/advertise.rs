//! `/advertise` scenarios — see PROTOCOL.md §6.
//!
//! **Ours-only**: nanostore's `/advertise` is admin-gated on a shared
//! `ADMIN_TOKEN` we don't possess. This worker gates on a BRC-31
//! identity-key allowlist (`ADMIN_IDENTITY_KEYS`). If the parity identity
//! is added to that allowlist, we can live-fire against the local
//! deployment (`PARITY_STORAGE_URL`) and prove the response shape
//! matches the TS-pinned contract.
//!
//! The scenario uses an intentionally-malformed `uhrpUrl` so we hit
//! `ERR_INVALID_REQUEST` without spending any admin-wallet sats or
//! broadcasting synthetic adverts to the network. If we ever want
//! happy-path `/advertise` in live-fire, it needs to chain off a real
//! `/upload` + object existence check (see `/renew` for the pattern).

use super::{AuthMode, Method, Scenario};

pub fn scenarios() -> Vec<Scenario> {
    vec![Scenario {
        route: "/advertise",
        name: "advertise-already-uploaded",
        method: Method::Post,
        body: Some(serde_json::json!({
            // Deliberately malformed `uhrpUrl` (not a valid base58check)
            // so `uhrp_url_to_hash()` rejects with ERR_INVALID_REQUEST
            // 400 before we touch R2, the admin wallet, or the chain.
            // Keeps the test idempotent + sat-free while still proving
            // admin-auth + body-validation + error-shape parity.
            "uhrpUrl": "uhrp://not-a-valid-base58check",
            "objectIdentifier": "AAAAAAAAAAAAAAAAAAAAAA",
            "uploaderIdentityKey":
                "020000000000000000000000000000000000000000000000000000000000000000",
            "fileSize": 1_048_576u64,
            "expiryTime": 1_808_467_200u64,
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
            "/advertise is intrinsically ours-only — nanostore admin token is private"
        );
    }
}
