//! `/quote` scenarios — see PROTOCOL.md §1.
//!
//! `/quote` is the simplest route: POST a JSON body, receive `{quote: u64}`.
//! No auth, no payment, no statefulness. Its canonical scenario exercises the
//! BSV-rate lookup + rounding path with a deterministic 1 MiB / 1 month input.

use super::{AuthMode, Method, Scenario};
use serde_json::json;

pub fn scenarios() -> Vec<Scenario> {
    vec![Scenario {
        route: "/quote",
        name: "small-file",
        method: Method::Post,
        body: Some(json!({
            // 1 MiB for 1 month (43,200 minutes). Tiny, deterministic request
            // that exercises the BSV-rate lookup + rounding path without
            // needing a large/expensive quote.
            "fileSize": 1_048_576u64,
            "retentionPeriod": 43_200u64,
        })),
        query: None,
        skip_reason: None,
        auth: AuthMode::Unauthenticated,
        ours_only: false,
    }]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn scenario_has_stable_stem() {
        let s = scenarios().into_iter().next().unwrap();
        assert_eq!(s.fixture_stem(), "quote.small-file");
    }
}
