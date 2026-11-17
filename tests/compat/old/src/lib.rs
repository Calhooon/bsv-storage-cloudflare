//! The storage's modules, mounted from `../../v0_2_4/src` as they are, with the
//! crates they were released on. `lib.rs` (the Worker's entry points) and
//! `health.rs` (its build stamp) are not mounted.

#![allow(dead_code, clippy::all)]

pub use bsv_middleware_cloudflare as middleware;
pub use bsv_rs;

#[path = "../../v0_2_4/src/error.rs"]
pub mod error;
#[path = "../../v0_2_4/src/link_cost.rs"]
pub mod link_cost;
#[path = "../../v0_2_4/src/overlay/mod.rs"]
pub mod overlay;
#[path = "../../v0_2_4/src/queue/mod.rs"]
pub mod queue;
#[path = "../../v0_2_4/src/routes/mod.rs"]
pub mod routes;
#[path = "../../v0_2_4/src/storage/mod.rs"]
pub mod storage;
#[path = "../../v0_2_4/src/types.rs"]
pub mod types;
#[path = "../../v0_2_4/src/uhrp/mod.rs"]
pub mod uhrp;
#[path = "../../v0_2_4/src/validation.rs"]
pub mod validation;
#[path = "../../v0_2_4/src/wallet/mod.rs"]
pub mod wallet;

/// The SHIP hosts the fan-out takes from a tracker's lookup answer.
pub fn hosts_from_lookup_answer(body: &[u8]) -> Result<Vec<String>, String> {
    overlay::hosts_from_lookup_answer(body)
}

/// The bound on a tracker's lookup answer.
pub const LOOKUP_ANSWER_MAX_BYTES: usize = overlay::LOOKUP_ANSWER_MAX_BYTES;
