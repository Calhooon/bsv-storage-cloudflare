//! POST /quote — see PROTOCOL.md §1. Stateless. Unauthenticated.
//!
//! Port of `src/routes/quote.ts` + `src/utils/getPriceForFile.ts`. Validation
//! order, error codes, and descriptions are copied verbatim from the TS
//! source so parity tests against nanostore.babbage.systems pass.

use crate::error::{
    ERR_INTERNAL, ERR_INVALID_RETENTION_PERIOD, ERR_INVALID_SIZE, ERR_NO_RETENTION_PERIOD,
    ERR_NO_SIZE,
};
use crate::types::{ErrorBody, QuoteRequest, QuoteResponse};
use serde::Deserialize;
use serde_json::{json, Value};
use worker::{Env, Fetch, Method, Request, RequestInit};

/// WhatsOnChain exchange-rate endpoint. See PROTOCOL.md §D.
const WOC_EXCHANGE_RATE_URL: &str = "https://api.whatsonchain.com/v1/bsv/main/exchangerate";

/// Hard-coded fallback if the WoC fetch fails. Diverges from TS (was 30.0) —
/// current BSV/USD is ~$16, so a 30.0 fallback would under-charge users in
/// sats terms whenever WoC is unreachable.
const FALLBACK_EXCHANGE_RATE_USD_PER_BSV: f64 = 15.0;

/// Minimum satoshi price. Diverges from TS (was 10). The per-upload overlay
/// broadcast costs ~500 sats in miner fees regardless of file size; a 10-sat
/// floor meant every tiny upload was a net loss. 1000 sats ≈ $0.00016 at
/// BSV=$16 — trivial to users, covers the broadcast with 2× margin.
const MIN_SATOSHI_PRICE: u64 = 1000;

/// Hard-coded maximum retention (PROTOCOL.md §1 validation, TS line 69).
const MAX_RETENTION_MINUTES: f64 = 69_000_000.0;

#[derive(Debug, Deserialize)]
struct WocRate {
    rate: f64,
}

pub async fn handle(body: &[u8], env: &Env) -> (Value, u16) {
    // Pre-auth — match TS Express behaviour: an empty / unparsable body causes
    // destructuring to yield `undefined`, which falls through to `ERR_NO_SIZE`.
    let req: QuoteRequest = serde_json::from_slice(body).unwrap_or(QuoteRequest {
        file_size: None,
        retention_period: None,
    });

    let min_hosting_minutes_raw = env
        .var("MIN_HOSTING_MINUTES")
        .ok()
        .map(|v| v.to_string())
        .unwrap_or_default();

    match validate(&req, &min_hosting_minutes_raw) {
        Err((code, description, status)) => (json!(ErrorBody::new(code, description)), status),
        Ok((file_size, retention_period)) => {
            let price_per_gb_mo = match env.var("PRICE_PER_GB_MO") {
                Ok(v) => v.to_string(),
                Err(_) => return internal_error(),
            };
            let price_per_gb_mo: f64 = match price_per_gb_mo.parse::<f64>() {
                Ok(v) if !v.is_nan() => v,
                _ => return internal_error(),
            };

            let exchange_rate = fetch_exchange_rate().await;
            let sat_price =
                compute_sat_price(file_size, retention_period, price_per_gb_mo, exchange_rate);
            (json!(QuoteResponse { quote: sat_price }), 200)
        }
    }
}

fn internal_error() -> (Value, u16) {
    (
        json!(ErrorBody::new(
            ERR_INTERNAL,
            "An internal error has occurred."
        )),
        500,
    )
}

/// Run the exact validation sequence from `src/routes/quote.ts`. Returns
/// `(fileSize, retentionPeriod)` on success, or `(code, description, status)`
/// on failure.
fn validate(
    req: &QuoteRequest,
    min_hosting_minutes_raw: &str,
) -> Result<(f64, f64), (&'static str, String, u16)> {
    // TS: `if (!fileSize)` — matches undefined, 0, NaN. We treat `None`, `0`,
    // and non-finite as "missing".
    let file_size = match req.file_size {
        Some(v) if v != 0.0 && v.is_finite() => v,
        _ => {
            return Err((
                ERR_NO_SIZE,
                "Provide the size of the file you want to host.".to_string(),
                400,
            ));
        }
    };

    // TS: `if (!retentionPeriod)` — same rule as above.
    let retention_period = match req.retention_period {
        Some(v) if v != 0.0 && v.is_finite() => v,
        _ => {
            return Err((
                ERR_NO_RETENTION_PERIOD,
                "Specify the number of minutes to host the file.".to_string(),
                400,
            ));
        }
    };

    // TS: `!Number.isInteger(Number(fileSize)) || fileSize <= 0`.
    if file_size.fract() != 0.0 || file_size <= 0.0 {
        return Err((
            ERR_INVALID_SIZE,
            "The file size must be an integer.".to_string(),
            400,
        ));
    }

    // TS: `const minHostingMinutes = Number(MIN_HOSTING_MINUTES) || 0`.
    // If env var is missing/blank/NaN, `Number(...) || 0` yields 0.
    let min_hosting_minutes: f64 = min_hosting_minutes_raw.parse().ok().unwrap_or(0.0);
    let min_hosting_minutes = if min_hosting_minutes.is_nan() {
        0.0
    } else {
        min_hosting_minutes
    };

    // TS: `!Number.isInteger(Number(retentionPeriod)) || retentionPeriod < minHostingMinutes`.
    if retention_period.fract() != 0.0 || retention_period < min_hosting_minutes {
        // TS interpolates `${MIN_HOSTING_MINUTES}` (the raw env var). If the
        // env var is unset, JS `${undefined}` renders as the literal string
        // "undefined" — we preserve that quirk.
        let rendered = if min_hosting_minutes_raw.is_empty() {
            "undefined"
        } else {
            min_hosting_minutes_raw
        };
        return Err((
            ERR_INVALID_RETENTION_PERIOD,
            format!(
                "The retention period must be an integer and must be more than {rendered} minutes"
            ),
            400,
        ));
    }

    if retention_period > MAX_RETENTION_MINUTES {
        return Err((
            ERR_INVALID_RETENTION_PERIOD,
            "The retention period must be less than 69 million minutes (about 130 years)"
                .to_string(),
            400,
        ));
    }

    Ok((file_size, retention_period))
}

/// Compute the upload/renew price in satoshis for the BRC-29 middleware.
///
/// Fetches the live WhatsOnChain rate + reads `PRICE_PER_GB_MO` from env.
/// Matches the TS payment middleware's price calculation in
/// `src/index.ts:105–114`. Returns 0 on any env/arithmetic failure (= free
/// pass; the route handler then produces the 400 with the correct error
/// code).
pub async fn compute_price_from_env(file_size: f64, retention_period: f64, env: &Env) -> u64 {
    let price_per_gb_mo: f64 = match env
        .var("PRICE_PER_GB_MO")
        .ok()
        .and_then(|v| v.to_string().parse::<f64>().ok())
    {
        Some(v) if v.is_finite() => v,
        _ => return 0,
    };
    let exchange_rate = fetch_exchange_rate().await;
    compute_sat_price(file_size, retention_period, price_per_gb_mo, exchange_rate)
}

/// Compute satoshi price per PROTOCOL.md §D. Pure — no I/O, unit-testable.
fn compute_sat_price(
    file_size_bytes: f64,
    retention_minutes: f64,
    price_per_gb_mo_usd: f64,
    exchange_rate_usd_per_bsv: f64,
) -> u64 {
    let file_size_gb = file_size_bytes / 1_000_000_000.0;
    let retention_months = retention_minutes / (60.0 * 24.0 * 30.0);
    let usd_price = file_size_gb * retention_months * price_per_gb_mo_usd;
    let exchange_rate_in_satoshis = 1.0 / (exchange_rate_usd_per_bsv / 100_000_000.0);
    let raw = (usd_price * exchange_rate_in_satoshis).floor();
    // `Math.max(10, floor(...))` in TS — never negative in practice, but clamp
    // below MIN_SATOSHI_PRICE either way.
    if raw < MIN_SATOSHI_PRICE as f64 {
        MIN_SATOSHI_PRICE
    } else {
        raw as u64
    }
}

/// Hit WhatsOnChain for the live BSV/USD rate. On ANY failure (network, HTTP
/// non-2xx, parse error, NaN), fall back to 30 USD/BSV — matches TS line 46.
async fn fetch_exchange_rate() -> f64 {
    match fetch_exchange_rate_inner().await {
        Some(rate) if rate.is_finite() && rate > 0.0 => rate,
        _ => FALLBACK_EXCHANGE_RATE_USD_PER_BSV,
    }
}

async fn fetch_exchange_rate_inner() -> Option<f64> {
    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    let request = Request::new_with_init(WOC_EXCHANGE_RATE_URL, &init).ok()?;
    let mut response = Fetch::Request(request).send().await.ok()?;

    let status = response.status_code();
    if !(200..300).contains(&status) {
        return None;
    }

    let parsed: WocRate = response.json().await.ok()?;
    Some(parsed.rate)
}

#[cfg(test)]
mod tests {
    // Unwraps are fine in tests — panic is the intended failure mode.
    #![allow(clippy::unwrap_used)]

    use super::*;

    // ── compute_sat_price ────────────────────────────────────────────────────

    #[test]
    fn spec_example_1mb_1day_hits_minimum() {
        // 1 MB, 1 day, 0.03 USD/GB/mo, 30 USD/BSV.
        // usd = 0.001 * 0.0333... * 0.03 ≈ 9.9e-7
        // sats = floor(9.9e-7 * 3_333_333.33) = 3 → clamped to MIN_SATOSHI_PRICE.
        assert_eq!(
            compute_sat_price(1_000_000.0, 1440.0, 0.03, 30.0),
            MIN_SATOSHI_PRICE
        );
    }

    #[test]
    fn spec_example_100mb_1mo() {
        // 100 MB for 1 month at 0.03 USD/GB/mo, 30 USD/BSV.
        // usd = 0.1 * 1 * 0.03 = 0.003 (exact in fp)
        // satsPerUsd = 3_333_333.333...
        // raw = 0.003 * 3_333_333.333 = 10000.0 → floor = 10_000
        // (PROTOCOL.md §D's "43,000" table row uses different retention; we
        // verify the pure formula deterministically here.)
        let got = compute_sat_price(100_000_000.0, 43_200.0, 0.03, 30.0);
        assert_eq!(got, 10_000);
    }

    #[test]
    fn spec_example_1gb_1year() {
        // 1 GB for 1 year at 0.03 USD/GB/mo, 30 USD/BSV.
        // retentionMonths = 525600 / 43200 = 12.1666...
        // usd = 1 * 12.1666... * 0.03 = 0.365
        // sats = floor(0.365 * 3_333_333.33) = 1_216_666
        let got = compute_sat_price(1_000_000_000.0, 525_600.0, 0.03, 30.0);
        assert_eq!(got, 1_216_666);
    }

    #[test]
    fn below_floor_clamps_to_minimum() {
        // Trivially small usd price must floor to MIN_SATOSHI_PRICE.
        assert_eq!(compute_sat_price(1.0, 1.0, 0.03, 30.0), MIN_SATOSHI_PRICE);
    }

    #[test]
    fn zero_inputs_return_minimum() {
        assert_eq!(
            compute_sat_price(0.0, 1440.0, 0.03, 30.0),
            MIN_SATOSHI_PRICE
        );
        assert_eq!(
            compute_sat_price(1_000_000.0, 0.0, 0.03, 30.0),
            MIN_SATOSHI_PRICE
        );
    }

    #[test]
    fn fallback_rate_produces_deterministic_output() {
        // Fallback is 15 USD/BSV. 1 GB × 1 year × $0.03/GB-mo:
        // usd = 1 * 12.1666... * 0.03 = 0.365
        // satsPerUsd = 1 / (15/1e8) = 6_666_666.666...
        // raw = 0.365 * 6_666_666.666 = 2_433_333.33 → floor = 2_433_333
        let got = compute_sat_price(
            1_000_000_000.0,
            525_600.0,
            0.03,
            FALLBACK_EXCHANGE_RATE_USD_PER_BSV,
        );
        assert_eq!(got, 2_433_333);
    }

    // ── validate ─────────────────────────────────────────────────────────────

    fn req(size: Option<f64>, period: Option<f64>) -> QuoteRequest {
        QuoteRequest {
            file_size: size,
            retention_period: period,
        }
    }

    #[test]
    fn missing_file_size_is_err_no_size() {
        let r = validate(&req(None, Some(1440.0)), "").unwrap_err();
        assert_eq!(r.0, ERR_NO_SIZE);
        assert_eq!(r.2, 400);
    }

    #[test]
    fn zero_file_size_is_err_no_size() {
        // JS `!0 === true` → ERR_NO_SIZE, not ERR_INVALID_SIZE.
        let r = validate(&req(Some(0.0), Some(1440.0)), "").unwrap_err();
        assert_eq!(r.0, ERR_NO_SIZE);
    }

    #[test]
    fn missing_retention_period_is_err_no_retention() {
        let r = validate(&req(Some(1_000_000.0), None), "").unwrap_err();
        assert_eq!(r.0, ERR_NO_RETENTION_PERIOD);
        assert_eq!(r.2, 400);
    }

    #[test]
    fn non_integer_file_size_is_err_invalid_size() {
        let r = validate(&req(Some(1.5), Some(1440.0)), "").unwrap_err();
        assert_eq!(r.0, ERR_INVALID_SIZE);
        assert_eq!(r.1, "The file size must be an integer.");
    }

    #[test]
    fn negative_file_size_is_err_invalid_size() {
        let r = validate(&req(Some(-10.0), Some(1440.0)), "").unwrap_err();
        assert_eq!(r.0, ERR_INVALID_SIZE);
    }

    #[test]
    fn non_integer_retention_is_err_invalid_retention() {
        let r = validate(&req(Some(1_000_000.0), Some(1.5)), "").unwrap_err();
        assert_eq!(r.0, ERR_INVALID_RETENTION_PERIOD);
    }

    #[test]
    fn retention_below_min_is_err_invalid_retention() {
        // MIN_HOSTING_MINUTES=1000, request 500 → rejected.
        let r = validate(&req(Some(1_000_000.0), Some(500.0)), "1000").unwrap_err();
        assert_eq!(r.0, ERR_INVALID_RETENTION_PERIOD);
        assert!(r.1.contains("1000"));
    }

    #[test]
    fn retention_above_max_is_err_invalid_retention() {
        let r = validate(&req(Some(1_000_000.0), Some(70_000_000.0)), "").unwrap_err();
        assert_eq!(r.0, ERR_INVALID_RETENTION_PERIOD);
        assert_eq!(
            r.1,
            "The retention period must be less than 69 million minutes (about 130 years)"
        );
    }

    #[test]
    fn missing_min_env_renders_undefined_like_js() {
        // Matches TS template-literal behaviour with an undefined env var.
        let r = validate(&req(Some(1_000_000.0), Some(0.5)), "").unwrap_err();
        assert_eq!(r.0, ERR_INVALID_RETENTION_PERIOD);
        assert!(r.1.contains("undefined"));
    }

    #[test]
    fn valid_inputs_pass() {
        let (fs, rp) = validate(&req(Some(1_000_000.0), Some(1440.0)), "0").unwrap();
        assert_eq!(fs, 1_000_000.0);
        assert_eq!(rp, 1440.0);
    }
}
