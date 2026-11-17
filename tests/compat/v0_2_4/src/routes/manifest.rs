//! Public, unsigned service discovery. Pricing shares the quote implementation.

use super::{quote, upload::MAX_UPLOAD_BYTES};
use bsv_rs::primitives::PrivateKey;
use serde::Serialize;
use std::collections::BTreeMap;
use worker::{Env, Error, Response, Result};

const MINUTES_PER_YEAR: f64 = 365.0 * 24.0 * 60.0;
const AUTH_PROTOCOL: &str = "brc-103/104";
const PAYMENT_TRANSPORT: &str = "header-only";
const CACHE_CONTROL: &str = "public, max-age=300";

struct Config {
    name: String,
    server_identity_key: String,
    public_url_base: String,
    price_per_gb_mo: f64,
    minimum_retention_minutes: f64,
}

impl Config {
    fn from_values(
        name: Option<&str>,
        server_key: &str,
        public_url_base: &str,
        price_per_gb_mo: &str,
        minimum_retention_minutes: &str,
    ) -> std::result::Result<Self, &'static str> {
        let server_identity_key = PrivateKey::from_hex(server_key)
            .map_err(|_| "SERVER_PRIVATE_KEY is invalid")?
            .public_key()
            .to_hex();
        let price_per_gb_mo = price_per_gb_mo
            .parse::<f64>()
            .ok()
            .filter(|v| v.is_finite())
            .ok_or("PRICE_PER_GB_MO must be finite")?;
        let minimum_retention_minutes = quote::minimum_retention_minutes(minimum_retention_minutes);
        if !minimum_retention_minutes.is_finite() {
            return Err("MIN_HOSTING_MINUTES must be finite");
        }
        if public_url_base.trim().is_empty() {
            return Err("PUBLIC_URL_BASE must not be empty");
        }
        Ok(Self {
            name: name.unwrap_or("bsv-storage-cloudflare").to_string(),
            server_identity_key,
            public_url_base: public_url_base.trim_end_matches('/').to_string(),
            price_per_gb_mo,
            minimum_retention_minutes,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    name: String,
    description: &'static str,
    auth_protocol: &'static str,
    auth_endpoint: &'static str,
    server_identity_key: String,
    capabilities: Capabilities,
    endpoints: Vec<Endpoint>,
    pricing: Pricing,
    public_url_format: PublicUrlFormat,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Capabilities {
    auth: &'static str,
    payment: &'static str,
    refunds: bool,
    payment_transport: &'static str,
    payment_transport_note: &'static str,
}

#[derive(Serialize)]
struct Endpoint {
    method: &'static str,
    path: &'static str,
    description: &'static str,
    auth: bool,
    payment: Option<Payment>,
    delivery: &'static str,
}

#[derive(Serialize)]
struct Payment {
    protocol: &'static str,
    dynamic: bool,
    transport: &'static str,
    description: &'static str,
}

#[derive(Serialize)]
struct Pricing {
    model: &'static str,
    currency: &'static str,
    margin: &'static str,
    #[serde(rename = "PRICE_PER_GB_MO")]
    price_per_gb_mo: f64,
    bsv_usd: f64,
    rates: BTreeMap<&'static str, f64>,
    minimum_satoshis: u64,
    minimum_retention_minutes: f64,
    maximum_file_size_bytes: u64,
    maximum_file_size_human: String,
    maximum_retention_minutes: u64,
    maximum_retention_human: String,
    formula: &'static str,
    formula_notes: BTreeMap<&'static str, String>,
    examples: BTreeMap<&'static str, Example>,
    note: String,
}

#[derive(Serialize)]
struct Example {
    usd: f64,
    satoshis: u64,
}

#[derive(Serialize)]
struct PublicUrlFormat {
    pattern: String,
    note: &'static str,
}

pub async fn handle(env: &Env) -> Result<Response> {
    let name = env.var("SERVICE_NAME").ok().map(|v| v.to_string());
    let minimum = env
        .var("MIN_HOSTING_MINUTES")
        .ok()
        .map(|v| v.to_string())
        .unwrap_or_default();
    let config = Config::from_values(
        name.as_deref(),
        &env.secret("SERVER_PRIVATE_KEY")?.to_string(),
        &env.var("PUBLIC_URL_BASE")?.to_string(),
        &env.var("PRICE_PER_GB_MO")?.to_string(),
        &minimum,
    )
    .map_err(Error::from)?;
    // One quote-rate fetch per request. The pure builder accepts a supplied rate
    // so native tests never touch the network or Worker bindings.
    let manifest = body(&config, quote::fetch_exchange_rate().await);
    let mut response = Response::from_json(&manifest)?;
    response
        .headers_mut()
        .set("Content-Type", "application/json")?;
    response.headers_mut().set("Cache-Control", CACHE_CONTROL)?;
    Ok(response)
}

fn endpoint(
    method: &'static str,
    path: &'static str,
    description: &'static str,
    auth: bool,
    paid: bool,
) -> Endpoint {
    Endpoint {
        method,
        path,
        description,
        auth,
        payment: paid.then_some(Payment {
            protocol: "brc-29",
            dynamic: true,
            transport: PAYMENT_TRANSPORT,
            description: "Send the authenticated request without payment to receive a signed 402 with the exact satoshi amount, then retry with payment JSON in the x-bsv-payment header; body mode is not supported.",
        }),
        delivery: "instant",
    }
}

fn body(config: &Config, exchange_rate: f64) -> Manifest {
    let rate_note = format!(
        "Live from WhatsOnChain; fallback {} USD/BSV on a failed fetch or invalid rate",
        quote::FALLBACK_EXCHANGE_RATE_USD_PER_BSV
    );
    let examples = [
        ("1_MB_1_year", 1_000_000.0),
        ("10_MB_1_year", 10_000_000.0),
        ("100_MB_1_year", 100_000_000.0),
        ("1_GB_1_year", 1_000_000_000.0),
    ]
    .into_iter()
    .map(|(name, bytes)| {
        (
            name,
            Example {
                usd: quote::compute_usd_price(bytes, MINUTES_PER_YEAR, config.price_per_gb_mo),
                satoshis: quote::compute_sat_price(
                    bytes,
                    MINUTES_PER_YEAR,
                    config.price_per_gb_mo,
                    exchange_rate,
                ),
            },
        )
    })
    .collect();

    Manifest {
        name: config.name.clone(),
        description: "UHRP file hosting on Cloudflare R2 with BRC-103/104 authentication, BRC-29 payments and public downloads.",
        auth_protocol: AUTH_PROTOCOL,
        auth_endpoint: "/.well-known/auth",
        server_identity_key: config.server_identity_key.clone(),
        capabilities: Capabilities {
            auth: AUTH_PROTOCOL,
            payment: "brc-29",
            refunds: false,
            payment_transport: PAYMENT_TRANSPORT,
            payment_transport_note: "Payment must be sent as JSON in the x-bsv-payment header; body mode (x-bsv-payment: body) is not supported.",
        },
        endpoints: vec![
            endpoint("GET", "/health", "Build provenance and health message; / is an alias.", false, false),
            endpoint("POST", "/quote", "Quote a file size and retention period in satoshis without authentication or payment.", false, false),
            endpoint("POST", "/upload", "Return a presigned R2 PUT URL and required headers for a paid upload; PUT the bytes directly to R2.", true, true),
            endpoint("POST", "/renew", "Pay to extend an existing advertisement using its recorded file size; any authenticated identity may renew.", true, true),
            endpoint("GET", "/find", "Find metadata for a UHRP URL belonging to the authenticated uploader.", true, false),
            endpoint("GET", "/list", "List files belonging to the authenticated uploader.", true, false),
            endpoint("POST", "/advertise", "Create a UHRP advertisement; the authenticated identity must also be in ADMIN_IDENTITY_KEYS.", true, false),
        ],
        pricing: Pricing {
            model: "per-GB-month",
            currency: "USD",
            margin: "0%",
            price_per_gb_mo: config.price_per_gb_mo,
            bsv_usd: exchange_rate,
            rates: BTreeMap::from([("USD_per_GB_month", config.price_per_gb_mo)]),
            minimum_satoshis: quote::MIN_SATOSHI_PRICE,
            minimum_retention_minutes: config.minimum_retention_minutes,
            maximum_file_size_bytes: MAX_UPLOAD_BYTES as u64,
            maximum_file_size_human: format!("{} GB ({} bytes, SI); enforced by /upload", MAX_UPLOAD_BYTES / 1_000_000_000.0, MAX_UPLOAD_BYTES as u64),
            maximum_retention_minutes: quote::MAX_RETENTION_MINUTES as u64,
            maximum_retention_human: format!("~{} years; enforced by /quote", (quote::MAX_RETENTION_MINUTES / MINUTES_PER_YEAR) as u64),
            formula: "max(minimum_satoshis, floor((fileSize / 1e9) * (retentionPeriod / 43200) * PRICE_PER_GB_MO * (1 / (bsv_usd / 1e8))))",
            formula_notes: BTreeMap::from([
                ("fileSize", "bytes (1 GB = 1,000,000,000, SI)".to_string()),
                ("retentionPeriod", "minutes (1 month = 43,200 = 60*24*30); examples use 525,600 minutes (365 days)".to_string()),
                ("bsvUsdRate", rate_note.clone()),
                ("rounding", "floor, then the minimum satoshi price".to_string()),
                ("minimum", format!("{} satoshis", quote::MIN_SATOSHI_PRICE)),
            ]),
            examples,
            note: format!("{rate_note}. bsv_usd and all examples use one call to the quote's rate fetch. Use /quote for current pricing; this unsigned manifest may be cached for 300 seconds. No additional margin multiplier is applied to PRICE_PER_GB_MO. USD examples are before the satoshi minimum. MIN_HOSTING_MINUTES supplies the configured lower bound (missing, unparseable or NaN values become zero). /quote requires positive integer file sizes and integer, nonzero retention and caps retention; /upload caps file size but does not enforce that retention maximum or integer retention. /quote does not enforce the upload size cap."),
        },
        public_url_format: PublicUrlFormat {
            pattern: format!("{}/cdn/{{base58id}}", config.public_url_base),
            note: "Replace {base58id} with the last segment of the object key in uploadURL, a base58 encoding of 16 random bytes; public downloads use PUBLIC_URL_BASE after the object is uploaded.",
        },
    }
}

#[cfg(test)]
#[path = "../../tests/unit/manifest.rs"]
mod tests;
