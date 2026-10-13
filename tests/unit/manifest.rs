#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use serde_json::Value;

fn fixture_config() -> Config {
    // Public test scalar, constructed in memory; no credentials or bindings.
    Config::from_values(
        None,
        &format!("{:064x}", 1),
        "https://files.invalid/",
        "0.05",
        "15",
    )
    .unwrap()
}

#[test]
fn fallback_manifest_matches_golden() {
    let actual = serde_json::to_value(body(
        &fixture_config(),
        quote::FALLBACK_EXCHANGE_RATE_USD_PER_BSV,
    ))
    .unwrap();
    let expected: Value =
        serde_json::from_str(include_str!("../fixtures/manifest/fallback.json")).unwrap();
    assert_eq!(actual, expected);
    let identity = actual["serverIdentityKey"].as_str().unwrap();
    assert_eq!(identity.len(), 66);
    assert!(identity.bytes().all(|c| c.is_ascii_hexdigit()));
    assert!(identity.starts_with("02") || identity.starts_with("03"));
    assert!(actual["publicUrlFormat"]["pattern"]
        .as_str()
        .unwrap()
        .ends_with("/cdn/{base58id}"));
}

#[test]
fn configuration_controls_name_identity_price_limits_and_public_url() {
    let key = format!("{:064x}", 2);
    let config = Config::from_values(
        Some("configured-storage"),
        &key,
        "https://other.invalid/prefix///",
        "0.125",
        "180",
    )
    .unwrap();
    let manifest = body(&config, 50.0);
    assert_eq!(manifest.name, "configured-storage");
    assert_eq!(
        manifest.server_identity_key,
        PrivateKey::from_hex(&key).unwrap().public_key().to_hex()
    );
    assert_eq!(manifest.pricing.price_per_gb_mo, 0.125);
    assert_eq!(manifest.pricing.rates["USD_per_GB_month"], 0.125);
    assert_eq!(manifest.pricing.minimum_retention_minutes, 180.0);
    assert_eq!(manifest.pricing.bsv_usd, 50.0);
    assert_eq!(
        manifest.public_url_format.pattern,
        "https://other.invalid/prefix/cdn/{base58id}"
    );
}

#[test]
fn examples_use_the_quote_at_each_injected_rate_and_respect_the_floor() {
    let mut config = fixture_config();
    for price in [0.05, 0.125, 0.000_000_001] {
        config.price_per_gb_mo = price;
        for rate in [quote::FALLBACK_EXCHANGE_RATE_USD_PER_BSV, 50.0] {
            let manifest = body(&config, rate);
            for (name, bytes) in [
                ("1_MB_1_year", 1_000_000.0),
                ("10_MB_1_year", 10_000_000.0),
                ("100_MB_1_year", 100_000_000.0),
                ("1_GB_1_year", 1_000_000_000.0),
            ] {
                let example = &manifest.pricing.examples[name];
                assert_eq!(
                    example.satoshis,
                    quote::compute_sat_price(bytes, 525_600.0, price, rate)
                );
                assert_eq!(example.usd, (bytes / 1e9) * (525_600.0 / 43_200.0) * price);
                assert!(example.satoshis >= manifest.pricing.minimum_satoshis);
            }
        }
    }
    assert_eq!(
        body(&config, 50.0).pricing.examples["1_GB_1_year"].satoshis,
        quote::MIN_SATOSHI_PRICE
    );
}

#[test]
fn manifest_names_the_enforced_limits_and_shared_fallback() {
    let pricing = body(&fixture_config(), 15.0).pricing;
    assert_eq!(pricing.minimum_satoshis, quote::MIN_SATOSHI_PRICE);
    assert_eq!(pricing.maximum_file_size_bytes, MAX_UPLOAD_BYTES as u64);
    assert_eq!(
        pricing.maximum_retention_minutes,
        quote::MAX_RETENTION_MINUTES as u64
    );
    assert!(pricing.maximum_file_size_human.contains("/upload"));
    assert!(pricing.maximum_retention_human.contains("/quote"));
    assert!(pricing.note.contains("WhatsOnChain"));
    assert!(pricing.note.contains(&format!(
        "fallback {} USD/BSV",
        quote::FALLBACK_EXCHANGE_RATE_USD_PER_BSV
    )));
}

#[test]
fn missing_or_invalid_minimum_matches_quote_configuration() {
    for raw in ["", "invalid", "NaN"] {
        let config = Config::from_values(
            None,
            &format!("{:064x}", 1),
            "https://files.invalid",
            "0.05",
            raw,
        )
        .unwrap();
        assert_eq!(config.minimum_retention_minutes, 0.0);
    }
}

#[test]
fn bad_configuration_is_refused_without_echoing_key_material() {
    let key = format!("{:064x}", 1);
    for bad in ["", "invalid", "NaN", "inf"] {
        assert!(Config::from_values(None, &key, "https://files.invalid", bad, "15").is_err());
    }
    assert!(Config::from_values(None, &key, "https://files.invalid", "0.05", "inf").is_err());
    assert!(Config::from_values(None, &key, " ", "0.05", "15").is_err());
    assert_eq!(
        Config::from_values(
            None,
            "invalid test scalar",
            "https://files.invalid",
            "0.05",
            "15"
        )
        .err(),
        Some("SERVER_PRIVATE_KEY is invalid")
    );
}
