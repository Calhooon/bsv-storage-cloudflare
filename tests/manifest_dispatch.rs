#![allow(clippy::unwrap_used, clippy::expect_used)]

#[test]
fn manifest_get_returns_before_authentication_with_cors() {
    let source = include_str!("../src/lib.rs");
    let route = source
        .find("if method == Method::Get && path == \"/.well-known/x402-info\"")
        .expect("public GET discovery route is missing");
    let auth = source.find("let auth_options =").unwrap();
    assert!(route < auth, "discovery must precede authentication");
    let branch = source[route..].split("\n    }").next().unwrap();
    assert!(branch.contains("routes::manifest::handle(&env).await?"));
    assert!(branch.contains("return Ok(add_cors_headers(resp))"));
}

#[test]
fn discovery_response_is_unsigned_json_with_a_five_minute_cache() {
    let source = include_str!("../src/routes/manifest.rs");
    assert!(source.contains("Response::from_json(&manifest)?"));
    assert!(source.contains("\"Content-Type\", \"application/json\""));
    assert!(source.contains("\"public, max-age=300\""));
    assert!(source.contains("\"Cache-Control\", CACHE_CONTROL"));
    assert_eq!(
        source.matches("quote::fetch_exchange_rate().await").count(),
        1
    );
    for forbidden in [
        "process_auth(",
        "process_payment",
        "sign_json_response",
        "with_status(",
    ] {
        assert!(!source.contains(forbidden));
    }
}
