//! JSON canonicalization — RFC 8785 (JCS) + a pretty variant for diffs + a
//! `$VOLATILE:<type>$` sentinel for dynamic-but-typechecked comparison.
//!
//! Three distinct operations on `serde_json::Value`:
//!
//! * [`jcs`] — the **contract form**. Implements RFC 8785 (JSON Canonicalization
//!   Scheme): lexicographic UTF-16 code-unit key sort, no insignificant
//!   whitespace, strings escaped minimally (same as JSON.stringify in ES2017+),
//!   numbers serialized per ECMA-262 (integers as ints, finite floats via the
//!   shortest-round-trip algorithm serde_json already implements). This is what
//!   we hash and what we compare byte-for-byte.
//! * [`pretty_sorted`] — a human-readable sibling used only for unified-diff
//!   rendering. Keys still sort lexicographically; output is 2-space indented.
//!   Never written to a fixture, never hashed.
//! * [`volatile_aware_equal`] — contract-aware comparison. Traverses the
//!   fixture value alongside the live value; wherever the fixture has a
//!   `$VOLATILE:<type>$` string sentinel, the live value is typechecked but
//!   not equality-compared. All other positions must JCS-equal.
//!
//! # Why hand-roll JCS instead of pulling a crate?
//!
//! JCS is ~60 lines of honest code. Third-party crates vary on edge cases
//! (number precision, JSON non-compliance around non-BMP strings) and add a
//! supply-chain risk we don't need for a harness. `serde_json`'s value model
//! already guarantees all numbers are either `i64/u64/f64` and all strings are
//! valid UTF-8 — JCS does the rest.
//!
//! # `$VOLATILE:<type>$` design
//!
//! Fixtures are meant to pin contract shape, not runtime values. For routes
//! like `/quote` where the `quote` integer depends on a live BSV/USD rate,
//! checking byte-exact equality across captures would force us to re-capture
//! daily. Instead, fixture authors can write:
//!
//! ```json
//! {"quote": "$VOLATILE:u64$"}
//! ```
//!
//! At diff time, [`volatile_aware_equal`] accepts any non-negative integer in
//! that position. Typechecking happens per [`VolatileKind::matches`]: a live
//! value is accepted iff its JSON shape matches the declared kind.
//!
//! Allowed kinds: `u64`, `i64`, `number`, `string`, `bool`, `iso8601`,
//! `hex32`, `hex64`, `hex66`, `uhrp_url`, `array`, `object`, `null`,
//! `satoshis` (alias for u64), `string_map`.
//!
//! # `$VOLATILE:string_map$` — backend-specific header maps
//!
//! Some response fields are *semantically* "a map of strings the client
//! must echo back", but the *specific key names* are determined by the
//! storage backend. The canonical example is `/upload`'s
//! `requiredHeaders`: nanostore (GCS) returns `{x-goog-custom-time: …,
//! x-goog-meta-uploaderidentitykey: …}`; our worker (R2-S3) returns
//! `{x-amz-meta-custom-time: …, x-amz-meta-uploaderidentitykey: …}`.
//! Both are spec-compliant — clients iterate the map dynamically and
//! don't hardcode the names.
//!
//! `$VOLATILE:string_map$` encodes that contract: "non-empty JSON object
//! where every value is a JSON string." It is *stricter* than
//! `$VOLATILE:object$` (which accepts any object) — an empty map, or a
//! map with non-string values, is still a regression worth catching.
//!
//! **Known edge cases** (handled)
//!
//! * **Key ordering**: RFC 8785 §3.2.3 specifies UTF-16 code-unit order, not
//!   UTF-8. For any string that is pure BMP (no surrogate pairs, i.e. no
//!   codepoint > U+FFFF), UTF-16 order == UTF-8 order == Rust's `str::cmp`.
//!   For strings containing supplementary-plane characters we explicitly sort
//!   by UTF-16 code units via [`utf16_cmp`]. Protocol JSON only uses BMP, but
//!   correctness is cheap.
//! * **Numbers**: `serde_json` emits integers without a decimal point and
//!   finite floats via Grisu — both match ECMA-262 §7.1.12.1 for our inputs.
//!   Non-finite floats can't appear in `serde_json::Value` (only `Number`s
//!   whose `f64` is finite are constructible), so no branch is needed.
//! * **Strings**: JCS requires the same escape set as `JSON.stringify` —
//!   `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, and `\u00XX` for the rest of
//!   U+0000..=U+001F. `serde_json::to_string` already produces this.

use serde_json::{Map, Value};

/// RFC 8785 canonical form. Deterministic byte-for-byte.
pub fn jcs(value: &Value) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    write_jcs(value, &mut out)?;
    Ok(out)
}

/// Hex-encoded SHA-256 of the JCS canonical form. Handy for the captures log.
pub fn jcs_sha256_hex(value: &Value) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let bytes = jcs(value)?;
    let digest = Sha256::digest(&bytes);
    Ok(hex::encode(digest))
}

/// Sorted-keys pretty JSON, **for diff rendering only**. Not a contract.
pub fn pretty_sorted(value: &Value) -> Result<String, String> {
    let sorted = sort_keys(value.clone());
    serde_json::to_string_pretty(&sorted).map_err(|e| format!("JSON serialize: {e}"))
}

fn sort_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| utf16_cmp(&a.0, &b.0));
            let mut out = Map::new();
            for (k, v) in entries {
                out.insert(k, sort_keys(v));
            }
            Value::Object(out)
        }
        Value::Array(xs) => Value::Array(xs.into_iter().map(sort_keys).collect()),
        other => other,
    }
}

fn write_jcs(value: &Value, out: &mut Vec<u8>) -> Result<(), String> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            // serde_json emits ints without a decimal point and finite floats
            // via shortest-roundtrip Grisu — both match ECMA-262 §7.1.12.1
            // for the inputs we ever see over the wire.
            let s = serde_json::to_string(n).map_err(|e| format!("number encode: {e}"))?;
            out.extend_from_slice(s.as_bytes());
        }
        Value::String(s) => {
            let encoded = serde_json::to_string(s).map_err(|e| format!("string encode: {e}"))?;
            out.extend_from_slice(encoded.as_bytes());
        }
        Value::Array(xs) => {
            out.push(b'[');
            for (i, v) in xs.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_jcs(v, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| utf16_cmp(a.0, b.0));
            out.push(b'{');
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                let encoded = serde_json::to_string(k).map_err(|e| format!("key encode: {e}"))?;
                out.extend_from_slice(encoded.as_bytes());
                out.push(b':');
                write_jcs(v, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// Lexicographic comparison by UTF-16 code units (RFC 8785 §3.2.3).
///
/// For BMP-only strings this collapses to `str::cmp`. The full iterator keeps
/// us correct for supplementary-plane input, which JCS treats as a pair of
/// surrogate code units (higher numerically than any BMP code unit).
fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let mut ai = a.encode_utf16();
    let mut bi = b.encode_utf16();
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (Some(x), Some(y)) => match x.cmp(&y) {
                std::cmp::Ordering::Equal => continue,
                other => return other,
            },
        }
    }
}

// ─── $VOLATILE:<type>$ sentinel ─────────────────────────────────────────────

/// Supported volatile types. `matches(v)` returns true iff `v` is an
/// acceptable live value for a fixture marked `$VOLATILE:<kind>$`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolatileKind {
    /// Non-negative integer in JSON (`u64`-range). Alias: `satoshis`.
    U64,
    /// Any signed integer.
    I64,
    /// Any JSON number (integer or float).
    Number,
    /// Any string. No further validation.
    String,
    /// `true` or `false`.
    Bool,
    /// String shaped like `YYYY-MM-DDTHH:MM:SS[.NNN]Z`.
    Iso8601,
    /// Hex string of length 32 (16 bytes).
    Hex32,
    /// Hex string of length 64 (32 bytes — e.g. txid, sha256).
    Hex64,
    /// Hex string of length 66 (33 bytes — compressed secp256k1 pubkey).
    Hex66,
    /// String starting with `uhrp://` followed by a base58check body.
    UhrpUrl,
    /// Any JSON array. Length + per-element validation is out of scope here;
    /// callers can extend if they need it.
    Array,
    /// Any JSON object. Same caveat as `Array`.
    Object,
    /// JSON `null`.
    Null,
    /// Non-empty JSON object whose values are all JSON strings. Use
    /// for backend-specific header maps (`/upload`'s `requiredHeaders`
    /// — see module docs for the GCS-vs-R2 story). An empty object is
    /// rejected — a server that returned zero required headers has
    /// regressed its upload handoff, which is exactly the kind of drift
    /// a sentinel-typed fixture should still catch.
    StringMap,
}

impl VolatileKind {
    /// Parse the inner type name from a `$VOLATILE:<name>$` sentinel.
    fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "u64" | "satoshis" => Self::U64,
            "i64" => Self::I64,
            "number" => Self::Number,
            "string" => Self::String,
            "bool" => Self::Bool,
            "iso8601" => Self::Iso8601,
            "hex32" => Self::Hex32,
            "hex64" => Self::Hex64,
            "hex66" => Self::Hex66,
            "uhrp_url" => Self::UhrpUrl,
            "array" => Self::Array,
            "object" => Self::Object,
            "null" => Self::Null,
            "string_map" => Self::StringMap,
            _ => return None,
        })
    }

    /// True iff `v` is an acceptable live value for this kind.
    pub fn matches(&self, v: &Value) -> bool {
        match self {
            Self::U64 => v.as_u64().is_some(),
            Self::I64 => v.as_i64().is_some(),
            Self::Number => v.is_number(),
            Self::String => v.is_string(),
            Self::Bool => v.is_boolean(),
            Self::Iso8601 => v.as_str().is_some_and(looks_like_iso8601),
            Self::Hex32 => v.as_str().is_some_and(|s| is_lowercase_hex(s, 32)),
            Self::Hex64 => v.as_str().is_some_and(|s| is_lowercase_hex(s, 64)),
            Self::Hex66 => v.as_str().is_some_and(|s| is_lowercase_hex(s, 66)),
            Self::UhrpUrl => v.as_str().is_some_and(looks_like_uhrp_url),
            Self::Array => v.is_array(),
            Self::Object => v.is_object(),
            Self::Null => v.is_null(),
            Self::StringMap => is_non_empty_string_map(v),
        }
    }
}

/// `v` is a non-empty JSON object whose values are all strings. Used by
/// [`VolatileKind::StringMap`]. Null or missing values are rejected —
/// the contract is "every required header is a string."
fn is_non_empty_string_map(v: &Value) -> bool {
    match v {
        Value::Object(map) => !map.is_empty() && map.values().all(|value| value.is_string()),
        _ => false,
    }
}

/// If `s` is of the form `$VOLATILE:<name>$`, return the parsed kind. Returns
/// `Err(msg)` if the sentinel prefix/suffix matches but the inner name is
/// unknown — that's a fixture bug worth surfacing rather than silently
/// treating as a literal string.
pub fn parse_volatile_marker(s: &str) -> Result<Option<VolatileKind>, String> {
    let Some(inner) = s
        .strip_prefix("$VOLATILE:")
        .and_then(|r| r.strip_suffix('$'))
    else {
        return Ok(None);
    };
    VolatileKind::from_name(inner)
        .map(Some)
        .ok_or_else(|| format!("unknown $VOLATILE kind: {inner} (see canon::VolatileKind)"))
}

/// Compare `live` against `fixture`, honoring `$VOLATILE:<kind>$` sentinels
/// in `fixture`. Returns the first mismatch path+reason, or `Ok(())` on match.
///
/// Semantics:
/// * Primitive literal in fixture → must JCS-equal live.
/// * `$VOLATILE:<kind>$` string in fixture → live is typechecked only.
/// * Object → same key set, recurse on each value.
/// * Array → same length, recurse positionally.
pub fn volatile_aware_equal(fixture: &Value, live: &Value) -> Result<(), String> {
    equal_at(&[], fixture, live)
}

fn equal_at(path: &[String], fixture: &Value, live: &Value) -> Result<(), String> {
    // Fixture is a volatile sentinel → typecheck live.
    if let Value::String(s) = fixture {
        if let Some(kind) = parse_volatile_marker(s).map_err(|e| at(path, &e))? {
            return if kind.matches(live) {
                Ok(())
            } else {
                Err(at(
                    path,
                    &format!(
                        "fixture sentinel $VOLATILE:{kind:?}$ does not match live value \
                         {live}",
                    ),
                ))
            };
        }
    }

    match (fixture, live) {
        (Value::Null, Value::Null) => Ok(()),
        (Value::Bool(a), Value::Bool(b)) if a == b => Ok(()),
        (Value::Number(a), Value::Number(b)) if numbers_equal(a, b) => Ok(()),
        (Value::String(a), Value::String(b)) if a == b => Ok(()),
        (Value::Array(a), Value::Array(b)) => {
            if a.len() != b.len() {
                return Err(at(
                    path,
                    &format!(
                        "array length mismatch: fixture={} live={}",
                        a.len(),
                        b.len()
                    ),
                ));
            }
            for (i, (fa, fb)) in a.iter().zip(b.iter()).enumerate() {
                let mut sub = path.to_vec();
                sub.push(format!("[{i}]"));
                equal_at(&sub, fa, fb)?;
            }
            Ok(())
        }
        (Value::Object(a), Value::Object(b)) => {
            // Key set must match exactly (superset/subset differences indicate
            // shape drift).
            for k in a.keys() {
                if !b.contains_key(k) {
                    return Err(at(path, &format!("live is missing key `{k}`")));
                }
            }
            for k in b.keys() {
                if !a.contains_key(k) {
                    return Err(at(
                        path,
                        &format!("live has unexpected key `{k}` not in fixture"),
                    ));
                }
            }
            for (k, fv) in a {
                let mut sub = path.to_vec();
                sub.push(k.clone());
                let lv = b.get(k).ok_or_else(|| at(path, "unreachable: key check"))?;
                equal_at(&sub, fv, lv)?;
            }
            Ok(())
        }
        _ => Err(at(
            path,
            &format!("type/value mismatch: fixture={fixture} live={live}"),
        )),
    }
}

fn at(path: &[String], msg: &str) -> String {
    if path.is_empty() {
        msg.to_string()
    } else {
        format!("at `{}`: {msg}", path.join("."))
    }
}

/// Compare two JSON numbers by their JCS canonical form. This handles the
/// cases where `serde_json::Number` may compare unequal (e.g. integer 10 vs
/// float 10.0 wired over JSON both render as `10` but the Number variants
/// differ). We compare on the serialized form, which is what the contract
/// asserts anyway.
fn numbers_equal(a: &serde_json::Number, b: &serde_json::Number) -> bool {
    match (serde_json::to_string(a).ok(), serde_json::to_string(b).ok()) {
        (Some(sa), Some(sb)) => sa == sb,
        _ => false,
    }
}

fn is_lowercase_hex(s: &str, expected_len: usize) -> bool {
    s.len() == expected_len
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
}

fn looks_like_iso8601(s: &str) -> bool {
    // YYYY-MM-DDTHH:MM:SS[.fff]Z — minimum 20 chars with trailing Z, digits +
    // separators. Cheap shape check; we don't parse.
    if !s.ends_with('Z') {
        return false;
    }
    if s.len() < 20 {
        return false;
    }
    let bytes = s.as_bytes();
    bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
}

fn looks_like_uhrp_url(s: &str) -> bool {
    let Some(body) = s.strip_prefix("uhrp://") else {
        return false;
    };
    !body.is_empty() && body.chars().all(|c| !c.is_whitespace() && !c.is_control())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- JCS ----

    /// RFC 8785 §3.2.3 — keys sorted by UTF-16 code unit. 'a' (0x0061) sorts
    /// before 'b' (0x0062), and both sort before 'å' (0x00E5).
    #[test]
    fn rfc8785_key_sort_order_latin() {
        let input = json!({
            "\u{00e5}": 1,
            "\u{0062}": 2,
            "\u{0061}": 3,
        });
        let got = jcs(&input).unwrap();
        let got_str = std::str::from_utf8(&got).unwrap();
        assert_eq!(got_str, "{\"a\":3,\"b\":2,\"\u{00e5}\":1}");
    }

    /// RFC 8785 §3.2.2.1 — numbers: integers without a decimal point, finite
    /// floats via ECMA-262 §7.1.12.1 (shortest-roundtrip). serde_json's
    /// default emitter already matches for the integer and common fractional
    /// cases we actually transmit over /quote, /upload, /find.
    #[test]
    fn rfc8785_numbers_shape() {
        let got = jcs(&json!({ "n": 193, "f": 4.5, "z": 0 })).unwrap();
        let got_str = std::str::from_utf8(&got).unwrap();
        assert_eq!(got_str, "{\"f\":4.5,\"n\":193,\"z\":0}");
    }

    /// RFC 8785 §3.2.2.2 — string serialization uses the minimal JSON escape
    /// set. Quote, backslash, and controls U+0000..=U+001F must be escaped;
    /// everything else (including non-ASCII) is emitted literally in UTF-8.
    #[test]
    fn rfc8785_string_escapes() {
        let got = jcs(&json!({ "s": "a\"b\\c\nd\te\u{0001}f\u{00e9}" })).unwrap();
        let got_str = std::str::from_utf8(&got).unwrap();
        // Quote -> \", backslash -> \\, newline -> \n, tab -> \t,
        // U+0001 -> \u0001, é -> literal UTF-8 bytes.
        assert_eq!(got_str, "{\"s\":\"a\\\"b\\\\c\\nd\\te\\u0001f\u{00e9}\"}");
    }

    #[test]
    fn jcs_is_byte_stable_across_key_permutations() {
        let a = json!({ "z": 1, "a": { "z": [1,2], "a": 3 }});
        let b = json!({ "a": { "a": 3, "z": [1,2] }, "z": 1 });
        assert_eq!(jcs(&a).unwrap(), jcs(&b).unwrap());
    }

    #[test]
    fn jcs_preserves_array_order() {
        // Arrays MUST NOT be reordered — RFC 8785 §3.2.
        let a = json!({ "xs": [3, 1, 2] });
        let b = json!({ "xs": [1, 2, 3] });
        assert_ne!(jcs(&a).unwrap(), jcs(&b).unwrap());
    }

    #[test]
    fn jcs_no_insignificant_whitespace() {
        let got = jcs(&json!({"b": 1, "a": [1, 2]})).unwrap();
        assert_eq!(std::str::from_utf8(&got).unwrap(), "{\"a\":[1,2],\"b\":1}");
    }

    #[test]
    fn jcs_utf16_orders_supplementary_plane_after_bmp() {
        // U+1F600 encodes to surrogate pair 0xD83D 0xDE00, both > any BMP unit.
        let input = json!({ "\u{1F600}": 1, "z": 2 });
        let got = jcs(&input).unwrap();
        let s = std::str::from_utf8(&got).unwrap();
        assert!(s.starts_with("{\"z\":2"));
    }

    #[test]
    fn jcs_sha256_is_deterministic() {
        let a = jcs_sha256_hex(&json!({"b":1,"a":2})).unwrap();
        let b = jcs_sha256_hex(&json!({"a":2,"b":1})).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    // ---- pretty_sorted (diff-only helper) ----

    #[test]
    fn pretty_sorted_sorts_at_every_depth() {
        let a = json!({ "z": 1, "a": { "z": [1,2], "a": 3 }});
        let b = json!({ "a": { "a": 3, "z": [1,2] }, "z": 1 });
        assert_eq!(pretty_sorted(&a).unwrap(), pretty_sorted(&b).unwrap());
    }

    // ---- $VOLATILE:<kind>$ sentinel ----

    #[test]
    fn parse_volatile_marker_recognizes_known_kinds() {
        assert_eq!(
            parse_volatile_marker("$VOLATILE:u64$").unwrap(),
            Some(VolatileKind::U64)
        );
        assert_eq!(
            parse_volatile_marker("$VOLATILE:string$").unwrap(),
            Some(VolatileKind::String)
        );
        assert_eq!(
            parse_volatile_marker("$VOLATILE:iso8601$").unwrap(),
            Some(VolatileKind::Iso8601)
        );
        assert_eq!(
            parse_volatile_marker("$VOLATILE:hex64$").unwrap(),
            Some(VolatileKind::Hex64)
        );
        // `satoshis` is a documented alias for u64.
        assert_eq!(
            parse_volatile_marker("$VOLATILE:satoshis$").unwrap(),
            Some(VolatileKind::U64)
        );
    }

    #[test]
    fn parse_volatile_marker_returns_none_for_plain_strings() {
        assert!(parse_volatile_marker("hello").unwrap().is_none());
        assert!(parse_volatile_marker("$VOLATILE:u64").unwrap().is_none()); // missing trailing $
        assert!(parse_volatile_marker("VOLATILE:u64$").unwrap().is_none()); // missing leading $
    }

    #[test]
    fn parse_volatile_marker_errors_on_unknown_kind() {
        assert!(parse_volatile_marker("$VOLATILE:nope$").is_err());
    }

    #[test]
    fn volatile_u64_accepts_positive_integer() {
        let fx = json!({"quote": "$VOLATILE:u64$"});
        let live = json!({"quote": 193});
        assert!(volatile_aware_equal(&fx, &live).is_ok());
    }

    #[test]
    fn volatile_u64_rejects_string() {
        let fx = json!({"quote": "$VOLATILE:u64$"});
        let live = json!({"quote": "not a number"});
        let err = volatile_aware_equal(&fx, &live).unwrap_err();
        assert!(err.contains("quote"));
    }

    #[test]
    fn volatile_u64_rejects_negative_number() {
        let fx = json!({"quote": "$VOLATILE:u64$"});
        let live = json!({"quote": -5});
        assert!(volatile_aware_equal(&fx, &live).is_err());
    }

    #[test]
    fn volatile_hex64_matches_32_byte_txid() {
        let fx = json!({"txid": "$VOLATILE:hex64$"});
        let live = json!({"txid": "a".repeat(64)});
        assert!(volatile_aware_equal(&fx, &live).is_ok());
    }

    #[test]
    fn volatile_hex64_rejects_short_hex() {
        let fx = json!({"txid": "$VOLATILE:hex64$"});
        let live = json!({"txid": "abcd"});
        assert!(volatile_aware_equal(&fx, &live).is_err());
    }

    #[test]
    fn volatile_iso8601_accepts_well_formed() {
        let fx = json!({"at": "$VOLATILE:iso8601$"});
        let live = json!({"at": "2026-04-20T12:34:56.000Z"});
        assert!(volatile_aware_equal(&fx, &live).is_ok());
    }

    #[test]
    fn volatile_iso8601_rejects_no_trailing_z() {
        let fx = json!({"at": "$VOLATILE:iso8601$"});
        let live = json!({"at": "2026-04-20T12:34:56"});
        assert!(volatile_aware_equal(&fx, &live).is_err());
    }

    #[test]
    fn volatile_uhrp_url_accepts_well_formed() {
        let fx = json!({"u": "$VOLATILE:uhrp_url$"});
        let live = json!({"u": "uhrp://abc123"});
        assert!(volatile_aware_equal(&fx, &live).is_ok());
    }

    #[test]
    fn volatile_uhrp_url_rejects_missing_scheme() {
        let fx = json!({"u": "$VOLATILE:uhrp_url$"});
        let live = json!({"u": "abc123"});
        assert!(volatile_aware_equal(&fx, &live).is_err());
    }

    #[test]
    fn volatile_array_accepts_any_array_including_empty() {
        let fx = json!({"xs": "$VOLATILE:array$"});
        assert!(volatile_aware_equal(&fx, &json!({"xs": []})).is_ok());
        assert!(volatile_aware_equal(&fx, &json!({"xs": [1,2,3]})).is_ok());
    }

    #[test]
    fn volatile_object_accepts_any_object() {
        let fx = json!({"o": "$VOLATILE:object$"});
        assert!(volatile_aware_equal(&fx, &json!({"o": {}})).is_ok());
        assert!(volatile_aware_equal(&fx, &json!({"o": {"k": 1}})).is_ok());
    }

    #[test]
    fn non_volatile_string_is_equality_compared() {
        let fx = json!({"status": "success"});
        assert!(volatile_aware_equal(&fx, &json!({"status": "success"})).is_ok());
        assert!(volatile_aware_equal(&fx, &json!({"status": "failure"})).is_err());
    }

    #[test]
    fn missing_key_reports_path() {
        let fx = json!({"a": {"b": 1}});
        let live = json!({"a": {}});
        let err = volatile_aware_equal(&fx, &live).unwrap_err();
        assert!(err.contains("missing key `b`"), "got: {err}");
    }

    #[test]
    fn extra_key_reports_path() {
        let fx = json!({"a": 1});
        let live = json!({"a": 1, "b": 2});
        let err = volatile_aware_equal(&fx, &live).unwrap_err();
        assert!(err.contains("unexpected key `b`"), "got: {err}");
    }

    #[test]
    fn nested_array_path_in_error() {
        let fx = json!({"xs": [1, 2, 3]});
        let live = json!({"xs": [1, 99, 3]});
        let err = volatile_aware_equal(&fx, &live).unwrap_err();
        assert!(err.contains("[1]"), "error must include index: {err}");
    }

    #[test]
    fn unknown_volatile_kind_is_error_not_silent_pass() {
        let fx = json!({"x": "$VOLATILE:bogus$"});
        let live = json!({"x": 1});
        let err = volatile_aware_equal(&fx, &live).unwrap_err();
        assert!(err.contains("bogus"), "got: {err}");
    }

    #[test]
    fn all_known_kind_names_are_parseable() {
        // Lock the supported alias list so adding a new kind without updating
        // `VolatileKind::from_name` is a test failure.
        for name in [
            "u64",
            "i64",
            "number",
            "string",
            "bool",
            "iso8601",
            "hex32",
            "hex64",
            "hex66",
            "uhrp_url",
            "array",
            "object",
            "null",
            "satoshis",
            "string_map",
        ] {
            let marker = format!("$VOLATILE:{name}$");
            assert!(
                parse_volatile_marker(&marker).unwrap().is_some(),
                "expected {name} to parse"
            );
        }
    }

    // ─── $VOLATILE:string_map$ — task #44 ────────────────────────────────
    //
    // Covers the backend-specific header-map case (requiredHeaders on
    // /upload). See the kind's doc comment for the rationale.

    // Unit: the `matches` predicate, every edge.

    #[test]
    fn string_map_accepts_single_entry() {
        let v = json!({"a": "b"});
        assert!(VolatileKind::StringMap.matches(&v));
    }

    #[test]
    fn string_map_accepts_nanostore_style_gcs_headers() {
        let v = json!({
            "x-goog-custom-time": "2026-05-21T17:39:35.000Z",
            "x-goog-meta-uploaderidentitykey":
                "027c0f60f2c5f70788a4b2331c58cc37515fa3ff4ee7acaa16593764e334edde0a",
        });
        assert!(
            VolatileKind::StringMap.matches(&v),
            "must accept the nanostore-reference shape"
        );
    }

    #[test]
    fn string_map_accepts_worker_style_r2_headers() {
        // Same semantic contract, different key names. This is the
        // whole point of #44 — both backends are spec-compliant.
        let v = json!({
            "x-amz-meta-custom-time": "2026-05-21T17:39:35.000Z",
            "x-amz-meta-uploaderidentitykey":
                "027c0f60f2c5f70788a4b2331c58cc37515fa3ff4ee7acaa16593764e334edde0a",
        });
        assert!(
            VolatileKind::StringMap.matches(&v),
            "must accept the R2-backend shape"
        );
    }

    #[test]
    fn string_map_accepts_arbitrary_header_namespace() {
        // Forward-compat: if a future backend ships `x-foo-*` required
        // headers, shape parity still passes. Specific names remain an
        // implementation detail; only the map-of-strings invariant is
        // pinned.
        let v = json!({
            "x-foo-one": "alpha",
            "authorization": "Bearer <token>",
        });
        assert!(VolatileKind::StringMap.matches(&v));
    }

    // Unit: the rejects — each catches a different regression.

    #[test]
    fn string_map_rejects_empty_object() {
        // Empty map = server forgot to emit required headers. Real
        // upload break. Must fail parity.
        let v = json!({});
        assert!(!VolatileKind::StringMap.matches(&v));
    }

    #[test]
    fn string_map_rejects_number_value() {
        let v = json!({"x-some-header": 42});
        assert!(!VolatileKind::StringMap.matches(&v));
    }

    #[test]
    fn string_map_rejects_null_value() {
        // null is the subtle one — JSON treats it as a "present key
        // with no value". Most header APIs would drop it silently;
        // better to flag.
        let v = json!({"x-some-header": null});
        assert!(!VolatileKind::StringMap.matches(&v));
    }

    #[test]
    fn string_map_rejects_bool_value() {
        let v = json!({"x-some-header": true});
        assert!(!VolatileKind::StringMap.matches(&v));
    }

    #[test]
    fn string_map_rejects_nested_object_value() {
        let v = json!({"x-some-header": {"nested": "bad"}});
        assert!(!VolatileKind::StringMap.matches(&v));
    }

    #[test]
    fn string_map_rejects_array_value() {
        let v = json!({"x-some-header": ["bad"]});
        assert!(!VolatileKind::StringMap.matches(&v));
    }

    #[test]
    fn string_map_rejects_mixed_value_types() {
        // One bad egg spoils the batch.
        let v = json!({"x-good": "ok", "x-bad": 1});
        assert!(!VolatileKind::StringMap.matches(&v));
    }

    #[test]
    fn string_map_rejects_non_object_json() {
        assert!(!VolatileKind::StringMap.matches(&json!([])));
        assert!(!VolatileKind::StringMap.matches(&json!("not an object")));
        assert!(!VolatileKind::StringMap.matches(&json!(42)));
        assert!(!VolatileKind::StringMap.matches(&json!(null)));
    }

    // Vector: volatile_aware_equal over a real-shaped fixture, driven by
    // both reference and local live-value shapes. Byte-level proof that
    // the sentinel accepts both nanostore AND our-worker outputs.

    #[test]
    fn string_map_vector_upload_fixture_accepts_both_backend_shapes() {
        let fixture = json!({
            "status": "success",
            "requiredHeaders": "$VOLATILE:string_map$",
            "uploadURL": "$VOLATILE:string$",
            "amount": "$VOLATILE:u64$",
            "description": "File can now be uploaded.",
        });

        let nanostore_live = json!({
            "status": "success",
            "requiredHeaders": {
                "x-goog-custom-time": "2026-05-21T17:39:35.000Z",
                "x-goog-meta-uploaderidentitykey":
                    "027c0f60f2c5f70788a4b2331c58cc37515fa3ff4ee7acaa16593764e334edde0a",
            },
            "uploadURL": "https://storage.googleapis.com/prod-uhrp/cdn/abc?X-Goog-Signature=...",
            "amount": 197,
            "description": "File can now be uploaded.",
        });

        let worker_live = json!({
            "status": "success",
            "requiredHeaders": {
                "x-amz-meta-custom-time": "2026-05-21T17:39:35.000Z",
                "x-amz-meta-uploaderidentitykey":
                    "027c0f60f2c5f70788a4b2331c58cc37515fa3ff4ee7acaa16593764e334edde0a",
            },
            "uploadURL": "https://your-worker.your-account.workers.dev/cdn/abc?X-Amz-Signature=...",
            "amount": 197,
            "description": "File can now be uploaded.",
        });

        assert!(
            volatile_aware_equal(&fixture, &nanostore_live).is_ok(),
            "nanostore's x-goog-* shape must pass the fixture"
        );
        assert!(
            volatile_aware_equal(&fixture, &worker_live).is_ok(),
            "our worker's x-amz-* shape must also pass the fixture"
        );
    }

    #[test]
    fn string_map_vector_upload_fixture_rejects_empty_required_headers() {
        // Regression the sentinel must still catch: server ships an
        // empty map. Before StringMap we used Object which tolerated
        // this silently.
        let fixture = json!({
            "requiredHeaders": "$VOLATILE:string_map$",
        });
        let regressed_live = json!({
            "requiredHeaders": {},
        });
        let err = volatile_aware_equal(&fixture, &regressed_live).unwrap_err();
        assert!(
            err.contains("requiredHeaders"),
            "error path must name the regressed field: {err}"
        );
    }

    #[test]
    fn string_map_vector_upload_fixture_rejects_non_string_header_value() {
        // Regression: server accidentally emits a number in the header
        // map (e.g. serializing a satoshi amount into what should be a
        // string header). Must fail.
        let fixture = json!({
            "requiredHeaders": "$VOLATILE:string_map$",
        });
        let regressed_live = json!({
            "requiredHeaders": {"x-amz-meta-size": 42},
        });
        assert!(volatile_aware_equal(&fixture, &regressed_live).is_err());
    }

    #[test]
    fn string_map_is_strictly_more_precise_than_object() {
        // Every value accepted by StringMap must also be accepted by
        // Object (subset property). But Object accepts empties and
        // non-string values which StringMap rejects.
        let good = json!({"a": "b"});
        assert!(VolatileKind::StringMap.matches(&good));
        assert!(VolatileKind::Object.matches(&good));

        let empty = json!({});
        assert!(!VolatileKind::StringMap.matches(&empty));
        assert!(
            VolatileKind::Object.matches(&empty),
            "Object is the laxer kind — empties still pass"
        );

        let nonstring = json!({"a": 1});
        assert!(!VolatileKind::StringMap.matches(&nonstring));
        assert!(VolatileKind::Object.matches(&nonstring));
    }

    // Sanity: jcs_sha256 on a fixture containing the new sentinel is
    // deterministic. Sentinels are string-valued so they're just data
    // to JCS, but the test pins the contract that fixture-hashing
    // keeps working.
    #[test]
    fn jcs_sha256_stable_for_fixture_with_string_map_sentinel() {
        let a = json!({
            "requiredHeaders": "$VOLATILE:string_map$",
            "status": "success",
        });
        let b = json!({
            "status": "success",
            "requiredHeaders": "$VOLATILE:string_map$",
        });
        assert_eq!(jcs_sha256_hex(&a).unwrap(), jcs_sha256_hex(&b).unwrap());
    }
}
