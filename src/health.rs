use serde_json::{json, Value};

pub(crate) fn body() -> Value {
    let shared = bsv_worker_build_info::build_json!();
    let build = json!({
        "lib_rev": shared["lib_rev"],
        "dirty": shared["dirty"],
        "built_at": shared["built_at"],
        "crates": {
            "bsv-storage-cloudflare": option_env!("STORAGE_CRATE_VERSION"),
            "bsv-rs": shared["crates"]["bsv-rs"],
            "bsv-middleware-cloudflare": shared["crates"]["bsv-middleware-cloudflare"],
            "bsv-middleware-core": shared["crates"]["bsv-middleware-core"],
            "bsv-overlay-engine": option_env!("STORAGE_OVERLAY_ENGINE_VERSION"),
        },
    });
    json!({
        "status": "success",
        "message": "bsv-storage-cloudflare running",
        "build": build,
    })
}

#[cfg(test)]
#[path = "../build_versions.rs"]
mod build_versions;

#[cfg(test)]
#[allow(clippy::expect_used, reason = "shape assertions in test code")]
mod tests {
    #[test]
    fn health_build_object_shape() {
        let body = super::body();
        assert_eq!(body["status"], "success");
        assert_eq!(body["message"], "bsv-storage-cloudflare running");
        let build = body["build"].as_object().expect("health build object");
        let mut keys: Vec<_> = build.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["built_at", "crates", "dirty", "lib_rev"]);
        let rev = build["lib_rev"].as_str().expect("revision string");
        assert_eq!(rev.len(), 40);
        assert!(rev.bytes().all(|c| c.is_ascii_hexdigit()));
        assert!(build["dirty"].is_boolean());
        let built_at = build["built_at"].as_str().expect("build time");
        assert!(built_at.ends_with('Z'));
        assert!(chrono::DateTime::parse_from_rfc3339(built_at).is_ok());
        let crates = build["crates"].as_object().expect("locked crate versions");
        assert_eq!(crates.len(), 5);
        for (name, version) in [
            ("bsv-storage-cloudflare", "0.2.2"),
            ("bsv-rs", "0.4.5"),
            ("bsv-middleware-cloudflare", "0.5.1"),
            ("bsv-middleware-core", "0.2.1"),
            ("bsv-overlay-engine", "0.1.0"),
        ] {
            assert_eq!(crates[name], version, "{name}");
            let locked = super::build_versions::lock_version(include_str!("../Cargo.lock"), name)
                .expect("unique lock entry");
            assert_eq!(crates[name], locked, "{name}");
        }
        println!("{body}");
    }
}
