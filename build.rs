mod build_versions;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    bsv_worker_build_info::emit();
    println!("cargo:rerun-if-changed=build_versions.rs");
    // Watch the checkout as well as the shared emitter's Git/source inputs.
    // Edits to docs or untracked files must refresh the dirty flag too.
    println!("cargo:rerun-if-changed=.");
    let lock = std::fs::read_to_string("Cargo.lock")?;
    for (name, variable) in [
        ("bsv-storage-cloudflare", "STORAGE_CRATE_VERSION"),
        ("bsv-overlay-engine", "STORAGE_OVERLAY_ENGINE_VERSION"),
    ] {
        let version = build_versions::lock_version(&lock, name)?;
        println!("cargo:rustc-env={variable}={version}");
    }
    Ok(())
}
