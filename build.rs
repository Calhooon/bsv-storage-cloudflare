mod build_versions;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    bsv_worker_build_info::emit();
    println!("cargo:rerun-if-changed=build_versions.rs");
    // Watch the checkout as well as the shared emitter's Git/source inputs.
    // Edits to docs or untracked files must refresh the dirty flag too.
    println!("cargo:rerun-if-changed=.");
    let lock = std::fs::read_to_string("Cargo.lock")?;
    let version = build_versions::lock_version(&lock, "bsv-storage-cloudflare")?;
    println!("cargo:rustc-env=STORAGE_CRATE_VERSION={version}");
    Ok(())
}
