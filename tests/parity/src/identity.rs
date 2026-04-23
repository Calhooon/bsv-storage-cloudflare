//! Test identity management for the parity harness.
//!
//! Stateful routes (`/list`, `/find`) only diff cleanly if we use the **same**
//! BRC-31 client identity against nanostore and the local worker. This module
//! resolves that identity with the following precedence:
//!
//! 1. `PARITY_IDENTITY_KEY` env var — hex-encoded 32-byte secp256k1 private
//!    key. If set, we use it and do **not** touch the file. Useful for CI.
//! 2. `tests/parity/.identity.json` — on-disk, gitignored, chmod 600.
//! 3. Generate a fresh keypair, write the file (600), print the pubkey.
//!
//! The private key is **never** printed. `identity` subcommand output includes
//! the public key, the file path, and the creation timestamp only.
//!
//! # File format
//!
//! ```json
//! {
//!   "privateKeyHex": "...",    // 64 hex chars
//!   "publicKeyHex": "...",     // 66 hex chars (compressed, 02/03 prefix)
//!   "createdAt": "2026-04-20T12:34:56+00:00"
//! }
//! ```
//!
//! # Why not delegate to `bsv-rs::wallet::ProtoWallet`?
//!
//! `ProtoWallet` wants a full signer stack. For a harness we just need a
//! persisted keypair; generation + hex round-trip lives cleanly on
//! `bsv_rs::primitives::ec::{PrivateKey,PublicKey}`.

use bsv_rs::primitives::ec::PrivateKey;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const ENV_VAR: &str = "PARITY_IDENTITY_KEY";

/// Fully-resolved identity for a single run of the harness.
///
/// The `Debug` impl deliberately redacts the private key — never log the
/// struct assuming it's safe.
#[derive(Clone)]
pub struct Identity {
    /// Used by the BRC-31 client for `/upload`, `/find`, `/list`, `/renew`,
    /// `/advertise` — wired up in the next agent's commit (see [`crate::auth`]).
    #[allow(dead_code)]
    pub private_key: PrivateKey,
    pub public_key_hex: String,
    pub source: Source,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("private_key", &"<redacted>")
            .field("public_key_hex", &self.public_key_hex)
            .field("source", &self.source)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub enum Source {
    Env,
    File { path: PathBuf, created_at: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IdentityFile {
    #[serde(rename = "privateKeyHex")]
    private_key_hex: String,
    #[serde(rename = "publicKeyHex")]
    public_key_hex: String,
    #[serde(rename = "createdAt")]
    created_at: String,
}

/// Location of the on-disk identity file. Gitignored. chmod 600 on unix.
pub fn identity_file_path() -> PathBuf {
    let crate_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(crate_dir).join(".identity.json")
}

/// Resolve the identity per the precedence rules documented on this module.
///
/// Side effects:
/// * May create `.identity.json` (chmod 600) if neither env var nor file
///   currently exist.
/// * On the unexpected case that the env var and file *both* exist AND
///   disagree on public key, we emit a warning to stderr. The env var wins.
pub fn resolve() -> Result<Identity, String> {
    // 1. Env var wins if set.
    if let Ok(hex) = std::env::var(ENV_VAR) {
        let id = parse_private_key_hex(&hex)
            .map_err(|e| format!("{ENV_VAR} is set but invalid: {e}"))?;
        let env_pub = id.public_key().to_hex();

        // Soft warning: if a file also exists and its pubkey differs, the
        // user has a surprise waiting for them.
        if let Ok(file) = read_file(&identity_file_path()) {
            if file.public_key_hex != env_pub {
                eprintln!(
                    "warning: {ENV_VAR} disagrees with {} — env pubkey={} file pubkey={}",
                    identity_file_path().display(),
                    env_pub,
                    file.public_key_hex
                );
            }
        }

        return Ok(Identity {
            public_key_hex: env_pub,
            private_key: id,
            source: Source::Env,
        });
    }

    // 2. File.
    let path = identity_file_path();
    if path.exists() {
        let file = read_file(&path)?;
        let id = parse_private_key_hex(&file.private_key_hex)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let derived_pub = id.public_key().to_hex();
        if derived_pub != file.public_key_hex {
            return Err(format!(
                "{}: privateKeyHex does not hash to publicKeyHex (expected {derived_pub}, file says {})",
                path.display(),
                file.public_key_hex
            ));
        }
        return Ok(Identity {
            public_key_hex: derived_pub,
            private_key: id,
            source: Source::File {
                path,
                created_at: file.created_at,
            },
        });
    }

    // 3. Generate.
    let id = PrivateKey::random();
    let created_at = chrono::Utc::now().to_rfc3339();
    let file = IdentityFile {
        private_key_hex: id.to_hex(),
        public_key_hex: id.public_key().to_hex(),
        created_at: created_at.clone(),
    };
    write_file(&path, &file)?;
    eprintln!(
        "created new identity file: {} (pubkey={})",
        path.display(),
        file.public_key_hex
    );
    eprintln!("  set PARITY_IDENTITY_KEY in the environment to override this for CI.");
    Ok(Identity {
        public_key_hex: file.public_key_hex,
        private_key: id,
        source: Source::File { path, created_at },
    })
}

/// Delete `.identity.json` and generate a fresh keypair in its place.
///
/// Returns an error if the file exists and `confirm_yes` is false. This
/// function only touches the on-disk file. If `PARITY_IDENTITY_KEY` is set
/// in the environment it will still take precedence at `resolve()` time;
/// the caller is responsible for warning the user if that is surprising.
pub fn regenerate(confirm_yes: bool) -> Result<Identity, String> {
    let path = identity_file_path();
    if path.exists() && !confirm_yes {
        return Err(format!(
            "{} already exists — pass --yes to overwrite",
            path.display()
        ));
    }
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| format!("remove {}: {e}", path.display()))?;
    }

    let id = PrivateKey::random();
    let created_at = chrono::Utc::now().to_rfc3339();
    let file = IdentityFile {
        private_key_hex: id.to_hex(),
        public_key_hex: id.public_key().to_hex(),
        created_at: created_at.clone(),
    };
    write_file(&path, &file)?;
    Ok(Identity {
        public_key_hex: file.public_key_hex,
        private_key: id,
        source: Source::File { path, created_at },
    })
}

fn parse_private_key_hex(hex: &str) -> Result<PrivateKey, String> {
    let trimmed = hex.trim();
    if trimmed.len() != 64 {
        return Err(format!(
            "expected 64 hex chars (32 bytes), got {}",
            trimmed.len()
        ));
    }
    PrivateKey::from_hex(trimmed).map_err(|e| format!("invalid private key: {e}"))
}

fn read_file(path: &std::path::Path) -> Result<IdentityFile, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_slice::<IdentityFile>(&bytes)
        .map_err(|e| format!("parse {}: {e}", path.display()))
}

fn write_file(path: &std::path::Path, file: &IdentityFile) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let text =
        serde_json::to_string_pretty(file).map_err(|e| format!("serialize identity: {e}"))?;
    std::fs::write(path, text).map_err(|e| format!("write {}: {e}", path.display()))?;
    restrict_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn restrict_permissions(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms).map_err(|e| format!("chmod 600 {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &std::path::Path) -> Result<(), String> {
    // On Windows we do not enforce ACL restrictions. Document and continue.
    eprintln!(
        "note: cannot set 0600 on non-unix platforms — ensure {} is protected by your user profile ACL",
        _path.display()
    );
    Ok(())
}

/// Human-readable description of where the identity came from. Never prints
/// the private key.
pub fn describe(id: &Identity) -> String {
    match &id.source {
        Source::Env => format!(
            "source: env:{ENV_VAR}\npublicKey: {}\ncreatedAt: (n/a — env var)",
            id.public_key_hex
        ),
        Source::File { path, created_at } => format!(
            "source: {}\npublicKey: {}\ncreatedAt: {}",
            path.display(),
            id.public_key_hex,
            created_at
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_hex() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let k = parse_private_key_hex(hex).unwrap();
        assert!(!k.public_key().to_hex().is_empty());
    }

    #[test]
    fn rejects_short_hex() {
        assert!(parse_private_key_hex("abcd").is_err());
    }

    #[test]
    fn rejects_invalid_hex() {
        let not_hex = "zz".repeat(32);
        assert!(parse_private_key_hex(&not_hex).is_err());
    }
}
