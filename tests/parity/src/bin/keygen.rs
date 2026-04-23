//! Emit one fresh BRC-100-compatible secp256k1 keypair to stdout.
//!
//! Uses `bsv_rs::primitives::ec::PrivateKey::random`, which is the exact
//! entropy path the parity harness uses for its test identity. Output is
//! two lines (privkey + pubkey hex) — pipe through `wrangler secret put`
//! or append to `secrets.md`.

use bsv_rs::primitives::ec::PrivateKey;

fn main() {
    let priv_key = PrivateKey::random();
    let pub_key = priv_key.public_key();
    println!("privkey: {}", priv_key.to_hex());
    println!("pubkey:  {}", pub_key.to_hex());
}
