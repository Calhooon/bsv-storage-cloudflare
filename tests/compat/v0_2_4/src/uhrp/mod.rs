//! UHRP protocol primitives — hash derivation and PushDrop advertisement encoding.
//!
//! Byte-for-byte parity with the TS impl is mandatory. See PROTOCOL.md §A (hashing)
//! and §B (PushDrop field layout) for the spec. Golden-file tests live in `tests/`
//! and gate CI.

pub mod hash;
pub mod pushdrop;
