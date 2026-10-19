//! The pure core of Winnow Rescue.
//!
//! Everything that must be identical on every platform lives here, and nothing
//! that touches a platform: no sockets, files, clock, randomness or logging.
//! Hosts supply those through traits. Secrets are zeroized types that never
//! leave this crate by value and are never serialized or printed.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro
)]

/// The crate version, the one figure every shell shows.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Entry points the fuzz targets call. Each takes raw bytes and must never
/// trap; refusing is the expected answer for almost every input.
#[cfg(feature = "fuzzing")]
pub mod fuzz_api {
    /// Placeholder until the secret parser lands: accepts any bytes.
    pub fn parse_secret(data: &[u8]) {
        let _ = core::str::from_utf8(data);
    }
}
