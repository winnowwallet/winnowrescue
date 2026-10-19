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
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects
    )
)]

pub mod destination;
pub mod error;
pub mod keys;
pub mod network;
pub mod paths;
pub mod plan;
pub mod secret;
pub mod words;

#[cfg(test)]
mod tests;

pub use destination::Destination;
pub use error::{DestinationError, ImportError, PathError, PlanError};
pub use keys::{
    Compression, DumpedKey, ExtendedKey, ParsedKey, parse_dumpwallet, parse_extended, parse_hex,
    parse_mini, parse_wif,
};
pub use network::Network;
pub use paths::{Chain, PathTemplate, Purpose, Quirk, ScriptKind, Step, TypedPath, parse_path};
pub use plan::{Branch, Origin, Plan, PlanFingerprint, Tier};
pub use secret::{KeyHandle, RootKey, SecretInput, Seed, Session, SessionKind};
pub use words::ElectrumKind;

/// The crate version, the one figure every shell shows.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Entry points the fuzz targets call. Each takes raw bytes and must never
/// trap; refusing is the expected answer for almost every input.
#[cfg(feature = "fuzzing")]
pub mod fuzz_api {
    use crate::{Destination, Network, Plan, SecretInput, Session};

    /// Reads the bytes as text; bytes that are not UTF-8 are read with the
    /// replacement character so the parsers still see them.
    fn text(data: &[u8]) -> String {
        String::from_utf8_lossy(data).into_owned()
    }

    /// Feeds the bytes as a secret to the importer on mainnet and on signet.
    /// A NUL byte splits them into the secret and a passphrase. Whatever
    /// imports gets a plan built from it, which exercises the derivation.
    pub fn parse_secret(data: &[u8]) {
        let (secret, passphrase) = match data.iter().position(|&b| b == 0) {
            Some(split) => {
                let (secret, rest) = data.split_at(split);
                (secret, rest.get(1..).map(text))
            }
            None => (data, None),
        };
        for network in [Network::Mainnet, Network::Signet] {
            let imported = Session::import(
                SecretInput::new(text(secret)),
                passphrase.clone().map(SecretInput::new),
                network,
            );
            if let Ok(session) = imported {
                let _ = Plan::build(&session);
            }
        }
    }

    /// Feeds the bytes as a destination address on every network.
    pub fn parse_destination(data: &[u8]) {
        let input = text(data);
        for network in [Network::Mainnet, Network::Signet, Network::Regtest] {
            let _ = Destination::parse(&input, network);
        }
    }

    /// Feeds the bytes as a typed path. A path that parses must print as one
    /// that parses back to the same path.
    ///
    /// # Panics
    ///
    /// If a path that parsed does not parse back to itself from its own text.
    pub fn parse_path(data: &[u8]) {
        if let Ok(path) = crate::parse_path(&text(data)) {
            assert_eq!(crate::parse_path(&path.to_string()), Ok(path));
        }
    }

    /// Feeds the bytes as the text of a `dumpwallet` file on mainnet and signet.
    pub fn parse_dumpwallet(data: &[u8]) {
        let input = text(data);
        for network in [Network::Mainnet, Network::Signet] {
            let _ = crate::parse_dumpwallet(&input, network);
        }
    }
}
