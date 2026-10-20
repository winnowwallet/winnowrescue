//! The networks the core understands.

use bitcoin::NetworkKind;
use serde::{Deserialize, Serialize};

/// A Bitcoin network the core can sweep on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Network {
    /// The Bitcoin main network.
    Mainnet,
    /// The default signet; testnet-style keys and addresses.
    Signet,
    /// A local regression-test network.
    Regtest,
}

impl Network {
    /// The same network as rust-bitcoin names it.
    #[must_use]
    pub const fn to_bitcoin(self) -> bitcoin::Network {
        match self {
            Self::Mainnet => bitcoin::Network::Bitcoin,
            Self::Signet => bitcoin::Network::Signet,
            Self::Regtest => bitcoin::Network::Regtest,
        }
    }

    /// Whether this is the main network.
    #[must_use]
    pub const fn is_mainnet(self) -> bool {
        matches!(self, Self::Mainnet)
    }

    /// The coin type BIP44 puts in a path: 0 for mainnet, 1 for every test
    /// network.
    #[must_use]
    pub const fn coin_type(self) -> u32 {
        match self {
            Self::Mainnet => 0,
            Self::Signet | Self::Regtest => 1,
        }
    }

    /// Whether keys and addresses are written in the main or the test style.
    #[must_use]
    pub const fn kind(self) -> NetworkKind {
        match self {
            Self::Mainnet => NetworkKind::Main,
            Self::Signet | Self::Regtest => NetworkKind::Test,
        }
    }
}
