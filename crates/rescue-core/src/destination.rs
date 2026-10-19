//! The one place coins are sent: a taproot address on the session's network.

use core::str::FromStr;

use bitcoin::address::AddressType;
use bitcoin::{Address, ScriptBuf};

use crate::error::DestinationError;
use crate::network::Network;

/// A checked destination: a P2TR address for one network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    address: Address,
    network: Network,
}

impl Destination {
    /// Parses an address (`Base58Check` or bech32/bech32m checksum included) and
    /// accepts it only if it is for `network` and pays to taproot.
    ///
    /// # Errors
    ///
    /// [`DestinationError::Malformed`] when the text is not an address or its
    /// checksum fails; the text is never echoed. [`DestinationError::WrongNetwork`]
    /// for an address of another network, and [`DestinationError::NotTaproot`]
    /// for any other kind of address.
    pub fn parse(text: &str, network: Network) -> Result<Self, DestinationError> {
        let unchecked = Address::from_str(text.trim()).map_err(|_| DestinationError::Malformed)?;
        let address = unchecked
            .require_network(network.to_bitcoin())
            .map_err(|_| DestinationError::WrongNetwork)?;
        if address.address_type() != Some(AddressType::P2tr) {
            return Err(DestinationError::NotTaproot);
        }
        Ok(Self { address, network })
    }

    /// The address.
    #[must_use]
    pub const fn address(&self) -> &Address {
        &self.address
    }

    /// The network it was checked for.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// The output script that pays it.
    #[must_use]
    pub fn script_pubkey(&self) -> ScriptBuf {
        self.address.script_pubkey()
    }
}
