//! The pure core of Winnow Rescue.
//!
//! Everything that must be identical on every platform lives here, and nothing
//! that touches a platform: no sockets, files, clock, randomness or logging.
//! Hosts supply those through traits. Secrets are zeroized types that never
//! leave this crate by value and are never serialized or printed.
//!
//! The proof rule: a server can hide coins, never invent them. Every coin an
//! indexer reports is proved from its transaction bytes, a merkle branch and a
//! header chain this crate validated from genesis.
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
pub mod headers;
pub mod keys;
pub mod network;
pub mod paths;
pub mod plan;
pub mod proof;
pub mod secret;
pub mod source;
pub mod words;

#[cfg(test)]
mod tests;

pub use destination::Destination;
pub use error::{DestinationError, HeaderError, ImportError, PathError, PlanError, ProofError};
pub use headers::{HEADER_SIZE, HeaderChain, MAINNET_CHECKPOINTS};
pub use keys::{
    Compression, DumpedKey, ExtendedKey, ParsedKey, parse_dumpwallet, parse_extended, parse_hex,
    parse_mini, parse_wif,
};
pub use network::Network;
pub use paths::{Chain, PathTemplate, Purpose, Quirk, ScriptKind, Step, TypedPath, parse_path};
pub use plan::{Branch, Origin, Plan, PlanFingerprint, Tier};
pub use proof::{MAX_BRANCH_LEN, MerkleBranch, ProvenCoin, fold, prove};
pub use secret::{KeyHandle, RootKey, SecretInput, Seed, Session, SessionKind};
pub use source::{Headers, SourceError};
pub use words::ElectrumKind;

/// The crate version, the one figure every shell shows.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Entry points the fuzz targets call. Each takes raw bytes and must never
/// trap; refusing is the expected answer for almost every input.
#[cfg(feature = "fuzzing")]
pub mod fuzz_api {
    use bitcoin::block::{Header, TxMerkleNode};
    use bitcoin::consensus::deserialize;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::{Transaction, Txid};

    use crate::{
        Destination, HEADER_SIZE, HeaderChain, MAX_BRANCH_LEN, MerkleBranch, Network, Plan,
        SecretInput, Session,
    };

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

    /// Feeds the bytes to a fresh mainnet chain and a fresh regtest chain as raw
    /// headers, then, on regtest, as headers made to follow the chain so the
    /// later checks run too.
    ///
    /// Whatever the answer, a chain that refused is exactly as it was, one that
    /// accepted is longer by the count it returned, and its saved form loads
    /// back as the same chain.
    ///
    /// # Panics
    ///
    /// If a chain changes when it refused, or does not grow by the count it
    /// returned, or its saved form does not load back as itself.
    pub fn headers_absorb(data: &[u8]) {
        for network in [Network::Mainnet, Network::Regtest] {
            let mut chain = HeaderChain::new(network);
            absorb_checked(&mut chain, data);
            // The same bytes again, one record at a time.
            for piece in data.chunks(HEADER_SIZE) {
                absorb_checked(&mut chain, piece);
            }
        }
        // Regtest takes about every other nonce, so headers that are made to
        // follow the tip get as far as the time rule.
        let mut chain = HeaderChain::new(Network::Regtest);
        for record in data.as_chunks::<HEADER_SIZE>().0 {
            let Ok(mut header) = deserialize::<Header>(record.as_slice()) else {
                continue;
            };
            let tip = chain.tip();
            header.prev_blockhash = chain.tip_hash();
            header.bits = tip.bits;
            header.time = tip.time.wrapping_add(header.time % 4);
            for _ in 0..4 {
                if header.validate_pow(header.target()).is_ok() {
                    break;
                }
                header.nonce = header.nonce.wrapping_add(1);
            }
            absorb_checked(&mut chain, &serialize(&header));
        }
    }

    /// One `absorb`, with the promises of the chain checked around it.
    fn absorb_checked(chain: &mut HeaderChain, bytes: &[u8]) {
        let (height, tip, work) = (chain.height(), chain.tip_hash(), chain.work());
        match chain.absorb(bytes) {
            Err(_) => {
                assert_eq!(
                    (chain.height(), chain.tip_hash(), chain.work()),
                    (height, tip, work)
                );
            }
            Ok(taken) => {
                assert_eq!(
                    u64::from(chain.height()).checked_sub(u64::from(height)),
                    u64::try_from(taken).ok()
                );
                assert_eq!(Some(chain.tip_hash()), chain.block_hash_at(chain.height()));
            }
        }
        let saved = chain.to_bytes();
        let loaded = HeaderChain::from_bytes(chain.network(), &saved);
        assert_eq!(loaded.map(|again| again.to_bytes()), Ok(saved));
    }

    /// Reads the bytes as a transaction id, a position and up to 64 more hashes
    /// of 32 bytes each, and folds them. Folding never fails, however many
    /// hashes there are, but a branch of more than [`MAX_BRANCH_LEN`] hashes,
    /// or whose position the hashes cannot reach, is refused as a shape. The
    /// same bytes read as whitespace-separated text go through both
    /// constructors that take the hashes as written by Electrum and Esplora,
    /// which must agree.
    ///
    /// # Panics
    ///
    /// If the shape check disagrees with its rule, or the two constructors
    /// disagree.
    pub fn merkle_fold(data: &[u8]) {
        let mut head = [0_u8; 36];
        for (slot, byte) in head.iter_mut().zip(data) {
            *slot = *byte;
        }
        let (id, position) = head.split_at(32);
        let txid = Txid::from_byte_array(<[u8; 32]>::try_from(id).unwrap_or_default());
        let position = u32::from_le_bytes(<[u8; 4]>::try_from(position).unwrap_or_default());
        let hashes: Vec<TxMerkleNode> = data
            .get(36..)
            .unwrap_or_default()
            .as_chunks::<32>()
            .0
            .iter()
            .take(64)
            .map(|chunk| TxMerkleNode::from_byte_array(*chunk))
            .collect();
        let branch = MerkleBranch::new(0, position, hashes);
        let root = crate::fold(txid, &branch);
        assert_eq!(root, crate::fold(txid, &branch));
        if branch.hashes.is_empty() {
            assert_eq!(root.to_byte_array(), txid.to_byte_array());
        }
        let shape = branch.check_shape();
        let reaches = u32::try_from(branch.hashes.len())
            .ok()
            .and_then(|depth| position.checked_shr(depth))
            .is_none_or(|left_over| left_over == 0);
        assert_eq!(
            shape.is_ok(),
            branch.hashes.len() <= MAX_BRANCH_LEN && reaches
        );

        let text = text(data);
        let written: Vec<&str> = text.split_whitespace().take(64).collect();
        let esplora = MerkleBranch::from_esplora(1, position, &written);
        let electrum = MerkleBranch::from_electrum(1, position, &written);
        assert_eq!(esplora, electrum);
        if let Ok(branch) = esplora {
            let _ = crate::fold(txid, &branch);
        }
    }

    /// Feeds the bytes as a transaction to the step that decodes it, refuses a
    /// size of 64 bytes and compares its id. A transaction that decodes must be
    /// accepted under its own id and refused under any other.
    ///
    /// # Panics
    ///
    /// If a transaction that decoded is not accepted under its own id, or is
    /// accepted under another.
    pub fn tx_boundary(data: &[u8]) {
        let nobody = Txid::from_byte_array([0; 32]);
        let Ok(tx) = deserialize::<Transaction>(data) else {
            assert_eq!(
                crate::proof::decode(data, nobody).err(),
                Some(crate::ProofError::Decode)
            );
            return;
        };
        let own = tx.compute_txid();
        let answer = crate::proof::decode(data, own);
        if tx.base_size() == 64 {
            assert_eq!(answer.err(), Some(crate::ProofError::SixtyFourBytes));
        } else {
            assert_eq!(answer.map(|decoded| decoded.compute_txid()), Ok(own));
            let mut other = own.to_byte_array();
            other[0] ^= 1;
            assert!(crate::proof::decode(data, Txid::from_byte_array(other)).is_err());
        }
    }
}
