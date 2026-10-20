//! What the core asks of its host to learn about the chain.
//!
//! The core does no input or output. A host (the Electrum and Esplora
//! adapters of the next crates, or a wallet's own node connection) implements
//! these traits, and the core checks everything they return: a source that
//! lies about headers is caught by the proof-of-work and checkpoint rules of
//! [`HeaderChain`](crate::HeaderChain), never trusted.

use bitcoin::{Amount, BlockHash, FeeRate, ScriptBuf, Txid};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::proof::MerkleBranch;

/// Why a source could not answer. The enum is small and `Copy` so it can be
/// passed to a string table without any server text riding along. A saved
/// discovery run keeps the one that ended it, so it is also written and read back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum SourceError {
    /// The server could not be reached, or stopped answering.
    #[error("the server could not be reached")]
    Unavailable,
    /// The server answered with something that is not what was asked for.
    #[error("the server's answer was not understood")]
    Malformed,
    /// A limit was hit: the server's own, or one the host set for itself.
    #[error("a limit was reached")]
    Limit,
    /// The server declined the request, or the person declined it on the
    /// consent screen.
    #[error("the request was refused")]
    Refused,
}

/// A place to read block headers from.
///
/// The shape is Electrum's `blockchain.block.headers`: raw 80-byte headers
/// one after another, which [`HeaderChain::absorb`](crate::HeaderChain::absorb)
/// takes unchanged. Methods take `&self`; a source that must change state to
/// answer (a socket, a counter) keeps it behind a lock, as the host's
/// generated bindings need in any case.
pub trait Headers {
    /// The height of the best block the source knows of.
    ///
    /// # Errors
    ///
    /// A [`SourceError`] when the source cannot say.
    fn tip(&self) -> Result<u32, SourceError>;

    /// `count` consecutive raw 80-byte headers, concatenated, from height
    /// `start`. A source may answer with fewer than asked, never with more.
    ///
    /// # Errors
    ///
    /// A [`SourceError`] when the source cannot answer.
    fn headers_raw(&self, start: u32, count: u32) -> Result<Vec<u8>, SourceError>;
}

/// One transaction in the history of a script, as an indexing server lists it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryItem {
    /// The id of the transaction.
    pub txid: Txid,
    /// The height of the block it is in, or `None` while it is unconfirmed.
    pub height: Option<u32>,
}

/// One unspent output paying a script, as an indexing server lists it.
///
/// The core does not take any of it as true: a coin is only a candidate until
/// its transaction and merkle branch have been proved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unspent {
    /// The id of the transaction that made the output.
    pub txid: Txid,
    /// The index of the output in that transaction.
    pub vout: u32,
    /// The amount the server says the output holds.
    pub amount: Amount,
    /// The height of the block the transaction is in, or `None` while it is
    /// unconfirmed.
    pub height: Option<u32>,
}

/// An indexing server, as discovery needs it: the history and the unspent
/// outputs of scripts, and the proof material for what it reports.
///
/// The lists of `history` and `unspent` answer the scripts one for one and in
/// the same order. Everything a source says is checked: the genesis hash by
/// the caller against the header chain, every coin by [`prove`](crate::prove).
/// A source that hides coins is not caught here (a second source can catch
/// it); a source that invents them is.
pub trait HistorySource {
    /// The hash of the first block of the chain the server follows, the guard
    /// against asking a server of another network.
    ///
    /// # Errors
    ///
    /// A [`SourceError`] when the source cannot say.
    fn genesis(&self) -> Result<BlockHash, SourceError>;

    /// For each script, the transactions that pay it or spend from it,
    /// confirmed and unconfirmed. Empty for a script never used.
    ///
    /// # Errors
    ///
    /// A [`SourceError`] when the source cannot answer.
    fn history(&self, scripts: &[ScriptBuf]) -> Result<Vec<Vec<HistoryItem>>, SourceError>;

    /// For each script, the outputs that pay it and are not spent.
    ///
    /// # Errors
    ///
    /// A [`SourceError`] when the source cannot answer.
    fn unspent(&self, scripts: &[ScriptBuf]) -> Result<Vec<Vec<Unspent>>, SourceError>;

    /// The raw bytes of a transaction, as the network serialises it.
    ///
    /// # Errors
    ///
    /// A [`SourceError`] when the source cannot answer.
    fn transaction_raw(&self, txid: Txid) -> Result<Vec<u8>, SourceError>;

    /// The merkle branch of a confirmed transaction in the block at `height`.
    ///
    /// # Errors
    ///
    /// A [`SourceError`] when the source cannot answer.
    fn merkle(&self, txid: Txid, height: u32) -> Result<MerkleBranch, SourceError>;

    /// The fee rate the server estimates for confirmation within `blocks`
    /// blocks, or `None` when it has no estimate.
    ///
    /// # Errors
    ///
    /// A [`SourceError`] when the source cannot answer.
    fn fee_estimate(&self, blocks: u16) -> Result<Option<FeeRate>, SourceError>;
}

/// A way to put a signed transaction on the network.
pub trait Broadcaster {
    /// Sends the raw transaction and returns the id the network gives it.
    ///
    /// # Errors
    ///
    /// A [`SourceError`] when it could not be sent, or was refused.
    fn broadcast(&self, raw: &[u8]) -> Result<Txid, SourceError>;
}
