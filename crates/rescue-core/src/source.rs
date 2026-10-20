//! What the core asks of its host to learn about the chain.
//!
//! The core does no input or output. A host (the Electrum and Esplora
//! adapters of the next crates, or a wallet's own node connection) implements
//! these traits, and the core checks everything they return: a source that
//! lies about headers is caught by the proof-of-work and checkpoint rules of
//! [`HeaderChain`](crate::HeaderChain), never trusted.

use thiserror::Error;

/// Why a source could not answer. The enum is small and `Copy` so it can be
/// passed to a string table without any server text riding along.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
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
