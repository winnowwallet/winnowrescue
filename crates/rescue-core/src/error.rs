//! The named reasons an input is refused.
//!
//! None of these carries any part of what the person typed: a wrong word is
//! named by its position, never by its text, and a bad address is never echoed.

use thiserror::Error;

/// Why a secret was refused. The enum is small and `Copy` on purpose: it can
/// be handed to a string table and to a log line without any risk of a secret
/// riding along.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ImportError {
    /// Nothing was entered.
    #[error("nothing was entered")]
    Empty,
    /// A word of the phrase is not in the BIP39 English list. `position` counts
    /// from 1 and stops at 255.
    #[error("word {position} is not in the word list")]
    WrongWord {
        /// The one-based position of the first word that is not in the list.
        position: u8,
    },
    /// Every word is in the list but the checksum of the phrase does not match.
    #[error("the words are all in the list but their checksum does not match")]
    BadChecksum,
    /// A BIP39 phrase has 12, 15, 18, 21 or 24 words.
    #[error("a phrase has 12, 15, 18, 21 or 24 words")]
    WrongWordCount,
    /// An Electrum seed for a two-factor wallet: a service holds a second key,
    /// so the words alone cannot spend.
    #[error("this Electrum seed belongs to a two-factor wallet, which needs a service to sign")]
    ElectrumKindUnsupported,
    /// A passphrase was given with something that has no passphrase.
    #[error("a passphrase only goes with words")]
    PassphraseNotApplicable,
    /// The text looks like a private key in WIF but is not one.
    #[error("this is not a valid private key in WIF")]
    BadWif,
    /// A test-network key was given while the session is on mainnet.
    #[error("this key is for a test network and cannot be used on mainnet")]
    TestnetKey,
    /// The text looks like a mini private key but its check byte does not match.
    #[error("this is not a valid mini private key")]
    BadMiniKey,
    /// The text looks like an extended private key but is not a valid one.
    #[error("this is not a valid extended private key")]
    BadExtendedKey,
    /// An extended public key holds no secret, so there is nothing to sweep with.
    #[error("an extended public key cannot sweep; watch-only comes later")]
    ExtendedPublicKey,
    /// A multi-signature extended key (Ypub/Zpub forms) needs other keys too.
    #[error("a multi-signature extended key cannot sweep by itself")]
    MultisigExtendedKey,
    /// A line of a wallet dump file is not valid. `line` counts from 1.
    #[error("line {line} of the wallet file is not valid")]
    BadDumpwallet {
        /// The one-based number of the first line that failed.
        line: u32,
    },
    /// The secret is a number outside the range secp256k1 allows.
    #[error("this secret is outside the range a key can have")]
    KeyOutOfRange,
    /// The text is not a phrase, a key, an extended key or a wallet file.
    #[error("this is not a phrase, a key or a wallet file")]
    NotRecognised,
}

/// Why a typed derivation path was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum PathError {
    /// The text is empty.
    #[error("the path is empty")]
    Empty,
    /// A path starts with `m`.
    #[error("a path starts with m")]
    MissingRoot,
    /// Two slashes in a row, or a slash at the end.
    #[error("a step between two slashes is empty")]
    EmptyStep,
    /// A step is not a whole number.
    #[error("a step is not a whole number")]
    NotANumber,
    /// A step is 2147483648 or more; the hardened mark is `'`, `h` or `H`.
    #[error("a step is too large; mark hardened steps with ', h or H")]
    IndexTooLarge,
    /// The path has more steps than any wallet uses.
    #[error("the path has too many steps")]
    TooDeep,
    /// `*` stands for the address index and can only be the last step.
    #[error("* can only be the last step")]
    WildcardNotLast,
}

/// Why a destination address was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum DestinationError {
    /// Not an address: wrong characters, wrong length or a failed checksum.
    #[error("this is not a valid address")]
    Malformed,
    /// A valid address, but for another network.
    #[error("this address is for another network")]
    WrongNetwork,
    /// A valid address that is not a taproot (bc1p) address.
    #[error("only taproot (bc1p) addresses are accepted")]
    NotTaproot,
}

/// Why a derivation plan, or one address of it, could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum PlanError {
    /// The key could not be derived: the path is deeper than BIP32 allows or
    /// the step leads to an invalid key.
    #[error("a key could not be derived along this path")]
    Derivation,
    /// An address index of 2147483648 or more.
    #[error("the address index is too large")]
    IndexTooLarge,
    /// The path does not fit this session: a typed path was asked of a session
    /// that holds loose keys, which have no tree to walk.
    #[error("this session has no key tree for a path")]
    NoTree,
}

/// Why a run of block headers, or a saved copy of a chain, was refused.
///
/// A failure at a header names the height that header would have had. None of
/// these carries bytes the server sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum HeaderError {
    /// The bytes are not a whole number of 80-byte headers.
    #[error("the headers are not a whole number of 80-byte records")]
    BadLength,
    /// A header does not name the one before it as its parent.
    #[error("the header at height {height} does not follow the one before it")]
    NotLinked {
        /// The height the header would have had.
        height: u32,
    },
    /// A header carries a difficulty other than the one the rules require at
    /// its height.
    #[error("the header at height {height} has the wrong difficulty")]
    WrongTarget {
        /// The height the header would have had.
        height: u32,
    },
    /// A header's hash is not below its target.
    #[error("the header at height {height} has no valid proof of work")]
    BadProofOfWork {
        /// The height the header would have had.
        height: u32,
    },
    /// A header's time is not later than the median of the eleven before it.
    #[error("the header at height {height} is not later than the median of the eleven before it")]
    TimeTooOld {
        /// The height the header would have had.
        height: u32,
    },
    /// A header at a checkpoint height is not the block the checkpoint names:
    /// the server is on another chain.
    #[error("the header at height {height} is not the block the checkpoint names")]
    CheckpointMismatch {
        /// The checkpoint height.
        height: u32,
    },
    /// The chain would be longer than a height can count.
    #[error("the chain would be longer than a height can count")]
    TooLong,
    /// A saved chain is shorter than its fixed parts.
    #[error("the saved chain is truncated")]
    CacheTruncated,
    /// A saved chain's trailing checksum does not match its body.
    #[error("the saved chain is damaged: its checksum does not match")]
    CacheChecksum,
    /// A saved chain is for another network than the one asked for.
    #[error("the saved chain is for another network")]
    CacheNetwork,
    /// A saved chain's count does not match the headers it holds.
    #[error("the saved chain's count does not match its headers")]
    CacheCount,
}

/// Why a coin could not be proved from a transaction, a merkle branch and the
/// header chain.
///
/// Like every error here, none carries the bytes it was given.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ProofError {
    /// The bytes are not one whole transaction.
    #[error("the bytes are not a transaction")]
    Decode,
    /// The transaction is exactly 64 bytes without its witness, the size of
    /// two merkle nodes: it could pass for an inner node of the tree
    /// (CVE-2012-2459), so it proves nothing.
    #[error("a transaction of exactly 64 bytes cannot be proved")]
    SixtyFourBytes,
    /// The transaction does not hash to the id the server gave for it.
    #[error("the transaction does not hash to the expected id")]
    TxidMismatch,
    /// The transaction has no output at that index.
    #[error("the transaction has no such output")]
    NoSuchOutput,
    /// The output does not pay the expected script.
    #[error("the output does not pay the expected script")]
    WrongScript,
    /// The branch names a block above the tip of the chain, which the chain
    /// has not reached.
    #[error("the block is above the tip of the validated chain")]
    HeightNotInChain,
    /// A branch has more than 32 hashes; its position is 32 bits wide, so no
    /// real tree is that deep.
    #[error("the merkle branch is longer than any real one")]
    BranchTooLong,
    /// The position has bits beyond what the branch's hashes can reach, so it
    /// names no leaf of that tree.
    #[error("the position is outside the tree the branch describes")]
    PositionOutOfRange,
    /// A hash of a branch given as text is not 64 hexadecimal characters.
    #[error("a hash of the merkle branch is not 64 hexadecimal characters")]
    BadBranchHash,
    /// The branch does not lead from the transaction to the block's merkle root.
    #[error("the merkle branch does not lead to the block's merkle root")]
    RootMismatch,
}
