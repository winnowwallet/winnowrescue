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
