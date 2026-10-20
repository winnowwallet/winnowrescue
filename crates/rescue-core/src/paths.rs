//! Script kinds, the standard purposes, the paths of wallets with habits, and
//! the parser for a path the person types.

use core::fmt;

use bitcoin::bip32::ChildNumber;
use serde::{Deserialize, Serialize};

use crate::error::{PathError, PlanError};
use crate::network::Network;

/// How far past the last used address every branch is checked before it is
/// called empty.
pub const GAP: u32 = 20;

/// Tier 1 looks at accounts `0` up to but not including this number.
pub const TIER_ONE_ACCOUNTS: u32 = 3;

/// A typed path longer than this is refused; no wallet goes anywhere near it.
const MAX_TYPED_STEPS: usize = 32;

/// What a coin's output script looks like, which decides how it is signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ScriptKind {
    /// Pay to public key hash. An old key may have an uncompressed public key.
    P2pkh {
        /// Whether the public key in the script is the 33-byte form.
        compressed: bool,
    },
    /// A native segwit key hash wrapped in a script hash (BIP49).
    P2shP2wpkh,
    /// A native segwit key hash (BIP84).
    P2wpkh,
    /// Taproot with the key-path-only tweak (BIP86).
    P2tr,
}

impl ScriptKind {
    /// The kind every key from a BIP32 tree has when it is a P2PKH: tree keys
    /// are always compressed.
    pub const TREE_P2PKH: Self = Self::P2pkh { compressed: true };
}

/// The purpose field of a standard path, `m/purpose'/coin'/account'`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Purpose {
    /// BIP44, pay to public key hash.
    Bip44,
    /// BIP49, segwit nested in a script hash.
    Bip49,
    /// BIP84, native segwit.
    Bip84,
    /// BIP86, taproot.
    Bip86,
}

impl Purpose {
    /// All four purposes, in the order the plan walks them.
    pub const ALL: [Self; 4] = [Self::Bip44, Self::Bip49, Self::Bip84, Self::Bip86];

    /// The number written in the path: 44, 49, 84 or 86.
    #[must_use]
    pub const fn number(self) -> u32 {
        match self {
            Self::Bip44 => 44,
            Self::Bip49 => 49,
            Self::Bip84 => 84,
            Self::Bip86 => 86,
        }
    }

    /// The script kind the purpose defines.
    #[must_use]
    pub const fn script_kind(self) -> ScriptKind {
        match self {
            Self::Bip44 => ScriptKind::TREE_P2PKH,
            Self::Bip49 => ScriptKind::P2shP2wpkh,
            Self::Bip84 => ScriptKind::P2wpkh,
            Self::Bip86 => ScriptKind::P2tr,
        }
    }
}

/// The two chains of an account: addresses given out, and change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Chain {
    /// Chain 0, the receiving addresses.
    External,
    /// Chain 1, the change addresses.
    Internal,
}

impl Chain {
    /// Both chains, receiving first.
    pub const ALL: [Self; 2] = [Self::External, Self::Internal];

    /// The number written in the path: 0 or 1.
    #[must_use]
    pub const fn number(self) -> u32 {
        match self {
            Self::External => 0,
            Self::Internal => 1,
        }
    }
}

/// One step of a path written as data. `CoinType` is the hardened coin type of
/// the session's network, so one table serves mainnet and the test networks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// A hardened child, written `n'`.
    Hardened(u32),
    /// An ordinary child, written `n`.
    Normal(u32),
    /// The hardened coin type: `0'` on mainnet, `1'` elsewhere.
    CoinType,
}

impl Step {
    fn resolve(self, network: Network) -> Result<ChildNumber, PlanError> {
        match self {
            Self::Hardened(index) => ChildNumber::from_hardened_idx(index),
            Self::Normal(index) => ChildNumber::from_normal_idx(index),
            Self::CoinType => ChildNumber::from_hardened_idx(network.coin_type()),
        }
        .map_err(|_| PlanError::IndexTooLarge)
    }
}

/// A wallet's habit: a path that is not BIP44's and is still in use in the
/// wild. A row is `prefix`, then the chain (0 or 1), then the address index.
#[derive(Clone, Copy, Debug)]
pub struct Quirk {
    /// What the row is, for the person reading the plan.
    pub name: &'static str,
    /// The steps before the chain.
    pub prefix: &'static [Step],
    /// Whether the chain step is hardened.
    pub chain_hardened: bool,
    /// Whether the address index is hardened.
    pub index_hardened: bool,
    /// The script kind of the addresses.
    pub kind: ScriptKind,
}

impl Quirk {
    /// The template of one chain of this row for a network.
    ///
    /// # Errors
    ///
    /// Fails only if the table holds an index of 2147483648 or more.
    pub fn template(&self, chain: Chain, network: Network) -> Result<PathTemplate, PlanError> {
        let mut steps = Vec::with_capacity(self.prefix.len().saturating_add(1));
        for step in self.prefix {
            steps.push(step.resolve(network)?);
        }
        let chain_step = if self.chain_hardened {
            Step::Hardened(chain.number())
        } else {
            Step::Normal(chain.number())
        };
        steps.push(chain_step.resolve(network)?);
        Ok(PathTemplate::new(steps, self.index_hardened, false))
    }
}

/// The wallets with habits that a BIP39 phrase or a root key may belong to,
/// tried after the four standard purposes.
pub const QUIRKS: [Quirk; 6] = [
    Quirk {
        name: "Bitcoin Core legacy HD m/0'/c'/i'",
        prefix: &[Step::Hardened(0)],
        chain_hardened: true,
        index_hardened: true,
        kind: ScriptKind::TREE_P2PKH,
    },
    Quirk {
        name: "BRD and MultiBit HD m/0'/c/i",
        prefix: &[Step::Hardened(0)],
        chain_hardened: false,
        index_hardened: false,
        kind: ScriptKind::TREE_P2PKH,
    },
    Quirk {
        name: "Samourai BIP84 account 2147483644'",
        prefix: &[
            Step::Hardened(84),
            Step::CoinType,
            Step::Hardened(2_147_483_644),
        ],
        chain_hardened: false,
        index_hardened: false,
        kind: ScriptKind::P2wpkh,
    },
    Quirk {
        name: "Samourai BIP84 account 2147483645'",
        prefix: &[
            Step::Hardened(84),
            Step::CoinType,
            Step::Hardened(2_147_483_645),
        ],
        chain_hardened: false,
        index_hardened: false,
        kind: ScriptKind::P2wpkh,
    },
    Quirk {
        name: "Samourai BIP84 account 2147483646'",
        prefix: &[
            Step::Hardened(84),
            Step::CoinType,
            Step::Hardened(2_147_483_646),
        ],
        chain_hardened: false,
        index_hardened: false,
        kind: ScriptKind::P2wpkh,
    },
    Quirk {
        name: "Samourai BIP84 account 2147483647'",
        prefix: &[
            Step::Hardened(84),
            Step::CoinType,
            Step::Hardened(2_147_483_647),
        ],
        chain_hardened: false,
        index_hardened: false,
        kind: ScriptKind::P2wpkh,
    },
];

/// Electrum 2.x standard seeds: `m/0/i` and `m/1/i`, pay to public key hash.
pub const ELECTRUM_STANDARD: Quirk = Quirk {
    name: "Electrum standard m/c/i",
    prefix: &[],
    chain_hardened: false,
    index_hardened: false,
    kind: ScriptKind::TREE_P2PKH,
};

/// Electrum 2.x segwit seeds: `m/0'/0/i` and `m/0'/1/i`, native segwit.
pub const ELECTRUM_SEGWIT: Quirk = Quirk {
    name: "Electrum segwit m/0'/c/i",
    prefix: &[Step::Hardened(0)],
    chain_hardened: false,
    index_hardened: false,
    kind: ScriptKind::P2wpkh,
};

/// A path with the address index left open, as a branch of the plan carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathTemplate {
    steps: Vec<ChildNumber>,
    index_hardened: bool,
    relative: bool,
}

impl PathTemplate {
    pub(crate) fn new(steps: Vec<ChildNumber>, index_hardened: bool, relative: bool) -> Self {
        Self {
            steps,
            index_hardened,
            relative,
        }
    }

    /// The steps before the address index.
    #[must_use]
    pub fn steps(&self) -> &[ChildNumber] {
        &self.steps
    }

    /// Whether the address index is a hardened child (Bitcoin Core's old HD
    /// wallets) rather than an ordinary one.
    #[must_use]
    pub const fn index_is_hardened(&self) -> bool {
        self.index_hardened
    }

    /// Whether the steps start at the key the person gave (an account key)
    /// rather than at the root `m`.
    #[must_use]
    pub const fn is_relative(&self) -> bool {
        self.relative
    }

    /// The full path of address `index`.
    ///
    /// # Errors
    ///
    /// [`PlanError::IndexTooLarge`] when `index` is 2147483648 or more.
    pub fn path_at(&self, index: u32) -> Result<Vec<ChildNumber>, PlanError> {
        let last = if self.index_hardened {
            ChildNumber::from_hardened_idx(index)
        } else {
            ChildNumber::from_normal_idx(index)
        }
        .map_err(|_| PlanError::IndexTooLarge)?;
        let mut path = self.steps.clone();
        path.push(last);
        Ok(path)
    }
}

impl fmt::Display for PathTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.relative { "." } else { "m" })?;
        for step in &self.steps {
            write!(f, "/{step}")?;
        }
        f.write_str(if self.index_hardened { "/*'" } else { "/*" })
    }
}

/// A path the person typed, parsed. It may end in `*`, which stands for the
/// address index; without it the path names an account and both chains are
/// walked beneath it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedPath {
    steps: Vec<ChildNumber>,
    wildcard: Option<bool>,
}

impl TypedPath {
    /// The steps before the optional `*`.
    #[must_use]
    pub fn steps(&self) -> &[ChildNumber] {
        &self.steps
    }

    /// `Some(hardened)` when the path ends in `*` or `*'`.
    #[must_use]
    pub const fn wildcard(&self) -> Option<bool> {
        self.wildcard
    }
}

impl fmt::Display for TypedPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("m")?;
        for step in &self.steps {
            write!(f, "/{step}")?;
        }
        match self.wildcard {
            Some(true) => f.write_str("/*'"),
            Some(false) => f.write_str("/*"),
            None => Ok(()),
        }
    }
}

/// Parses a path the person typed: `m`, then `/` and steps, each a whole
/// number below 2147483648 optionally followed by `'`, `h` or `H` for a
/// hardened step; the last step may be `*` (or `*'`, `*h`, `*H`) for the
/// address index. Anything else is refused by name.
///
/// # Errors
///
/// A [`PathError`] naming what is wrong.
pub fn parse_path(text: &str) -> Result<TypedPath, PathError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(PathError::Empty);
    }
    let mut parts = text.split('/');
    if parts.next() != Some("m") {
        return Err(PathError::MissingRoot);
    }
    let parts: Vec<&str> = parts.collect();
    let mut steps = Vec::new();
    let mut wildcard = None;
    for (position, part) in parts.iter().enumerate() {
        if part.is_empty() {
            return Err(PathError::EmptyStep);
        }
        let (digits, hardened) = match part.strip_suffix(['\'', 'h', 'H']) {
            Some(digits) => (digits, true),
            None => (*part, false),
        };
        if digits == "*" {
            if position.saturating_add(1) != parts.len() {
                return Err(PathError::WildcardNotLast);
            }
            wildcard = Some(hardened);
            continue;
        }
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(PathError::NotANumber);
        }
        let index: u32 = digits.parse().map_err(|_| PathError::IndexTooLarge)?;
        let child = if hardened {
            ChildNumber::from_hardened_idx(index)
        } else {
            ChildNumber::from_normal_idx(index)
        }
        .map_err(|_| PathError::IndexTooLarge)?;
        if steps.len() >= MAX_TYPED_STEPS {
            return Err(PathError::TooDeep);
        }
        steps.push(child);
    }
    Ok(TypedPath { steps, wildcard })
}
