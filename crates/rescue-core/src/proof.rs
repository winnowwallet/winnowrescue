//! A coin proved by its transaction, a merkle branch and the header chain.
//!
//! An indexing server says "this address has a coin". [`prove`] does not take
//! its word: it hashes the transaction the server sent and compares it with the
//! id the server gave, checks the output pays the script the person's own keys
//! derive, folds the merkle branch up to a root and compares that with the root
//! in the block header, and looks the header up in a chain whose every header
//! passed the proof-of-work rules. Whoever lies has to redo a block's work, so
//! a server can hide coins and never invent them.
//!
//! Unconfirmed coins have no header to prove against and are not covered.

use bitcoin::block::{Header, TxMerkleNode};
use bitcoin::consensus::deserialize;
use bitcoin::hashes::{Hash, sha256d};
use bitcoin::{Amount, OutPoint, Script, ScriptBuf, Transaction, Txid};

use crate::error::ProofError;
use crate::headers::HeaderChain;

/// The most hashes a branch may have. The position that picks the leaf is 32
/// bits, so a branch of more hashes is not the path to any leaf. A real block
/// holds well under 2^16 transactions, so a real branch has at most 16.
pub const MAX_BRANCH_LEN: usize = 32;

/// The size, without witnesses, that a transaction must not have: two merkle
/// nodes side by side.
const INNER_NODE_SIZE: usize = 64;

/// The path from one transaction to the merkle root of its block.
///
/// `hashes` are the siblings met on the way up, leaf level first, as
/// [`TxMerkleNode`]s: the 32 bytes in the internal order the hashing uses,
/// which is the reverse of how block explorers and servers write them.
/// Electrum's `blockchain.transaction.get_merkle` and Esplora's
/// `/tx/:txid/merkle-proof` both answer with the hashes in that written order
/// (hex of the reversed bytes, like a txid), and [`from_electrum`] and
/// [`from_esplora`] read it.
///
/// [`from_electrum`]: Self::from_electrum
/// [`from_esplora`]: Self::from_esplora
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleBranch {
    /// The height of the block the transaction is in.
    pub height: u32,
    /// The index of the transaction in the block: bit 0 says whether the leaf
    /// is a right child, bit 1 the same one level up, and so on.
    pub position: u32,
    /// The sibling hashes, leaf level first, in internal byte order.
    pub hashes: Vec<TxMerkleNode>,
}

impl MerkleBranch {
    /// A branch from hashes already decoded, in internal byte order.
    #[must_use]
    pub const fn new(height: u32, position: u32, hashes: Vec<TxMerkleNode>) -> Self {
        Self {
            height,
            position,
            hashes,
        }
    }

    /// A branch from the answer of Electrum's `blockchain.transaction.get_merkle`:
    /// its `block_height`, its `pos`, and its `merkle` list of hex strings.
    ///
    /// # Errors
    ///
    /// [`ProofError::BadBranchHash`] when a string is not 64 hexadecimal
    /// characters.
    pub fn from_electrum<S: AsRef<str>>(
        block_height: u32,
        pos: u32,
        merkle: &[S],
    ) -> Result<Self, ProofError> {
        Self::from_written(block_height, pos, merkle)
    }

    /// A branch from the answer of Esplora's `/tx/:txid/merkle-proof`: its
    /// `block_height`, its `pos`, and its `merkle` list of hex strings, which
    /// are written the same way as Electrum's.
    ///
    /// # Errors
    ///
    /// [`ProofError::BadBranchHash`] when a string is not 64 hexadecimal
    /// characters.
    pub fn from_esplora<S: AsRef<str>>(
        block_height: u32,
        pos: u32,
        merkle: &[S],
    ) -> Result<Self, ProofError> {
        Self::from_written(block_height, pos, merkle)
    }

    /// Reads hashes written the way explorers write them: hex of the reversed
    /// bytes, which is what `TxMerkleNode` parses.
    fn from_written<S: AsRef<str>>(
        height: u32,
        position: u32,
        written: &[S],
    ) -> Result<Self, ProofError> {
        let hashes = written
            .iter()
            .map(|hash| {
                hash.as_ref()
                    .parse::<TxMerkleNode>()
                    .map_err(|_| ProofError::BadBranchHash)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::new(height, position, hashes))
    }

    /// Whether the shape can be the path to a leaf: at most
    /// [`MAX_BRANCH_LEN`] hashes, and a position that the hashes' levels can
    /// reach, so position and branch cannot disagree about the tree's depth.
    pub(crate) fn check_shape(&self) -> Result<(), ProofError> {
        if self.hashes.len() > MAX_BRANCH_LEN {
            return Err(ProofError::BranchTooLong);
        }
        let reach = u32::try_from(self.hashes.len())
            .ok()
            .and_then(|depth| self.position.checked_shr(depth));
        // The bits past the top level must be none. A branch of 32 hashes
        // reaches every bit of the position, so the shift leaves nothing.
        if reach.is_some_and(|left_over| left_over != 0) {
            return Err(ProofError::PositionOutOfRange);
        }
        Ok(())
    }
}

/// Folds a transaction id up a merkle branch to a root, hashing each pair with
/// double SHA-256: at each level the position's bit says whether the running
/// node is the right child (the sibling goes first) or the left.
///
/// The result is only a candidate: it is a root when the branch is the real
/// one. Any number of hashes and any position fold without failing.
#[must_use]
pub fn fold(txid: Txid, branch: &MerkleBranch) -> TxMerkleNode {
    let mut node = TxMerkleNode::from(txid);
    for (level, sibling) in branch.hashes.iter().enumerate() {
        let right_child = u32::try_from(level)
            .ok()
            .and_then(|level| branch.position.checked_shr(level))
            .is_some_and(|rest| rest & 1 == 1);
        let (left, right) = if right_child {
            (sibling.to_byte_array(), node.to_byte_array())
        } else {
            (node.to_byte_array(), sibling.to_byte_array())
        };
        let mut pair = [0_u8; 2 * 32];
        let (low, high) = pair.split_at_mut(32);
        low.copy_from_slice(&left);
        high.copy_from_slice(&right);
        node = TxMerkleNode::from_raw_hash(sha256d::Hash::hash(&pair));
    }
    node
}

/// A coin whose existence has been proved: its transaction hashes to its id,
/// the output pays the expected script, and the transaction is in a block of
/// the validated chain.
///
/// Only [`prove`] makes one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenCoin {
    outpoint: OutPoint,
    amount: Amount,
    script: ScriptBuf,
    height: u32,
    confirmations: u32,
}

impl ProvenCoin {
    /// The transaction id and output index.
    #[must_use]
    pub const fn outpoint(&self) -> OutPoint {
        self.outpoint
    }

    /// The amount of the output.
    #[must_use]
    pub const fn amount(&self) -> Amount {
        self.amount
    }

    /// The script the output pays.
    #[must_use]
    pub fn script(&self) -> &Script {
        &self.script
    }

    /// The height of the block the transaction was mined in.
    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// How many blocks bury it: 1 when its block is the tip of the chain it
    /// was proved against.
    #[must_use]
    pub const fn confirmations(&self) -> u32 {
        self.confirmations
    }
}

/// Decodes `tx_bytes` as one transaction and refuses the two ways its bytes
/// can mislead: a size of exactly 64 bytes without witnesses, and an id other
/// than `expected`.
///
/// The size rule is about the bytes the id is the hash of, the transaction
/// without its witnesses: that is the stretch an attacker can make read as two
/// merkle nodes. A transaction whose witness-carrying bytes are 64 long is
/// shorter than that without them and is not affected.
pub(crate) fn decode(tx_bytes: &[u8], expected: Txid) -> Result<Transaction, ProofError> {
    let tx: Transaction = deserialize(tx_bytes).map_err(|_| ProofError::Decode)?;
    if tx.base_size() == INNER_NODE_SIZE {
        return Err(ProofError::SixtyFourBytes);
    }
    if tx.compute_txid() != expected {
        return Err(ProofError::TxidMismatch);
    }
    Ok(tx)
}

/// Proves that output `vout` of the transaction `tx_bytes` pays
/// `expected_script` and that the transaction is in a block of `chain`.
///
/// The checks run in this order, and the first to fail is named: the bytes
/// decode as a transaction; they are not the 64 bytes of two merkle nodes (the
/// CVE-2012-2459 shape); they hash to `expected_txid`; the output exists and
/// pays `expected_script`; the branch's block is in the chain; the branch has
/// a shape a tree can have; and the branch folds to the merkle root of that
/// block's header.
///
/// # Errors
///
/// A [`ProofError`] naming the check that failed. None carries the bytes.
pub fn prove(
    tx_bytes: &[u8],
    expected_txid: Txid,
    vout: u32,
    expected_script: &Script,
    branch: &MerkleBranch,
    chain: &HeaderChain,
) -> Result<ProvenCoin, ProofError> {
    let tx = decode(tx_bytes, expected_txid)?;
    let output = usize::try_from(vout)
        .ok()
        .and_then(|index| tx.output.get(index))
        .ok_or(ProofError::NoSuchOutput)?;
    if output.script_pubkey.as_script() != expected_script {
        return Err(ProofError::WrongScript);
    }
    let header: Header = chain
        .header_at(branch.height)
        .ok_or(ProofError::HeightNotInChain)?;
    branch.check_shape()?;
    if fold(expected_txid, branch) != header.merkle_root {
        return Err(ProofError::RootMismatch);
    }
    let confirmations = chain
        .height()
        .checked_sub(branch.height)
        .and_then(|above| above.checked_add(1))
        .ok_or(ProofError::HeightNotInChain)?;
    Ok(ProvenCoin {
        outpoint: OutPoint {
            txid: expected_txid,
            vout,
        },
        amount: output.value,
        script: output.script_pubkey.clone(),
        height: branch.height,
        confirmations,
    })
}
