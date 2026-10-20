//! Coin proofs against two recorded mainnet coins, the 64-byte transaction
//! that can pass for a merkle node, and the branch constructors.

use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::block::TxMerkleNode;
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use serde_json::Value;

use super::chains::{early_mainnet, grind, header, modern_mainnet, regtest_rows};
use super::vector;
use crate::{HeaderChain, MAX_BRANCH_LEN, MerkleBranch, Network, ProofError, fold, prove};

/// A recorded coin: the transaction as the server gave it, the proofs as both
/// servers gave them, and what the server's own JSON says its outputs are.
struct Recorded {
    txid: Txid,
    raw: Vec<u8>,
    header: Vec<u8>,
    height: u32,
    position: u32,
    esplora: Vec<String>,
    electrum: Vec<String>,
    outputs: Vec<(ScriptBuf, Amount)>,
}

fn recorded(file: &str) -> Recorded {
    let json: Value = serde_json::from_str(&vector(file)).unwrap();
    let strings = |value: &Value| -> Vec<String> {
        value["merkle"]
            .as_array()
            .unwrap()
            .iter()
            .map(|hash| hash.as_str().unwrap().to_owned())
            .collect()
    };
    let (esplora, electrum) = (&json["esplora_merkle_proof"], &json["electrum_get_merkle"]);
    assert_eq!(esplora["block_height"], json["block_height"]);
    assert_eq!(esplora["pos"], electrum["pos"]);
    assert_eq!(esplora["block_height"], electrum["block_height"]);
    Recorded {
        txid: Txid::from_str(json["txid"].as_str().unwrap()).unwrap(),
        raw: Vec::from_hex(json["raw"].as_str().unwrap()).unwrap(),
        header: Vec::from_hex(json["header"].as_str().unwrap()).unwrap(),
        height: u32::try_from(json["block_height"].as_u64().unwrap()).unwrap(),
        position: u32::try_from(esplora["pos"].as_u64().unwrap()).unwrap(),
        esplora: strings(esplora),
        electrum: strings(electrum),
        outputs: json["esplora_tx"]["vout"]
            .as_array()
            .unwrap()
            .iter()
            .map(|out| {
                (
                    ScriptBuf::from_hex(out["scriptpubkey"].as_str().unwrap()).unwrap(),
                    Amount::from_sat(out["value"].as_u64().unwrap()),
                )
            })
            .collect(),
    }
}

const SEGWIT: &str = "bitcoin-mainnet/proof-block862000-pos1500.json";
const COINBASE: &str = "bitcoin-mainnet/proof-block1-coinbase.json";

fn segwit() -> (Recorded, MerkleBranch, HeaderChain) {
    let coin = recorded(SEGWIT);
    let branch = MerkleBranch::from_esplora(coin.height, coin.position, &coin.esplora).unwrap();
    (coin, branch, modern_mainnet())
}

#[test]
fn a_segwit_coin_deep_in_a_block_is_proved() {
    let (coin, branch, chain) = segwit();
    assert_eq!(branch.hashes.len(), 12);
    assert_eq!(branch.position, 1500);
    // The recorded header is the one the validated chain holds there.
    assert_eq!(serialize(&chain.header_at(862_000).unwrap()), coin.header);
    // The transaction carries a witness, which its id leaves out.
    let tx: Transaction = bitcoin::consensus::deserialize(&coin.raw).unwrap();
    assert!(!tx.input[0].witness.is_empty());
    assert_ne!(
        tx.compute_txid().to_byte_array(),
        tx.compute_wtxid().to_byte_array()
    );

    let (script, amount) = coin.outputs[1].clone();
    let proven = prove(&coin.raw, coin.txid, 1, &script, &branch, &chain).unwrap();
    assert_eq!(proven.outpoint(), OutPoint::new(coin.txid, 1));
    assert_eq!(proven.amount(), amount);
    assert_eq!(proven.amount(), Amount::from_sat(546));
    assert_eq!(proven.script(), script.as_script());
    assert_eq!(proven.height(), 862_000);
    assert_eq!(proven.confirmations(), 864_864 - 862_000 + 1);

    // The folded root is the header's merkle root.
    assert_eq!(
        fold(coin.txid, &branch),
        chain.header_at(862_000).unwrap().merkle_root
    );
    // The other output is a different coin of the same transaction.
    let (script, _) = coin.outputs[0].clone();
    let data = prove(&coin.raw, coin.txid, 0, &script, &branch, &chain).unwrap();
    assert_eq!(data.amount(), Amount::ZERO);
}

#[test]
fn the_only_transaction_of_a_block_is_proved_with_no_hashes() {
    let coin = recorded(COINBASE);
    let branch = MerkleBranch::from_electrum(coin.height, coin.position, &coin.electrum).unwrap();
    assert_eq!(branch.hashes, Vec::new());
    let chain = early_mainnet();
    let (script, amount) = coin.outputs[0].clone();
    let proven = prove(&coin.raw, coin.txid, 0, &script, &branch, &chain).unwrap();
    assert_eq!(amount, Amount::from_sat(50 * 100_000_000));
    assert_eq!(proven.amount(), amount);
    assert_eq!(proven.height(), 1);
    assert_eq!(proven.confirmations(), 4032);
    // With nothing to fold, the id is the root.
    assert_eq!(
        fold(coin.txid, &branch).to_byte_array(),
        coin.txid.to_byte_array()
    );
    assert_eq!(
        fold(coin.txid, &branch),
        chain.header_at(1).unwrap().merkle_root
    );
}

#[test]
fn a_coin_in_the_tip_block_has_one_confirmation() {
    let (coin, branch, chain) = segwit();
    // The same proof against a chain that stops at its block.
    let mut upto = crate::tests::chains::modern_seed();
    let rows = super::chains::modern_rows();
    upto.absorb(&super::chains::concat(&rows[..=(862_000 - 860_832)]))
        .unwrap();
    assert_eq!(upto.height(), 862_000);
    let (script, _) = coin.outputs[1].clone();
    let proven = prove(&coin.raw, coin.txid, 1, &script, &branch, &upto).unwrap();
    assert_eq!(proven.confirmations(), 1);
    assert!(chain.height() > upto.height());
}

#[test]
fn electrum_and_esplora_write_the_same_hashes_in_the_same_order() {
    let coin = recorded(SEGWIT);
    assert_eq!(coin.esplora, coin.electrum);
    let esplora = MerkleBranch::from_esplora(coin.height, coin.position, &coin.esplora).unwrap();
    let electrum = MerkleBranch::from_electrum(coin.height, coin.position, &coin.electrum).unwrap();
    assert_eq!(esplora, electrum);
    // They are written as a txid is: hex of the reversed bytes.
    for (hash, written) in esplora.hashes.iter().zip(&coin.esplora) {
        let mut bytes = hash.to_byte_array();
        bytes.reverse();
        assert_eq!(&bytes.as_hex().to_string(), written);
    }
    // Decoded hashes, in internal order, make the same branch.
    let decoded = MerkleBranch::new(coin.height, coin.position, esplora.hashes.clone());
    assert_eq!(decoded, esplora);
}

#[test]
fn a_hash_that_is_not_sixty_four_hex_characters_is_named() {
    let good = "ab".repeat(32);
    let cases = [
        String::new(),
        "ab".repeat(31),
        "ab".repeat(33),
        format!("{}zz", "ab".repeat(31)),
        format!(" {}", "ab".repeat(31)),
        "0x".to_owned() + &"ab".repeat(31),
    ];
    for bad in cases {
        let list = [good.clone(), bad.clone()];
        assert_eq!(
            MerkleBranch::from_esplora(1, 0, &list),
            Err(ProofError::BadBranchHash),
            "{bad:?}"
        );
        assert_eq!(
            MerkleBranch::from_electrum(1, 0, &[bad.as_str()]),
            Err(ProofError::BadBranchHash)
        );
    }
    assert!(MerkleBranch::from_esplora(1, 0, &[good.as_str()]).is_ok());
    assert_eq!(
        MerkleBranch::from_esplora::<&str>(1, 0, &[])
            .unwrap()
            .hashes,
        Vec::new()
    );
}

#[test]
fn a_wrong_output_index_or_script_is_refused() {
    let (coin, branch, chain) = segwit();
    let (data_script, _) = coin.outputs[0].clone();
    let (pays_script, _) = coin.outputs[1].clone();
    let go =
        |vout: u32, script: &ScriptBuf| prove(&coin.raw, coin.txid, vout, script, &branch, &chain);
    assert!(go(1, &pays_script).is_ok());
    // The index of the other output with this one's script, and the reverse.
    assert_eq!(go(0, &pays_script).err(), Some(ProofError::WrongScript));
    assert_eq!(go(1, &data_script).err(), Some(ProofError::WrongScript));
    // An output that does not exist.
    for vout in [2, 3, u32::MAX] {
        assert_eq!(go(vout, &pays_script).err(), Some(ProofError::NoSuchOutput));
    }
    // A script one byte off, one byte short and empty.
    let mut off = pays_script.to_bytes();
    *off.last_mut().unwrap() ^= 1;
    assert_eq!(
        go(1, &ScriptBuf::from_bytes(off)).err(),
        Some(ProofError::WrongScript)
    );
    let short = ScriptBuf::from_bytes(pays_script.to_bytes()[..21].to_vec());
    assert_eq!(go(1, &short).err(), Some(ProofError::WrongScript));
    assert_eq!(
        go(1, &ScriptBuf::new()).err(),
        Some(ProofError::WrongScript)
    );
}

#[test]
fn a_wrong_position_is_refused() {
    let (coin, branch, chain) = segwit();
    let (script, _) = coin.outputs[1].clone();
    let go = |position: u32| {
        let moved = MerkleBranch::new(branch.height, position, branch.hashes.clone());
        prove(&coin.raw, coin.txid, 1, &script, &moved, &chain).err()
    };
    // Neighbours, mirror positions, and each bit of the real one flipped.
    for position in [0, 1, 1499, 1501, 0x5dd ^ 0xfff, 2206, 2207] {
        assert_eq!(go(position), Some(ProofError::RootMismatch), "{position}");
    }
    for bit in 0..12 {
        assert_eq!(
            go(0x5dc ^ (1 << bit)),
            Some(ProofError::RootMismatch),
            "bit {bit}"
        );
    }
    // A position the twelve levels cannot reach names no leaf of the tree.
    for position in [4096, 1500 + 4096, 1 << 20, u32::MAX] {
        assert_eq!(
            go(position),
            Some(ProofError::PositionOutOfRange),
            "{position}"
        );
    }
    assert_eq!(go(1500), None);
}

#[test]
fn a_tampered_swapped_dropped_or_added_hash_is_refused() {
    let (coin, branch, chain) = segwit();
    let (script, _) = coin.outputs[1].clone();
    let go = |hashes: Vec<TxMerkleNode>| {
        let changed = MerkleBranch::new(branch.height, branch.position, hashes);
        prove(&coin.raw, coin.txid, 1, &script, &changed, &chain).err()
    };
    for level in 0..branch.hashes.len() {
        for bit in [0, 7, 100, 255] {
            let mut hashes = branch.hashes.clone();
            let mut bytes = hashes[level].to_byte_array();
            bytes[bit / 8] ^= 1 << (bit % 8);
            hashes[level] = TxMerkleNode::from_byte_array(bytes);
            assert_eq!(
                go(hashes),
                Some(ProofError::RootMismatch),
                "level {level} bit {bit}"
            );
        }
    }
    let mut swapped = branch.hashes.clone();
    swapped.swap(2, 3);
    assert_eq!(go(swapped), Some(ProofError::RootMismatch));
    let mut dropped = branch.hashes.clone();
    dropped.pop();
    assert_eq!(go(dropped), Some(ProofError::RootMismatch));
    let mut dropped_first = branch.hashes.clone();
    dropped_first.remove(0);
    assert_eq!(go(dropped_first), Some(ProofError::RootMismatch));
    let mut added = branch.hashes.clone();
    added.push(branch.hashes[0]);
    assert_eq!(go(added), Some(ProofError::RootMismatch));
    // More hashes than any tree has, however the position is chosen.
    let mut long = branch.hashes.clone();
    long.resize(MAX_BRANCH_LEN + 1, branch.hashes[0]);
    assert_eq!(go(long), Some(ProofError::BranchTooLong));
    let mut longest = branch.hashes.clone();
    longest.resize(MAX_BRANCH_LEN, branch.hashes[0]);
    assert_eq!(go(longest), Some(ProofError::RootMismatch));
    assert_eq!(go(branch.hashes.clone()), None);
}

#[test]
fn a_block_the_chain_has_not_reached_or_the_wrong_block_is_refused() {
    let (coin, branch, chain) = segwit();
    let (script, _) = coin.outputs[1].clone();
    let go = |height: u32| {
        let moved = MerkleBranch::new(height, branch.position, branch.hashes.clone());
        prove(&coin.raw, coin.txid, 1, &script, &moved, &chain).err()
    };
    assert_eq!(go(862_001), Some(ProofError::RootMismatch));
    assert_eq!(go(861_999), Some(ProofError::RootMismatch));
    assert_eq!(go(864_864), Some(ProofError::RootMismatch));
    assert_eq!(go(864_865), Some(ProofError::HeightNotInChain));
    assert_eq!(go(u32::MAX), Some(ProofError::HeightNotInChain));
    // An empty chain proves nothing but a genesis coinbase.
    let genesis_only = HeaderChain::new(Network::Mainnet);
    assert_eq!(
        prove(&coin.raw, coin.txid, 1, &script, &branch, &genesis_only).err(),
        Some(ProofError::HeightNotInChain)
    );
}

#[test]
fn bytes_that_are_not_the_transaction_are_refused_in_order() {
    let (coin, branch, chain) = segwit();
    let (script, _) = coin.outputs[1].clone();
    let other = Txid::from_str(&"cd".repeat(32)).unwrap();
    let go = |bytes: &[u8], txid: Txid| prove(bytes, txid, 1, &script, &branch, &chain).err();
    let whole = coin.raw.clone();

    // Not one whole transaction.
    assert_eq!(go(&[], coin.txid), Some(ProofError::Decode));
    assert_eq!(
        go(&whole[..whole.len() - 1], coin.txid),
        Some(ProofError::Decode)
    );
    assert_eq!(go(&whole[..10], coin.txid), Some(ProofError::Decode));
    assert_eq!(
        go(&[whole.clone(), vec![0]].concat(), coin.txid),
        Some(ProofError::Decode)
    );
    assert_eq!(go(&[0xff; 100], coin.txid), Some(ProofError::Decode));
    // A transaction, but not the one named.
    assert_eq!(go(&whole, other), Some(ProofError::TxidMismatch));
    let coinbase = recorded(COINBASE);
    assert_eq!(go(&coinbase.raw, coin.txid), Some(ProofError::TxidMismatch));
    // The same transaction with one satoshi more in an output is a whole
    // transaction with another id.
    let mut doctored: Transaction = bitcoin::consensus::deserialize(&whole).unwrap();
    doctored.output[1].value += Amount::from_sat(1);
    assert_eq!(
        go(&serialize(&doctored), coin.txid),
        Some(ProofError::TxidMismatch)
    );
    assert_eq!(go(&whole, coin.txid), None);
}

/// A transaction of one input with an empty signature script and one output
/// with a script of `script_len` bytes. Without witnesses it is
/// `60 + script_len` bytes: 64 when the script has four.
fn small_transaction(script_len: usize, witness: bool) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([7; 32]), 3),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: if witness {
                Witness::from_slice(&[[1_u8, 2, 3]])
            } else {
                Witness::new()
            },
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51; script_len]),
        }],
    }
}

/// A regtest chain whose header at height 1 has `root` as its merkle root,
/// mined again so the work is valid.
fn regtest_block_with_root(root: TxMerkleNode) -> HeaderChain {
    let mut block = header(&regtest_rows()[1]);
    block.merkle_root = root;
    grind(&mut block);
    let mut chain = HeaderChain::new(Network::Regtest);
    assert_eq!(chain.absorb(&serialize(&block)), Ok(1));
    chain
}

#[test]
fn a_transaction_of_exactly_sixty_four_bytes_proves_nothing() {
    // The shape of CVE-2012-2459 / the second-preimage trick: two 32-byte
    // merkle nodes side by side hash to their parent exactly as a 64-byte
    // transaction hashes to its id. So the id of this transaction is also the
    // parent of two nodes, and a block whose root is that parent can be made to
    // look as if it contained the transaction, with a branch of no hashes.
    let tx = small_transaction(4, false);
    let bytes = serialize(&tx);
    assert_eq!(bytes.len(), 64);
    let txid = tx.compute_txid();
    let chain = regtest_block_with_root(TxMerkleNode::from(txid));
    let nothing = MerkleBranch::new(1, 0, vec![]);
    // Without the size rule the proof would hold: the fold is the root.
    assert_eq!(
        fold(txid, &nothing),
        chain.header_at(1).unwrap().merkle_root
    );

    let script = ScriptBuf::from_bytes(vec![0x51; 4]);
    for (vout, script) in [(0, &script), (1, &script), (0, &ScriptBuf::new())] {
        assert_eq!(
            prove(&bytes, txid, vout, script, &nothing, &chain).err(),
            Some(ProofError::SixtyFourBytes)
        );
    }
    // Refused before the id is compared: a wrong id does not hide it.
    let other = Txid::from_byte_array([9; 32]);
    assert_eq!(
        prove(&bytes, other, 0, &script, &nothing, &chain).err(),
        Some(ProofError::SixtyFourBytes)
    );
}

#[test]
fn it_is_the_size_without_witnesses_that_counts() {
    // The same transaction with a witness is longer on the wire but is still
    // 64 bytes of what the id hashes.
    let tx = small_transaction(4, true);
    let bytes = serialize(&tx);
    assert!(bytes.len() > 64);
    assert_eq!(tx.base_size(), 64);
    let txid = tx.compute_txid();
    let chain = regtest_block_with_root(TxMerkleNode::from(txid));
    let script = ScriptBuf::from_bytes(vec![0x51; 4]);
    assert_eq!(
        prove(
            &bytes,
            txid,
            0,
            &script,
            &MerkleBranch::new(1, 0, vec![]),
            &chain
        )
        .err(),
        Some(ProofError::SixtyFourBytes)
    );
}

#[test]
fn transactions_one_byte_either_side_of_sixty_four_are_proved() {
    for script_len in [3, 5] {
        let tx = small_transaction(script_len, false);
        let bytes = serialize(&tx);
        assert_eq!(bytes.len(), 60 + script_len);
        let txid = tx.compute_txid();
        let chain = regtest_block_with_root(TxMerkleNode::from(txid));
        let script = ScriptBuf::from_bytes(vec![0x51; script_len]);
        let proven = prove(
            &bytes,
            txid,
            0,
            &script,
            &MerkleBranch::new(1, 0, vec![]),
            &chain,
        )
        .unwrap();
        assert_eq!(proven.confirmations(), 1);
        assert_eq!(proven.amount(), Amount::from_sat(1));
    }
}

#[test]
fn folding_never_fails_whatever_the_branch() {
    let txid = Txid::from_byte_array([5; 32]);
    let node = TxMerkleNode::from_byte_array([6; 32]);
    for depth in [0, 1, 31, 32, 33, 100, 1000] {
        for position in [0, 1, 0x8000_0000, u32::MAX] {
            let branch = MerkleBranch::new(0, position, vec![node; depth]);
            let _ = fold(txid, &branch);
        }
    }
    // Past 32 levels the position has no more bits, so every step is a left one.
    let long = MerkleBranch::new(0, u32::MAX, vec![node; 40]);
    let mut left_only = MerkleBranch::new(0, u32::MAX, vec![node; 32]);
    let at_32 = fold(txid, &left_only);
    left_only.hashes.resize(40, node);
    assert_eq!(fold(txid, &long), fold(txid, &left_only));
    assert_ne!(at_32, fold(txid, &long));
}
