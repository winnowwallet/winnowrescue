//! Discovery against in-memory sources.
//!
//! The proof data is real: the transactions, merkle branches and header ranges
//! recorded under `vectors/bitcoin-mainnet/`. The history is the mock's: which
//! addresses are used, and which coins the server reports for them, is chosen
//! by each test. Rules are held by properties against a model written
//! separately from the engine, not by numbers read off the engine.

#![allow(clippy::too_many_lines)]

use core::str::FromStr;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use bitcoin::block::TxMerkleNode;
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::{
    Address, Amount, BlockHash, FeeRate, OutPoint, ScriptBuf, Txid, WPubkeyHash, bip32::Xpriv,
};
use proptest::prelude::*;

use super::chains::{early_mainnet, modern_mainnet};
use super::import;
use super::plan::{WORDS, independent};
use super::proof::{COINBASE, Recorded, SEGWIT, recorded};
use crate::discover::{MAX_ACCOUNTS, MAX_CANDIDATES, MAX_INDEX, answer};
use crate::{
    Budget, Candidate, CandidateState, Chain, Derivation, DiscoverError, Discovery, HeaderChain,
    HistoryItem, HistorySource, LaneKey, MerkleBranch, Network, Origin, Plan, Position, Progress,
    ProofError, Purpose, Request, Response, ScriptKind, ScriptSource, Session, SourceError,
    Unspent, drive,
};

/// A session and its plan, made once.
struct Fixture {
    session: Session,
    plan: Plan,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let session = import(WORDS, Network::Mainnet).unwrap();
        let plan = Plan::build(&session).unwrap();
        Fixture { session, plan }
    })
}

/// The lane of an account of a purpose: a branch of the plan for accounts 0 to
/// 2, one the engine opens beyond.
fn lane(plan: &Plan, purpose: Purpose, account: u32, chain: Chain) -> LaneKey {
    if account < 3 {
        let at = plan
            .branches()
            .iter()
            .position(|branch| {
                branch.origin == (Origin::Purpose { purpose, account })
                    && branch.chain == Some(chain)
            })
            .unwrap();
        LaneKey::Plan(u32::try_from(at).unwrap())
    } else {
        LaneKey::Account {
            purpose,
            account,
            chain,
        }
    }
}

// ---------------------------------------------------------------------------
// Scripts

/// A script that names its lane and index, so a mock can tell which address it
/// is without a key.
fn synthetic(lane: LaneKey, index: u32) -> ScriptBuf {
    let mut hash = [0_u8; 20];
    match lane {
        LaneKey::Plan(at) => {
            hash[0] = 1;
            hash[1..5].copy_from_slice(&at.to_be_bytes());
        }
        LaneKey::Account {
            purpose,
            account,
            chain,
        } => {
            hash[0] = 2;
            hash[1] = u8::try_from(purpose.number()).unwrap();
            hash[2..6].copy_from_slice(&account.to_be_bytes());
            hash[6] = u8::try_from(chain.number()).unwrap();
        }
    }
    hash[12..16].copy_from_slice(&index.to_be_bytes());
    ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(hash))
}

/// The lane and index a [`synthetic`] script names.
fn unmake(script: &ScriptBuf) -> (LaneKey, u32) {
    let hash = &script.as_bytes()[2..22];
    let index = u32::from_be_bytes(hash[12..16].try_into().unwrap());
    let lane = if hash[0] == 1 {
        LaneKey::Plan(u32::from_be_bytes(hash[1..5].try_into().unwrap()))
    } else {
        let purpose = Purpose::ALL
            .into_iter()
            .find(|p| p.number() == u32::from(hash[1]))
            .unwrap();
        LaneKey::Account {
            purpose,
            account: u32::from_be_bytes(hash[2..6].try_into().unwrap()),
            chain: Chain::ALL[usize::from(hash[6])],
        }
    };
    (lane, index)
}

struct Synthetic;

impl ScriptSource for Synthetic {
    fn script(&self, lane: LaneKey, index: u32) -> Result<ScriptBuf, DiscoverError> {
        Ok(synthetic(lane, index))
    }
}

/// Another source of scripts, except at the addresses a test puts a script of
/// its own.
struct Overlay<'a> {
    base: &'a dyn ScriptSource,
    at: BTreeMap<(LaneKey, u32), ScriptBuf>,
}

impl<'a> Overlay<'a> {
    fn new(base: &'a dyn ScriptSource) -> Self {
        Self {
            base,
            at: BTreeMap::new(),
        }
    }

    fn place(&mut self, lane: LaneKey, index: u32, script: &ScriptBuf) {
        self.at.insert((lane, index), script.clone());
    }
}

impl ScriptSource for Overlay<'_> {
    fn script(&self, lane: LaneKey, index: u32) -> Result<ScriptBuf, DiscoverError> {
        match self.at.get(&(lane, index)) {
            Some(script) => Ok(script.clone()),
            None => self.base.script(lane, index),
        }
    }
}

// ---------------------------------------------------------------------------
// Sources

/// A source with a shelf of recorded answers, keyed by script. It can be made
/// to fail after a number of calls, and counts the calls it gets.
#[derive(Clone)]
struct Shelf {
    genesis: BlockHash,
    history: BTreeMap<ScriptBuf, Vec<HistoryItem>>,
    unspent: BTreeMap<ScriptBuf, Vec<Unspent>>,
    transactions: BTreeMap<Txid, Vec<u8>>,
    merkles: BTreeMap<Txid, MerkleBranch>,
    fail_after: Option<usize>,
    calls: Cell<usize>,
    fetched: Cell<(usize, usize)>,
}

impl Shelf {
    fn new(genesis: BlockHash) -> Self {
        Self {
            genesis,
            history: BTreeMap::new(),
            unspent: BTreeMap::new(),
            transactions: BTreeMap::new(),
            merkles: BTreeMap::new(),
            fail_after: None,
            calls: Cell::new(0),
            fetched: Cell::new((0, 0)),
        }
    }

    /// The server's view of a recorded coin at `script`: the transaction is in
    /// its history, the output is unspent, and it can give the transaction and
    /// the branch.
    fn put(&mut self, script: &ScriptBuf, coin: &Recorded, vout: u32) {
        let amount = coin.outputs[usize::try_from(vout).unwrap()].1;
        self.history
            .entry(script.clone())
            .or_default()
            .push(HistoryItem {
                txid: coin.txid,
                height: Some(coin.height),
            });
        self.unspent
            .entry(script.clone())
            .or_default()
            .push(Unspent {
                txid: coin.txid,
                vout,
                amount,
                height: Some(coin.height),
            });
        self.transactions.insert(coin.txid, coin.raw.clone());
        self.merkles.insert(
            coin.txid,
            MerkleBranch::from_electrum(coin.height, coin.position, &coin.electrum).unwrap(),
        );
    }

    fn tick(&self) -> Result<(), SourceError> {
        self.calls.set(self.calls.get() + 1);
        if self
            .fail_after
            .is_some_and(|limit| self.calls.get() > limit)
        {
            return Err(SourceError::Unavailable);
        }
        Ok(())
    }
}

impl HistorySource for Shelf {
    fn genesis(&self) -> Result<BlockHash, SourceError> {
        self.tick()?;
        Ok(self.genesis)
    }

    fn history(&self, scripts: &[ScriptBuf]) -> Result<Vec<Vec<HistoryItem>>, SourceError> {
        self.tick()?;
        Ok(scripts
            .iter()
            .map(|script| self.history.get(script).cloned().unwrap_or_default())
            .collect())
    }

    fn unspent(&self, scripts: &[ScriptBuf]) -> Result<Vec<Vec<Unspent>>, SourceError> {
        self.tick()?;
        Ok(scripts
            .iter()
            .map(|script| self.unspent.get(script).cloned().unwrap_or_default())
            .collect())
    }

    fn transaction_raw(&self, txid: Txid) -> Result<Vec<u8>, SourceError> {
        self.tick()?;
        self.fetched
            .set((self.fetched.get().0 + 1, self.fetched.get().1));
        self.transactions
            .get(&txid)
            .cloned()
            .ok_or(SourceError::Refused)
    }

    fn merkle(&self, txid: Txid, _height: u32) -> Result<MerkleBranch, SourceError> {
        self.tick()?;
        self.fetched
            .set((self.fetched.get().0, self.fetched.get().1 + 1));
        self.merkles.get(&txid).cloned().ok_or(SourceError::Refused)
    }

    fn fee_estimate(&self, _blocks: u16) -> Result<Option<FeeRate>, SourceError> {
        self.tick()?;
        Ok(None)
    }
}

/// A source whose history is a set of used addresses, and which reports one
/// unspent output (or none) for each. It never has a transaction worth
/// proving; the point is the walk. It remembers the largest answer it gave and
/// the highest index it was asked about.
struct Oracle {
    used: BTreeSet<(LaneKey, u32)>,
    coins: bool,
    genesis: BlockHash,
    largest: Cell<u64>,
    highest: Cell<u32>,
}

impl Oracle {
    fn new(used: BTreeSet<(LaneKey, u32)>, coins: bool) -> Self {
        Self {
            used,
            coins,
            genesis: HeaderChain::new(Network::Mainnet).block_hash_at(0).unwrap(),
            largest: Cell::new(0),
            highest: Cell::new(0),
        }
    }

    fn txid(lane: LaneKey, index: u32) -> Txid {
        let mut bytes = [0_u8; 32];
        bytes[..20].copy_from_slice(&synthetic(lane, index).as_bytes()[2..22]);
        Txid::from_byte_array(bytes)
    }

    fn note(&self, size: u64) {
        self.largest.set(self.largest.get().max(size));
    }
}

impl HistorySource for Oracle {
    fn genesis(&self) -> Result<BlockHash, SourceError> {
        Ok(self.genesis)
    }

    fn history(&self, scripts: &[ScriptBuf]) -> Result<Vec<Vec<HistoryItem>>, SourceError> {
        let answers: Vec<Vec<HistoryItem>> = scripts
            .iter()
            .map(|script| {
                let (lane, index) = unmake(script);
                self.highest.set(self.highest.get().max(index));
                if self.used.contains(&(lane, index)) {
                    vec![HistoryItem {
                        txid: Self::txid(lane, index),
                        height: Some(1),
                    }]
                } else {
                    Vec::new()
                }
            })
            .collect();
        self.note(
            Response::History {
                positions: Vec::new(),
                answers: answers.clone(),
            }
            .size(),
        );
        Ok(answers)
    }

    fn unspent(&self, scripts: &[ScriptBuf]) -> Result<Vec<Vec<Unspent>>, SourceError> {
        let answers: Vec<Vec<Unspent>> = scripts
            .iter()
            .map(|script| {
                let (lane, index) = unmake(script);
                if self.coins && self.used.contains(&(lane, index)) {
                    vec![Unspent {
                        txid: Self::txid(lane, index),
                        vout: 0,
                        amount: Amount::from_sat(1000),
                        height: Some(1),
                    }]
                } else {
                    Vec::new()
                }
            })
            .collect();
        self.note(
            Response::Unspent {
                positions: Vec::new(),
                answers: answers.clone(),
            }
            .size(),
        );
        Ok(answers)
    }

    fn transaction_raw(&self, _txid: Txid) -> Result<Vec<u8>, SourceError> {
        self.note(10);
        Ok(vec![0xAB; 10])
    }

    fn merkle(&self, _txid: Txid, height: u32) -> Result<MerkleBranch, SourceError> {
        self.note(8);
        Ok(MerkleBranch::new(height, 0, Vec::new()))
    }

    fn fee_estimate(&self, _blocks: u16) -> Result<Option<FeeRate>, SourceError> {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Helpers

type Essence = (
    Vec<crate::LaneProgress>,
    Vec<Candidate>,
    Vec<crate::CoinRecord>,
);

/// What a run found, in an order that does not depend on how the requests were
/// batched.
fn essence(progress: &Progress) -> Essence {
    let mut lanes = progress.lanes.clone();
    lanes.sort_by_key(|lane| lane.lane);
    let mut candidates = progress.candidates.clone();
    candidates.sort_by_key(|candidate| (candidate.txid, candidate.vout));
    let mut coins = progress.coins.clone();
    coins.sort_by_key(|coin| (coin.txid, coin.vout));
    (lanes, candidates, coins)
}

fn lane_progress(progress: &Progress, lane: LaneKey) -> &crate::LaneProgress {
    progress
        .lanes
        .iter()
        .find(|saved| saved.lane == lane)
        .unwrap()
}

/// The accounts the engine opened beyond the plan, with their purposes.
fn opened(progress: &Progress) -> BTreeSet<(Purpose, u32)> {
    progress
        .lanes
        .iter()
        .filter_map(|saved| match saved.lane {
            LaneKey::Account {
                purpose, account, ..
            } => Some((purpose, account)),
            LaneKey::Plan(_) => None,
        })
        .collect()
}

fn genesis_of(chain: &HeaderChain) -> BlockHash {
    chain.block_hash_at(0).unwrap()
}

// ---------------------------------------------------------------------------
// Real coins, mock history

/// The recorded coin of block 1 (a coinbase paying a public key) at an address
/// of the first BIP44 account, and the recorded segwit coin of block 862000 at
/// an address of the third BIP84 account.
struct Scene {
    block1: Recorded,
    segwit: Recorded,
    first: (LaneKey, u32),
    second: (LaneKey, u32),
}

fn scene(plan: &Plan) -> Scene {
    Scene {
        block1: recorded(COINBASE),
        segwit: recorded(SEGWIT),
        first: (lane(plan, Purpose::Bip44, 0, Chain::External), 3),
        second: (lane(plan, Purpose::Bip84, 2, Chain::Internal), 4),
    }
}

#[test]
fn two_recorded_coins_are_found_and_proved() {
    let fx = fixture();
    let scene = scene(&fx.plan);
    let real = Derivation::new(&fx.plan, &fx.session).unwrap();
    let mut scripts = Overlay::new(&real);
    scripts.place(scene.first.0, scene.first.1, &scene.block1.outputs[0].0);
    scripts.place(scene.second.0, scene.second.1, &scene.segwit.outputs[1].0);
    let (early, modern) = (early_mainnet(), modern_mainnet());
    let mut shelf = Shelf::new(genesis_of(&early));
    shelf.put(&scene.block1.outputs[0].0, &scene.block1, 0);
    shelf.put(&scene.segwit.outputs[1].0, &scene.segwit, 1);

    let mut discovery = Discovery::new(&fx.plan, Budget::UNLIMITED);
    let first = drive(&mut discovery, &scripts, &shelf, &early).unwrap();
    // Block 1 is in the chain; block 862000 is above its tip and waits.
    assert_eq!(first.coins.len(), 1);
    assert_eq!(first.header_tip, Some(4032));
    assert!(!first.complete);
    let waiting = first
        .candidates
        .iter()
        .find(|candidate| candidate.txid == scene.segwit.txid)
        .unwrap();
    assert_eq!(waiting.state, CandidateState::Candidate);
    // What the waiting coin needs is kept for it, and nothing else.
    assert_eq!(discovery.held(), (1, 1));

    // The longer chain proves the rest.
    let done = discovery.prove_pending(&scripts, &modern).unwrap();
    assert!(done.complete && !done.exhausted);
    assert_eq!(discovery.held(), (0, 0));
    assert_eq!(done.header_tip, Some(864_864));
    assert_eq!(done.candidates.len(), 2);
    assert!(
        done.candidates
            .iter()
            .all(|c| c.state == CandidateState::Proven)
    );

    let coins = discovery.coins();
    assert_eq!(coins.len(), 2);
    let (a, b) = (&coins[0], &coins[1]);
    assert_eq!(a.outpoint(), OutPoint::new(scene.block1.txid, 0));
    assert_eq!(a.amount(), scene.block1.outputs[0].1);
    assert_eq!(a.amount(), Amount::from_sat(5_000_000_000));
    assert_eq!(a.script(), scene.block1.outputs[0].0.as_script());
    assert_eq!((a.height(), a.confirmations()), (1, 4032));
    assert_eq!(a.is_coinbase(), scene.block1.coinbase);
    assert!(a.is_coinbase());
    assert_eq!(b.outpoint(), OutPoint::new(scene.segwit.txid, 1));
    assert_eq!(b.amount(), Amount::from_sat(546));
    assert_eq!(b.script(), scene.segwit.outputs[1].0.as_script());
    assert_eq!((b.height(), b.confirmations()), (862_000, 2865));
    assert_eq!(b.is_coinbase(), scene.segwit.coinbase);
    assert!(!b.is_coinbase());
    // The same two, as plain records.
    assert_eq!(done.coins.len(), 2);
    assert_eq!(done.coins[1].sats, 546);
    assert!(done.coins[0].coinbase && !done.coins[1].coinbase);

    // A used address widened its account, and a used address in the third
    // account opened the two after it, and nothing else was opened.
    let hit = lane_progress(&done, scene.first.0);
    assert_eq!((hit.hits, hit.last_hit, hit.gap), (1, Some(3), 100));
    assert_eq!(hit.next_index, 3 + 1 + 100);
    assert_eq!(hit.pending_unspent, Vec::<u32>::new());
    let sibling = lane(&fx.plan, Purpose::Bip44, 0, Chain::Internal);
    assert_eq!(lane_progress(&done, sibling).gap, 100);
    assert_eq!(lane_progress(&done, sibling).hits, 0);
    let next = lane(&fx.plan, Purpose::Bip44, 1, Chain::External);
    assert_eq!(lane_progress(&done, next).gap, 20);
    assert_eq!(
        opened(&done),
        BTreeSet::from([(Purpose::Bip84, 3), (Purpose::Bip84, 4)])
    );
}

#[test]
fn a_server_that_omits_a_coin_yields_nothing_and_no_error() {
    let fx = fixture();
    let scene = scene(&fx.plan);
    let real = Derivation::new(&fx.plan, &fx.session).unwrap();
    let mut scripts = Overlay::new(&real);
    scripts.place(scene.first.0, scene.first.1, &scene.block1.outputs[0].0);
    let early = early_mainnet();
    let script = &scene.block1.outputs[0].0;

    // It says the address was used and lists nothing unspent: spent out.
    let mut shelf = Shelf::new(genesis_of(&early));
    shelf.put(script, &scene.block1, 0);
    shelf.unspent.clear();
    let mut discovery = Discovery::new(&fx.plan, Budget::UNLIMITED);
    let progress = drive(&mut discovery, &scripts, &shelf, &early).unwrap();
    assert!(progress.complete && progress.stopped.is_none());
    assert!(progress.candidates.is_empty() && progress.coins.is_empty());
    assert_eq!(discovery.coins().len(), 0);
    // The address still counted as used for the gap.
    let hit = lane_progress(&progress, scene.first.0);
    assert_eq!((hit.hits, hit.gap), (1, 100));

    // It says nothing at all about the address.
    let shelf = Shelf::new(genesis_of(&early));
    let mut discovery = Discovery::new(&fx.plan, Budget::UNLIMITED);
    let progress = drive(&mut discovery, &scripts, &shelf, &early).unwrap();
    assert!(progress.complete && progress.candidates.is_empty());
    assert_eq!(lane_progress(&progress, scene.first.0).hits, 0);
}

type ShelfChange = Box<dyn FnOnce(&mut Shelf, &Recorded, &ScriptBuf)>;
type ProgressChange = Box<dyn Fn(&mut Progress)>;

/// The coinbase of block 1 at the first BIP84 address, with the shelf changed
/// by `change`, run against the chain that holds block 1.
fn forged(change: impl FnOnce(&mut Shelf, &Recorded, &ScriptBuf)) -> (Discovery, Progress, Shelf) {
    let fx = fixture();
    let block1 = recorded(COINBASE);
    let lane0 = lane(&fx.plan, Purpose::Bip84, 0, Chain::External);
    let script = block1.outputs[0].0.clone();
    let mut scripts = Overlay::new(&Synthetic);
    scripts.place(lane0, 0, &script);
    let early = early_mainnet();
    let mut shelf = Shelf::new(genesis_of(&early));
    shelf.put(&script, &block1, 0);
    change(&mut shelf, &block1, &script);
    let mut discovery = Discovery::new(&fx.plan, Budget::UNLIMITED);
    let progress = drive(&mut discovery, &scripts, &shelf, &early).unwrap();
    (discovery, progress, shelf)
}

#[test]
fn an_honest_shelf_proves_the_coin() {
    let (discovery, progress, _) = forged(|_, _, _| {});
    assert_eq!(progress.candidates[0].state, CandidateState::Proven);
    assert_eq!(discovery.coins().len(), 1);
}

#[test]
fn a_forged_proof_is_refused_by_name_and_is_no_coin() {
    let wrong_root = MerkleBranch::new(1, 0, vec![TxMerkleNode::from_byte_array([7; 32])]);
    let cases: Vec<(&str, ProofError, ShelfChange)> = vec![
        (
            "a byte of the transaction changed",
            ProofError::TxidMismatch,
            Box::new(|shelf, coin, _| shelf.transactions.get_mut(&coin.txid).unwrap()[10] ^= 1),
        ),
        (
            "bytes that are not a transaction",
            ProofError::Decode,
            Box::new(|shelf, coin, _| {
                shelf.transactions.insert(coin.txid, vec![1, 2, 3]);
            }),
        ),
        (
            "a branch that does not lead to the root",
            ProofError::RootMismatch,
            Box::new(move |shelf, coin, _| {
                shelf.merkles.insert(coin.txid, wrong_root);
            }),
        ),
        (
            "an output the transaction does not have",
            ProofError::NoSuchOutput,
            Box::new(|shelf, _, script| shelf.unspent.get_mut(script).unwrap()[0].vout = 1),
        ),
        (
            "an output that pays some other script",
            ProofError::WrongScript,
            Box::new(|shelf, _, script| {
                // The server reports the coin for an address that is not the
                // one the transaction pays.
                let other = synthetic(LaneKey::Plan(0), 0);
                let history = shelf.history.remove(script).unwrap();
                let unspent = shelf.unspent.remove(script).unwrap();
                shelf.history.insert(other.clone(), history);
                shelf.unspent.insert(other, unspent);
            }),
        ),
        (
            "a block the transaction is not in",
            ProofError::RootMismatch,
            Box::new(|shelf, _, script| shelf.unspent.get_mut(script).unwrap()[0].height = Some(2)),
        ),
    ];
    for (what, reason, change) in cases {
        let (discovery, progress, shelf) = forged(change);
        let refused = progress
            .candidates
            .iter()
            .filter(|candidate| candidate.state == CandidateState::Refused(reason))
            .count();
        assert!(refused >= 1, "{what}: {:?}", progress.candidates);
        assert!(
            progress
                .candidates
                .iter()
                .all(|candidate| matches!(candidate.state, CandidateState::Refused(_))),
            "{what}"
        );
        assert!(
            progress.coins.is_empty() && discovery.coins().is_empty(),
            "{what}"
        );
        assert!(progress.complete && progress.stopped.is_none(), "{what}");
        // Refused once, not asked again and again.
        assert_eq!(shelf.fetched.get().0, 1, "{what}");
    }
}

#[test]
fn an_unconfirmed_output_stays_unconfirmed_and_is_never_proved() {
    let (discovery, progress, shelf) = forged(|shelf, _, script| {
        shelf.unspent.get_mut(script).unwrap()[0].height = None;
    });
    assert_eq!(progress.candidates.len(), 1);
    assert_eq!(progress.candidates[0].state, CandidateState::Unconfirmed);
    assert_eq!(progress.candidates[0].height, None);
    assert!(progress.complete && progress.coins.is_empty() && discovery.coins().is_empty());
    // No transaction and no branch was asked for.
    assert_eq!(shelf.fetched.get(), (0, 0));
}

#[test]
fn the_same_page_twice_does_not_double_count() {
    let fx = fixture();
    let scene = scene(&fx.plan);
    let early = early_mainnet();
    let script = scene.block1.outputs[0].0.clone();
    let mut scripts = Overlay::new(&Synthetic);
    scripts.place(scene.first.0, scene.first.1, &script);
    let mut shelf = Shelf::new(genesis_of(&early));
    shelf.put(&script, &scene.block1, 0);
    // The server lists everything twice.
    let twice = |items: &mut Vec<HistoryItem>| items.push(items[0]);
    shelf.history.values_mut().for_each(twice);
    shelf
        .unspent
        .values_mut()
        .for_each(|items| items.push(items[0]));

    let mut once = Discovery::new(&fx.plan, Budget::UNLIMITED);
    let single = drive(&mut once, &scripts, &shelf, &early).unwrap();
    assert_eq!(single.candidates.len(), 1);
    assert_eq!(single.coins.len(), 1);
    assert_eq!(lane_progress(&single, scene.first.0).hits, 1);

    // The host delivers every answer twice.
    let mut doubled = Discovery::new(&fx.plan, Budget::UNLIMITED);
    loop {
        let requests = doubled.next_requests(&scripts).unwrap();
        if requests.is_empty() {
            break;
        }
        for request in requests {
            let response = answer(&shelf, request).unwrap();
            let first = doubled.absorb(response.clone()).unwrap();
            let again = doubled.absorb(response.clone()).unwrap();
            // The repeat changed nothing but the cost it was counted at.
            assert_eq!(
                Progress {
                    queries: first.queries,
                    bytes: first.bytes,
                    ..again.clone()
                },
                first
            );
            assert_eq!(again.queries, first.queries + response.lookups());
        }
        doubled.prove_pending(&scripts, &early).unwrap();
    }
    let both = doubled.prove_pending(&scripts, &early).unwrap();
    assert_eq!(essence(&both), essence(&single));
}

#[test]
fn a_run_that_loses_its_source_midway_resumes_to_the_same_end() {
    let fx = fixture();
    let early = early_mainnet();
    let block1 = recorded(COINBASE);
    let mut scripts = Overlay::new(&Synthetic);
    let real = lane(&fx.plan, Purpose::Bip44, 1, Chain::Internal);
    scripts.place(real, 7, &block1.outputs[0].0);
    // Besides the real coin, two outputs a server could invent.
    let invented = [
        (lane(&fx.plan, Purpose::Bip49, 0, Chain::External), 2),
        (lane(&fx.plan, Purpose::Bip86, 2, Chain::External), 15),
    ];
    let shelf = || {
        let mut shelf = Shelf::new(genesis_of(&early));
        shelf.put(&block1.outputs[0].0, &block1, 0);
        for (lane, index) in invented {
            let script = synthetic(lane, index);
            let txid = Txid::from_byte_array([u8::try_from(index).unwrap(); 32]);
            shelf.history.insert(
                script.clone(),
                vec![HistoryItem {
                    txid,
                    height: Some(5),
                }],
            );
            shelf.unspent.insert(
                script,
                vec![Unspent {
                    txid,
                    vout: 0,
                    amount: Amount::from_sat(900),
                    height: Some(5),
                }],
            );
            shelf.transactions.insert(txid, vec![9, 9, 9]);
            shelf
                .merkles
                .insert(txid, MerkleBranch::new(5, 0, Vec::new()));
        }
        shelf
    };

    let reference = shelf();
    let mut whole = Discovery::new(&fx.plan, Budget::UNLIMITED);
    let end = drive(&mut whole, &scripts, &reference, &early).unwrap();
    assert!(end.complete);
    assert_eq!(end.coins.len(), 1);
    assert_eq!(end.candidates.len(), 3);
    let calls = reference.calls.get();
    assert!(calls > 10);

    for fail_after in 0..calls {
        let mut broken = shelf();
        broken.fail_after = Some(fail_after);
        let mut discovery = Discovery::new(&fx.plan, Budget::UNLIMITED);
        let stopped = drive(&mut discovery, &scripts, &broken, &early).unwrap();
        assert_eq!(
            stopped.stopped,
            Some(SourceError::Unavailable),
            "{fail_after}"
        );
        assert!(!stopped.complete);

        // Saved as text, read back, continued with a fresh budget.
        let saved = serde_json::to_string(&stopped).unwrap();
        let loaded: Progress = serde_json::from_str(&saved).unwrap();
        assert_eq!(loaded, stopped);
        let mut resumed = Discovery::resume(&loaded, &fx.plan, Budget::UNLIMITED).unwrap();
        let healthy = shelf();
        let finished = drive(&mut resumed, &scripts, &healthy, &early).unwrap();
        assert!(
            finished.complete && finished.stopped.is_none(),
            "{fail_after}"
        );
        assert_eq!(essence(&finished), essence(&end), "{fail_after}");
        assert_eq!(resumed.coins().len(), 1);
    }
}

#[test]
fn a_source_of_another_chain_is_refused_by_name() {
    let fx = fixture();
    let early = early_mainnet();
    let regtest = HeaderChain::new(Network::Regtest);
    let mut discovery = Discovery::new(&fx.plan, Budget::UNLIMITED);

    let strange = Shelf::new(genesis_of(&regtest));
    assert_eq!(
        drive(&mut discovery, &Synthetic, &strange, &early),
        Err(DiscoverError::GenesisMismatch)
    );
    // Nothing was asked of it but its genesis.
    assert_eq!(strange.calls.get(), 1);
    assert!(
        discovery
            .progress()
            .lanes
            .iter()
            .all(|lane| lane.next_index == 0)
    );

    // A header chain of another network than the plan's.
    let shelf = Shelf::new(genesis_of(&regtest));
    assert_eq!(
        drive(&mut discovery, &Synthetic, &shelf, &regtest),
        Err(DiscoverError::WrongNetwork)
    );
    assert_eq!(shelf.calls.get(), 0);
    assert_eq!(
        discovery.prove_pending(&Synthetic, &regtest),
        Err(DiscoverError::WrongNetwork)
    );

    // A server that cannot even say its genesis ends the run, with the progress.
    let mut dead = Shelf::new(genesis_of(&early));
    dead.fail_after = Some(0);
    let progress = drive(&mut discovery, &Synthetic, &dead, &early).unwrap();
    assert_eq!(progress.stopped, Some(SourceError::Unavailable));
    assert!(!progress.complete && !progress.exhausted);
}

// ---------------------------------------------------------------------------
// Resume

/// A saved run with some of everything in it: a proven coin, a refused one, an
/// unconfirmed one, an opened account and a pending address.
fn saved_run() -> Progress {
    let fx = fixture();
    let block1 = recorded(COINBASE);
    let early = early_mainnet();
    let mut scripts = Overlay::new(&Synthetic);
    let (a, b, c) = (
        lane(&fx.plan, Purpose::Bip84, 2, Chain::External),
        lane(&fx.plan, Purpose::Bip44, 0, Chain::External),
        lane(&fx.plan, Purpose::Bip49, 0, Chain::External),
    );
    scripts.place(b, 1, &block1.outputs[0].0);
    let mut shelf = Shelf::new(genesis_of(&early));
    shelf.put(&block1.outputs[0].0, &block1, 0);
    for (lane, index, height, tx) in [(a, 0, Some(5), 1_u8), (c, 4, None, 2)] {
        let script = synthetic(lane, index);
        let txid = Txid::from_byte_array([tx; 32]);
        shelf
            .history
            .insert(script.clone(), vec![HistoryItem { txid, height }]);
        shelf.unspent.insert(
            script,
            vec![Unspent {
                txid,
                vout: 0,
                amount: Amount::from_sat(700),
                height,
            }],
        );
        shelf.transactions.insert(txid, vec![5, 5]);
        shelf
            .merkles
            .insert(txid, MerkleBranch::new(5, 0, Vec::new()));
    }
    let mut discovery = Discovery::new(&fx.plan, Budget::UNLIMITED);
    drive(&mut discovery, &scripts, &shelf, &early).unwrap()
}

#[test]
fn a_saved_run_is_continued_and_its_coins_must_be_proved_again() {
    let fx = fixture();
    let progress = saved_run();
    let states: Vec<CandidateState> = progress.candidates.iter().map(|c| c.state).collect();
    assert!(states.contains(&CandidateState::Proven));
    assert!(states.contains(&CandidateState::Unconfirmed));
    assert!(states.contains(&CandidateState::Refused(ProofError::Decode)));
    assert!(!opened(&progress).is_empty());
    assert_eq!(progress.coins.len(), 1);

    let resumed = Discovery::resume(&progress, &fx.plan, Budget::UNLIMITED).unwrap();
    let again = resumed.progress();
    // Where the walk stood is kept; the counters, the tip and the stop start again.
    assert_eq!(again.lanes, progress.lanes);
    assert_eq!((again.queries, again.bytes, again.header_tip), (0, 0, None));
    assert!(resumed.coins().is_empty() && again.coins.is_empty());
    for (before, after) in progress.candidates.iter().zip(&again.candidates) {
        let expected = match before.state {
            CandidateState::Proven => CandidateState::Candidate,
            other => other,
        };
        assert_eq!(after.state, expected);
        assert_eq!(
            (after.txid, after.vout, after.sats),
            (before.txid, before.vout, before.sats)
        );
    }
    // A coin that must be proved again is something to ask for.
    assert!(!again.complete);
    let requests = resumed.next_requests(&Synthetic).unwrap();
    assert!(matches!(requests[0], Request::Transaction { .. }));
}

#[test]
fn a_saved_run_for_other_keys_or_another_network_is_refused_by_name() {
    let fx = fixture();
    let progress = saved_run();
    let other = import(
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        Network::Mainnet,
    )
    .unwrap();
    let other_plan = Plan::build(&other).unwrap();
    assert!(matches!(
        Discovery::resume(&progress, &other_plan, Budget::UNLIMITED),
        Err(DiscoverError::WrongPlan)
    ));
    let signet = Plan::build(&import(WORDS, Network::Signet).unwrap()).unwrap();
    assert!(matches!(
        Discovery::resume(&progress, &signet, Budget::UNLIMITED),
        Err(DiscoverError::WrongNetwork)
    ));
    // The same keys with the same tier-1 branches but a typed path added later
    // are the same plan, and a lane saved for the typed path no longer fits.
    let mut with_path = Plan::build(&fx.session).unwrap();
    with_path
        .add_typed(
            &fx.session,
            &crate::parse_path("m/44'/0'/9'").unwrap(),
            ScriptKind::P2wpkh,
        )
        .unwrap();
    let typed_run = Discovery::new(&with_path, Budget::UNLIMITED).progress();
    let plain = Discovery::resume(&typed_run, &fx.plan, Budget::UNLIMITED);
    assert!(matches!(plain, Err(DiscoverError::BadProgress)));
    // And a plan with a typed path takes a run saved without one.
    let before_typing = Discovery::new(&fx.plan, Budget::UNLIMITED).progress();
    let widened = Discovery::resume(&before_typing, &with_path, Budget::UNLIMITED).unwrap();
    assert_eq!(widened.progress().lanes.len(), with_path.branches().len());
    // A lane of a typed path is tied to its own path, not to its place.
    let mut other_path = Plan::build(&fx.session).unwrap();
    other_path
        .add_typed(
            &fx.session,
            &crate::parse_path("m/44'/0'/8'").unwrap(),
            ScriptKind::P2wpkh,
        )
        .unwrap();
    assert!(matches!(
        Discovery::resume(&typed_run, &other_path, Budget::UNLIMITED),
        Err(DiscoverError::BadProgress)
    ));
}

#[test]
fn a_saved_run_no_walk_could_have_made_is_refused() {
    let fx = fixture();
    let good = saved_run();
    let at = |progress: &Progress, key: LaneKey| {
        progress
            .lanes
            .iter()
            .position(|saved| saved.lane == key)
            .unwrap()
    };
    // The first lane is a BIP44 lane with a coin at address 1.
    let bend = |f: fn(&mut crate::LaneProgress)| -> ProgressChange {
        Box::new(move |progress: &mut Progress| f(&mut progress.lanes[0]))
    };
    let opened_lane = |account| -> ProgressChange {
        Box::new(move |progress: &mut Progress| {
            progress.lanes.push(crate::LaneProgress {
                lane: LaneKey::Account {
                    purpose: Purpose::Bip44,
                    account,
                    chain: Chain::External,
                },
                first_script: None,
                next_index: 0,
                gap: 20,
                hits: 0,
                last_hit: None,
                pending_unspent: Vec::new(),
            });
        })
    };
    assert_eq!(good.lanes[0].lane, LaneKey::Plan(0));
    assert_eq!(good.lanes[0].last_hit, Some(1));
    let changes: Vec<(&str, ProgressChange)> = vec![
        (
            "a lane twice",
            Box::new(|p: &mut Progress| p.lanes.push(p.lanes[0].clone())),
        ),
        (
            "a lane the plan does not have",
            Box::new(|p: &mut Progress| p.lanes[0].lane = LaneKey::Plan(5000)),
        ),
        (
            "a first script that is not the plan's",
            bend(|l| l.first_script = None),
        ),
        ("an opened lane of a first account", opened_lane(2)),
        ("an account past the cap", opened_lane(100)),
        (
            "an index past the cap",
            bend(|l| l.next_index = MAX_INDEX + 1),
        ),
        ("a gap past the widest", bend(|l| l.gap = 1001)),
        (
            "more hits than addresses asked",
            bend(|l| l.hits = l.next_index + 1),
        ),
        ("a last hit with no hit", bend(|l| l.hits = 0)),
        (
            "a last hit past the next index",
            bend(|l| l.last_hit = Some(l.next_index)),
        ),
        (
            "pending addresses out of order",
            bend(|l| {
                l.hits = 2;
                l.last_hit = Some(20);
                l.pending_unspent = vec![9, 3];
            }),
        ),
        (
            "pending addresses past the last hit",
            bend(|l| l.pending_unspent = vec![l.last_hit.unwrap() + 1]),
        ),
        (
            "a coin for no lane",
            Box::new(|p: &mut Progress| p.candidates[0].lane = LaneKey::Plan(5000)),
        ),
        (
            "a coin at an address not yet asked about",
            Box::new(move |p: &mut Progress| {
                let i = at(p, p.candidates[0].lane);
                p.candidates[0].index = p.lanes[i].next_index;
            }),
        ),
        (
            "a coin twice",
            Box::new(|p: &mut Progress| p.candidates.push(p.candidates[0].clone())),
        ),
        (
            "more money than exists",
            Box::new(|p: &mut Progress| p.candidates[0].sats = 21_000_000 * 100_000_000 + 1),
        ),
    ];
    for (what, change) in changes {
        let mut bad = good.clone();
        change(&mut bad);
        assert!(
            matches!(
                Discovery::resume(&bad, &fx.plan, Budget::UNLIMITED),
                Err(DiscoverError::BadProgress)
            ),
            "{what}"
        );
    }
    // The unaltered file is fine.
    assert!(Discovery::resume(&good, &fx.plan, Budget::UNLIMITED).is_ok());

    // A coin saved with a block, as unconfirmed, is read as the block says.
    let mut odd = good.clone();
    odd.candidates[0].state = CandidateState::Unconfirmed;
    odd.candidates[0].height = Some(7);
    let resumed = Discovery::resume(&odd, &fx.plan, Budget::UNLIMITED).unwrap();
    assert_eq!(
        resumed.progress().candidates[0].state,
        CandidateState::Candidate
    );
}

#[test]
fn a_saved_run_holds_nothing_secret() {
    let fx = fixture();
    let mnemonic = bip39::Mnemonic::parse_normalized(WORDS).unwrap();
    let seed = mnemonic.to_seed("");
    let master = Xpriv::new_master(bitcoin::Network::Bitcoin, &seed).unwrap();
    let secrets = [
        WORDS.to_owned(),
        "abandon abandon".to_owned(),
        seed.as_hex().to_string(),
        master.to_string(),
        master.private_key.display_secret().to_string(),
    ];
    // A run over the real derivation, with used addresses, so the JSON has
    // lanes, hits and an opened account in it.
    let real = Derivation::new(&fx.plan, &fx.session).unwrap();
    let early = early_mainnet();
    let mut shelf = Shelf::new(genesis_of(&early));
    for path in ["m/84'/0'/2'/0/2", "m/84'/0'/0'/1/0"] {
        let address = independent(WORDS, bitcoin::Network::Bitcoin, path, ScriptKind::P2wpkh);
        let script = Address::from_str(&address)
            .unwrap()
            .assume_checked()
            .script_pubkey();
        shelf.history.insert(
            script,
            vec![HistoryItem {
                txid: Txid::from_byte_array([3; 32]),
                height: Some(10),
            }],
        );
    }
    let mut discovery = Discovery::new(&fx.plan, Budget::UNLIMITED);
    let progress = drive(&mut discovery, &real, &shelf, &early).unwrap();
    assert!(progress.complete);

    // Found where the independent derivation says, and the account after the
    // used one was opened.
    assert_eq!(
        lane_progress(
            &progress,
            lane(&fx.plan, Purpose::Bip84, 2, Chain::External)
        )
        .last_hit,
        Some(2)
    );
    assert_eq!(
        lane_progress(
            &progress,
            lane(&fx.plan, Purpose::Bip84, 0, Chain::Internal)
        )
        .last_hit,
        Some(0)
    );
    assert_eq!(
        opened(&progress),
        BTreeSet::from([(Purpose::Bip84, 3), (Purpose::Bip84, 4)])
    );

    let text = serde_json::to_string(&progress).unwrap();
    assert!(text.len() > 1000);
    for secret in &secrets {
        assert!(!text.contains(secret), "the saved run holds a secret");
    }
    // What it does hold is public: the fingerprint, in hex.
    assert!(text.contains(&fx.plan.fingerprint().to_string()));
    let debug = format!("{progress:?} {discovery:?}");
    for secret in &secrets {
        assert!(!debug.contains(secret));
    }
}

// ---------------------------------------------------------------------------
// The derivation

#[test]
fn scripts_come_from_the_session_along_the_paths_the_plan_names() {
    let fx = fixture();
    let real = Derivation::new(&fx.plan, &fx.session).unwrap();
    let cases = [
        (
            lane(&fx.plan, Purpose::Bip84, 0, Chain::External),
            5,
            "m/84'/0'/0'/0/5",
            ScriptKind::P2wpkh,
        ),
        (
            lane(&fx.plan, Purpose::Bip44, 2, Chain::Internal),
            0,
            "m/44'/0'/2'/1/0",
            ScriptKind::TREE_P2PKH,
        ),
        (
            lane(&fx.plan, Purpose::Bip49, 1, Chain::External),
            19,
            "m/49'/0'/1'/0/19",
            ScriptKind::P2shP2wpkh,
        ),
        // Accounts the plan does not list, derived from the same root.
        (
            lane(&fx.plan, Purpose::Bip84, 7, Chain::Internal),
            9,
            "m/84'/0'/7'/1/9",
            ScriptKind::P2wpkh,
        ),
        (
            lane(&fx.plan, Purpose::Bip86, 99, Chain::External),
            0,
            "m/86'/0'/99'/0/0",
            ScriptKind::P2tr,
        ),
        (
            lane(&fx.plan, Purpose::Bip44, 3, Chain::External),
            1000,
            "m/44'/0'/3'/0/1000",
            ScriptKind::TREE_P2PKH,
        ),
    ];
    for (key, index, path, kind) in cases {
        let address = independent(WORDS, bitcoin::Network::Bitcoin, path, kind);
        let expected = Address::from_str(&address)
            .unwrap()
            .assume_checked()
            .script_pubkey();
        assert_eq!(real.script(key, index).unwrap(), expected, "{path}");
    }
    // A lane of the plan is the plan's own branch.
    assert_eq!(
        real.script(LaneKey::Plan(0), 0).unwrap(),
        fx.plan.branches()[0].first_address.script_pubkey()
    );
    assert!(real.script(LaneKey::Plan(5000), 0).is_err());
    // An index that is not a child number cannot be derived.
    assert!(real.script(LaneKey::Plan(0), u32::MAX).is_err());
}

#[test]
fn a_plan_is_only_paired_with_the_session_it_was_built_from() {
    let fx = fixture();
    let other = import(
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        Network::Mainnet,
    )
    .unwrap();
    assert!(matches!(
        Derivation::new(&fx.plan, &other),
        Err(DiscoverError::WrongSession)
    ));
    let signet = import(WORDS, Network::Signet).unwrap();
    assert!(matches!(
        Derivation::new(&fx.plan, &signet),
        Err(DiscoverError::WrongSession)
    ));
    assert!(Derivation::new(&fx.plan, &fx.session).is_ok());
}

#[test]
fn a_single_key_is_asked_about_once_for_each_kind() {
    let session = import(
        "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
        Network::Mainnet,
    )
    .unwrap();
    let plan = Plan::build(&session).unwrap();
    assert_eq!(plan.branches().len(), 4);
    let real = Derivation::new(&plan, &session).unwrap();
    let mut discovery = Discovery::new(&plan, Budget::UNLIMITED);
    let requests = discovery.next_requests(&real).unwrap();
    assert_eq!(requests.len(), 1);
    let Request::History { positions, scripts } = &requests[0] else {
        panic!("a history request is first");
    };
    assert_eq!(positions.len(), 4);
    for (at, branch) in plan.branches().iter().enumerate() {
        assert_eq!(positions[at].index, 0);
        assert_eq!(scripts[at], branch.first_address.script_pubkey());
    }

    // Its P2WPKH address was used, once. A key has no tree: no more addresses.
    let shelf = {
        let early = early_mainnet();
        let mut shelf = Shelf::new(genesis_of(&early));
        shelf.history.insert(
            scripts[2].clone(),
            vec![HistoryItem {
                txid: Txid::from_byte_array([4; 32]),
                height: Some(3),
            }],
        );
        shelf
    };
    let progress = drive(&mut discovery, &real, &shelf, &early_mainnet()).unwrap();
    assert!(progress.complete);
    assert!(
        progress
            .lanes
            .iter()
            .all(|saved| saved.next_index == 1 && saved.gap == plan.branches()[0].gap)
    );
    assert_eq!(
        progress.lanes.iter().map(|saved| saved.hits).sum::<u32>(),
        1
    );
    assert_eq!(shelf.calls.get(), 3); // genesis, history, unspent
}

// ---------------------------------------------------------------------------
// Requests, answers, budgets

#[test]
fn the_first_requests_are_tier_one_in_batches_of_a_hundred() {
    let fx = fixture();
    let discovery = Discovery::new(&fx.plan, Budget::UNLIMITED);
    let requests = discovery.next_requests(&Synthetic).unwrap();
    // 24 tier-1 and 12 tier-2 lanes, 20 addresses each.
    let sizes: Vec<usize> = requests
        .iter()
        .map(|request| match request {
            Request::History { positions, scripts } => {
                assert_eq!(positions.len(), scripts.len());
                scripts.len()
            }
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(sizes, vec![100, 100, 100, 100, 100, 100, 100, 20]);
    assert_eq!(sizes.iter().sum::<usize>(), 36 * 20);
    // The positions are the plan's lanes in order, tier 1 first.
    let flat: Vec<Position> = requests
        .iter()
        .flat_map(|request| match request {
            Request::History { positions, .. } => positions.clone(),
            _ => Vec::new(),
        })
        .collect();
    for (n, position) in flat.iter().enumerate() {
        assert_eq!(position.lane, LaneKey::Plan(u32::try_from(n / 20).unwrap()));
        assert_eq!(position.index, u32::try_from(n % 20).unwrap());
    }
    assert!(requests.iter().all(|request| request.lookups() <= 100));
    // Asking again gives the same.
    assert_eq!(discovery.next_requests(&Synthetic).unwrap(), requests);
}

#[test]
fn an_account_opened_later_is_still_asked_about_before_tier_two() {
    let fx = fixture();
    let mut discovery = Discovery::new(&fx.plan, Budget::UNLIMITED);
    let hit = lane(&fx.plan, Purpose::Bip84, 2, Chain::External);
    discovery
        .absorb(Response::History {
            positions: vec![Position {
                lane: hit,
                index: 0,
            }],
            answers: vec![vec![HistoryItem {
                txid: Txid::from_byte_array([6; 32]),
                height: Some(2),
            }]],
        })
        .unwrap();
    let asked: Vec<LaneKey> = discovery
        .next_requests(&Synthetic)
        .unwrap()
        .iter()
        .flat_map(|request| match request {
            Request::History { positions, .. } | Request::Unspent { positions, .. } => {
                positions.iter().map(|position| position.lane).collect()
            }
            _ => Vec::new(),
        })
        .collect();
    let tier_two = asked
        .iter()
        .position(|lane| matches!(lane, LaneKey::Plan(at) if *at >= 24))
        .unwrap();
    let opened = asked
        .iter()
        .rposition(|lane| matches!(lane, LaneKey::Account { .. }))
        .unwrap();
    assert!(opened < tier_two);
}

#[test]
fn what_an_answer_costs_is_counted_by_a_rule_written_down() {
    let item = HistoryItem {
        txid: Txid::from_byte_array([1; 32]),
        height: Some(1),
    };
    let coin = Unspent {
        txid: Txid::from_byte_array([1; 32]),
        vout: 0,
        amount: Amount::from_sat(1),
        height: None,
    };
    let history = Response::History {
        positions: Vec::new(),
        answers: vec![vec![item, item], Vec::new(), vec![item]],
    };
    assert_eq!((history.lookups(), history.size()), (3, 3 * 8 + 3 * 36));
    let unspent = Response::Unspent {
        positions: Vec::new(),
        answers: vec![vec![coin], Vec::new()],
    };
    assert_eq!((unspent.lookups(), unspent.size()), (2, 2 * 8 + 48));
    let transaction = Response::Transaction {
        txid: item.txid,
        raw: vec![0; 250],
    };
    assert_eq!((transaction.lookups(), transaction.size()), (1, 250));
    let merkle = Response::Merkle {
        txid: item.txid,
        height: 1,
        branch: MerkleBranch::new(1, 0, vec![TxMerkleNode::from_byte_array([0; 32]); 3]),
    };
    assert_eq!((merkle.lookups(), merkle.size()), (1, 8 + 3 * 32));
}

#[test]
fn an_answer_that_is_not_for_anything_asked_is_refused_and_changes_nothing() {
    let fx = fixture();
    let mut discovery = Discovery::new(&fx.plan, Budget::UNLIMITED);
    let lane0 = LaneKey::Plan(0);
    let position = |lane, index| Position { lane, index };
    let used = || {
        vec![HistoryItem {
            txid: Txid::from_byte_array([8; 32]),
            height: Some(1),
        }]
    };
    // One address of the first lane is used, so that it has a coin to ask for.
    discovery
        .absorb(Response::History {
            positions: vec![position(lane0, 0)],
            answers: vec![used()],
        })
        .unwrap();
    let before = discovery.progress();

    let coin = |n: u32| Unspent {
        txid: Txid::from_byte_array([9; 32]),
        vout: n,
        amount: Amount::from_sat(1),
        height: Some(1),
    };
    let too_many = (0..=u32::try_from(MAX_CANDIDATES).unwrap())
        .map(coin)
        .collect();
    let bad = [
        (
            Response::History {
                positions: vec![position(lane0, 1)],
                answers: Vec::new(),
            },
            DiscoverError::AnswerShape,
        ),
        (
            Response::History {
                positions: vec![position(LaneKey::Plan(999), 0)],
                answers: vec![Vec::new()],
            },
            DiscoverError::UnexpectedAnswer,
        ),
        (
            // Not the next address of the lane.
            Response::History {
                positions: vec![position(lane0, 5)],
                answers: vec![Vec::new()],
            },
            DiscoverError::UnexpectedAnswer,
        ),
        (
            // Past the end of the lane's window.
            Response::History {
                positions: (1..=MAX_INDEX)
                    .map(|index| position(lane0, index))
                    .collect(),
                answers: vec![Vec::new(); usize::try_from(MAX_INDEX).unwrap()],
            },
            DiscoverError::UnexpectedAnswer,
        ),
        (
            // An account the engine has not opened.
            Response::History {
                positions: vec![position(
                    LaneKey::Account {
                        purpose: Purpose::Bip44,
                        account: 3,
                        chain: Chain::External,
                    },
                    0,
                )],
                answers: vec![Vec::new()],
            },
            DiscoverError::UnexpectedAnswer,
        ),
        (
            Response::Unspent {
                positions: vec![position(lane0, 0)],
                answers: Vec::new(),
            },
            DiscoverError::AnswerShape,
        ),
        (
            // An address never asked about.
            Response::Unspent {
                positions: vec![position(lane0, 7)],
                answers: vec![vec![coin(0)]],
            },
            DiscoverError::UnexpectedAnswer,
        ),
        (
            Response::Unspent {
                positions: vec![position(lane0, 0)],
                answers: vec![too_many],
            },
            DiscoverError::TooManyCoins,
        ),
    ];
    for (response, expected) in bad {
        assert_eq!(discovery.absorb(response), Err(expected));
        assert_eq!(discovery.progress(), before);
    }

    // Answers to things not asked for are not errors; they cost what they cost
    // and are not kept.
    let stray = Response::Transaction {
        txid: Txid::from_byte_array([1; 32]),
        raw: vec![0; 17],
    };
    let after = discovery.absorb(stray).unwrap();
    assert_eq!(
        (after.queries, after.bytes),
        (before.queries + 1, before.bytes + 17)
    );
    assert_eq!(
        Progress {
            queries: before.queries,
            bytes: before.bytes,
            ..after
        },
        before
    );
}

#[test]
fn a_run_that_runs_out_of_budget_says_so_and_goes_on_with_a_fresh_one() {
    let fx = fixture();
    let early = early_mainnet();
    let used: BTreeSet<_> = [
        (lane(&fx.plan, Purpose::Bip84, 0, Chain::External), 3),
        (lane(&fx.plan, Purpose::Bip49, 2, Chain::Internal), 11),
    ]
    .into();
    let oracle = Oracle::new(used.clone(), true);
    let mut whole = Discovery::new(&fx.plan, Budget::UNLIMITED);
    let end = drive(&mut whole, &Synthetic, &oracle, &early).unwrap();
    assert!(end.complete && !end.exhausted);
    assert_eq!(end.candidates.len(), 2);

    let mut discovery = Discovery::new(
        &fx.plan,
        Budget {
            max_queries: 150,
            max_bytes: u64::MAX,
        },
    );
    let first = drive(&mut discovery, &Synthetic, &oracle, &early).unwrap();
    assert!(first.exhausted && !first.complete);
    assert_eq!(first.queries, 150);
    assert_eq!(discovery.next_requests(&Synthetic).unwrap(), Vec::new());
    // The same call again asks for nothing and spends nothing.
    let again = drive(&mut discovery, &Synthetic, &oracle, &early).unwrap();
    assert_eq!(again, first);

    // A fresh budget goes on from there, and the end is the same.
    let mut rounds = 0;
    let mut last = first;
    while !last.complete {
        discovery.renew_budget(Budget {
            max_queries: 150,
            max_bytes: u64::MAX,
        });
        last = drive(&mut discovery, &Synthetic, &oracle, &early).unwrap();
        assert!(last.queries <= 150);
        rounds += 1;
        assert!(rounds < 100);
    }
    assert_eq!(essence(&last), essence(&end));

    // A budget of no bytes spends nothing either.
    let mut none = Discovery::new(
        &fx.plan,
        Budget {
            max_queries: 1000,
            max_bytes: 0,
        },
    );
    let stopped = drive(&mut none, &Synthetic, &oracle, &early).unwrap();
    assert!(stopped.exhausted);
    assert_eq!((stopped.queries, stopped.bytes), (0, 0));
}

// ---------------------------------------------------------------------------
// The caps

#[test]
fn the_numbers_of_the_walk_are_the_ones_the_design_gives() {
    // Tier 1 asks 20 addresses, a used address widens its account to 100, a
    // search further to 1,000; at most 100 accounts of a purpose; 100 scripts
    // to a request. The index cap and the coin cap are this crate's own.
    assert_eq!(crate::paths::GAP, 20);
    assert_eq!(crate::paths::TIER_ONE_ACCOUNTS, 3);
    assert_eq!(crate::discover::WIDE_GAP, 100);
    assert_eq!(crate::discover::FURTHER_GAP, 1_000);
    assert_eq!(MAX_ACCOUNTS, 100);
    assert_eq!(crate::discover::MAX_BATCH, 100);
    assert_eq!(MAX_INDEX, 10_000);
    assert_eq!(MAX_CANDIDATES, 10_000);
}

#[test]
fn accounts_stop_at_the_cap_whatever_the_server_says() {
    let fx = fixture();
    // Index 0 of both chains of every account of every purpose is used.
    let mut used = BTreeSet::new();
    for purpose in Purpose::ALL {
        for account in 0..110 {
            for chain in Chain::ALL {
                used.insert((lane(&fx.plan, purpose, account, chain), 0));
            }
        }
    }
    let oracle = Oracle::new(used, false);
    let mut discovery = Discovery::new(&fx.plan, Budget::UNLIMITED);
    let progress = drive(
        &mut discovery,
        &Synthetic,
        &oracle,
        &HeaderChain::new(Network::Mainnet),
    )
    .unwrap();
    assert!(progress.complete);
    let accounts = opened(&progress);
    for purpose in Purpose::ALL {
        let numbers: Vec<u32> = accounts
            .iter()
            .filter(|(p, _)| *p == purpose)
            .map(|(_, account)| *account)
            .collect();
        assert_eq!(numbers, (3..100).collect::<Vec<_>>());
    }
    let longest = progress
        .lanes
        .iter()
        .map(|saved| saved.next_index)
        .max()
        .unwrap();
    assert_eq!(longest, 1 + 100);
}

#[test]
fn no_lane_is_walked_past_the_index_cap() {
    let fx = fixture();
    let first = lane(&fx.plan, Purpose::Bip44, 0, Chain::External);
    let used = (0..2 * MAX_INDEX).map(|index| (first, index)).collect();
    let oracle = Oracle::new(used, false);
    let mut discovery = Discovery::new(&fx.plan, Budget::UNLIMITED);
    let progress = drive(
        &mut discovery,
        &Synthetic,
        &oracle,
        &HeaderChain::new(Network::Mainnet),
    )
    .unwrap();
    assert!(progress.complete);
    let walked = lane_progress(&progress, first);
    assert_eq!((walked.next_index, walked.hits), (MAX_INDEX, MAX_INDEX));
    assert_eq!(walked.last_hit, Some(MAX_INDEX - 1));
    assert_eq!(oracle.highest.get(), MAX_INDEX - 1);
}

#[test]
fn searching_further_reaches_an_address_the_widened_gap_missed() {
    let fx = fixture();
    let main = lane(&fx.plan, Purpose::Bip84, 0, Chain::External);
    let used = BTreeSet::from([(main, 5), (main, 999)]);
    let oracle = Oracle::new(used, false);
    let chain = HeaderChain::new(Network::Mainnet);
    let mut discovery = Discovery::new(&fx.plan, Budget::UNLIMITED);
    let first = drive(&mut discovery, &Synthetic, &oracle, &chain).unwrap();
    // 5 + 1 + 100: the address at 999 was out of reach.
    let reached = lane_progress(&first, main);
    assert_eq!(
        (reached.hits, reached.last_hit, reached.next_index),
        (1, Some(5), 106)
    );
    assert!(first.complete);

    discovery.search_further();
    let reopened = discovery.progress();
    assert!(!reopened.complete);
    // Only a lane with a used address was raised.
    assert_eq!(lane_progress(&reopened, main).gap, 1000);
    let change = lane(&fx.plan, Purpose::Bip84, 0, Chain::Internal);
    assert_eq!(lane_progress(&reopened, change).gap, 100);
    let elsewhere = lane(&fx.plan, Purpose::Bip44, 0, Chain::External);
    assert_eq!(lane_progress(&reopened, elsewhere).gap, 20);

    let further = drive(&mut discovery, &Synthetic, &oracle, &chain).unwrap();
    let found = lane_progress(&further, main);
    assert_eq!((found.hits, found.last_hit), (2, Some(999)));
    assert_eq!(found.next_index, 999 + 1 + 1000);
    assert!(further.complete);
}

// ---------------------------------------------------------------------------
// Properties

/// A lane of the universe the properties draw from: the 36 lanes of the plan,
/// then eight accounts beyond the plan for each purpose.
fn universe(n: usize) -> LaneKey {
    let plan = &fixture().plan;
    if n < plan.branches().len() {
        return LaneKey::Plan(u32::try_from(n).unwrap());
    }
    let m = n - plan.branches().len();
    LaneKey::Account {
        purpose: Purpose::ALL[(m / 16) % 4],
        account: 3 + u32::try_from((m / 2) % 8).unwrap(),
        chain: Chain::ALL[m % 2],
    }
}

fn used_sets() -> impl Strategy<Value = BTreeSet<(LaneKey, u32)>> {
    let key = (0_usize..100).prop_map(universe);
    let index = prop_oneof![0_u32..25, 0_u32..250, 0_u32..1200];
    prop::collection::btree_set((key, index), 0..40)
}

/// Which addresses a complete walk finds, worked out as the fixed point of the
/// rules and not by walking: the gap of a lane is 100 when any lane of its
/// account has a used address and 20 otherwise, a lane is looked at up to its
/// last used address plus one plus the gap, and an account after the third is
/// opened when one of the two before it has a used address.
fn model(plan: &Plan, used: &BTreeSet<(LaneKey, u32)>) -> BTreeMap<LaneKey, BTreeSet<u32>> {
    let group_of = |key: LaneKey| -> String {
        match key {
            LaneKey::Plan(at) => match &plan.branches()[usize::try_from(at).unwrap()].origin {
                Origin::Purpose { purpose, account } => format!("{purpose:?} {account}"),
                other => format!("{other:?}"),
            },
            LaneKey::Account {
                purpose, account, ..
            } => format!("{purpose:?} {account}"),
        }
    };
    let mut found: BTreeMap<LaneKey, BTreeSet<u32>> = BTreeMap::new();
    let mut accounts: BTreeSet<(Purpose, u32)> = BTreeSet::new();
    loop {
        let before = (found.clone(), accounts.clone());
        let mut lanes: Vec<LaneKey> = (0..plan.branches().len())
            .map(|at| LaneKey::Plan(u32::try_from(at).unwrap()))
            .collect();
        for &(purpose, account) in &accounts {
            for chain in Chain::ALL {
                lanes.push(LaneKey::Account {
                    purpose,
                    account,
                    chain,
                });
            }
        }
        let widened: BTreeSet<String> = lanes
            .iter()
            .filter(|key| found.get(key).is_some_and(|set| !set.is_empty()))
            .map(|&key| group_of(key))
            .collect();
        for &key in &lanes {
            let gap = if widened.contains(&group_of(key)) {
                100
            } else {
                20
            };
            let entry = found.entry(key).or_default();
            loop {
                let end = entry
                    .last()
                    .map_or(0, |last| last + 1)
                    .saturating_add(gap)
                    .min(MAX_INDEX);
                let now: BTreeSet<u32> = used
                    .iter()
                    .filter(|(lane, index)| *lane == key && *index < end)
                    .map(|(_, index)| *index)
                    .collect();
                if now == *entry {
                    break;
                }
                *entry = now;
            }
        }
        for purpose in Purpose::ALL {
            let hit = |account: u32| {
                Chain::ALL.into_iter().any(|chain| {
                    found
                        .get(&lane(plan, purpose, account, chain))
                        .is_some_and(|set| !set.is_empty())
                })
            };
            for account in 3..100 {
                if accounts.contains(&(purpose, account)) {
                    continue;
                }
                if hit(account - 1) || hit(account - 2) {
                    accounts.insert((purpose, account));
                } else {
                    break;
                }
            }
        }
        if before == (found.clone(), accounts.clone()) {
            return found;
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, failure_persistence: None, ..ProptestConfig::default() })]

    /// Whatever addresses a server calls used, a complete walk finds exactly
    /// the used addresses the rules reach, opens exactly the accounts the rules
    /// open, and keeps to its caps.
    #[test]
    fn the_walk_finds_what_the_rules_reach_and_no_more(used in used_sets()) {
        let fx = fixture();
        let oracle = Oracle::new(used.clone(), false);
        let mut discovery = Discovery::new(&fx.plan, Budget::UNLIMITED);
        let progress = drive(&mut discovery, &Synthetic, &oracle, &HeaderChain::new(Network::Mainnet)).unwrap();
        prop_assert!(progress.complete);

        let expected = model(&fx.plan, &used);
        let mut accounts = BTreeSet::new();
        for saved in &progress.lanes {
            let found = expected.get(&saved.lane).cloned().unwrap_or_default();
            prop_assert_eq!(usize::try_from(saved.hits).unwrap(), found.len(), "{:?}", saved.lane);
            prop_assert_eq!(saved.last_hit, found.last().copied());
            prop_assert!(saved.pending_unspent.is_empty());
            prop_assert!(saved.next_index <= MAX_INDEX);
            if let LaneKey::Account { purpose, account, .. } = saved.lane {
                prop_assert!((3..100).contains(&account));
                accounts.insert((purpose, account));
            }
        }
        // The lanes are the plan's and the accounts the model opened, no others.
        let opened_by_model: BTreeSet<_> = expected
            .keys()
            .filter_map(|key| match key {
                LaneKey::Account { purpose, account, .. } => Some((*purpose, *account)),
                LaneKey::Plan(_) => None,
            })
            .collect();
        prop_assert_eq!(&accounts, &opened_by_model);

        // Two empty accounts in a row end a purpose: the last account opened
        // has a used address in it or in the one before, and the one after
        // does not exist.
        for purpose in Purpose::ALL {
            let last = accounts.iter().filter(|(p, _)| *p == purpose).map(|(_, a)| *a).max();
            if let Some(last) = last.filter(|last| last + 1 < 100) {
                let hit = |account: u32| {
                    Chain::ALL.into_iter().any(|chain| {
                        lane_progress(&progress, lane(&fx.plan, purpose, account, chain)).hits > 0
                    })
                };
                prop_assert!(!hit(last) && !hit(last - 1));
            }
        }
        // Every address found is an address the server called used.
        for (key, set) in &expected {
            for index in set {
                prop_assert!(used.contains(&(*key, *index)));
            }
        }
    }

    /// A run never spends more lookups than its budget, never takes more bytes
    /// than the budget plus the one answer that crossed it, says it is
    /// exhausted exactly when it stopped for that reason, and goes on from a
    /// fresh budget to the same end as a run with no limit.
    #[test]
    fn the_budget_holds(
        used in used_sets(),
        queries in 0_u32..700,
        bytes in 0_u64..30_000,
    ) {
        let fx = fixture();
        let chain = HeaderChain::new(Network::Mainnet);
        let oracle = Oracle::new(used.clone(), true);
        let mut unlimited = Discovery::new(&fx.plan, Budget::UNLIMITED);
        let end = drive(&mut unlimited, &Synthetic, &oracle, &chain).unwrap();
        prop_assert!(end.complete);

        let oracle = Oracle::new(used, true);
        let mut discovery = Discovery::new(&fx.plan, Budget { max_queries: queries, max_bytes: bytes });
        let first = drive(&mut discovery, &Synthetic, &oracle, &chain).unwrap();
        prop_assert!(first.queries <= u64::from(queries));
        prop_assert!(first.bytes <= bytes.saturating_add(oracle.largest.get()));
        prop_assert!(first.stopped.is_none());
        if first.exhausted {
            prop_assert!(!first.complete);
            prop_assert!(discovery.budget_spent());
            prop_assert_eq!(discovery.next_requests(&Synthetic).unwrap(), Vec::new());
        } else {
            prop_assert!(first.complete);
        }

        let mut last = first;
        let mut rounds = 0;
        while !last.complete {
            discovery.renew_budget(Budget { max_queries: 120, max_bytes: 1 });
            last = drive(&mut discovery, &Synthetic, &oracle, &chain).unwrap();
            prop_assert!(last.queries <= 120);
            rounds += 1;
            prop_assert!(rounds < 5_000);
        }
        prop_assert_eq!(essence(&last), essence(&end));
    }
}
