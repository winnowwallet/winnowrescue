//! Discovery: finding the coins of a plan with no birthday to bound the search.
//!
//! The engine does no input or output and holds no key. It is a state machine:
//! [`Discovery::next_requests`] says what to ask an indexing server next,
//! the host asks, [`Discovery::absorb`] takes each answer, and
//! [`Discovery::prove_pending`] proves the coins that have all their parts
//! against a header chain the host supplies. [`drive`] is that loop for a host
//! that has a [`HistorySource`] and a [`HeaderChain`] in hand.
//!
//! # The walk
//!
//! The plan's branches are walked as lanes, tier 1 first. A lane is one chain
//! of one account; it is asked about the addresses at index 0, 1, 2 and so on
//! until a stretch of unused ones ends it. That stretch is the gap: 20 at the
//! start. An address counts as used when its history is not empty, so an
//! address that was paid and spent still counts. A used address widens the gap
//! of every lane of its account to 100, and a lane with a used address at index
//! `i` is walked at least to `i + 1 + gap`. For the standard purposes (44, 49,
//! 84 and 86) accounts 0 to 2 are always walked, and account `n` after them is
//! opened as soon as account `n - 1` or `n - 2` has a used address; two empty
//! accounts in a row therefore end a purpose, and so does the limit of
//! [`MAX_ACCOUNTS`] accounts. No lane is walked past index
//! [`MAX_INDEX`] whatever a server says. [`Discovery::search_further`] raises
//! the gap of every lane that has a used address to [`FURTHER_GAP`].
//!
//! # Coins
//!
//! For each used address the engine asks for the unspent outputs. Each one is
//! a [`Candidate`]. A confirmed candidate asks for its transaction and its
//! merkle branch, and [`Discovery::prove_pending`] runs [`prove`] on it:
//! the candidate becomes `Proven` and a [`ProvenCoin`] is kept, or becomes
//! `Refused` with the named reason and is never a coin. A candidate whose block
//! is above the tip of the chain it was tried against waits for a longer chain
//! (the headers may simply not have arrived yet). An unconfirmed candidate
//! stays `Unconfirmed` and is never proved. Proving is a separate step, not
//! part of `absorb`, so that answering stays independent of the header chain
//! and the chain can grow between the two.
//!
//! # Budgets
//!
//! A [`Budget`] bounds one run between calls to the host. A query is one
//! lookup: one script in a history or unspent request, one transaction, one
//! merkle branch. [`Discovery::next_requests`] never asks for more lookups
//! than the budget has left, and returns nothing once the queries or the bytes
//! of the answers are used up. The bytes are an estimate of the size of the
//! answers as decoded, see [`Response::size`]; a run can pass the byte limit
//! by at most the one answer that crossed it. A run that stops this way has
//! `exhausted` set in its [`Progress`], and a fresh budget continues it.
//!
//! # Progress and secrets
//!
//! [`Progress`] is public data. It holds the network, the plan's fingerprint,
//! for each lane the next index, the gap, the hit count and the used indexes
//! whose coins are not yet asked for, the candidates and the proven coins. It
//! holds no key and no word, and its type is asserted below not to be able to:
//! the secret types are neither `Clone` nor `Serialize`, and `Progress` is
//! both. The scripts of the addresses are made inside the core by
//! [`Derivation`], from the session, when a request is built or a coin is
//! proved, and are not kept.
//!
//! A saved [`Progress`] says where a walk stopped; it is not evidence.
//! [`Discovery::resume`] refuses one made for other keys or another network,
//! refuses numbers no walk could have saved, and takes every coin back to a
//! candidate that must be proved again.

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::{OutPoint, ScriptBuf, Txid};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use static_assertions::assert_impl_all;

use crate::error::{DiscoverError, ProofError};
use crate::headers::HeaderChain;
use crate::network::Network;
use crate::paths::{Chain, GAP, Purpose, TIER_ONE_ACCOUNTS};
use crate::plan::{Branch, Origin, Plan, PlanFingerprint, Tier};
use crate::proof::{MerkleBranch, ProvenCoin, prove};
use crate::secret::Session;
use crate::source::{HistoryItem, HistorySource, SourceError, Unspent};

/// The most scripts one history or unspent request holds.
pub const MAX_BATCH: usize = 100;

/// The gap of every lane of an account that has a used address.
pub const WIDE_GAP: u32 = 100;

/// The gap [`Discovery::search_further`] gives a lane that has a used address.
pub const FURTHER_GAP: u32 = 1_000;

/// The most accounts walked for one purpose, the first three included.
pub const MAX_ACCOUNTS: u32 = 100;

/// A lane is never walked at this index or beyond, whatever a server says.
pub const MAX_INDEX: u32 = 10_000;

/// The most candidates one run keeps. No wallet holds this many coins, and a
/// server that says it does is refused rather than believed or stored.
pub const MAX_CANDIDATES: usize = 10_000;

/// The most requests one call to [`Discovery::next_requests`] returns.
const MAX_REQUESTS: usize = 16;

/// The most bytes a transaction may have; one larger is stored as nothing and
/// so is refused as not being a transaction.
const MAX_TX_BYTES: usize = 4_000_000;

/// The most satoshis that exist.
const MAX_MONEY_SATS: u64 = 21_000_000 * 100_000_000;

/// What one script costs in the size estimate, whatever the answer.
const FRAME_BYTES: u64 = 8;
/// What one history item costs in the size estimate: id and height.
const HISTORY_ITEM_BYTES: u64 = 36;
/// What one unspent output costs in the size estimate: id, index, amount, height.
const UNSPENT_BYTES: u64 = 48;
/// What one merkle hash costs in the size estimate.
const HASH_BYTES: u64 = 32;

/// What one run of the engine may spend between calls to the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    /// The most lookups: scripts asked about, transactions and branches fetched.
    pub max_queries: u32,
    /// The most bytes of answers, by [`Response::size`].
    pub max_bytes: u64,
}

impl Budget {
    /// A budget that is never used up.
    pub const UNLIMITED: Self = Self {
        max_queries: u32::MAX,
        max_bytes: u64::MAX,
    };
}

/// Which chain of which account a lane is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LaneKey {
    /// The branch at this position of the plan's branch list.
    Plan(u32),
    /// A chain of an account of a standard purpose that the plan does not list
    /// (the plan lists accounts 0 to 2); the engine opened it.
    Account {
        /// BIP44, 49, 84 or 86.
        purpose: Purpose,
        /// The account number, 3 up to but not including [`MAX_ACCOUNTS`].
        account: u32,
        /// Which of the account's two chains.
        chain: Chain,
    },
}

/// One address of the walk: an index of a lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Position {
    /// The lane.
    pub lane: LaneKey,
    /// The address index in the lane.
    pub index: u32,
}

/// Where the engine gets the script of an address from. It is the only way a
/// key is touched, and it hands out only a script.
///
/// [`Derivation`] is the one a host uses. The tests of this crate put recorded
/// coins at chosen addresses with another.
pub trait ScriptSource {
    /// The output script of the address at `index` of `lane`.
    ///
    /// # Errors
    ///
    /// A [`DiscoverError`] when the address cannot be derived.
    fn script(&self, lane: LaneKey, index: u32) -> Result<ScriptBuf, DiscoverError>;
}

/// Derives the scripts of a plan's lanes from the session the plan was made
/// from. It borrows both and keeps nothing.
#[derive(Clone, Copy)]
pub struct Derivation<'a> {
    plan: &'a Plan,
    session: &'a Session,
}

impl<'a> Derivation<'a> {
    /// Pairs a plan with its session.
    ///
    /// # Errors
    ///
    /// [`DiscoverError::WrongSession`] when the first addresses of the plan's
    /// tier-1 branches are not the ones the session derives.
    pub fn new(plan: &'a Plan, session: &'a Session) -> Result<Self, DiscoverError> {
        if plan.belongs_to(session) {
            Ok(Self { plan, session })
        } else {
            Err(DiscoverError::WrongSession)
        }
    }
}

impl ScriptSource for Derivation<'_> {
    fn script(&self, lane: LaneKey, index: u32) -> Result<ScriptBuf, DiscoverError> {
        let address = match lane {
            LaneKey::Plan(position) => {
                let branch = usize::try_from(position)
                    .ok()
                    .and_then(|position| self.plan.branches().get(position))
                    .ok_or(DiscoverError::UnexpectedAnswer)?;
                self.plan.address(self.session, branch, index)?
            }
            LaneKey::Account {
                purpose,
                account,
                chain,
            } => self
                .plan
                .account_address(self.session, purpose, account, chain, index)?,
        };
        Ok(address.script_pubkey())
    }
}

/// What the engine asks the host to look up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// The history of each script. `positions` and `scripts` go together, one
    /// for one; the answer is a [`Response::History`] with the same
    /// `positions` and a list of history items for each.
    History {
        /// Which address each script is.
        positions: Vec<Position>,
        /// The scripts, at most [`MAX_BATCH`].
        scripts: Vec<ScriptBuf>,
    },
    /// The unspent outputs of each script, answered by [`Response::Unspent`].
    Unspent {
        /// Which address each script is.
        positions: Vec<Position>,
        /// The scripts, at most [`MAX_BATCH`].
        scripts: Vec<ScriptBuf>,
    },
    /// The raw transaction with this id, answered by [`Response::Transaction`].
    Transaction {
        /// The id.
        txid: Txid,
    },
    /// The merkle branch of this transaction in the block at this height,
    /// answered by [`Response::Merkle`].
    Merkle {
        /// The id.
        txid: Txid,
        /// The height of the block.
        height: u32,
    },
}

impl Request {
    /// How many lookups the request costs against the budget.
    #[must_use]
    pub fn lookups(&self) -> u64 {
        match self {
            Self::History { scripts, .. } | Self::Unspent { scripts, .. } => count(scripts.len()),
            Self::Transaction { .. } | Self::Merkle { .. } => 1,
        }
    }
}

/// What the host found out, to be handed to [`Discovery::absorb`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    /// The answer to a [`Request::History`]: the `positions` of the request,
    /// and for each the history items the server listed.
    History {
        /// The positions of the request, unchanged.
        positions: Vec<Position>,
        /// For each position, its history.
        answers: Vec<Vec<HistoryItem>>,
    },
    /// The answer to a [`Request::Unspent`].
    Unspent {
        /// The positions of the request, unchanged.
        positions: Vec<Position>,
        /// For each position, its unspent outputs.
        answers: Vec<Vec<Unspent>>,
    },
    /// The answer to a [`Request::Transaction`].
    Transaction {
        /// The id asked for.
        txid: Txid,
        /// The bytes the server sent.
        raw: Vec<u8>,
    },
    /// The answer to a [`Request::Merkle`].
    Merkle {
        /// The id asked for.
        txid: Txid,
        /// The height asked for. The branch's own height is not read: the
        /// block the engine proves against is the one it asked about.
        height: u32,
        /// The branch the server sent.
        branch: MerkleBranch,
    },
}

impl Response {
    /// How many lookups the answer cost against the budget.
    #[must_use]
    pub fn lookups(&self) -> u64 {
        match self {
            Self::History { answers, .. } => count(answers.len()),
            Self::Unspent { answers, .. } => count(answers.len()),
            Self::Transaction { .. } | Self::Merkle { .. } => 1,
        }
    }

    /// The size of the answer, for the budget: 8 bytes for each script, 36 for
    /// each history item, 48 for each unspent output, the length of a
    /// transaction, and 8 plus 32 for each hash of a branch. It is an estimate
    /// of the decoded answer, not of what crossed the wire.
    #[must_use]
    pub fn size(&self) -> u64 {
        match self {
            Self::History { answers, .. } => {
                framed(answers.iter().map(Vec::len), HISTORY_ITEM_BYTES)
            }
            Self::Unspent { answers, .. } => framed(answers.iter().map(Vec::len), UNSPENT_BYTES),
            Self::Transaction { raw, .. } => count(raw.len()),
            Self::Merkle { branch, .. } => {
                FRAME_BYTES.saturating_add(count(branch.hashes.len()).saturating_mul(HASH_BYTES))
            }
        }
    }
}

fn count(length: usize) -> u64 {
    u64::try_from(length).unwrap_or(u64::MAX)
}

/// The cost of lists of answers: a frame for each list and `each` for each
/// entry in it.
fn framed(lengths: impl Iterator<Item = usize>, each: u64) -> u64 {
    lengths.fold(0, |total, length| {
        total
            .saturating_add(FRAME_BYTES)
            .saturating_add(count(length).saturating_mul(each))
    })
}

/// How far a reported coin has got.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidateState {
    /// Reported as confirmed and not yet proved: its transaction or branch is
    /// still to come, or the header chain has not reached its block.
    Candidate,
    /// Proved. A [`ProvenCoin`] is held for it.
    Proven,
    /// Reported with no block yet. Never proved; not rescuable until it has one.
    Unconfirmed,
    /// Its proof failed, for this reason. It is never a coin.
    Refused(ProofError),
}

/// An unspent output a server reported for an address of the plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    /// The lane of the address it was reported for.
    pub lane: LaneKey,
    /// The address index in the lane.
    pub index: u32,
    /// The id of the transaction.
    pub txid: Txid,
    /// The index of the output.
    pub vout: u32,
    /// The amount in satoshis: the server's word until it is proved, the
    /// transaction's after.
    pub sats: u64,
    /// The block the server says the transaction is in; `None` if unconfirmed.
    pub height: Option<u32>,
    /// How far it has got.
    pub state: CandidateState,
}

impl Candidate {
    fn outpoint(&self) -> OutPoint {
        OutPoint::new(self.txid, self.vout)
    }

    fn wants_proof(&self) -> bool {
        self.state == CandidateState::Candidate && self.height.is_some()
    }
}

/// A proved coin as a plain record, for showing and saving.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinRecord {
    /// The id of the transaction.
    pub txid: Txid,
    /// The index of the output.
    pub vout: u32,
    /// The amount in satoshis.
    pub sats: u64,
    /// The script the output pays.
    pub script: ScriptBuf,
    /// The height of the block it was mined in.
    pub height: u32,
    /// How many blocks buried it when it was proved.
    pub confirmations: u32,
    /// Whether it is a block reward, which waits 100 blocks to be spent.
    pub coinbase: bool,
}

impl From<&ProvenCoin> for CoinRecord {
    fn from(coin: &ProvenCoin) -> Self {
        Self {
            txid: coin.outpoint().txid,
            vout: coin.outpoint().vout,
            sats: coin.amount().to_sat(),
            script: coin.script().to_owned(),
            height: coin.height(),
            confirmations: coin.confirmations(),
            coinbase: coin.is_coinbase(),
        }
    }
}

/// Where a lane's walk stands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneProgress {
    /// Which lane.
    pub lane: LaneKey,
    /// For a lane of the plan, the script at index 0 (public, and what ties
    /// the lane to the plan on resume); `None` for a lane the engine opened.
    pub first_script: Option<ScriptBuf>,
    /// The first index not yet asked about.
    pub next_index: u32,
    /// How many unused addresses in a row end the walk after the last used one.
    pub gap: u32,
    /// How many of the addresses asked about were used.
    pub hits: u32,
    /// The highest used index.
    pub last_hit: Option<u32>,
    /// The used indexes whose unspent outputs are not yet asked for.
    pub pending_unspent: Vec<u32>,
}

/// The public state of a run. It is what a host shows, and what it saves to
/// resume with [`Discovery::resume`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Progress {
    /// The network.
    pub network: Network,
    /// The fingerprint of the plan the run is for.
    pub fingerprint: PlanFingerprint,
    /// Every lane, the plan's first.
    pub lanes: Vec<LaneProgress>,
    /// Every output a server reported, in the order reported.
    pub candidates: Vec<Candidate>,
    /// The proved coins.
    pub coins: Vec<CoinRecord>,
    /// The height of the header chain at the last proving step.
    pub header_tip: Option<u32>,
    /// The lookups spent in this run.
    pub queries: u64,
    /// The bytes of answers taken in this run.
    pub bytes: u64,
    /// The budget is used up and there is more to do.
    pub exhausted: bool,
    /// There is nothing more to ask for and no candidate waits for a header.
    pub complete: bool,
    /// Why the last [`drive`] stopped early, if a source failed.
    pub stopped: Option<SourceError>,
}

// A struct holding a `Session`, a `RootKey` or a `KeyHandle` could not be
// `Clone` or `Serialize`, because none of them is (asserted in `secret`). So
// these lines fail to build if any of them gets into `Progress` or what it
// holds.
assert_impl_all!(Progress: Clone, Serialize, DeserializeOwned, Send, Sync);

/// Which lanes widen together: the two chains of an account, or the chains of
/// one row of the table of wallets with habits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Group {
    Account(Purpose, u32),
    Row(u32),
}

#[derive(Clone, Debug)]
struct Lane {
    key: LaneKey,
    tier: Tier,
    group: Group,
    first_script: Option<ScriptBuf>,
    /// A loose key has one address and no tree.
    single: bool,
    next_index: u32,
    gap: u32,
    hits: u32,
    last_hit: Option<u32>,
    pending: Vec<u32>,
}

impl Lane {
    /// The index the walk of this lane stops before.
    fn end(&self) -> u32 {
        if self.single {
            return 1;
        }
        let after_hit = self.last_hit.map_or(0, |hit| hit.saturating_add(1));
        after_hit.saturating_add(self.gap).min(MAX_INDEX)
    }

    fn scanned(&self) -> bool {
        self.next_index >= self.end()
    }

    fn progress(&self) -> LaneProgress {
        LaneProgress {
            lane: self.key,
            first_script: self.first_script.clone(),
            next_index: self.next_index,
            gap: self.gap,
            hits: self.hits,
            last_hit: self.last_hit,
            pending_unspent: self.pending.clone(),
        }
    }
}

/// The lane for the branch at `position` of the plan, at the start of its walk.
fn lane_of(position: usize, branch: &Branch, group: Group) -> Lane {
    Lane {
        key: LaneKey::Plan(u32::try_from(position).unwrap_or(u32::MAX)),
        tier: branch.tier,
        group,
        first_script: Some(branch.first_address.script_pubkey()),
        single: branch.path.is_none(),
        next_index: 0,
        gap: branch.gap,
        hits: 0,
        last_hit: None,
        pending: Vec::new(),
    }
}

/// The discovery engine. See the module documentation for the rules it walks by.
#[derive(Clone, Debug)]
pub struct Discovery {
    network: Network,
    fingerprint: PlanFingerprint,
    budget: Budget,
    lanes: Vec<Lane>,
    lane_at: BTreeMap<LaneKey, usize>,
    /// The standard purposes the plan has accounts for.
    purposes: Vec<Purpose>,
    candidates: Vec<Candidate>,
    outpoints: BTreeSet<OutPoint>,
    coins: Vec<ProvenCoin>,
    /// Transactions fetched for candidates that wait for proof.
    raw: BTreeMap<Txid, Vec<u8>>,
    /// Branches fetched for candidates that wait for proof, by id and height.
    branches: BTreeMap<(Txid, u32), MerkleBranch>,
    header_tip: Option<u32>,
    queries: u64,
    bytes: u64,
    stopped: Option<SourceError>,
}

impl Discovery {
    /// A new run over the branches of `plan`, with `budget` to spend.
    #[must_use]
    pub fn new(plan: &Plan, budget: Budget) -> Self {
        let mut purposes = Vec::new();
        let mut lanes: Vec<Lane> = Vec::new();
        for (position, branch) in plan.branches().iter().enumerate() {
            let group = if let Origin::Purpose { purpose, account } = branch.origin {
                if !purposes.contains(&purpose) {
                    purposes.push(purpose);
                }
                Group::Account(purpose, account)
            } else {
                let first = plan.branches().iter().position(|other| {
                    other.origin == branch.origin
                        && other.kind == branch.kind
                        && other.tier == branch.tier
                });
                Group::Row(u32::try_from(first.unwrap_or(position)).unwrap_or(u32::MAX))
            };
            lanes.push(lane_of(position, branch, group));
        }
        let mut engine = Self {
            network: plan.network(),
            fingerprint: plan.fingerprint(),
            budget,
            lanes: Vec::new(),
            lane_at: BTreeMap::new(),
            purposes,
            candidates: Vec::new(),
            outpoints: BTreeSet::new(),
            coins: Vec::new(),
            raw: BTreeMap::new(),
            branches: BTreeMap::new(),
            header_tip: None,
            queries: 0,
            bytes: 0,
            stopped: None,
        };
        for lane in lanes {
            engine.push_lane(lane);
        }
        engine
    }

    /// Continues a saved run with a fresh budget.
    ///
    /// Only a run made for this plan on this network is continued. What the
    /// saved run held is checked against the limits of the walk and against the
    /// plan, so a file that has been damaged or made up is refused by name.
    /// Every candidate that had been proved goes back to waiting for proof:
    /// the file is where the walk stopped, not evidence of a coin. The
    /// counters, the header tip and the reason a run stopped start again.
    ///
    /// # Errors
    ///
    /// [`DiscoverError::WrongNetwork`] and [`DiscoverError::WrongPlan`] for a
    /// run of another network or other keys, and [`DiscoverError::BadProgress`]
    /// for anything else that no run could have saved.
    pub fn resume(progress: &Progress, plan: &Plan, budget: Budget) -> Result<Self, DiscoverError> {
        if progress.network != plan.network() {
            return Err(DiscoverError::WrongNetwork);
        }
        if progress.fingerprint != plan.fingerprint() {
            return Err(DiscoverError::WrongPlan);
        }
        let mut engine = Self::new(plan, budget);
        let mut seen = BTreeSet::new();
        for saved in &progress.lanes {
            if !seen.insert(saved.lane) {
                return Err(DiscoverError::BadProgress);
            }
            engine.restore_lane(saved)?;
        }
        engine.restore_candidates(&progress.candidates)?;
        engine.widen();
        engine.open_accounts();
        Ok(engine)
    }

    fn push_lane(&mut self, lane: Lane) {
        self.lane_at.insert(lane.key, self.lanes.len());
        self.lanes.push(lane);
    }

    /// Takes the saved numbers of one lane, if they are numbers a walk can have.
    fn restore_lane(&mut self, saved: &LaneProgress) -> Result<(), DiscoverError> {
        let bad = DiscoverError::BadProgress;
        let known = self.lane_at.get(&saved.lane).copied();
        let lane = match (known, saved.lane) {
            (Some(at), _) => {
                let lane = self.lanes.get_mut(at).ok_or(bad)?;
                if lane.first_script != saved.first_script {
                    return Err(bad);
                }
                lane
            }
            (
                None,
                LaneKey::Account {
                    purpose,
                    account,
                    chain,
                },
            ) => {
                let opened = (TIER_ONE_ACCOUNTS..MAX_ACCOUNTS).contains(&account)
                    && self.purposes.contains(&purpose)
                    && saved.first_script.is_none();
                if !opened {
                    return Err(bad);
                }
                self.push_lane(opened_lane(purpose, account, chain));
                self.lanes.last_mut().ok_or(bad)?
            }
            (None, LaneKey::Plan(_)) => return Err(bad),
        };
        let limit = if lane.single { 1 } else { MAX_INDEX };
        let sorted = saved
            .pending_unspent
            .windows(2)
            .all(|pair| pair[0] < pair[1]);
        let consistent = saved.next_index <= limit
            && saved.gap <= FURTHER_GAP
            && saved.hits <= saved.next_index
            && saved.last_hit.is_some() == (saved.hits > 0)
            && saved.last_hit.is_none_or(|hit| hit < saved.next_index)
            && sorted
            && saved.pending_unspent.len() <= usize::try_from(saved.hits).unwrap_or(usize::MAX)
            && saved
                .pending_unspent
                .last()
                .is_none_or(|last| saved.last_hit.is_some_and(|hit| *last <= hit));
        if !consistent {
            return Err(bad);
        }
        lane.next_index = saved.next_index;
        lane.gap = lane.gap.max(saved.gap);
        lane.hits = saved.hits;
        lane.last_hit = saved.last_hit;
        lane.pending.clone_from(&saved.pending_unspent);
        Ok(())
    }

    /// Takes the saved candidates, each one needing its proof again.
    fn restore_candidates(&mut self, saved: &[Candidate]) -> Result<(), DiscoverError> {
        if saved.len() > MAX_CANDIDATES {
            return Err(DiscoverError::BadProgress);
        }
        for candidate in saved {
            let lane = self
                .lane_at
                .get(&candidate.lane)
                .and_then(|&at| self.lanes.get(at))
                .ok_or(DiscoverError::BadProgress)?;
            if candidate.index >= lane.next_index
                || candidate.sats > MAX_MONEY_SATS
                || !self.outpoints.insert(candidate.outpoint())
            {
                return Err(DiscoverError::BadProgress);
            }
            let state = match (candidate.height, candidate.state) {
                (None, _) => CandidateState::Unconfirmed,
                (Some(_), CandidateState::Refused(reason)) => CandidateState::Refused(reason),
                (Some(_), _) => CandidateState::Candidate,
            };
            self.candidates.push(Candidate {
                state,
                ..candidate.clone()
            });
        }
        Ok(())
    }

    /// The network the run is for.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// The proved coins, in the order they were proved.
    #[must_use]
    pub fn coins(&self) -> &[ProvenCoin] {
        &self.coins
    }

    /// Gives the run a fresh budget and starts counting again, keeping
    /// everything found. This is how a run that exhausted its budget goes on
    /// without being saved and resumed.
    pub fn renew_budget(&mut self, budget: Budget) {
        self.budget = budget;
        self.queries = 0;
        self.bytes = 0;
        self.stopped = None;
    }

    /// Raises the gap of every lane that has a used address to
    /// [`FURTHER_GAP`] and so reopens the walk. A lane with no used address is
    /// left as it is.
    pub fn search_further(&mut self) {
        for lane in &mut self.lanes {
            if lane.hits > 0 && !lane.single {
                lane.gap = lane.gap.max(FURTHER_GAP);
            }
        }
    }

    /// How many transactions and branches are held for candidates that wait
    /// for their proof.
    #[cfg(test)]
    pub(crate) fn held(&self) -> (usize, usize) {
        (self.raw.len(), self.branches.len())
    }

    /// Whether the budget is used up.
    #[must_use]
    pub fn budget_spent(&self) -> bool {
        self.queries >= u64::from(self.budget.max_queries) || self.bytes >= self.budget.max_bytes
    }

    /// Whether the budget is used up with work left to ask for.
    #[must_use]
    pub fn exhausted(&self) -> bool {
        self.budget_spent() && self.requests_possible()
    }

    /// Whether there is nothing left to ask for and no candidate waits for a
    /// longer header chain.
    #[must_use]
    pub fn complete(&self) -> bool {
        !self.requests_possible()
            && !self
                .candidates
                .iter()
                .any(|candidate| candidate.state == CandidateState::Candidate)
    }

    /// Whether a request could be made, budget aside.
    fn requests_possible(&self) -> bool {
        self.lanes
            .iter()
            .any(|lane| !lane.scanned() || !lane.pending.is_empty())
            || self.candidates.iter().any(|candidate| {
                candidate.height.is_some_and(|height| {
                    candidate.wants_proof()
                        && (!self.raw.contains_key(&candidate.txid)
                            || !self.branches.contains_key(&(candidate.txid, height)))
                })
            })
    }

    fn remaining_queries(&self) -> usize {
        usize::try_from(u64::from(self.budget.max_queries).saturating_sub(self.queries))
            .unwrap_or(usize::MAX)
    }

    /// The state of the run as public data.
    #[must_use]
    pub fn progress(&self) -> Progress {
        Progress {
            network: self.network,
            fingerprint: self.fingerprint,
            lanes: self.lanes.iter().map(Lane::progress).collect(),
            candidates: self.candidates.clone(),
            coins: self.coins.iter().map(CoinRecord::from).collect(),
            header_tip: self.header_tip,
            queries: self.queries,
            bytes: self.bytes,
            exhausted: self.exhausted(),
            complete: self.complete(),
            stopped: self.stopped,
        }
    }

    /// What to ask next: the transactions and branches of candidates waiting
    /// for proof, then the unspent outputs of used addresses, then the history
    /// of addresses not yet asked about, tier 1 first. History and unspent
    /// requests hold at most [`MAX_BATCH`] scripts, and may span lanes. At most
    /// 16 requests are returned, together costing no more lookups than the
    /// budget has left; none are when the budget is used up or when the walk is
    /// complete.
    ///
    /// The same requests come back until their answers are taken, so a host
    /// may answer them in any order, and may drop them and ask again.
    ///
    /// # Errors
    ///
    /// A [`DiscoverError`] if the scripts cannot be derived.
    pub fn next_requests(&self, scripts: &dyn ScriptSource) -> Result<Vec<Request>, DiscoverError> {
        let mut out = Vec::new();
        let mut left = self.remaining_queries();
        if self.budget_spent() {
            return Ok(out);
        }

        let mut transactions = BTreeSet::new();
        let mut merkles = BTreeSet::new();
        for candidate in self.candidates.iter().filter(|c| c.wants_proof()) {
            if !self.raw.contains_key(&candidate.txid) {
                transactions.insert(candidate.txid);
            }
            if let Some(height) = candidate.height
                && !self.branches.contains_key(&(candidate.txid, height))
            {
                merkles.insert((candidate.txid, height));
            }
        }
        for txid in transactions {
            if left == 0 || out.len() >= MAX_REQUESTS {
                return Ok(out);
            }
            left = left.saturating_sub(1);
            out.push(Request::Transaction { txid });
        }
        for (txid, height) in merkles {
            if left == 0 || out.len() >= MAX_REQUESTS {
                return Ok(out);
            }
            left = left.saturating_sub(1);
            out.push(Request::Merkle { txid, height });
        }

        // Tier 1 first, and within a tier in the order the lanes were made.
        let mut order: Vec<&Lane> = self.lanes.iter().collect();
        order.sort_by_key(|lane| lane.tier);

        let unspent: Vec<Vec<Position>> = order
            .iter()
            .flat_map(|lane| {
                lane.pending.chunks(MAX_BATCH).map(|chunk| {
                    chunk
                        .iter()
                        .map(|&index| Position {
                            lane: lane.key,
                            index,
                        })
                        .collect()
                })
            })
            .collect();
        pack(&mut out, &mut left, unspent, scripts, true)?;

        let history: Vec<Vec<Position>> = order
            .iter()
            .filter(|lane| !lane.scanned())
            .map(|lane| {
                let to = lane.end().min(
                    lane.next_index
                        .saturating_add(u32::try_from(MAX_BATCH).unwrap_or(u32::MAX)),
                );
                (lane.next_index..to)
                    .map(|index| Position {
                        lane: lane.key,
                        index,
                    })
                    .collect()
            })
            .collect();
        pack(&mut out, &mut left, history, scripts, false)?;
        Ok(out)
    }

    /// Takes the answer to a request.
    ///
    /// An answer to something already taken (the same page twice) changes
    /// nothing but the counters. An answer that is not for anything that was
    /// asked, or whose parts do not match its question, is refused and changes
    /// nothing at all, the counters included. A taken answer costs its
    /// [`lookups`](Response::lookups) and its [`size`](Response::size).
    ///
    /// # Errors
    ///
    /// [`DiscoverError::UnexpectedAnswer`], [`DiscoverError::AnswerShape`] or
    /// [`DiscoverError::TooManyCoins`], as described.
    pub fn absorb(&mut self, response: Response) -> Result<Progress, DiscoverError> {
        let (lookups, size) = (response.lookups(), response.size());
        match response {
            Response::History { positions, answers } => {
                self.absorb_history(&positions, &answers)?;
            }
            Response::Unspent { positions, answers } => {
                self.absorb_unspent(&positions, &answers)?;
            }
            Response::Transaction { txid, raw } => self.absorb_transaction(txid, raw),
            Response::Merkle {
                txid,
                height,
                branch,
            } => self.absorb_merkle(txid, height, branch),
        }
        self.queries = self.queries.saturating_add(lookups);
        self.bytes = self.bytes.saturating_add(size);
        Ok(self.progress())
    }

    fn absorb_history(
        &mut self,
        positions: &[Position],
        answers: &[Vec<HistoryItem>],
    ) -> Result<(), DiscoverError> {
        if positions.len() != answers.len() {
            return Err(DiscoverError::AnswerShape);
        }
        // Each lane takes its addresses in order, from the first not yet asked
        // about; one already taken is a repeat and is skipped.
        let mut expected: BTreeMap<LaneKey, u32> = BTreeMap::new();
        let mut taken = Vec::new();
        for (position, answer) in positions.iter().zip(answers) {
            let at = *self
                .lane_at
                .get(&position.lane)
                .ok_or(DiscoverError::UnexpectedAnswer)?;
            let lane = self.lanes.get(at).ok_or(DiscoverError::UnexpectedAnswer)?;
            if position.index < lane.next_index {
                continue;
            }
            let next = expected
                .get(&position.lane)
                .copied()
                .unwrap_or(lane.next_index);
            if position.index != next || position.index >= lane.end() {
                return Err(DiscoverError::UnexpectedAnswer);
            }
            expected.insert(position.lane, next.saturating_add(1));
            taken.push((at, position.index, !answer.is_empty()));
        }
        for (at, index, used) in taken {
            let Some(lane) = self.lanes.get_mut(at) else {
                continue;
            };
            lane.next_index = index.saturating_add(1);
            if used {
                lane.hits = lane.hits.saturating_add(1);
                lane.last_hit = Some(lane.last_hit.map_or(index, |hit| hit.max(index)));
                if let Err(slot) = lane.pending.binary_search(&index) {
                    lane.pending.insert(slot, index);
                }
            }
        }
        self.widen();
        self.open_accounts();
        Ok(())
    }

    fn absorb_unspent(
        &mut self,
        positions: &[Position],
        answers: &[Vec<Unspent>],
    ) -> Result<(), DiscoverError> {
        if positions.len() != answers.len() {
            return Err(DiscoverError::AnswerShape);
        }
        let mut done = BTreeSet::new();
        let mut known = self.outpoints.clone();
        let mut fresh = Vec::new();
        for (position, outputs) in positions.iter().zip(answers) {
            let lane = self
                .lane_at
                .get(&position.lane)
                .and_then(|&at| self.lanes.get(at))
                .ok_or(DiscoverError::UnexpectedAnswer)?;
            if lane.pending.binary_search(&position.index).is_err() {
                // Taken already, or never asked.
                if position.index >= lane.next_index {
                    return Err(DiscoverError::UnexpectedAnswer);
                }
                continue;
            }
            if !done.insert(*position) {
                continue;
            }
            for output in outputs {
                let outpoint = OutPoint::new(output.txid, output.vout);
                if known.insert(outpoint) {
                    fresh.push(Candidate {
                        lane: position.lane,
                        index: position.index,
                        txid: output.txid,
                        vout: output.vout,
                        sats: output.amount.to_sat(),
                        height: output.height,
                        state: if output.height.is_some() {
                            CandidateState::Candidate
                        } else {
                            CandidateState::Unconfirmed
                        },
                    });
                }
            }
        }
        if self.candidates.len().saturating_add(fresh.len()) > MAX_CANDIDATES {
            return Err(DiscoverError::TooManyCoins);
        }
        for position in done {
            if let Some(lane) = self
                .lane_at
                .get(&position.lane)
                .copied()
                .and_then(|at| self.lanes.get_mut(at))
                && let Ok(slot) = lane.pending.binary_search(&position.index)
            {
                lane.pending.remove(slot);
            }
        }
        self.outpoints = known;
        self.candidates.extend(fresh);
        self.open_accounts();
        Ok(())
    }

    fn absorb_transaction(&mut self, txid: Txid, raw: Vec<u8>) {
        let wanted = self
            .candidates
            .iter()
            .any(|candidate| candidate.wants_proof() && candidate.txid == txid);
        if wanted && !self.raw.contains_key(&txid) {
            let raw = if raw.len() > MAX_TX_BYTES {
                Vec::new()
            } else {
                raw
            };
            self.raw.insert(txid, raw);
        }
    }

    fn absorb_merkle(&mut self, txid: Txid, height: u32, branch: MerkleBranch) {
        let wanted = self.candidates.iter().any(|candidate| {
            candidate.wants_proof() && candidate.txid == txid && candidate.height == Some(height)
        });
        if wanted && !self.branches.contains_key(&(txid, height)) {
            // The block is the one asked about, whatever height the branch says.
            let branch = MerkleBranch::new(height, branch.position, branch.hashes);
            self.branches.insert((txid, height), branch);
        }
    }

    /// Proves every candidate that has its transaction and its branch against
    /// `chain`, and returns the state of the run.
    ///
    /// A candidate is proved by [`prove`] against the script `scripts` gives
    /// for its address, and so is never believed on the amount or the script a
    /// server gave. It becomes `Proven`, or `Refused` with the reason. A
    /// candidate whose block is above the tip of `chain` is left waiting.
    ///
    /// # Errors
    ///
    /// [`DiscoverError::WrongNetwork`] if `chain` is of another network, and a
    /// [`DiscoverError`] if a script cannot be derived.
    pub fn prove_pending(
        &mut self,
        scripts: &dyn ScriptSource,
        chain: &HeaderChain,
    ) -> Result<Progress, DiscoverError> {
        if chain.network() != self.network {
            return Err(DiscoverError::WrongNetwork);
        }
        self.header_tip = Some(chain.height());
        for at in 0..self.candidates.len() {
            let Some(candidate) = self.candidates.get(at) else {
                continue;
            };
            let Some(height) = candidate.height.filter(|_| candidate.wants_proof()) else {
                continue;
            };
            let (Some(raw), Some(branch)) = (
                self.raw.get(&candidate.txid),
                self.branches.get(&(candidate.txid, height)),
            ) else {
                continue;
            };
            let script = scripts.script(candidate.lane, candidate.index)?;
            let outcome = prove(raw, candidate.txid, candidate.vout, &script, branch, chain);
            let Some(candidate) = self.candidates.get_mut(at) else {
                continue;
            };
            match outcome {
                Ok(coin) => {
                    candidate.sats = coin.amount().to_sat();
                    candidate.state = CandidateState::Proven;
                    self.coins.push(coin);
                }
                Err(ProofError::HeightNotInChain) => {}
                Err(reason) => candidate.state = CandidateState::Refused(reason),
            }
        }
        // Keep only what a candidate still waiting needs.
        let waiting: Vec<(Txid, u32)> = self
            .candidates
            .iter()
            .filter(|candidate| candidate.wants_proof())
            .filter_map(|candidate| candidate.height.map(|height| (candidate.txid, height)))
            .collect();
        self.raw
            .retain(|txid, _| waiting.iter().any(|(wanted, _)| wanted == txid));
        self.branches.retain(|key, _| waiting.contains(key));
        Ok(self.progress())
    }

    /// Gives every lane of an account that has a used address the wide gap.
    fn widen(&mut self) {
        let hit: BTreeSet<Group> = self
            .lanes
            .iter()
            .filter(|lane| lane.hits > 0)
            .map(|lane| lane.group)
            .collect();
        for lane in &mut self.lanes {
            if !lane.single && hit.contains(&lane.group) {
                lane.gap = lane.gap.max(WIDE_GAP);
            }
        }
    }

    /// Opens the accounts that the rule asks for: account `n` of a purpose
    /// once account `n - 1` or `n - 2` has a used address, up to the limit.
    fn open_accounts(&mut self) {
        // For each account: whether any of its lanes has a used address, and
        // whether all of its lanes have been walked to their end.
        let mut seen: BTreeMap<(Purpose, u32), (bool, bool)> = BTreeMap::new();
        for lane in &self.lanes {
            if let Group::Account(purpose, account) = lane.group {
                let entry = seen.entry((purpose, account)).or_insert((false, true));
                entry.0 |= lane.hits > 0;
                entry.1 &= lane.scanned();
            }
        }
        let hit = |seen: &BTreeMap<(Purpose, u32), (bool, bool)>, purpose, account: Option<u32>| {
            account
                .is_some_and(|account| seen.get(&(purpose, account)).is_some_and(|state| state.0))
        };
        let mut opened = Vec::new();
        for &purpose in &self.purposes {
            let mut account = TIER_ONE_ACCOUNTS;
            while account < MAX_ACCOUNTS {
                if !seen.contains_key(&(purpose, account)) {
                    let one_back = hit(&seen, purpose, account.checked_sub(1));
                    if !one_back && !hit(&seen, purpose, account.checked_sub(2)) {
                        break;
                    }
                    seen.insert((purpose, account), (false, false));
                    opened.push((purpose, account));
                }
                account = account.saturating_add(1);
            }
        }
        for (purpose, account) in opened {
            for chain in Chain::ALL {
                self.push_lane(opened_lane(purpose, account, chain));
            }
        }
    }
}

/// A lane of an account the plan does not list, at the start of its walk.
fn opened_lane(purpose: Purpose, account: u32, chain: Chain) -> Lane {
    Lane {
        key: LaneKey::Account {
            purpose,
            account,
            chain,
        },
        tier: Tier::One,
        group: Group::Account(purpose, account),
        first_script: None,
        single: false,
        next_index: 0,
        gap: GAP,
        hits: 0,
        last_hit: None,
        pending: Vec::new(),
    }
}

/// Packs segments of positions, each from one lane, into requests of at most
/// [`MAX_BATCH`] scripts without splitting a segment, spending lookups from
/// `left` and stopping at [`MAX_REQUESTS`].
fn pack(
    out: &mut Vec<Request>,
    left: &mut usize,
    segments: Vec<Vec<Position>>,
    scripts: &dyn ScriptSource,
    unspent: bool,
) -> Result<(), DiscoverError> {
    let mut current: Vec<Position> = Vec::new();
    for mut segment in segments {
        if *left == 0 || out.len() >= MAX_REQUESTS {
            break;
        }
        segment.truncate(*left);
        if current.len().saturating_add(segment.len()) > MAX_BATCH {
            out.push(request(std::mem::take(&mut current), scripts, unspent)?);
            if out.len() >= MAX_REQUESTS {
                return Ok(());
            }
        }
        *left = left.saturating_sub(segment.len());
        current.extend(segment);
    }
    if !current.is_empty() {
        out.push(request(current, scripts, unspent)?);
    }
    Ok(())
}

fn request(
    positions: Vec<Position>,
    scripts: &dyn ScriptSource,
    unspent: bool,
) -> Result<Request, DiscoverError> {
    let scripts = positions
        .iter()
        .map(|position| scripts.script(position.lane, position.index))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(if unspent {
        Request::Unspent { positions, scripts }
    } else {
        Request::History { positions, scripts }
    })
}

/// Walks the plan against a source until the budget is used up or nothing is
/// left to ask, and returns the state of the run.
///
/// The source's genesis hash is compared with the genesis block of `chain`
/// first, and a mismatch is refused: a server of another network or chain
/// would otherwise be believed about addresses. After each round of answers
/// the coins that have all their parts are proved against `chain`, which the
/// host should have caught up to the source's tip.
///
/// A [`SourceError`] ends the run, with the progress so far returned and the
/// error in its `stopped`; the host decides whether to try again, with this
/// engine or a saved [`Progress`]. A source that answers a different number of
/// lists than it was given scripts counts as one that answered
/// [`SourceError::Malformed`].
///
/// # Errors
///
/// [`DiscoverError::WrongNetwork`] if `chain` is not of the engine's network,
/// [`DiscoverError::GenesisMismatch`] as described, and any error of
/// [`Discovery::next_requests`], [`Discovery::absorb`] or
/// [`Discovery::prove_pending`].
pub fn drive(
    discovery: &mut Discovery,
    scripts: &dyn ScriptSource,
    source: &dyn HistorySource,
    chain: &HeaderChain,
) -> Result<Progress, DiscoverError> {
    if chain.network() != discovery.network {
        return Err(DiscoverError::WrongNetwork);
    }
    discovery.stopped = None;
    match source.genesis() {
        Ok(genesis) if chain.block_hash_at(0) == Some(genesis) => {}
        Ok(_) => return Err(DiscoverError::GenesisMismatch),
        Err(error) => {
            discovery.stopped = Some(error);
            return Ok(discovery.progress());
        }
    }
    'run: loop {
        let requests = discovery.next_requests(scripts)?;
        if requests.is_empty() {
            break;
        }
        for request in requests {
            if discovery.budget_spent() {
                break 'run;
            }
            match answer(source, request) {
                Ok(response) => {
                    discovery.absorb(response)?;
                }
                Err(error) => {
                    discovery.stopped = Some(error);
                    break 'run;
                }
            }
        }
        discovery.prove_pending(scripts, chain)?;
    }
    discovery.prove_pending(scripts, chain)
}

/// Asks the source one request.
pub(crate) fn answer(
    source: &dyn HistorySource,
    request: Request,
) -> Result<Response, SourceError> {
    match request {
        Request::History { positions, scripts } => {
            let answers = source.history(&scripts)?;
            if answers.len() != scripts.len() {
                return Err(SourceError::Malformed);
            }
            Ok(Response::History { positions, answers })
        }
        Request::Unspent { positions, scripts } => {
            let answers = source.unspent(&scripts)?;
            if answers.len() != scripts.len() {
                return Err(SourceError::Malformed);
            }
            Ok(Response::Unspent { positions, answers })
        }
        Request::Transaction { txid } => Ok(Response::Transaction {
            txid,
            raw: source.transaction_raw(txid)?,
        }),
        Request::Merkle { txid, height } => Ok(Response::Merkle {
            txid,
            height,
            branch: source.merkle(txid, height)?,
        }),
    }
}
