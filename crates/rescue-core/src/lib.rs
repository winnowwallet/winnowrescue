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
pub mod discover;
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
pub use discover::{
    Budget, Candidate, CandidateState, CoinRecord, Derivation, Discovery, LaneKey, LaneProgress,
    Position, Progress, Request, Response, ScriptSource, drive,
};
pub use error::{
    DestinationError, DiscoverError, HeaderError, ImportError, PathError, PlanError, ProofError,
};
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
pub use source::{Broadcaster, Headers, HistoryItem, HistorySource, SourceError, Unspent};
pub use words::ElectrumKind;

/// The crate version, the one figure every shell shows.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Entry points the fuzz targets call. Each takes raw bytes and must never
/// trap; refusing is the expected answer for almost every input.
#[cfg(feature = "fuzzing")]
pub mod fuzz_api {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::OnceLock;

    use bitcoin::block::{Header, TxMerkleNode};
    use bitcoin::consensus::deserialize;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, ScriptBuf, Transaction, Txid, WPubkeyHash};

    use crate::discover::{FURTHER_GAP, MAX_BATCH, MAX_CANDIDATES, MAX_INDEX};
    use crate::{
        Budget, CandidateState, Chain, Destination, DiscoverError, Discovery, HEADER_SIZE,
        HeaderChain, HistoryItem, LaneKey, MAX_BRANCH_LEN, MerkleBranch, Network, Plan, Position,
        Progress, Purpose, Request, Response, ScriptSource, SecretInput, Session, Unspent,
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

    /// The plan the discovery targets run over: the 36 branches of a fixed,
    /// public test phrase on mainnet, made once. The scripts of the walk are
    /// not derived from it (see [`Named`]); only its shape and fingerprint are
    /// used.
    fn discovery_plan() -> Option<&'static Plan> {
        static PLAN: OnceLock<Option<Plan>> = OnceLock::new();
        PLAN.get_or_init(|| {
            let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let session =
                Session::import(SecretInput::new(words.to_owned()), None, Network::Mainnet).ok()?;
            Plan::build(&session).ok()
        })
        .as_ref()
    }

    /// Scripts that spell out their address, made without deriving a key, so a
    /// walk of thousands of addresses costs a few writes each.
    struct Named;

    impl ScriptSource for Named {
        fn script(&self, lane: LaneKey, index: u32) -> Result<ScriptBuf, DiscoverError> {
            let mut hash = [0_u8; 20];
            let (tag, rest) = hash.split_at_mut(1);
            match lane {
                LaneKey::Plan(at) => {
                    tag.copy_from_slice(&[1]);
                    rest[..4].copy_from_slice(&at.to_be_bytes());
                }
                LaneKey::Account {
                    purpose,
                    account,
                    chain,
                } => {
                    tag.copy_from_slice(&[2]);
                    rest[0] = u8::try_from(purpose.number()).unwrap_or(0);
                    rest[1..5].copy_from_slice(&account.to_be_bytes());
                    rest[5] = u8::try_from(chain.number()).unwrap_or(0);
                }
            }
            rest[11..15].copy_from_slice(&index.to_be_bytes());
            Ok(ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(hash)))
        }
    }

    /// The input as a stream of choices; it reads as zeros once it is spent.
    struct Choices<'a>(core::slice::Iter<'a, u8>);

    impl Choices<'_> {
        fn spent(&self) -> bool {
            self.0.len() == 0
        }

        fn byte(&mut self) -> u8 {
            self.0.next().copied().unwrap_or(0)
        }

        fn short(&mut self) -> u16 {
            u16::from_be_bytes([self.byte(), self.byte()])
        }

        fn txid(&mut self) -> Txid {
            Txid::from_byte_array([self.byte(); 32])
        }

        fn raw(&mut self) -> Vec<u8> {
            let length = self.byte() % 12;
            (0..length).map(|_| self.byte()).collect()
        }
    }

    /// An answer to `request` made from the choices: a quarter of the
    /// addresses used, coins of any height, any transaction bytes and branch.
    fn reply(request: &Request, choices: &mut Choices<'_>) -> Response {
        match request {
            Request::History { positions, .. } => Response::History {
                positions: positions.clone(),
                answers: positions
                    .iter()
                    .map(|_| {
                        if choices.byte().is_multiple_of(4) {
                            vec![HistoryItem {
                                txid: choices.txid(),
                                height: Some(u32::from(choices.byte())),
                            }]
                        } else {
                            Vec::new()
                        }
                    })
                    .collect(),
            },
            Request::Unspent { positions, .. } => Response::Unspent {
                positions: positions.clone(),
                answers: positions
                    .iter()
                    .map(|_| {
                        (0..choices.byte() % 3)
                            .map(|_| Unspent {
                                txid: choices.txid(),
                                vout: u32::from(choices.byte() % 3),
                                amount: Amount::from_sat(u64::from(choices.short())),
                                height: if choices.byte().is_multiple_of(5) {
                                    None
                                } else {
                                    Some(u32::from(choices.byte()))
                                },
                            })
                            .collect()
                    })
                    .collect(),
            },
            Request::Transaction { txid } => Response::Transaction {
                txid: *txid,
                raw: choices.raw(),
            },
            Request::Merkle { txid, height } => Response::Merkle {
                txid: *txid,
                height: *height,
                branch: MerkleBranch::new(
                    u32::from(choices.byte()),
                    u32::from(choices.byte()),
                    (0..choices.byte() % 4)
                        .map(|_| TxMerkleNode::from_byte_array([choices.byte(); 32]))
                        .collect(),
                ),
            },
        }
    }

    fn lane_from(choices: &mut Choices<'_>) -> LaneKey {
        match choices.byte() % 3 {
            0 => LaneKey::Plan(u32::from(choices.byte() % 40)),
            1 => LaneKey::Account {
                purpose: Purpose::ALL
                    .get(usize::from(choices.byte() % 4))
                    .copied()
                    .unwrap_or(Purpose::Bip44),
                account: u32::from(choices.byte() % 8).saturating_add(3),
                chain: Chain::ALL
                    .get(usize::from(choices.byte() % 2))
                    .copied()
                    .unwrap_or(Chain::External),
            },
            _ => LaneKey::Plan(u32::from(choices.byte())),
        }
    }

    /// A response that need not be for anything asked: positions of any lane
    /// and index, a different number of answers than positions, any kind.
    fn hostile(choices: &mut Choices<'_>) -> Response {
        let count = usize::from(choices.byte() % 5);
        let positions: Vec<Position> = (0..count)
            .map(|_| Position {
                lane: lane_from(choices),
                index: if choices.byte().is_multiple_of(8) {
                    choices.short().into()
                } else {
                    u32::from(choices.byte() % 40)
                },
            })
            .collect();
        let answers = if choices.byte().is_multiple_of(8) {
            count.saturating_add(1)
        } else {
            count
        };
        match choices.byte() % 4 {
            0 => Response::History {
                positions,
                answers: (0..answers)
                    .map(|_| {
                        (0..choices.byte() % 2)
                            .map(|_| HistoryItem {
                                txid: choices.txid(),
                                height: None,
                            })
                            .collect()
                    })
                    .collect(),
            },
            1 => Response::Unspent {
                positions,
                answers: (0..answers)
                    .map(|_| {
                        (0..choices.byte() % 3)
                            .map(|_| Unspent {
                                txid: choices.txid(),
                                vout: u32::from(choices.byte() % 2),
                                amount: Amount::from_sat(u64::from(choices.short())),
                                height: Some(u32::from(choices.byte())),
                            })
                            .collect()
                    })
                    .collect(),
            },
            2 => Response::Transaction {
                txid: choices.txid(),
                raw: choices.raw(),
            },
            _ => Response::Merkle {
                txid: choices.txid(),
                height: u32::from(choices.byte()),
                branch: MerkleBranch::new(0, u32::from(choices.byte()), Vec::new()),
            },
        }
    }

    /// What must hold of an engine whatever it has been told: its numbers are
    /// ones a walk can have, the requests it makes keep to the limits and the
    /// budget, it makes none when it is complete or exhausted, and its saved
    /// state writes, reads back and resumes.
    ///
    /// # Panics
    ///
    /// If any of that fails.
    fn check(discovery: &Discovery, plan: &Plan, budget: Budget, heavy: bool) {
        let progress = discovery.progress();
        for lane in &progress.lanes {
            assert!(lane.next_index <= MAX_INDEX);
            assert!(lane.gap <= FURTHER_GAP);
            assert!(lane.hits <= lane.next_index);
            assert_eq!(lane.last_hit.is_some(), lane.hits > 0);
            assert!(
                lane.pending_unspent
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
            );
            assert!(
                lane.pending_unspent
                    .iter()
                    .all(|&index| index < lane.next_index)
            );
        }
        assert!(progress.candidates.len() <= MAX_CANDIDATES);
        let outpoints: BTreeSet<_> = progress
            .candidates
            .iter()
            .map(|candidate| (candidate.txid, candidate.vout))
            .collect();
        assert_eq!(outpoints.len(), progress.candidates.len());
        let proven = progress
            .candidates
            .iter()
            .filter(|candidate| candidate.state == CandidateState::Proven)
            .count();
        assert_eq!(proven, discovery.coins().len());
        assert_eq!(proven, progress.coins.len());
        assert!(
            progress
                .candidates
                .iter()
                .all(|c| (c.height.is_none()) == (c.state == CandidateState::Unconfirmed))
        );

        let made = discovery.next_requests(&Named);
        assert!(made.is_ok(), "the scripts of a walk can be made");
        let requests = made.unwrap_or_default();
        let remaining = u64::from(budget.max_queries).saturating_sub(progress.queries);
        let lookups: u64 = requests.iter().map(Request::lookups).sum();
        assert!(lookups <= remaining);
        for request in &requests {
            if let Request::History { positions, scripts }
            | Request::Unspent { positions, scripts } = request
            {
                assert_eq!(positions.len(), scripts.len());
                assert!(!scripts.is_empty() && scripts.len() <= MAX_BATCH);
                assert!(positions.iter().all(|position| position.index < MAX_INDEX));
            }
        }
        if progress.exhausted || progress.complete {
            assert_eq!(requests.len(), 0);
        }
        assert!(!(progress.exhausted && progress.complete));

        if heavy {
            check_saved(&progress, plan, budget);
        }
    }

    /// What must hold of the saved form of an engine's state: it writes, reads
    /// back as itself, and resumes.
    ///
    /// # Panics
    ///
    /// If it does not.
    fn check_saved(progress: &Progress, plan: &Plan, budget: Budget) {
        let written = serde_json::to_vec(progress);
        assert!(written.is_ok());
        let read = serde_json::from_slice::<Progress>(&written.unwrap_or_default());
        assert_eq!(read.as_ref().ok(), Some(progress));
        let made = Discovery::resume(progress, plan, budget);
        assert!(made.is_ok(), "a run the engine saved resumes");
        let Ok(resumed) = made else {
            return;
        };
        let again = resumed.progress();
        assert_eq!(again.lanes, progress.lanes);
        assert_eq!(again.candidates.len(), progress.candidates.len());
    }

    /// A saved run made by the engine from a fixed pattern of answers, as JSON.
    fn base_run() -> Option<&'static Vec<u8>> {
        static BASE: OnceLock<Option<Vec<u8>>> = OnceLock::new();
        BASE.get_or_init(|| {
            let plan = discovery_plan()?;
            let pattern: Vec<u8> = (0..=255).cycle().take(4096).collect();
            let mut choices = Choices(pattern.iter());
            let mut discovery = Discovery::new(plan, Budget::UNLIMITED);
            for _ in 0..6 {
                for request in discovery.next_requests(&Named).ok()? {
                    discovery.absorb(reply(&request, &mut choices)).ok()?;
                }
            }
            serde_json::to_vec(&discovery.progress()).ok()
        })
        .as_ref()
    }

    /// The runs of digits in JSON text that are numbers and not part of a
    /// string, as byte ranges. The text the engine writes has no escapes.
    fn numbers_of(text: &[u8]) -> Vec<core::ops::Range<usize>> {
        let mut found = Vec::new();
        let (mut in_string, mut start) = (false, None);
        for (at, byte) in text.iter().enumerate() {
            if *byte == b'"' {
                in_string = !in_string;
            }
            let digit = !in_string && byte.is_ascii_digit();
            match (digit, start) {
                (true, None) => start = Some(at),
                (false, Some(first)) => {
                    found.push(first..at);
                    start = None;
                }
                _ => {}
            }
        }
        found
    }

    /// Reads a saved run and, when it reads and the plan accepts it, runs the
    /// engine on a few steps from there.
    fn resume_from(progress: &Progress, plan: &Plan, data: &[u8]) {
        let budget = Budget::UNLIMITED;
        if let Ok(mut discovery) = Discovery::resume(progress, plan, budget) {
            check(&discovery, plan, budget, true);
            let mut choices = Choices(data.iter());
            for _ in 0..3 {
                let Ok(requests) = discovery.next_requests(&Named) else {
                    return;
                };
                for request in requests {
                    let _ = discovery.absorb(reply(&request, &mut choices));
                }
                check(&discovery, plan, budget, true);
            }
        }
    }

    /// Feeds the bytes as the JSON of a saved discovery run to its reader and
    /// to `resume`, and again as edits to the numbers of a saved run the engine
    /// made, which reaches the checks `resume` makes on a file that has been
    /// damaged. A run `resume` accepts must satisfy everything the engine
    /// promises of a run, and take a few steps.
    ///
    /// # Panics
    ///
    /// If a run that resumed breaks one of the promises.
    pub fn progress_resume(data: &[u8]) {
        let Some(plan) = discovery_plan() else {
            return;
        };
        if let Ok(progress) = serde_json::from_slice::<Progress>(data) {
            resume_from(&progress, plan, data);
        }
        let Some(base) = base_run() else {
            return;
        };
        let numbers = numbers_of(base);
        let mut chosen: BTreeMap<usize, &str> = BTreeMap::new();
        for edit in data.as_chunks::<3>().0.iter().take(3) {
            let pick = usize::from(u16::from_be_bytes([edit[0], edit[1]]));
            let text = match edit[2] % 8 {
                0 => "0",
                1 => "1",
                2 => "20",
                3 => "100",
                4 => "1000",
                5 => "10000",
                6 => "10001",
                _ => "4294967295",
            };
            if let Some(at) = pick.checked_rem(numbers.len()) {
                chosen.insert(at, text);
            }
        }
        let mut edited = Vec::with_capacity(base.len());
        let mut copied = 0;
        for (at, text) in chosen {
            let Some(span) = numbers.get(at) else {
                continue;
            };
            edited.extend_from_slice(base.get(copied..span.start).unwrap_or_default());
            edited.extend_from_slice(text.as_bytes());
            copied = span.end;
        }
        edited.extend_from_slice(base.get(copied..).unwrap_or_default());
        if let Ok(progress) = serde_json::from_slice::<Progress>(&edited) {
            resume_from(&progress, plan, data);
        }
    }

    /// Feeds the bytes to a discovery engine as a script of steps: answers made
    /// to the requests it makes (some of them damaged: dropped parts, a changed
    /// order, said twice), answers that were never asked for, a search for
    /// more, and the proving of what has arrived against the genesis header
    /// chain.
    ///
    /// A step the engine refuses leaves its state, counters included, exactly
    /// as it was. A step it takes adds exactly the answer's lookups and size to
    /// the counters. After every step [`check`] holds.
    ///
    /// # Panics
    ///
    /// If a step breaks one of those promises.
    pub fn history_absorb(data: &[u8]) {
        let Some(plan) = discovery_plan() else {
            return;
        };
        let mut choices = Choices(data.iter());
        let budget = Budget {
            max_queries: u32::from(choices.short()).saturating_mul(4),
            max_bytes: u64::from(choices.short()).saturating_mul(64),
        };
        let mut discovery = Discovery::new(plan, budget);
        let chain = HeaderChain::new(Network::Mainnet);
        for round in 0..32_u8 {
            if choices.spent() {
                break;
            }
            let before = discovery.progress();
            let step = choices.byte();
            let response = match step % 8 {
                0..=3 => {
                    let Ok(requests) = discovery.next_requests(&Named) else {
                        return;
                    };
                    let Some(request) = requests.get(usize::from(step / 8) % 4) else {
                        continue;
                    };
                    let mut response = reply(request, &mut choices);
                    match choices.byte() % 4 {
                        1 => match &mut response {
                            Response::History { answers, .. } => {
                                answers.pop();
                            }
                            Response::Unspent { answers, .. } => {
                                answers.pop();
                            }
                            Response::Transaction { .. } | Response::Merkle { .. } => {}
                        },
                        2 => match &mut response {
                            Response::History { positions, answers } => {
                                positions.reverse();
                                answers.reverse();
                            }
                            Response::Unspent { positions, answers } => {
                                positions.reverse();
                                answers.reverse();
                            }
                            Response::Transaction { .. } | Response::Merkle { .. } => {}
                        },
                        3 => {
                            let _ = discovery.absorb(response.clone());
                        }
                        _ => {}
                    }
                    response
                }
                4 | 5 => hostile(&mut choices),
                6 => {
                    discovery.search_further();
                    check(&discovery, plan, budget, round % 4 == 0);
                    continue;
                }
                _ => {
                    let _ = discovery.prove_pending(&Named, &chain);
                    check(&discovery, plan, budget, round % 4 == 0);
                    continue;
                }
            };
            let before = if step % 8 < 4 {
                discovery.progress()
            } else {
                before
            };
            let (lookups, size) = (response.lookups(), response.size());
            match discovery.absorb(response) {
                Err(_) => assert_eq!(discovery.progress(), before),
                Ok(after) => {
                    assert_eq!(after, discovery.progress());
                    assert_eq!(after.queries, before.queries.saturating_add(lookups));
                    assert_eq!(after.bytes, before.bytes.saturating_add(size));
                }
            }
            check(&discovery, plan, budget, round % 4 == 0);
        }
        check(&discovery, plan, budget, true);
    }
}
