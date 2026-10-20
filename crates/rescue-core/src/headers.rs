//! The header chain: every block header from genesis, checked as it arrives.
//!
//! A server that lists a coin also hands over the headers that bury it. None
//! of that is trusted. A [`HeaderChain`] starts at the network's genesis
//! header and takes headers only after checking each one: it names the tip as
//! its parent, carries the difficulty the rules require at its height, hashes
//! below that target, and is later than the median of the eleven before it.
//! On mainnet the chain also has to pass through Bitcoin Core's old
//! checkpoints. A coin proved against this chain was mined by someone who did
//! the work, so a server can hide coins and never invent them.
//!
//! What it does not do, because it has no clock: it does not refuse a header
//! whose time lies in the future. And on signet, whose blocks are also signed
//! by the network's key, only the proof of work is checked, since the
//! signature sits in the block's coinbase and a header does not carry it.
//!
//! The chain keeps the headers as a `Vec<Header>`: 80 bytes each, the same as
//! the wire form, so a mainnet chain of a million headers is about 80 MB.

use core::fmt;

use bitcoin::block::Header;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::deserialize;
use bitcoin::consensus::encode::serialize;
use bitcoin::consensus::params::Params;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::pow::{CompactTarget, Target, Work};
use bitcoin::{BlockHash, block::ValidationError};

use crate::error::HeaderError;
use crate::network::Network;

/// The size of one raw header.
pub const HEADER_SIZE: usize = 80;

/// How many headers share one difficulty: the retarget interval of mainnet,
/// signet and regtest alike.
const RETARGET_INTERVAL: u32 = 2016;

/// How many earlier timestamps the median is taken over.
const MEDIAN_SPAN: usize = 11;

/// The fixed bytes of a saved chain before its headers: the network and the
/// count.
const CACHE_HEAD: usize = 5;

/// The bytes of the checksum that ends a saved chain.
const CACHE_TAIL: usize = 32;

/// The mainnet checkpoints of Bitcoin Core: a height and the hash of the block
/// there, as the block hash is usually written. Copied from the
/// `checkpointData` of `src/kernel/chainparams.cpp` in the last Core release
/// that has it, v29.4 (the file is kept in `vectors/bitcoin-core-v29.4/`, and
/// a test reads the table back out of it so the two cannot drift). A header at
/// one of these heights must be exactly this block, so a server on another
/// chain is caught at the first checkpoint it crosses.
pub const MAINNET_CHECKPOINTS: [(u32, &str); 13] = [
    (
        11_111,
        "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d",
    ),
    (
        33_333,
        "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6",
    ),
    (
        74_000,
        "0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20",
    ),
    (
        105_000,
        "00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97",
    ),
    (
        134_444,
        "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe",
    ),
    (
        168_000,
        "000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763",
    ),
    (
        193_000,
        "000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317",
    ),
    (
        210_000,
        "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e",
    ),
    (
        216_116,
        "00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e",
    ),
    (
        225_430,
        "00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932",
    ),
    (
        250_000,
        "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214",
    ),
    (
        279_000,
        "0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40",
    ),
    (
        295_000,
        "00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983",
    ),
];

/// A header chain for one network, from its genesis header.
///
/// Headers go in through [`absorb`](Self::absorb) or come back from a saved
/// copy through [`from_bytes`](Self::from_bytes), and both run the same
/// checks. There is no other way to add one.
#[derive(Clone)]
pub struct HeaderChain {
    network: Network,
    /// The height of `headers[0]`. Always 0 for a chain a host can build; the
    /// tests start a chain partway along to absorb a recorded stretch of
    /// mainnet without the million headers before it.
    base: u32,
    headers: Vec<Header>,
    tip_hash: BlockHash,
    /// The total work of the chain, 256 bits big-endian, saturating at the
    /// largest value (a total no proof of work could ever reach).
    work: [u8; 32],
}

impl fmt::Debug for HeaderChain {
    /// Prints the network, the height and the tip, never the headers: a mainnet
    /// chain is a million of them.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeaderChain")
            .field("network", &self.network)
            .field("height", &self.height())
            .field("tip", &self.tip_hash)
            .finish_non_exhaustive()
    }
}

impl HeaderChain {
    /// A chain holding only the genesis header of `network`.
    #[must_use]
    pub fn new(network: Network) -> Self {
        let genesis = genesis_block(network.to_bitcoin()).header;
        Self {
            network,
            base: 0,
            tip_hash: genesis.block_hash(),
            work: genesis.work().to_be_bytes(),
            headers: vec![genesis],
        }
    }

    /// A chain that starts at `base` with the given headers, which the caller
    /// vouches for. Tests only: it is how a recorded stretch of mainnet far
    /// from genesis is absorbed without everything before it.
    #[cfg(test)]
    pub(crate) fn from_window(network: Network, base: u32, headers: Vec<Header>) -> Self {
        let tip_hash = headers.last().map_or_else(
            || genesis_block(network.to_bitcoin()).header.block_hash(),
            Header::block_hash,
        );
        let mut work = [0; 32];
        for header in &headers {
            add_work(&mut work, &header.work().to_be_bytes());
        }
        Self {
            network,
            base,
            headers,
            tip_hash,
            work,
        }
    }

    /// The network this chain is for.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Takes concatenated raw 80-byte headers (what Electrum's
    /// `blockchain.block.headers` and `blockchain.block.header` return) that
    /// continue the chain, and returns how many it took.
    ///
    /// Every header is checked before it is kept: it must name the tip as its
    /// parent, carry the difficulty the rules require at its height (the
    /// parent's, except at every 2016th height, where it is recomputed from the
    /// period before; regtest never retargets), hash below that target, be
    /// later than the median time of the eleven before it, and, on mainnet,
    /// be the checkpointed block where there is a checkpoint.
    ///
    /// The call is all or nothing: if any header is refused the chain is left
    /// exactly as it was, so a server that lies half way through a batch
    /// leaves nothing of the batch behind.
    ///
    /// # Errors
    ///
    /// [`HeaderError::BadLength`] when the bytes are not a whole number of
    /// headers; otherwise the [`HeaderError`] that names the first header
    /// refused and the height it would have had.
    pub fn absorb(&mut self, raw: &[u8]) -> Result<usize, HeaderError> {
        let kept = (self.headers.len(), self.tip_hash, self.work);
        let taken = self.extend(raw);
        if taken.is_err() {
            self.headers.truncate(kept.0);
            self.tip_hash = kept.1;
            self.work = kept.2;
        }
        taken
    }

    /// The body of [`absorb`](Self::absorb): leaves whatever it appended when
    /// it fails, for `absorb` to take back.
    fn extend(&mut self, raw: &[u8]) -> Result<usize, HeaderError> {
        let (records, rest) = raw.as_chunks::<HEADER_SIZE>();
        if !rest.is_empty() {
            return Err(HeaderError::BadLength);
        }
        let params = Params::new(self.network.to_bitcoin());
        self.headers.reserve(records.len());
        let mut taken: usize = 0;
        for record in records {
            let header: Header =
                deserialize(record.as_slice()).map_err(|_| HeaderError::BadLength)?;
            let hash = self.check_next(&params, &header)?;
            self.headers.push(header);
            self.tip_hash = hash;
            add_work(&mut self.work, &header.work().to_be_bytes());
            taken = taken.checked_add(1).ok_or(HeaderError::TooLong)?;
        }
        Ok(taken)
    }

    /// Checks `header` as the next one after the tip and returns its hash.
    fn check_next(&self, params: &Params, header: &Header) -> Result<BlockHash, HeaderError> {
        let height = self.next_height()?;
        if header.prev_blockhash != self.tip_hash {
            return Err(HeaderError::NotLinked { height });
        }
        let expected = self.expected_bits(params, height)?;
        if header.bits != expected {
            return Err(HeaderError::WrongTarget { height });
        }
        let hash = header
            .validate_pow(Target::from_compact(expected))
            .map_err(|refusal| match refusal {
                ValidationError::BadProofOfWork => HeaderError::BadProofOfWork { height },
                _ => HeaderError::WrongTarget { height },
            })?;
        if header.time <= self.median_time_past() {
            return Err(HeaderError::TimeTooOld { height });
        }
        if !self.passes_checkpoint(height, hash) {
            return Err(HeaderError::CheckpointMismatch { height });
        }
        Ok(hash)
    }

    /// The height the next header would have.
    fn next_height(&self) -> Result<u32, HeaderError> {
        u32::try_from(self.headers.len())
            .ok()
            .and_then(|held| self.base.checked_add(held))
            .ok_or(HeaderError::TooLong)
    }

    /// The compact target the header at `height` must carry: the tip's, except
    /// at a retarget height, where it comes from the period before.
    fn expected_bits(&self, params: &Params, height: u32) -> Result<CompactTarget, HeaderError> {
        let wrong = HeaderError::WrongTarget { height };
        let tip = self.headers.last().ok_or(wrong)?;
        let retargets =
            !params.no_pow_retargeting && height.checked_rem(RETARGET_INTERVAL) == Some(0);
        if !retargets {
            return Ok(tip.bits);
        }
        let first = height
            .checked_sub(RETARGET_INTERVAL)
            .and_then(|at| self.header_at(at))
            .ok_or(wrong)?;
        Ok(retarget(&first, tip, params))
    }

    /// The median of the times of up to eleven headers before the next one.
    fn median_time_past(&self) -> u32 {
        let mut times = [0_u32; MEDIAN_SPAN];
        let held = times
            .iter_mut()
            .zip(self.headers.iter().rev())
            .map(|(slot, header)| *slot = header.time)
            .count();
        let recent = times.get_mut(..held).unwrap_or_default();
        recent.sort_unstable();
        recent.get(held / 2).copied().unwrap_or_default()
    }

    /// Whether `hash` is the block the checkpoint at `height` names, or there
    /// is no checkpoint at that height. A malformed table entry would refuse
    /// every header at its height; the tests parse the whole table.
    fn passes_checkpoint(&self, height: u32, hash: BlockHash) -> bool {
        if !self.network.is_mainnet() {
            return true;
        }
        MAINNET_CHECKPOINTS
            .binary_search_by_key(&height, |&(checkpoint, _)| checkpoint)
            .map_or(true, |at| {
                MAINNET_CHECKPOINTS
                    .get(at)
                    .is_some_and(|(_, wanted)| wanted.parse::<BlockHash>().is_ok_and(|w| w == hash))
            })
    }

    /// The height of the tip. The genesis header alone is height 0.
    #[must_use]
    pub fn height(&self) -> u32 {
        let held = u32::try_from(self.headers.len().saturating_sub(1)).unwrap_or(u32::MAX);
        self.base.saturating_add(held)
    }

    /// The tip header.
    #[must_use]
    pub fn tip(&self) -> Header {
        self.headers
            .last()
            .copied()
            .unwrap_or_else(|| genesis_block(self.network.to_bitcoin()).header)
    }

    /// The hash of the tip.
    #[must_use]
    pub const fn tip_hash(&self) -> BlockHash {
        self.tip_hash
    }

    /// The header at `height`, or `None` above the tip.
    #[must_use]
    pub fn header_at(&self, height: u32) -> Option<Header> {
        let index = usize::try_from(height.checked_sub(self.base)?).ok()?;
        self.headers.get(index).copied()
    }

    /// The hash of the block at `height`, or `None` above the tip.
    #[must_use]
    pub fn block_hash_at(&self, height: u32) -> Option<BlockHash> {
        self.header_at(height).map(|header| header.block_hash())
    }

    /// The total work of the chain: the sum, over every header, of the work its
    /// target stands for. The heavier of two chains is the one to follow.
    #[must_use]
    pub fn work(&self) -> Work {
        Work::from_be_bytes(self.work)
    }

    /// The chain as bytes to keep in the host's public cache: one byte for the
    /// network (0 mainnet, 1 signet, 2 regtest), the number of headers after
    /// genesis as four bytes little-endian, those headers raw, then the
    /// SHA-256 of everything before it.
    ///
    /// The checksum catches a damaged file. It does not vouch for the content:
    /// [`from_bytes`](Self::from_bytes) checks every header again.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let after_genesis = self.headers.get(1..).unwrap_or_default();
        let count = u32::try_from(after_genesis.len()).unwrap_or(u32::MAX);
        let mut bytes = Vec::with_capacity(
            CACHE_HEAD
                .saturating_add(after_genesis.len().saturating_mul(HEADER_SIZE))
                .saturating_add(CACHE_TAIL),
        );
        bytes.push(network_byte(self.network));
        bytes.extend_from_slice(&count.to_le_bytes());
        for header in after_genesis {
            bytes.extend_from_slice(&serialize(header));
        }
        let checksum = sha256::Hash::hash(&bytes);
        bytes.extend_from_slice(checksum.as_byte_array());
        bytes
    }

    /// Rebuilds a chain from [`to_bytes`](Self::to_bytes), checking every
    /// header again as [`absorb`](Self::absorb) would: a damaged or doctored
    /// cache is refused, never trusted.
    ///
    /// # Errors
    ///
    /// [`HeaderError::CacheTruncated`], [`HeaderError::CacheChecksum`],
    /// [`HeaderError::CacheNetwork`] or [`HeaderError::CacheCount`] when the
    /// bytes are not a cache of `network`; otherwise the error of the first
    /// header that fails its checks.
    pub fn from_bytes(network: Network, bytes: &[u8]) -> Result<Self, HeaderError> {
        let split = bytes
            .len()
            .checked_sub(CACHE_TAIL)
            .filter(|&body| body >= CACHE_HEAD)
            .ok_or(HeaderError::CacheTruncated)?;
        let (body, checksum) = bytes.split_at(split);
        if sha256::Hash::hash(body).as_byte_array().as_slice() != checksum {
            return Err(HeaderError::CacheChecksum);
        }
        let (head, headers) = body.split_at(CACHE_HEAD);
        let (&saved_network, count) = head.split_first().ok_or(HeaderError::CacheTruncated)?;
        if saved_network != network_byte(network) {
            return Err(HeaderError::CacheNetwork);
        }
        let count = <[u8; 4]>::try_from(count)
            .map(u32::from_le_bytes)
            .map_err(|_| HeaderError::CacheTruncated)?;
        let expected = usize::try_from(count)
            .ok()
            .and_then(|count| count.checked_mul(HEADER_SIZE));
        if expected != Some(headers.len()) {
            return Err(HeaderError::CacheCount);
        }
        let mut chain = Self::new(network);
        chain.absorb(headers)?;
        Ok(chain)
    }
}

/// The byte a saved chain starts with.
const fn network_byte(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0,
        Network::Signet => 1,
        Network::Regtest => 2,
    }
}

/// The compact target after a retarget, given the first and the last header of
/// the period that ended.
///
/// rust-bitcoin subtracts the two times as unsigned numbers, which traps when
/// the last time is before the first. Consensus allows that (times need only
/// pass the median rule) and clamps the span to its minimum, so it is handed
/// over as a span of zero, which clamps the same way.
pub(crate) fn retarget(first: &Header, last: &Header, params: &Params) -> CompactTarget {
    if last.time >= first.time {
        CompactTarget::from_header_difficulty_adjustment(*first, *last, params)
    } else {
        CompactTarget::from_next_work_required(last.bits, 0, params)
    }
}

/// Adds `more` to `total`, both 256 bits big-endian; a sum too large for 256
/// bits stays at the largest value.
fn add_work(total: &mut [u8; 32], more: &[u8; 32]) {
    let mut carry = false;
    let mut sum = [0_u8; 32];
    for ((slot, have), add) in sum.iter_mut().zip(total.iter()).zip(more).rev() {
        let (partial, first) = have.overflowing_add(*add);
        let (digit, second) = partial.overflowing_add(u8::from(carry));
        *slot = digit;
        carry = first || second;
    }
    *total = if carry { [u8::MAX; 32] } else { sum };
}
