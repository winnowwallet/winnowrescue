//! Recorded chains for the header and proof tests: the files under
//! `vectors/bitcoin-mainnet/` and `vectors/bitcoin-regtest/`, parsed, and
//! chains built from them once and shared.

use std::str::FromStr;
use std::sync::OnceLock;

use bitcoin::BlockHash;
use bitcoin::block::Header;
use bitcoin::consensus::deserialize;
use bitcoin::hex::FromHex;

use super::vector;
use crate::{HEADER_SIZE, HeaderChain, Network};

/// One raw header, as a line of a header file holds it.
pub type Raw = [u8; HEADER_SIZE];

/// The raw headers of a file: one lowercase hex line each.
pub fn rows(file: &str) -> Vec<Raw> {
    vector(file)
        .lines()
        .map(|line| {
            <Vec<u8>>::from_hex(line.trim())
                .unwrap()
                .try_into()
                .expect("a header line is 80 bytes")
        })
        .collect()
}

/// The rows laid one after another, as `blockchain.block.headers` returns them.
pub fn concat(rows: &[Raw]) -> Vec<u8> {
    rows.concat()
}

/// A raw header as a `Header`.
pub fn header(raw: &Raw) -> Header {
    deserialize(raw).unwrap()
}

/// The rows as `Header`s.
pub fn headers(rows: &[Raw]) -> Vec<Header> {
    rows.iter().map(header).collect()
}

/// Mutable access to the fields of a raw header by their place on the wire.
pub mod at {
    use std::ops::Range;

    pub const VERSION: Range<usize> = 0..4;
    pub const PREV: Range<usize> = 4..36;
    pub const MERKLE_ROOT: Range<usize> = 36..68;
    pub const TIME: Range<usize> = 68..72;
    pub const BITS: Range<usize> = 72..76;
    pub const NONCE: Range<usize> = 76..80;
}

/// `raw` with one bit of the field at `field` flipped.
pub fn flipped(raw: &Raw, field: std::ops::Range<usize>, bit: u32) -> Raw {
    let mut copy = *raw;
    copy[field.start + (bit / 8) as usize] ^= 1 << (bit % 8);
    copy
}

/// The heights and hashes of `block-hashes.txt`.
pub fn block_hashes() -> Vec<(u32, BlockHash)> {
    vector("bitcoin-mainnet/block-hashes.txt")
        .lines()
        .map(|line| {
            let (height, hash) = line.split_once(' ').unwrap();
            (height.parse().unwrap(), BlockHash::from_str(hash).unwrap())
        })
        .collect()
}

pub const MAINNET_FILES: [(&str, u32); 4] = [
    ("bitcoin-mainnet/headers-0-4032.hex", 0),
    ("bitcoin-mainnet/headers-11100-11112.hex", 11100),
    ("bitcoin-mainnet/headers-858816-860831.hex", 858_816),
    ("bitcoin-mainnet/headers-860832-864864.hex", 860_832),
];

/// The recorded mainnet header at `height`, from whichever file holds it.
pub fn recorded(height: u32) -> Header {
    for (file, first) in MAINNET_FILES {
        let held = rows(file);
        let last = first + u32::try_from(held.len()).unwrap() - 1;
        if (first..=last).contains(&height) {
            return header(&held[(height - first) as usize]);
        }
    }
    panic!("no recorded header at {height}")
}

pub const REGTEST_FILE: &str = "bitcoin-regtest/headers-0-2020.hex";

/// The 2021 recorded regtest rows: genesis, then 2020 mined blocks.
pub fn regtest_rows() -> Vec<Raw> {
    rows(REGTEST_FILE)
}

/// Mines `header` on regtest: counts the nonce up until its hash is below its
/// target, which takes about two tries.
pub fn grind(header: &mut Header) {
    while header.validate_pow(header.target()).is_err() {
        header.nonce = header.nonce.wrapping_add(1);
    }
}

/// The median of the times of the (up to eleven) rows before `height`, as the
/// rule is written: sort them and take the one at half their number.
pub fn median_before(rows: &[Raw], height: usize) -> u32 {
    let mut times: Vec<u32> = rows[height.saturating_sub(11)..height]
        .iter()
        .map(|raw| header(raw).time)
        .collect();
    times.sort_unstable();
    times[times.len() / 2]
}

/// Mainnet from genesis to height 4032, absorbed in one call.
pub fn early_mainnet() -> HeaderChain {
    static CHAIN: OnceLock<HeaderChain> = OnceLock::new();
    CHAIN
        .get_or_init(|| {
            let all = rows(MAINNET_FILES[0].0);
            let mut chain = HeaderChain::new(Network::Mainnet);
            assert_eq!(chain.absorb(&concat(&all[1..])), Ok(4032));
            chain
        })
        .clone()
}

/// The retarget period before 860832, as a chain that stops at 860831. Only
/// what the next header's checks look at is behind it, so it is a window and
/// not the chain from genesis.
pub fn modern_seed() -> HeaderChain {
    HeaderChain::from_window(
        Network::Mainnet,
        858_816,
        headers(&rows(MAINNET_FILES[2].0)),
    )
}

/// The rows of the modern range, 860832 to 864864.
pub fn modern_rows() -> Vec<Raw> {
    rows(MAINNET_FILES[3].0)
}

/// The modern seed with the whole modern range absorbed: a window from 858816
/// to 864864 that spans three retargets at real difficulty.
pub fn modern_mainnet() -> HeaderChain {
    static CHAIN: OnceLock<HeaderChain> = OnceLock::new();
    CHAIN
        .get_or_init(|| {
            let mut chain = modern_seed();
            assert_eq!(chain.absorb(&concat(&modern_rows())), Ok(4033));
            chain
        })
        .clone()
}

/// The recorded regtest chain, genesis to height 2020.
pub fn regtest_full() -> HeaderChain {
    static CHAIN: OnceLock<HeaderChain> = OnceLock::new();
    CHAIN
        .get_or_init(|| {
            let all = regtest_rows();
            let mut chain = HeaderChain::new(Network::Regtest);
            assert_eq!(chain.absorb(&concat(&all[1..])), Ok(2020));
            chain
        })
        .clone()
}
