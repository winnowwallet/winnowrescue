//! The header chain against recorded mainnet and regtest headers, the
//! checkpoint table of Bitcoin Core, and the saved form of a chain.

use std::str::FromStr;

use bitcoin::consensus::encode::serialize;
use bitcoin::consensus::params::Params;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::pow::{CompactTarget, Work};
use bitcoin::{BlockHash, block::Header};

use super::chains::{
    MAINNET_FILES, Raw, at, block_hashes, concat, early_mainnet, flipped, grind, header, headers,
    median_before, modern_mainnet, modern_rows, modern_seed, recorded, regtest_full, regtest_rows,
    rows,
};
use super::vector;
use crate::headers::retarget;
use crate::{HEADER_SIZE, HeaderChain, HeaderError, MAINNET_CHECKPOINTS, Network};

fn genesis_hash_asserted_by(class: &str) -> BlockHash {
    let text = vector("bitcoin-core-v29.4/chainparams.cpp");
    let (_, after) = text.split_once(class).unwrap();
    let (_, line) = after.split_once("hashGenesisBlock == uint256{\"").unwrap();
    BlockHash::from_str(line.split_once('"').unwrap().0).unwrap()
}

#[test]
fn a_header_takes_eighty_bytes_in_memory_as_on_the_wire() {
    assert_eq!(std::mem::size_of::<Header>(), HEADER_SIZE);
}

#[test]
fn a_chain_prints_its_tip_and_not_its_headers() {
    let text = format!("{:?}", regtest_full());
    assert!(text.len() < 200, "{text}");
    assert!(text.contains("2020"));
}

#[test]
fn each_chain_starts_at_the_genesis_core_asserts_for_its_network() {
    for (network, class) in [
        (Network::Mainnet, "class CMainParams"),
        (Network::Signet, "class SigNetParams"),
        (Network::Regtest, "class CRegTestParams"),
    ] {
        let chain = HeaderChain::new(network);
        assert_eq!(chain.network(), network);
        assert_eq!(chain.height(), 0);
        assert_eq!(
            chain.block_hash_at(0),
            Some(genesis_hash_asserted_by(class)),
            "{network:?}"
        );
        assert_eq!(chain.tip_hash(), genesis_hash_asserted_by(class));
        assert_eq!(chain.header_at(0), Some(chain.tip()));
        assert_eq!(chain.header_at(1), None);
        assert_eq!(chain.block_hash_at(1), None);
    }
}

#[test]
fn the_recorded_genesis_headers_are_the_ones_the_chains_start_with() {
    let mainnet = rows(MAINNET_FILES[0].0);
    assert_eq!(
        header(&mainnet[0]),
        HeaderChain::new(Network::Mainnet).tip()
    );
    let regtest = regtest_rows();
    assert_eq!(
        header(&regtest[0]),
        HeaderChain::new(Network::Regtest).tip()
    );
    assert_eq!(
        serialize(&HeaderChain::new(Network::Regtest).tip()),
        regtest[0]
    );
}

#[test]
fn the_checkpoint_table_is_the_one_in_bitcoin_core() {
    let text = vector("bitcoin-core-v29.4/chainparams.cpp");
    // The main network's class comes first in the file and so does its table,
    // which runs to the first line that is only `};`.
    let (_, after) = text.split_once("checkpointData = {").unwrap();
    let mut parsed = Vec::new();
    for line in after.lines().map(str::trim) {
        if line == "};" {
            break;
        }
        if let Some((height, rest)) = line.strip_prefix('{').and_then(|l| l.split_once(',')) {
            let hash = rest.split_once("uint256{\"").unwrap().1;
            parsed.push((
                height.trim().parse::<u32>().unwrap(),
                hash.split_once('"').unwrap().0.to_owned(),
            ));
        }
    }
    let ours: Vec<(u32, String)> = MAINNET_CHECKPOINTS
        .iter()
        .map(|&(height, hash)| (height, hash.to_owned()))
        .collect();
    assert_eq!(ours, parsed);
    assert_eq!(parsed.len(), 13);
    assert!(parsed.windows(2).all(|pair| pair[0].0 < pair[1].0));
    for (_, hash) in MAINNET_CHECKPOINTS {
        BlockHash::from_str(hash).unwrap();
    }
}

#[test]
fn recorded_headers_have_the_hashes_a_second_source_gave() {
    let listed = block_hashes();
    assert!(listed.len() >= 12);
    for (height, hash) in listed {
        assert_eq!(recorded(height).block_hash(), hash, "height {height}");
    }
    // The checkpoint at 11111 is in the recorded window.
    assert_eq!(
        recorded(11_111).block_hash(),
        BlockHash::from_str(MAINNET_CHECKPOINTS[0].1).unwrap()
    );
}

#[test]
fn mainnet_from_genesis_to_4032_is_absorbed_whole_or_in_pieces() {
    let all = rows(MAINNET_FILES[0].0);
    let whole = early_mainnet();
    assert_eq!(whole.height(), 4032);
    assert_eq!(whole.tip(), header(&all[4032]));
    for (height, hash) in block_hashes().into_iter().filter(|&(h, _)| h <= 4032) {
        assert_eq!(whole.block_hash_at(height), Some(hash), "height {height}");
    }
    assert_eq!(whole.header_at(4033), None);

    let mut pieces = HeaderChain::new(Network::Mainnet);
    let mut next = 1;
    for size in [1, 2, 7, 2015, 2007] {
        let chunk = &all[next..next + size];
        assert_eq!(pieces.absorb(&concat(chunk)), Ok(size));
        next += size;
    }
    assert_eq!(next, 4033);
    assert_eq!(pieces.to_bytes(), whole.to_bytes());
    assert_eq!(pieces.absorb(&[]), Ok(0));
}

#[test]
fn the_genesis_header_is_not_taken_a_second_time() {
    let all = rows(MAINNET_FILES[0].0);
    let mut chain = HeaderChain::new(Network::Mainnet);
    assert_eq!(
        chain.absorb(&concat(&all[..3])),
        Err(HeaderError::NotLinked { height: 1 })
    );
    assert_eq!(chain.height(), 0);
}

/// A fresh mainnet chain's saved form, to compare a refused chain with.
fn untouched() -> Vec<u8> {
    HeaderChain::new(Network::Mainnet).to_bytes()
}

#[test]
fn a_flipped_bit_is_refused_at_its_header_and_leaves_nothing_of_the_batch() {
    let all = rows(MAINNET_FILES[0].0);
    let refusals = [
        (at::VERSION, HeaderError::BadProofOfWork { height: 100 }),
        (at::PREV, HeaderError::NotLinked { height: 100 }),
        (at::MERKLE_ROOT, HeaderError::BadProofOfWork { height: 100 }),
        (at::TIME, HeaderError::BadProofOfWork { height: 100 }),
        (at::BITS, HeaderError::WrongTarget { height: 100 }),
        (at::NONCE, HeaderError::BadProofOfWork { height: 100 }),
    ];
    for (field, refusal) in refusals {
        let mut damaged = all.clone();
        damaged[100] = flipped(&damaged[100], field.clone(), 3);
        let mut chain = HeaderChain::new(Network::Mainnet);
        assert_eq!(
            chain.absorb(&concat(&damaged[1..=200])),
            Err(refusal),
            "{field:?}"
        );
        // All or nothing: the 99 good headers before it are not kept.
        assert_eq!(chain.height(), 0);
        assert_eq!(chain.to_bytes(), untouched());
        assert_eq!(
            chain.tip_hash(),
            HeaderChain::new(Network::Mainnet).tip_hash()
        );
        // The good headers still go in afterwards.
        assert_eq!(chain.absorb(&concat(&all[1..=200])), Ok(200));
    }
}

#[test]
fn a_swapped_pair_a_missing_header_and_a_stranger_are_refused() {
    let all = rows(MAINNET_FILES[0].0);
    let mut swapped = all.clone();
    swapped.swap(50, 51);
    let mut missing = all.clone();
    missing.remove(70);
    let cases = [
        (swapped, HeaderError::NotLinked { height: 50 }),
        (missing, HeaderError::NotLinked { height: 70 }),
    ];
    for (rows, refusal) in cases {
        let mut chain = HeaderChain::new(Network::Mainnet);
        assert_eq!(chain.absorb(&concat(&rows[1..200])), Err(refusal));
        assert_eq!(chain.height(), 0);
    }
    // A header of the modern chain, and one of the regtest chain, on genesis.
    for stranger in [modern_rows()[0], regtest_rows()[1]] {
        let mut chain = HeaderChain::new(Network::Mainnet);
        assert_eq!(
            chain.absorb(&stranger),
            Err(HeaderError::NotLinked { height: 1 })
        );
    }
}

#[test]
fn bytes_that_are_not_whole_headers_are_refused() {
    let all = rows(MAINNET_FILES[0].0);
    let good = concat(&all[1..=10]);
    for bytes in [
        &good[..good.len() - 1],
        &[good.clone(), vec![0]].concat()[..],
        &[0_u8; 79][..],
    ] {
        let mut chain = HeaderChain::new(Network::Mainnet);
        assert_eq!(chain.absorb(bytes), Err(HeaderError::BadLength));
        assert_eq!(chain.height(), 0);
    }
}

#[test]
fn the_modern_range_is_absorbed_through_three_retargets_at_real_difficulty() {
    let chain = modern_mainnet();
    assert_eq!(chain.height(), 864_864);
    for (height, hash) in block_hashes().into_iter().filter(|&(h, _)| h >= 858_816) {
        assert_eq!(chain.block_hash_at(height), Some(hash), "height {height}");
    }
    for retarget_height in [860_832, 862_848, 864_864] {
        let (before, after) = (
            chain.header_at(retarget_height - 1).unwrap(),
            chain.header_at(retarget_height).unwrap(),
        );
        // These are real changes of difficulty, not a clamp at a limit.
        assert_ne!(before.bits, after.bits, "{retarget_height}");
    }
    // Inside a period the target is the previous header's.
    for height in [860_833, 861_000, 862_847, 862_849, 864_863] {
        assert_eq!(
            chain.header_at(height).unwrap().bits,
            chain.header_at(height - 1).unwrap().bits
        );
    }
    // Below the window nothing is held.
    assert_eq!(chain.header_at(858_815), None);
    assert!(chain.header_at(858_816).is_some());
}

#[test]
fn the_early_retargets_at_the_limit_are_accepted_too() {
    let chain = early_mainnet();
    // Difficulty 1 is also the lowest there is: 2016 and 4032 stay at it.
    let limit = chain.header_at(0).unwrap().bits;
    for height in [2015, 2016, 2017, 4031, 4032] {
        assert_eq!(chain.header_at(height).unwrap().bits, limit);
    }
}

#[test]
fn a_flipped_bit_or_a_swapped_pair_in_the_modern_range_is_refused() {
    let all = modern_rows();
    let mut damaged = all.clone();
    damaged[1000] = flipped(&damaged[1000], at::NONCE, 17);
    let mut chain = modern_seed();
    assert_eq!(
        chain.absorb(&concat(&damaged)),
        Err(HeaderError::BadProofOfWork { height: 861_832 })
    );
    assert_eq!(chain.height(), 860_831);

    let mut swapped = all.clone();
    swapped.swap(3000, 3001);
    assert_eq!(
        chain.absorb(&concat(&swapped)),
        Err(HeaderError::NotLinked { height: 863_832 })
    );
    assert_eq!(chain.height(), 860_831);
    assert_eq!(chain.absorb(&concat(&all)), Ok(4033));
}

#[test]
fn the_modern_range_after_a_bad_target_is_refused() {
    let all = modern_rows();

    // The period it retargets from began at a different time than it did, so
    // the difficulty it asks for is not the one the real header carries. (The
    // tip stays the real one, so the first header still links.)
    let mut seed = headers(&rows(MAINNET_FILES[2].0));
    seed[0].time -= 600_000;
    let mut tampered = HeaderChain::from_window(Network::Mainnet, 858_816, seed);
    assert_eq!(
        tampered.absorb(&concat(&all)),
        Err(HeaderError::WrongTarget { height: 860_832 })
    );
    assert_eq!(tampered.height(), 860_831);

    // A retarget header that kept the old difficulty.
    let mut kept = all.clone();
    let old = kept[2015][at::BITS].to_vec();
    kept[2016][at::BITS].copy_from_slice(&old);
    let mut chain = modern_seed();
    assert_eq!(
        chain.absorb(&concat(&kept)),
        Err(HeaderError::WrongTarget { height: 862_848 })
    );

    // A header in the middle of a period that carries an easier target.
    let mut easy = all.clone();
    easy[500][at::BITS].copy_from_slice(&0x1d00_ffff_u32.to_le_bytes());
    assert_eq!(
        modern_seed().absorb(&concat(&easy)),
        Err(HeaderError::WrongTarget { height: 861_332 })
    );
}

#[test]
fn the_difficulty_must_be_written_the_way_the_rules_write_it() {
    // 0x2000ff00 and 0x210000ff are two writings of one target. Core compares
    // the written form, so a header that rewrites the parent's difficulty in
    // the other form is refused even when its work would meet the target.
    let parent = {
        let mut genesis = HeaderChain::new(Network::Regtest).tip();
        genesis.bits = CompactTarget::from_consensus(0x2000_ff00);
        genesis
    };
    let child = |bits: u32| {
        let mut next = parent;
        next.prev_blockhash = parent.block_hash();
        next.time = parent.time + 1;
        next.bits = CompactTarget::from_consensus(bits);
        grind(&mut next);
        next
    };
    assert_eq!(child(0x2000_ff00).target(), child(0x2100_00ff).target());
    let mut chain = HeaderChain::from_window(Network::Regtest, 100, vec![parent]);
    assert_eq!(
        chain.absorb(&serialize(&child(0x2100_00ff))),
        Err(HeaderError::WrongTarget { height: 101 })
    );
    assert_eq!(chain.absorb(&serialize(&child(0x2000_ff00))), Ok(1));
}

#[test]
fn a_retarget_whose_period_ends_before_it_began_does_not_trap() {
    // Times only have to pass the median rule, so the last header of a period
    // can be earlier than its first. Consensus clamps the span; the library
    // routine subtracts the times without checking.
    let chain = modern_mainnet();
    let first = chain.header_at(860_832).unwrap();
    let mut last = chain.header_at(862_847).unwrap();
    last.time = first.time - 5_000;
    let backwards = retarget(&first, &last, &Params::MAINNET);
    last.time = first.time;
    assert_eq!(backwards, retarget(&first, &last, &Params::MAINNET));
    // The shortest span a period can count for is a quarter of two weeks, and
    // it quarters the target.
    let target = |bits: CompactTarget| bitcoin::pow::Target::from_compact(bits);
    assert!(target(backwards) < target(last.bits));
    // In order, the library's own routine is what runs.
    let ordinary = chain.header_at(862_847).unwrap();
    assert_eq!(
        retarget(&first, &ordinary, &Params::MAINNET),
        chain.header_at(862_848).unwrap().bits
    );
}

#[test]
fn a_header_at_a_checkpoint_must_be_the_checkpointed_block() {
    // The eleven headers before height 11111, then the checkpoint itself.
    let window = rows(MAINNET_FILES[1].0);
    let mut chain = HeaderChain::from_window(Network::Mainnet, 11_100, headers(&window[..11]));
    assert_eq!(chain.absorb(&concat(&window[11..])), Ok(2));
    assert_eq!(chain.height(), 11_112);

    // Real headers of difficulty 1 with valid work, placed where height 11111
    // is the next one: they link, carry the right target and the right work,
    // and are not the checkpointed block.
    let early = rows(MAINNET_FILES[0].0);
    let held = headers(&early[1000..1050]);
    let mut crossing = HeaderChain::from_window(Network::Mainnet, 11_061, held.clone());
    assert_eq!(
        crossing.absorb(&early[1050]),
        Err(HeaderError::CheckpointMismatch { height: 11_111 })
    );
    assert_eq!(crossing.height(), 11_110);
    // Control: one height further on there is no checkpoint, and it is taken.
    let mut past = HeaderChain::from_window(Network::Mainnet, 11_062, held);
    assert_eq!(past.absorb(&early[1050]), Ok(1));
}

#[test]
fn checkpoints_are_a_mainnet_rule() {
    // The same real headers, in a chain of another network, at the height of
    // a mainnet checkpoint: regtest and signet have no table, and regtest
    // keeps the target it has, so the header is taken.
    let early = rows(MAINNET_FILES[0].0);
    let held = headers(&early[1000..1050]);
    let mut regtest = HeaderChain::from_window(Network::Regtest, 11_061, held);
    assert_eq!(regtest.absorb(&early[1050]), Ok(1));
}

#[test]
fn regtest_never_retargets() {
    let chain = regtest_full();
    let all = regtest_rows();
    assert_eq!(chain.height(), 2020);
    let limit = header(&all[0]).bits;
    assert_eq!(limit.to_consensus(), 0x207f_ffff);
    for height in [2015, 2016, 2017, 2020] {
        assert_eq!(chain.header_at(height).unwrap().bits, limit);
    }
    // Under mainnet's rule the same period would have come out differently, so
    // the chain's acceptance is the rule at work and not a coincidence.
    let mainnet_rule = CompactTarget::from_header_difficulty_adjustment(
        chain.header_at(0).unwrap(),
        chain.header_at(2015).unwrap(),
        &Params::MAINNET,
    );
    assert_ne!(mainnet_rule, limit);
}

#[test]
fn the_chain_work_is_what_core_reported() {
    let all = regtest_rows();
    let mut checked = 0;
    for line in vector("bitcoin-regtest/chainwork.txt").lines() {
        let mut fields = line.split(' ');
        let height: usize = fields.next().unwrap().parse().unwrap();
        let hash = BlockHash::from_str(fields.next().unwrap()).unwrap();
        let work = Work::from_unprefixed_hex(fields.next().unwrap()).unwrap();
        let mut chain = HeaderChain::new(Network::Regtest);
        chain.absorb(&concat(&all[1..=height])).unwrap();
        assert_eq!(
            chain.block_hash_at(u32::try_from(height).unwrap()),
            Some(hash)
        );
        assert_eq!(chain.work(), work, "height {height}");
        checked += 1;
    }
    assert_eq!(checked, 10);
    // More headers, more work.
    assert!(regtest_full().work() > Work::from_be_bytes([0; 32]));
}

/// Absorbs the first `height` recorded regtest headers after genesis and tries
/// the next with its time changed to `time`, mined again to carry valid work.
fn regtest_next_with_time(height: usize, time: impl Fn(u32) -> u32) -> Result<usize, HeaderError> {
    let all = regtest_rows();
    let mut chain = HeaderChain::new(Network::Regtest);
    chain.absorb(&concat(&all[1..height])).unwrap();
    let mut candidate = header(&all[height]);
    candidate.time = time(median_before(&all, height));
    grind(&mut candidate);
    chain.absorb(&serialize(&candidate))
}

#[test]
fn a_time_at_or_below_the_median_of_the_eleven_before_is_refused() {
    // Height 1 has one earlier time, height 5 five, 15 and 40 a full eleven.
    for height in [1, 2, 5, 11, 12, 15, 40] {
        let refusal = Err(HeaderError::TimeTooOld {
            height: u32::try_from(height).unwrap(),
        });
        assert_eq!(
            regtest_next_with_time(height, |m| m),
            refusal,
            "equal, {height}"
        );
        assert_eq!(
            regtest_next_with_time(height, |m| m - 1),
            refusal,
            "one below, {height}"
        );
        assert_eq!(
            regtest_next_with_time(height, |m| m - 10_000),
            refusal,
            "far below, {height}"
        );
        // One second after the median is the earliest time that is allowed.
        assert_eq!(regtest_next_with_time(height, |m| m + 1), Ok(1), "{height}");
        assert_eq!(regtest_next_with_time(height, |m| m + 1_000), Ok(1));
    }
}

#[test]
fn the_recorded_regtest_blocks_sit_on_the_edge_of_the_median_rule() {
    // Core mined them seconds apart, so nearly every one carries the median
    // plus one: the chain accepted the whole file only by taking that edge.
    let all = regtest_rows();
    let on_the_edge = (1..all.len())
        .filter(|&height| header(&all[height]).time == median_before(&all, height) + 1)
        .count();
    assert!(on_the_edge > 2000, "{on_the_edge}");
}

#[test]
fn a_chain_cannot_grow_past_what_a_height_can_count() {
    let genesis = HeaderChain::new(Network::Regtest).tip();
    let mut chain = HeaderChain::from_window(Network::Regtest, u32::MAX, vec![genesis]);
    assert_eq!(chain.height(), u32::MAX);
    assert_eq!(chain.absorb(&[0; HEADER_SIZE]), Err(HeaderError::TooLong));
    assert_eq!(chain.absorb(&[]), Ok(0));
}

fn checksum_fixed(mut bytes: Vec<u8>) -> Vec<u8> {
    let body = bytes.len() - 32;
    let sum = sha256::Hash::hash(&bytes[..body]);
    bytes[body..].copy_from_slice(sum.as_byte_array());
    bytes
}

#[test]
fn a_chain_is_saved_as_network_count_headers_and_a_checksum() {
    let chain = regtest_full();
    let bytes = chain.to_bytes();
    assert_eq!(bytes.len(), 1 + 4 + 2020 * HEADER_SIZE + 32);
    assert_eq!(bytes[0], 2);
    assert_eq!(bytes[1..5], 2020_u32.to_le_bytes());
    let all = regtest_rows();
    assert_eq!(bytes[5..5 + 80], all[1]);
    assert_eq!(bytes[5..bytes.len() - 32], concat(&all[1..]));
    let sum = sha256::Hash::hash(&bytes[..bytes.len() - 32]);
    assert_eq!(bytes[bytes.len() - 32..], sum.to_byte_array());

    let again = HeaderChain::from_bytes(Network::Regtest, &bytes).unwrap();
    assert_eq!(again.height(), 2020);
    assert_eq!(again.tip_hash(), chain.tip_hash());
    assert_eq!(again.work(), chain.work());
    assert_eq!(again.to_bytes(), bytes);

    let mainnet = early_mainnet().to_bytes();
    assert_eq!(mainnet[0], 0);
    let again = HeaderChain::from_bytes(Network::Mainnet, &mainnet).unwrap();
    assert_eq!(again.height(), 4032);
    assert_eq!(again.to_bytes(), mainnet);

    let fresh = HeaderChain::new(Network::Signet).to_bytes();
    assert_eq!(fresh.len(), 37);
    assert_eq!(fresh[0], 1);
    let again = HeaderChain::from_bytes(Network::Signet, &fresh).unwrap();
    assert_eq!(again.height(), 0);
}

#[test]
fn a_damaged_or_foreign_cache_is_refused() {
    let bytes = regtest_full().to_bytes();

    // A damaged file: any bit, in the body or in the checksum.
    for place in [
        0,
        3,
        5,
        5 + 500 * 80 + 76,
        bytes.len() - 33,
        bytes.len() - 1,
    ] {
        let mut damaged = bytes.clone();
        damaged[place] ^= 0x10;
        assert_eq!(
            HeaderChain::from_bytes(Network::Regtest, &damaged).err(),
            Some(HeaderError::CacheChecksum),
            "byte {place}"
        );
    }
    // A file cut short, and one with something added.
    assert_eq!(
        HeaderChain::from_bytes(Network::Regtest, &bytes[..bytes.len() - 1]).err(),
        Some(HeaderError::CacheChecksum)
    );
    assert_eq!(
        HeaderChain::from_bytes(Network::Regtest, &[bytes.clone(), vec![0]].concat()).err(),
        Some(HeaderError::CacheChecksum)
    );
    for short in [0, 1, 36] {
        assert_eq!(
            HeaderChain::from_bytes(Network::Regtest, &bytes[..short]).err(),
            Some(HeaderError::CacheTruncated)
        );
    }
    // Another network's file, even a sound one.
    assert_eq!(
        HeaderChain::from_bytes(Network::Mainnet, &bytes).err(),
        Some(HeaderError::CacheNetwork)
    );
    let mut unknown = bytes.clone();
    unknown[0] = 9;
    assert_eq!(
        HeaderChain::from_bytes(Network::Regtest, &checksum_fixed(unknown)).err(),
        Some(HeaderError::CacheNetwork)
    );
}

#[test]
fn a_doctored_cache_with_a_correct_checksum_is_refused_by_its_headers() {
    let bytes = regtest_full().to_bytes();

    // The count says one more or one fewer than the headers present.
    for count in [2019_u32, 2021, 0, u32::MAX] {
        let mut lying = bytes.clone();
        lying[1..5].copy_from_slice(&count.to_le_bytes());
        assert_eq!(
            HeaderChain::from_bytes(Network::Regtest, &checksum_fixed(lying)).err(),
            Some(HeaderError::CacheCount),
            "count {count}"
        );
    }
    // A header changed after the fact: header 500 is at 5 + 499 * 80.
    let mut forged = bytes.clone();
    let start = 5 + 499 * HEADER_SIZE;
    let mut changed: Raw = forged[start..start + HEADER_SIZE].try_into().unwrap();
    changed = flipped(&changed, at::TIME, 9);
    forged[start..start + HEADER_SIZE].copy_from_slice(&changed);
    let forged = checksum_fixed(forged);
    let refusal = HeaderChain::from_bytes(Network::Regtest, &forged).err();
    // Either its work is gone, or (about half the time) it still has some and
    // the next header no longer follows it.
    assert!(
        matches!(
            refusal,
            Some(
                HeaderError::BadProofOfWork { height: 500 }
                    | HeaderError::NotLinked { height: 501 }
                    | HeaderError::TimeTooOld { height: 500 }
            )
        ),
        "{refusal:?}"
    );
    // Two headers swapped.
    let mut swapped = bytes.clone();
    let (a, b) = (5 + 99 * HEADER_SIZE, 5 + 100 * HEADER_SIZE);
    let first: Raw = swapped[a..a + HEADER_SIZE].try_into().unwrap();
    swapped.copy_within(b..b + HEADER_SIZE, a);
    swapped[b..b + HEADER_SIZE].copy_from_slice(&first);
    assert_eq!(
        HeaderChain::from_bytes(Network::Regtest, &checksum_fixed(swapped)).err(),
        Some(HeaderError::NotLinked { height: 100 })
    );
}
