//! The plan: branches, tiers, the first address of each, and the fingerprint.

use core::str::FromStr;

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::key::CompressedPublicKey;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, NetworkKind};

use super::{import, import_with, secp, vector};
use crate::words::{ElectrumVersion, electrum_normalise, electrum_version};
use crate::{
    Chain, ElectrumKind, Network, Origin, Plan, PlanError, Purpose, ScriptKind, SessionKind, Tier,
    parse_path,
};

pub const WORDS: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// The address of a path below a seed, computed with rust-bitcoin's own path
/// parser and none of this crate's template code.
pub fn independent(words: &str, network: bitcoin::Network, path: &str, kind: ScriptKind) -> String {
    let mnemonic = bip39::Mnemonic::parse_normalized(words).unwrap();
    let seed = mnemonic.to_seed("");
    let master = Xpriv::new_master(network, &seed).unwrap();
    let secp = secp();
    let derived = master
        .derive_priv(&secp, &DerivationPath::from_str(path).unwrap())
        .unwrap();
    let key = PublicKey::from_secret_key(&secp, &derived.private_key);
    let compressed = CompressedPublicKey(key);
    match kind {
        ScriptKind::P2pkh { .. } => Address::p2pkh(compressed, network),
        ScriptKind::P2shP2wpkh => Address::p2shwpkh(&compressed, network),
        ScriptKind::P2wpkh => Address::p2wpkh(&compressed, network),
        ScriptKind::P2tr => Address::p2tr(&secp, key.x_only_public_key().0, None, network),
    }
    .to_string()
}

#[test]
fn a_phrase_gets_24_tier_one_and_12_tier_two_branches() {
    let session = import(WORDS, Network::Mainnet).unwrap();
    let plan = Plan::build(&session).unwrap();
    assert_eq!(plan.network(), Network::Mainnet);
    assert_eq!(plan.branches().len(), 36);
    assert!(plan.branches().iter().all(|b| b.gap == 20));
    let (one, two): (Vec<_>, Vec<_>) = plan.branches().iter().partition(|b| b.tier == Tier::One);
    assert_eq!((one.len(), two.len()), (24, 12));
    assert!(plan.branches()[..24].iter().all(|b| b.tier == Tier::One));
    assert!(plan.branches()[24..].iter().all(|b| b.tier == Tier::Two));

    // Purposes 44, 49, 84, 86; accounts 0 to 2; chains 0 and 1, in that order.
    let mut expected = Vec::new();
    for purpose in Purpose::ALL {
        for account in 0..3 {
            for chain in Chain::ALL {
                expected.push((purpose, account, chain));
            }
        }
    }
    let found: Vec<_> = one
        .iter()
        .map(|b| match &b.origin {
            Origin::Purpose { purpose, account } => (*purpose, *account, b.chain.unwrap()),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(found, expected);
    assert_eq!(one[0].path.as_ref().unwrap().to_string(), "m/44'/0'/0'/0/*");
    assert_eq!(one[1].path.as_ref().unwrap().to_string(), "m/44'/0'/0'/1/*");
    assert_eq!(
        one[23].path.as_ref().unwrap().to_string(),
        "m/86'/0'/2'/1/*"
    );
}

#[test]
fn every_first_address_matches_an_independent_derivation() {
    let session = import(WORDS, Network::Mainnet).unwrap();
    let plan = Plan::build(&session).unwrap();
    for branch in plan.branches() {
        let template = branch.path.as_ref().unwrap();
        let mut path = template.to_string();
        // Index 0 in place of the star; the Core legacy rows use a hardened one.
        path = path.replace("/*'", "/0'").replace("/*", "/0");
        let expected = independent(WORDS, bitcoin::Network::Bitcoin, &path, branch.kind);
        assert_eq!(branch.first_address.to_string(), expected, "{path}");
    }
}

#[test]
fn the_wallets_with_habits_are_tier_two() {
    let session = import(WORDS, Network::Mainnet).unwrap();
    let plan = Plan::build(&session).unwrap();
    let names: Vec<(&str, String)> = plan
        .branches()
        .iter()
        .filter(|b| b.tier == Tier::Two)
        .map(|b| {
            let Origin::Quirk(name) = &b.origin else {
                panic!("quirk")
            };
            (*name, b.path.as_ref().unwrap().to_string())
        })
        .collect();
    assert_eq!(
        names[0],
        ("Bitcoin Core legacy HD m/0'/c'/i'", "m/0'/0'/*'".to_owned())
    );
    assert_eq!(names[1].1, "m/0'/1'/*'");
    assert_eq!(
        names[2],
        ("BRD and MultiBit HD m/0'/c/i", "m/0'/0/*".to_owned())
    );
    assert_eq!(names[11].1, "m/84'/0'/2147483647'/1/*");
    assert!(
        plan.branches()[24]
            .path
            .as_ref()
            .unwrap()
            .index_is_hardened()
    );
    assert!(
        !plan.branches()[26]
            .path
            .as_ref()
            .unwrap()
            .index_is_hardened()
    );
}

#[test]
fn the_addresses_are_written_for_the_network_of_the_session() {
    let signet = Plan::build(&import(WORDS, Network::Signet).unwrap()).unwrap();
    let regtest = Plan::build(&import(WORDS, Network::Regtest).unwrap()).unwrap();
    let first = |plan: &Plan, purpose| {
        plan.branches()
            .iter()
            .find(|b| {
                b.origin
                    == Origin::Purpose {
                        purpose,
                        account: 0,
                    }
                    && b.chain == Some(Chain::External)
            })
            .unwrap()
            .first_address
            .to_string()
    };
    assert!(first(&signet, Purpose::Bip84).starts_with("tb1q"));
    assert!(first(&regtest, Purpose::Bip84).starts_with("bcrt1q"));
    assert!(first(&signet, Purpose::Bip86).starts_with("tb1p"));
    assert!(first(&signet, Purpose::Bip49).starts_with('2'));
    // Test networks use coin type 1.
    let path = signet.branches()[0].path.as_ref().unwrap().to_string();
    assert_eq!(path, "m/44'/1'/0'/0/*");
    let expected = independent(
        WORDS,
        bitcoin::Network::Signet,
        "m/84'/1'/0'/0/0",
        ScriptKind::P2wpkh,
    );
    assert_eq!(first(&signet, Purpose::Bip84), expected);
}

#[test]
fn the_fingerprint_is_the_hash_of_the_tier_one_first_scripts() {
    let session = import(WORDS, Network::Mainnet).unwrap();
    let plan = Plan::build(&session).unwrap();
    let mut scripts = Vec::new();
    for branch in plan.branches().iter().filter(|b| b.tier == Tier::One) {
        scripts.extend_from_slice(branch.first_address.script_pubkey().as_bytes());
    }
    assert_eq!(
        plan.fingerprint().as_bytes(),
        &sha256::Hash::hash(&scripts).to_byte_array()
    );
    assert_eq!(plan.fingerprint().to_string().len(), 64);
    // The same secret again gives the same fingerprint; another does not.
    let again = Plan::build(&import(WORDS, Network::Mainnet).unwrap()).unwrap();
    assert_eq!(plan.fingerprint(), again.fingerprint());
    let passphrase = Plan::build(&import_with(WORDS, "TREZOR", Network::Mainnet).unwrap()).unwrap();
    assert_ne!(plan.fingerprint(), passphrase.fingerprint());
    let signet = Plan::build(&import(WORDS, Network::Signet).unwrap()).unwrap();
    assert_ne!(plan.fingerprint(), signet.fingerprint());
}

#[test]
fn a_typed_path_is_tier_three_and_leaves_the_fingerprint_alone() {
    let session = import(WORDS, Network::Mainnet).unwrap();
    let mut plan = Plan::build(&session).unwrap();
    let before = plan.fingerprint();
    let count = plan.branches().len();

    // An account: both chains beneath it.
    plan.add_typed(
        &session,
        &parse_path("m/84'/0'/0'").unwrap(),
        ScriptKind::P2wpkh,
    )
    .unwrap();
    // The address index named: one branch.
    plan.add_typed(
        &session,
        &parse_path("m/44'/0'/0'/0/*").unwrap(),
        ScriptKind::TREE_P2PKH,
    )
    .unwrap();
    // A hardened index.
    plan.add_typed(
        &session,
        &parse_path("m/0'/0'/*'").unwrap(),
        ScriptKind::TREE_P2PKH,
    )
    .unwrap();
    assert_eq!(plan.branches().len(), count + 4);
    assert_eq!(plan.fingerprint(), before);

    let added = &plan.branches()[count..];
    assert!(
        added
            .iter()
            .all(|b| b.tier == Tier::Three && b.origin == Origin::Typed && b.gap == 20)
    );
    let shown: Vec<String> = added
        .iter()
        .map(|b| b.path.as_ref().unwrap().to_string())
        .collect();
    assert_eq!(
        shown,
        [
            "m/84'/0'/0'/0/*",
            "m/84'/0'/0'/1/*",
            "m/44'/0'/0'/0/*",
            "m/0'/0'/*'"
        ]
    );
    assert_eq!(added[0].chain, Some(Chain::External));
    assert_eq!(added[2].chain, None);

    // They land on the addresses the standard branches already showed.
    let tier_one = |purpose, chain| {
        plan.branches()
            .iter()
            .find(|b| {
                b.origin
                    == Origin::Purpose {
                        purpose,
                        account: 0,
                    }
                    && b.chain == Some(chain)
            })
            .unwrap()
            .first_address
            .clone()
    };
    assert_eq!(
        added[0].first_address,
        tier_one(Purpose::Bip84, Chain::External)
    );
    assert_eq!(
        added[1].first_address,
        tier_one(Purpose::Bip84, Chain::Internal)
    );
    assert_eq!(
        added[2].first_address,
        tier_one(Purpose::Bip44, Chain::External)
    );
    // ... and the Core legacy row of tier two.
    assert_eq!(added[3].first_address, plan.branches()[24].first_address);
}

#[test]
fn a_loose_key_has_no_tree_for_a_typed_path() {
    let session = import(
        "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d",
        Network::Mainnet,
    )
    .unwrap();
    let mut plan = Plan::build(&session).unwrap();
    let outcome = plan.add_typed(&session, &parse_path("m/0").unwrap(), ScriptKind::P2wpkh);
    assert_eq!(outcome, Err(PlanError::NoTree));
}

#[test]
fn an_electrum_seed_has_only_its_two_branches() {
    for (words, kind, paths, script) in [
        (
            "cycle rocket west magnet parrot shuffle foot correct salt library feed song",
            ElectrumKind::Standard,
            ["m/0/*", "m/1/*"],
            ScriptKind::TREE_P2PKH,
        ),
        (
            "bitter grass shiver impose acquire brush forget axis eager alone wine silver",
            ElectrumKind::Segwit,
            ["m/0'/0/*", "m/0'/1/*"],
            ScriptKind::P2wpkh,
        ),
    ] {
        let session = import(words, Network::Mainnet).unwrap();
        assert_eq!(
            session.kind(),
            SessionKind::Words {
                bip39: false,
                electrum: Some(kind)
            }
        );
        let plan = Plan::build(&session).unwrap();
        assert_eq!(plan.branches().len(), 2);
        for ((branch, path), chain) in plan.branches().iter().zip(paths).zip(Chain::ALL) {
            assert_eq!(branch.tier, Tier::One);
            assert_eq!(branch.origin, Origin::Electrum(kind));
            assert_eq!(branch.path.as_ref().unwrap().to_string(), path);
            assert_eq!(branch.chain, Some(chain));
            assert_eq!(branch.kind, script);
            assert_eq!(branch.gap, 20);
        }
    }
}

/// A phrase that is a valid BIP39 phrase and an Electrum seed at once: it
/// happens by chance (about one BIP39 phrase in 256), and both readings must
/// be offered.
fn both_ways() -> (String, ElectrumVersion) {
    for number in 0_u128.. {
        let mnemonic = bip39::Mnemonic::from_entropy(&number.to_be_bytes()).unwrap();
        let words = mnemonic.to_string();
        if let Some(version @ (ElectrumVersion::Standard | ElectrumVersion::Segwit)) =
            electrum_version(&electrum_normalise(&words))
        {
            return (words, version);
        }
    }
    unreachable!()
}

#[test]
fn a_phrase_that_is_both_gets_both_readings() {
    let (words, version) = both_ways();
    let kind = if version == ElectrumVersion::Standard {
        ElectrumKind::Standard
    } else {
        ElectrumKind::Segwit
    };
    let session = import(&words, Network::Mainnet).unwrap();
    assert_eq!(
        session.kind(),
        SessionKind::Words {
            bip39: true,
            electrum: Some(kind)
        }
    );
    let plan = Plan::build(&session).unwrap();
    // 24 BIP39 and 2 Electrum branches in tier one, then the 12 of tier two.
    assert_eq!(plan.branches().len(), 38);
    assert!(plan.branches()[..26].iter().all(|b| b.tier == Tier::One));
    assert!(plan.branches()[26..].iter().all(|b| b.tier == Tier::Two));
    assert_eq!(
        plan.branches()
            .iter()
            .filter(|b| matches!(b.origin, Origin::Electrum(_)))
            .count(),
        2
    );
    // The fingerprint covers both.
    let bip39_only: Vec<_> = plan
        .branches()
        .iter()
        .filter(|b| matches!(b.origin, Origin::Purpose { .. }))
        .collect();
    assert_eq!(bip39_only.len(), 24);
}

#[test]
fn a_loose_key_has_one_branch_for_each_kind_it_can_have() {
    let kinds = |text: &str| -> Vec<ScriptKind> {
        Plan::build(&import(text, Network::Mainnet).unwrap())
            .unwrap()
            .branches()
            .iter()
            .map(|b| b.kind)
            .collect()
    };
    let compressed = ScriptKind::TREE_P2PKH;
    let uncompressed = ScriptKind::P2pkh { compressed: false };
    // A compressed WIF: legacy, nested, native and taproot.
    assert_eq!(
        kinds("KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d"),
        [
            compressed,
            ScriptKind::P2shP2wpkh,
            ScriptKind::P2wpkh,
            ScriptKind::P2tr
        ]
    );
    // An uncompressed WIF and a mini key: only the old uncompressed address.
    assert_eq!(
        kinds("5JPy8Zg7z4P7RSLsiqcqyeAF1935zjNUdMxcDeVrtU1oarrgnB7"),
        [uncompressed]
    );
    assert_eq!(kinds("S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy"), [uncompressed]);
    // A bare 32-byte secret does not say, so both forms are tried.
    assert_eq!(
        kinds("4c7a9640c72dc2099f23715d0c8a0d8a35f8906e3cab61dd3f78b67bf887c9ab"),
        [
            compressed,
            uncompressed,
            ScriptKind::P2shP2wpkh,
            ScriptKind::P2wpkh,
            ScriptKind::P2tr
        ]
    );
}

#[test]
fn the_same_secret_as_wif_and_as_hex_gives_the_same_addresses() {
    let wif = Plan::build(
        &import(
            "5JPy8Zg7z4P7RSLsiqcqyeAF1935zjNUdMxcDeVrtU1oarrgnB7",
            Network::Mainnet,
        )
        .unwrap(),
    )
    .unwrap();
    let hex = Plan::build(
        &import(
            "4c7a9640c72dc2099f23715d0c8a0d8a35f8906e3cab61dd3f78b67bf887c9ab",
            Network::Mainnet,
        )
        .unwrap(),
    )
    .unwrap();
    // The hex form has the uncompressed address among its five.
    assert!(
        hex.branches()
            .iter()
            .any(|b| b.first_address == wif.branches()[0].first_address)
    );
    assert_eq!(
        wif.branches()[0].first_address.to_string(),
        "1CciesT23BNionJeXrbxmjc7ywfiyM4oLW"
    );
    for branch in hex.branches() {
        assert!(branch.path.is_none() && branch.chain.is_none());
        assert_eq!(branch.gap, 1);
        assert_eq!(branch.tier, Tier::One);
    }
}

fn master_xprv() -> String {
    let json = vector("bips/bip-0032.mediawiki");
    let (_, rest) = json
        .split_once("Seed (hex): 000102030405060708090a0b0c0d0e0f")
        .unwrap();
    let (_, after) = rest.split_once("** ext prv: ").unwrap();
    after.lines().next().unwrap().trim().to_owned()
}

#[test]
fn a_plain_root_key_walks_everything_and_a_declared_one_walks_its_kind() {
    let master = master_xprv();
    let session = import(&master, Network::Mainnet).unwrap();
    assert_eq!(
        session.kind(),
        SessionKind::ExtendedKey {
            depth: 0,
            declared: None
        }
    );
    let plan = Plan::build(&session).unwrap();
    // 24 standard, 12 habits and the 4 Electrum chains.
    assert_eq!(plan.branches().len(), 40);
    assert_eq!(
        plan.branches()
            .iter()
            .filter(|b| b.tier == Tier::One)
            .count(),
        24
    );

    // The same key written as a zprv declares native segwit.
    let key: Xpriv = master.parse().unwrap();
    let mut payload = key.encode();
    payload[..4].copy_from_slice(&[0x04, 0xb2, 0x43, 0x0c]);
    let zprv = bitcoin::base58::encode_check(&payload);
    let declared = Plan::build(&import(&zprv, Network::Mainnet).unwrap()).unwrap();
    // BIP84 (6), the 4 Samourai accounts (8) and Electrum segwit (2).
    assert_eq!(declared.branches().len(), 16);
    assert!(
        declared
            .branches()
            .iter()
            .all(|b| b.kind == ScriptKind::P2wpkh)
    );
}

#[test]
fn an_undeclared_account_key_is_tried_as_every_kind() {
    let key: Xpriv = super::bip32::vector_1_xprv("m/0'/1/2'/2").parse().unwrap();
    let session = import(&key.to_string(), Network::Mainnet).unwrap();
    assert_eq!(
        session.kind(),
        SessionKind::ExtendedKey {
            depth: 4,
            declared: None
        }
    );
    let plan = Plan::build(&session).unwrap();
    assert_eq!(plan.branches().len(), 8);
    assert!(
        plan.branches()
            .iter()
            .all(|b| b.origin == Origin::Account && b.tier == Tier::One)
    );
    assert!(
        plan.branches()
            .iter()
            .all(|b| b.path.as_ref().unwrap().is_relative())
    );
    // A typed path is walked from the key itself.
    let mut plan = plan;
    plan.add_typed(&session, &parse_path("m/7").unwrap(), ScriptKind::P2wpkh)
        .unwrap();
    assert_eq!(
        plan.branches()[8].path.as_ref().unwrap().to_string(),
        "./7/0/*"
    );
}

#[test]
fn a_key_too_deep_to_derive_from_is_an_error_not_a_trap() {
    let key: Xpriv = super::bip32::vector_1_xprv("m/0'/1/2'/2").parse().unwrap();
    let mut deep = key;
    deep.depth = 255;
    assert_eq!(deep.network, NetworkKind::Main);
    let session = import(&deep.to_string(), Network::Mainnet).unwrap();
    assert_eq!(Plan::build(&session).err(), Some(PlanError::Derivation));
}

#[test]
fn the_derived_address_of_a_branch_is_the_first_address_at_index_zero() {
    let session = import(WORDS, Network::Mainnet).unwrap();
    let plan = Plan::build(&session).unwrap();
    for branch in plan.branches() {
        assert_eq!(
            plan.address(&session, branch, 0).unwrap(),
            branch.first_address
        );
    }
    let branch = &plan.branches()[0];
    assert_ne!(
        plan.address(&session, branch, 1).unwrap(),
        branch.first_address
    );
    assert_eq!(
        plan.address(&session, branch, 0x8000_0000),
        Err(PlanError::IndexTooLarge)
    );
}
