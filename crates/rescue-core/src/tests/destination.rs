//! The destination: one taproot address on the session's network.

use bitcoin::Address;
use bitcoin::address::KnownHrp;
use bitcoin::key::TweakedPublicKey;
use bitcoin::secp256k1::XOnlyPublicKey;

use super::{bip39_root, derive, field, import, vector};
use crate::{Destination, DestinationError, Network};

const MAINNET_P2TR: &str = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";

fn bip86_address(marker: &str) -> String {
    field(&vector("bips/bip-0086.mediawiki"), marker, "address")
}

#[test]
fn the_three_bip86_addresses_are_accepted_on_mainnet() {
    for marker in [
        "// Account 0, first receiving address",
        "// Account 0, second receiving address",
        "// Account 0, first change address",
    ] {
        let text = bip86_address(marker);
        let destination = Destination::parse(&text, Network::Mainnet).unwrap();
        assert_eq!(destination.address().to_string(), text);
        assert_eq!(destination.network(), Network::Mainnet);
        assert_eq!(destination.script_pubkey().len(), 34);
    }
    assert_eq!(
        bip86_address("// Account 0, first receiving address"),
        MAINNET_P2TR
    );
}

#[test]
fn white_space_around_an_address_is_ignored() {
    assert!(Destination::parse(&format!(" {MAINNET_P2TR}\r\n"), Network::Mainnet).is_ok());
}

#[test]
fn the_same_address_is_for_one_network_only() {
    assert_eq!(
        Destination::parse(MAINNET_P2TR, Network::Signet).err(),
        Some(DestinationError::WrongNetwork)
    );
    assert_eq!(
        Destination::parse(MAINNET_P2TR, Network::Regtest).err(),
        Some(DestinationError::WrongNetwork)
    );
}

/// A taproot address written for any network from the first BIP86 key.
fn taproot_for(hrp: KnownHrp) -> String {
    let session = import(
        &field(
            &vector("bips/bip-0086.mediawiki"),
            "==Test vectors==",
            "mnemonic",
        ),
        Network::Mainnet,
    )
    .unwrap();
    let key = derive(bip39_root(&session), "m/86'/0'/0'/0/0");
    let x_only = XOnlyPublicKey::from_keypair(&key.to_keypair(&super::secp())).0;
    Address::p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(x_only), hrp).to_string()
}

#[test]
fn signet_and_regtest_addresses_are_accepted_for_their_own_network() {
    let signet = taproot_for(KnownHrp::Testnets);
    let regtest = taproot_for(KnownHrp::Regtest);
    assert!(signet.starts_with("tb1p") && regtest.starts_with("bcrt1p"));
    assert!(Destination::parse(&signet, Network::Signet).is_ok());
    assert!(Destination::parse(&regtest, Network::Regtest).is_ok());
    assert_eq!(
        Destination::parse(&signet, Network::Mainnet).err(),
        Some(DestinationError::WrongNetwork)
    );
    assert_eq!(
        Destination::parse(&signet, Network::Regtest).err(),
        Some(DestinationError::WrongNetwork)
    );
    assert_eq!(
        Destination::parse(&regtest, Network::Signet).err(),
        Some(DestinationError::WrongNetwork)
    );
}

#[test]
fn other_kinds_of_address_are_refused_as_not_taproot() {
    for text in [
        // P2PKH, P2SH, P2WPKH, P2WSH on mainnet (from the BIP texts and Core).
        "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
        "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        "bc1qyucykdlhp62tezs0hagqury402qwhk589q80tqs5myh3rxq34nwqhkdhv7",
    ] {
        assert_eq!(
            Destination::parse(text, Network::Mainnet).err(),
            Some(DestinationError::NotTaproot),
            "{text}"
        );
    }
}

#[test]
fn a_typo_in_the_checksum_is_malformed_and_never_echoed() {
    for position in 4..MAINNET_P2TR.len() {
        let mut typo: Vec<char> = MAINNET_P2TR.chars().collect();
        typo[position] = if typo[position] == 'q' { 'p' } else { 'q' };
        let typo: String = typo.into_iter().collect();
        let error = Destination::parse(&typo, Network::Mainnet).err().unwrap();
        assert_eq!(error, DestinationError::Malformed, "{typo}");
        assert!(!format!("{error} {error:?}").contains(&typo[4..]));
    }
}

#[test]
fn mixed_case_and_the_old_checksum_are_malformed() {
    let mixed = format!("BC1P{}", &MAINNET_P2TR[4..]);
    assert_eq!(
        Destination::parse(&mixed, Network::Mainnet).err(),
        Some(DestinationError::Malformed)
    );
    // A version 1 program under the bech32 (BIP173) checksum instead of bech32m.
    let old_checksum = "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx";
    assert!(Destination::parse(old_checksum, Network::Mainnet).is_err());
}

#[test]
fn nothing_and_rubbish_are_malformed() {
    for text in ["", " ", "bc1p", "hello", "0x1234", "bitcoin:bc1p"] {
        assert_eq!(
            Destination::parse(text, Network::Mainnet).err(),
            Some(DestinationError::Malformed),
            "{text:?}"
        );
    }
}
