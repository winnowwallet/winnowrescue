//! Bitcoin Core v31.0 `key_io_valid.json` and `key_io_invalid.json`, asserted
//! again at this crate's boundary.

use serde_json::Value;

use super::{import, vector};
use crate::{
    Compression, Destination, DestinationError, ImportError, Network, SessionKind,
    parse_dumpwallet, parse_extended, parse_hex, parse_mini, parse_path, parse_wif,
};

fn rows(file: &str) -> Vec<Value> {
    serde_json::from_str::<Value>(&vector(file))
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

fn network_of(chain: &str) -> Network {
    match chain {
        "main" => Network::Mainnet,
        "regtest" => Network::Regtest,
        // Test networks write keys and addresses alike.
        "test" | "testnet4" | "signet" => Network::Signet,
        other => panic!("unknown chain {other}"),
    }
}

#[test]
fn the_sixteen_private_keys_are_read_with_their_secret_and_compression() {
    let mut seen = 0;
    for row in rows("bitcoin-core-v31.0/key_io_valid.json") {
        let meta = &row[2];
        if meta["isPrivkey"] != true {
            continue;
        }
        let (text, secret) = (row[0].as_str().unwrap(), row[1].as_str().unwrap());
        let chain = meta["chain"].as_str().unwrap();
        let network = network_of(chain);
        let parsed = parse_wif(text, network).unwrap_or_else(|e| panic!("{text}: {e}"));
        assert_eq!(
            parsed.secret_bytes().to_vec(),
            <Vec<u8> as bitcoin::hex::FromHex>::from_hex(secret).unwrap()
        );
        let compression = if meta["isCompressed"] == true {
            Compression::Compressed
        } else {
            Compression::Uncompressed
        };
        assert_eq!(parsed.compression(), compression, "{text}");

        // Through the importer, as a person would paste it.
        let session = import(text, network).unwrap();
        assert_eq!(session.kind(), SessionKind::Keys { count: 1 });

        // A key of a test network never gets a mainnet session.
        if chain == "main" {
            assert!(parse_wif(text, Network::Mainnet).is_ok());
        } else {
            assert_eq!(
                parse_wif(text, Network::Mainnet).err(),
                Some(ImportError::TestnetKey),
                "{text}"
            );
            assert_eq!(
                import(text, Network::Mainnet).err(),
                Some(ImportError::TestnetKey),
                "{text}"
            );
            assert!(parse_wif(text, Network::Regtest).is_ok());
        }
        seen += 1;
    }
    assert_eq!(seen, 16);
}

#[test]
fn a_private_key_is_never_a_destination_or_a_phrase() {
    for row in rows("bitcoin-core-v31.0/key_io_valid.json") {
        if row[2]["isPrivkey"] != true {
            continue;
        }
        let text = row[0].as_str().unwrap();
        for network in [Network::Mainnet, Network::Signet, Network::Regtest] {
            assert!(Destination::parse(text, network).is_err());
        }
        assert!(parse_mini(text).is_err());
        assert!(parse_hex(text).is_err());
        assert!(parse_extended(text, Network::Signet).is_err());
        assert!(parse_path(text).is_err());
    }
}

#[test]
fn the_address_rows_are_accepted_only_when_they_pay_to_taproot() {
    let mut taproot = 0;
    let mut other = 0;
    for row in rows("bitcoin-core-v31.0/key_io_valid.json") {
        let meta = &row[2];
        if meta["isPrivkey"] == true {
            continue;
        }
        let (text, script) = (row[0].as_str().unwrap(), row[1].as_str().unwrap());
        let network = network_of(meta["chain"].as_str().unwrap());
        let is_taproot = script.starts_with("5120") && script.len() == 68;
        let outcome = Destination::parse(text, network);
        if is_taproot {
            let destination = outcome.unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(destination.script_pubkey().to_hex_string(), script);
            if meta["tryCaseFlip"] == true {
                // A QR code carries a bech32m address in capitals.
                let shouted = Destination::parse(&text.to_uppercase(), network).unwrap();
                assert_eq!(shouted.script_pubkey().to_hex_string(), script);
            }
            taproot += 1;
        } else {
            assert_eq!(outcome.err(), Some(DestinationError::NotTaproot), "{text}");
            other += 1;
        }
    }
    // Eight taproot rows (two per network family) and the rest are not.
    assert_eq!(taproot, 8);
    assert!(other > taproot);
}

#[test]
fn a_taproot_address_of_another_network_is_refused_as_such() {
    let mut checked = 0;
    for row in rows("bitcoin-core-v31.0/key_io_valid.json") {
        let meta = &row[2];
        let script = row[1].as_str().unwrap();
        if meta["isPrivkey"] == true || !(script.starts_with("5120") && script.len() == 68) {
            continue;
        }
        let text = row[0].as_str().unwrap();
        let home = network_of(meta["chain"].as_str().unwrap());
        for network in [Network::Mainnet, Network::Signet, Network::Regtest] {
            let outcome = Destination::parse(text, network);
            if network == home {
                assert!(outcome.is_ok(), "{text}");
            } else {
                assert_eq!(
                    outcome.err(),
                    Some(DestinationError::WrongNetwork),
                    "{text} on {network:?}"
                );
            }
        }
        checked += 1;
    }
    assert_eq!(checked, 8);
}

#[test]
fn every_invalid_string_is_refused_by_every_parser() {
    let rows = rows("bitcoin-core-v31.0/key_io_invalid.json");
    assert!(rows.len() > 30);
    for row in rows {
        let text = row[0].as_str().unwrap();
        for network in [Network::Mainnet, Network::Signet, Network::Regtest] {
            assert!(parse_wif(text, network).is_err(), "wif {text:?}");
            assert!(parse_extended(text, network).is_err(), "extended {text:?}");
            assert!(
                parse_dumpwallet(text, network).is_err(),
                "dumpwallet {text:?}"
            );
            assert!(
                Destination::parse(text, network).is_err(),
                "destination {text:?}"
            );
            assert!(import(text, network).is_err(), "import {text:?}");
        }
        assert!(parse_mini(text).is_err(), "mini {text:?}");
        assert!(parse_hex(text).is_err(), "hex {text:?}");
        assert!(parse_path(text).is_err(), "path {text:?}");
    }
}
