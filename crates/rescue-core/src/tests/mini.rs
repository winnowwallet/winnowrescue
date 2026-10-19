//! Casascius mini private keys: the two examples, recomputed independently
//! (`vectors/mini-keys/recompute.py`) before they were written down.

use bitcoin::PrivateKey;
use bitcoin::hex::DisplayHex;
use serde_json::Value;

use super::{import, vector};
use crate::{Compression, ImportError, Network, Plan, ScriptKind, SessionKind, parse_mini};

const ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

struct Example {
    text: String,
    secret: String,
    wif: String,
    address: String,
}

fn examples() -> Vec<Example> {
    let json: Value = serde_json::from_str(&vector("mini-keys/mini-keys.json")).unwrap();
    json["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| Example {
            text: row["text"].as_str().unwrap().to_owned(),
            secret: row["secret_hex"].as_str().unwrap().to_owned(),
            wif: row["wif_uncompressed"].as_str().unwrap().to_owned(),
            address: row["p2pkh_uncompressed"].as_str().unwrap().to_owned(),
        })
        .collect()
}

#[test]
fn both_lengths_are_covered() {
    let lengths: Vec<usize> = examples().iter().map(|e| e.text.len()).collect();
    assert_eq!(lengths, [30, 22]);
}

#[test]
fn the_secret_wif_and_address_are_the_independently_recomputed_ones() {
    for example in examples() {
        let key = parse_mini(&example.text).unwrap();
        assert_eq!(key.secret_bytes().to_lower_hex_string(), example.secret);
        assert_eq!(key.compression(), Compression::Uncompressed);
        let wif = PrivateKey {
            compressed: false,
            network: bitcoin::NetworkKind::Main,
            inner: bitcoin::secp256k1::SecretKey::from_slice(&key.secret_bytes()).unwrap(),
        }
        .to_wif();
        assert_eq!(wif, example.wif);

        // The plan holds one uncompressed P2PKH branch, and its first address
        // is the one to compare with the old wallet.
        let session = import(&example.text, Network::Mainnet).unwrap();
        assert_eq!(session.kind(), SessionKind::Keys { count: 1 });
        let plan = Plan::build(&session).unwrap();
        let [branch] = plan.branches() else {
            panic!("one branch")
        };
        assert_eq!(branch.kind, ScriptKind::P2pkh { compressed: false });
        assert_eq!(branch.first_address.to_string(), example.address);
        assert!(branch.path.is_none() && branch.chain.is_none());
        assert_eq!(branch.gap, 1);
    }
}

#[test]
fn a_one_character_typo_fails_the_check_byte() {
    // The check byte is 8 bits, so about one typo in 256 would pass by chance;
    // for these two keys the substitution of the next alphabet character at
    // each position is caught every time.
    for example in examples() {
        let characters: Vec<char> = example.text.chars().collect();
        for position in 1..characters.len() {
            let index = ALPHABET.find(characters[position]).unwrap();
            let replacement = ALPHABET.chars().nth((index + 1) % ALPHABET.len()).unwrap();
            let mut typo = characters.clone();
            typo[position] = replacement;
            let typo: String = typo.into_iter().collect();
            assert_eq!(
                parse_mini(&typo).err(),
                Some(ImportError::BadMiniKey),
                "{typo}"
            );
            assert_eq!(
                import(&typo, Network::Mainnet).err(),
                Some(ImportError::BadMiniKey)
            );
        }
    }
}

#[test]
fn a_dropped_or_added_character_is_refused() {
    for example in examples() {
        let shorter = &example.text[..example.text.len() - 1];
        let longer = format!("{}a", example.text);
        assert_eq!(parse_mini(shorter).err(), Some(ImportError::BadMiniKey));
        assert_eq!(parse_mini(&longer).err(), Some(ImportError::BadMiniKey));
    }
}

#[test]
fn the_text_must_start_with_s_and_use_the_base58_alphabet() {
    let example = &examples()[1];
    let lower = example.text.replacen('S', "s", 1);
    assert_eq!(parse_mini(&lower).err(), Some(ImportError::BadMiniKey));
    for bad in ['0', 'O', 'I', 'l', ' ', '-', 'é'] {
        let mut text: Vec<char> = example.text.chars().collect();
        text[5] = bad;
        let text: String = text.into_iter().collect();
        assert_eq!(
            parse_mini(&text).err(),
            Some(ImportError::BadMiniKey),
            "{text:?}"
        );
    }
}

#[test]
fn surrounding_white_space_is_ignored() {
    let example = &examples()[0];
    assert!(parse_mini(&format!("  {}\n", example.text)).is_ok());
}
