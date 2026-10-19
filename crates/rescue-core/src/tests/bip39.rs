//! BIP39: the Trezor vectors (entropy, words, seed with the passphrase
//! "TREZOR", root key), the wrong-word position, and the PBKDF2 cross-check.

use bitcoin::hex::{DisplayHex, FromHex};
use serde_json::Value;
use unicode_normalization::UnicodeNormalization;

use super::{bip39_root, import, import_with, vector};
use crate::words::pbkdf2_hmac_sha512;
use crate::{ImportError, Network};

struct Case {
    entropy: String,
    words: String,
    seed: String,
    xprv: String,
}

fn cases() -> Vec<Case> {
    let json: Value = serde_json::from_str(&vector("python-mnemonic/vectors.json")).unwrap();
    json["english"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            let row: Vec<&str> = row
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            Case {
                entropy: row[0].to_owned(),
                words: row[1].to_owned(),
                seed: row[2].to_owned(),
                xprv: row[3].to_owned(),
            }
        })
        .collect()
}

#[test]
fn the_vector_file_holds_all_24_english_cases() {
    assert_eq!(cases().len(), 24);
}

#[test]
fn entropy_becomes_the_published_words() {
    for case in cases() {
        let entropy = <Vec<u8>>::from_hex(&case.entropy).unwrap();
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(mnemonic.to_string(), case.words);
    }
}

#[test]
fn words_with_the_passphrase_trezor_give_the_published_seed_and_root_key() {
    for case in cases() {
        let session = import_with(&case.words, "TREZOR", Network::Mainnet).unwrap();
        assert_eq!(
            bip39_root(&session).xpriv().to_string(),
            case.xprv,
            "{}",
            case.words
        );
        // The seed itself, through the crate that is the reference.
        let mnemonic = bip39::Mnemonic::parse_normalized(&case.words).unwrap();
        assert_eq!(mnemonic.to_seed("TREZOR").to_lower_hex_string(), case.seed);
    }
}

#[test]
fn our_pbkdf2_matches_the_bip39_seed_with_the_salt_mnemonic() {
    for case in cases() {
        let salt = format!("mnemonic{}", "TREZOR");
        let ours = pbkdf2_hmac_sha512(case.words.as_bytes(), salt.as_bytes(), 2048);
        assert_eq!(ours.to_lower_hex_string(), case.seed, "{}", case.words);
        let theirs = bip39::Mnemonic::parse_normalized(&case.words)
            .unwrap()
            .to_seed("TREZOR");
        assert_eq!(*ours, theirs);
    }
}

#[test]
fn words_are_read_in_any_case_and_spacing() {
    let case = &cases()[0];
    let messy = format!("  {}\n", case.words.to_uppercase().replace(' ', "  \t"));
    let session = import_with(&messy, "TREZOR", Network::Mainnet).unwrap();
    assert_eq!(bip39_root(&session).xpriv().to_string(), case.xprv);
}

#[test]
fn every_valid_length_is_accepted() {
    // The Trezor vectors hold 12, 18 and 24 words; 15 and 21 come from
    // entropy of 20 and 28 bytes.
    for bytes in [16_usize, 20, 24, 28, 32] {
        let entropy = vec![0x5a; bytes];
        let words = bip39::Mnemonic::from_entropy(&entropy).unwrap().to_string();
        assert_eq!(words.split(' ').count(), bytes / 4 * 3, "{bytes} bytes");
        assert!(import(&words, Network::Mainnet).is_ok(), "{bytes} bytes");
    }
    for case in cases() {
        assert!(import(&case.words, Network::Mainnet).is_ok());
    }
}

#[test]
fn a_replaced_word_is_named_by_its_position() {
    let cases = cases();
    let case = &cases[1];
    let words: Vec<&str> = case.words.split(' ').collect();
    for position in 0..words.len() {
        let mut changed: Vec<String> = words.iter().map(|w| (*w).to_owned()).collect();
        changed[position] = "winnow".to_owned();
        let outcome = import(&changed.join(" "), Network::Mainnet).err();
        let expected = u8::try_from(position + 1).unwrap();
        assert_eq!(outcome, Some(ImportError::WrongWord { position: expected }));
    }
}

#[test]
fn only_the_first_wrong_word_is_named() {
    let mut words: Vec<String> = cases()[0].words.split(' ').map(str::to_owned).collect();
    words[3] = "zzzz".to_owned();
    words[7] = "yyyy".to_owned();
    assert_eq!(
        import(&words.join(" "), Network::Mainnet).err(),
        Some(ImportError::WrongWord { position: 4 })
    );
}

#[test]
fn a_swapped_last_word_fails_the_checksum() {
    // Twelve times "abandon" is every word in the list and the wrong checksum.
    let words = ["abandon"; 12].join(" ");
    assert_eq!(
        import(&words, Network::Mainnet).err(),
        Some(ImportError::BadChecksum)
    );
}

#[test]
fn a_phrase_of_the_wrong_length_is_named() {
    let eleven = cases()[0].words.rsplit_once(' ').unwrap().0.to_owned();
    assert_eq!(
        import(&eleven, Network::Mainnet).err(),
        Some(ImportError::WrongWordCount)
    );
}

#[test]
fn the_error_never_holds_the_phrase() {
    let mut words: Vec<String> = cases()[0].words.split(' ').map(str::to_owned).collect();
    words[5] = "wrongwordhere".to_owned();
    let error = import(&words.join(" "), Network::Mainnet).err().unwrap();
    let shown = format!("{error} {error:?}");
    assert!(!shown.contains("wrongwordhere"));
    assert!(!shown.contains("abandon"));
}

#[test]
fn a_passphrase_with_a_key_is_refused() {
    let outcome = import_with(
        "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d",
        "TREZOR",
        Network::Mainnet,
    );
    assert_eq!(outcome.err(), Some(ImportError::PassphraseNotApplicable));
}

#[test]
fn an_empty_passphrase_counts_as_none() {
    let case = &cases()[0];
    let with_empty = import_with(&case.words, "", Network::Mainnet).unwrap();
    let without = import(&case.words, Network::Mainnet).unwrap();
    assert_eq!(
        bip39_root(&with_empty).xpriv(),
        bip39_root(&without).xpriv()
    );
}

/// Electrum's `test_cjk_normalization`: a Japanese BIP39 phrase written with
/// ideographic spaces (U+3000) and the same text as the passphrase. The two
/// seeds are PBKDF2 with the salt "mnemonic" over the NFKD forms.
#[test]
fn nfkd_of_a_japanese_phrase_and_passphrase_gives_electrums_bip39_seeds() {
    let text = vector("electrum/test_mnemonic.py");
    let hex_line = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("cjk_toku_kanchi_hex = \""))
        .unwrap()
        .trim_end_matches('"');
    let phrase = String::from_utf8(<Vec<u8>>::from_hex(hex_line).unwrap()).unwrap();
    assert!(phrase.contains('\u{3000}'));
    let expected: Vec<&str> = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("bytes.fromhex(\""))
        .map(|l| l.split('"').next().unwrap())
        .collect();
    assert_eq!(expected.len(), 2);

    // Electrum normalises with " ".join(split()) as well as NFKD; the
    // ideographic space becomes an ordinary one in NFKD.
    let nfkd: String = phrase.nfkd().collect();
    let words = nfkd.split_whitespace().collect::<Vec<_>>().join(" ");
    let first = pbkdf2_hmac_sha512(words.as_bytes(), b"mnemonic", 2048);
    assert_eq!(first.to_lower_hex_string(), expected[0]);
    let salt = format!("mnemonic{nfkd}");
    let second = pbkdf2_hmac_sha512(words.as_bytes(), salt.as_bytes(), 2048);
    assert_eq!(second.to_lower_hex_string(), expected[1]);
}
