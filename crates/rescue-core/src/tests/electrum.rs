//! Electrum 2.x seeds: the seed-type and `mnemonic_to_seed` cases of
//! `test_mnemonic.py`, and the first addresses of the standard and segwit
//! seeds of `test_wallet_vertical.py`.
//!
//! Both files are Python, so the cases are read out of the source text with a
//! few narrow line patterns rather than copied by hand.

use bitcoin::hex::{DisplayHex, FromHex};

use super::{derive, electrum_root, import, import_with, vector, with_version};
use crate::secret::Material;
use crate::words::{ElectrumVersion, electrum_normalise, electrum_seed, electrum_version};
use crate::{ElectrumKind, ImportError, Network, Origin, Plan, SessionKind, Tier};

/// The text between the first pair of single quotes after `marker`.
pub(super) fn quoted_after(text: &str, marker: &str) -> String {
    let (_, rest) = text
        .split_once(marker)
        .unwrap_or_else(|| panic!("no {marker:?}"));
    let rest = rest.split_once('\'').unwrap().1;
    rest.split_once('\'').unwrap().0.to_owned()
}

struct SeedCase {
    name: String,
    words: String,
    passphrase: String,
    segwit: bool,
    bip32_seed: String,
}

/// `UNICODE_HORROR` from `test_wallet_vertical.py`, from its hex form.
fn unicode_horror() -> String {
    let source = vector("electrum/test_wallet_vertical.py");
    let hex = quoted_after(&source, "UNICODE_HORROR_HEX = ");
    String::from_utf8(<Vec<u8>>::from_hex(&hex).unwrap()).unwrap()
}

/// The `SEED_TEST_CASES` of `test_mnemonic.py`.
fn seed_cases() -> Vec<SeedCase> {
    let source = vector("electrum/test_mnemonic.py");
    let horror = unicode_horror();
    let mut cases = Vec::new();
    let mut current: Option<SeedCase> = None;
    for line in source.lines() {
        let line = line.trim();
        if let Some(name) = line.strip_suffix("': SeedTestCase(") {
            let name = name.trim_start_matches('\'').to_owned();
            current = Some(SeedCase {
                name,
                words: String::new(),
                passphrase: String::new(),
                segwit: false,
                bip32_seed: String::new(),
            });
        } else if let Some(case) = current.as_mut() {
            if let Some(rest) = line.strip_prefix("words='") {
                rest.strip_suffix("',").unwrap().clone_into(&mut case.words);
            } else if let Some(rest) = line.strip_prefix("passphrase='") {
                rest.strip_suffix("',")
                    .unwrap()
                    .clone_into(&mut case.passphrase);
            } else if line == "passphrase=UNICODE_HORROR," {
                case.passphrase.clone_from(&horror);
            } else if line == "seed_version=SEED_PREFIX_SW," {
                case.segwit = true;
            } else if let Some(rest) = line.strip_prefix("bip32_seed='") {
                rest.strip_suffix("'),")
                    .unwrap()
                    .clone_into(&mut case.bip32_seed);
                cases.extend(current.take());
            }
        }
    }
    cases
}

#[test]
fn the_ten_published_cases_are_found() {
    let names: Vec<String> = seed_cases().into_iter().map(|c| c.name).collect();
    assert_eq!(
        names,
        [
            "english",
            "english_with_passphrase",
            "japanese",
            "japanese_with_passphrase",
            "chinese",
            "chinese_with_passphrase",
            "spanish",
            "spanish_with_passphrase",
            "spanish2",
            "spanish3",
        ]
    );
}

#[test]
fn mnemonic_to_seed_matches_every_published_case() {
    for case in seed_cases() {
        let normalised = electrum_normalise(&case.words);
        let seed = electrum_seed(&normalised, &case.passphrase);
        assert_eq!(
            seed.as_bytes().to_lower_hex_string(),
            case.bip32_seed,
            "{}",
            case.name
        );
    }
}

#[test]
fn the_version_of_every_published_case_is_read() {
    for case in seed_cases() {
        let expected = if case.segwit {
            ElectrumVersion::Segwit
        } else {
            ElectrumVersion::Standard
        };
        let normalised = electrum_normalise(&case.words);
        assert_eq!(
            electrum_version(&normalised),
            Some(expected),
            "{}",
            case.name
        );
    }
}

#[test]
fn every_published_case_imports_as_an_electrum_seed() {
    for case in seed_cases() {
        let session = import_with(&case.words, &case.passphrase, Network::Mainnet)
            .unwrap_or_else(|e| panic!("{}: {e}", case.name));
        let kind = if case.segwit {
            ElectrumKind::Segwit
        } else {
            ElectrumKind::Standard
        };
        match session.kind() {
            SessionKind::Words { electrum, .. } => {
                assert_eq!(electrum, Some(kind), "{}", case.name);
            }
            other => panic!("{}: {other:?}", case.name),
        }
        let plan = Plan::build(&session).unwrap();
        let electrum: Vec<_> = plan
            .branches()
            .iter()
            .filter(|b| matches!(b.origin, Origin::Electrum(_)))
            .collect();
        assert_eq!(electrum.len(), 2, "{}", case.name);
        assert!(electrum.iter().all(|b| b.tier == Tier::One));
        // The seed is the published one: the root key is the BIP32 master of it.
        let seed = <Vec<u8>>::from_hex(&case.bip32_seed).unwrap();
        let master = bitcoin::bip32::Xpriv::new_master(bitcoin::NetworkKind::Main, &seed).unwrap();
        assert_eq!(electrum_root(&session).xpriv(), &master, "{}", case.name);
    }
}

#[test]
fn the_plain_mnemonic_to_seed_case_foobar() {
    let source = vector("electrum/test_mnemonic.py");
    let (_, after) = source
        .split_once("mnemonic='foobar', passphrase='none')")
        .unwrap();
    let expected = quoted_after(after, "self.assertEqual(");
    let seed = electrum_seed(&electrum_normalise("foobar"), "none");
    assert_eq!(seed.as_bytes().to_lower_hex_string(), expected);
}

/// The `(words, type)` pairs of `Test_seeds.mnemonics`.
fn type_cases() -> Vec<(String, String)> {
    let source = vector("electrum/test_mnemonic.py");
    let (_, after) = source.split_once("    mnemonics = {").unwrap();
    let block = after.split_once("\n    }").unwrap().0;
    let mut cases = Vec::new();
    for line in block.lines() {
        let line = line.trim();
        // The one case written as an expression, `'...' * 4`, is skipped.
        if !line.starts_with("('") || line.contains("' *") {
            continue;
        }
        let inner = line.trim_start_matches("('");
        let (words, rest) = inner.split_once("', '").unwrap();
        let kind = rest.split_once('\'').unwrap().0;
        cases.push((words.to_owned(), kind.to_owned()));
    }
    cases
}

#[test]
fn the_seed_type_of_every_published_case_is_read() {
    let cases = type_cases();
    // 23 literal cases of the 24 in the set (one is an expression).
    assert_eq!(cases.len(), 23);
    let mut compared = 0;
    for (words, kind) in cases {
        let found = electrum_version(&electrum_normalise(&words));
        let expected = match kind.as_str() {
            "standard" => Some(ElectrumVersion::Standard),
            "segwit" => Some(ElectrumVersion::Segwit),
            "2fa" => Some(ElectrumVersion::TwoFactor),
            "2fa_segwit" => Some(ElectrumVersion::TwoFactorSegwit),
            // Electrum 1.x seeds are decided by their own word list first;
            // they are not Electrum 2.x seeds, and none is read as one here.
            "old" | "" => None,
            other => panic!("unknown type {other}"),
        };
        assert_eq!(found, expected, "{words:?} is {kind:?}");
        compared += 1;
    }
    assert_eq!(compared, 23);
}

#[test]
fn two_factor_seeds_are_refused_by_name() {
    for (words, kind) in type_cases() {
        if kind == "2fa" && words.split_whitespace().count() >= 12 {
            // A two-factor phrase that is also valid BIP39 by chance would be
            // imported as BIP39; none of the published ones is.
            assert_eq!(
                import(&words, Network::Mainnet).err(),
                Some(ImportError::ElectrumKindUnsupported),
                "{words}"
            );
        }
    }
}

/// The body of one test function of `test_wallet_vertical.py`.
fn body(source: &str, name: &str) -> String {
    let (_, rest) = source.split_once(&format!("def {name}(")).unwrap();
    rest.split("\n    async def ").next().unwrap().to_owned()
}

fn standard_and_segwit_cases() -> Vec<(&'static str, bool, bool)> {
    // (function, segwit, with UNICODE_HORROR as the passphrase)
    vec![
        ("test_electrum_seed_standard", false, false),
        ("test_electrum_seed_segwit", true, false),
        ("test_electrum_seed_segwit_passphrase", true, true),
    ]
}

#[test]
fn the_first_addresses_and_root_key_match_electrums_wallet_tests() {
    let source = vector("electrum/test_wallet_vertical.py");
    for (function, segwit, with_passphrase) in standard_and_segwit_cases() {
        let text = body(&source, function);
        let words = quoted_after(&text, "seed_words = ");
        let xprv = quoted_after(&text, "ks.xprv, ");
        let receiving = quoted_after(&text, "get_receiving_addresses()[0], ");
        let change = quoted_after(&text, "get_change_addresses()[0], ");
        let passphrase = if with_passphrase {
            unicode_horror()
        } else {
            String::new()
        };

        let session = import_with(&words, &passphrase, Network::Mainnet).unwrap();
        // Electrum's keystore holds the master for a standard seed and the key
        // at m/0' for a segwit one, which it writes as a zprv.
        let root = electrum_root(&session);
        let written = if segwit {
            with_version(&derive(root, "m/0'"), [0x04, 0xb2, 0x43, 0x0c])
        } else {
            root.xpriv().to_string()
        };
        assert_eq!(written, xprv, "{function}");

        let plan = Plan::build(&session).unwrap();
        let branches: Vec<_> = plan
            .branches()
            .iter()
            .filter(|b| matches!(b.origin, Origin::Electrum(_)))
            .collect();
        assert_eq!(
            branches[0].first_address.to_string(),
            receiving,
            "{function}"
        );
        assert_eq!(branches[1].first_address.to_string(), change, "{function}");
    }
}

#[test]
fn an_electrum_seed_is_not_taken_for_bip39_unless_it_is_both() {
    let case = &seed_cases()[0];
    let session = import(&case.words, Network::Mainnet).unwrap();
    assert!(matches!(
        &session.material,
        Material::Words {
            electrum: Some(_),
            ..
        }
    ));
}
