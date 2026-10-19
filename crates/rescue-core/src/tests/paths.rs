//! The typed-path parser and the table of wallets with habits.

use crate::paths::{ELECTRUM_SEGWIT, ELECTRUM_STANDARD, QUIRKS};
use crate::{Chain, Network, PathError, ScriptKind, parse_path};

#[test]
fn the_accepted_spellings_all_give_the_same_path() {
    let reference = parse_path("m/84'/0'/0'/1/7").unwrap();
    for text in [
        "m/84h/0h/0h/1/7",
        "m/84H/0H/0H/1/7",
        "m/84'/0H/0h/1/7",
        "  m/84'/0'/0'/1/7\n",
    ] {
        assert_eq!(parse_path(text).unwrap(), reference, "{text:?}");
    }
    assert_eq!(reference.steps().len(), 5);
    assert_eq!(reference.wildcard(), None);
    assert_eq!(reference.to_string(), "m/84'/0'/0'/1/7");
}

#[test]
fn the_root_alone_and_the_largest_index_are_paths() {
    assert_eq!(parse_path("m").unwrap().steps().len(), 0);
    assert!(parse_path("m/2147483647'/2147483647").is_ok());
}

#[test]
fn a_trailing_star_marks_the_address_index() {
    let open = parse_path("m/44'/0'/0'/0/*").unwrap();
    assert_eq!(open.wildcard(), Some(false));
    assert_eq!(open.to_string(), "m/44'/0'/0'/0/*");
    for text in ["m/0'/0'/*'", "m/0'/0'/*h", "m/0'/0'/*H"] {
        let hardened = parse_path(text).unwrap();
        assert_eq!(hardened.wildcard(), Some(true), "{text}");
        assert_eq!(hardened.to_string(), "m/0'/0'/*'");
    }
}

#[test]
fn everything_else_is_refused_by_name() {
    let cases = [
        ("", PathError::Empty),
        ("   ", PathError::Empty),
        ("84'/0'", PathError::MissingRoot),
        ("/m/84'", PathError::MissingRoot),
        ("M/84'", PathError::MissingRoot),
        ("m84'", PathError::MissingRoot),
        ("m/", PathError::EmptyStep),
        ("m//1", PathError::EmptyStep),
        ("m/1/", PathError::EmptyStep),
        ("m/x", PathError::NotANumber),
        ("m/+1", PathError::NotANumber),
        ("m/-1", PathError::NotANumber),
        ("m/1.5", PathError::NotANumber),
        ("m/1 /2", PathError::NotANumber),
        ("m/0x10", PathError::NotANumber),
        ("m/'", PathError::NotANumber),
        ("m/h", PathError::NotANumber),
        ("m/1p", PathError::NotANumber),
        ("m/1''", PathError::NotANumber),
        ("m/１", PathError::NotANumber),
        ("m/2147483648", PathError::IndexTooLarge),
        ("m/2147483648'", PathError::IndexTooLarge),
        ("m/4294967296", PathError::IndexTooLarge),
        ("m/99999999999999999999", PathError::IndexTooLarge),
        ("m/*/1", PathError::WildcardNotLast),
        ("m/*/*", PathError::WildcardNotLast),
        ("m/**", PathError::NotANumber),
    ];
    for (text, expected) in cases {
        assert_eq!(parse_path(text).err(), Some(expected), "{text:?}");
    }
}

#[test]
fn a_path_longer_than_any_wallet_uses_is_refused() {
    let long = format!("m{}", "/1".repeat(33));
    assert_eq!(parse_path(&long).err(), Some(PathError::TooDeep));
    assert!(parse_path(&format!("m{}", "/1".repeat(32))).is_ok());
}

#[test]
fn the_table_of_wallets_with_habits() {
    let templates = |network| {
        QUIRKS
            .iter()
            .flat_map(|row| {
                Chain::ALL
                    .map(|chain| (row.template(chain, network).unwrap().to_string(), row.kind))
            })
            .collect::<Vec<_>>()
    };
    let p2pkh = ScriptKind::P2pkh { compressed: true };
    assert_eq!(
        templates(Network::Mainnet),
        [
            ("m/0'/0'/*'".to_owned(), p2pkh),
            ("m/0'/1'/*'".to_owned(), p2pkh),
            ("m/0'/0/*".to_owned(), p2pkh),
            ("m/0'/1/*".to_owned(), p2pkh),
            ("m/84'/0'/2147483644'/0/*".to_owned(), ScriptKind::P2wpkh),
            ("m/84'/0'/2147483644'/1/*".to_owned(), ScriptKind::P2wpkh),
            ("m/84'/0'/2147483645'/0/*".to_owned(), ScriptKind::P2wpkh),
            ("m/84'/0'/2147483645'/1/*".to_owned(), ScriptKind::P2wpkh),
            ("m/84'/0'/2147483646'/0/*".to_owned(), ScriptKind::P2wpkh),
            ("m/84'/0'/2147483646'/1/*".to_owned(), ScriptKind::P2wpkh),
            ("m/84'/0'/2147483647'/0/*".to_owned(), ScriptKind::P2wpkh),
            ("m/84'/0'/2147483647'/1/*".to_owned(), ScriptKind::P2wpkh),
        ]
    );
    // The coin type follows the network.
    assert!(
        templates(Network::Signet)
            .iter()
            .any(|(t, _)| t == "m/84'/1'/2147483647'/1/*")
    );
}

#[test]
fn the_electrum_rows() {
    let show = |row: &crate::Quirk| {
        Chain::ALL.map(|chain| row.template(chain, Network::Mainnet).unwrap().to_string())
    };
    assert_eq!(show(&ELECTRUM_STANDARD), ["m/0/*", "m/1/*"]);
    assert_eq!(show(&ELECTRUM_SEGWIT), ["m/0'/0/*", "m/0'/1/*"]);
    assert_eq!(
        ELECTRUM_STANDARD.kind,
        ScriptKind::P2pkh { compressed: true }
    );
    assert_eq!(ELECTRUM_SEGWIT.kind, ScriptKind::P2wpkh);
}
