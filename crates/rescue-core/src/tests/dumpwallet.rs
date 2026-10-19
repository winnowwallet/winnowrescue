//! Bitcoin Core `dumpwallet` text, built from the BIP84 and BIP49 vectors so
//! that every key can be checked against the address the line lists.

use super::{field, import, vector};
use crate::{
    Compression, ImportError, Network, Origin, Plan, ScriptKind, SessionKind, parse_dumpwallet,
};

fn bip84_file() -> (String, [(String, String, String); 3]) {
    let text = vector("bips/bip-0084.mediawiki");
    let one = |marker: &str| {
        (
            field(&text, marker, "privkey"),
            field(&text, marker, "address"),
            marker.to_owned(),
        )
    };
    let keys = [
        one("// Account 0, first receiving address"),
        one("// Account 0, second receiving address"),
        one("// Account 0, first change address"),
    ];
    let file = format!(
        "# Wallet dump created by Bitcoin Core v0.21.0\n\
         # * Created on 2026-10-18T10:00:00Z\n\
         # * Best block at time of backup was 700000 (0000000000000000000abc),\n\
         #   mined on 2026-10-18T09:00:00Z\n\
         \n\
         {} 2026-10-18T10:00:00Z label=Savings%20account # addr={} hdkeypath=m/84'/0'/0'/0/0\n\
         {} 2026-10-18T10:00:01Z reserve=1 # addr={} hdkeypath=m/84'/0'/0'/0/1\n\
         \r\n\
         {} 2026-10-18T10:00:02Z change=1 # addr={} hdkeypath=m/84'/0'/0'/1/0\n\
         \n\
         # End of dump\n",
        keys[0].0, keys[0].1, keys[1].0, keys[1].1, keys[2].0, keys[2].1,
    );
    (file, keys)
}

#[test]
fn each_key_is_kept_with_its_address_and_path() {
    let (file, keys) = bip84_file();
    let dumped = parse_dumpwallet(&file, Network::Mainnet).unwrap();
    assert_eq!(dumped.len(), 3);
    let paths = ["m/84'/0'/0'/0/0", "m/84'/0'/0'/0/1", "m/84'/0'/0'/1/0"];
    for ((entry, (_, address, _)), path) in dumped.iter().zip(&keys).zip(paths) {
        assert_eq!(entry.address(), Some(address.as_str()));
        assert_eq!(entry.path().unwrap().to_string(), path);
        assert_eq!(entry.key().compression(), Compression::Compressed);
    }
}

#[test]
fn the_plan_of_a_wallet_file_lets_the_person_compare_each_listed_address() {
    let (file, keys) = bip84_file();
    let session = import(&file, Network::Mainnet).unwrap();
    assert_eq!(session.kind(), SessionKind::Keys { count: 3 });
    let plan = Plan::build(&session).unwrap();
    // Four script kinds for each compressed key; all in tier 1 with a gap of 1.
    assert_eq!(plan.branches().len(), 12);
    for (index, (_, address, _)) in keys.iter().enumerate() {
        let native = plan
            .branches()
            .iter()
            .find(|b| {
                b.kind == ScriptKind::P2wpkh
                    && matches!(&b.origin, Origin::Key { index: i, .. } if *i == index)
            })
            .unwrap();
        assert_eq!(&native.first_address.to_string(), address);
        let Origin::Key { listed_address, .. } = &native.origin else {
            panic!("a key")
        };
        assert_eq!(listed_address.as_deref(), Some(address.as_str()));
        assert_eq!(native.gap, 1);
    }
}

#[test]
fn a_bad_key_names_its_line() {
    let (file, keys) = bip84_file();
    let broken = file.replace(&keys[1].0, &format!("{}x", &keys[1].0[1..]));
    let line = broken
        .lines()
        .position(|l| l.contains("reserve=1"))
        .unwrap()
        + 1;
    assert_eq!(
        parse_dumpwallet(&broken, Network::Mainnet).err(),
        Some(ImportError::BadDumpwallet {
            line: u32::try_from(line).unwrap()
        })
    );
    assert_eq!(
        import(&broken, Network::Mainnet).err(),
        Some(ImportError::BadDumpwallet {
            line: u32::try_from(line).unwrap()
        })
    );
}

#[test]
fn comments_and_blank_lines_alone_hold_no_key() {
    let comments = "# Wallet dump\n\n# nothing else\n";
    assert_eq!(
        parse_dumpwallet(comments, Network::Mainnet).err(),
        Some(ImportError::NotRecognised)
    );
    assert_eq!(
        import(comments, Network::Mainnet).err(),
        Some(ImportError::NotRecognised)
    );
}

#[test]
fn a_test_network_key_in_the_file_is_refused_on_mainnet() {
    let text = vector("bips/bip-0049.mediawiki");
    let wif = field(&text, "==Test vectors==", "account0recvPrivateKey");
    let file =
        format!("{wif} 2026-10-18T10:00:00Z label= # addr=2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2\n");
    assert!(parse_dumpwallet(&file, Network::Signet).is_ok());
    assert_eq!(
        parse_dumpwallet(&file, Network::Mainnet).err(),
        Some(ImportError::TestnetKey)
    );
}

#[test]
fn a_line_without_a_comment_or_with_an_odd_path_is_still_a_key() {
    let (_, keys) = bip84_file();
    let file = format!(
        "{} 2026-10-18T10:00:00Z label= # addr=x hdkeypath=not/a/path\n{}\n",
        keys[0].0, keys[1].0
    );
    let dumped = parse_dumpwallet(&file, Network::Mainnet).unwrap();
    assert_eq!(dumped.len(), 2);
    assert_eq!(dumped[0].address(), Some("x"));
    assert!(dumped[0].path().is_none());
    assert!(dumped[1].address().is_none());
}
