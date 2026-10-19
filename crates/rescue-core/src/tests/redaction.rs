//! No secret type prints, copies or serialises its contents, and the ones that
//! hold a key erase it on demand.

use bitcoin::NetworkKind;
use bitcoin::bip32::{ChainCode, Xpriv};
use bitcoin::secp256k1::SecretKey;

use super::{bip39_root, import};
use crate::secret::{KeyHandle, Material, RootKey, Seed};
use crate::{
    Network, SecretInput, Session, parse_dumpwallet, parse_extended, parse_mini, parse_wif,
};

const WORDS: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn every_secret_type() -> Vec<(&'static str, String, String)> {
    let master = Xpriv::new_master(NetworkKind::Main, &[7; 32]).unwrap();
    let key = SecretKey::from_slice(&[9; 32]).unwrap();
    let wif = "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d";
    let xprv = master.to_string();
    let dump = format!(
        "{wif} 2026-10-18T10:00:00Z label= # addr=bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu\n"
    );
    let show = |value: &dyn std::fmt::Debug| (format!("{value:?}"), format!("{value:#?}"));
    let mut shown = Vec::new();
    let mut add = |name: &'static str, value: &dyn std::fmt::Debug| {
        let (plain, pretty) = show(value);
        shown.push((name, plain, pretty));
    };
    add("SecretInput", &SecretInput::new(WORDS.to_owned()));
    add("Seed", &Seed::new([3; 64]));
    add("RootKey", &RootKey::new(master));
    add("KeyHandle", &KeyHandle::new(key));
    add("Session (words)", &import(WORDS, Network::Mainnet).unwrap());
    add("Session (key)", &import(wif, Network::Mainnet).unwrap());
    add("ParsedKey", &parse_wif(wif, Network::Mainnet).unwrap());
    add(
        "ParsedKey (mini)",
        &parse_mini("SzavMBLoXU6kDrqtUVmffv").unwrap(),
    );
    add(
        "ExtendedKey",
        &parse_extended(&xprv, Network::Mainnet).unwrap(),
    );
    add(
        "DumpedKey",
        &parse_dumpwallet(&dump, Network::Mainnet).unwrap().remove(0),
    );
    shown
}

#[test]
fn debug_of_every_secret_type_prints_redacted() {
    for (name, plain, pretty) in every_secret_type() {
        assert_eq!(plain, "<redacted>", "{name}");
        assert_eq!(pretty, "<redacted>", "{name}");
    }
}

#[test]
fn debug_of_a_container_holding_a_secret_shows_nothing_of_it() {
    let session = import(WORDS, Network::Mainnet);
    assert_eq!(format!("{session:?}"), "Ok(<redacted>)");
    let keys = parse_dumpwallet(
        "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d 2026-10-18T10:00:00Z label=\n",
        Network::Mainnet,
    );
    assert_eq!(format!("{keys:?}"), "Ok([<redacted>])");
}

#[test]
fn what_the_person_typed_never_appears_in_an_error() {
    let secret = "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9X";
    let error = import(secret, Network::Mainnet).err().unwrap();
    assert!(!format!("{error} {error:?}").contains("KyZp"));
}

#[test]
fn a_root_key_is_erased_on_demand() {
    let master = Xpriv::new_master(NetworkKind::Main, &[7; 32]).unwrap();
    let mut root = RootKey::new(master);
    assert_eq!(root.xpriv().private_key, master.private_key);
    root.erase_now();
    assert_ne!(root.xpriv().private_key, master.private_key);
    assert_eq!(
        root.xpriv().chain_code,
        ChainCode::try_from(&[0_u8; 32][..]).unwrap()
    );
    assert_ne!(root.xpriv().chain_code, master.chain_code);
}

#[test]
fn a_key_handle_is_erased_on_demand() {
    let key = SecretKey::from_slice(&[9; 32]).unwrap();
    let mut handle = KeyHandle::new(key);
    assert_eq!(handle.secret_key(), &key);
    handle.erase_now();
    assert_ne!(handle.secret_key(), &key);
}

#[test]
fn the_secret_of_a_words_session_is_the_root_key_and_nothing_else_is_kept() {
    let session = import(WORDS, Network::Mainnet).unwrap();
    assert!(matches!(
        &session.material,
        Material::Words {
            bip39: Some(_),
            electrum: None
        }
    ));
    assert_eq!(bip39_root(&session).xpriv().depth, 0);
}

#[test]
fn a_session_and_its_network_travel_together() {
    let session: Session = import(WORDS, Network::Regtest).unwrap();
    assert_eq!(session.network(), Network::Regtest);
}
