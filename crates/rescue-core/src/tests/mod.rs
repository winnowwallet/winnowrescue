//! Tests that read the files under `vectors/` and need the crate's internals,
//! for instance to serialise a derived key. Expected values come from those
//! files, never from the code under test.

mod bip32;
mod bip39;
mod chains;
mod core_key_io;
mod derivation;
mod destination;
mod discover;
mod dumpwallet;
mod electrum;
mod headers;
mod mini;
mod paths;
mod plan;
mod proof;
mod redaction;
mod slip132;
mod source;

use std::path::Path;

use bitcoin::NetworkKind;
use bitcoin::PrivateKey;
use bitcoin::bip32::{Xpriv, Xpub};
use bitcoin::secp256k1::{All, Secp256k1};

use crate::plan::with_key;
use crate::secret::{Material, RootKey};
use crate::{Network, SecretInput, Session};

/// The text of a file under `vectors/`.
fn vector(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

fn secp() -> Secp256k1<All> {
    Secp256k1::new()
}

fn import(text: &str, network: Network) -> Result<Session, crate::ImportError> {
    Session::import(SecretInput::new(text.to_owned()), None, network)
}

fn import_with(
    text: &str,
    passphrase: &str,
    network: Network,
) -> Result<Session, crate::ImportError> {
    Session::import(
        SecretInput::new(text.to_owned()),
        Some(SecretInput::new(passphrase.to_owned())),
        network,
    )
}

/// The BIP39 root of a words session.
fn bip39_root(session: &Session) -> &RootKey {
    match &session.material {
        Material::Words {
            bip39: Some(root), ..
        } => root,
        _ => panic!("not a BIP39 session"),
    }
}

/// The Electrum root of a words session.
fn electrum_root(session: &Session) -> &RootKey {
    match &session.material {
        Material::Words {
            electrum: Some(electrum),
            ..
        } => &electrum.root,
        _ => panic!("not an Electrum session"),
    }
}

/// Derives `path` (as typed, from `m`) below `root` and returns the extended
/// private key there.
fn derive(root: &RootKey, path: &str) -> Xpriv {
    let typed = crate::parse_path(path).expect("a valid path");
    assert_eq!(typed.wildcard(), None);
    with_key(&secp(), root, typed.steps(), |x| *x).expect("derivable")
}

fn xpub_of(key: &Xpriv) -> Xpub {
    Xpub::from_priv(&secp(), key)
}

/// WIF of the key at `path` below `root`, compressed.
fn wif_at(root: &RootKey, path: &str, kind: NetworkKind) -> String {
    let key = derive(root, path);
    PrivateKey::new(key.private_key, kind).to_wif()
}

/// The text of a `Base58Check` extended key from a 78-byte payload.
fn encode_payload(payload: &[u8; 78]) -> String {
    bitcoin::base58::encode_check(payload)
}

/// An extended private key written with the given SLIP-0132 version bytes.
fn with_version(key: &Xpriv, version: [u8; 4]) -> String {
    let mut payload = key.encode();
    payload[..4].copy_from_slice(&version);
    encode_payload(&payload)
}

/// An extended public key written with the given SLIP-0132 version bytes.
fn pub_with_version(key: &Xpub, version: [u8; 4]) -> String {
    let mut payload = key.encode();
    payload[..4].copy_from_slice(&version);
    encode_payload(&payload)
}

/// The value of the first line starting with `key` and `=`, after the first
/// occurrence of `marker`, with trailing `(testnet)` and `//` notes removed.
fn field(text: &str, marker: &str, key: &str) -> String {
    let (_, after) = text
        .split_once(marker)
        .unwrap_or_else(|| panic!("no {marker:?}"));
    for line in after.lines() {
        let line = line.trim();
        if let Some(value) = line
            .strip_prefix(key)
            .and_then(|rest| rest.trim_start().strip_prefix('='))
        {
            // BIP49 writes "address = base58check(...) = 2Mww... (testnet)".
            let value = value.rsplit('=').next().unwrap_or(value);
            let value = value.split("//").next().unwrap_or(value);
            let value = value.trim().trim_end_matches("(testnet)").trim();
            return value.trim_start_matches("0x").to_owned();
        }
    }
    panic!("no {key:?} after {marker:?}")
}
