//! BIP32 test vectors 1 to 4 (chains) and 5 (invalid extended keys), read from
//! the BIP text.

use bitcoin::NetworkKind;
use bitcoin::bip32::Xpriv;

use super::{secp, vector, xpub_of};
use crate::keys::parse_extended;
use crate::plan::with_key;
use crate::secret::RootKey;
use crate::{ImportError, Network, parse_path};

struct ChainVector {
    path: String,
    xpub: String,
    xprv: String,
}

struct SeedVector {
    seed: Vec<u8>,
    chains: Vec<ChainVector>,
}

/// Test vectors 1 to 4 from the text of BIP32: a seed line and then, for each
/// chain, a `* Chain m/0<sub>H</sub>/1` line followed by its public and
/// private keys.
fn seed_vectors(text: &str) -> Vec<SeedVector> {
    let start = text.find("===Test vector 1===").expect("vector 1");
    let end = text.find("===Test vector 5===").expect("vector 5");
    let mut vectors: Vec<SeedVector> = Vec::new();
    let mut path = String::new();
    let mut xpub = String::new();
    for line in text[start..end].lines() {
        if let Some(hex) = line.strip_prefix("Seed (hex): ") {
            vectors.push(SeedVector {
                seed: <Vec<u8> as bitcoin::hex::FromHex>::from_hex(hex.trim()).expect("hex"),
                chains: Vec::new(),
            });
        } else if let Some(chain) = line.strip_prefix("* Chain ") {
            path = chain.replace("<sub>H</sub>", "'");
        } else if let Some(key) = line.strip_prefix("** ext pub: ") {
            xpub = key.trim().to_owned();
        } else if let Some(key) = line.strip_prefix("** ext prv: ") {
            vectors
                .last_mut()
                .expect("a seed first")
                .chains
                .push(ChainVector {
                    path: path.clone(),
                    xpub: xpub.clone(),
                    xprv: key.trim().to_owned(),
                });
        }
    }
    vectors
}

/// The published extended private key of test vector 1 at a chain.
pub(super) fn vector_1_xprv(path: &str) -> String {
    let text = vector("bips/bip-0032.mediawiki");
    let vectors = seed_vectors(&text);
    let chain = vectors[0]
        .chains
        .iter()
        .find(|c| c.path == path)
        .expect("a chain of vector 1");
    chain.xprv.clone()
}

#[test]
fn every_chain_of_vectors_1_to_4_serialises_as_published() {
    let text = vector("bips/bip-0032.mediawiki");
    let vectors = seed_vectors(&text);
    assert_eq!(vectors.len(), 4);
    let chains: usize = vectors.iter().map(|v| v.chains.len()).sum();
    // 6 + 6 + 2 + 3 chains.
    assert_eq!(chains, 17);
    for vector in &vectors {
        let master = RootKey::new(Xpriv::new_master(NetworkKind::Main, &vector.seed).unwrap());
        for chain in &vector.chains {
            let typed = parse_path(&chain.path).unwrap_or_else(|e| panic!("{}: {e}", chain.path));
            let key = with_key(&secp(), &master, typed.steps(), |x| *x).unwrap();
            assert_eq!(key.to_string(), chain.xprv, "xprv at {}", chain.path);
            assert_eq!(
                xpub_of(&key).to_string(),
                chain.xpub,
                "xpub at {}",
                chain.path
            );
        }
    }
}

#[test]
fn every_xprv_of_vectors_1_to_4_is_read_back_unchanged() {
    let text = vector("bips/bip-0032.mediawiki");
    for vector in seed_vectors(&text) {
        for chain in &vector.chains {
            let parsed = parse_extended(&chain.xprv, Network::Mainnet).unwrap();
            assert_eq!(parsed.declared_kind(), None, "{}", chain.path);
            let depth = u8::try_from(parse_path(&chain.path).unwrap().steps().len()).unwrap();
            assert_eq!(parsed.depth(), depth, "{}", chain.path);
            // A public key is refused by name, not read as a private one.
            assert_eq!(
                parse_extended(&chain.xpub, Network::Mainnet).err(),
                Some(ImportError::ExtendedPublicKey),
                "{}",
                chain.path
            );
        }
    }
}

#[test]
fn every_invalid_extended_key_of_vector_5_is_refused() {
    let text = vector("bips/bip-0032.mediawiki");
    let start = text.find("===Test vector 5===").expect("vector 5");
    let end = text.find("==Acknowledgements==").expect("end");
    let mut checked = 0;
    for line in text[start..end]
        .lines()
        .filter_map(|l| l.strip_prefix("* "))
    {
        let key = line.split_whitespace().next().unwrap();
        for network in [Network::Mainnet, Network::Signet] {
            let outcome = parse_extended(key, network);
            assert!(outcome.is_err(), "{line} was accepted on {network:?}");
        }
        checked += 1;
    }
    assert_eq!(checked, 16);
}
