//! The version bytes of SLIP-0132: the ten Bitcoin rows of its table, and the
//! swap to BIP32's own bytes that lets `Xpriv` parse every private form.

use bitcoin::NetworkKind;
use bitcoin::bip32::Xpriv;

use super::{pub_with_version, vector, with_version, xpub_of};
use crate::keys::parse_extended;
use crate::{ImportError, Network, ScriptKind};

/// One Bitcoin row of the SLIP-0132 table.
pub(super) struct Row {
    pub(super) coin: String,
    pub(super) public: [u8; 4],
    pub(super) public_prefix: String,
    pub(super) private: [u8; 4],
    pub(super) private_prefix: String,
}

fn version(cell: &str) -> ([u8; 4], String) {
    // `0x0488b21e` - `xpub`
    let mut parts = cell
        .split('`')
        .filter(|p| !p.trim().is_empty() && p.trim() != "-");
    let hex = parts.next().unwrap().trim_start_matches("0x");
    let prefix = parts.next().unwrap().to_owned();
    let bytes = <[u8; 4] as bitcoin::hex::FromHex>::from_hex(hex).unwrap();
    (bytes, prefix)
}

/// The rows for Bitcoin and Bitcoin Testnet.
pub(super) fn table() -> Vec<Row> {
    let text = vector("slip-0132/slip-0132.md");
    let mut rows = Vec::new();
    for line in text.lines() {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.len() < 4 || !(cells[0] == "Bitcoin" || cells[0] == "Bitcoin Testnet") {
            continue;
        }
        let (public, public_prefix) = version(cells[1]);
        let (private, private_prefix) = version(cells[2]);
        rows.push(Row {
            coin: cells[0].to_owned(),
            public,
            public_prefix,
            private,
            private_prefix,
        });
    }
    rows
}

/// The private key of BIP32 test vector 1 at chain `m/0'/1/2'/2`: depth 4, so
/// the key is neither a master nor an account.
fn key_text() -> String {
    super::bip32::vector_1_xprv("m/0'/1/2'/2")
}

#[test]
fn the_table_has_ten_bitcoin_rows() {
    let rows = table();
    assert_eq!(rows.len(), 10);
    assert_eq!(rows.iter().filter(|r| r.coin == "Bitcoin").count(), 5);
    let prefixes: Vec<&str> = rows.iter().map(|r| r.private_prefix.as_str()).collect();
    assert_eq!(
        prefixes,
        [
            "xprv", "yprv", "zprv", "Yprv", "Zprv", "tprv", "uprv", "vprv", "Uprv", "Vprv"
        ]
    );
}

#[test]
fn every_row_writes_the_prefix_its_version_bytes_promise() {
    let key: Xpriv = key_text().parse().unwrap();
    for row in table() {
        assert!(
            with_version(&key, row.private).starts_with(&row.private_prefix),
            "{}",
            row.private_prefix
        );
        assert!(
            pub_with_version(&xpub_of(&key), row.public).starts_with(&row.public_prefix),
            "{}",
            row.public_prefix
        );
    }
}

#[test]
fn private_forms_are_read_with_their_declared_kind() {
    let key: Xpriv = key_text().parse().unwrap();
    for row in table() {
        let text = with_version(&key, row.private);
        let testnet = row.coin == "Bitcoin Testnet";
        let outcome = parse_extended(&text, Network::Signet);
        match row.private_prefix.as_str() {
            "xprv" | "tprv" => assert_eq!(outcome.unwrap().declared_kind(), None),
            "yprv" | "uprv" => {
                assert_eq!(
                    outcome.unwrap().declared_kind(),
                    Some(ScriptKind::P2shP2wpkh)
                );
            }
            "zprv" | "vprv" => {
                assert_eq!(outcome.unwrap().declared_kind(), Some(ScriptKind::P2wpkh));
            }
            _ => assert_eq!(outcome.err(), Some(ImportError::MultisigExtendedKey)),
        }
        // On mainnet a test-network form is refused by name; a multi-signature
        // form is refused as that first.
        let on_mainnet = parse_extended(&text, Network::Mainnet);
        match (testnet, row.private_prefix.as_str()) {
            (_, "Yprv" | "Zprv" | "Uprv" | "Vprv") => {
                assert_eq!(on_mainnet.err(), Some(ImportError::MultisigExtendedKey));
            }
            (true, _) => assert_eq!(on_mainnet.err(), Some(ImportError::TestnetKey)),
            (false, _) => assert!(on_mainnet.is_ok(), "{}", row.private_prefix),
        }
    }
}

#[test]
fn the_swapped_key_is_the_same_key() {
    let key: Xpriv = key_text().parse().unwrap();
    for row in table()
        .iter()
        .filter(|r| !matches!(r.private_prefix.as_str(), "Yprv" | "Zprv" | "Uprv" | "Vprv"))
    {
        let text = with_version(&key, row.private);
        let parsed = parse_extended(&text, Network::Signet).unwrap();
        assert_eq!(parsed.depth(), key.depth);
        let session = crate::secret::Session::from_material(
            Network::Signet,
            crate::secret::Material::Extended(parsed.into_root()),
        );
        let crate::secret::Material::Extended(ext) = &session.material else {
            panic!("extended")
        };
        // BIP32 keeps the private key, chain code, depth, parent and index
        // whatever the version bytes were.
        assert_eq!(
            ext.root.xpriv().private_key,
            key.private_key,
            "{}",
            row.private_prefix
        );
        assert_eq!(
            ext.root.xpriv().chain_code,
            key.chain_code,
            "{}",
            row.private_prefix
        );
        assert_eq!(ext.root.xpriv().child_number, key.child_number);
        assert_eq!(ext.root.xpriv().parent_fingerprint, key.parent_fingerprint);
        let kind = if row.coin == "Bitcoin Testnet" {
            NetworkKind::Test
        } else {
            NetworkKind::Main
        };
        assert_eq!(ext.root.xpriv().network, kind, "{}", row.private_prefix);
    }
}

#[test]
fn public_forms_are_refused_by_name() {
    let key: Xpriv = key_text().parse().unwrap();
    for row in table() {
        let text = pub_with_version(&xpub_of(&key), row.public);
        for network in [Network::Mainnet, Network::Signet] {
            assert_eq!(
                parse_extended(&text, network).err(),
                Some(ImportError::ExtendedPublicKey),
                "{}",
                row.public_prefix
            );
        }
    }
}

#[test]
fn the_import_routes_extended_keys_to_the_extended_parser() {
    let key: Xpriv = key_text().parse().unwrap();
    for row in table() {
        let text = with_version(&key, row.private);
        let outcome = super::import(&text, Network::Signet);
        if matches!(
            row.private_prefix.as_str(),
            "Yprv" | "Zprv" | "Uprv" | "Vprv"
        ) {
            assert_eq!(outcome.err(), Some(ImportError::MultisigExtendedKey));
        } else {
            assert!(outcome.is_ok(), "{}", row.private_prefix);
        }
    }
}

#[test]
fn an_extended_key_with_a_typo_fails_its_checksum() {
    let mut text = key_text();
    let changed = if &text[60..61] == "A" { "B" } else { "A" };
    text.replace_range(60..61, changed);
    assert_eq!(
        parse_extended(&text, Network::Mainnet).err(),
        Some(ImportError::BadExtendedKey)
    );
    assert_eq!(
        super::import(&text, Network::Mainnet).err(),
        Some(ImportError::BadExtendedKey)
    );
}
