//! BIP49, BIP84 and BIP86 test vectors, the three mainnet vectors of
//! SLIP-0132, and the BIP39 wallet cases of Electrum's `test_wallet_vertical.py`,
//! checked through the plan and the keys it derives.

use bitcoin::NetworkKind;
use bitcoin::hex::DisplayHex;

use super::slip132::{Row, table};
use super::{
    bip39_root, derive, field, import, import_with, pub_with_version, vector, wif_at, with_version,
    xpub_of,
};
use crate::{
    Branch, Chain, ImportError, Network, Origin, Plan, Purpose, ScriptKind, Session, SessionKind,
};

fn standard(plan: &Plan, purpose: Purpose, account: u32, chain: Chain) -> &Branch {
    plan.branches()
        .iter()
        .find(|b| b.origin == Origin::Purpose { purpose, account } && b.chain == Some(chain))
        .expect("a standard branch")
}

fn row_with_private<'a>(rows: &'a [Row], prefix: &str) -> &'a Row {
    rows.iter()
        .find(|r| r.private_prefix == prefix)
        .expect("a SLIP-0132 row")
}

#[test]
fn bip84_vectors() {
    let text = vector("bips/bip-0084.mediawiki");
    let rows = table();
    let zrow = row_with_private(&rows, "zprv");
    let marker = "==Test vectors==";
    let session = import(&field(&text, marker, "mnemonic"), Network::Mainnet).unwrap();
    let root = bip39_root(&session);
    assert_eq!(
        with_version(root.xpriv(), zrow.private),
        field(&text, marker, "rootpriv")
    );
    assert_eq!(
        pub_with_version(&xpub_of(root.xpriv()), zrow.public),
        field(&text, marker, "rootpub")
    );
    let account = derive(root, "m/84'/0'/0'");
    assert_eq!(
        with_version(&account, zrow.private),
        field(&text, marker, "xpriv")
    );
    assert_eq!(
        pub_with_version(&xpub_of(&account), zrow.public),
        field(&text, marker, "xpub")
    );

    let plan = Plan::build(&session).unwrap();
    let receiving = standard(&plan, Purpose::Bip84, 0, Chain::External);
    let change = standard(&plan, Purpose::Bip84, 0, Chain::Internal);
    let first = "// Account 0, first receiving address";
    let second = "// Account 0, second receiving address";
    let changing = "// Account 0, first change address";
    assert_eq!(
        receiving.first_address.to_string(),
        field(&text, first, "address")
    );
    assert_eq!(
        plan.address(&session, receiving, 1).unwrap().to_string(),
        field(&text, second, "address")
    );
    assert_eq!(
        change.first_address.to_string(),
        field(&text, changing, "address")
    );

    for (marker, path) in [
        (first, "m/84'/0'/0'/0/0"),
        (second, "m/84'/0'/0'/0/1"),
        (changing, "m/84'/0'/0'/1/0"),
    ] {
        assert_eq!(
            wif_at(root, path, NetworkKind::Main),
            field(&text, marker, "privkey")
        );
        let key = xpub_of(&derive(root, path)).public_key;
        assert_eq!(
            key.serialize().to_lower_hex_string(),
            field(&text, marker, "pubkey")
        );
    }
}

#[test]
fn the_bip84_account_key_walks_the_same_addresses() {
    let text = vector("bips/bip-0084.mediawiki");
    let marker = "==Test vectors==";
    let session = import(&field(&text, marker, "xpriv"), Network::Mainnet).unwrap();
    assert_eq!(
        session.kind(),
        SessionKind::ExtendedKey {
            depth: 3,
            declared: Some(ScriptKind::P2wpkh)
        }
    );
    let plan = Plan::build(&session).unwrap();
    // Two chains, native segwit only, walked from the key itself.
    assert_eq!(plan.branches().len(), 2);
    let [receiving, change] = plan.branches() else {
        panic!("two branches")
    };
    assert_eq!(receiving.path.as_ref().unwrap().to_string(), "./0/*");
    assert_eq!(
        receiving.first_address.to_string(),
        field(&text, "// Account 0, first receiving address", "address")
    );
    assert_eq!(
        plan.address(&session, receiving, 1).unwrap().to_string(),
        field(&text, "// Account 0, second receiving address", "address")
    );
    assert_eq!(
        change.first_address.to_string(),
        field(&text, "// Account 0, first change address", "address")
    );
}

#[test]
fn the_bip84_root_key_is_the_same_as_the_words() {
    let text = vector("bips/bip-0084.mediawiki");
    let marker = "==Test vectors==";
    let by_words = import(&field(&text, marker, "mnemonic"), Network::Mainnet).unwrap();
    let by_key = import(&field(&text, marker, "rootpriv"), Network::Mainnet).unwrap();
    assert_eq!(
        by_key.kind(),
        SessionKind::ExtendedKey {
            depth: 0,
            declared: Some(ScriptKind::P2wpkh)
        }
    );
    let words_plan = Plan::build(&by_words).unwrap();
    let key_plan = Plan::build(&by_key).unwrap();
    // The declared kind keeps only BIP84 of tier 1 (and the segwit quirks).
    let wanted = standard(&words_plan, Purpose::Bip84, 0, Chain::External);
    let found = standard(&key_plan, Purpose::Bip84, 0, Chain::External);
    assert_eq!(wanted.first_address, found.first_address);
    let tier_one = key_plan
        .branches()
        .iter()
        .filter(|b| b.tier == crate::Tier::One)
        .count();
    assert_eq!(tier_one, 6);
}

#[test]
fn bip86_vectors() {
    let text = vector("bips/bip-0086.mediawiki");
    let marker = "==Test vectors==";
    let session = import(&field(&text, marker, "mnemonic"), Network::Mainnet).unwrap();
    let root = bip39_root(&session);
    assert_eq!(root.xpriv().to_string(), field(&text, marker, "rootpriv"));
    assert_eq!(
        xpub_of(root.xpriv()).to_string(),
        field(&text, marker, "rootpub")
    );
    let account = derive(root, "m/86'/0'/0'");
    assert_eq!(
        account.to_string(),
        field(&text, "// Account 0, root", "xprv")
    );
    assert_eq!(
        xpub_of(&account).to_string(),
        field(&text, "// Account 0, root", "xpub")
    );

    let plan = Plan::build(&session).unwrap();
    for (marker, path, account_chain, index) in [
        (
            "// Account 0, first receiving address",
            "m/86'/0'/0'/0/0",
            Chain::External,
            0,
        ),
        (
            "// Account 0, second receiving address",
            "m/86'/0'/0'/0/1",
            Chain::External,
            1,
        ),
        (
            "// Account 0, first change address",
            "m/86'/0'/0'/1/0",
            Chain::Internal,
            0,
        ),
    ] {
        let key = derive(root, path);
        assert_eq!(key.to_string(), field(&text, marker, "xprv"), "{path}");
        assert_eq!(
            xpub_of(&key).to_string(),
            field(&text, marker, "xpub"),
            "{path}"
        );
        let internal = xpub_of(&key).public_key.x_only_public_key().0;
        assert_eq!(
            internal.serialize().to_lower_hex_string(),
            field(&text, marker, "internal_key")
        );
        let branch = standard(&plan, Purpose::Bip86, 0, account_chain);
        let address = plan.address(&session, branch, index).unwrap();
        assert_eq!(
            address.to_string(),
            field(&text, marker, "address"),
            "{path}"
        );
        assert_eq!(
            address.script_pubkey().to_hex_string(),
            field(&text, marker, "scriptPubKey"),
            "{path}"
        );
        if index == 0 {
            assert_eq!(branch.first_address, address);
        }
    }
}

#[test]
fn a_single_bip86_key_gives_the_tweaked_taproot_address() {
    // The secret behind the first BIP86 address, as a WIF, swept as a loose key.
    let text = vector("bips/bip-0086.mediawiki");
    let marker = "==Test vectors==";
    let session = import(&field(&text, marker, "mnemonic"), Network::Mainnet).unwrap();
    let wif = wif_at(bip39_root(&session), "m/86'/0'/0'/0/0", NetworkKind::Main);
    let single = import(&wif, Network::Mainnet).unwrap();
    let plan = Plan::build(&single).unwrap();
    let taproot = plan
        .branches()
        .iter()
        .find(|b| b.kind == ScriptKind::P2tr)
        .unwrap();
    assert_eq!(
        taproot.first_address.to_string(),
        field(&text, "// Account 0, first receiving address", "address")
    );
}

#[test]
fn bip49_vectors_on_a_test_network() {
    let text = vector("bips/bip-0049.mediawiki");
    let rows = table();
    let urow = row_with_private(&rows, "uprv");
    let marker = "==Test vectors==";
    let session = import(&field(&text, marker, "masterseedWords"), Network::Signet).unwrap();
    let root = bip39_root(&session);
    assert_eq!(
        with_version(root.xpriv(), urow.private),
        field(&text, marker, "masterseed")
    );

    let account = derive(root, "m/49'/1'/0'");
    assert_eq!(
        with_version(&account, urow.private),
        field(&text, marker, "account0Xpriv")
    );
    assert_eq!(
        pub_with_version(&xpub_of(&account), urow.public),
        field(&text, marker, "account0Xpub")
    );
    let wif = wif_at(root, "m/49'/1'/0'/0/0", NetworkKind::Test);
    assert_eq!(wif, field(&text, marker, "account0recvPrivateKey"));
    let key = derive(root, "m/49'/1'/0'/0/0");
    assert_eq!(
        key.private_key.secret_bytes().to_lower_hex_string(),
        field(&text, marker, "account0recvPrivateKeyHex")
    );
    assert_eq!(
        xpub_of(&key).public_key.serialize().to_lower_hex_string(),
        field(&text, marker, "account0recvPublicKeyHex")
    );

    let address = field(&text, marker, "address");
    let plan = Plan::build(&session).unwrap();
    let branch = standard(&plan, Purpose::Bip49, 0, Chain::External);
    assert_eq!(branch.first_address.to_string(), address);
    // The same secret as a loose WIF: the nested segwit branch has it too.
    let single = import(&wif, Network::Signet).unwrap();
    let single_plan = Plan::build(&single).unwrap();
    let nested = single_plan
        .branches()
        .iter()
        .find(|b| b.kind == ScriptKind::P2shP2wpkh)
        .unwrap();
    assert_eq!(nested.first_address.to_string(), address);
}

#[test]
fn bip49_uprv_keys_declare_nested_segwit() {
    let text = vector("bips/bip-0049.mediawiki");
    let marker = "==Test vectors==";
    let address = field(&text, marker, "address");

    // The master key: the plan keeps only the BIP49 purpose of tier 1.
    let master = import(&field(&text, marker, "masterseed"), Network::Signet).unwrap();
    assert_eq!(
        master.kind(),
        SessionKind::ExtendedKey {
            depth: 0,
            declared: Some(ScriptKind::P2shP2wpkh)
        }
    );
    let plan = Plan::build(&master).unwrap();
    assert!(
        plan.branches()
            .iter()
            .all(|b| b.kind == ScriptKind::P2shP2wpkh)
    );
    assert_eq!(
        standard(&plan, Purpose::Bip49, 0, Chain::External)
            .first_address
            .to_string(),
        address
    );

    // The account key.
    let account = import(&field(&text, marker, "account0Xpriv"), Network::Signet).unwrap();
    let plan = Plan::build(&account).unwrap();
    assert_eq!(plan.branches()[0].first_address.to_string(), address);

    // A test-network key is not for mainnet.
    assert_eq!(
        import(&field(&text, marker, "account0Xpriv"), Network::Mainnet).err(),
        Some(ImportError::TestnetKey)
    );
}

/// The three mainnet vectors of SLIP-0132: for each of `m/44'/0'/0'`,
/// `m/49'/0'/0'` and `m/84'/0'/0'`, the account keys and the first address.
struct SlipVector {
    path: String,
    private: String,
    public: String,
    address: String,
}

fn slip_vectors() -> (String, Vec<SlipVector>) {
    let text = vector("slip-0132/slip-0132.md");
    let (_, after) = text.split_once("## Bitcoin Test Vectors").unwrap();
    let block = after.split("```").nth(1).unwrap();
    let mut words = String::new();
    let mut vectors: Vec<SlipVector> = Vec::new();
    let mut lines = block.lines().map(str::trim).filter(|l| !l.is_empty());
    while let Some(line) = lines.next() {
        if let Some(phrase) = line.strip_prefix("Mnemonic: ") {
            words = phrase.to_owned();
        } else if line.ends_with("address:") {
            vectors.last_mut().unwrap().address = lines.next().unwrap().to_owned();
        } else if line.starts_with("m/") {
            vectors.push(SlipVector {
                path: line.to_owned(),
                private: lines.next().unwrap().to_owned(),
                public: lines.next().unwrap().to_owned(),
                address: String::new(),
            });
        }
    }
    (words, vectors)
}

#[test]
fn slip_0132_mainnet_vectors() {
    let (words, vectors) = slip_vectors();
    assert_eq!(vectors.len(), 3);
    let session = import(&words, Network::Mainnet).unwrap();
    let root = bip39_root(&session);
    let plan = Plan::build(&session).unwrap();
    let rows = table();
    let expected = [
        ("xprv", Purpose::Bip44, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"),
        ("yprv", Purpose::Bip49, "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"),
        (
            "zprv",
            Purpose::Bip84,
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        ),
    ];
    for (vector, (prefix, purpose, address)) in vectors.iter().zip(expected) {
        let row = row_with_private(&rows, prefix);
        assert!(vector.private.starts_with(prefix), "{}", vector.path);
        let account = derive(root, &vector.path);
        assert_eq!(
            with_version(&account, row.private),
            vector.private,
            "{}",
            vector.path
        );
        assert_eq!(
            pub_with_version(&xpub_of(&account), row.public),
            vector.public,
            "{}",
            vector.path
        );
        // The address in the SLIP is the one the task and the file agree on.
        assert_eq!(vector.address, address);
        let branch = standard(&plan, purpose, 0, Chain::External);
        assert_eq!(
            branch.first_address.to_string(),
            vector.address,
            "{}",
            vector.path
        );
        // The extended key as the person would paste it.
        let pasted = import(&vector.private, Network::Mainnet).unwrap();
        let pasted_plan = Plan::build(&pasted).unwrap();
        assert_eq!(
            pasted_plan.branches()[0].first_address.to_string(),
            vector.address
        );
    }
}

/// The BIP39 wallet cases of Electrum's `test_wallet_vertical.py`: the account
/// key and the first receiving and change addresses, with and without the
/// passphrase `UNICODE_HORROR`.
#[test]
fn electrums_bip39_wallet_cases() {
    let source = vector("electrum/test_wallet_vertical.py");
    let rows = table();
    let cases = [
        (
            "test_bip39_seed_bip44_standard",
            Purpose::Bip44,
            "xprv",
            false,
        ),
        (
            "test_bip39_seed_bip44_standard_passphrase",
            Purpose::Bip44,
            "xprv",
            true,
        ),
        (
            "test_bip39_seed_bip49_p2sh_segwit",
            Purpose::Bip49,
            "yprv",
            false,
        ),
        (
            "test_bip39_seed_bip84_native_segwit",
            Purpose::Bip84,
            "zprv",
            false,
        ),
    ];
    let horror = {
        let hex = super::electrum::quoted_after(&source, "UNICODE_HORROR_HEX = ");
        let bytes = <Vec<u8> as bitcoin::hex::FromHex>::from_hex(&hex).unwrap();
        String::from_utf8(bytes).unwrap()
    };
    for (function, purpose, prefix, with_passphrase) in cases {
        let (_, rest) = source.split_once(&format!("def {function}(")).unwrap();
        let text = rest.split("\n    async def ").next().unwrap();
        let words = super::electrum::quoted_after(text, "seed_words = ");
        let passphrase = if with_passphrase {
            horror.clone()
        } else {
            String::new()
        };
        let session = import_with(&words, &passphrase, Network::Mainnet).unwrap();
        let root = bip39_root(&session);
        let path = format!("m/{}'/0'/0'", purpose.number());
        let account = derive(root, &path);
        let row = row_with_private(&rows, prefix);
        assert_eq!(
            with_version(&account, row.private),
            super::electrum::quoted_after(text, "ks.xprv, "),
            "{function}"
        );
        assert_eq!(
            pub_with_version(&xpub_of(&account), row.public),
            super::electrum::quoted_after(text, "ks.xpub, "),
            "{function}"
        );
        let plan = Plan::build(&session).unwrap();
        assert_eq!(
            standard(&plan, purpose, 0, Chain::External)
                .first_address
                .to_string(),
            super::electrum::quoted_after(text, "get_receiving_addresses()[0], "),
            "{function}"
        );
        assert_eq!(
            standard(&plan, purpose, 0, Chain::Internal)
                .first_address
                .to_string(),
            super::electrum::quoted_after(text, "get_change_addresses()[0], "),
            "{function}"
        );
    }
}

#[test]
fn a_session_remembers_nothing_but_its_kind() {
    let session: Session = import(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(
        session.kind(),
        SessionKind::Words {
            bip39: true,
            electrum: None
        }
    );
}
