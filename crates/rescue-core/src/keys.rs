//! Private keys as people have them: WIF, Casascius mini keys, 32-byte hex,
//! Bitcoin Core `dumpwallet` text and extended private keys, including the
//! SLIP-0132 forms.
//!
//! Each parser checks the published checksum or rule of its format and says
//! which rule failed by name, never by echoing the text.

use bitcoin::NetworkKind;
use bitcoin::PrivateKey;
use bitcoin::base58;
use bitcoin::bip32::Xpriv;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::hex::FromHex;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey, Signing};
use zeroize::Zeroizing;

use crate::error::ImportError;
use crate::network::Network;
use crate::paths::{ScriptKind, TypedPath, parse_path};
use crate::secret::{ExtendedRoot, KeyHandle, LooseKey, RootKey, redacted_debug};

/// Longest text any single-key parser looks at. A WIF is 52 characters and an
/// extended key 112, so this only stops pathological input from costing time.
const MAX_KEY_TEXT: usize = 120;

/// What the form of a key says about its public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    /// The key is for the 33-byte public key.
    Compressed,
    /// The key is for the 65-byte public key (old wallets, mini keys).
    Uncompressed,
    /// The form does not say (a bare 32-byte secret): both are tried.
    Unknown,
}

/// A private key read from WIF, a mini key or hex.
pub struct ParsedKey {
    key: KeyHandle,
    compression: Compression,
}

impl ParsedKey {
    /// What the format said about the public key.
    #[must_use]
    pub const fn compression(&self) -> Compression {
        self.compression
    }

    /// The compressed public key, which is not a secret.
    #[must_use]
    pub fn public_key<C: Signing>(&self, secp: &Secp256k1<C>) -> PublicKey {
        self.key.public_key(secp)
    }

    pub(crate) fn into_loose(self) -> LooseKey {
        LooseKey {
            key: self.key,
            compression: self.compression,
            listed_address: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn secret_bytes(&self) -> [u8; 32] {
        self.key.secret_key().secret_bytes()
    }
}

/// An extended private key read from text.
pub struct ExtendedKey {
    root: RootKey,
    declared: Option<ScriptKind>,
}

impl ExtendedKey {
    /// How many derivations below the master the key is: 0 for a root.
    #[must_use]
    pub fn depth(&self) -> u8 {
        self.root.xpriv().depth
    }

    /// The script kind the version bytes declared: nested segwit for `yprv`
    /// and `uprv`, native segwit for `zprv` and `vprv`, nothing for `xprv`
    /// and `tprv`.
    #[must_use]
    pub const fn declared_kind(&self) -> Option<ScriptKind> {
        self.declared
    }

    pub(crate) fn into_root(self) -> ExtendedRoot {
        ExtendedRoot {
            root: self.root,
            declared: self.declared,
        }
    }
}

/// One key of a `dumpwallet` file, with the address and path the file listed.
pub struct DumpedKey {
    key: ParsedKey,
    address: Option<String>,
    path: Option<TypedPath>,
}

impl DumpedKey {
    /// The key.
    #[must_use]
    pub const fn key(&self) -> &ParsedKey {
        &self.key
    }

    /// The address after `addr=`, as the file wrote it.
    #[must_use]
    pub fn address(&self) -> Option<&str> {
        self.address.as_deref()
    }

    /// The path after `hdkeypath=`, when the file gave one and it parses.
    #[must_use]
    pub const fn path(&self) -> Option<&TypedPath> {
        self.path.as_ref()
    }

    pub(crate) fn into_loose(self) -> LooseKey {
        LooseKey {
            key: self.key.key,
            compression: self.key.compression,
            listed_address: self.address,
        }
    }
}

redacted_debug!(ParsedKey, ExtendedKey, DumpedKey);

/// What a piece of text looks like, decided before any secret is parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Form {
    Words,
    Extended,
    Wif,
    Mini,
    Hex,
    WalletFile,
    Unknown,
}

const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const EXTENDED_PREFIXES: [&str; 20] = [
    "xprv", "xpub", "yprv", "ypub", "zprv", "zpub", "Yprv", "Ypub", "Zprv", "Zpub", "tprv", "tpub",
    "uprv", "upub", "vprv", "vpub", "Uprv", "Upub", "Vprv", "Vpub",
];

fn is_base58(text: &str) -> bool {
    text.chars().all(|c| BASE58_ALPHABET.contains(c))
}

/// A WIF is 51 characters (uncompressed) or 52 (compressed) and starts with
/// 5, 9, K, L or c.
fn looks_like_wif(token: &str) -> bool {
    matches!(token.len(), 51 | 52)
        && token.starts_with(['5', '9', 'K', 'L', 'c'])
        && is_base58(token)
}

/// Decides which parser a piece of non-empty trimmed text belongs to.
pub(crate) fn classify(text: &str) -> Form {
    let mut tokens = text.split_whitespace();
    let Some(first) = tokens.next() else {
        return Form::Unknown;
    };
    if tokens.next().is_none() {
        return classify_token(first);
    }
    let comment_lines = text.lines().any(|line| line.trim_start().starts_with('#'));
    let first_data_token = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .and_then(|line| line.split_whitespace().next());
    if comment_lines || first_data_token.is_some_and(looks_like_wif) {
        Form::WalletFile
    } else {
        Form::Words
    }
}

fn classify_token(token: &str) -> Form {
    if token
        .get(..4)
        .is_some_and(|head| EXTENDED_PREFIXES.contains(&head))
    {
        Form::Extended
    } else if looks_like_wif(token) {
        Form::Wif
    } else if matches!(token.len(), 22 | 30) && token.starts_with('S') {
        Form::Mini
    } else if token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()) {
        Form::Hex
    } else if token.chars().all(char::is_alphabetic) {
        Form::Words
    } else {
        Form::Unknown
    }
}

/// Reads a private key in WIF (`Base58Check`, version byte 0x80 or 0xEF, an
/// optional trailing 0x01 for a compressed public key).
///
/// # Errors
///
/// [`ImportError::BadWif`] for anything that is not a valid WIF, and
/// [`ImportError::TestnetKey`] for a test-network key (0xEF) when `network`
/// is mainnet.
pub fn parse_wif(text: &str, network: Network) -> Result<ParsedKey, ImportError> {
    let text = text.trim();
    if text.len() > MAX_KEY_TEXT {
        return Err(ImportError::BadWif);
    }
    // rust-bitcoin reads any final byte of a compressed WIF as the flag; the
    // format has exactly 0x01 there, and Core's key_io_invalid.json holds
    // keys that differ only in it.
    let payload = Zeroizing::new(base58::decode_check(text).map_err(|_| ImportError::BadWif)?);
    if payload.len() == 34 && payload.last() != Some(&1) {
        return Err(ImportError::BadWif);
    }
    let mut private = PrivateKey::from_wif(text).map_err(|_| ImportError::BadWif)?;
    let handle = KeyHandle::new(private.inner);
    let compression = if private.compressed {
        Compression::Compressed
    } else {
        Compression::Uncompressed
    };
    let kind = private.network;
    private.inner.non_secure_erase();
    core::hint::black_box(&private);
    if kind == NetworkKind::Test && network.is_mainnet() {
        return Err(ImportError::TestnetKey);
    }
    Ok(ParsedKey {
        key: handle,
        compression,
    })
}

/// Reads a Casascius mini private key: 22 or 30 characters from the Base58
/// alphabet starting with `S`, valid when the first byte of the SHA-256 of the
/// text followed by `?` is zero. The secret is the SHA-256 of the text and the
/// key is for the uncompressed public key, by convention.
///
/// # Errors
///
/// [`ImportError::BadMiniKey`] when the length, the characters or the check
/// byte are wrong, so a mistyped character is caught.
pub fn parse_mini(text: &str) -> Result<ParsedKey, ImportError> {
    let text = text.trim();
    if !matches!(text.len(), 22 | 30) || !text.starts_with('S') || !is_base58(text) {
        return Err(ImportError::BadMiniKey);
    }
    let mut marked = Zeroizing::new(String::with_capacity(31));
    marked.push_str(text);
    marked.push('?');
    if sha256::Hash::hash(marked.as_bytes())
        .as_byte_array()
        .first()
        != Some(&0)
    {
        return Err(ImportError::BadMiniKey);
    }
    let secret = Zeroizing::new(sha256::Hash::hash(text.as_bytes()).to_byte_array());
    let key = SecretKey::from_slice(secret.as_slice()).map_err(|_| ImportError::KeyOutOfRange)?;
    Ok(ParsedKey {
        key: KeyHandle::new(key),
        compression: Compression::Uncompressed,
    })
}

/// Reads a bare 32-byte secret written as 64 hexadecimal digits. The text does
/// not say whether the old uncompressed or the usual compressed public key
/// was meant, so the plan tries both.
///
/// # Errors
///
/// [`ImportError::NotRecognised`] when it is not exactly 64 hexadecimal digits,
/// [`ImportError::KeyOutOfRange`] when the number is zero or not below the
/// curve order.
pub fn parse_hex(text: &str) -> Result<ParsedKey, ImportError> {
    let text = text.trim();
    if text.len() != 64 {
        return Err(ImportError::NotRecognised);
    }
    let bytes = Zeroizing::new(<[u8; 32]>::from_hex(text).map_err(|_| ImportError::NotRecognised)?);
    let key = SecretKey::from_slice(bytes.as_slice()).map_err(|_| ImportError::KeyOutOfRange)?;
    Ok(ParsedKey {
        key: KeyHandle::new(key),
        compression: Compression::Unknown,
    })
}

/// What a SLIP-0132 version says the extended key is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    /// `xprv` and `tprv` and their public forms: no script kind declared.
    Plain,
    /// `yprv` and `uprv`: segwit nested in a script hash.
    Nested,
    /// `zprv` and `vprv`: native segwit.
    Native,
    /// `Yprv` and `Uprv`: a multi-signature script hash of a segwit script.
    MultisigNested,
    /// `Zprv` and `Vprv`: a multi-signature native segwit script.
    MultisigNative,
}

/// One row of the Bitcoin part of SLIP-0132.
struct Slip132 {
    version: [u8; 4],
    private: bool,
    testnet: bool,
    family: Family,
}

const SLIP132: [Slip132; 20] = [
    Slip132 {
        version: [0x04, 0x88, 0xb2, 0x1e],
        private: false,
        testnet: false,
        family: Family::Plain,
    },
    Slip132 {
        version: [0x04, 0x88, 0xad, 0xe4],
        private: true,
        testnet: false,
        family: Family::Plain,
    },
    Slip132 {
        version: [0x04, 0x9d, 0x7c, 0xb2],
        private: false,
        testnet: false,
        family: Family::Nested,
    },
    Slip132 {
        version: [0x04, 0x9d, 0x78, 0x78],
        private: true,
        testnet: false,
        family: Family::Nested,
    },
    Slip132 {
        version: [0x04, 0xb2, 0x47, 0x46],
        private: false,
        testnet: false,
        family: Family::Native,
    },
    Slip132 {
        version: [0x04, 0xb2, 0x43, 0x0c],
        private: true,
        testnet: false,
        family: Family::Native,
    },
    Slip132 {
        version: [0x02, 0x95, 0xb4, 0x3f],
        private: false,
        testnet: false,
        family: Family::MultisigNested,
    },
    Slip132 {
        version: [0x02, 0x95, 0xb0, 0x05],
        private: true,
        testnet: false,
        family: Family::MultisigNested,
    },
    Slip132 {
        version: [0x02, 0xaa, 0x7e, 0xd3],
        private: false,
        testnet: false,
        family: Family::MultisigNative,
    },
    Slip132 {
        version: [0x02, 0xaa, 0x7a, 0x99],
        private: true,
        testnet: false,
        family: Family::MultisigNative,
    },
    Slip132 {
        version: [0x04, 0x35, 0x87, 0xcf],
        private: false,
        testnet: true,
        family: Family::Plain,
    },
    Slip132 {
        version: [0x04, 0x35, 0x83, 0x94],
        private: true,
        testnet: true,
        family: Family::Plain,
    },
    Slip132 {
        version: [0x04, 0x4a, 0x52, 0x62],
        private: false,
        testnet: true,
        family: Family::Nested,
    },
    Slip132 {
        version: [0x04, 0x4a, 0x4e, 0x28],
        private: true,
        testnet: true,
        family: Family::Nested,
    },
    Slip132 {
        version: [0x04, 0x5f, 0x1c, 0xf6],
        private: false,
        testnet: true,
        family: Family::Native,
    },
    Slip132 {
        version: [0x04, 0x5f, 0x18, 0xbc],
        private: true,
        testnet: true,
        family: Family::Native,
    },
    Slip132 {
        version: [0x02, 0x42, 0x89, 0xef],
        private: false,
        testnet: true,
        family: Family::MultisigNested,
    },
    Slip132 {
        version: [0x02, 0x42, 0x85, 0xb5],
        private: true,
        testnet: true,
        family: Family::MultisigNested,
    },
    Slip132 {
        version: [0x02, 0x57, 0x54, 0x83],
        private: false,
        testnet: true,
        family: Family::MultisigNative,
    },
    Slip132 {
        version: [0x02, 0x57, 0x50, 0x48],
        private: true,
        testnet: true,
        family: Family::MultisigNative,
    },
];

/// BIP32's own private version bytes, which `Xpriv::decode` accepts.
const BIP32_MAINNET_PRIVATE: [u8; 4] = [0x04, 0x88, 0xad, 0xe4];
const BIP32_TESTNET_PRIVATE: [u8; 4] = [0x04, 0x35, 0x83, 0x94];

/// Reads an extended private key: `xprv` and `tprv`, and the SLIP-0132 forms
/// `yprv`, `zprv`, `uprv` and `vprv`, whose four version bytes are swapped
/// for BIP32's before parsing. The declared script kind is kept.
///
/// # Errors
///
/// [`ImportError::ExtendedPublicKey`] for `xpub`, `ypub`, `zpub` and the other
/// public forms, [`ImportError::MultisigExtendedKey`] for `Yprv`, `Zprv`,
/// `Uprv` and `Vprv`, [`ImportError::TestnetKey`] for a test-network key on
/// mainnet, and [`ImportError::BadExtendedKey`] for anything else that is not
/// a valid BIP32 private key.
pub fn parse_extended(text: &str, network: Network) -> Result<ExtendedKey, ImportError> {
    let text = text.trim();
    if text.len() > MAX_KEY_TEXT {
        return Err(ImportError::BadExtendedKey);
    }
    let data = Zeroizing::new(base58::decode_check(text).map_err(|_| ImportError::BadExtendedKey)?);
    let data: &[u8; 78] = data
        .as_slice()
        .try_into()
        .map_err(|_| ImportError::BadExtendedKey)?;
    let version: [u8; 4] = [data[0], data[1], data[2], data[3]];
    let row = SLIP132
        .iter()
        .find(|row| row.version == version)
        .ok_or(ImportError::BadExtendedKey)?;
    if !row.private {
        return Err(ImportError::ExtendedPublicKey);
    }
    if matches!(row.family, Family::MultisigNested | Family::MultisigNative) {
        return Err(ImportError::MultisigExtendedKey);
    }
    if row.testnet && network.is_mainnet() {
        return Err(ImportError::TestnetKey);
    }
    // A private key is the byte 0 and then 32 bytes.
    if data[45] != 0 {
        return Err(ImportError::BadExtendedKey);
    }
    let mut swapped = Zeroizing::new(*data);
    swapped[..4].copy_from_slice(if row.testnet {
        &BIP32_TESTNET_PRIVATE
    } else {
        &BIP32_MAINNET_PRIVATE
    });
    let key = Xpriv::decode(swapped.as_slice()).map_err(|_| ImportError::BadExtendedKey)?;
    let root = RootKey::new(key);
    // BIP32: a master key has no parent and no index.
    let xpriv = root.xpriv();
    if xpriv.depth == 0
        && (xpriv.parent_fingerprint.as_bytes() != &[0; 4] || u32::from(xpriv.child_number) != 0)
    {
        return Err(ImportError::BadExtendedKey);
    }
    let declared = match row.family {
        Family::Nested => Some(ScriptKind::P2shP2wpkh),
        Family::Native => Some(ScriptKind::P2wpkh),
        _ => None,
    };
    Ok(ExtendedKey { root, declared })
}

/// Reads the text of Bitcoin Core's `dumpwallet`: lines of
/// `<WIF> <timestamp> <label|reserve=1|change=1> # addr=<address>
/// [hdkeypath=<path>]`. Blank lines and `#` comment lines are skipped, and
/// each key is kept with the address and path its line listed.
///
/// # Errors
///
/// [`ImportError::BadDumpwallet`] naming the first line whose key is not a
/// valid WIF, [`ImportError::TestnetKey`] for a test-network key on mainnet,
/// and [`ImportError::NotRecognised`] when the text holds no key at all.
pub fn parse_dumpwallet(text: &str, network: Network) -> Result<Vec<DumpedKey>, ImportError> {
    let mut dumped = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (data, comment) = match line.split_once('#') {
            Some((data, comment)) => (data, comment),
            None => (line, ""),
        };
        let number = u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX);
        let wif = data
            .split_whitespace()
            .next()
            .ok_or(ImportError::BadDumpwallet { line: number })?;
        let key = parse_wif(wif, network).map_err(|error| match error {
            ImportError::TestnetKey => ImportError::TestnetKey,
            _ => ImportError::BadDumpwallet { line: number },
        })?;
        let mut address = None;
        let mut path = None;
        for field in comment.split_whitespace() {
            if let Some(listed) = field.strip_prefix("addr=") {
                address = Some(listed.to_owned());
            } else if let Some(listed) = field.strip_prefix("hdkeypath=") {
                path = parse_path(listed).ok();
            }
        }
        dumped.push(DumpedKey { key, address, path });
    }
    if dumped.is_empty() {
        return Err(ImportError::NotRecognised);
    }
    Ok(dumped)
}
