//! Words: BIP39 phrases and Electrum 2.x seeds.
//!
//! BIP39 goes through the `bip39` crate. Electrum seeds follow
//! `electrum/mnemonic.py`: the text is normalised, a version is read from an
//! HMAC-SHA512 of it, and the seed is PBKDF2-HMAC-SHA512 with the salt
//! `"electrum"` and the normalised passphrase.

use bip39::{Language, Mnemonic};
use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine, sha512};
use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::canonical_combining_class;
use zeroize::Zeroizing;

use crate::error::ImportError;
use crate::network::Network;
use crate::secret::{ElectrumRoot, Material, RootKey, Seed};

/// PBKDF2 rounds for both BIP39 and Electrum seeds.
const PBKDF2_ROUNDS: u32 = 2048;

/// The kinds of Electrum 2.x seed the core can sweep.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ElectrumKind {
    /// Version prefix `01`: legacy addresses at `m/0/i` and `m/1/i`.
    Standard,
    /// Version prefix `100`: native segwit addresses at `m/0'/0/i` and
    /// `m/0'/1/i`.
    Segwit,
}

/// Every version Electrum 2.x writes in the seed; the two-factor ones are
/// recognised only to be refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ElectrumVersion {
    Standard,
    Segwit,
    TwoFactor,
    TwoFactorSegwit,
}

/// The ranges Electrum treats as CJK when it removes the spaces between
/// characters (`CJK_INTERVALS` in `electrum/mnemonic.py`).
const CJK_INTERVALS: [(u32, u32); 29] = [
    (0x4E00, 0x9FFF),
    (0x3400, 0x4DBF),
    (0x20000, 0x2A6DF),
    (0x2A700, 0x2B73F),
    (0x2B740, 0x2B81F),
    (0xF900, 0xFAFF),
    (0x2F800, 0x2FA1D),
    (0x3190, 0x319F),
    (0x2E80, 0x2EFF),
    (0x2F00, 0x2FDF),
    (0x31C0, 0x31EF),
    (0x2FF0, 0x2FFF),
    (0xE0100, 0xE01EF),
    (0x3100, 0x312F),
    (0x31A0, 0x31BF),
    (0xFF00, 0xFFEF),
    (0x3040, 0x309F),
    (0x30A0, 0x30FF),
    (0x31F0, 0x31FF),
    (0x1B000, 0x1B0FF),
    (0xAC00, 0xD7AF),
    (0x1100, 0x11FF),
    (0xA960, 0xA97F),
    (0xD7B0, 0xD7FF),
    (0x3130, 0x318F),
    (0xA4D0, 0xA4FF),
    (0x16F00, 0x16F9F),
    (0xA000, 0xA48F),
    (0xA490, 0xA4CF),
];

fn is_cjk(c: char) -> bool {
    let n = u32::from(c);
    CJK_INTERVALS
        .iter()
        .any(|&(low, high)| low <= n && n <= high)
}

/// What Python's `str.split()` splits on: Unicode white space and the four
/// separator controls.
fn is_python_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Electrum's `normalize_text`: NFKD, lower case, combining marks removed,
/// white space collapsed to single spaces, and a space between two CJK
/// characters removed.
pub(crate) fn electrum_normalise(text: &str) -> Zeroizing<String> {
    let decomposed: Zeroizing<String> = Zeroizing::new(text.nfkd().collect());
    let lowered = Zeroizing::new(decomposed.to_lowercase());
    let unmarked: Zeroizing<String> = Zeroizing::new(
        lowered
            .chars()
            .filter(|&c| canonical_combining_class(c) == 0)
            .collect(),
    );
    let spaced = Zeroizing::new(
        unmarked
            .split(is_python_space)
            .filter(|word| !word.is_empty())
            .collect::<Vec<_>>()
            .join(" "),
    );
    let chars: Zeroizing<Vec<char>> = Zeroizing::new(spaced.chars().collect());
    let mut out = Zeroizing::new(String::with_capacity(spaced.len()));
    for (index, &c) in chars.iter().enumerate() {
        let before = index.checked_sub(1).and_then(|i| chars.get(i));
        let after = chars.get(index.saturating_add(1));
        let between_cjk = matches!((before, after), (Some(&b), Some(&a)) if is_cjk(b) && is_cjk(a));
        if !(c == ' ' && between_cjk) {
            out.push(c);
        }
    }
    out
}

/// Reads the version Electrum 2.x wrote into an already normalised seed: the
/// hexadecimal HMAC-SHA512 of it with the key `"Seed version"` starts with
/// `01` (standard), `100` (segwit), `101` (two-factor) or `102` (two-factor
/// segwit).
pub(crate) fn electrum_version(normalised: &str) -> Option<ElectrumVersion> {
    let mut engine = HmacEngine::<sha512::Hash>::new(b"Seed version");
    engine.input(normalised.as_bytes());
    let mac = Hmac::<sha512::Hash>::from_engine(engine);
    let bytes = mac.as_byte_array();
    // Hex digits are nibbles: "01" is the whole first byte, "10x" is the first
    // byte 0x10 and the high nibble of the second.
    match (bytes.first()?, bytes.get(1)? >> 4) {
        (0x01, _) => Some(ElectrumVersion::Standard),
        (0x10, 0) => Some(ElectrumVersion::Segwit),
        (0x10, 1) => Some(ElectrumVersion::TwoFactor),
        (0x10, 2) => Some(ElectrumVersion::TwoFactorSegwit),
        _ => None,
    }
}

/// PBKDF2 with HMAC-SHA512 as the pseudo-random function, one 64-byte block
/// of output (RFC 8018, section 5.2, with `dkLen = hLen`).
pub(crate) fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], rounds: u32) -> Zeroizing<[u8; 64]> {
    let keyed = HmacEngine::<sha512::Hash>::new(password);
    // U1 = PRF(password, salt || INT(1))
    let mut engine = keyed.clone();
    engine.input(salt);
    engine.input(&1_u32.to_be_bytes());
    let mut u = Zeroizing::new(Hmac::<sha512::Hash>::from_engine(engine).to_byte_array());
    let mut t = Zeroizing::new(*u);
    for _ in 1..rounds {
        let mut engine = keyed.clone();
        engine.input(&*u);
        *u = Hmac::<sha512::Hash>::from_engine(engine).to_byte_array();
        for (acc, byte) in t.iter_mut().zip(u.iter()) {
            *acc ^= byte;
        }
    }
    t
}

/// The seed of an already normalised Electrum seed text and passphrase.
pub(crate) fn electrum_seed(normalised: &str, passphrase: &str) -> Seed {
    let passphrase = electrum_normalise(passphrase);
    let mut salt = Zeroizing::new(Vec::with_capacity(8_usize.saturating_add(passphrase.len())));
    salt.extend_from_slice(b"electrum");
    salt.extend_from_slice(passphrase.as_bytes());
    Seed::new(*pbkdf2_hmac_sha512(
        normalised.as_bytes(),
        &salt,
        PBKDF2_ROUNDS,
    ))
}

/// Parses the words as a BIP39 phrase in English, naming the first word that
/// is not in the list by its one-based position.
fn bip39_root(tokens: &[&str], passphrase: &str, network: Network) -> Result<RootKey, ImportError> {
    for (index, word) in tokens.iter().enumerate() {
        if Language::English.find_word(word).is_none() {
            let position = u8::try_from(index.saturating_add(1)).unwrap_or(u8::MAX);
            return Err(ImportError::WrongWord { position });
        }
    }
    if !matches!(tokens.len(), 12 | 15 | 18 | 21 | 24) {
        return Err(ImportError::WrongWordCount);
    }
    let joined = Zeroizing::new(tokens.join(" "));
    let mnemonic =
        Mnemonic::parse_in_normalized(Language::English, &joined).map_err(|error| match error {
            bip39::Error::InvalidChecksum => ImportError::BadChecksum,
            bip39::Error::BadWordCount(_) | bip39::Error::BadEntropyBitCount(_) => {
                ImportError::WrongWordCount
            }
            _ => ImportError::NotRecognised,
        })?;
    let seed = Seed::new(mnemonic.to_seed(passphrase));
    RootKey::from_seed(network, &seed)
}

/// Imports a phrase. It may be a BIP39 phrase, an Electrum seed, or both at
/// once, which happens by chance; the person's derive-and-compare settles it.
pub(crate) fn import(
    text: &str,
    passphrase: &str,
    network: Network,
) -> Result<Material, ImportError> {
    let lowered = Zeroizing::new(text.to_lowercase());
    let tokens: Vec<&str> = lowered.split_whitespace().collect();
    let bip39 = bip39_root(&tokens, passphrase, network);

    let normalised = electrum_normalise(text);
    let electrum = match electrum_version(&normalised) {
        Some(version @ (ElectrumVersion::Standard | ElectrumVersion::Segwit)) => {
            let kind = if version == ElectrumVersion::Standard {
                ElectrumKind::Standard
            } else {
                ElectrumKind::Segwit
            };
            let seed = electrum_seed(&normalised, passphrase);
            Some(ElectrumRoot {
                root: RootKey::from_seed(network, &seed)?,
                kind,
            })
        }
        Some(ElectrumVersion::TwoFactor | ElectrumVersion::TwoFactorSegwit) => {
            if bip39.is_err() {
                return Err(ImportError::ElectrumKindUnsupported);
            }
            None
        }
        None => None,
    };
    match (bip39, electrum) {
        (Err(error), None) => Err(error),
        (bip39, electrum) => Ok(Material::Words {
            bip39: bip39.ok(),
            electrum,
        }),
    }
}
