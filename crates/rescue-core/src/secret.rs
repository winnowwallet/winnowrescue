//! The secret types and the session that holds them.
//!
//! Every type here is zeroized or erased when it is dropped, prints
//! `<redacted>` for `Debug`, and is neither `Clone` nor `Serialize`; the
//! assertions at the bottom of the file stop the build if that ever changes.
//! Nothing here hands a secret out by value: a [`KeyHandle`] can say what its
//! public key is and the crate can sign with it, and that is all.

use bitcoin::bip32::{ChainCode, Xpriv};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey, Signing};
use zeroize::Zeroizing;

use crate::error::ImportError;
use crate::keys::{self, Compression, Form};
use crate::network::Network;
use crate::paths::ScriptKind;
use crate::words::{self, ElectrumKind};

/// What the person typed or pasted: words, a key, an extended key or the text
/// of a wallet file. It takes ownership of the `String` and wipes it on drop.
pub struct SecretInput(Zeroizing<String>);

impl SecretInput {
    /// Takes the text; the caller's `String` is consumed so no unwiped copy is
    /// left behind by this crate.
    #[must_use]
    pub fn new(text: String) -> Self {
        Self(Zeroizing::new(text))
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl From<String> for SecretInput {
    fn from(text: String) -> Self {
        Self::new(text)
    }
}

/// A 64-byte BIP39 or Electrum seed, wiped on drop.
pub struct Seed(Zeroizing<[u8; 64]>);

impl Seed {
    pub(crate) fn new(bytes: [u8; 64]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// A BIP32 extended private key. The key and the chain code are overwritten
/// when it is dropped, and it cannot be copied.
pub struct RootKey(Xpriv);

impl RootKey {
    pub(crate) fn new(key: Xpriv) -> Self {
        Self(key)
    }

    /// The BIP32 master key of a seed.
    pub(crate) fn from_seed(network: Network, seed: &Seed) -> Result<Self, ImportError> {
        Xpriv::new_master(network.kind(), seed.as_bytes())
            .map(Self::new)
            .map_err(|_| ImportError::KeyOutOfRange)
    }

    pub(crate) fn xpriv(&self) -> &Xpriv {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn erase_now(&mut self) {
        self.erase();
    }
}

impl RootKey {
    /// Overwrites the private key and zeroes the chain code.
    fn erase(&mut self) {
        self.0.private_key.non_secure_erase();
        if let Ok(zero) = ChainCode::try_from(&[0_u8; 32][..]) {
            self.0.chain_code = zero;
        }
        // Keep the compiler from deciding the writes above are dead.
        core::hint::black_box(&self.0);
    }
}

impl Drop for RootKey {
    fn drop(&mut self) {
        self.erase();
    }
}

/// One secp256k1 secret key, erased on drop. It is never returned by value
/// from this crate.
pub struct KeyHandle(SecretKey);

impl KeyHandle {
    pub(crate) fn new(key: SecretKey) -> Self {
        Self(key)
    }

    /// The public key, which is not a secret.
    #[must_use]
    pub fn public_key<C: Signing>(&self, secp: &Secp256k1<C>) -> PublicKey {
        PublicKey::from_secret_key(secp, &self.0)
    }

    #[cfg(test)]
    pub(crate) fn secret_key(&self) -> &SecretKey {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn erase_now(&mut self) {
        self.erase();
    }
}

impl KeyHandle {
    /// Overwrites the secret key.
    fn erase(&mut self) {
        self.0.non_secure_erase();
        core::hint::black_box(&self.0);
    }
}

impl Drop for KeyHandle {
    fn drop(&mut self) {
        self.erase();
    }
}

/// A private key that is not part of a tree, with what is known of the form
/// of its public key and, from a wallet file, the address it was listed with.
pub(crate) struct LooseKey {
    pub(crate) key: KeyHandle,
    pub(crate) compression: Compression,
    pub(crate) listed_address: Option<String>,
}

/// An Electrum root: the master key of the seed and which kind of seed it was.
pub(crate) struct ElectrumRoot {
    pub(crate) root: RootKey,
    pub(crate) kind: ElectrumKind,
}

/// An extended private key the person gave, and the script kind its version
/// bytes declared (`None` for the plain `xprv` and `tprv`).
pub(crate) struct ExtendedRoot {
    pub(crate) root: RootKey,
    pub(crate) declared: Option<ScriptKind>,
}

/// Whatever the plan needs to derive keys later.
pub(crate) enum Material {
    /// Words. A phrase can be valid as BIP39 and as an Electrum seed at once,
    /// by chance; both readings are kept.
    Words {
        bip39: Option<RootKey>,
        electrum: Option<ElectrumRoot>,
    },
    /// An extended private key.
    Extended(ExtendedRoot),
    /// One or more keys with no tree: WIF, mini key, hex or a wallet file.
    Keys(Vec<LooseKey>),
}

/// What a session was made from, for showing the person.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionKind {
    /// Words. `bip39` says the phrase passed the BIP39 checksum; `electrum`
    /// is set when it is also an Electrum 2.x seed of a supported kind.
    Words {
        /// The phrase is a valid BIP39 phrase.
        bip39: bool,
        /// The phrase is an Electrum seed of this kind.
        electrum: Option<ElectrumKind>,
    },
    /// An extended private key at this depth below the root.
    ExtendedKey {
        /// 0 for a root key, 3 for an account key, and so on.
        depth: u8,
        /// The script kind the version bytes declared, if they did.
        declared: Option<ScriptKind>,
    },
    /// Loose keys with no tree.
    Keys {
        /// How many keys.
        count: usize,
    },
}

/// A secret imported for one network, ready for a [`crate::plan::Plan`] to be
/// made from it. It cannot be copied, serialized or printed.
pub struct Session {
    network: Network,
    pub(crate) material: Material,
}

impl Session {
    pub(crate) fn from_material(network: Network, material: Material) -> Self {
        Self { network, material }
    }

    /// Reads what the person typed. The text is consumed and wiped whatever
    /// the outcome. `passphrase` goes with words only; an empty one counts as
    /// none.
    ///
    /// # Errors
    ///
    /// An [`ImportError`] naming what is wrong, never carrying the secret.
    pub fn import(
        secret: SecretInput,
        passphrase: Option<SecretInput>,
        network: Network,
    ) -> Result<Self, ImportError> {
        let outcome = Self::from_text(
            secret.as_str(),
            passphrase.as_ref().map(SecretInput::as_str),
            network,
        );
        // Wiped here, whatever the outcome; the caller keeps no copy.
        drop(secret);
        drop(passphrase);
        outcome
    }

    fn from_text(
        text: &str,
        passphrase: Option<&str>,
        network: Network,
    ) -> Result<Self, ImportError> {
        let text = text.trim();
        if text.is_empty() {
            return Err(ImportError::Empty);
        }
        let passphrase = passphrase.filter(|p| !p.is_empty());
        let form = keys::classify(text);
        if passphrase.is_some() && form != Form::Words {
            return Err(ImportError::PassphraseNotApplicable);
        }
        let material = match form {
            Form::Words => words::import(text, passphrase.unwrap_or(""), network)?,
            Form::Extended => Material::Extended(keys::parse_extended(text, network)?.into_root()),
            Form::Wif => Material::Keys(vec![keys::parse_wif(text, network)?.into_loose()]),
            Form::Mini => Material::Keys(vec![keys::parse_mini(text)?.into_loose()]),
            Form::Hex => Material::Keys(vec![keys::parse_hex(text)?.into_loose()]),
            Form::WalletFile => {
                let dumped = keys::parse_dumpwallet(text, network)?;
                Material::Keys(
                    dumped
                        .into_iter()
                        .map(keys::DumpedKey::into_loose)
                        .collect(),
                )
            }
            Form::Unknown => return Err(ImportError::NotRecognised),
        };
        Ok(Self::from_material(network, material))
    }

    /// The network the session was imported for.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// What the session was made from.
    #[must_use]
    pub fn kind(&self) -> SessionKind {
        match &self.material {
            Material::Words { bip39, electrum } => SessionKind::Words {
                bip39: bip39.is_some(),
                electrum: electrum.as_ref().map(|e| e.kind),
            },
            Material::Extended(ext) => SessionKind::ExtendedKey {
                depth: ext.root.xpriv().depth,
                declared: ext.declared,
            },
            Material::Keys(keys) => SessionKind::Keys { count: keys.len() },
        }
    }
}

macro_rules! redacted_debug {
    ($($secret:ty),+ $(,)?) => {$(
        impl ::core::fmt::Debug for $secret {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str("<redacted>")
            }
        }
        ::static_assertions::assert_not_impl_any!($secret: ::serde::Serialize, Clone);
    )+};
}

redacted_debug!(SecretInput, Seed, RootKey, KeyHandle, Session);

pub(crate) use redacted_debug;
