//! The derivation plan: every branch of keys a session will be searched on,
//! each with its first address so the person can compare it with the old
//! wallet before anything is scanned (derive-and-compare).

use core::fmt;

use bitcoin::Address;
use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::hex::DisplayHex;
use bitcoin::key::CompressedPublicKey;
use bitcoin::secp256k1::{All, PublicKey, Secp256k1};

use crate::error::PlanError;
use crate::keys::Compression;
use crate::network::Network;
use crate::paths::{
    Chain, ELECTRUM_SEGWIT, ELECTRUM_STANDARD, GAP, PathTemplate, Purpose, QUIRKS, Quirk,
    ScriptKind, TIER_ONE_ACCOUNTS, TypedPath,
};
use crate::secret::{LooseKey, Material, RootKey, Session};
use crate::words::ElectrumKind;

/// How early in the search a branch is looked at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    /// The standard purposes, an Electrum seed's own paths, or the script
    /// kinds of a loose key.
    One,
    /// The paths of wallets with habits.
    Two,
    /// A path the person typed.
    Three,
}

/// Why a branch is in the plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    /// A standard path: `m/purpose'/coin'/account'`.
    Purpose {
        /// BIP44, 49, 84 or 86.
        purpose: Purpose,
        /// The account number.
        account: u32,
    },
    /// A row of the table of wallets with habits.
    Quirk(&'static str),
    /// One of the two chains an Electrum seed uses.
    Electrum(ElectrumKind),
    /// A chain under an account-level extended key.
    Account,
    /// A path the person typed.
    Typed,
    /// A key with no tree. From a wallet file, `listed_address` is the
    /// address the file gave it.
    Key {
        /// The position of the key among those imported.
        index: usize,
        /// The address the wallet file listed for the key, if any.
        listed_address: Option<String>,
    },
}

/// Where a branch gets its keys from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Source {
    Bip39,
    Electrum,
    Extended,
    Key(usize),
}

/// What a tree branch is made of, before its first address is rendered.
struct Spec {
    source: Source,
    tier: Tier,
    origin: Origin,
    template: PathTemplate,
    chain: Option<Chain>,
    kind: ScriptKind,
}

/// One run of addresses to search, with the first one rendered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Branch {
    /// How early the branch is searched.
    pub tier: Tier,
    /// Why the branch is in the plan.
    pub origin: Origin,
    /// The path with the address index left open; `None` for a loose key.
    pub path: Option<PathTemplate>,
    /// The chain, when the path has one.
    pub chain: Option<Chain>,
    /// The script kind of the addresses.
    pub kind: ScriptKind,
    /// How many unused addresses in a row end the search of this branch.
    pub gap: u32,
    /// Address 0 of the branch, for the network of the session.
    pub first_address: Address,
    source: Source,
}

/// A public fingerprint of a plan: the SHA-256 of the first scripts of the
/// tier-1 branches, concatenated in order. It lets a saved search be resumed
/// only when the same secret is entered again.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PlanFingerprint([u8; 32]);

impl PlanFingerprint {
    /// The 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for PlanFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.as_hex())
    }
}

impl fmt::Debug for PlanFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PlanFingerprint({self})")
    }
}

/// The branches a session will be searched on.
pub struct Plan {
    network: Network,
    secp: Secp256k1<All>,
    branches: Vec<Branch>,
    fingerprint: PlanFingerprint,
}

impl fmt::Debug for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Plan")
            .field("network", &self.network)
            .field("branches", &self.branches)
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

/// The kinds a BIP32 key of unknown purpose can have.
const TREE_KINDS: [ScriptKind; 4] = [
    ScriptKind::TREE_P2PKH,
    ScriptKind::P2shP2wpkh,
    ScriptKind::P2wpkh,
    ScriptKind::P2tr,
];

/// Derives along `steps` from `start` and hands the result to `f`. Every
/// intermediate key is erased when it goes out of scope.
pub(crate) fn with_key<R>(
    secp: &Secp256k1<All>,
    start: &RootKey,
    steps: &[ChildNumber],
    f: impl FnOnce(&Xpriv) -> R,
) -> Result<R, PlanError> {
    match steps.split_first() {
        None => Ok(f(start.xpriv())),
        Some((first, rest)) => {
            let child = start
                .xpriv()
                .derive_priv(secp, &[*first])
                .map_err(|_| PlanError::Derivation)?;
            let child = RootKey::new(child);
            with_key(secp, &child, rest, f)
        }
    }
}

/// The address a public key has under a script kind.
fn render(secp: &Secp256k1<All>, network: Network, key: &PublicKey, kind: ScriptKind) -> Address {
    let compressed = CompressedPublicKey(*key);
    let net = network.to_bitcoin();
    match kind {
        ScriptKind::P2pkh { compressed: true } => Address::p2pkh(compressed, net),
        ScriptKind::P2pkh { compressed: false } => {
            Address::p2pkh(bitcoin::PublicKey::new_uncompressed(*key), net)
        }
        ScriptKind::P2shP2wpkh => Address::p2shwpkh(&compressed, net),
        ScriptKind::P2wpkh => Address::p2wpkh(&compressed, net),
        ScriptKind::P2tr => Address::p2tr(secp, key.x_only_public_key().0, None, net),
    }
}

impl Plan {
    /// Builds the plan of a session: tier 1 and tier 2 for words and root
    /// keys, the branches of an account key, or the script kinds of each
    /// loose key.
    ///
    /// # Errors
    ///
    /// [`PlanError::Derivation`] if a key cannot be derived, which BIP32 puts
    /// at about one in 2^127 per key.
    pub fn build(session: &Session) -> Result<Self, PlanError> {
        let mut plan = Self {
            network: session.network(),
            secp: Secp256k1::new(),
            branches: Vec::new(),
            fingerprint: PlanFingerprint([0; 32]),
        };
        match &session.material {
            Material::Words { bip39, electrum } => {
                if let Some(root) = bip39 {
                    plan.push_standard(root, Source::Bip39, None)?;
                    for row in &QUIRKS {
                        let origin = Origin::Quirk(row.name);
                        plan.push_row(root, Source::Bip39, &origin, row, Tier::Two)?;
                    }
                }
                if let Some(electrum) = electrum {
                    let row = match electrum.kind {
                        ElectrumKind::Standard => &ELECTRUM_STANDARD,
                        ElectrumKind::Segwit => &ELECTRUM_SEGWIT,
                    };
                    let origin = Origin::Electrum(electrum.kind);
                    plan.push_row(&electrum.root, Source::Electrum, &origin, row, Tier::One)?;
                }
            }
            Material::Extended(ext) if ext.root.xpriv().depth == 0 => {
                let declared = ext.declared;
                plan.push_standard(&ext.root, Source::Extended, declared)?;
                let electrum_rows = [ELECTRUM_STANDARD, ELECTRUM_SEGWIT];
                for row in QUIRKS.iter().chain(&electrum_rows) {
                    if declared.is_none_or(|kind| row.kind == kind) {
                        let origin = Origin::Quirk(row.name);
                        plan.push_row(&ext.root, Source::Extended, &origin, row, Tier::Two)?;
                    }
                }
            }
            Material::Extended(ext) => plan.push_account_chains(&ext.root, ext.declared)?,
            Material::Keys(keys) => {
                for (index, loose) in keys.iter().enumerate() {
                    plan.push_loose(index, loose);
                }
            }
        }
        // Tier 1 first; the sort is stable, so the order within a tier stays.
        plan.branches.sort_by_key(|branch| branch.tier);
        plan.fingerprint = plan.compute_fingerprint();
        Ok(plan)
    }

    /// Adds a typed path as tier 3. A path ending in `*` names the address
    /// index; any other path is taken as an account and both its chains are
    /// walked. It is walked from every key tree of the session; for an
    /// account-level extended key it is walked from that key.
    ///
    /// # Errors
    ///
    /// [`PlanError::NoTree`] when the session holds only loose keys, and
    /// [`PlanError::Derivation`] if a key cannot be derived.
    pub fn add_typed(
        &mut self,
        session: &Session,
        path: &TypedPath,
        kind: ScriptKind,
    ) -> Result<(), PlanError> {
        let roots: Vec<(Source, &RootKey, bool)> = match &session.material {
            Material::Words { bip39, electrum } => bip39
                .iter()
                .map(|root| (Source::Bip39, root, false))
                .chain(electrum.iter().map(|e| (Source::Electrum, &e.root, false)))
                .collect(),
            Material::Extended(ext) => {
                vec![(Source::Extended, &ext.root, ext.root.xpriv().depth > 0)]
            }
            Material::Keys(_) => return Err(PlanError::NoTree),
        };
        let mut added = Vec::new();
        for (source, root, relative) in roots {
            let steps = path.steps().to_vec();
            let spec = |template, chain| Spec {
                source,
                tier: Tier::Three,
                origin: Origin::Typed,
                template,
                chain,
                kind,
            };
            match path.wildcard() {
                Some(hardened) => {
                    let template = PathTemplate::new(steps, hardened, relative);
                    added.push(self.tree_branch(root, spec(template, None))?);
                }
                None => {
                    for chain in Chain::ALL {
                        let mut chain_steps = steps.clone();
                        chain_steps.push(
                            ChildNumber::from_normal_idx(chain.number())
                                .map_err(|_| PlanError::IndexTooLarge)?,
                        );
                        let template = PathTemplate::new(chain_steps, false, relative);
                        added.push(self.tree_branch(root, spec(template, Some(chain)))?);
                    }
                }
            }
        }
        self.branches.extend(added);
        Ok(())
    }

    /// The network the first addresses are written for.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Every branch, tier 1 first.
    #[must_use]
    pub fn branches(&self) -> &[Branch] {
        &self.branches
    }

    /// The public fingerprint of the plan.
    #[must_use]
    pub const fn fingerprint(&self) -> PlanFingerprint {
        self.fingerprint
    }

    /// The address at `index` of a branch of this plan, which `session` must be
    /// the session the plan was built from.
    ///
    /// # Errors
    ///
    /// [`PlanError::IndexTooLarge`] for an index of 2147483648 or more, and
    /// [`PlanError::Derivation`] if the key cannot be derived.
    pub fn address(
        &self,
        session: &Session,
        branch: &Branch,
        index: u32,
    ) -> Result<Address, PlanError> {
        let key = match (&session.material, branch.source, &branch.path) {
            (Material::Keys(keys), Source::Key(position), None) => {
                let loose = keys.get(position).ok_or(PlanError::NoTree)?;
                loose.key.public_key(&self.secp)
            }
            (_, source, Some(template)) => {
                let root = Self::root_of(session, source).ok_or(PlanError::NoTree)?;
                let steps = template.path_at(index)?;
                with_key(&self.secp, root, &steps, |x| {
                    PublicKey::from_secret_key(&self.secp, &x.private_key)
                })?
            }
            _ => return Err(PlanError::NoTree),
        };
        Ok(render(&self.secp, self.network, &key, branch.kind))
    }

    fn root_of(session: &Session, source: Source) -> Option<&RootKey> {
        match (&session.material, source) {
            (Material::Words { bip39, .. }, Source::Bip39) => bip39.as_ref(),
            (Material::Words { electrum, .. }, Source::Electrum) => {
                electrum.as_ref().map(|e| &e.root)
            }
            (Material::Extended(ext), Source::Extended) => Some(&ext.root),
            _ => None,
        }
    }

    fn tree_branch(&self, root: &RootKey, spec: Spec) -> Result<Branch, PlanError> {
        let steps = spec.template.path_at(0)?;
        let key = with_key(&self.secp, root, &steps, |x| {
            PublicKey::from_secret_key(&self.secp, &x.private_key)
        })?;
        Ok(Branch {
            tier: spec.tier,
            origin: spec.origin,
            path: Some(spec.template),
            chain: spec.chain,
            kind: spec.kind,
            gap: GAP,
            first_address: render(&self.secp, self.network, &key, spec.kind),
            source: spec.source,
        })
    }

    /// Tier 1: the four purposes, accounts 0 to 2, both chains. A declared
    /// script kind keeps only the purposes that produce it.
    fn push_standard(
        &mut self,
        root: &RootKey,
        source: Source,
        declared: Option<ScriptKind>,
    ) -> Result<(), PlanError> {
        for purpose in Purpose::ALL {
            if declared.is_some_and(|kind| purpose.script_kind() != kind) {
                continue;
            }
            for account in 0..TIER_ONE_ACCOUNTS {
                for chain in Chain::ALL {
                    let steps = [
                        ChildNumber::from_hardened_idx(purpose.number()),
                        ChildNumber::from_hardened_idx(self.network.coin_type()),
                        ChildNumber::from_hardened_idx(account),
                        ChildNumber::from_normal_idx(chain.number()),
                    ]
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| PlanError::IndexTooLarge)?;
                    let spec = Spec {
                        source,
                        tier: Tier::One,
                        origin: Origin::Purpose { purpose, account },
                        template: PathTemplate::new(steps, false, false),
                        chain: Some(chain),
                        kind: purpose.script_kind(),
                    };
                    let branch = self.tree_branch(root, spec)?;
                    self.branches.push(branch);
                }
            }
        }
        Ok(())
    }

    /// Both chains of one row of the table of wallets with habits.
    fn push_row(
        &mut self,
        root: &RootKey,
        source: Source,
        origin: &Origin,
        row: &Quirk,
        tier: Tier,
    ) -> Result<(), PlanError> {
        for chain in Chain::ALL {
            let spec = Spec {
                source,
                tier,
                origin: origin.clone(),
                template: row.template(chain, self.network)?,
                chain: Some(chain),
                kind: row.kind,
            };
            let branch = self.tree_branch(root, spec)?;
            self.branches.push(branch);
        }
        Ok(())
    }

    /// The two chains under an account-level extended key, for the declared
    /// script kind or, when the version bytes declared none, for every kind.
    fn push_account_chains(
        &mut self,
        root: &RootKey,
        declared: Option<ScriptKind>,
    ) -> Result<(), PlanError> {
        let kinds: &[ScriptKind] = match &declared {
            Some(kind) => core::slice::from_ref(kind),
            None => &TREE_KINDS,
        };
        for &kind in kinds {
            for chain in Chain::ALL {
                let step = ChildNumber::from_normal_idx(chain.number())
                    .map_err(|_| PlanError::IndexTooLarge)?;
                let spec = Spec {
                    source: Source::Extended,
                    tier: Tier::One,
                    origin: Origin::Account,
                    template: PathTemplate::new(vec![step], false, true),
                    chain: Some(chain),
                    kind,
                };
                let branch = self.tree_branch(root, spec)?;
                self.branches.push(branch);
            }
        }
        Ok(())
    }

    /// One branch for each script kind a loose key can have.
    fn push_loose(&mut self, index: usize, loose: &LooseKey) {
        let compressed = ScriptKind::TREE_P2PKH;
        let uncompressed = ScriptKind::P2pkh { compressed: false };
        let kinds: &[ScriptKind] = match loose.compression {
            Compression::Compressed => &[
                compressed,
                ScriptKind::P2shP2wpkh,
                ScriptKind::P2wpkh,
                ScriptKind::P2tr,
            ],
            Compression::Uncompressed => &[uncompressed],
            Compression::Unknown => &[
                compressed,
                uncompressed,
                ScriptKind::P2shP2wpkh,
                ScriptKind::P2wpkh,
                ScriptKind::P2tr,
            ],
        };
        let public = loose.key.public_key(&self.secp);
        for &kind in kinds {
            self.branches.push(Branch {
                tier: Tier::One,
                origin: Origin::Key {
                    index,
                    listed_address: loose.listed_address.clone(),
                },
                path: None,
                chain: None,
                kind,
                gap: 1,
                first_address: render(&self.secp, self.network, &public, kind),
                source: Source::Key(index),
            });
        }
    }

    fn compute_fingerprint(&self) -> PlanFingerprint {
        let mut scripts = Vec::new();
        for branch in self.branches.iter().filter(|b| b.tier == Tier::One) {
            scripts.extend_from_slice(branch.first_address.script_pubkey().as_bytes());
        }
        PlanFingerprint(sha256::Hash::hash(&scripts).to_byte_array())
    }
}
