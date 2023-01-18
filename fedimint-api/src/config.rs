use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::hash::Hash;
use std::io::Write;
use std::ops::Mul;
use std::str::FromStr;

use anyhow::bail;
use anyhow::format_err;
use bitcoin::secp256k1;
use bitcoin_hashes::hex;
use bitcoin_hashes::hex::{FromHex, ToHex};
use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::sha256::HashEngine;
use fedimint_api::BitcoinHash;
use hbbft::crypto::group::Curve;
use hbbft::crypto::group::GroupEncoding;
use hbbft::crypto::poly::Commitment;
use hbbft::crypto::{G1Projective, G2Projective, PublicKeySet, SecretKeyShare};
use hbbft::pairing::group::Group;
use rand::{CryptoRng, RngCore};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tbs::hash::hash_bytes_to_curve;
use tbs::poly::Poly;
use tbs::serde_impl;
use tbs::Scalar;
use threshold_crypto::serde_impl::SerdeSecret;
use url::Url;

use crate::cancellable::Cancellable;
use crate::core::{ModuleInstanceId, ModuleKind};
use crate::net::peers::MuxPeerConnections;
use crate::PeerId;

/// [`serde_json::Value`] that must contain `kind: String` field
///
/// TODO: enforce at ser/deserialization
/// TODO: make inside prive and enforce `kind` on construction, to
/// other functions non-falliable
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonWithKind {
    kind: ModuleKind,
    #[serde(flatten)]
    value: serde_json::Value,
}

impl JsonWithKind {
    pub fn new(kind: ModuleKind, value: serde_json::Value) -> Self {
        Self { kind, value }
    }

    /// Workaround for a serde `flatten` quirk
    ///
    /// We serialize config with no fields as: eg. `{ kind: "ln" }`.
    ///
    /// When `kind` gets removed and `value` is parsed, it will
    /// parse as `Value::Object` that is empty.
    ///
    /// Howerver empty module structs, like `struct FooConfigLocal;` (unit struct),
    /// will fail to deserialize with this value, as they expect
    /// `Value::Null`.
    ///
    /// We can turn manually empty object into null, and that's what
    /// we do in this function. This fixes the deserialization into
    /// unit type, but in turn breaks deserialization into `struct Foo{}`,
    /// which is arguably much less common, but valid.
    ///
    /// TODO: In the future, we should have a typed and erased versions of
    /// module construction traits, and then we can try with and
    /// without the workaround to have both cases working.
    /// See https://github.com/fedimint/fedimint/issues/1303
    pub fn with_fixed_empty_value(self) -> Self {
        if let serde_json::Value::Object(ref o) = self.value {
            if o.is_empty() {
                return Self {
                    kind: self.kind,
                    value: serde_json::Value::Null,
                };
            }
        }

        self
    }

    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    pub fn kind(&self) -> &ModuleKind {
        &self.kind
    }

    pub fn is_kind(&self, kind: &ModuleKind) -> bool {
        &self.kind == kind
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ApiEndpoint {
    /// The peer's API websocket network address and port (e.g. `ws://10.42.0.10:5000`)
    pub url: Url,
    /// human-readable name
    pub name: String,
}

/// Total client config
///
/// This includes global settings and client-side module configs.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClientConfig {
    /// name of the federation
    pub federation_name: String,
    // Stable and unique id and threshold pubkey of the federation for authenticating configs
    pub federation_id: FederationId,
    /// API endpoints for each federation member
    pub nodes: Vec<ApiEndpoint>,
    /// Threshold pubkey for authenticating epoch history
    pub epoch_pk: threshold_crypto::PublicKey,
    /// Configs from other client modules
    pub modules: BTreeMap<ModuleInstanceId, ClientModuleConfig>,
}

/// The federation id is a copy of the authentication threshold public key of the federation
///
/// Stable id so long as guardians membership does not change
/// Unique id so long as guardians do not all collude
#[derive(Debug, Serialize, Deserialize, Clone, Eq, Hash, PartialEq)]
pub struct FederationId(pub threshold_crypto::PublicKey);

/// Display as a hex encoding
impl FederationId {
    /// Non-unique dummy id for testing
    pub fn dummy() -> Self {
        Self(threshold_crypto::PublicKey::from(G1Projective::identity()))
    }

    fn try_from_bytes(bytes: [u8; 48]) -> Option<Self> {
        Some(Self(threshold_crypto::PublicKey::from_bytes(bytes).ok()?))
    }
}

impl ToString for FederationId {
    fn to_string(&self) -> String {
        self.0.to_bytes().to_hex()
    }
}

impl FromStr for FederationId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from_bytes(
            Vec::from_hex(s)?
                .try_into()
                .map_err(|bytes: Vec<u8>| hex::Error::InvalidLength(48, bytes.len()))?,
        )
        .ok_or_else::<anyhow::Error, _>(|| format_err!("Invalid FederationId pubkey"))
    }
}

impl ClientConfig {
    pub fn get_module<T: DeserializeOwned>(&self, id: ModuleInstanceId) -> anyhow::Result<T> {
        if let Some(client_cfg) = self.modules.get(&id) {
            Ok(serde_json::from_value(client_cfg.0.value().clone())?)
        } else {
            Err(format_err!("Client config for module id: {id} not found"))
        }
    }

    /// (soft-deprecated): Get the first instance of a module of a given kind in defined in config
    ///
    /// Since module ids are numerical and for time being we only support 1:1 mint, wallet, ln
    /// module code in the client, this is useful, but please write any new code that avoids
    /// assumptions about available modules.
    pub fn get_first_module_by_kind<T: DeserializeOwned>(
        &self,
        kind: impl Into<ModuleKind>,
    ) -> anyhow::Result<(ModuleInstanceId, T)> {
        let kind: ModuleKind = kind.into();
        let Some((id, module_cfg)) = self.modules.iter().find(|(_, v)| v.is_kind(&kind)) else {
            anyhow::bail!("Module kind {kind} not found")
        };

        Ok((*id, serde_json::from_value(module_cfg.0.value().clone())?))
    }
}

/// Global Fedimint configuration generation settings passed to modules
///
/// This includes typed module settings for know modules for simplicity,
/// and better UX, while the non-standard modules have to use a type-erased
/// config.
///
/// Candidate for re-designing when the modularization effort is
/// complete.
#[derive(Debug, Clone, Default)]
pub struct ConfigGenParams(BTreeMap<String, serde_json::Value>);

impl ConfigGenParams {
    pub fn new() -> ConfigGenParams {
        ConfigGenParams::default()
    }

    /// Add params for a module
    pub fn attach<P: ModuleGenParams>(mut self, module_params: P) -> Self {
        self.0.insert(
            P::MODULE_NAME.to_string(),
            serde_json::to_value(&module_params).expect("Encoding to value doesn't fail"),
        );
        self
    }

    /// Retrieve a typed config generation parameters for a module
    pub fn get<P: ModuleGenParams>(&self) -> anyhow::Result<P> {
        let value = self
            .0
            .get(P::MODULE_NAME)
            .ok_or_else(|| anyhow::anyhow!("No params found for module {}", P::MODULE_NAME))?;
        serde_json::from_value(value.clone())
            .map_err(|e| anyhow::Error::new(e).context("Invalid module params"))
    }
}

pub trait ModuleGenParams: serde::Serialize + serde::de::DeserializeOwned {
    const MODULE_NAME: &'static str;
}

/// Config for the client-side of a particular Federation module
///
/// Since modules are (tbd.) pluggable into Federations,
/// it needs to be some form of an abstract type-erased-like
/// value.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClientModuleConfig(JsonWithKind);

impl ClientModuleConfig {
    pub fn new(kind: ModuleKind, value: serde_json::Value) -> Self {
        Self(JsonWithKind::new(kind, value))
    }

    pub fn is_kind(&self, kind: &ModuleKind) -> bool {
        self.0.is_kind(kind)
    }

    pub fn kind(&self) -> &ModuleKind {
        self.0.kind()
    }

    pub fn value(&self) -> &serde_json::Value {
        self.0.value()
    }
}

impl ClientModuleConfig {
    pub fn cast<T: TypedClientModuleConfig>(&self) -> anyhow::Result<T> {
        Ok(serde_json::from_value(self.0.value().clone())?)
    }
}

/// Config for the server-side of a particular Federation module
///
/// See [`ClientModuleConfig`].
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServerModuleConfig {
    pub local: JsonWithKind,
    pub private: JsonWithKind,
    pub consensus: JsonWithKind,
}

impl ServerModuleConfig {
    pub fn from(local: JsonWithKind, private: JsonWithKind, consensus: JsonWithKind) -> Self {
        Self {
            local,
            private,
            consensus,
        }
    }

    pub fn to_typed<T: TypedServerModuleConfig>(&self) -> anyhow::Result<T> {
        let local = serde_json::from_value(self.local.value().clone())?;
        let private = serde_json::from_value(self.private.value().clone())?;
        let consensus = serde_json::from_value(self.consensus.value().clone())?;

        Ok(TypedServerModuleConfig::from_parts(
            local, private, consensus,
        ))
    }
}

/// Consensus-critical part of a server side module config
pub trait TypedServerModuleConsensusConfig: DeserializeOwned + Serialize {
    /// Derive client side config for this module (type-erased)
    fn to_client_config(&self) -> ClientModuleConfig;
}

/// Module (server side) config
pub trait TypedServerModuleConfig: DeserializeOwned + Serialize {
    /// Local non-consensus, not security-sensitive settings
    type Local: DeserializeOwned + Serialize;
    /// Private for this federation member data that are security sensitive and will be encrypted at rest
    type Private: DeserializeOwned + Serialize;
    /// Shared consensus-critical config
    type Consensus: TypedServerModuleConsensusConfig;

    /// Assemble from the three functionally distinct parts
    fn from_parts(local: Self::Local, private: Self::Private, consensus: Self::Consensus) -> Self;

    /// Split the config into its three functionally distinct parts
    fn to_parts(self) -> (ModuleKind, Self::Local, Self::Private, Self::Consensus);

    /// Turn the typed config into type-erased version
    fn to_erased(self) -> ServerModuleConfig {
        let (kind, local, private, consensus) = self.to_parts();

        ServerModuleConfig {
            local: JsonWithKind::new(
                kind.clone(),
                serde_json::to_value(local).expect("serialization can't fail"),
            ),
            private: JsonWithKind::new(
                kind.clone(),
                serde_json::to_value(private).expect("serialization can't fail"),
            ),
            consensus: JsonWithKind::new(
                kind,
                serde_json::to_value(consensus).expect("serialization can't fail"),
            ),
        }
    }

    /// Validate the config
    fn validate_config(&self, identity: &PeerId) -> anyhow::Result<()>;
}

/// Typed client side module config
pub trait TypedClientModuleConfig: DeserializeOwned + Serialize {
    fn kind(&self) -> ModuleKind;

    fn to_erased(&self) -> ClientModuleConfig {
        ClientModuleConfig::new(
            self.kind(),
            serde_json::to_value(self).expect("serialization can't fail"),
        )
    }
}

/// Things that a `distributed_gen` config can send between peers
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum DkgPeerMsg {
    PublicKey(secp256k1::PublicKey),
    DistributedGen((String, SupportedDkgMessage)),
}

/// Supported (by Fedimint's code) `DkgMessage<T>` types
///
/// Since `DkgMessage` is an open-set, yet we only use a subset of it,
/// we can make a subset-trait to convert it to an `enum` that we
/// it's easier to handle.
///
/// Candidate for refactoring after modularization effort is complete.
pub trait ISupportedDkgMessage: Sized + Serialize + DeserializeOwned {
    fn to_msg(self) -> SupportedDkgMessage;
    fn from_msg(msg: SupportedDkgMessage) -> anyhow::Result<Self>;
}

/// `enum` version of [`SupportedDkgMessage`]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SupportedDkgMessage {
    G1(DkgMessage<G1Projective>),
    G2(DkgMessage<G2Projective>),
}

impl ISupportedDkgMessage for DkgMessage<G1Projective> {
    fn to_msg(self) -> SupportedDkgMessage {
        SupportedDkgMessage::G1(self)
    }

    fn from_msg(msg: SupportedDkgMessage) -> anyhow::Result<Self> {
        match msg {
            SupportedDkgMessage::G1(s) => Ok(s),
            SupportedDkgMessage::G2(_) => bail!("Incorrect DkgGroup: G2"),
        }
    }
}

impl ISupportedDkgMessage for DkgMessage<G2Projective> {
    fn to_msg(self) -> SupportedDkgMessage {
        SupportedDkgMessage::G2(self)
    }

    fn from_msg(msg: SupportedDkgMessage) -> anyhow::Result<Self> {
        match msg {
            SupportedDkgMessage::G1(_) => bail!("Incorrect DkgGroup: G1"),
            SupportedDkgMessage::G2(s) => Ok(s),
        }
    }
}

struct Dkg<G> {
    gen_g: G,
    peers: Vec<PeerId>,
    our_id: PeerId,
    threshold: usize,
    f1_poly: Poly<Scalar, Scalar>,
    f2_poly: Poly<Scalar, Scalar>,
    hashed_commits: BTreeMap<PeerId, Sha256>,
    commitments: BTreeMap<PeerId, Vec<G>>,
    sk_shares: BTreeMap<PeerId, Scalar>,
    pk_shares: BTreeMap<PeerId, Vec<G>>,
}

/// Implementation of "Secure Distributed Key Generation for Discrete-Log Based Cryptosystems"
/// by Rosario Gennaro and Stanislaw Jarecki and Hugo Krawczyk and Tal Rabin
///
/// Prevents any manipulation of the secret key, but fails with any non-cooperative peers
impl<G: DkgGroup> Dkg<G> {
    /// Creates the DKG and the first step of the algorithm
    pub fn new(
        group: G,
        our_id: PeerId,
        peers: Vec<PeerId>,
        threshold: usize,
        rng: &mut impl rand::RngCore,
    ) -> (Self, DkgStep<G>) {
        let f1_poly: Poly<Scalar, Scalar> = Poly::random(threshold - 1, rng);
        let f2_poly: Poly<Scalar, Scalar> = Poly::random(threshold - 1, rng);

        let mut dkg = Dkg {
            gen_g: group,
            peers,
            our_id,
            threshold,
            f1_poly,
            f2_poly,
            hashed_commits: Default::default(),
            commitments: Default::default(),
            sk_shares: Default::default(),
            pk_shares: Default::default(),
        };

        // broadcast our commitment to the polynomials
        let commit: Vec<G> = dkg
            .f1_poly
            .coefficients()
            .map(|c| dkg.gen_g * *c)
            .zip(dkg.f2_poly.coefficients().map(|c| dkg.gen_h() * *c))
            .map(|(g, h)| g + h)
            .collect();

        let hashed = dkg.hash(commit.clone());
        dkg.commitments.insert(our_id, commit);
        dkg.hashed_commits.insert(our_id, hashed);
        let step = dkg.broadcast(DkgMessage::HashedCommit(hashed));

        (dkg, step)
    }

    /// Runs a single step of the DKG algorithm, processing a `msg` from `peer`
    pub fn step(&mut self, peer: PeerId, msg: DkgMessage<G>) -> DkgStep<G> {
        match msg {
            DkgMessage::HashedCommit(hashed) => {
                match self.hashed_commits.get(&peer) {
                    Some(old) if *old != hashed => panic!("{} sent us two hashes!", peer),
                    _ => self.hashed_commits.insert(peer, hashed),
                };

                if self.hashed_commits.len() == self.peers.len() {
                    let our_commit = self.commitments[&self.our_id].clone();
                    return self.broadcast(DkgMessage::Commit(our_commit));
                }
            }
            DkgMessage::Commit(commit) => {
                let hash = self.hash(commit.clone());
                assert_eq!(self.threshold, commit.len(), "wrong degree from {}", peer);
                assert_eq!(hash, self.hashed_commits[&peer], "wrong hash from {}", peer);

                match self.commitments.get(&peer) {
                    Some(old) if *old != commit => panic!("{} sent us two commitments!", peer),
                    _ => self.commitments.insert(peer, commit),
                };

                // once everyone has made commitments, send out shares
                if self.commitments.len() == self.peers.len() {
                    let mut messages = vec![];
                    for peer in &self.peers {
                        let s1 = self.f1_poly.evaluate(scalar(peer));
                        let s2 = self.f2_poly.evaluate(scalar(peer));

                        if *peer == self.our_id {
                            self.sk_shares.insert(self.our_id, s1);
                        } else {
                            messages.push((*peer, DkgMessage::Share(s1, s2)));
                        }
                    }
                    return DkgStep::Messages(messages);
                }
            }
            // Pedersen-VSS verifies the shares match the commitments
            DkgMessage::Share(s1, s2) => {
                let share_product = (self.gen_g * s1) + (self.gen_h() * s2);
                let commitment = self
                    .commitments
                    .get(&peer)
                    .unwrap_or_else(|| panic!("{} sent share before commit", peer));
                let commit_product: G = commitment
                    .iter()
                    .enumerate()
                    .map(|(idx, commit)| *commit * scalar(&self.our_id).pow(&[idx as u64, 0, 0, 0]))
                    .reduce(|a, b| a + b)
                    .expect("sums");

                assert_eq!(share_product, commit_product, "bad commit from {}", peer);
                match self.sk_shares.get(&peer) {
                    Some(old) if *old != s1 => panic!("{} sent us two shares!", peer),
                    _ => self.sk_shares.insert(peer, s1),
                };

                if self.sk_shares.len() == self.peers.len() {
                    let extract: Vec<G> = self
                        .f1_poly
                        .coefficients()
                        .map(|c| self.gen_g * *c)
                        .collect();

                    self.pk_shares.insert(self.our_id, extract.clone());
                    return self.broadcast(DkgMessage::Extract(extract));
                }
            }
            // Feldman-VSS exposes the public key shares
            DkgMessage::Extract(extract) => {
                let share = self
                    .sk_shares
                    .get(&peer)
                    .unwrap_or_else(|| panic!("{} sent extract before share", peer));
                let share_product = self.gen_g * *share;
                let extract_product: G = extract
                    .iter()
                    .enumerate()
                    .map(|(idx, commit)| *commit * scalar(&self.our_id).pow(&[idx as u64, 0, 0, 0]))
                    .reduce(|a, b| a + b)
                    .expect("sums");

                assert_eq!(share_product, extract_product, "bad extract from {}", peer);
                assert_eq!(self.threshold, extract.len(), "wrong degree from {}", peer);
                match self.pk_shares.get(&peer) {
                    Some(old) if *old != extract => panic!("{} sent us two extracts!", peer),
                    _ => self.pk_shares.insert(peer, extract),
                };

                if self.pk_shares.len() == self.peers.len() {
                    let sks = self.sk_shares.values().sum();

                    let pks: Vec<G> = (0..self.threshold)
                        .map(|idx| {
                            self.pk_shares
                                .values()
                                .map(|shares| *shares.get(idx).unwrap())
                                .reduce(|a, b| a + b)
                                .expect("sums")
                        })
                        .collect();

                    return DkgStep::Result(DkgKeys {
                        public_key_set: pks,
                        secret_key_share: sks,
                    });
                }
            }
        }

        DkgStep::Messages(vec![])
    }

    fn hash(&self, poly: Vec<G>) -> Sha256 {
        let mut engine = HashEngine::default();
        for element in poly.iter() {
            engine
                .write_all(element.to_bytes().as_ref())
                .expect("hashes");
        }
        Sha256::from_engine(engine)
    }

    fn broadcast(&self, msg: DkgMessage<G>) -> DkgStep<G> {
        let others = self.peers.iter().filter(|p| **p != self.our_id);
        DkgStep::Messages(others.map(|peer| (*peer, msg.clone())).collect())
    }

    /// Get a second generator by hashing the first one to the curve
    fn gen_h(&self) -> G {
        hash_bytes_to_curve::<G>(self.gen_g.clone().to_bytes().as_ref())
    }
}

/// PeerIds are offset by 1, since evaluating a poly at 0 reveals the secret
pub fn scalar(peer: &PeerId) -> Scalar {
    Scalar::from(peer.to_usize() as u64 + 1)
}

pub struct DkgRunner<T> {
    peers: Vec<PeerId>,
    our_id: PeerId,
    dkg_config: HashMap<T, usize>,
}

/// Helper for running multiple DKGs over the same peer connections
///
/// Messages are `(T, DkgMessage)` for creating a DKG for every `T`
impl<T> DkgRunner<T>
where
    T: Serialize + DeserializeOwned + Unpin + Send + Clone + Eq + Hash,
{
    /// Create multiple DKGs with the same `threshold` signatures required
    pub fn multi(keys: Vec<T>, threshold: usize, our_id: &PeerId, peers: &[PeerId]) -> Self {
        let dkg_config = keys.into_iter().map(|key| (key, threshold)).collect();

        Self {
            our_id: *our_id,
            peers: peers.to_vec(),
            dkg_config,
        }
    }

    /// Create a single DKG with `threshold` signatures required
    pub fn new(key: T, threshold: usize, our_id: &PeerId, peers: &[PeerId]) -> Self {
        Self::multi(vec![key], threshold, our_id, peers)
    }

    /// Create another DKG with `threshold` signatures required
    pub fn add(&mut self, key: T, threshold: usize) {
        self.dkg_config.insert(key, threshold);
    }

    /// Create keys from G2 (96B keys, 48B messages) used in `tbs`
    pub async fn run_g2(
        &mut self,
        module_id: ModuleInstanceId,
        connections: &MuxPeerConnections<ModuleInstanceId, DkgPeerMsg>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Cancellable<HashMap<T, DkgKeys<G2Projective>>> {
        self.run(module_id, G2Projective::generator(), connections, rng)
            .await
    }

    /// Create keys from G1 (48B keys, 96B messages) used in `threshold_crypto`
    pub async fn run_g1(
        &mut self,
        module_id: ModuleInstanceId,
        connections: &MuxPeerConnections<ModuleInstanceId, DkgPeerMsg>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Cancellable<HashMap<T, DkgKeys<G1Projective>>> {
        self.run(module_id, G1Projective::generator(), connections, rng)
            .await
    }

    /// Runs the DKG algorithms with our peers
    pub async fn run<G: DkgGroup>(
        &mut self,
        module_id: ModuleInstanceId,
        group: G,
        connections: &MuxPeerConnections<ModuleInstanceId, DkgPeerMsg>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Cancellable<HashMap<T, DkgKeys<G>>>
    where
        DkgMessage<G>: ISupportedDkgMessage,
    {
        let mut dkgs: HashMap<T, Dkg<G>> = HashMap::new();
        let mut results: HashMap<T, DkgKeys<G>> = HashMap::new();

        // create the dkgs and send our initial messages
        for (key, threshold) in self.dkg_config.iter() {
            let our_id = self.our_id;
            let peers = self.peers.clone();
            let (dkg, step) = Dkg::new(group, our_id, peers, *threshold, rng);
            if let DkgStep::Messages(messages) = step {
                for (peer, msg) in messages {
                    connections
                        .send(
                            &[peer],
                            module_id,
                            DkgPeerMsg::DistributedGen((
                                serde_json::to_string(key).expect("serialization can't fail"),
                                msg.to_msg(),
                            )),
                        )
                        .await?;
                }
            }
            dkgs.insert(key.clone(), dkg);
        }

        // process steps for each key
        // TODO: fix error handling here; what do we do on a malfunctining peer when building the federation?
        loop {
            let (peer, msg) = connections.receive(module_id).await?;

            let (key, message) = if let DkgPeerMsg::DistributedGen(v) = msg {
                v
            } else {
                panic!("Module {module_id} wrong message received: {msg:?}")
            };

            let key = serde_json::from_str(&key).expect("invalid key");
            let message = ISupportedDkgMessage::from_msg(message).expect("invalid message");
            let step = dkgs.get_mut(&key).expect("exists").step(peer, message);

            match step {
                DkgStep::Messages(messages) => {
                    for (peer, msg) in messages {
                        connections
                            .send(
                                &[peer],
                                module_id,
                                DkgPeerMsg::DistributedGen((
                                    serde_json::to_string(&key)
                                        .expect("FIXME - handle errors here"),
                                    msg.to_msg(),
                                )),
                            )
                            .await?;
                    }
                }
                DkgStep::Result(result) => {
                    results.insert(key, result);
                }
            }

            if results.len() == dkgs.len() {
                return Ok(results);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum DkgStep<G: DkgGroup> {
    Messages(Vec<(PeerId, DkgMessage<G>)>),
    Result(DkgKeys<G>),
}

#[derive(Debug, Clone)]
pub struct DkgKeys<G> {
    pub public_key_set: Vec<G>,
    pub secret_key_share: Scalar,
}

/// Our secret key share of a threshold key
#[derive(Debug, Clone)]
pub struct ThresholdKeys {
    pub public_key_set: PublicKeySet,
    pub secret_key_share: SerdeSecret<SecretKeyShare>,
}

impl DkgKeys<G2Projective> {
    pub fn tbs(self) -> (Poly<G2Projective, Scalar>, tbs::SecretKeyShare) {
        (
            Poly::from(self.public_key_set),
            tbs::SecretKeyShare(self.secret_key_share),
        )
    }
}

impl DkgKeys<G1Projective> {
    pub fn threshold_crypto(&self) -> ThresholdKeys {
        ThresholdKeys {
            public_key_set: PublicKeySet::from(Commitment::from(self.public_key_set.clone())),
            secret_key_share: SerdeSecret(SecretKeyShare::from_mut(
                &mut self.secret_key_share.clone(),
            )),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum DkgMessage<G: DkgGroup> {
    HashedCommit(Sha256),
    Commit(#[serde(with = "serde_commit")] Vec<G>),
    Share(
        #[serde(with = "serde_impl::scalar")] Scalar,
        #[serde(with = "serde_impl::scalar")] Scalar,
    ),
    Extract(#[serde(with = "serde_commit")] Vec<G>),
}

/// Defines a group (e.g. G1 or G2) that we can generate keys for
pub trait DkgGroup:
    Group + Mul<Scalar, Output = Self> + Curve + GroupEncoding + SGroup + Unpin
{
}

impl<T: Group + Mul<Scalar, Output = T> + Curve + GroupEncoding + SGroup + Unpin> DkgGroup for T {}

/// Handling the Group serialization with a wrapper
mod serde_commit {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::config::DkgGroup;

    pub fn serialize<S: Serializer, G: DkgGroup>(vec: &[G], s: S) -> Result<S::Ok, S::Error> {
        let wrap_vec: Vec<Wrap<G>> = vec.iter().cloned().map(Wrap).collect();
        wrap_vec.serialize(s)
    }

    pub fn deserialize<'d, D: Deserializer<'d>, G: DkgGroup>(d: D) -> Result<Vec<G>, D::Error> {
        let wrap_vec = <Vec<Wrap<G>>>::deserialize(d)?;
        Ok(wrap_vec.into_iter().map(|wrap| wrap.0).collect())
    }

    struct Wrap<G: DkgGroup>(G);

    impl<G: DkgGroup> Serialize for Wrap<G> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            self.0.serialize2(s)
        }
    }

    impl<'d, G: DkgGroup> Deserialize<'d> for Wrap<G> {
        fn deserialize<D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
            G::deserialize2(d).map(Wrap)
        }
    }
}

pub trait SGroup: Sized {
    fn serialize2<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error>;
    fn deserialize2<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error>;
}

impl SGroup for G2Projective {
    fn serialize2<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serde_impl::g2::serialize(&self.to_affine(), s)
    }

    fn deserialize2<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
        serde_impl::g2::deserialize(d).map(G2Projective::from)
    }
}

impl SGroup for G1Projective {
    fn serialize2<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serde_impl::g1::serialize(&self.to_affine(), s)
    }

    fn deserialize2<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
        serde_impl::g1::deserialize(d).map(G1Projective::from)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};

    use fedimint_api::config::{DkgStep, ThresholdKeys};
    use hbbft::crypto::group::Curve;
    use hbbft::crypto::{G1Projective, G2Projective};
    use rand::rngs::OsRng;

    use crate::config::{scalar, Dkg, DkgGroup, DkgKeys};
    use crate::PeerId;

    #[test_log::test]
    fn test_dkg() {
        for (peer, keys) in run(G1Projective::generator()) {
            let ThresholdKeys {
                public_key_set,
                secret_key_share,
            } = keys.threshold_crypto();
            assert_eq!(public_key_set.threshold(), 2);
            assert_eq!(
                public_key_set.public_key_share(peer.to_usize()),
                secret_key_share.public_key_share()
            );
        }

        for (peer, keys) in run(G2Projective::generator()) {
            let (pk, sk) = keys.tbs();
            assert_eq!(pk.coefficients().len(), 3);
            assert_eq!(
                pk.evaluate(scalar(&peer)).to_affine(),
                sk.to_pub_key_share().0
            );
        }
    }

    fn run<G: DkgGroup>(group: G) -> HashMap<PeerId, DkgKeys<G>> {
        let mut rng = OsRng::default();
        let num_peers = 4;
        let threshold = 3;
        let peers = (0..num_peers as u16).map(PeerId::from).collect::<Vec<_>>();

        let mut steps: VecDeque<(PeerId, DkgStep<G>)> = VecDeque::new();
        let mut dkgs: HashMap<PeerId, Dkg<G>> = HashMap::new();
        let mut keys: HashMap<PeerId, DkgKeys<G>> = HashMap::new();

        for peer in &peers {
            let (dkg, step) = Dkg::new(group, *peer, peers.clone(), threshold, &mut rng);
            dkgs.insert(*peer, dkg);
            steps.push_back((*peer, step));
        }

        while keys.len() < peers.len() {
            match steps.pop_front() {
                Some((peer, DkgStep::Messages(messages))) => {
                    for (receive_peer, msg) in messages {
                        let receive_dkg = dkgs.get_mut(&receive_peer).unwrap();
                        let step = receive_dkg.step(peer, msg);
                        steps.push_back((receive_peer, step));
                    }
                }
                Some((peer, DkgStep::Result(step_keys))) => {
                    keys.insert(peer, step_keys);
                }
                _ => {}
            }
        }

        keys
    }
}
