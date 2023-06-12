use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::ops::Mul;
use std::path::Path;
use std::str::FromStr;

use anyhow::{bail, format_err};
use bitcoin::secp256k1;
use bitcoin_hashes::hex::{format_hex, FromHex};
use bitcoin_hashes::sha256::{Hash as Sha256, HashEngine};
use bitcoin_hashes::{hex, sha256};
use fedimint_core::cancellable::Cancelled;
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::Encodable;
use fedimint_core::epoch::SerdeSignature;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::{BitcoinHash, ModuleDecoderRegistry};
use serde::de::DeserializeOwned;
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tbs::{serde_impl, Scalar};
use thiserror::Error;
use threshold_crypto::group::{Curve, Group, GroupEncoding};
use threshold_crypto::{G1Projective, G2Projective};
use url::Url;

use crate::encoding::Decodable;
use crate::module::{
    DynCommonModuleGen, DynServerModuleGen, IDynCommonModuleGen, ModuleConsensusVersion,
};
use crate::task::{MaybeSend, MaybeSync};
use crate::{maybe_add_send_sync, PeerId};

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
    /// However empty module structs, like `struct FooConfigLocal;` (unit
    /// struct), will fail to deserialize with this value, as they expect
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
    /// See <https://github.com/fedimint/fedimint/issues/1303>
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

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct PeerUrl {
    /// The peer's public URL (e.g. `wss://fedimint-server-1:5000`)
    pub url: Url,
    /// The peer's name
    pub name: String,
}

/// Total client config
///
/// This includes global settings and client-side module configs.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct ClientConfig {
    // Stable and unique id and threshold pubkey of the federation for authenticating configs
    pub federation_id: FederationId,
    /// API endpoints for each federation member
    pub api_endpoints: BTreeMap<PeerId, PeerUrl>,
    /// Threshold pubkey for authenticating epoch history
    pub epoch_pk: threshold_crypto::PublicKey,
    // TODO: make it a String -> serde_json::Value map?
    /// Additional config the federation wants to transmit to the clients
    pub meta: BTreeMap<String, String>,
    /// Configs from other client modules
    pub modules: BTreeMap<ModuleInstanceId, ClientModuleConfig>,
}

/// The API response for client config requests, signed by the Federation
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClientConfigResponse {
    /// The client config
    pub client_config: ClientConfig,
    /// Auth key signature over the `client_config`
    pub signature: SerdeSignature,
}

/// The federation id is a copy of the authentication threshold public key of
/// the federation
///
/// Stable id so long as guardians membership does not change
/// Unique id so long as guardians do not all collude
#[derive(
    Debug,
    Copy,
    Serialize,
    Deserialize,
    Clone,
    Eq,
    Hash,
    PartialEq,
    Encodable,
    Decodable,
    Ord,
    PartialOrd,
)]
pub struct FederationId(pub threshold_crypto::PublicKey);

impl Display for FederationId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        format_hex(&self.0.to_bytes(), f)
    }
}

/// Display as a hex encoding
impl FederationId {
    /// Random dummy id for testing
    pub fn dummy() -> Self {
        let rand_pk = threshold_crypto::SecretKey::random().public_key();
        Self(rand_pk)
    }

    fn try_from_bytes(bytes: [u8; 48]) -> Option<Self> {
        Some(Self(threshold_crypto::PublicKey::from_bytes(bytes).ok()?))
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
    /// Returns the consensus hash for a given client config
    pub fn consensus_hash(&self) -> sha256::Hash {
        let mut engine = HashEngine::default();
        self.consensus_encode(&mut engine)
            .expect("Consensus hashing should never fail");
        sha256::Hash::from_engine(engine)
    }

    pub fn get_module<T: Decodable>(&self, id: ModuleInstanceId) -> anyhow::Result<T> {
        if let Some(client_cfg) = self.modules.get(&id) {
            Ok(Decodable::consensus_decode(
                &mut &client_cfg.config[..],
                &Default::default(),
            )?)
        } else {
            Err(format_err!("Client config for module id {id} not found"))
        }
    }

    // TODO: rename this and one above
    pub fn get_module_cfg(&self, id: ModuleInstanceId) -> anyhow::Result<ClientModuleConfig> {
        if let Some(client_cfg) = self.modules.get(&id) {
            Ok(client_cfg.clone())
        } else {
            Err(format_err!("Client config for module id {id} not found"))
        }
    }

    /// (soft-deprecated): Get the first instance of a module of a given kind in
    /// defined in config
    ///
    /// Since module ids are numerical and for time being we only support 1:1
    /// mint, wallet, ln module code in the client, this is useful, but
    /// please write any new code that avoids assumptions about available
    /// modules.
    pub fn get_first_module_by_kind<T: Decodable>(
        &self,
        kind: impl Into<ModuleKind>,
    ) -> anyhow::Result<(ModuleInstanceId, T)> {
        let kind: ModuleKind = kind.into();
        let Some((id, module_cfg)) = self.modules.iter().find(|(_, v)| v.is_kind(&kind)) else {
            anyhow::bail!("Module kind {kind} not found")
        };
        Ok((
            *id,
            T::consensus_decode(&mut &module_cfg.config[..], &Default::default())?,
        ))
    }

    // TODO: rename this and above
    pub fn get_first_module_by_kind_cfg(
        &self,
        kind: impl Into<ModuleKind>,
    ) -> anyhow::Result<(ModuleInstanceId, ClientModuleConfig)> {
        let kind: ModuleKind = kind.into();
        self.modules
            .iter()
            .find(|(_, v)| v.is_kind(&kind))
            .map(|(id, v)| (*id, v.clone()))
            .ok_or_else(|| anyhow::format_err!("Module kind {kind} not found"))
    }

    /// Federation name from config metadata (if set)
    pub fn federation_name(&self) -> Option<&str> {
        self.meta.get(META_FEDERATION_NAME_KEY).map(|x| &**x)
    }
}

#[derive(Clone, Debug)]
pub struct ModuleGenRegistry<M>(BTreeMap<ModuleKind, M>);

impl<M> Default for ModuleGenRegistry<M> {
    fn default() -> Self {
        Self(Default::default())
    }
}

/// Type erased `ModuleGenParams` used to generate the `ServerModuleConfig`
/// during config gen
#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConfigGenModuleParams {
    pub local: Option<serde_json::Value>,
    pub consensus: Option<serde_json::Value>,
}

pub type ServerModuleGenRegistry = ModuleGenRegistry<DynServerModuleGen>;

impl ConfigGenModuleParams {
    pub fn new(local: Option<serde_json::Value>, consensus: Option<serde_json::Value>) -> Self {
        Self { local, consensus }
    }

    /// Converts the JSON into typed version, errors unless both `local` and
    /// `consensus` values are defined
    pub fn to_typed<P: ModuleGenParams>(&self) -> anyhow::Result<P> {
        Ok(P::from_parts(
            Self::parse("local", self.local.clone())?,
            Self::parse("consensus", self.consensus.clone())?,
        ))
    }

    fn parse<P: DeserializeOwned>(
        name: &str,
        json: Option<serde_json::Value>,
    ) -> anyhow::Result<P> {
        let json = json.ok_or(format_err!("{name} config gen params missing"))?;
        serde_json::from_value(json)
            .map_err(|e| anyhow::Error::new(e).context("Invalid module params"))
    }

    pub fn from_typed<P: ModuleGenParams>(p: P) -> anyhow::Result<Self> {
        let (local, consensus) = p.to_parts();
        Ok(Self {
            local: Some(serde_json::to_value(local)?),
            consensus: Some(serde_json::to_value(consensus)?),
        })
    }
}

pub type CommonModuleGenRegistry = ModuleGenRegistry<DynCommonModuleGen>;

/// Registry that contains the config gen params for all modules
pub type ServerModuleGenParamsRegistry = ModuleRegistry<ConfigGenModuleParams>;

impl Eq for ServerModuleGenParamsRegistry {}

impl PartialEq for ServerModuleGenParamsRegistry {
    fn eq(&self, other: &Self) -> bool {
        self.iter_modules().eq(other.iter_modules())
    }
}

impl Serialize for ServerModuleGenParamsRegistry {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let modules: Vec<_> = self.iter_modules().collect();
        let mut serializer = serializer.serialize_map(Some(modules.len()))?;
        for (id, kind, params) in modules.into_iter() {
            serializer.serialize_key(&id)?;
            serializer.serialize_value(&(kind.clone(), params.clone()))?;
        }
        serializer.end()
    }
}

impl<'de> Deserialize<'de> for ServerModuleGenParamsRegistry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let json: BTreeMap<ModuleInstanceId, (ModuleKind, ConfigGenModuleParams)> =
            Deserialize::deserialize(deserializer)?;
        let mut params = BTreeMap::new();

        for (id, (kind, module)) in json {
            params.insert(id, (kind, module));
        }
        Ok(ModuleRegistry::from(params))
    }
}

impl<M> From<Vec<M>> for ModuleGenRegistry<M>
where
    M: AsRef<dyn IDynCommonModuleGen + Send + Sync + 'static>,
{
    fn from(value: Vec<M>) -> Self {
        Self(BTreeMap::from_iter(
            value.into_iter().map(|i| (i.as_ref().module_kind(), i)),
        ))
    }
}

impl<M> FromIterator<M> for ModuleGenRegistry<M>
where
    M: AsRef<maybe_add_send_sync!(dyn IDynCommonModuleGen + 'static)>,
{
    fn from_iter<T: IntoIterator<Item = M>>(iter: T) -> Self {
        Self(BTreeMap::from_iter(
            iter.into_iter().map(|i| (i.as_ref().module_kind(), i)),
        ))
    }
}

impl<M> ModuleGenRegistry<M> {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn attach<T>(&mut self, gen: T)
    where
        T: Into<M> + 'static + Send + Sync,
        M: AsRef<dyn IDynCommonModuleGen + 'static + Send + Sync>,
    {
        let gen: M = gen.into();
        let kind = gen.as_ref().module_kind();
        if self.0.insert(kind.clone(), gen).is_some() {
            panic!("Can't insert module of same kind twice: {kind}");
        }
    }

    pub fn kinds(&self) -> BTreeSet<ModuleKind> {
        self.0.keys().cloned().collect()
    }

    pub fn get(&self, k: &ModuleKind) -> Option<&M> {
        self.0.get(k)
    }
}

impl ModuleRegistry<ConfigGenModuleParams> {
    pub fn attach_config_gen_params<T: ModuleGenParams>(
        &mut self,
        id: ModuleInstanceId,
        kind: ModuleKind,
        gen: T,
    ) -> &mut Self {
        self.register_module(
            id,
            kind,
            ConfigGenModuleParams::from_typed(gen).expect("Invalid config gen params for {kind}"),
        );
        self
    }
}

impl ServerModuleGenRegistry {
    pub fn to_common(&self) -> CommonModuleGenRegistry {
        ModuleGenRegistry(
            self.0
                .iter()
                .map(|(k, v)| (k.clone(), v.to_dyn_common()))
                .collect(),
        )
    }
}

impl<M> ModuleGenRegistry<M>
where
    M: AsRef<dyn IDynCommonModuleGen + Send + Sync + 'static>,
{
    pub fn decoders<'a>(
        &self,
        module_kinds: impl Iterator<Item = (ModuleInstanceId, &'a ModuleKind)>,
    ) -> anyhow::Result<ModuleDecoderRegistry> {
        let mut modules = BTreeMap::new();
        for (id, kind) in module_kinds {
            let Some(init) = self.0.get(kind) else {
                anyhow::bail!("Detected configuration for unsupported module kind: {kind}")
            };

            modules.insert(id, (kind.clone(), init.as_ref().decoder()));
        }
        Ok(ModuleDecoderRegistry::from(modules))
    }
}

/// Empty struct for if there are no params
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EmptyGenParams {}

pub trait ModuleGenParams: serde::Serialize + serde::de::DeserializeOwned {
    /// Locally configurable parameters for config generation
    type Local: DeserializeOwned + Serialize;
    /// Consensus parameters for config generation
    type Consensus: DeserializeOwned + Serialize;

    /// Assemble from the distinct parts
    fn from_parts(local: Self::Local, consensus: Self::Consensus) -> Self;

    /// Split the config into its distinct parts
    fn to_parts(self) -> (Self::Local, Self::Consensus);
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct ServerModuleConsensusConfig {
    pub kind: ModuleKind,
    pub version: ModuleConsensusVersion,
    #[serde(with = "::hex::serde")]
    pub config: Vec<u8>,
}

/// Config for the client-side of a particular Federation module
///
/// Since modules are (tbd.) pluggable into Federations,
/// it needs to be some form of an abstract type-erased-like
/// value.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct ClientModuleConfig {
    pub kind: ModuleKind,
    pub version: ModuleConsensusVersion,
    #[serde(with = "::hex::serde")]
    pub config: Vec<u8>,
}

impl ClientModuleConfig {
    pub fn from_typed<T: Encodable + Serialize>(
        kind: ModuleKind,
        version: ModuleConsensusVersion,
        value: &T,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            kind,
            version,
            config: value.consensus_encode_to_vec()?,
        })
    }

    pub fn is_kind(&self, kind: &ModuleKind) -> bool {
        &self.kind == kind
    }

    pub fn kind(&self) -> &ModuleKind {
        &self.kind
    }

    pub fn value(&self) -> &[u8] {
        &self.config
    }
}

impl ClientModuleConfig {
    pub fn cast<T: TypedClientModuleConfig>(&self) -> anyhow::Result<T> {
        Ok(T::consensus_decode(
            &mut &self.config[..],
            &Default::default(),
        )?)
    }
}

/// Config for the server-side of a particular Federation module
///
/// See [`ClientModuleConfig`].
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServerModuleConfig {
    pub local: JsonWithKind,
    pub private: JsonWithKind,
    pub consensus: ServerModuleConsensusConfig,
    pub consensus_json: JsonWithKind,
}

impl ServerModuleConfig {
    pub fn from(
        local: JsonWithKind,
        private: JsonWithKind,
        consensus: ServerModuleConsensusConfig,
        consensus_json: JsonWithKind,
    ) -> Self {
        Self {
            local,
            private,
            consensus,
            consensus_json,
        }
    }

    pub fn to_typed<T: TypedServerModuleConfig>(&self) -> anyhow::Result<T> {
        let local = serde_json::from_value(self.local.value().clone())?;
        let private = serde_json::from_value(self.private.value().clone())?;
        let consensus =
            <T::Consensus>::consensus_decode(&mut &self.consensus.config[..], &Default::default())?;

        Ok(TypedServerModuleConfig::from_parts(
            local, private, consensus,
        ))
    }
}

/// Consensus-critical part of a server side module config
pub trait TypedServerModuleConsensusConfig:
    DeserializeOwned + Serialize + Encodable + Decodable
{
    fn kind(&self) -> ModuleKind;

    fn version(&self) -> ModuleConsensusVersion;

    fn from_erased(erased: &ServerModuleConsensusConfig) -> anyhow::Result<Self> {
        Ok(Self::consensus_decode(
            &mut &erased.config[..],
            &Default::default(),
        )?)
    }
}

/// Module (server side) config, typed
pub trait TypedServerModuleConfig: DeserializeOwned + Serialize {
    /// Local non-consensus, not security-sensitive settings
    type Local: DeserializeOwned + Serialize;
    /// Private for this federation member data that are security sensitive and
    /// will be encrypted at rest
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
            consensus: ServerModuleConsensusConfig {
                kind: consensus.kind(),
                version: consensus.version(),
                config: consensus
                    .consensus_encode_to_vec()
                    .expect("serialization can't fail"),
            },
            consensus_json: JsonWithKind::new(
                kind,
                serde_json::to_value(consensus).expect("serialization can't fail"),
            ),
        }
    }
}

/// Typed client side module config
pub trait TypedClientModuleConfig:
    DeserializeOwned + Serialize + Decodable + Encodable + MaybeSend + MaybeSync
{
    fn kind(&self) -> ModuleKind;

    fn version(&self) -> ModuleConsensusVersion;

    fn to_erased(&self) -> ClientModuleConfig {
        ClientModuleConfig::from_typed(self.kind(), self.version(), self)
            .expect("serialization can't fail")
    }
}

/// Things that a `distributed_gen` config can send between peers
// TODO: Needs to be modularized in case modules want to send new message types for DKG
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum DkgPeerMsg {
    PublicKey(secp256k1::PublicKey),
    DistributedGen(SupportedDkgMessage),
    // Dkg completed on our side
    Done,
}

/// Result of running DKG
pub type DkgResult<T> = Result<T, DkgError>;

#[derive(Error, Debug)]
/// Captures an error occurring in DKG
pub enum DkgError {
    /// User has cancelled the DKG task
    #[error("Operation cancelled")]
    Cancelled(#[from] Cancelled),
    /// Error running DKG
    #[error("Running DKG failed due to {0}")]
    Failed(#[from] anyhow::Error),
    #[error("The module was not found {0}")]
    ModuleNotFound(ModuleKind),
    #[error("Params for modules were not found {0:?}")]
    ParamsNotFound(BTreeSet<ModuleKind>),
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

/// Key under which the federation name can be sent to client in the `meta` part
/// of the config
pub const META_FEDERATION_NAME_KEY: &str = "federation_name";

pub fn load_from_file<T: DeserializeOwned>(path: &Path) -> Result<T, anyhow::Error> {
    let file = std::fs::File::open(path)?;
    Ok(serde_json::from_reader(file)?)
}

pub mod serde_binary_human_readable {
    use std::borrow::Cow;

    use bitcoin_hashes::hex::{FromHex, ToHex};
    use serde::de::DeserializeOwned;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<T: Serialize, S: Serializer>(x: &T, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            let bytes =
                bincode::serialize(x).map_err(|e| serde::ser::Error::custom(format!("{e:?}")))?;
            s.serialize_str(&bytes.to_hex())
        } else {
            Serialize::serialize(x, s)
        }
    }

    pub fn deserialize<'d, T: DeserializeOwned, D: Deserializer<'d>>(d: D) -> Result<T, D::Error> {
        if d.is_human_readable() {
            let hex_str: Cow<str> = Deserialize::deserialize(d)?;
            let bytes = Vec::from_hex(&hex_str).map_err(serde::de::Error::custom)?;
            bincode::deserialize(&bytes).map_err(|e| serde::de::Error::custom(format!("{e:?}")))
        } else {
            Deserialize::deserialize(d)
        }
    }
}
