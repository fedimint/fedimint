use std::collections::BTreeMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::ops::Mul;
use std::path::Path;
use std::str::FromStr;

use anyhow::{bail, format_err};
use bitcoin::secp256k1;
use bitcoin_hashes::hex::{FromHex, ToHex};
use bitcoin_hashes::sha256::{Hash as Sha256, HashEngine};
use bitcoin_hashes::{hex, sha256};
use fedimint_core::cancellable::Cancelled;
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::Encodable;
use fedimint_core::{BitcoinHash, ModuleDecoderRegistry};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tbs::{serde_impl, Scalar};
use thiserror::Error;
use threshold_crypto::group::{Curve, Group, GroupEncoding};
use threshold_crypto::{G1Projective, G2Projective, Signature};
use url::Url;

use crate::module::DynModuleGen;
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
    /// Howerver empty module structs, like `struct FooConfigLocal;` (unit
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

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable)]
pub struct ApiEndpoint {
    /// The peer's API websocket network address and port (e.g.
    /// `ws://10.42.0.10:5000`)
    pub url: Url,
    /// human-readable name
    pub name: String,
}

/// Total client config
///
/// This includes global settings and client-side module configs.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable)]
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
    #[encodable_ignore]
    pub modules: BTreeMap<ModuleInstanceId, ClientModuleConfig>,
}

/// The API response for configuration requests
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConfigResponse {
    /// The client config
    pub client: ClientConfig,
    /// Hash of the consensus config (for validating against peers)
    pub consensus_hash: sha256::Hash,
    /// Auth key signature of the client config hash if it exists
    pub client_hash_signature: Option<Signature>,
}

/// The federation id is a copy of the authentication threshold public key of
/// the federation
///
/// Stable id so long as guardians membership does not change
/// Unique id so long as guardians do not all collude
#[derive(Debug, Serialize, Deserialize, Clone, Eq, Hash, PartialEq, Encodable)]
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
    /// Returns the consensus hash for a given client config
    pub fn consensus_hash(
        &self,
        module_config_gens: &ModuleGenRegistry,
    ) -> anyhow::Result<sha256::Hash> {
        let modules: BTreeMap<ModuleInstanceId, sha256::Hash> = self
            .modules
            .iter()
            .map(|(module_instance_id, v)| {
                let kind = v.kind();
                Ok((
                    *module_instance_id,
                    module_config_gens
                        .get(kind)
                        .ok_or_else(|| format_err!("module config gen not found: {kind}"))?
                        .hash_client_module(v.value().clone())?,
                ))
            })
            .collect::<anyhow::Result<_>>()?;

        let mut engine = HashEngine::default();
        self.consensus_encode(&mut engine)?;
        for (k, v) in modules.iter() {
            k.consensus_encode(&mut engine)?;
            v.consensus_encode(&mut engine)?;
        }

        Ok(sha256::Hash::from_engine(engine))
    }

    pub fn get_module<T: DeserializeOwned>(&self, id: ModuleInstanceId) -> anyhow::Result<T> {
        if let Some(client_cfg) = self.modules.get(&id) {
            Ok(serde_json::from_value(client_cfg.0.value().clone())?)
        } else {
            Err(format_err!("Client config for module id: {id} not found"))
        }
    }

    /// (soft-deprecated): Get the first instance of a module of a given kind in
    /// defined in config
    ///
    /// Since module ids are numerical and for time being we only support 1:1
    /// mint, wallet, ln module code in the client, this is useful, but
    /// please write any new code that avoids assumptions about available
    /// modules.
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

/// Parameters for generating all module configs
///
/// The same `ModuleKind` may have multiple instances with different settings
#[derive(Debug, Clone, Default)]
pub struct ConfigGenParams {
    modules: BTreeMap<ModuleInstanceId, JsonWithKind>,
    pub registry: ModuleGenRegistry,
}

impl ConfigGenParams {
    pub fn new() -> ConfigGenParams {
        ConfigGenParams::default()
    }

    pub fn generators(&self) -> Vec<(ModuleInstanceId, DynModuleGen)> {
        self.modules
            .iter()
            .map(|(id, kind)| (*id, self.registry.get(kind.kind()).expect("Exists").clone()))
            .collect()
    }

    /// Add a module with configuration parameters
    pub fn attach<P: ModuleGenParams>(mut self, module_params: P) -> Self {
        let next_id = self.modules.len() as u16;
        let value = JsonWithKind::new(
            ModuleKind::from_static_str(P::MODULE_NAME),
            serde_json::to_value(&module_params).expect("Encoding to value doesn't fail"),
        );
        self.registry.insert(value.kind.clone(), P::module_gen());
        self.modules.insert(next_id, value);
        self
    }

    /// Retrieve typed config generation parameters for a module
    pub fn get<P: ModuleGenParams>(&self, id: &ModuleInstanceId) -> anyhow::Result<P> {
        let value = self
            .modules
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("No params found for module {}", id))?;
        serde_json::from_value(value.value().clone())
            .map_err(|e| anyhow::Error::new(e).context("Invalid module params"))
    }
}

#[derive(Clone, Debug, Default)]
pub struct ModuleGenRegistry(BTreeMap<ModuleKind, DynModuleGen>);

impl From<Vec<DynModuleGen>> for ModuleGenRegistry {
    fn from(value: Vec<DynModuleGen>) -> Self {
        Self(BTreeMap::from_iter(
            value.into_iter().map(|i| (i.module_kind(), i)),
        ))
    }
}

impl ModuleGenRegistry {
    pub fn insert(&mut self, k: ModuleKind, v: DynModuleGen) {
        self.0.insert(k, v);
    }

    pub fn get(&self, k: &ModuleKind) -> Option<&DynModuleGen> {
        self.0.get(k)
    }

    pub fn decoders<'a>(
        &self,
        module_kinds: impl Iterator<Item = (ModuleInstanceId, &'a ModuleKind)>,
    ) -> anyhow::Result<ModuleDecoderRegistry> {
        let mut modules = BTreeMap::new();
        for (id, kind) in module_kinds {
            let Some(init) = self.0.get(kind) else {
                anyhow::bail!("Detected configuration for unsupported module kind: {kind}")
            };

            modules.insert(id, init.decoder());
        }
        Ok(ModuleDecoderRegistry::from_iter(modules))
    }
}

pub trait ModuleGenParams: serde::Serialize + serde::de::DeserializeOwned {
    const MODULE_NAME: &'static str;

    // TODO: make a const?
    fn module_gen() -> DynModuleGen;
}

/// Response from the API for this particular module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleConfigResponse {
    /// The client configuration
    pub client: ClientModuleConfig,
    /// Hash of the consensus configuration
    pub consensus_hash: sha256::Hash,
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
pub trait TypedServerModuleConsensusConfig: DeserializeOwned + Serialize + Encodable {
    /// Derive client side config for this module (type-erased)
    fn to_client_config(&self) -> ClientModuleConfig;
}

/// Module (server side) config
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
pub trait TypedClientModuleConfig: DeserializeOwned + Serialize + Encodable {
    fn kind(&self) -> ModuleKind;

    fn to_erased(&self) -> ClientModuleConfig {
        ClientModuleConfig::new(
            self.kind(),
            serde_json::to_value(self).expect("serialization can't fail"),
        )
    }
}

/// Things that a `distributed_gen` config can send between peers
// TODO: Needs to be modularized in case modules want to send new message types for DKG
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum DkgPeerMsg {
    PublicKey(secp256k1::PublicKey),
    DistributedGen((String, SupportedDkgMessage)),
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
