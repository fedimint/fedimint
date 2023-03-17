use std::collections::BTreeMap;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::ops::Mul;
use std::path::Path;
use std::str::FromStr;
use std::env;

use anyhow::{bail, format_err};
use bitcoin::secp256k1;
use bitcoin_hashes::hex::{format_hex, FromHex};
use bitcoin_hashes::sha256::{Hash as Sha256, HashEngine};
use bitcoin_hashes::{hex, sha256};
use fedimint_core::cancellable::Cancelled;
use fedimint_core::core::{
    ModuleInstanceId, ModuleKind, LEGACY_HARDCODED_INSTANCE_ID_LN,
    LEGACY_HARDCODED_INSTANCE_ID_MINT, LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_core::encoding::Encodable;
use fedimint_core::{BitcoinHash, ModuleDecoderRegistry};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tbs::{serde_impl, Scalar};
use thiserror::Error;
use threshold_crypto::group::{Curve, Group, GroupEncoding};
use threshold_crypto::{G1Projective, G2Projective, Signature};
use url::Url;

use crate::module::{DynCommonModuleGen, DynServerModuleGen, IDynCommonModuleGen};
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
    // Stable and unique id and threshold pubkey of the federation for authenticating configs
    pub federation_id: FederationId,
    /// API endpoints for each federation member
    pub api_endpoints: BTreeMap<PeerId, ApiEndpoint>,
    /// Threshold pubkey for authenticating epoch history
    pub epoch_pk: threshold_crypto::PublicKey,
    /// Configs from other client modules
    #[encodable_ignore]
    pub modules: BTreeMap<ModuleInstanceId, ClientModuleConfig>,
    // TODO: make it a String -> serde_json::Value map?
    /// Additional config the federation wants to transmit to the clients
    pub meta: BTreeMap<String, String>,
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

impl Display for FederationId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        format_hex(&self.0.to_bytes(), f)
    }
}

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
        module_config_gens: &CommonModuleGenRegistry,
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
                        .map(|gen| gen.hash_client_module(v.value().clone()))
                        .unwrap_or(Ok(v.consensus_hash))?,
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
            Ok(serde_json::from_value(client_cfg.value().clone())?)
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

        Ok((*id, serde_json::from_value(module_cfg.value().clone())?))
    }
}

/// Parameters for generating all module configs
///
/// The same `ModuleKind` may have multiple instances with different settings
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

#[derive(Clone, Debug)]
pub struct ModuleGenRegistry<M>(BTreeMap<ModuleKind, M>);

impl<M> Default for ModuleGenRegistry<M> {
    fn default() -> Self {
        Self(Default::default())
    }
}

pub type ServerModuleGenRegistry = ModuleGenRegistry<DynServerModuleGen>;

pub type CommonModuleGenRegistry = ModuleGenRegistry<DynCommonModuleGen>;

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

    pub fn get(&self, k: &ModuleKind) -> Option<&M> {
        self.0.get(k)
    }

    /// Return legacy initialization order. See [`LegacyInitOrderIter`].
    pub fn legacy_init_order_iter(&self) -> LegacyInitOrderIter<M>
    where
        M: Clone,
    {
        let args: Vec<String> = env::args().collect();

        let mut extra_module_instances = Vec::new();

        // Iterate over the command-line arguments and look for instances of --extra-module-instance.
        let mut i = 0;
        while i < args.len() {
            if args[i] == "--extra-module-instance" {
                // Extract the <kind> value from the next argument.
                if let Some(kind) = args.get(i+1) {
                    // Add the <kind> instance to the vector.
                    extra_module_instances.push(ModuleKind::new(kind));
                }
                i += 2; // Skip both --extra-module-instance and the <kind> argument.
            } else {
                i += 1; // Move to the next argument.
            }
        }

        // Chain the modules instances to the legacy_init_order_iter.
        let mut legacy_init_order_iter = Vec::new();
        // fixed 3 module instances
        let mut initial_module: Vec<String> = ["mint", "ln", "wallet"];
        //adding all module instances to legacy_init_order_iter.
        legacy_init_order_iter.append(&mut initial_module);
        legacy_init_order_iter.append(&mut extra_module_instances);
        
        // ... continue with the rest of the initialization code
        for hardcoded_module in  legacy_init_order_iter{
            if !self
                .0
                .contains_key(&ModuleKind::from_static_str(hardcoded_module))
            {
                panic!("Missing {hardcoded_module} module");
            }
        }

        LegacyInitOrderIter {
            next_id: 0,
            rest: self.0.clone(),
        }
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

            modules.insert(id, init.as_ref().decoder());
        }
        Ok(ModuleDecoderRegistry::from_iter(modules))
    }
}

/// Iterate over module generators in a legacy, hardcoded order: ln, mint,
/// wallet, rest... Returning each `kind` exactly once, so that
/// `LEGACY_HARDCODED_` constants correspond to correct module kind.
///
/// We would like to get rid of it eventually, but old client and test code
/// assumes it in multiple places, and it will take work to fix it, while we
/// want new code to not assume this 1:1 relationship.
pub struct LegacyInitOrderIter<M> {
    /// Counter of what module id will this returned value get assigned
    next_id: ModuleInstanceId,
    rest: BTreeMap<ModuleKind, M>,
}

impl<M> Iterator for LegacyInitOrderIter<M> {
    type Item = (ModuleKind, M);

    fn next(&mut self) -> Option<Self::Item> {
        let ret = match self.next_id {
            LEGACY_HARDCODED_INSTANCE_ID_LN => {
                let kind = ModuleKind::from_static_str("ln");
                Some((
                    kind.clone(),
                    self.rest.remove(&kind).expect("checked in constructor"),
                ))
            }
            LEGACY_HARDCODED_INSTANCE_ID_MINT => {
                let kind = ModuleKind::from_static_str("mint");
                Some((
                    kind.clone(),
                    self.rest.remove(&kind).expect("checked in constructor"),
                ))
            }
            LEGACY_HARDCODED_INSTANCE_ID_WALLET => {
                let kind = ModuleKind::from_static_str("wallet");
                Some((
                    kind.clone(),
                    self.rest.remove(&kind).expect("checked in constructor"),
                ))
            }
            _ => self.rest.pop_first(),
        };

        if ret.is_some() {
            self.next_id += 1;
        }
        ret
    }
}

pub trait ModuleGenParams: serde::Serialize + serde::de::DeserializeOwned {
    const MODULE_NAME: &'static str;
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
pub struct ClientModuleConfig {
    kind: ModuleKind,
    consensus_hash: sha256::Hash,
    config: serde_json::Value,
}

impl ClientModuleConfig {
    pub fn from_typed<T: Encodable + Serialize>(
        kind: ModuleKind,
        value: &T,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            kind,
            consensus_hash: value.consensus_hash()?,
            config: serde_json::to_value(value)?,
        })
    }

    pub fn is_kind(&self, kind: &ModuleKind) -> bool {
        &self.kind == kind
    }

    pub fn kind(&self) -> &ModuleKind {
        &self.kind
    }

    pub fn value(&self) -> &serde_json::Value {
        &self.config
    }
}

impl ClientModuleConfig {
    pub fn cast<T: TypedClientModuleConfig>(&self) -> anyhow::Result<T> {
        Ok(serde_json::from_value(self.config.clone())?)
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
pub trait TypedClientModuleConfig:
    DeserializeOwned + Serialize + Encodable + MaybeSend + MaybeSync
{
    fn kind(&self) -> ModuleKind;

    fn to_erased(&self) -> ClientModuleConfig {
        ClientModuleConfig::from_typed(self.kind(), self).expect("serialization can't fail")
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
