use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::ops::Mul;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, bail, format_err, Context};
use bitcoin::secp256k1;
use bitcoin_hashes::hex::{format_hex, FromHex};
use bitcoin_hashes::sha256::{Hash as Sha256, HashEngine};
use bitcoin_hashes::{hex, sha256};
use fedimint_core::api::{FederationApiExt, InviteCode, WsFederationApi};
use fedimint_core::cancellable::Cancelled;
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{DynRawFallback, Encodable};
use fedimint_core::endpoint_constants::CLIENT_CONFIG_ENDPOINT;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::task::sleep;
use fedimint_core::util::SafeUrl;
use fedimint_core::{BitcoinHash, ModuleDecoderRegistry};
use fedimint_logging::LOG_CORE;
use serde::de::DeserializeOwned;
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tbs::{serde_impl, Scalar};
use thiserror::Error;
use threshold_crypto::group::{Curve, Group, GroupEncoding};
use threshold_crypto::{G1Projective, G2Projective};
use tracing::{debug, warn};

use crate::core::DynClientConfig;
use crate::encoding::Decodable;
use crate::module::{
    CoreConsensusVersion, DynCommonModuleInit, DynServerModuleInit, IDynCommonModuleInit,
    ModuleConsensusVersion,
};
use crate::query::FilterMap;
use crate::{maybe_add_send_sync, PeerId};

// TODO: make configurable
/// This limits the RAM consumption of a AlephBFT Unit to roughly 50kB
pub const ALEPH_BFT_UNIT_BYTE_LIMIT: usize = 50_000;

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
    pub url: SafeUrl,
    /// The peer's name
    pub name: String,
}

/// Total client config
///
/// This includes global settings and client-side module configs.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct ClientConfig {
    #[serde(flatten)]
    pub global: GlobalClientConfig,
    #[serde(deserialize_with = "de_int_key")]
    pub modules: BTreeMap<ModuleInstanceId, ClientModuleConfig>,
}

// FIXME: workaround for https://github.com/serde-rs/json/issues/989
fn de_int_key<'de, D, K, V>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: Eq + Ord + FromStr,
    K::Err: Display,
    V: Deserialize<'de>,
{
    let string_map = <BTreeMap<String, V>>::deserialize(deserializer)?;
    let map = string_map
        .into_iter()
        .map(|(key_str, value)| {
            let key = K::from_str(&key_str).map_err(serde::de::Error::custom)?;
            Ok((key, value))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    Ok(map)
}

/// Client config that cannot be cryptographically verified but is easier to
/// parse by external tools
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct JsonClientConfig {
    pub global: GlobalClientConfig,
    pub modules: BTreeMap<ModuleInstanceId, JsonWithKind>,
}

/// Federation-wide client config
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct GlobalClientConfig {
    /// API endpoints for each federation member
    #[serde(deserialize_with = "de_int_key")]
    pub api_endpoints: BTreeMap<PeerId, PeerUrl>,
    /// Core consensus version
    pub consensus_version: CoreConsensusVersion,
    // TODO: make it a String -> serde_json::Value map?
    /// Additional config the federation wants to transmit to the clients
    pub meta: BTreeMap<String, String>,
}

impl GlobalClientConfig {
    pub fn calculate_federation_id(&self) -> FederationId {
        FederationId(self.api_endpoints.consensus_hash())
    }

    /// Federation name from config metadata (if set)
    pub fn federation_name(&self) -> Option<&str> {
        self.meta.get(META_FEDERATION_NAME_KEY).map(|x| &**x)
    }
}

impl ClientConfig {
    /// See [`DynRawFallback::redecode_raw`].
    pub fn redecode_raw(
        self,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, crate::encoding::DecodeError> {
        Ok(Self {
            modules: self
                .modules
                .into_iter()
                .map(|(k, v)| Ok((k, v.redecode_raw(modules)?)))
                .collect::<Result<_, _>>()?,
            ..self
        })
    }

    pub fn calculate_federation_id(&self) -> FederationId {
        self.global.calculate_federation_id()
    }

    /// Get the value of a given meta field
    pub fn meta<V: serde::de::DeserializeOwned + 'static>(
        &self,
        key: &str,
    ) -> Result<Option<V>, anyhow::Error> {
        let Some(str_value) = self.global.meta.get(key) else {
            return Ok(None);
        };
        let res = serde_json::from_str(str_value)
            .map(Some)
            .context(format!("Decoding meta field '{key}' failed"));

        // In the past we encoded some string fields as "just a string" without quotes,
        // this code ensures that old meta values still parse since config is hard to
        // change
        if res.is_err() && std::any::TypeId::of::<V>() == std::any::TypeId::of::<String>() {
            let string_ret = Box::new(str_value.clone());
            let ret: Box<V> = unsafe {
                // We can transmute a String to V because we know that V==String
                std::mem::transmute(string_ret)
            };
            Ok(Some(*ret))
        } else {
            res
        }
    }

    /// Create an invite code with the api endpoint of the given peer which can
    /// be used to download this client config
    pub fn invite_code(&self, peer: &PeerId) -> Option<InviteCode> {
        self.global.api_endpoints.get(peer).map(|peer_url| {
            InviteCode::new(peer_url.url.clone(), *peer, self.calculate_federation_id())
        })
    }

    /// Tries to download the client config from the federation,
    /// attempts to retry teb times before giving up.
    pub async fn download_from_invite_code(
        invite_code: &InviteCode,
    ) -> anyhow::Result<ClientConfig> {
        debug!("Downloading client config from {:?}", invite_code);

        for _ in 0..10 {
            match Self::try_download_client_config(invite_code).await {
                Ok(cfg) => {
                    return Ok(cfg);
                }
                Err(error) => {
                    debug!("Failed to download client config {:?}", error);

                    sleep(Duration::from_millis(500)).await;
                }
            }
        }

        Err(anyhow!("Failed to download client config"))
    }

    async fn try_download_client_config(invite_code: &InviteCode) -> anyhow::Result<ClientConfig> {
        // we have to download the api endpoints first
        let federation_id = invite_code.federation_id();

        let query_strategy = FilterMap::new(
            move |cfg: ClientConfig| {
                if federation_id.0 != cfg.global.api_endpoints.consensus_hash() {
                    bail!("Guardian api endpoint map does not hash to FederationId")
                }

                Ok(cfg.global.api_endpoints)
            },
            1,
        );

        let api_endpoints = WsFederationApi::from_invite_code(&[invite_code.clone()])
            .request_with_strategy(
                query_strategy,
                CLIENT_CONFIG_ENDPOINT.to_owned(),
                ApiRequestErased::default(),
            )
            .await?;

        // now we can build an api for all guardians and download the client config
        let api_endpoints = api_endpoints
            .into_iter()
            .map(|(peer, url)| (peer, url.url))
            .collect();

        let client_config = WsFederationApi::new(api_endpoints)
            .request_current_consensus::<ClientConfig>(
                CLIENT_CONFIG_ENDPOINT.to_owned(),
                ApiRequestErased::default(),
            )
            .await?;

        if client_config.calculate_federation_id() != federation_id {
            bail!("Obtained client config has different federation id");
        }

        Ok(client_config)
    }
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
pub struct FederationId(pub sha256::Hash);

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
/// Prefix of the [`FederationId`], useful for UX improvements
///
/// Intentionally compact to save on the encoding. With 4 billion
/// combinations real-life non-malicious collisions should never
/// happen.
pub struct FederationIdPrefix([u8; 4]);

impl Display for FederationIdPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        format_hex(&self.0, f)
    }
}

impl Display for FederationId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        format_hex(&self.0, f)
    }
}

/// Display as a hex encoding
impl FederationId {
    /// Random dummy id for testing
    pub fn dummy() -> Self {
        Self(sha256::Hash::from_inner([42; 32]))
    }

    pub(crate) fn from_byte_array(bytes: [u8; 32]) -> Self {
        Self(sha256::Hash::from_inner(bytes))
    }

    pub fn to_prefix(&self) -> FederationIdPrefix {
        FederationIdPrefix(self.0[..4].try_into().expect("can't fail"))
    }

    /// Converts a federation id to a public key to which we know but discard
    /// the private key.
    ///
    /// Clients MUST never use this private key for any signing operations!
    ///
    /// That is ok because we only use the public key for adding a route
    /// hint to LN invoices that tells fedimint clients that the invoice can
    /// only be paid internally. Since no LN node with that pub key can exist
    /// other LN senders will know that they cannot pay the invoice.
    pub fn to_fake_ln_pub_key(
        &self,
        secp: &secp256k1::Secp256k1<secp256k1_zkp::All>,
    ) -> anyhow::Result<secp256k1::PublicKey> {
        let sk = secp256k1::SecretKey::from_slice(&self.0)?;
        Ok(secp256k1::PublicKey::from_secret_key(secp, &sk))
    }
}

impl FromStr for FederationId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from_byte_array(
            Vec::from_hex(s)?
                .try_into()
                .map_err(|bytes: Vec<u8>| hex::Error::InvalidLength(32, bytes.len()))?,
        ))
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

    pub fn get_module<T: Decodable + 'static>(&self, id: ModuleInstanceId) -> anyhow::Result<&T> {
        if let Some(client_cfg) = self.modules.get(&id) {
            client_cfg.cast()
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
    pub fn get_first_module_by_kind<T: Decodable + 'static>(
        &self,
        kind: impl Into<ModuleKind>,
    ) -> anyhow::Result<(ModuleInstanceId, &T)> {
        let kind: ModuleKind = kind.into();
        let Some((id, module_cfg)) = self.modules.iter().find(|(_, v)| v.is_kind(&kind)) else {
            anyhow::bail!("Module kind {kind} not found")
        };
        Ok((*id, module_cfg.cast()?))
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
}

#[derive(Clone, Debug)]
pub struct ModuleInitRegistry<M>(BTreeMap<ModuleKind, M>);

impl<M> Default for ModuleInitRegistry<M> {
    fn default() -> Self {
        Self(Default::default())
    }
}

/// Type erased `ModuleInitParams` used to generate the `ServerModuleConfig`
/// during config gen
#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConfigGenModuleParams {
    pub local: serde_json::Value,
    pub consensus: serde_json::Value,
}

pub type ServerModuleInitRegistry = ModuleInitRegistry<DynServerModuleInit>;

impl ConfigGenModuleParams {
    pub fn new(local: serde_json::Value, consensus: serde_json::Value) -> Self {
        Self { local, consensus }
    }

    /// Converts the JSON into typed version, errors unless both `local` and
    /// `consensus` values are defined
    pub fn to_typed<P: ModuleInitParams>(&self) -> anyhow::Result<P> {
        Ok(P::from_parts(
            Self::parse("local", self.local.clone())?,
            Self::parse("consensus", self.consensus.clone())?,
        ))
    }

    fn parse<P: DeserializeOwned>(name: &str, json: serde_json::Value) -> anyhow::Result<P> {
        serde_json::from_value(json).with_context(|| format!("Schema mismatch for {name} argument"))
    }

    pub fn from_typed<P: ModuleInitParams>(p: P) -> anyhow::Result<Self> {
        let (local, consensus) = p.to_parts();
        Ok(Self {
            local: serde_json::to_value(local)?,
            consensus: serde_json::to_value(consensus)?,
        })
    }
}

pub type CommonModuleInitRegistry = ModuleInitRegistry<DynCommonModuleInit>;

/// Registry that contains the config gen params for all modules
pub type ServerModuleConfigGenParamsRegistry = ModuleRegistry<ConfigGenModuleParams>;

impl Eq for ServerModuleConfigGenParamsRegistry {}

impl PartialEq for ServerModuleConfigGenParamsRegistry {
    fn eq(&self, other: &Self) -> bool {
        self.iter_modules().eq(other.iter_modules())
    }
}

impl Serialize for ServerModuleConfigGenParamsRegistry {
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

impl<'de> Deserialize<'de> for ServerModuleConfigGenParamsRegistry {
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

impl<M> From<Vec<M>> for ModuleInitRegistry<M>
where
    M: AsRef<dyn IDynCommonModuleInit + Send + Sync + 'static>,
{
    fn from(value: Vec<M>) -> Self {
        Self(BTreeMap::from_iter(
            value.into_iter().map(|i| (i.as_ref().module_kind(), i)),
        ))
    }
}

impl<M> FromIterator<M> for ModuleInitRegistry<M>
where
    M: AsRef<maybe_add_send_sync!(dyn IDynCommonModuleInit + 'static)>,
{
    fn from_iter<T: IntoIterator<Item = M>>(iter: T) -> Self {
        Self(BTreeMap::from_iter(
            iter.into_iter().map(|i| (i.as_ref().module_kind(), i)),
        ))
    }
}

impl<M> ModuleInitRegistry<M> {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn attach<T>(&mut self, gen: T)
    where
        T: Into<M> + 'static + Send + Sync,
        M: AsRef<dyn IDynCommonModuleInit + 'static + Send + Sync>,
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
    pub fn attach_config_gen_params<T: ModuleInitParams>(
        &mut self,
        id: ModuleInstanceId,
        kind: ModuleKind,
        gen: T,
    ) -> &mut Self {
        let params = ConfigGenModuleParams::from_typed(gen)
            .unwrap_or_else(|err| panic!("Invalid config gen params for {kind}: {err}"));
        self.register_module(id, kind, params);
        self
    }
    pub fn append_config_gen_params<T: ModuleInitParams>(
        &mut self,
        kind: ModuleKind,
        gen: T,
    ) -> &mut Self {
        let params = ConfigGenModuleParams::from_typed(gen)
            .unwrap_or_else(|err| panic!("Invalid config gen params for {kind}: {err}"));
        self.append_module(kind, params);
        self
    }
}

impl ServerModuleInitRegistry {
    pub fn to_common(&self) -> CommonModuleInitRegistry {
        ModuleInitRegistry(
            self.0
                .iter()
                .map(|(k, v)| (k.clone(), v.to_dyn_common()))
                .collect(),
        )
    }
}

impl<M> ModuleInitRegistry<M>
where
    M: AsRef<dyn IDynCommonModuleInit + Send + Sync + 'static>,
{
    #[deprecated(
        note = "You probably want `available_decoders` to support missing module kinds. If you really want a strict behavior, use `decoders_strict`"
    )]
    pub fn decoders<'a>(
        &self,
        modules: impl Iterator<Item = (ModuleInstanceId, &'a ModuleKind)>,
    ) -> anyhow::Result<ModuleDecoderRegistry> {
        self.decoders_strict(modules)
    }

    /// Get decoders for `modules` and fail if any is unsupported
    pub fn decoders_strict<'a>(
        &self,
        modules: impl Iterator<Item = (ModuleInstanceId, &'a ModuleKind)>,
    ) -> anyhow::Result<ModuleDecoderRegistry> {
        let mut decoders = BTreeMap::new();
        for (id, kind) in modules {
            let Some(init) = self.0.get(kind) else {
                anyhow::bail!(
                    "Detected configuration for unsupported module id: {id}, kind: {kind}"
                )
            };

            decoders.insert(id, (kind.clone(), init.as_ref().decoder()));
        }
        Ok(ModuleDecoderRegistry::from(decoders))
    }

    /// Get decoders for `modules` and skip unsupported ones
    pub fn available_decoders<'a>(
        &self,
        modules: impl Iterator<Item = (ModuleInstanceId, &'a ModuleKind)>,
    ) -> anyhow::Result<ModuleDecoderRegistry> {
        let mut decoders = BTreeMap::new();
        for (id, kind) in modules {
            let Some(init) = self.0.get(kind) else {
                warn!(target: LOG_CORE, "Unsupported module id: {id}, kind: {kind}");
                continue;
            };

            decoders.insert(id, (kind.clone(), init.as_ref().decoder()));
        }
        Ok(ModuleDecoderRegistry::from(decoders))
    }
}

/// Empty struct for if there are no params
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EmptyGenParams {}

pub trait ModuleInitParams: serde::Serialize + serde::de::DeserializeOwned {
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
    #[serde(with = "::fedimint_core::encoding::as_hex")]
    pub config: DynRawFallback<DynClientConfig>,
}

impl ClientModuleConfig {
    pub fn from_typed<T: fedimint_core::core::ClientConfig>(
        module_instance_id: ModuleInstanceId,
        kind: ModuleKind,
        version: ModuleConsensusVersion,
        value: T,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            kind,
            version,
            config: fedimint_core::core::DynClientConfig::from_typed(module_instance_id, value)
                .into(),
        })
    }

    pub fn redecode_raw(
        self,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, crate::encoding::DecodeError> {
        Ok(Self {
            config: self.config.redecode_raw(modules)?,
            ..self
        })
    }

    pub fn is_kind(&self, kind: &ModuleKind) -> bool {
        &self.kind == kind
    }

    pub fn kind(&self) -> &ModuleKind {
        &self.kind
    }
}

impl ClientModuleConfig {
    pub fn cast<T>(&self) -> anyhow::Result<&T>
    where
        T: 'static,
    {
        self.config
            .expect_decoded_ref()
            .as_any()
            .downcast_ref::<T>()
            .context("can't convert client module config to desired type")
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
                config: consensus.consensus_encode_to_vec(),
            },
            consensus_json: JsonWithKind::new(
                kind,
                serde_json::to_value(consensus).expect("serialization can't fail"),
            ),
        }
    }
}

/// Things that a `distributed_gen` config can send between peers
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum DkgPeerMsg {
    PublicKey(secp256k1::PublicKey),
    DistributedGen(SupportedDkgMessage),
    Module(Vec<u8>),
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
    #[error("Failed to decode module message {0:?}")]
    ModuleDecodeError(ModuleKind),
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

/// Key under which the vetted gateways can be sent to client in the `meta` part
/// of the config
pub const META_VETTED_GATEWAYS_KEY: &str = "vetted_gateways";

/// Key under which the override URL can be sent to client in the `meta` part
/// of the config
pub const META_OVERRIDE_URL_KEY: &str = "meta_override_url";

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

#[cfg(test)]
mod tests {
    use fedimint_core::config::{ClientConfig, GlobalClientConfig};

    use crate::module::CoreConsensusVersion;

    #[test]
    fn test_dcode_meta() {
        let config = ClientConfig {
            global: GlobalClientConfig {
                api_endpoints: Default::default(),
                consensus_version: CoreConsensusVersion { major: 0, minor: 0 },
                meta: vec![
                    ("foo".to_string(), "bar".to_string()),
                    ("baz".to_string(), "\"bam\"".to_string()),
                    ("arr".to_string(), "[\"1\", \"2\"]".to_string()),
                ]
                .into_iter()
                .collect(),
            },
            modules: Default::default(),
        };

        assert_eq!(
            config
                .meta::<String>("foo")
                .expect("parsing legacy string failed"),
            Some("bar".to_string())
        );
        assert_eq!(
            config.meta::<String>("baz").expect("parsing string failed"),
            Some("bam".to_string())
        );
        assert_eq!(
            config
                .meta::<Vec<String>>("arr")
                .expect("parsing array failed"),
            Some(vec!["1".to_string(), "2".to_string()])
        );

        assert!(config.meta::<Vec<String>>("foo").is_err());
        assert!(config.meta::<Vec<String>>("baz").is_err());
        assert_eq!(
            config
                .meta::<String>("arr")
                .expect("parsing via legacy fallback failed"),
            Some("[\"1\", \"2\"]".to_string())
        );
    }
}
