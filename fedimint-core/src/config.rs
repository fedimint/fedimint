use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, format_err};
use bitcoin::hashes::sha256::HashEngine;
use bitcoin::hashes::{Hash as BitcoinHash, hex, sha256};
use bls12_381::Scalar;
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{DynRawFallback, Encodable};
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::util::SafeUrl;
use fedimint_core::{ModuleDecoderRegistry, format_hex};
use fedimint_logging::LOG_CORE;
use hex::FromHex;
use secp256k1::PublicKey;
use serde::de::DeserializeOwned;
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::json;
use threshold_crypto::{G1Projective, G2Projective};
use tracing::warn;

use crate::core::DynClientConfig;
use crate::encoding::Decodable;
use crate::module::{
    CoreConsensusVersion, DynCommonModuleInit, IDynCommonModuleInit, ModuleConsensusVersion,
};
use crate::{PeerId, maybe_add_send_sync};

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

/// Total client config v0 (<0.4.0). Does not contain broadcast public keys.
///
/// This includes global settings and client-side module configs.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct ClientConfigV0 {
    #[serde(flatten)]
    pub global: GlobalClientConfigV0,
    #[serde(deserialize_with = "de_int_key")]
    pub modules: BTreeMap<ModuleInstanceId, ClientModuleConfig>,
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

fn optional_de_int_key<'de, D, K, V>(deserializer: D) -> Result<Option<BTreeMap<K, V>>, D::Error>
where
    D: Deserializer<'de>,
    K: Eq + Ord + FromStr,
    K::Err: Display,
    V: Deserialize<'de>,
{
    let Some(string_map) = <Option<BTreeMap<String, V>>>::deserialize(deserializer)? else {
        return Ok(None);
    };

    let map = string_map
        .into_iter()
        .map(|(key_str, value)| {
            let key = K::from_str(&key_str).map_err(serde::de::Error::custom)?;
            Ok((key, value))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;

    Ok(Some(map))
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
pub struct GlobalClientConfigV0 {
    /// API endpoints for each federation member
    #[serde(deserialize_with = "de_int_key")]
    pub api_endpoints: BTreeMap<PeerId, PeerUrl>,
    /// Core consensus version
    pub consensus_version: CoreConsensusVersion,
    // TODO: make it a String -> serde_json::Value map?
    /// Additional config the federation wants to transmit to the clients
    pub meta: BTreeMap<String, String>,
}

/// Federation-wide client config
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct GlobalClientConfig {
    /// API endpoints for each federation member
    #[serde(deserialize_with = "de_int_key")]
    pub api_endpoints: BTreeMap<PeerId, PeerUrl>,
    /// Signing session keys for each federation member
    /// Optional for 0.3.x backwards compatibility
    #[serde(default, deserialize_with = "optional_de_int_key")]
    pub broadcast_public_keys: Option<BTreeMap<PeerId, PublicKey>>,
    /// Core consensus version
    pub consensus_version: CoreConsensusVersion,
    // TODO: make it a String -> serde_json::Value map?
    /// Additional config the federation wants to transmit to the clients
    pub meta: BTreeMap<String, String>,
}

impl GlobalClientConfig {
    /// 0.4.0 and later uses a hash of broadcast public keys to calculate the
    /// federation id. 0.3.x and earlier use a hash of api endpoints
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
                .map(|(k, v)| {
                    // Assuming this isn't running in any hot path it's better to have the debug
                    // info than saving one allocation
                    let kind = v.kind.clone();
                    v.redecode_raw(modules)
                        .context(format!("redecode_raw: instance: {k}, kind: {kind}"))
                        .map(|v| (k, v))
                })
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
            let ret = unsafe {
                // We can transmute a String to V because we know that V==String
                std::mem::transmute::<Box<String>, Box<V>>(string_ret)
            };
            Ok(Some(*ret))
        } else {
            res
        }
    }

    /// Converts a consensus-encoded client config struct to a client config
    /// struct that when encoded as JSON shows the fields of module configs
    /// instead of a consensus-encoded hex string.
    ///
    /// In case of unknown module the config value is a hex string.
    pub fn to_json(&self) -> JsonClientConfig {
        JsonClientConfig {
            global: self.global.clone(),
            modules: self
                .modules
                .iter()
                .map(|(&module_instance_id, module_config)| {
                    let module_config_json = JsonWithKind {
                        kind: module_config.kind.clone(),
                        value: module_config.config
                            .clone()
                            .decoded()
                            .and_then(|dyn_cfg| dyn_cfg.to_json())
                            .unwrap_or_else(|| json!({
                            "unknown_module_hex": module_config.config.consensus_encode_to_hex()
                        })),
                    };
                    (module_instance_id, module_config_json)
                })
                .collect(),
        }
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
        format_hex(&self.0.to_byte_array(), f)
    }
}

impl FromStr for FederationIdPrefix {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(<[u8; 4]>::from_hex(s)?))
    }
}

impl FederationIdPrefix {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

/// Display as a hex encoding
impl FederationId {
    /// Random dummy id for testing
    pub fn dummy() -> Self {
        Self(sha256::Hash::from_byte_array([42; 32]))
    }

    pub(crate) fn from_byte_array(bytes: [u8; 32]) -> Self {
        Self(sha256::Hash::from_byte_array(bytes))
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
        secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    ) -> anyhow::Result<bitcoin::secp256k1::PublicKey> {
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&self.0.to_byte_array())?;
        Ok(bitcoin::secp256k1::PublicKey::from_secret_key(secp, &sk))
    }
}

impl FromStr for FederationId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from_byte_array(<[u8; 32]>::from_hex(s)?))
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
        self.modules.get(&id).map_or_else(
            || Err(format_err!("Client config for module id {id} not found")),
            |client_cfg| client_cfg.cast(),
        )
    }

    // TODO: rename this and one above
    pub fn get_module_cfg(&self, id: ModuleInstanceId) -> anyhow::Result<ClientModuleConfig> {
        self.modules.get(&id).map_or_else(
            || Err(format_err!("Client config for module id {id} not found")),
            |client_cfg| Ok(client_cfg.clone()),
        )
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

impl<M> ModuleInitRegistry<M> {
    pub fn iter(&self) -> impl Iterator<Item = (&ModuleKind, &M)> {
        self.0.iter()
    }
}

impl<M> Default for ModuleInitRegistry<M> {
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}

/// Type erased `ModuleInitParams` used to generate the `ServerModuleConfig`
/// during config gen
#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConfigGenModuleParams {
    pub local: serde_json::Value,
    pub consensus: serde_json::Value,
}

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
        for (id, kind, params) in modules {
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
        Ok(Self::from(params))
    }
}

impl<M> From<Vec<M>> for ModuleInitRegistry<M>
where
    M: AsRef<dyn IDynCommonModuleInit + Send + Sync + 'static>,
{
    fn from(value: Vec<M>) -> Self {
        Self(
            value
                .into_iter()
                .map(|i| (i.as_ref().module_kind(), i))
                .collect::<BTreeMap<_, _>>(),
        )
    }
}

impl<M> FromIterator<M> for ModuleInitRegistry<M>
where
    M: AsRef<maybe_add_send_sync!(dyn IDynCommonModuleInit + 'static)>,
{
    fn from_iter<T: IntoIterator<Item = M>>(iter: T) -> Self {
        Self(
            iter.into_iter()
                .map(|i| (i.as_ref().module_kind(), i))
                .collect::<BTreeMap<_, _>>(),
        )
    }
}

impl<M> ModuleInitRegistry<M> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn attach<T>(&mut self, r#gen: T)
    where
        T: Into<M> + 'static + Send + Sync,
        M: AsRef<dyn IDynCommonModuleInit + 'static + Send + Sync>,
    {
        let r#gen: M = r#gen.into();
        let kind = r#gen.as_ref().module_kind();
        assert!(
            self.0.insert(kind.clone(), r#gen).is_none(),
            "Can't insert module of same kind twice: {kind}"
        );
    }

    pub fn kinds(&self) -> BTreeSet<ModuleKind> {
        self.0.keys().cloned().collect()
    }

    pub fn get(&self, k: &ModuleKind) -> Option<&M> {
        self.0.get(k)
    }
}

impl ModuleRegistry<ConfigGenModuleParams> {
    pub fn attach_config_gen_params_by_id<T: ModuleInitParams>(
        &mut self,
        id: ModuleInstanceId,
        kind: ModuleKind,
        r#gen: T,
    ) -> &mut Self {
        let params = ConfigGenModuleParams::from_typed(r#gen)
            .unwrap_or_else(|err| panic!("Invalid config gen params for {kind}: {err}"));
        self.register_module(id, kind, params);
        self
    }

    pub fn attach_config_gen_params<T: ModuleInitParams>(
        &mut self,
        kind: ModuleKind,
        r#gen: T,
    ) -> &mut Self {
        let params = ConfigGenModuleParams::from_typed(r#gen)
            .unwrap_or_else(|err| panic!("Invalid config gen params for {kind}: {err}"));
        self.append_module(kind, params);
        self
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
}

impl ServerModuleConfig {
    pub fn from(
        local: JsonWithKind,
        private: JsonWithKind,
        consensus: ServerModuleConsensusConfig,
    ) -> Self {
        Self {
            local,
            private,
            consensus,
        }
    }

    pub fn to_typed<T: TypedServerModuleConfig>(&self) -> anyhow::Result<T> {
        let local = serde_json::from_value(self.local.value().clone())?;
        let private = serde_json::from_value(self.private.value().clone())?;
        let consensus = <T::Consensus>::consensus_decode_whole(
            &self.consensus.config[..],
            &ModuleRegistry::default(),
        )?;

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
        Ok(Self::consensus_decode_whole(
            &erased.config[..],
            &ModuleRegistry::default(),
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
                kind,
                serde_json::to_value(private).expect("serialization can't fail"),
            ),
            consensus: ServerModuleConsensusConfig {
                kind: consensus.kind(),
                version: consensus.version(),
                config: consensus.consensus_encode_to_vec(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encodable, Decodable)]
pub enum P2PMessage {
    Aleph(Vec<u8>),
    Checksum(sha256::Hash),
    Dkg(DkgMessage),
    Encodable(Vec<u8>),
}

#[derive(Debug, PartialEq, Eq, Clone, Encodable, Decodable)]
pub enum DkgMessage {
    Hash(sha256::Hash),
    Commitment(Vec<(G1Projective, G2Projective)>),
    Share(Scalar),
}

// TODO: Remove the Serde encoding as soon as the p2p layer drops it as
// requirement
impl Serialize for DkgMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.consensus_encode_to_hex().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DkgMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::consensus_decode_hex(
            &String::deserialize(deserializer)?,
            &ModuleDecoderRegistry::default(),
        )
        .map_err(serde::de::Error::custom)
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

    use hex::{FromHex, ToHex};
    use serde::de::DeserializeOwned;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<T: Serialize, S: Serializer>(x: &T, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            let bytes =
                bincode::serialize(x).map_err(|e| serde::ser::Error::custom(format!("{e:?}")))?;
            s.serialize_str(&bytes.encode_hex::<String>())
        } else {
            Serialize::serialize(x, s)
        }
    }

    pub fn deserialize<'d, T: DeserializeOwned, D: Deserializer<'d>>(d: D) -> Result<T, D::Error> {
        if d.is_human_readable() {
            let hex_str: Cow<str> = Deserialize::deserialize(d)?;
            let bytes = Vec::from_hex(hex_str.as_ref()).map_err(serde::de::Error::custom)?;
            bincode::deserialize(&bytes).map_err(|e| serde::de::Error::custom(format!("{e:?}")))
        } else {
            Deserialize::deserialize(d)
        }
    }
}

#[cfg(test)]
mod tests;
