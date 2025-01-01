use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{bail, format_err, Context};
use fedimint_api_client::api::P2PConnectionStatus;
use fedimint_core::admin_client::ConfigGenParamsConsensus;
pub use fedimint_core::config::{
    serde_binary_human_readable, ClientConfig, DkgPeerMsg, FederationId, GlobalClientConfig,
    JsonWithKind, ModuleInitRegistry, PeerUrl, ServerModuleConfig, ServerModuleConsensusConfig,
    ServerModuleInitRegistry, TypedServerModuleConfig,
};
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::envs::is_running_in_test_env;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::{
    ApiAuth, ApiVersion, CoreConsensusVersion, DynServerModuleInit, MultiApiVersion, PeerHandle,
    SupportedApiVersionsSummary, SupportedCoreApiVersions, CORE_CONSENSUS_VERSION,
};
use fedimint_core::net::peers::IP2PConnections;
use fedimint_core::task::{sleep, TaskGroup};
use fedimint_core::{secp256k1, timing, NumPeersExt, PeerId};
use fedimint_logging::{LOG_NET_PEER, LOG_NET_PEER_DKG};
use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio_rustls::rustls;
use tracing::info;

use crate::config::api::ConfigGenParamsLocal;
use crate::config::distributedgen::PeerHandleOps;
use crate::envs::FM_MAX_CLIENT_CONNECTIONS_ENV;
use crate::fedimint_core::encoding::Encodable;
use crate::net::p2p::ReconnectP2PConnections;
use crate::net::p2p_connector::{dns_sanitize, P2PConnector, TlsConfig};
use crate::TlsTcpConnector;

pub mod api;
pub mod distributedgen;
pub mod io;

/// The default maximum open connections the API can handle
const DEFAULT_MAX_CLIENT_CONNECTIONS: u32 = 1000;

/// Consensus broadcast settings that result in 3 minutes session time
const DEFAULT_BROADCAST_ROUND_DELAY_MS: u16 = 50;
const DEFAULT_BROADCAST_ROUNDS_PER_SESSION: u16 = 3600;

fn default_broadcast_rounds_per_session() -> u16 {
    DEFAULT_BROADCAST_ROUNDS_PER_SESSION
}

/// Consensus broadcast settings that result in 10 seconds session time
const DEFAULT_TEST_BROADCAST_ROUND_DELAY_MS: u16 = 50;
const DEFAULT_TEST_BROADCAST_ROUNDS_PER_SESSION: u16 = 200;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// All the serializable configuration for the fedimint server
pub struct ServerConfig {
    /// Contains all configuration that needs to be the same for every server
    pub consensus: ServerConfigConsensus,
    /// Contains all configuration that is locally configurable and not secret
    pub local: ServerConfigLocal,
    /// Contains all configuration that will be encrypted such as private key
    /// material
    pub private: ServerConfigPrivate,
}

impl ServerConfig {
    pub fn iter_module_instances(
        &self,
    ) -> impl Iterator<Item = (ModuleInstanceId, &ModuleKind)> + '_ {
        self.consensus.iter_module_instances()
    }

    pub(crate) fn supported_api_versions_summary(
        modules: &BTreeMap<ModuleInstanceId, ServerModuleConsensusConfig>,
        module_inits: &ServerModuleInitRegistry,
    ) -> SupportedApiVersionsSummary {
        SupportedApiVersionsSummary {
            core: Self::supported_api_versions(),
            modules: modules
                .iter()
                .map(|(&id, config)| {
                    (
                        id,
                        module_inits
                            .get(&config.kind)
                            .expect("missing module kind gen")
                            .supported_api_versions(),
                    )
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfigPrivate {
    /// Secret API auth string
    pub api_auth: ApiAuth,
    /// Secret key for TLS communication, required for peer authentication
    #[serde(with = "serde_tls_key")]
    pub tls_key: rustls::PrivateKey,
    /// Secret key for the atomic broadcast to sign messages
    pub broadcast_secret_key: SecretKey,
    /// Secret material from modules
    pub modules: BTreeMap<ModuleInstanceId, JsonWithKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encodable)]
pub struct ServerConfigConsensus {
    /// The version of the binary code running
    pub code_version: String,
    /// Agreed on core consensus version
    pub version: CoreConsensusVersion,
    /// Public keys for the atomic broadcast to authenticate messages
    pub broadcast_public_keys: BTreeMap<PeerId, PublicKey>,
    /// Number of rounds per session.
    #[serde(default = "default_broadcast_rounds_per_session")]
    pub broadcast_rounds_per_session: u16,
    /// Network addresses and names for all peer APIs
    pub api_endpoints: BTreeMap<PeerId, PeerUrl>,
    /// Certs for TLS communication, required for peer authentication
    #[serde(with = "serde_tls_cert_map")]
    pub tls_certs: BTreeMap<PeerId, rustls::Certificate>,
    /// All configuration that needs to be the same for modules
    pub modules: BTreeMap<ModuleInstanceId, ServerModuleConsensusConfig>,
    /// Additional config the federation wants to transmit to the clients
    pub meta: BTreeMap<String, String>,
}

// FIXME: (@leonardo) Should this have another field for the expected transport
// ? (e.g. clearnet/tor/...)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfigLocal {
    /// Network addresses and names for all p2p connections
    pub p2p_endpoints: BTreeMap<PeerId, PeerUrl>,
    /// Our peer id (generally should not change)
    pub identity: PeerId,
    /// How many API connections we will accept
    pub max_connections: u32,
    /// Influences the atomic broadcast ordering latency, should be higher than
    /// the expected latency between peers so everyone can get proposed
    /// consensus items confirmed. This is only relevant for byzantine
    /// faults.
    pub broadcast_round_delay_ms: u16,
    /// Non-consensus, non-private configuration from modules
    pub modules: BTreeMap<ModuleInstanceId, JsonWithKind>,
}

#[derive(Debug, Clone)]
/// All the parameters necessary for generating the `ServerConfig` during setup
///
/// * Guardians can create the parameters using a setup UI or CLI tool
/// * Used for distributed or trusted config generation
pub struct ConfigGenParams {
    pub local: ConfigGenParamsLocal,
    pub consensus: ConfigGenParamsConsensus,
}

impl ServerConfigConsensus {
    pub fn iter_module_instances(
        &self,
    ) -> impl Iterator<Item = (ModuleInstanceId, &ModuleKind)> + '_ {
        self.modules.iter().map(|(k, v)| (*k, &v.kind))
    }

    pub fn to_client_config(
        &self,
        module_config_gens: &ModuleInitRegistry<DynServerModuleInit>,
    ) -> Result<ClientConfig, anyhow::Error> {
        let client = ClientConfig {
            global: GlobalClientConfig {
                api_endpoints: self.api_endpoints.clone(),
                broadcast_public_keys: Some(self.broadcast_public_keys.clone()),
                consensus_version: self.version,
                meta: self.meta.clone(),
            },
            modules: self
                .modules
                .iter()
                .map(|(k, v)| {
                    let gen = module_config_gens
                        .get(&v.kind)
                        .ok_or_else(|| format_err!("Module gen kind={} not found", v.kind))?;
                    Ok((*k, gen.get_client_config(*k, v)?))
                })
                .collect::<anyhow::Result<BTreeMap<_, _>>>()?,
        };
        Ok(client)
    }
}

impl ServerConfig {
    /// Api versions supported by this server
    pub fn supported_api_versions() -> SupportedCoreApiVersions {
        SupportedCoreApiVersions {
            core_consensus: CORE_CONSENSUS_VERSION,
            api: MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 5 }])
                .expect("not version conflicts"),
        }
    }
    /// Creates a new config from the results of a trusted or distributed key
    /// setup
    pub fn from(
        params: ConfigGenParams,
        identity: PeerId,
        broadcast_public_keys: BTreeMap<PeerId, PublicKey>,
        broadcast_secret_key: SecretKey,
        modules: BTreeMap<ModuleInstanceId, ServerModuleConfig>,
        code_version_str: String,
    ) -> Self {
        let private = ServerConfigPrivate {
            api_auth: params.local.api_auth.clone(),
            tls_key: params.local.our_private_key.clone(),
            broadcast_secret_key,
            modules: BTreeMap::new(),
        };
        let local = ServerConfigLocal {
            p2p_endpoints: params.p2p_urls(),
            identity,
            max_connections: DEFAULT_MAX_CLIENT_CONNECTIONS,
            broadcast_round_delay_ms: if is_running_in_test_env() {
                DEFAULT_TEST_BROADCAST_ROUND_DELAY_MS
            } else {
                DEFAULT_BROADCAST_ROUND_DELAY_MS
            },
            modules: BTreeMap::new(),
        };
        let consensus = ServerConfigConsensus {
            code_version: code_version_str,
            version: CORE_CONSENSUS_VERSION,
            broadcast_public_keys,
            broadcast_rounds_per_session: if is_running_in_test_env() {
                DEFAULT_TEST_BROADCAST_ROUNDS_PER_SESSION
            } else {
                DEFAULT_BROADCAST_ROUNDS_PER_SESSION
            },
            api_endpoints: params.api_urls(),
            tls_certs: params.tls_certs(),
            modules: BTreeMap::new(),
            meta: params.consensus.meta,
        };
        let mut cfg = Self {
            consensus,
            local,
            private,
        };
        cfg.add_modules(modules);
        cfg
    }

    pub fn get_invite_code(&self, api_secret: Option<String>) -> InviteCode {
        InviteCode::new(
            self.consensus.api_endpoints[&self.local.identity]
                .url
                .clone(),
            self.local.identity,
            self.calculate_federation_id(),
            api_secret,
        )
    }

    pub fn calculate_federation_id(&self) -> FederationId {
        FederationId(self.consensus.api_endpoints.consensus_hash())
    }

    pub fn add_modules(&mut self, modules: BTreeMap<ModuleInstanceId, ServerModuleConfig>) {
        for (name, config) in modules {
            let ServerModuleConfig {
                local,
                private,
                consensus,
            } = config;

            self.local.modules.insert(name, local);
            self.private.modules.insert(name, private);
            self.consensus.modules.insert(name, consensus);
        }
    }

    /// Constructs a module config by name
    pub fn get_module_config_typed<T: TypedServerModuleConfig>(
        &self,
        id: ModuleInstanceId,
    ) -> anyhow::Result<T> {
        let local = Self::get_module_cfg_by_instance_id(&self.local.modules, id)?;
        let private = Self::get_module_cfg_by_instance_id(&self.private.modules, id)?;
        let consensus = self
            .consensus
            .modules
            .get(&id)
            .ok_or_else(|| format_err!("Module {id} not found"))?
            .clone();
        let module = ServerModuleConfig::from(local, private, consensus);

        module.to_typed()
    }
    pub fn get_module_id_by_kind(
        &self,
        kind: impl Into<ModuleKind>,
    ) -> anyhow::Result<ModuleInstanceId> {
        let kind = kind.into();
        Ok(*self
            .consensus
            .modules
            .iter()
            .find(|(_, v)| v.kind == kind)
            .ok_or_else(|| format_err!("Module {kind} not found"))?
            .0)
    }

    /// Constructs a module config by id
    pub fn get_module_config(&self, id: ModuleInstanceId) -> anyhow::Result<ServerModuleConfig> {
        let local = Self::get_module_cfg_by_instance_id(&self.local.modules, id)?;
        let private = Self::get_module_cfg_by_instance_id(&self.private.modules, id)?;
        let consensus = self
            .consensus
            .modules
            .get(&id)
            .ok_or_else(|| format_err!("Module {id} not found"))?
            .clone();
        Ok(ServerModuleConfig::from(local, private, consensus))
    }

    fn get_module_cfg_by_instance_id(
        json: &BTreeMap<ModuleInstanceId, JsonWithKind>,
        id: ModuleInstanceId,
    ) -> anyhow::Result<JsonWithKind> {
        Ok(json
            .get(&id)
            .ok_or_else(|| format_err!("Module {id} not found"))
            .cloned()?
            .with_fixed_empty_value())
    }

    pub fn validate_config(
        &self,
        identity: &PeerId,
        module_config_gens: &ServerModuleInitRegistry,
    ) -> anyhow::Result<()> {
        let peers = self.local.p2p_endpoints.clone();
        let consensus = self.consensus.clone();
        let private = self.private.clone();

        let my_public_key = private.broadcast_secret_key.public_key(&Secp256k1::new());

        if Some(&my_public_key) != consensus.broadcast_public_keys.get(identity) {
            bail!("Broadcast secret key doesn't match corresponding public key");
        }
        if peers.keys().max().copied().map(PeerId::to_usize) != Some(peers.len() - 1) {
            bail!("Peer ids are not indexed from 0");
        }
        if peers.keys().min().copied() != Some(PeerId::from(0)) {
            bail!("Peer ids are not indexed from 0");
        }

        for (module_id, module_kind) in &self
            .consensus
            .modules
            .iter()
            .map(|(id, config)| Ok((*id, config.kind.clone())))
            .collect::<anyhow::Result<BTreeSet<_>>>()?
        {
            module_config_gens
                .get(module_kind)
                .ok_or_else(|| format_err!("module config gen not found {module_kind}"))?
                .validate_config(identity, self.get_module_config(*module_id)?)?;
        }

        Ok(())
    }

    pub fn trusted_dealer_gen(
        params: &HashMap<PeerId, ConfigGenParams>,
        registry: &ServerModuleInitRegistry,
        code_version_str: &str,
    ) -> BTreeMap<PeerId, Self> {
        let peer0 = &params[&PeerId::from(0)];

        let mut broadcast_pks = BTreeMap::new();
        let mut broadcast_sks = BTreeMap::new();
        for peer_id in peer0.peer_ids() {
            let (broadcast_sk, broadcast_pk) = secp256k1::generate_keypair(&mut OsRng);
            broadcast_pks.insert(peer_id, broadcast_pk);
            broadcast_sks.insert(peer_id, broadcast_sk);
        }

        let modules = peer0.consensus.modules.iter_modules();
        let module_configs: BTreeMap<_, _> = modules
            .map(|(module_id, kind, module_params)| {
                (
                    module_id,
                    registry
                        .get(kind)
                        .expect("Module not registered")
                        .trusted_dealer_gen(&peer0.peer_ids(), module_params),
                )
            })
            .collect();

        let server_config: BTreeMap<_, _> = peer0
            .peer_ids()
            .iter()
            .map(|&id| {
                let config = ServerConfig::from(
                    params[&id].clone(),
                    id,
                    broadcast_pks.clone(),
                    *broadcast_sks.get(&id).expect("We created this entry"),
                    module_configs
                        .iter()
                        .map(|(module_id, cfgs)| (*module_id, cfgs[&id].clone()))
                        .collect(),
                    code_version_str.to_string(),
                );
                (id, config)
            })
            .collect();

        server_config
    }

    /// Runs the distributed key gen algorithm
    pub async fn distributed_gen(
        p2p_bind_addr: SocketAddr,
        params: &ConfigGenParams,
        registry: ServerModuleInitRegistry,
        task_group: &TaskGroup,
        code_version_str: String,
    ) -> anyhow::Result<Self> {
        let _timing /* logs on drop */ = timing::TimeReporter::new("distributed-gen").info();

        // in case we are running by ourselves, avoid DKG
        if params.peer_ids().len() == 1 {
            let server = Self::trusted_dealer_gen(
                &HashMap::from([(params.local.our_id, params.clone())]),
                &registry,
                &code_version_str,
            );
            return Ok(server[&params.local.our_id].clone());
        }

        let connector = TlsTcpConnector::new(
            params.tls_config(),
            p2p_bind_addr,
            params
                .p2p_urls()
                .into_iter()
                .map(|(id, peer)| (id, peer.url))
                .collect(),
            params.local.our_id,
        )
        .into_dyn();

        let mut p2p_status_senders = BTreeMap::new();
        let mut p2p_status_receivers = BTreeMap::new();

        for peer in connector.peers() {
            let (p2p_sender, p2p_receiver) = watch::channel(P2PConnectionStatus::Disconnected);

            p2p_status_senders.insert(peer, p2p_sender);
            p2p_status_receivers.insert(peer, p2p_receiver);
        }

        let connections = ReconnectP2PConnections::new(
            params.local.our_id,
            connector,
            task_group,
            Some(p2p_status_senders),
        )
        .await
        .into_dyn();

        while p2p_status_receivers
            .values()
            .any(|r| *r.borrow() == P2PConnectionStatus::Disconnected)
        {
            info!(
                target: LOG_NET_PEER_DKG,
                "Waiting for all p2p connections to open..."
            );

            sleep(Duration::from_secs(1)).await;
        }

        info!(
            target: LOG_NET_PEER_DKG,
            "Running distributed key generation..."
        );

        let handle = PeerHandle::new(
            params.peer_ids().to_num_peers(),
            params.local.our_id,
            &connections,
        );

        let (broadcast_sk, broadcast_pk) = secp256k1::generate_keypair(&mut OsRng);

        let broadcast_public_keys = handle.exchange_encodable(broadcast_pk).await?;

        let mut module_cfgs = BTreeMap::new();

        for (module_id, kind, module_params) in params.consensus.modules.iter_modules() {
            info!(
                target: LOG_NET_PEER_DKG,
                "Running distributed key generation for module of kind {kind}..."
            );

            let cfg = registry
                .get(kind)
                .context("Module of kind {kind} not found")?
                .distributed_gen(&handle, module_params)
                .await?;

            module_cfgs.insert(module_id, cfg);
        }

        // We need to wait for out outgoing message queues to be fully transmitted
        // before we move on in order for our peers to be able to complete the dkg.

        connections.await_empty_outgoing_message_queues().await;

        info!(
            target: LOG_NET_PEER,
            "Distributed key generation has completed successfully!"
        );

        let server = ServerConfig::from(
            params.clone(),
            params.local.our_id,
            broadcast_public_keys,
            broadcast_sk,
            module_cfgs,
            code_version_str,
        );

        Ok(server)
    }
}

impl ServerConfig {
    pub fn tls_config(&self) -> TlsConfig {
        TlsConfig {
            private_key: self.private.tls_key.clone(),
            certificates: self.consensus.tls_certs.clone(),
            peer_names: self
                .local
                .p2p_endpoints
                .iter()
                .map(|(id, endpoint)| (*id, endpoint.name.to_string()))
                .collect(),
        }
    }

    pub fn get_incoming_count(&self) -> u16 {
        self.local.identity.into()
    }
}

impl ConfigGenParams {
    pub fn peer_ids(&self) -> Vec<PeerId> {
        self.consensus.peers.keys().copied().collect()
    }

    pub fn tls_config(&self) -> TlsConfig {
        TlsConfig {
            private_key: self.local.our_private_key.clone(),
            certificates: self.tls_certs(),
            peer_names: self
                .p2p_urls()
                .into_iter()
                .map(|(id, peer)| (id, peer.name))
                .collect(),
        }
    }

    pub fn tls_certs(&self) -> BTreeMap<PeerId, rustls::Certificate> {
        self.consensus
            .peers
            .iter()
            .map(|(id, peer)| (*id, peer.cert.clone()))
            .collect::<BTreeMap<_, _>>()
    }

    pub fn p2p_urls(&self) -> BTreeMap<PeerId, PeerUrl> {
        self.consensus
            .peers
            .iter()
            .map(|(id, peer)| {
                (
                    *id,
                    PeerUrl {
                        name: peer.name.clone(),
                        url: peer.p2p_url.clone(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>()
    }

    pub fn api_urls(&self) -> BTreeMap<PeerId, PeerUrl> {
        self.consensus
            .peers
            .iter()
            .map(|(id, peer)| {
                (
                    *id,
                    PeerUrl {
                        name: peer.name.clone(),
                        url: peer.api_url.clone(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>()
    }
}

// TODO: Remove once new config gen UI is written
pub fn max_connections() -> u32 {
    env::var(FM_MAX_CLIENT_CONNECTIONS_ENV)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_CLIENT_CONNECTIONS)
}

pub fn gen_cert_and_key(
    name: &str,
) -> Result<(rustls::Certificate, rustls::PrivateKey), anyhow::Error> {
    let keypair = rcgen::KeyPair::generate()?;
    let keypair_ser = keypair.serialize_der();
    let mut params = rcgen::CertificateParams::new(vec![dns_sanitize(name)])?;

    params.is_ca = rcgen::IsCa::NoCa;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, dns_sanitize(name));

    let cert = params.self_signed(&keypair)?;

    Ok((
        rustls::Certificate(cert.der().to_vec()),
        rustls::PrivateKey(keypair_ser),
    ))
}

mod serde_tls_cert_map {
    use std::borrow::Cow;
    use std::collections::BTreeMap;

    use fedimint_core::PeerId;
    use hex::{FromHex, ToHex};
    use serde::de::Error;
    use serde::ser::SerializeMap;
    use serde::{Deserialize, Deserializer, Serializer};
    use tokio_rustls::rustls;

    pub fn serialize<S>(
        certs: &BTreeMap<PeerId, rustls::Certificate>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut serializer = serializer.serialize_map(Some(certs.len()))?;
        for (key, value) in certs {
            serializer.serialize_key(key)?;
            let hex_str = value.0.encode_hex::<String>();
            serializer.serialize_value(&hex_str)?;
        }
        serializer.end()
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<BTreeMap<PeerId, rustls::Certificate>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map: BTreeMap<PeerId, Cow<str>> = Deserialize::deserialize(deserializer)?;
        let mut certs = BTreeMap::new();

        for (key, value) in map {
            let cert =
                rustls::Certificate(Vec::from_hex(value.as_ref()).map_err(D::Error::custom)?);
            certs.insert(key, cert);
        }
        Ok(certs)
    }
}

mod serde_tls_key {
    use std::borrow::Cow;

    use hex::{FromHex, ToHex};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use tokio_rustls::rustls;

    pub fn serialize<S>(key: &rustls::PrivateKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_str = key.0.encode_hex::<String>();
        Serialize::serialize(&hex_str, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<rustls::PrivateKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str: Cow<str> = Deserialize::deserialize(deserializer)?;
        let bytes = Vec::from_hex(hex_str.as_ref()).map_err(serde::de::Error::custom)?;
        Ok(rustls::PrivateKey(bytes))
    }
}
