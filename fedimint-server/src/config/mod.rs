use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, bail, ensure, format_err};
use bitcoin::hashes::sha256;
use fedimint_core::config::ServerModuleConfigGenParamsRegistry;
pub use fedimint_core::config::{
    ClientConfig, FederationId, GlobalClientConfig, JsonWithKind, ModuleInitRegistry, P2PMessage,
    PeerUrl, ServerModuleConfig, ServerModuleConsensusConfig, TypedServerModuleConfig,
    serde_binary_human_readable,
};
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::Decodable;
use fedimint_core::envs::is_running_in_test_env;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{
    ApiAuth, ApiVersion, CORE_CONSENSUS_VERSION, CoreConsensusVersion, MultiApiVersion,
    SupportedApiVersionsSummary, SupportedCoreApiVersions,
};
use fedimint_core::net::peers::{DynP2PConnections, Recipient};
use fedimint_core::task::sleep;
use fedimint_core::util::SafeUrl;
use fedimint_core::{NumPeersExt, PeerId, base32, secp256k1, timing};
use fedimint_logging::LOG_NET_PEER_DKG;
use fedimint_server_core::config::PeerHandleOpsExt as _;
use fedimint_server_core::{DynServerModuleInit, ServerModuleInitRegistry};
use hex::{FromHex, ToHex};
use peer_handle::PeerHandle;
use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use tokio_rustls::rustls;
use tracing::info;

use crate::fedimint_core::encoding::Encodable;
use crate::net::p2p::P2PStatusReceivers;
use crate::net::p2p_connector::TlsConfig;

pub mod dkg;
pub mod io;
pub mod peer_handle;
pub mod setup;

/// The default maximum open connections the API can handle
pub const DEFAULT_MAX_CLIENT_CONNECTIONS: u32 = 1000;

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
    /// Optional secret key for our websocket p2p endpoint
    pub tls_key: Option<String>,
    /// Optional secret key for our iroh api endpoint
    #[serde(default)]
    pub iroh_api_sk: Option<iroh::SecretKey>,
    /// Optional secret key for our iroh p2p endpoint
    #[serde(default)]
    pub iroh_p2p_sk: Option<iroh::SecretKey>,
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
    /// Public keys for all iroh api and p2p endpoints
    #[serde(default)]
    pub iroh_endpoints: BTreeMap<PeerId, PeerIrohEndpoints>,
    /// Certs for TLS communication, required for peer authentication
    pub tls_certs: BTreeMap<PeerId, String>,
    /// All configuration that needs to be the same for modules
    pub modules: BTreeMap<ModuleInstanceId, ServerModuleConsensusConfig>,
    /// Additional config the federation wants to transmit to the clients
    pub meta: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encodable)]
pub struct PeerIrohEndpoints {
    /// The peer's name
    pub name: String,
    /// Public key for our iroh api endpoint
    pub api_pk: iroh::PublicKey,
    /// Public key for our iroh p2p endpoint
    pub p2p_pk: iroh::PublicKey,
}

pub fn legacy_consensus_config_hash(cfg: &ServerConfigConsensus) -> sha256::Hash {
    #[derive(Encodable)]
    struct LegacyServerConfigConsensusHashMap {
        code_version: String,
        version: CoreConsensusVersion,
        broadcast_public_keys: BTreeMap<PeerId, PublicKey>,
        broadcast_rounds_per_session: u16,
        api_endpoints: BTreeMap<PeerId, PeerUrl>,
        tls_certs: BTreeMap<PeerId, String>,
        modules: BTreeMap<ModuleInstanceId, ServerModuleConsensusConfig>,
        meta: BTreeMap<String, String>,
    }

    LegacyServerConfigConsensusHashMap {
        code_version: cfg.code_version.clone(),
        version: cfg.version,
        broadcast_public_keys: cfg.broadcast_public_keys.clone(),
        broadcast_rounds_per_session: cfg.broadcast_rounds_per_session,
        api_endpoints: cfg.api_endpoints.clone(),
        tls_certs: cfg.tls_certs.clone(),
        modules: cfg.modules.clone(),
        meta: cfg.meta.clone(),
    }
    .consensus_hash_sha256()
}

/// The type of networking `fedimintd` should use
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub enum NetworkingStack {
    #[default]
    Tcp,
    Iroh,
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
}

/// All the info we configure prior to config gen starting
#[derive(Debug, Clone)]
pub struct ConfigGenSettings {
    /// Bind address for our P2P connection (both iroh and tcp/tls)
    pub p2p_bind: SocketAddr,
    /// Bind address for our API
    pub api_bind: SocketAddr,
    /// Bind address for our UI connection (always http)
    pub ui_bind: SocketAddr,
    /// URL for our P2P connection
    pub p2p_url: Option<SafeUrl>,
    /// URL for our API connection
    pub api_url: Option<SafeUrl>,
    /// Networking stack to use
    /// TODO: we might make it a part of the API  request when ready
    /// (move to `SetLocalParamsRequest`).
    pub networking: NetworkingStack,
    /// Set the params (if leader) or just the local params (if follower)
    pub modules: ServerModuleConfigGenParamsRegistry,
    /// Registry for config gen
    pub registry: ServerModuleInitRegistry,
}

#[derive(Debug, Clone)]
/// All the parameters necessary for generating the `ServerConfig` during setup
///
/// * Guardians can create the parameters using a setup UI or CLI tool
/// * Used for distributed or trusted config generation
pub struct ConfigGenParams {
    /// Our own peer id
    pub identity: PeerId,
    /// Our TLS certificate private key
    pub tls_key: Option<rustls::PrivateKey>,
    /// Optional secret key for our iroh api endpoint
    pub iroh_api_sk: Option<iroh::SecretKey>,
    /// Optional secret key for our iroh p2p endpoint
    pub iroh_p2p_sk: Option<iroh::SecretKey>,
    /// Secret API auth string
    pub api_auth: ApiAuth,
    /// Endpoints of all servers
    pub peers: BTreeMap<PeerId, PeerSetupCode>,
    /// Guardian-defined key-value pairs that will be passed to the client
    pub meta: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encodable, Decodable)]
/// Connection information sent between peers in order to start config gen
pub struct PeerSetupCode {
    /// Name of the peer, used in TLS auth
    pub name: String,
    /// The peer's api and p2p endpoint
    pub endpoints: PeerEndpoints,
    /// Federation name set by the leader
    pub federation_name: Option<String>,
}

impl PeerSetupCode {
    pub fn encode_base32(&self) -> String {
        format!(
            "fedimint{}",
            base32::encode(&self.consensus_encode_to_vec())
        )
    }

    pub fn decode_base32(s: &str) -> anyhow::Result<Self> {
        ensure!(s.starts_with("fedimint"), "Invalid Prefix");

        let params = Self::consensus_decode_whole(
            &base32::decode(&s[8..])?,
            &ModuleDecoderRegistry::default(),
        )?;

        Ok(params)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encodable, Decodable)]
pub enum PeerEndpoints {
    Tcp {
        /// Url for our websocket api endpoint
        api_url: SafeUrl,
        /// Url for our websocket p2p endpoint
        p2p_url: SafeUrl,
        /// TLS certificate for our websocket p2p endpoint       
        cert: Vec<u8>,
    },
    Iroh {
        /// Public key for our iroh api endpoint
        api_pk: iroh::PublicKey,
        /// Public key for our iroh p2p endpoint
        p2p_pk: iroh::PublicKey,
    },
}

impl ServerConfigConsensus {
    pub fn api_endpoints(&self) -> BTreeMap<PeerId, PeerUrl> {
        if self.iroh_endpoints.is_empty() {
            self.api_endpoints.clone()
        } else {
            self.iroh_endpoints
                .iter()
                .map(|(peer, endpoints)| {
                    let url = PeerUrl {
                        name: endpoints.name.clone(),
                        url: SafeUrl::parse(&format!("iroh://{}", endpoints.api_pk))
                            .expect("Failed to parse iroh url"),
                    };

                    (*peer, url)
                })
                .collect()
        }
    }

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
                api_endpoints: self.api_endpoints(),
                broadcast_public_keys: Some(self.broadcast_public_keys.clone()),
                consensus_version: self.version,
                meta: self.meta.clone(),
            },
            modules: self
                .modules
                .iter()
                .map(|(k, v)| {
                    let r#gen = module_config_gens
                        .get(&v.kind)
                        .ok_or_else(|| format_err!("Module gen kind={} not found", v.kind))?;
                    Ok((*k, r#gen.get_client_config(*k, v)?))
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
        code_version: String,
    ) -> Self {
        let consensus = ServerConfigConsensus {
            code_version,
            version: CORE_CONSENSUS_VERSION,
            broadcast_public_keys,
            broadcast_rounds_per_session: if is_running_in_test_env() {
                DEFAULT_TEST_BROADCAST_ROUNDS_PER_SESSION
            } else {
                DEFAULT_BROADCAST_ROUNDS_PER_SESSION
            },
            api_endpoints: params.api_urls(),
            iroh_endpoints: params.iroh_endpoints(),
            tls_certs: params.tls_certs(),
            modules: modules
                .iter()
                .map(|(peer, cfg)| (*peer, cfg.consensus.clone()))
                .collect(),
            meta: params.meta.clone(),
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
        };

        let private = ServerConfigPrivate {
            api_auth: params.api_auth.clone(),
            tls_key: params.tls_key.map(|key| key.0.encode_hex()),
            iroh_api_sk: params.iroh_api_sk,
            iroh_p2p_sk: params.iroh_p2p_sk,
            broadcast_secret_key,
            modules: modules
                .iter()
                .map(|(peer, cfg)| (*peer, cfg.private.clone()))
                .collect(),
        };

        Self {
            consensus,
            local,
            private,
        }
    }

    pub fn get_invite_code(&self, api_secret: Option<String>) -> InviteCode {
        InviteCode::new(
            self.consensus.api_endpoints()[&self.local.identity]
                .url
                .clone(),
            self.local.identity,
            self.calculate_federation_id(),
            api_secret,
        )
    }

    pub fn calculate_federation_id(&self) -> FederationId {
        FederationId(self.consensus.api_endpoints().consensus_hash())
    }

    /// Constructs a module config by name
    pub fn get_module_config_typed<T: TypedServerModuleConfig>(
        &self,
        id: ModuleInstanceId,
    ) -> anyhow::Result<T> {
        let private = Self::get_module_cfg_by_instance_id(&self.private.modules, id)?;
        let consensus = self
            .consensus
            .modules
            .get(&id)
            .ok_or_else(|| format_err!("Module {id} not found"))?
            .clone();
        let module = ServerModuleConfig::from(private, consensus);

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
        let private = Self::get_module_cfg_by_instance_id(&self.private.modules, id)?;
        let consensus = self
            .consensus
            .modules
            .get(&id)
            .ok_or_else(|| format_err!("Module {id} not found"))?
            .clone();
        Ok(ServerModuleConfig::from(private, consensus))
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
        let endpoints = self.consensus.api_endpoints().clone();
        let consensus = self.consensus.clone();
        let private = self.private.clone();

        let my_public_key = private.broadcast_secret_key.public_key(&Secp256k1::new());

        if Some(&my_public_key) != consensus.broadcast_public_keys.get(identity) {
            bail!("Broadcast secret key doesn't match corresponding public key");
        }
        if endpoints.keys().max().copied().map(PeerId::to_usize) != Some(endpoints.len() - 1) {
            bail!("Peer ids are not indexed from 0");
        }
        if endpoints.keys().min().copied() != Some(PeerId::from(0)) {
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
        modules: ServerModuleConfigGenParamsRegistry,
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

        let module_configs: BTreeMap<_, _> = modules
            .iter_modules()
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
        modules: ServerModuleConfigGenParamsRegistry,
        params: &ConfigGenParams,
        registry: ServerModuleInitRegistry,
        code_version_str: String,
        connections: DynP2PConnections<P2PMessage>,
        p2p_status_receivers: P2PStatusReceivers,
    ) -> anyhow::Result<Self> {
        let _timing /* logs on drop */ = timing::TimeReporter::new("distributed-gen").info();

        // in case we are running by ourselves, avoid DKG
        if params.peer_ids().len() == 1 {
            let server = Self::trusted_dealer_gen(
                modules,
                &HashMap::from([(params.identity, params.clone())]),
                &registry,
                &code_version_str,
            );
            return Ok(server[&params.identity].clone());
        }

        info!(
            target: LOG_NET_PEER_DKG,
            "Waiting for all p2p connections to open..."
        );

        while p2p_status_receivers.values().any(|r| r.borrow().is_none()) {
            let peers = p2p_status_receivers
                .iter()
                .filter_map(|entry| entry.1.borrow().map(|_| *entry.0))
                .collect::<Vec<PeerId>>();

            info!(
                target: LOG_NET_PEER_DKG,
                "Connected to peers: {peers:?}..."
            );

            sleep(Duration::from_secs(1)).await;
        }

        let checksum = params.peers.consensus_hash_sha256();

        info!(
            target: LOG_NET_PEER_DKG,
            "Comparing connection codes checksum {checksum}..."
        );

        connections
            .send(Recipient::Everyone, P2PMessage::Checksum(checksum))
            .await;

        for peer in params
            .peer_ids()
            .into_iter()
            .filter(|p| *p != params.identity)
        {
            ensure!(
                connections
                    .receive_from_peer(peer)
                    .await
                    .context("Unexpected shutdown of p2p connections")?
                    == P2PMessage::Checksum(checksum),
                "Peer {peer} has not send the correct checksum message"
            );
        }

        info!(
            target: LOG_NET_PEER_DKG,
            "Running config generation..."
        );

        let handle = PeerHandle::new(
            params.peer_ids().to_num_peers(),
            params.identity,
            &connections,
        );

        let (broadcast_sk, broadcast_pk) = secp256k1::generate_keypair(&mut OsRng);

        let broadcast_public_keys = handle.exchange_encodable(broadcast_pk).await?;

        let mut module_cfgs = BTreeMap::new();

        for (module_id, kind, module_params) in modules.iter_modules() {
            info!(
                target: LOG_NET_PEER_DKG,
                "Running config generation for module of kind {kind}..."
            );

            let cfg = registry
                .get(kind)
                .context("Module of kind {kind} not found")?
                .distributed_gen(&handle, module_params)
                .await?;

            module_cfgs.insert(module_id, cfg);
        }

        let cfg = ServerConfig::from(
            params.clone(),
            params.identity,
            broadcast_public_keys,
            broadcast_sk,
            module_cfgs,
            code_version_str,
        );

        let checksum = cfg.consensus.consensus_hash_sha256();

        info!(
            target: LOG_NET_PEER_DKG,
            "Comparing consensus config checksum {checksum}..."
        );

        connections
            .send(Recipient::Everyone, P2PMessage::Checksum(checksum))
            .await;

        for peer in params
            .peer_ids()
            .into_iter()
            .filter(|p| *p != params.identity)
        {
            ensure!(
                connections
                    .receive_from_peer(peer)
                    .await
                    .context("Unexpected shutdown of p2p connections")?
                    == P2PMessage::Checksum(checksum),
                "Peer {peer} has not send the correct checksum message"
            );
        }

        info!(
            target: LOG_NET_PEER_DKG,
            "Config generation has completed successfully!"
        );

        Ok(cfg)
    }
}

impl ServerConfig {
    pub fn tls_config(&self) -> TlsConfig {
        TlsConfig {
            private_key: rustls::PrivateKey(
                Vec::from_hex(self.private.tls_key.clone().unwrap()).unwrap(),
            ),
            certificates: self
                .consensus
                .tls_certs
                .iter()
                .map(|(peer, cert)| (*peer, rustls::Certificate(Vec::from_hex(cert).unwrap())))
                .collect(),
            peer_names: self
                .local
                .p2p_endpoints
                .iter()
                .map(|(id, endpoint)| (*id, endpoint.name.to_string()))
                .collect(),
        }
    }
}

impl ConfigGenParams {
    pub fn peer_ids(&self) -> Vec<PeerId> {
        self.peers.keys().copied().collect()
    }

    pub fn tls_config(&self) -> TlsConfig {
        TlsConfig {
            private_key: self.tls_key.clone().unwrap(),
            certificates: self
                .tls_certs()
                .iter()
                .map(|(peer, cert)| (*peer, rustls::Certificate(Vec::from_hex(cert).unwrap())))
                .collect(),
            peer_names: self
                .p2p_urls()
                .into_iter()
                .map(|(id, peer)| (id, peer.name))
                .collect(),
        }
    }

    pub fn tls_certs(&self) -> BTreeMap<PeerId, String> {
        self.peers
            .iter()
            .filter_map(|(id, peer)| {
                match peer.endpoints.clone() {
                    PeerEndpoints::Tcp { cert, .. } => Some(cert.encode_hex()),
                    PeerEndpoints::Iroh { .. } => None,
                }
                .map(|peer| (*id, peer))
            })
            .collect()
    }

    pub fn p2p_urls(&self) -> BTreeMap<PeerId, PeerUrl> {
        self.peers
            .iter()
            .filter_map(|(id, peer)| {
                match peer.endpoints.clone() {
                    PeerEndpoints::Tcp { p2p_url, .. } => Some(PeerUrl {
                        name: peer.name.clone(),
                        url: p2p_url.clone(),
                    }),
                    PeerEndpoints::Iroh { .. } => None,
                }
                .map(|peer| (*id, peer))
            })
            .collect()
    }

    pub fn api_urls(&self) -> BTreeMap<PeerId, PeerUrl> {
        self.peers
            .iter()
            .filter_map(|(id, peer)| {
                match peer.endpoints.clone() {
                    PeerEndpoints::Tcp { api_url, .. } => Some(PeerUrl {
                        name: peer.name.clone(),
                        url: api_url.clone(),
                    }),
                    PeerEndpoints::Iroh { .. } => None,
                }
                .map(|peer| (*id, peer))
            })
            .collect()
    }

    pub fn iroh_endpoints(&self) -> BTreeMap<PeerId, PeerIrohEndpoints> {
        self.peers
            .iter()
            .filter_map(|(id, peer)| {
                match peer.endpoints.clone() {
                    PeerEndpoints::Tcp { .. } => None,
                    PeerEndpoints::Iroh { api_pk, p2p_pk } => Some(PeerIrohEndpoints {
                        name: peer.name.clone(),
                        api_pk,
                        p2p_pk,
                    }),
                }
                .map(|peer| (*id, peer))
            })
            .collect()
    }
}
