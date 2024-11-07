use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{bail, format_err};
use fedimint_core::admin_client::ConfigGenParamsConsensus;
pub use fedimint_core::config::{
    serde_binary_human_readable, ClientConfig, DkgError, DkgPeerMsg, DkgResult, FederationId,
    GlobalClientConfig, JsonWithKind, ModuleInitRegistry, PeerUrl, ServerModuleConfig,
    ServerModuleConsensusConfig, ServerModuleInitRegistry, TypedServerModuleConfig,
};
use fedimint_core::core::{ModuleInstanceId, ModuleKind, MODULE_INSTANCE_ID_GLOBAL};
use fedimint_core::envs::is_running_in_test_env;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::{
    ApiAuth, ApiVersion, CoreConsensusVersion, DynServerModuleInit, MultiApiVersion, PeerHandle,
    SupportedApiVersionsSummary, SupportedCoreApiVersions, CORE_CONSENSUS_VERSION,
};
use fedimint_core::net::peers::{IMuxPeerConnections, IPeerConnections, PeerConnections};
use fedimint_core::task::{timeout, Cancelled, Elapsed, TaskGroup};
use fedimint_core::{secp256k1, timing, PeerId};
use fedimint_logging::{LOG_NET_PEER, LOG_NET_PEER_DKG};
use futures::future::join_all;
use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio_rustls::rustls;
use tracing::{error, info};

use crate::config::api::ConfigGenParamsLocal;
use crate::config::distributedgen::{DkgRunner, PeerHandleOps};
use crate::envs::FM_MAX_CLIENT_CONNECTIONS_ENV;
use crate::fedimint_core::encoding::Encodable;
use crate::fedimint_core::NumPeersExt;
use crate::multiplexed::PeerConnectionMultiplexer;
use crate::net::connect::{dns_sanitize, Connector, TlsConfig};
use crate::net::peers::{DelayCalculator, NetworkConfig};
use crate::net::peers_reliable::ReconnectPeerConnectionsReliable;
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
            api: MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 4 }])
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
        FederationId(self.consensus.api_endpoints.consensus_hash_bitcoin30())
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
        delay_calculator: DelayCalculator,
        task_group: &TaskGroup,
        code_version_str: String,
    ) -> DkgResult<Self> {
        let _timing /* logs on drop */ = timing::TimeReporter::new("distributed-gen").info();
        let server_conn = connect(
            params.p2p_network(p2p_bind_addr),
            params.tls_config(),
            delay_calculator,
            task_group,
        )
        .await;
        let connections = PeerConnectionMultiplexer::new(server_conn).into_dyn();

        let peers = &params.peer_ids();
        let our_id = &params.local.our_id;

        let broadcast_keys_exchange = PeerHandle::new(
            &connections,
            MODULE_INSTANCE_ID_GLOBAL,
            *our_id,
            peers.clone(),
        );

        let (broadcast_sk, broadcast_pk) = secp256k1::generate_keypair(&mut OsRng);

        let broadcast_public_keys = broadcast_keys_exchange
            .exchange_pubkeys("broadcast".to_string(), broadcast_pk)
            .await?;

        // in case we are running by ourselves, avoid DKG
        if peers.len() == 1 {
            let server = Self::trusted_dealer_gen(
                &HashMap::from([(*our_id, params.clone())]),
                &registry,
                &code_version_str,
            );
            return Ok(server[our_id].clone());
        }
        info!(
            target: LOG_NET_PEER_DKG,
            "Peer {} running distributed key generation...", our_id
        );

        // BFT uses a lower threshold of signing keys (f+1)
        let mut dkg = DkgRunner::new(
            KeyType::Bft,
            peers.to_num_peers().one_honest(),
            our_id,
            peers,
        );
        dkg.add(KeyType::Auth, peers.to_num_peers().threshold());
        dkg.add(KeyType::Epoch, peers.to_num_peers().threshold());

        let mut registered_modules = registry.kinds();
        let mut module_cfgs: BTreeMap<ModuleInstanceId, ServerModuleConfig> = BTreeMap::new();
        let modules = params.consensus.modules.iter_modules();
        let modules_runner = modules.map(|(module_instance_id, kind, module_params)| {
            let dkg = PeerHandle::new(&connections, module_instance_id, *our_id, peers.clone());
            let registry = registry.clone();

            async move {
                let result = match registry.get(kind) {
                    None => Err(DkgError::ModuleNotFound(kind.clone())),
                    Some(gen) => gen.distributed_gen(&dkg, module_params).await,
                };
                (module_instance_id, result)
            }
        });
        for (module_instance_id, config) in join_all(modules_runner).await {
            let config = config?;
            registered_modules.remove(&config.consensus.kind);
            module_cfgs.insert(module_instance_id, config);
        }
        if !registered_modules.is_empty() {
            return Err(DkgError::ParamsNotFound(registered_modules));
        }

        info!(
            target: LOG_NET_PEER_DKG,
            "Sending confirmations to other peers."
        );
        // Note: Since our outgoing buffers are asynchronous, we don't actually know
        // if other peers received our message, just because we received theirs.
        // That's why we need to do a one last best effort sync.
        let dkg_done = "DKG DONE".to_string();
        connections
            .send(
                peers,
                (MODULE_INSTANCE_ID_GLOBAL, dkg_done.clone()),
                DkgPeerMsg::Done,
            )
            .await?;

        info!(
            target: LOG_NET_PEER_DKG,
            "Waiting for confirmations from other peers."
        );
        if let Err(Elapsed) = timeout(Duration::from_secs(30), async {
            let mut done_peers = BTreeSet::from([*our_id]);

            while done_peers.len() < peers.len() {
                match connections.receive((MODULE_INSTANCE_ID_GLOBAL, dkg_done.clone())).await {
                    Ok((peer_id, DkgPeerMsg::Done)) => {
                        info!(
                            target: LOG_NET_PEER_DKG,
                            pper_id = %peer_id, "Got completion confirmation");
                        done_peers.insert(peer_id);
                    },
                    Ok((peer_id, msg)) => {
                        error!(target: LOG_NET_PEER_DKG, %peer_id, ?msg, "Received incorrect message after dkg was supposed to be finished. Probably dkg multiplexing bug.");
                    },
                    Err(Cancelled) => {/* ignore shutdown for time being, we'll timeout soon anyway */},
                }
            }
        })
        .await
        {
            error!(target: LOG_NET_PEER_DKG, "Timeout waiting for dkg completion confirmation from other peers");
        };

        let server = ServerConfig::from(
            params.clone(),
            *our_id,
            broadcast_public_keys,
            broadcast_sk,
            module_cfgs,
            code_version_str,
        );

        info!(
            target: LOG_NET_PEER,
            "Distributed key generation has completed successfully!"
        );

        Ok(server)
    }
}

/// The types of keys to run distributed key generation for
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum KeyType {
    Bft,
    Epoch,
    Auth,
}

impl ServerConfig {
    pub fn network_config(&self, p2p_bind_addr: SocketAddr) -> NetworkConfig {
        NetworkConfig {
            identity: self.local.identity,
            peers: self
                .local
                .p2p_endpoints
                .iter()
                .map(|(&id, endpoint)| (id, endpoint.url.clone()))
                .collect(),
            p2p_bind_addr,
        }
    }

    pub fn tls_config(&self) -> TlsConfig {
        TlsConfig {
            our_private_key: self.private.tls_key.clone(),
            peer_certs: self.consensus.tls_certs.clone(),
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

    pub fn p2p_network(&self, p2p_bind_addr: SocketAddr) -> NetworkConfig {
        NetworkConfig {
            identity: self.local.our_id,
            p2p_bind_addr,
            peers: self
                .p2p_urls()
                .into_iter()
                .map(|(id, peer)| (id, peer.url))
                .collect(),
        }
    }

    pub fn tls_config(&self) -> TlsConfig {
        TlsConfig {
            our_private_key: self.local.our_private_key.clone(),
            peer_certs: self.tls_certs(),
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

pub async fn connect<T>(
    network: NetworkConfig,
    certs: TlsConfig,
    delay_calculator: DelayCalculator,
    task_group: &TaskGroup,
) -> PeerConnections<T>
where
    T: std::fmt::Debug + Clone + Serialize + DeserializeOwned + Unpin + Send + Sync + 'static,
{
    let connector = TlsTcpConnector::new(certs, network.identity).into_dyn();
    let (connections, _) =
        ReconnectPeerConnectionsReliable::new(network, delay_calculator, connector, task_group)
            .await;
    connections.into_dyn()
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
