use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use std::{env, fs};

use anyhow::{bail, format_err};
use fedimint_aead::{encrypted_read, get_encryption_key, get_password_hash};
use fedimint_core::admin_client::{
    ConfigGenParamsConsensus, ConfigGenParamsRequest, PeerServerParams,
};
use fedimint_core::api::{ClientConfigDownloadToken, WsClientConnectInfo};
use fedimint_core::cancellable::Cancelled;
pub use fedimint_core::config::*;
use fedimint_core::config::{
    ClientConfig, ClientConfigResponse, DkgPeerMsg, FederationId, JsonWithKind, PeerUrl,
    ServerModuleConfig, ServerModuleGenRegistry, TypedServerModuleConfig,
};
use fedimint_core::core::{
    ModuleInstanceId, ModuleKind, MODULE_INSTANCE_ID_DKG_DONE, MODULE_INSTANCE_ID_GLOBAL,
};
use fedimint_core::module::registry::ServerModuleRegistry;
use fedimint_core::module::{
    ApiAuth, ApiVersion, CoreConsensusVersion, DynServerModuleGen, PeerHandle,
    SupportedApiVersionsSummary, SupportedCoreApiVersions,
};
use fedimint_core::net::peers::{IMuxPeerConnections, IPeerConnections, PeerConnections};
use fedimint_core::task::{timeout, Elapsed, TaskGroup};
use fedimint_core::{timing, PeerId};
use fedimint_logging::{LOG_NET_PEER, LOG_NET_PEER_DKG};
use hbbft::crypto::serde_impl::SerdeSecret;
use hbbft::NetworkInfo;
use itertools::Itertools;
use rand::rngs::OsRng;
use rand::Rng;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio_rustls::rustls;
use tracing::{error, info};

use crate::config::api::ConfigGenParamsLocal;
use crate::config::distributedgen::{DkgRunner, ThresholdKeys};
use crate::config::io::{parse_peer_params, CODE_VERSION, SALT_FILE, TLS_CERT, TLS_PK};
use crate::fedimint_core::encoding::Encodable;
use crate::fedimint_core::NumPeers;
use crate::multiplexed::PeerConnectionMultiplexer;
use crate::net::connect::{Connector, TlsConfig};
use crate::net::peers::{DelayCalculator, NetworkConfig};
use crate::{ReconnectPeerConnections, TlsTcpConnector};

pub mod api;
pub mod distributedgen;
pub mod io;

/// The default maximum open connections the API can handle
const DEFAULT_MAX_CLIENT_CONNECTIONS: u32 = 1000;

/// The env var for maximum open connections the API can handle
const ENV_MAX_CLIENT_CONNECTIONS: &str = "FM_MAX_CLIENT_CONNECTIONS";

/// How many times a config download token can be used by a client
const DEFAULT_CONFIG_DOWNLOAD_LIMIT: u64 = 100;

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
        modules: &ServerModuleRegistry,
    ) -> SupportedApiVersionsSummary {
        SupportedApiVersionsSummary {
            core: Self::supported_api_versions(),
            modules: modules
                .iter_modules()
                .map(|(id, _, module)| (id, module.supported_api_versions()))
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
    /// Secret key for contributing to threshold auth key
    #[serde(with = "serde_binary_human_readable")]
    pub auth_sks: SerdeSecret<hbbft::crypto::SecretKeyShare>,
    /// Secret key for contributing to HBBFT consensus
    #[serde(with = "serde_binary_human_readable")]
    pub hbbft_sks: SerdeSecret<hbbft::crypto::SecretKeyShare>,
    /// Secret key for signing consensus epochs
    #[serde(with = "serde_binary_human_readable")]
    pub epoch_sks: SerdeSecret<hbbft::crypto::SecretKeyShare>,
    /// Secret material from modules
    pub modules: BTreeMap<ModuleInstanceId, JsonWithKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encodable)]
pub struct ServerConfigConsensus {
    /// The version of the binary code running
    pub code_version: String,
    /// Agreed on core consensus version
    pub version: CoreConsensusVersion,
    /// Public keys authenticating members of the federation and the configs
    #[serde(with = "serde_binary_human_readable")]
    pub auth_pk_set: hbbft::crypto::PublicKeySet,
    /// Public keys for HBBFT consensus from all peers
    #[serde(with = "serde_binary_human_readable")]
    pub hbbft_pk_set: hbbft::crypto::PublicKeySet,
    /// Public keys for signing consensus epochs from all peers
    #[serde(with = "serde_binary_human_readable")]
    pub epoch_pk_set: hbbft::crypto::PublicKeySet,
    /// Network addresses and names for all peer APIs
    pub api_endpoints: BTreeMap<PeerId, PeerUrl>,
    /// Certs for TLS communication, required for peer authentication
    #[serde(with = "serde_tls_cert_map")]
    pub tls_certs: BTreeMap<PeerId, rustls::Certificate>,
    /// All configuration that needs to be the same for modules
    pub modules: BTreeMap<ModuleInstanceId, ServerModuleConsensusConfig>,
    #[encodable_ignore]
    /// Human readable representation of [`Self::modules`]
    pub modules_json: BTreeMap<ModuleInstanceId, JsonWithKind>,
    /// Additional config the federation wants to transmit to the clients
    pub meta: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfigLocal {
    /// Network addresses and names for all p2p connections
    pub p2p_endpoints: BTreeMap<PeerId, PeerUrl>,
    /// Our peer id (generally should not change)
    pub identity: PeerId,
    /// Our bind address for communicating with peers
    pub fed_bind: SocketAddr,
    /// Our bind address for our API endpoints
    pub api_bind: SocketAddr,
    /// How many API connections we will accept
    pub max_connections: u32,
    /// Non-consensus, non-private configuration from modules
    pub modules: BTreeMap<ModuleInstanceId, JsonWithKind>,
    /// Required to download the client config
    pub download_token: ClientConfigDownloadToken,
    /// Limit on the number of times a config download token can be used
    pub download_token_limit: Option<u64>,
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

    pub fn try_to_config_response(
        &self,
        // TODO: remove
        module_config_gens: &ServerModuleGenRegistry,
    ) -> anyhow::Result<ClientConfigResponse> {
        Ok(ClientConfigResponse {
            client_config: self.to_client_config(module_config_gens)?,
            signature: None,
        })
    }

    fn to_client_config(
        &self,
        module_config_gens: &ModuleGenRegistry<DynServerModuleGen>,
    ) -> Result<ClientConfig, anyhow::Error> {
        let client = ClientConfig {
            federation_id: FederationId(self.auth_pk_set.public_key()),
            epoch_pk: self.epoch_pk_set.public_key(),
            api_endpoints: self.api_endpoints.clone(),
            modules: self
                .modules
                .iter()
                .map(|(k, v)| {
                    let gen = module_config_gens
                        .get(&v.kind)
                        .ok_or_else(|| format_err!("Module gen kind={} not found", v.kind))?;
                    Ok((*k, gen.get_client_config(v)?))
                })
                .collect::<anyhow::Result<BTreeMap<_, _>>>()?,
            meta: self.meta.clone(),
        };
        Ok(client)
    }

    pub fn to_config_response(
        &self,
        module_config_gens: &ServerModuleGenRegistry,
    ) -> ClientConfigResponse {
        self.try_to_config_response(module_config_gens)
            .expect("configuration mismatch")
    }
}

pub const CORE_CONSENSUS_VERSION: CoreConsensusVersion = CoreConsensusVersion(0);

impl ServerConfig {
    /// Api versions supported by this server
    pub fn supported_api_versions() -> SupportedCoreApiVersions {
        SupportedCoreApiVersions {
            consensus: CORE_CONSENSUS_VERSION,
            api: vec![ApiVersion { major: 0, minor: 0 }],
        }
    }
    /// Creates a new config from the results of a trusted or distributed key
    /// setup
    pub fn from(
        params: ConfigGenParams,
        identity: PeerId,
        auth_keys: ThresholdKeys,
        epoch_keys: ThresholdKeys,
        hbbft_keys: ThresholdKeys,
        modules: BTreeMap<ModuleInstanceId, ServerModuleConfig>,
    ) -> Self {
        let private = ServerConfigPrivate {
            api_auth: params.local.api_auth.clone(),
            tls_key: params.local.our_private_key.clone(),
            auth_sks: auth_keys.secret_key_share,
            hbbft_sks: hbbft_keys.secret_key_share,
            epoch_sks: epoch_keys.secret_key_share,
            modules: Default::default(),
        };
        let local = ServerConfigLocal {
            p2p_endpoints: params.p2p_urls(),
            identity,
            fed_bind: params.local.p2p_bind,
            api_bind: params.local.api_bind,
            max_connections: DEFAULT_MAX_CLIENT_CONNECTIONS,
            modules: Default::default(),
            download_token: ClientConfigDownloadToken(OsRng.gen()),
            download_token_limit: params.local.download_token_limit,
        };
        let consensus = ServerConfigConsensus {
            code_version: CODE_VERSION.to_string(),
            version: CORE_CONSENSUS_VERSION,
            auth_pk_set: auth_keys.public_key_set,
            hbbft_pk_set: hbbft_keys.public_key_set,
            epoch_pk_set: epoch_keys.public_key_set,
            api_endpoints: params.api_urls(),
            tls_certs: params.tls_certs(),
            modules: Default::default(),
            modules_json: Default::default(),
            meta: params.consensus.requested.meta,
        };
        let mut cfg = Self {
            consensus,
            local,
            private,
        };
        cfg.add_modules(modules);
        cfg
    }

    pub fn get_connect_info(&self) -> WsClientConnectInfo {
        let id = FederationId(self.consensus.auth_pk_set.public_key());
        let url = self.consensus.api_endpoints[&self.local.identity]
            .url
            .clone();
        let download_token = self.local.download_token.clone();

        WsClientConnectInfo {
            url,
            download_token,
            id,
        }
    }

    pub fn add_modules(&mut self, modules: BTreeMap<ModuleInstanceId, ServerModuleConfig>) {
        for (name, config) in modules.into_iter() {
            let ServerModuleConfig {
                local,
                private,
                consensus,
                consensus_json,
            } = config;

            self.local.modules.insert(name, local);
            self.private.modules.insert(name, private);
            self.consensus.modules.insert(name, consensus);
            self.consensus.modules_json.insert(name, consensus_json);
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
        let consensus_json = Self::get_module_cfg_by_instance_id(&self.consensus.modules_json, id)?;
        let module = ServerModuleConfig::from(local, private, consensus, consensus_json);

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
        let consensus_json = Self::get_module_cfg_by_instance_id(&self.consensus.modules_json, id)?;
        Ok(ServerModuleConfig::from(
            local,
            private,
            consensus,
            consensus_json,
        ))
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
        module_config_gens: &ServerModuleGenRegistry,
    ) -> anyhow::Result<()> {
        let peers = self.local.p2p_endpoints.clone();
        let consensus = self.consensus.clone();
        let private = self.private.clone();
        let id = identity.to_usize();

        if private.epoch_sks.public_key_share() != consensus.epoch_pk_set.public_key_share(id) {
            bail!("Epoch private key doesn't match pubkey share");
        }
        if private.hbbft_sks.public_key_share() != consensus.hbbft_pk_set.public_key_share(id) {
            bail!("HBBFT private key doesn't match pubkey share");
        }
        if peers.keys().max().copied().map(|id| id.to_usize()) != Some(peers.len() - 1) {
            bail!("Peer ids are not indexed from 0");
        }
        if peers.keys().min().copied() != Some(PeerId::from(0)) {
            bail!("Peer ids are not indexed from 0");
        }

        for (module_id, module_kind) in self
            .consensus
            .modules
            .iter()
            .map(|(id, config)| Ok((*id, config.kind.clone())))
            .collect::<anyhow::Result<BTreeSet<_>>>()?
            .iter()
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
        registry: ServerModuleGenRegistry,
    ) -> BTreeMap<PeerId, Self> {
        let mut rng = OsRng;
        let peer0 = &params[&PeerId::from(0)];

        let netinfo = NetworkInfo::generate_map(peer0.peer_ids(), &mut rng)
            .expect("Could not generate HBBFT netinfo");
        let epochinfo = NetworkInfo::generate_map(peer0.peer_ids(), &mut rng)
            .expect("Could not generate HBBFT netinfo");
        let authinfo = NetworkInfo::generate_map(peer0.peer_ids(), &mut rng)
            .expect("Could not generate HBBFT netinfo");

        let modules = peer0.consensus.requested.modules.iter_modules();
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

        let server_config: BTreeMap<_, _> = netinfo
            .iter()
            .map(|(&id, _netinf)| {
                let config = ServerConfig::from(
                    params[&id].clone(),
                    id,
                    Self::extract_keys(authinfo.get(&id).expect("peer exists")),
                    Self::extract_keys(epochinfo.get(&id).expect("peer exists")),
                    Self::extract_keys(netinfo.get(&id).expect("peer exists")),
                    module_configs
                        .iter()
                        .map(|(module_id, cfgs)| (*module_id, cfgs[&id].clone()))
                        .collect(),
                );
                (id, config)
            })
            .collect();

        server_config
    }

    fn extract_keys(info: &NetworkInfo<PeerId>) -> ThresholdKeys {
        ThresholdKeys {
            public_key_set: info.public_key_set().clone(),
            secret_key_share: SerdeSecret(info.secret_key_share().unwrap().clone()),
        }
    }

    /// Runs the distributed key gen algorithm
    pub async fn distributed_gen(
        params: &ConfigGenParams,
        registry: ServerModuleGenRegistry,
        delay_calculator: DelayCalculator,
        task_group: &mut TaskGroup,
    ) -> DkgResult<Self> {
        let _timing /* logs on drop */ = timing::TimeReporter::new("distributed-gen").info();
        let server_conn = connect(
            params.p2p_network(),
            params.tls_config(),
            delay_calculator,
            task_group,
        )
        .await;
        let connections = PeerConnectionMultiplexer::new(server_conn).into_dyn();
        let mut rng = OsRng;

        let peers = &params.peer_ids();
        let our_id = &params.local.our_id;
        // in case we are running by ourselves, avoid DKG
        if peers.len() == 1 {
            let server =
                Self::trusted_dealer_gen(&HashMap::from([(*our_id, params.clone())]), registry);
            return Ok(server[our_id].clone());
        }
        info!(
            target: LOG_NET_PEER_DKG,
            "Peer {} running distributed key generation...", our_id
        );

        // hbbft uses a lower threshold of signing keys (f+1)
        let mut dkg = DkgRunner::new(KeyType::Hbbft, peers.one_honest(), our_id, peers);
        dkg.add(KeyType::Auth, peers.threshold());
        dkg.add(KeyType::Epoch, peers.threshold());

        // run DKG for epoch and hbbft keys
        let keys = dkg
            .run_g1(MODULE_INSTANCE_ID_GLOBAL, &connections, &mut rng)
            .await?;
        let auth_keys = keys[&KeyType::Auth].threshold_crypto();
        let hbbft_keys = keys[&KeyType::Hbbft].threshold_crypto();
        let epoch_keys = keys[&KeyType::Epoch].threshold_crypto();

        let mut module_cfgs: BTreeMap<ModuleInstanceId, ServerModuleConfig> = Default::default();
        let modules = params.consensus.requested.modules.iter_modules();
        for (module_instance_id, kind, module_params) in modules {
            let dkg = PeerHandle::new(&connections, module_instance_id, *our_id, peers.clone());
            module_cfgs.insert(
                module_instance_id,
                registry
                    .get(kind)
                    .expect("Module not registered")
                    .distributed_gen(&dkg, module_params)
                    .await?,
            );
        }

        info!(
            target: LOG_NET_PEER_DKG,
            "Sending confirmations to other peers."
        );
        // Note: Since our outgoing buffers are asynchronous, we don't actually know
        // if other peers received our message, just because we received theirs.
        // That's why we need to do a one last best effort sync.
        connections
            .send(peers, MODULE_INSTANCE_ID_DKG_DONE, DkgPeerMsg::Done)
            .await?;

        info!(
            target: LOG_NET_PEER_DKG,
            "Waiting for confirmations from other peers."
        );
        if let Err(Elapsed) = timeout(Duration::from_secs(30), async {
            let mut done_peers = BTreeSet::from([*our_id]);

            while done_peers.len() < peers.len() {
                match connections.receive(MODULE_INSTANCE_ID_DKG_DONE).await {
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
            auth_keys,
            epoch_keys,
            hbbft_keys,
            module_cfgs,
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
    Hbbft,
    Epoch,
    Auth,
}

impl ServerConfig {
    pub fn network_config(&self) -> NetworkConfig {
        NetworkConfig {
            identity: self.local.identity,
            bind_addr: self.local.fed_bind,
            peers: self
                .local
                .p2p_endpoints
                .iter()
                .map(|(&id, endpoint)| (id, endpoint.url.clone()))
                .collect(),
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
        self.consensus.peers.keys().cloned().collect()
    }

    pub fn p2p_network(&self) -> NetworkConfig {
        NetworkConfig {
            identity: self.local.our_id,
            bind_addr: self.local.p2p_bind,
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

    /// Parses from the connect strings and TLS info on the filesystem
    pub fn parse_from_connect_strings(
        bind_p2p: SocketAddr,
        bind_api: SocketAddr,
        dir_out_path: &Path,
        federation_name: String,
        certs: Vec<String>,
        password: &str,
        module_params: ServerModuleGenParamsRegistry,
    ) -> anyhow::Result<Self> {
        let mut peers = BTreeMap::<PeerId, PeerServerParams>::new();
        for (idx, cert) in certs.into_iter().sorted().enumerate() {
            peers.insert(PeerId::from(idx as u16), parse_peer_params(cert)?);
        }

        let salt = fs::read_to_string(dir_out_path.join(SALT_FILE))?;
        let api_auth = get_password_hash(password, &salt)?;
        let key = get_encryption_key(password, &salt)?;
        let tls_pk = encrypted_read(&key, dir_out_path.join(TLS_PK))?;
        let cert_string = fs::read_to_string(dir_out_path.join(TLS_CERT))?;

        let our_params = parse_peer_params(cert_string)?;
        let our_id = peers
            .iter()
            .find(|(_peer, params)| params.cert == our_params.cert)
            .map(|(peer, _)| *peer)
            .ok_or_else(|| anyhow::Error::msg("Our id not found"))?;

        Ok(ConfigGenParams::new(
            ApiAuth(api_auth),
            bind_p2p,
            bind_api,
            rustls::PrivateKey(tls_pk),
            our_id,
            peers,
            federation_name,
            Some(DEFAULT_CONFIG_DOWNLOAD_LIMIT),
            module_params,
        ))
    }

    /// Generates the parameters necessary for running server config generation
    // TODO: Move into testing once new config gen UI is written
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        api_auth: ApiAuth,
        p2p_bind: SocketAddr,
        api_bind: SocketAddr,
        our_private_key: rustls::PrivateKey,
        our_id: PeerId,
        peers: BTreeMap<PeerId, PeerServerParams>,
        federation_name: String,
        download_token_limit: Option<u64>,
        modules: ServerModuleGenParamsRegistry,
    ) -> ConfigGenParams {
        ConfigGenParams {
            local: ConfigGenParamsLocal {
                our_id,
                our_private_key,
                api_auth,
                p2p_bind,
                api_bind,
                download_token_limit,
                max_connections: max_connections(),
            },
            consensus: ConfigGenParamsConsensus {
                peers,
                requested: ConfigGenParamsRequest {
                    meta: BTreeMap::from([(META_FEDERATION_NAME_KEY.to_owned(), federation_name)]),
                    modules,
                },
            },
        }
    }
}

// TODO: Remove once new config gen UI is written
pub fn max_connections() -> u32 {
    env::var(ENV_MAX_CLIENT_CONNECTIONS)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_CLIENT_CONNECTIONS)
}

pub async fn connect<T>(
    network: NetworkConfig,
    certs: TlsConfig,
    delay_calculator: DelayCalculator,
    task_group: &mut TaskGroup,
) -> PeerConnections<T>
where
    T: std::fmt::Debug + Clone + Serialize + DeserializeOwned + Unpin + Send + Sync + 'static,
{
    let connector = TlsTcpConnector::new(certs, network.identity).into_dyn();
    ReconnectPeerConnections::new(network, delay_calculator, connector, task_group)
        .await
        .into_dyn()
}

pub fn gen_cert_and_key(
    name: &str,
) -> Result<(rustls::Certificate, rustls::PrivateKey), anyhow::Error> {
    let keypair = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let keypair_ser = keypair.serialize_der();
    let sanitized_name = name.replace(|c: char| !c.is_ascii_alphanumeric(), "_");
    let mut params = rcgen::CertificateParams::new(vec![sanitized_name.to_owned()]);

    params.key_pair = Some(keypair);
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    params.is_ca = rcgen::IsCa::NoCa;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, sanitized_name);

    let cert = rcgen::Certificate::from_params(params)?;

    Ok((
        rustls::Certificate(cert.serialize_der()?),
        rustls::PrivateKey(keypair_ser),
    ))
}

mod serde_tls_cert_map {
    use std::borrow::Cow;
    use std::collections::BTreeMap;

    use bitcoin_hashes::hex::{FromHex, ToHex};
    use fedimint_core::PeerId;
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
        for (key, value) in certs.iter() {
            serializer.serialize_key(key)?;
            let hex_str = value.0.to_hex();
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
            let cert = rustls::Certificate(Vec::from_hex(&value).map_err(D::Error::custom)?);
            certs.insert(key, cert);
        }
        Ok(certs)
    }
}

mod serde_tls_key {
    use std::borrow::Cow;

    use bitcoin_hashes::hex::{FromHex, ToHex};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use tokio_rustls::rustls;

    pub fn serialize<S>(key: &rustls::PrivateKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_str = key.0.to_hex();
        Serialize::serialize(&hex_str, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<rustls::PrivateKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str: Cow<str> = Deserialize::deserialize(deserializer)?;
        let bytes = Vec::from_hex(&hex_str).map_err(serde::de::Error::custom)?;
        Ok(rustls::PrivateKey(bytes))
    }
}
