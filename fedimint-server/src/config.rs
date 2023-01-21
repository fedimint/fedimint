use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{bail, format_err};
use bitcoin::hashes::sha256;
use bitcoin::hashes::sha256::HashEngine;
use fedimint_api::cancellable::{Cancellable, Cancelled};
use fedimint_api::config::{
    ApiEndpoint, ClientConfig, ConfigGenParams, ConfigResponse, DkgPeerMsg, DkgRunner,
    FederationId, JsonWithKind, ModuleConfigResponse, ModuleGenRegistry, ServerModuleConfig,
    ThresholdKeys, TypedServerModuleConfig,
};
use fedimint_api::core::{ModuleInstanceId, ModuleKind, MODULE_INSTANCE_ID_GLOBAL};
use fedimint_api::net::peers::{IPeerConnections, MuxPeerConnections, PeerConnections};
use fedimint_api::task::{timeout, Elapsed, TaskGroup};
use fedimint_api::{Amount, PeerId};
pub use fedimint_core::config::*;
use fedimint_core::modules::mint::MintGenParams;
use fedimint_wallet::WalletGenParams;
use hbbft::crypto::serde_impl::SerdeSecret;
use hbbft::NetworkInfo;
use rand::{CryptoRng, RngCore};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio_rustls::rustls;
use tracing::{error, info};
use url::Url;

use crate::fedimint_api::encoding::Encodable;
use crate::fedimint_api::BitcoinHash;
use crate::fedimint_api::NumPeers;
use crate::net::connect::TlsConfig;
use crate::net::connect::{parse_host_port, Connector};
use crate::net::peers::NetworkConfig;
use crate::{ReconnectPeerConnections, TlsTcpConnector};

/// The maximum open connections the API can handle
const DEFAULT_MAX_CLIENT_CONNECTIONS: u32 = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// All the serializable configuration for the fedimint server
pub struct ServerConfig {
    /// Contains all configuration that needs to be the same for every server
    pub consensus: ServerConfigConsensus,
    /// Contains all configuration that is locally configurable and not secret
    pub local: ServerConfigLocal,
    /// Contains all configuration that will be encrypted such as private key material
    pub private: ServerConfigPrivate,
}

impl ServerConfig {
    pub fn iter_module_instances(
        &self,
    ) -> impl Iterator<Item = (ModuleInstanceId, &ModuleKind)> + '_ {
        self.consensus.iter_module_instances()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfigPrivate {
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
    /// Configurable federation name
    pub federation_name: String,
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
    pub api: BTreeMap<PeerId, ApiEndpoint>,
    /// All configuration that needs to be the same for modules
    #[encodable_ignore]
    pub modules: BTreeMap<ModuleInstanceId, JsonWithKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfigLocal {
    /// Network addresses and certs for all p2p connections
    pub p2p: BTreeMap<PeerId, PeerEndpoint>,
    /// Our peer id (generally should not change)
    pub identity: PeerId,
    /// Our bind address for communicating with peers
    pub fed_bind: SocketAddr,
    /// Our bind address for our API endpoints
    pub api_bind: SocketAddr,
    /// Our publicly known TLS cert
    #[serde(with = "serde_tls_cert")]
    pub tls_cert: rustls::Certificate,
    /// How many API connections we will accept
    pub max_connections: u32,
    /// Non-consensus, non-private configuration from modules
    pub modules: BTreeMap<ModuleInstanceId, JsonWithKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEndpoint {
    /// Certs for TLS communication, required for peer authentication
    #[serde(with = "serde_tls_cert")]
    pub tls_cert: rustls::Certificate,
    /// The TLS network address and port, used for HBBFT consensus
    pub hbbft: Url,
}

#[derive(Debug, Clone)]
/// network config for a server
pub struct ServerConfigParams {
    pub tls: TlsConfig,
    pub fed_network: NetworkConfig,
    pub api_network: NetworkConfig,
    pub federation_name: String,

    /// extra options for extra settings and modules
    pub modules: ConfigGenParams,
}

impl ServerConfigConsensus {
    pub fn iter_module_instances(
        &self,
    ) -> impl Iterator<Item = (ModuleInstanceId, &ModuleKind)> + '_ {
        self.modules.iter().map(|(k, v)| (*k, v.kind()))
    }

    /// encodes the fields into a sha256 hash for comparison
    /// TODO use the derive macro to automatically pick up new fields here
    fn try_to_config_response(
        &self,
        module_config_gens: &ModuleGenRegistry,
    ) -> anyhow::Result<ConfigResponse> {
        let modules: BTreeMap<ModuleInstanceId, ModuleConfigResponse> = self
            .modules
            .iter()
            .map(|(module_instance_id, v)| {
                let kind = v.kind();
                Ok((
                    *module_instance_id,
                    module_config_gens
                        .get(kind)
                        .ok_or_else(|| format_err!("module config gen not found: {kind}"))?
                        .to_config_response(v.value().clone())?,
                ))
            })
            .collect::<anyhow::Result<_>>()?;

        let mut engine = HashEngine::default();
        self.consensus_encode(&mut engine)?;
        for (k, v) in modules.iter() {
            k.consensus_encode(&mut engine)?;
            v.consensus_hash.consensus_encode(&mut engine)?;
        }
        let consensus_hash = sha256::Hash::from_engine(engine);

        let client = ClientConfig {
            federation_name: self.federation_name.clone(),
            federation_id: FederationId(self.auth_pk_set.public_key()),
            epoch_pk: self.epoch_pk_set.public_key(),
            nodes: self.api.values().cloned().collect(),
            modules: modules.into_iter().map(|(k, v)| (k, v.client)).collect(),
        };

        Ok(ConfigResponse {
            client,
            consensus_hash,
        })
    }

    pub fn to_config_response(&self, module_config_gens: &ModuleGenRegistry) -> ConfigResponse {
        self.try_to_config_response(module_config_gens)
            .expect("configuration mismatch")
    }
}

impl ServerConfig {
    /// Creates a new config from the results of a trusted or distributed key setup
    #[allow(clippy::too_many_arguments)]
    pub fn from(
        code_version: &str,
        params: ServerConfigParams,
        identity: PeerId,
        auth_keys: ThresholdKeys,
        epoch_keys: ThresholdKeys,
        hbbft_keys: ThresholdKeys,
        modules: BTreeMap<ModuleInstanceId, ServerModuleConfig>,
    ) -> Self {
        let private = ServerConfigPrivate {
            tls_key: params.tls.our_private_key.clone(),
            auth_sks: auth_keys.secret_key_share,
            hbbft_sks: hbbft_keys.secret_key_share,
            epoch_sks: epoch_keys.secret_key_share,
            modules: Default::default(),
        };
        let local = ServerConfigLocal {
            p2p: params.peers(),
            identity,
            fed_bind: params.fed_network.bind_addr,
            api_bind: params.api_network.bind_addr,
            tls_cert: params.tls.our_certificate.clone(),
            max_connections: DEFAULT_MAX_CLIENT_CONNECTIONS,
            modules: Default::default(),
        };
        let consensus = ServerConfigConsensus {
            code_version: code_version.to_string(),
            federation_name: params.federation_name.clone(),
            auth_pk_set: auth_keys.public_key_set,
            hbbft_pk_set: hbbft_keys.public_key_set,
            epoch_pk_set: epoch_keys.public_key_set,
            api: params.api_nodes(),
            modules: Default::default(),
        };
        let mut cfg = Self {
            consensus,
            local,
            private,
        };
        cfg.add_modules(modules);
        cfg
    }

    pub fn add_modules(&mut self, modules: BTreeMap<ModuleInstanceId, ServerModuleConfig>) {
        for (name, config) in modules.into_iter() {
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
        let consensus = Self::get_module_cfg_by_instance_id(&self.consensus.modules, id)?;
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
            .find(|(_, v)| v.is_kind(&kind))
            .ok_or_else(|| format_err!("Module {kind} not found"))?
            .0)
    }

    /// Constructs a module config by name
    pub fn get_module_config(&self, id: ModuleInstanceId) -> anyhow::Result<ServerModuleConfig> {
        let local = Self::get_module_cfg_by_instance_id(&self.local.modules, id)?;
        let private = Self::get_module_cfg_by_instance_id(&self.private.modules, id)?;
        let consensus = Self::get_module_cfg_by_instance_id(&self.consensus.modules, id)?;
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
        module_config_gens: &ModuleGenRegistry,
    ) -> anyhow::Result<()> {
        let peers = self.local.p2p.clone();
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
            .map(|(id, config)| Ok((*id, config.kind())))
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

    #[allow(clippy::too_many_arguments)]
    pub fn trusted_dealer_gen(
        code_version: &str,
        peers: &[PeerId],
        params: &HashMap<PeerId, ServerConfigParams>,
        module_config_gens: ModuleGenRegistry,
        mut rng: impl RngCore + CryptoRng,
    ) -> BTreeMap<PeerId, Self> {
        let netinfo = NetworkInfo::generate_map(peers.to_vec(), &mut rng)
            .expect("Could not generate HBBFT netinfo");
        let epochinfo = NetworkInfo::generate_map(peers.to_vec(), &mut rng)
            .expect("Could not generate HBBFT netinfo");
        let authinfo = NetworkInfo::generate_map(peers.to_vec(), &mut rng)
            .expect("Could not generate HBBFT netinfo");

        let peer0 = &params[&PeerId::from(0)];

        // We assume user wants one module instance for every module kind
        let module_configs: BTreeMap<_, _> = module_config_gens
            .legacy_init_order_iter()
            .enumerate()
            .map(|(module_id, (_kind, gen))| {
                (
                    u16::try_from(module_id).expect("Can't fail"),
                    gen.trusted_dealer_gen(peers, &peer0.modules),
                )
            })
            .collect();

        let server_config: BTreeMap<_, _> = netinfo
            .iter()
            .map(|(&id, _netinf)| {
                let config = ServerConfig::from(
                    code_version,
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

    #[allow(clippy::too_many_arguments)]
    pub async fn distributed_gen(
        code_version: &str,
        connections: &MuxPeerConnections<ModuleInstanceId, DkgPeerMsg>,
        our_id: &PeerId,
        peers: &[PeerId],
        params: &ServerConfigParams,
        module_config_gens: ModuleGenRegistry,
        mut rng: impl RngCore + CryptoRng,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<Cancellable<Self>> {
        // in case we are running by ourselves, avoid DKG
        if peers.len() == 1 {
            let server = Self::trusted_dealer_gen(
                code_version,
                peers,
                &HashMap::from([(*our_id, params.clone())]),
                module_config_gens,
                rng,
            );
            return Ok(Ok(server[our_id].clone()));
        }
        info!("Peer {} running distributed key generation...", our_id);

        // hbbft uses a lower threshold of signing keys (f+1)
        let mut dkg = DkgRunner::new(KeyType::Hbbft, peers.one_honest(), our_id, peers);
        dkg.add(KeyType::Auth, peers.threshold());
        dkg.add(KeyType::Epoch, peers.threshold());

        // run DKG for epoch and hbbft keys
        let keys = if let Ok(v) = dkg
            .run_g1(MODULE_INSTANCE_ID_GLOBAL, connections, &mut rng)
            .await
        {
            v
        } else {
            return Ok(Err(Cancelled));
        };
        let auth_keys = keys[&KeyType::Auth].threshold_crypto();
        let hbbft_keys = keys[&KeyType::Hbbft].threshold_crypto();
        let epoch_keys = keys[&KeyType::Epoch].threshold_crypto();

        let mut module_cfgs: BTreeMap<ModuleInstanceId, ServerModuleConfig> = Default::default();

        // NOTE: Currently we do not implement user-assisted module-kind to module-instance-id assignment
        // We assume that user wants one instance of each module that was compiled in. This is how
        // things were initially, where we consider "module as a code" as "module as an instance at runtime"
        for (module_instance_id, (_kind, gen)) in
            module_config_gens.legacy_init_order_iter().enumerate()
        {
            let module_instance_id = u16::try_from(module_instance_id)
                .expect("64k module instances should be enough for everyone");
            module_cfgs.insert(
                module_instance_id,
                if let Ok(cfgs) = gen
                    .distributed_gen(
                        connections,
                        our_id,
                        module_instance_id,
                        peers,
                        &params.modules,
                        task_group,
                    )
                    .await?
                {
                    cfgs
                } else {
                    return Ok(Err(Cancelled));
                },
            );
        }

        info!("Sending confirmations to other peers.");
        // Note: Since our outgoing buffers are asynchronous, we don't actually know
        // if other peers received our message, just because we received theirs.
        // That's why we need to do a one last best effort sync.
        connections
            .send(peers, MODULE_INSTANCE_ID_GLOBAL, DkgPeerMsg::Done)
            .await?;

        info!("Waiting for confirmations from other peers.");
        if let Err(Elapsed) = timeout(Duration::from_secs(30), async {
            let mut done_peers = BTreeSet::from([*our_id]);

            while done_peers.len() < peers.len() {
                match connections.receive(MODULE_INSTANCE_ID_GLOBAL).await {
                    Ok((peer_id, DkgPeerMsg::Done)) => {
                        info!(%peer_id, "Got completion confirmation");
                        done_peers.insert(peer_id);
                    },
                    Ok((peer_id, msg)) => {
                        error!(%peer_id, ?msg, "Received incorrect message after dkg was supposed to be finished. Probably dkg multiplexing bug.");
                    },
                    Err(Cancelled) => {/* ignore shutdown for time being, we'll timeout soon anyway */},
                }
            }
        })
        .await
        {
            error!("Timeout waiting for dkg completion confirmation from other peers");
        };

        let server = ServerConfig::from(
            code_version,
            params.clone(),
            *our_id,
            auth_keys,
            epoch_keys,
            hbbft_keys,
            module_cfgs,
        );

        info!("Distributed key generation has completed successfully!");

        Ok(Ok(server))
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
                .p2p
                .iter()
                .map(|(&id, peer)| (id, peer.hbbft.clone()))
                .collect(),
        }
    }

    pub fn tls_config(&self) -> TlsConfig {
        TlsConfig {
            our_certificate: self.local.tls_cert.clone(),
            our_private_key: self.private.tls_key.clone(),
            peer_certs: self
                .local
                .p2p
                .iter()
                .map(|(peer, cfg)| (*peer, cfg.tls_cert.clone()))
                .collect(),
            peer_names: self
                .consensus
                .api
                .iter()
                .map(|(peer, cfg)| (*peer, cfg.name.to_string()))
                .collect(),
        }
    }

    pub fn get_incoming_count(&self) -> u16 {
        self.local.identity.into()
    }
}

#[derive(Clone)]
pub struct PeerServerParams {
    pub cert: rustls::Certificate,
    pub p2p_url: Url,
    pub api_url: Url,
    pub name: String,
}

impl ServerConfigParams {
    /// Generates denominations as powers of 2 until a `max`
    pub fn gen_denominations(max: Amount) -> Vec<Amount> {
        let mut amounts = vec![];

        let mut denomination = Amount::from_msats(1);
        while denomination < max {
            amounts.push(denomination);
            denomination = denomination * 2;
        }

        amounts
    }

    pub fn peers(&self) -> BTreeMap<PeerId, PeerEndpoint> {
        self.fed_network
            .peers
            .iter()
            .map(|(peer, hbbft)| {
                (
                    *peer,
                    PeerEndpoint {
                        tls_cert: self.tls.peer_certs[peer].clone(),
                        hbbft: hbbft.clone(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>()
    }

    pub fn api_nodes(&self) -> BTreeMap<PeerId, ApiEndpoint> {
        self.fed_network
            .peers
            .keys()
            .map(|peer| {
                (
                    *peer,
                    ApiEndpoint {
                        name: self.tls.peer_names[peer].clone(),
                        url: self.api_network.peers[peer].clone(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>()
    }

    /// Generates the parameters necessary for running server config generation
    #[allow(clippy::too_many_arguments)]
    pub fn gen_params(
        bind_p2p: SocketAddr,
        bind_api: SocketAddr,
        key: rustls::PrivateKey,
        our_id: PeerId,
        max_denomination: Amount,
        peers: &BTreeMap<PeerId, PeerServerParams>,
        federation_name: String,
        network: bitcoin::network::constants::Network,
        finality_delay: u32,
    ) -> ServerConfigParams {
        let peer_certs: HashMap<PeerId, rustls::Certificate> = peers
            .iter()
            .map(|(peer, params)| (*peer, params.cert.clone()))
            .collect::<HashMap<_, _>>();

        let peer_names: HashMap<PeerId, String> = peers
            .iter()
            .map(|(peer, params)| (*peer, params.name.to_string()))
            .collect::<HashMap<_, _>>();

        let tls = TlsConfig {
            our_certificate: peers[&our_id].cert.clone(),
            our_private_key: key,
            peer_certs,
            peer_names,
        };

        ServerConfigParams {
            tls,
            fed_network: Self::gen_network(&bind_p2p, &our_id, peers, |params| params.p2p_url),
            api_network: Self::gen_network(&bind_api, &our_id, peers, |params| params.api_url),
            federation_name,
            modules: ConfigGenParams::new()
                .attach(WalletGenParams {
                    network,
                    // TODO this is not very elegant, but I'm planning to get rid of it in a next commit anyway
                    finality_delay,
                })
                .attach(MintGenParams {
                    mint_amounts: ServerConfigParams::gen_denominations(max_denomination),
                }),
        }
    }

    fn gen_network(
        bind_address: &SocketAddr,
        our_id: &PeerId,
        peers: &BTreeMap<PeerId, PeerServerParams>,
        extract_url: impl Fn(PeerServerParams) -> Url,
    ) -> NetworkConfig {
        NetworkConfig {
            identity: *our_id,
            bind_addr: *bind_address,
            peers: peers
                .iter()
                .map(|(peer, params)| {
                    let url = extract_url(params.clone());
                    (*peer, url)
                })
                .collect(),
        }
    }

    /// config for servers running on different ports on a local network
    pub fn gen_local(
        peers: &[PeerId],
        max_denomination: Amount,
        base_port: u16,
        federation_name: &str,
    ) -> HashMap<PeerId, ServerConfigParams> {
        let keys: HashMap<PeerId, (rustls::Certificate, rustls::PrivateKey)> = peers
            .iter()
            .map(|peer| {
                let (cert, key) = gen_cert_and_key(&format!("peer-{}", peer.to_usize())).unwrap();
                (*peer, (cert, key))
            })
            .collect::<HashMap<_, _>>();

        let peer_params: BTreeMap<PeerId, PeerServerParams> = peers
            .iter()
            .map(|peer| {
                let peer_port = base_port + u16::from(*peer) * 10;
                let p2p_url = format!("ws://127.0.0.1:{}", peer_port);
                let api_url = format!("ws://127.0.0.1:{}", peer_port + 1);

                let params: PeerServerParams = PeerServerParams {
                    cert: keys[peer].0.clone(),
                    p2p_url: p2p_url.parse().expect("Should parse"),
                    api_url: api_url.parse().expect("Should parse"),
                    name: format!("peer-{}", peer.to_usize()),
                };
                (*peer, params)
            })
            .collect();

        peers
            .iter()
            .map(|peer| {
                let bind_p2p = parse_host_port(peer_params[peer].clone().p2p_url);
                let bind_api = parse_host_port(peer_params[peer].clone().api_url);

                let params: ServerConfigParams = Self::gen_params(
                    bind_p2p.parse().expect("Should parse"),
                    bind_api.parse().expect("Should parse"),
                    keys[peer].1.clone(),
                    *peer,
                    max_denomination,
                    &peer_params,
                    federation_name.to_string(),
                    bitcoin::network::constants::Network::Regtest,
                    10,
                );
                (*peer, params)
            })
            .collect()
    }
}

pub async fn connect<T>(
    network: NetworkConfig,
    certs: TlsConfig,
    task_group: &mut TaskGroup,
) -> PeerConnections<T>
where
    T: std::fmt::Debug + Clone + Serialize + DeserializeOwned + Unpin + Send + Sync + 'static,
{
    let connector = TlsTcpConnector::new(certs).into_dyn();
    ReconnectPeerConnections::new(network, connector, task_group)
        .await
        .into_dyn()
}

pub fn gen_cert_and_key(
    name: &str,
) -> Result<(rustls::Certificate, rustls::PrivateKey), anyhow::Error> {
    let keypair = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let keypair_ser = keypair.serialize_der();
    let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]);

    params.key_pair = Some(keypair);
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    params.is_ca = rcgen::IsCa::NoCa;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);

    let cert = rcgen::Certificate::from_params(params)?;

    Ok((
        rustls::Certificate(cert.serialize_der()?),
        rustls::PrivateKey(keypair_ser),
    ))
}

mod serde_tls_cert {
    use std::borrow::Cow;

    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use tokio_rustls::rustls;

    pub fn serialize<S>(cert: &rustls::Certificate, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_str = hex::encode(&cert.0);
        Serialize::serialize(&hex_str, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<rustls::Certificate, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str: Cow<str> = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(hex_str.as_ref()).map_err(|_e| D::Error::custom("Invalid hex"))?;
        Ok(rustls::Certificate(bytes))
    }
}

mod serde_tls_key {
    use std::borrow::Cow;

    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use tokio_rustls::rustls;

    pub fn serialize<S>(key: &rustls::PrivateKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_str = hex::encode(&key.0);
        Serialize::serialize(&hex_str, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<rustls::PrivateKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str: Cow<str> = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(hex_str.as_ref()).map_err(|_e| D::Error::custom("Invalid hex"))?;
        Ok(rustls::PrivateKey(bytes))
    }
}
