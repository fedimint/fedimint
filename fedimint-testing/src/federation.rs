use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU16, Ordering};

use fedimint_client::module::gen::{ClientModuleGenRegistry, DynClientModuleGen, IClientModuleGen};
use fedimint_client::{Client, ClientBuilder};
use fedimint_core::admin_client::{
    ConfigGenParamsConsensus, ConfigGenParamsRequest, PeerServerParams,
};
use fedimint_core::config::{
    ModuleGenParams, ServerModuleGenParamsRegistry, ServerModuleGenRegistry,
    META_FEDERATION_NAME_KEY,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::Database;
use fedimint_core::module::{ApiAuth, DynServerModuleGen, IServerModuleGen};
use fedimint_core::task::{MaybeSend, MaybeSync, TaskGroup};
use fedimint_core::PeerId;
use fedimint_server::config::api::ConfigGenParamsLocal;
use fedimint_server::config::{gen_cert_and_key, ConfigGenParams, ServerConfig};
use fedimint_server::consensus::server::ConsensusServer;
use fedimint_server::net::connect::mock::{MockNetwork, StreamReliability};
use fedimint_server::net::connect::{parse_host_port, Connector};
use fedimint_server::net::peers::DelayCalculator;
use fedimint_server::{FedimintApiHandler, FedimintServer};
use tokio_rustls::rustls;

// Offset from the normal port by 30000 to avoid collisions
static BASE_PORT: AtomicU16 = AtomicU16::new(38173);

/// Constructs the FederationTest and Clients
#[derive(Default)]
pub struct FederationFixture {
    num_peers: u16,
    ids: Vec<ModuleInstanceId>,
    clients: Vec<DynClientModuleGen>,
    servers: Vec<DynServerModuleGen>,
    params: ServerModuleGenParamsRegistry,
    primary_client: ModuleInstanceId,
}

impl FederationFixture {
    pub fn new_with_peers(num_peers: u16) -> Self {
        Self {
            num_peers,
            ..Default::default()
        }
    }

    /// Add a module to the federation
    pub fn with_module(
        mut self,
        id: ModuleInstanceId,
        client: impl IClientModuleGen + MaybeSend + MaybeSync + 'static,
        server: impl IServerModuleGen + MaybeSend + MaybeSync + 'static,
        params: impl ModuleGenParams,
    ) -> Self {
        self.params
            .attach_config_gen_params(server.module_kind(), params);
        self.ids.push(id);
        self.clients.push(DynClientModuleGen::from(client));
        self.servers.push(DynServerModuleGen::from(server));
        self
    }

    /// Set the primary client module
    pub fn with_primary_module(mut self, id: ModuleInstanceId) -> Self {
        self.primary_client = id;
        self
    }

    pub(crate) fn build(&mut self, task: TaskGroup) -> FederationTest {
        // Enough ports to not have collisions with other tests
        let base_port = BASE_PORT.fetch_add(self.num_peers * 10, Ordering::Relaxed);
        let peers = (0..self.num_peers).map(PeerId::from).collect::<Vec<_>>();
        let params = local_config_gen_params(&peers, base_port, self.params.clone())
            .expect("Generates local config");

        // TODO: refactor constructors to make this easier
        let mut instances = BTreeMap::new();
        for i in 0..self.servers.len() {
            let kind = self.servers[i].as_ref().module_kind();
            instances.insert(self.ids[i], (kind, self.servers[i].clone()));
        }
        let configs = ServerConfig::trusted_dealer_gen(&params, instances);
        FederationTest {
            configs,
            server_gen: ServerModuleGenRegistry::from(self.servers.clone()),
            client_gen: ClientModuleGenRegistry::from(self.clients.clone()),
            primary_client: self.primary_client,
            task,
        }
    }
}

/// Test fixture for running a fedimint federation
pub struct FederationTest {
    configs: BTreeMap<PeerId, ServerConfig>,
    server_gen: ServerModuleGenRegistry,
    client_gen: ClientModuleGenRegistry,
    primary_client: ModuleInstanceId,
    task: TaskGroup,
}

impl FederationTest {
    pub async fn new_client(&self) -> Client {
        let client_config = self.configs[&PeerId::from(0)]
            .consensus
            .to_config_response(&self.server_gen)
            .client_config;

        let mut client_builder = ClientBuilder::default();
        client_builder.with_module_gens(self.client_gen.clone());
        client_builder.with_primary_module(self.primary_client);
        client_builder.with_config(client_config);
        client_builder.with_database(MemDatabase::new());
        client_builder
            .build(&mut self.task.make_subgroup().await)
            .await
            .expect("Failed to build client")
    }

    /// Spawns federation consensus servers and APIs
    pub(crate) async fn start(&mut self) -> (Vec<ConsensusServer>, Vec<FedimintApiHandler>) {
        let mut servers = vec![];
        let mut handles = vec![];
        let network = MockNetwork::new();

        for (peer_id, config) in self.configs.clone() {
            let reliability = StreamReliability::INTEGRATION_TEST;
            let connections = network.connector(peer_id, reliability).into_dyn();

            let instances = config.consensus.iter_module_instances();
            let decoders = self.server_gen.decoders(instances).unwrap();
            let db = Database::new(MemDatabase::new(), decoders);

            let server = ConsensusServer::new_with(
                config.clone(),
                db.clone(),
                self.server_gen.clone(),
                connections,
                DelayCalculator::TEST_DEFAULT,
                &mut self.task,
            )
            .await
            .expect("Failed to init server");

            let api_handle = FedimintServer::spawn_consensus_api(&server).await;
            handles.push(api_handle);
            servers.push(server);
        }
        (servers, handles)
    }
}

/// Creates the config gen params for each peer
///
/// Uses peers * 2 ports offset from `base_port`
fn local_config_gen_params(
    peers: &[PeerId],
    base_port: u16,
    server_config_gen: ServerModuleGenParamsRegistry,
) -> anyhow::Result<HashMap<PeerId, ConfigGenParams>> {
    // Generate TLS cert and private key
    let tls_keys: HashMap<PeerId, (rustls::Certificate, rustls::PrivateKey)> = peers
        .iter()
        .map(|peer| {
            (
                *peer,
                gen_cert_and_key(&format!("peer-{}", peer.to_usize())).unwrap(),
            )
        })
        .collect();

    // Generate the P2P and API URL on 2 different ports for each peer
    let connections: BTreeMap<PeerId, PeerServerParams> = peers
        .iter()
        .map(|peer| {
            let peer_port = base_port + u16::from(*peer) * 2;
            let p2p_url = format!("ws://127.0.0.1:{peer_port}");
            let api_url = format!("ws://127.0.0.1:{}", peer_port + 1);

            let params: PeerServerParams = PeerServerParams {
                cert: tls_keys[peer].0.clone(),
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
            let p2p_bind = parse_host_port(connections[peer].clone().p2p_url)?;
            let api_bind = parse_host_port(connections[peer].clone().api_url)?;

            let params = ConfigGenParams {
                local: ConfigGenParamsLocal {
                    our_id: *peer,
                    our_private_key: tls_keys[peer].1.clone(),
                    api_auth: ApiAuth("unused".to_string()),
                    p2p_bind: p2p_bind.parse().expect("Valid address"),
                    api_bind: api_bind.parse().expect("Valid address"),
                    download_token_limit: None,
                    max_connections: 10,
                },
                consensus: ConfigGenParamsConsensus {
                    peers: connections.clone(),
                    requested: ConfigGenParamsRequest {
                        meta: BTreeMap::from([(
                            META_FEDERATION_NAME_KEY.to_owned(),
                            "federation_name".to_string(),
                        )]),
                        modules: server_config_gen.clone(),
                    },
                },
            };
            Ok((*peer, params))
        })
        .collect::<anyhow::Result<HashMap<_, _>>>()
}
