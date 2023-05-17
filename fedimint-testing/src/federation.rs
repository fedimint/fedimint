use std::collections::{BTreeMap, HashMap};

use fedimint_client::module::gen::ClientModuleGenRegistry;
use fedimint_client::secret::PlainRootSecretStrategy;
use fedimint_client::{Client, ClientBuilder};
use fedimint_core::admin_client::{ConfigGenParamsConsensus, PeerServerParams};
use fedimint_core::api::WsClientConnectInfo;
use fedimint_core::config::{
    ServerModuleGenParamsRegistry, ServerModuleGenRegistry, META_FEDERATION_NAME_KEY,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::Database;
use fedimint_core::module::ApiAuth;
use fedimint_core::task::TaskGroup;
use fedimint_core::PeerId;
use fedimint_logging::TracingSetup;
use fedimint_server::config::api::ConfigGenParamsLocal;
use fedimint_server::config::{gen_cert_and_key, ConfigGenParams, ServerConfig};
use fedimint_server::consensus::server::ConsensusServer;
use fedimint_server::net::connect::mock::{MockNetwork, StreamReliability};
use fedimint_server::net::connect::{parse_host_port, Connector};
use fedimint_server::net::peers::DelayCalculator;
use fedimint_server::FedimintServer;
use tokio_rustls::rustls;

/// Test fixture for a running fedimint federation
pub struct FederationTest {
    configs: BTreeMap<PeerId, ServerConfig>,
    server_gen: ServerModuleGenRegistry,
    client_gen: ClientModuleGenRegistry,
    primary_client: ModuleInstanceId,
    task: TaskGroup,
}

impl FederationTest {
    /// Create two clients, useful for send/receive tests
    pub async fn two_clients(&self) -> (Client, Client) {
        (self.new_client().await, self.new_client().await)
    }

    /// Create a client connected to this fed
    pub async fn new_client(&self) -> Client {
        let client_config = self.configs[&PeerId::from(0)]
            .consensus
            .to_client_config(&self.server_gen)
            .unwrap();

        let mut client_builder = ClientBuilder::default();
        client_builder.with_module_gens(self.client_gen.clone());
        client_builder.with_primary_module(self.primary_client);
        client_builder.with_config(client_config);
        client_builder.with_database(MemDatabase::new());
        client_builder
            .build::<PlainRootSecretStrategy>(&mut self.task.make_subgroup().await)
            .await
            .expect("Failed to build client")
    }

    /// Return first connection code for gateways
    pub fn connection_code(&self) -> WsClientConnectInfo {
        self.configs[&PeerId::from(0)].get_connect_info()
    }

    pub(crate) async fn new(
        num_peers: u16,
        base_port: u16,
        params: ServerModuleGenParamsRegistry,
        server_gen: ServerModuleGenRegistry,
        client_gen: ClientModuleGenRegistry,
        primary_client: ModuleInstanceId,
    ) -> Self {
        // Ensure tracing has been set once
        let _ = TracingSetup::default().init();

        let peers = (0..num_peers).map(PeerId::from).collect::<Vec<_>>();
        let params =
            local_config_gen_params(&peers, base_port, params).expect("Generates local config");

        let configs = ServerConfig::trusted_dealer_gen(&params, server_gen.clone());
        let network = MockNetwork::new();

        let mut task = TaskGroup::new();
        for (peer_id, config) in configs.clone() {
            let reliability = StreamReliability::INTEGRATION_TEST;
            let connections = network.connector(peer_id, reliability).into_dyn();

            let instances = config.consensus.iter_module_instances();
            let decoders = server_gen.decoders(instances).unwrap();
            let db = Database::new(MemDatabase::new(), decoders);

            let server = ConsensusServer::new_with(
                config.clone(),
                db.clone(),
                server_gen.clone(),
                connections,
                DelayCalculator::TEST_DEFAULT,
                &mut task,
            )
            .await
            .expect("Failed to init server");

            let api_handle = FedimintServer::spawn_consensus_api(&server, false).await;
            task.spawn("fedimintd", move |handle| async {
                server.run_consensus(handle).await.unwrap();
                api_handle.stop().await;
            })
            .await;
        }

        Self {
            configs,
            server_gen,
            client_gen,
            primary_client,
            task,
        }
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
                status: None,
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
                    meta: BTreeMap::from([(
                        META_FEDERATION_NAME_KEY.to_owned(),
                        "federation_name".to_string(),
                    )]),
                    modules: server_config_gen.clone(),
                },
            };
            Ok((*peer, params))
        })
        .collect::<anyhow::Result<HashMap<_, _>>>()
}
