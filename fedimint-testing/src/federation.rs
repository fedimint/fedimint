use std::collections::{BTreeMap, HashMap};

use fedimint_client::module::init::ClientModuleInitRegistry;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client::{ClientArc, ClientBuilder};
use fedimint_core::admin_client::{ConfigGenParamsConsensus, PeerServerParams};
use fedimint_core::api::InviteCode;
use fedimint_core::config::{
    ClientConfig, FederationId, ServerModuleConfigGenParamsRegistry, ServerModuleInitRegistry,
    META_FEDERATION_NAME_KEY,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::Database;
use fedimint_core::module::ApiAuth;
use fedimint_core::task::TaskGroup;
use fedimint_core::PeerId;
use fedimint_logging::LOG_TEST;
use fedimint_server::config::api::ConfigGenParamsLocal;
use fedimint_server::config::{gen_cert_and_key, ConfigGenParams, ServerConfig};
use fedimint_server::consensus::server::ConsensusServer;
use fedimint_server::net::connect::mock::{MockNetwork, StreamReliability};
use fedimint_server::net::connect::{parse_host_port, Connector};
use fedimint_server::net::peers::DelayCalculator;
use fedimint_server::FedimintServer;
use rand::thread_rng;
use tokio_rustls::rustls;
use tracing::info;

/// Test fixture for a running fedimint federation
pub struct FederationTest {
    configs: BTreeMap<PeerId, ServerConfig>,
    server_init: ServerModuleInitRegistry,
    client_init: ClientModuleInitRegistry,
    primary_client: ModuleInstanceId,
    _task: TaskGroup,
}

impl FederationTest {
    /// Create two clients, useful for send/receive tests
    pub async fn two_clients(&self) -> (ClientArc, ClientArc) {
        (self.new_client().await, self.new_client().await)
    }

    /// Create a client connected to this fed
    pub async fn new_client(&self) -> ClientArc {
        let client_config = self.configs[&PeerId::from(0)]
            .consensus
            .to_client_config(&self.server_init)
            .unwrap();

        self.new_client_with_config(client_config).await
    }

    pub async fn new_client_with_config(&self, client_config: ClientConfig) -> ClientArc {
        info!(target: LOG_TEST, "Setting new client with config");
        let mut client_builder = ClientBuilder::default();
        client_builder.with_module_inits(self.client_init.clone());
        client_builder.with_primary_module(self.primary_client);
        client_builder.with_config(client_config);
        client_builder.with_database(MemDatabase::new());
        let client_secret = match client_builder
            .load_decodable_client_secret::<[u8; 64]>()
            .await
        {
            Ok(secret) => secret,
            Err(_) => {
                let secret = PlainRootSecretStrategy::random(&mut thread_rng());
                client_builder
                    .store_encodable_client_secret(secret)
                    .await
                    .expect("Storing client secret must work");
                secret
            }
        };
        client_builder
            .build(PlainRootSecretStrategy::to_root_secret(&client_secret))
            .await
            .expect("Failed to build client")
    }

    /// Return first invite code for gateways
    pub fn invite_code(&self) -> InviteCode {
        self.configs[&PeerId::from(0)].get_invite_code()
    }

    ///  Return first id for gateways
    pub fn id(&self) -> FederationId {
        self.configs[&PeerId::from(0)]
            .consensus
            .to_client_config(&self.server_init)
            .unwrap()
            .global
            .federation_id
    }

    pub(crate) async fn new(
        num_peers: u16,
        base_port: u16,
        params: ServerModuleConfigGenParamsRegistry,
        server_init: ServerModuleInitRegistry,
        client_init: ClientModuleInitRegistry,
        primary_client: ModuleInstanceId,
    ) -> Self {
        let peers = (0..num_peers).map(PeerId::from).collect::<Vec<_>>();
        let params =
            local_config_gen_params(&peers, base_port, params).expect("Generates local config");

        let configs = ServerConfig::trusted_dealer_gen(&params, server_init.clone());
        let network = MockNetwork::new();

        let mut task = TaskGroup::new();
        for (peer_id, config) in configs.clone() {
            let reliability = StreamReliability::INTEGRATION_TEST;
            let connections = network.connector(peer_id, reliability).into_dyn();

            let instances = config.consensus.iter_module_instances();
            let decoders = server_init.available_decoders(instances).unwrap();
            let db = Database::new(MemDatabase::new(), decoders);

            let (consensus_server, consensus_api) = ConsensusServer::new_with(
                config.clone(),
                db.clone(),
                server_init.clone(),
                connections,
                DelayCalculator::TEST_DEFAULT,
                &mut task,
            )
            .await
            .expect("Failed to init server");

            let api_handle = FedimintServer::spawn_consensus_api(consensus_api, false).await;

            task.spawn("fedimintd", move |handle| async move {
                consensus_server.run_consensus(handle).await.unwrap();
                api_handle.stop().await;
            })
            .await;
        }

        Self {
            configs,
            server_init,
            client_init,
            primary_client,
            _task: task,
        }
    }
}

/// Creates the config gen params for each peer
///
/// Uses peers * 2 ports offset from `base_port`
pub fn local_config_gen_params(
    peers: &[PeerId],
    base_port: u16,
    server_config_gen: ServerModuleConfigGenParamsRegistry,
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
            let p2p_url = format!("fedimint://127.0.0.1:{peer_port}");
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
                    api_auth: ApiAuth("pass".to_string()),
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
