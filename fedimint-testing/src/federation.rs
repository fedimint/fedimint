use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use fedimint_api_client::api::net::Connector;
use fedimint_api_client::api::{DynGlobalApi, FederationApiExt};
use fedimint_client::module::init::ClientModuleInitRegistry;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client::{AdminCreds, Client, ClientHandleArc};
use fedimint_core::admin_client::{ConfigGenParamsConsensus, PeerServerParams};
use fedimint_core::config::{
    ClientConfig, FederationId, ServerModuleConfigGenParamsRegistry, ServerModuleInitRegistry,
    META_FEDERATION_NAME_KEY,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::Database;
use fedimint_core::endpoint_constants::SESSION_COUNT_ENDPOINT;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::{ApiAuth, ApiRequestErased};
use fedimint_core::task::{block_in_place, sleep_in_test, TaskGroup};
use fedimint_core::PeerId;
use fedimint_logging::LOG_TEST;
use fedimint_rocksdb::RocksDb;
use fedimint_server::config::api::ConfigGenParamsLocal;
use fedimint_server::config::{gen_cert_and_key, ConfigGenParams, ServerConfig};
use fedimint_server::consensus;
use fedimint_server::net::connect::parse_host_port;
use ln_gateway::rpc::ConnectFedPayload;
use ln_gateway::Gateway;
use tokio_rustls::rustls;
use tracing::info;

/// Test fixture for a running fedimint federation
#[derive(Clone)]
pub struct FederationTest {
    configs: BTreeMap<PeerId, ServerConfig>,
    server_init: ServerModuleInitRegistry,
    client_init: ClientModuleInitRegistry,
    primary_client: ModuleInstanceId,
    _task: TaskGroup,
}

impl FederationTest {
    /// Create two clients, useful for send/receive tests
    pub async fn two_clients(&self) -> (ClientHandleArc, ClientHandleArc) {
        (self.new_client().await, self.new_client().await)
    }

    /// Create a client connected to this fed
    pub async fn new_client(&self) -> ClientHandleArc {
        let client_config = self.configs[&PeerId::from(0)]
            .consensus
            .to_client_config(&self.server_init)
            .unwrap();

        self.new_client_with(client_config, MemDatabase::new().into(), None)
            .await
    }

    /// Create a client connected to this fed but using RocksDB instead of MemDB
    pub async fn new_client_rocksdb(&self) -> ClientHandleArc {
        let client_config = self.configs[&PeerId::from(0)]
            .consensus
            .to_client_config(&self.server_init)
            .unwrap();

        self.new_client_with(
            client_config,
            RocksDb::open(tempfile::tempdir().expect("Couldn't create temp dir"))
                .expect("Couldn't open DB")
                .into(),
            None,
        )
        .await
    }

    /// Create a new admin client connected to this fed
    pub async fn new_admin_client(&self, peer_id: PeerId, auth: ApiAuth) -> ClientHandleArc {
        let client_config = self.configs[&PeerId::from(0)]
            .consensus
            .to_client_config(&self.server_init)
            .unwrap();

        let admin_creds = AdminCreds { peer_id, auth };

        self.new_client_with(client_config, MemDatabase::new().into(), Some(admin_creds))
            .await
    }

    pub async fn new_client_with(
        &self,
        client_config: ClientConfig,
        db: Database,
        admin_creds: Option<AdminCreds>,
    ) -> ClientHandleArc {
        info!(target: LOG_TEST, "Setting new client with config");
        let mut client_builder = Client::builder(db).await.expect("Failed to build client");
        client_builder.with_module_inits(self.client_init.clone());
        client_builder.with_primary_module(self.primary_client);
        if let Some(admin_creds) = admin_creds {
            client_builder.set_admin_creds(admin_creds);
        }
        let client_secret = Client::load_or_generate_client_secret(client_builder.db_no_decoders())
            .await
            .unwrap();
        client_builder
            .join(
                PlainRootSecretStrategy::to_root_secret(&client_secret),
                client_config,
                None,
            )
            .await
            .map(Arc::new)
            .expect("Failed to build client")
    }

    /// Return first invite code for gateways
    pub fn invite_code(&self) -> InviteCode {
        self.configs[&PeerId::from(0)].get_invite_code(None)
    }

    ///  Return the federation id
    pub fn id(&self) -> FederationId {
        self.configs[&PeerId::from(0)]
            .consensus
            .to_client_config(&self.server_init)
            .unwrap()
            .global
            .calculate_federation_id()
    }

    /// Connects a gateway to this `FederationTest`
    pub async fn connect_gateway(&self, gw: &Gateway) {
        gw.handle_connect_federation(ConnectFedPayload {
            invite_code: self.invite_code().to_string(),
            #[cfg(feature = "tor")]
            use_tor: Some(false), // TODO: (@leonardo) Should we get it from self.configs too ?
            recover: Some(false),
        })
        .await
        .expect("Failed to connect federation");
    }
}

/// Builder struct for creating a `FederationTest`.
#[derive(Clone, Debug)]
pub struct FederationTestBuilder {
    num_peers: u16,
    num_offline: u16,
    base_port: u16,
    primary_client: ModuleInstanceId,
    version_hash: String,
    params: ServerModuleConfigGenParamsRegistry,
    server_init: ServerModuleInitRegistry,
    client_init: ClientModuleInitRegistry,
}

impl FederationTestBuilder {
    pub fn new(
        params: ServerModuleConfigGenParamsRegistry,
        server_init: ServerModuleInitRegistry,
        client_init: ClientModuleInitRegistry,
    ) -> FederationTestBuilder {
        let num_peers = 4;
        Self {
            num_peers,
            num_offline: 1,
            base_port: block_in_place(|| fedimint_portalloc::port_alloc(num_peers * 2))
                .expect("Failed to allocate a port range"),
            primary_client: 0,
            version_hash: "fedimint-testing-dummy-version-hash".to_owned(),
            params,
            server_init,
            client_init,
        }
    }

    pub fn num_peers(mut self, num_peers: u16) -> FederationTestBuilder {
        self.num_peers = num_peers;
        self
    }

    pub fn num_offline(mut self, num_offline: u16) -> FederationTestBuilder {
        self.num_offline = num_offline;
        self
    }

    pub fn base_port(mut self, base_port: u16) -> FederationTestBuilder {
        self.base_port = base_port;
        self
    }

    pub fn primary_client(mut self, primary_client: ModuleInstanceId) -> FederationTestBuilder {
        self.primary_client = primary_client;
        self
    }

    pub fn version_hash(mut self, version_hash: String) -> FederationTestBuilder {
        self.version_hash = version_hash;
        self
    }

    pub async fn build(self) -> FederationTest {
        let num_offline = self.num_offline;
        assert!(
            self.num_peers > 3 * self.num_offline,
            "too many peers offline ({num_offline}) to reach consensus"
        );
        let peers = (0..self.num_peers).map(PeerId::from).collect::<Vec<_>>();
        let params = local_config_gen_params(&peers, self.base_port, &self.params)
            .expect("Generates local config");

        let configs =
            ServerConfig::trusted_dealer_gen(&params, &self.server_init, &self.version_hash);

        let task_group = TaskGroup::new();
        for (peer_id, config) in configs.clone() {
            let p2p_bind_addr = params.get(&peer_id).expect("Must exist").local.p2p_bind;
            let api_bind_addr = params.get(&peer_id).expect("Must exist").local.api_bind;
            if u16::from(peer_id) >= self.num_peers - self.num_offline {
                continue;
            }

            let instances = config.consensus.iter_module_instances();
            let decoders = self.server_init.available_decoders(instances).unwrap();
            let db = Database::new(MemDatabase::new(), decoders);
            let module_init_registry = self.server_init.clone();
            let subgroup = task_group.make_subgroup();
            let checkpoint_dir = tempfile::Builder::new().tempdir().unwrap().into_path();

            task_group.spawn("fedimintd", move |_| async move {
                consensus::run(
                    p2p_bind_addr,
                    api_bind_addr,
                    config.clone(),
                    db.clone(),
                    module_init_registry,
                    &subgroup,
                    fedimint_server::net::api::ApiSecrets::default(),
                    checkpoint_dir,
                )
                .await
                .expect("Could not initialise consensus");
            });
        }

        for (peer_id, config) in configs.clone() {
            if u16::from(peer_id) >= self.num_peers - self.num_offline {
                continue;
            }

            // FIXME: (@leonardo) Currently there is no support for Tor while testing,
            // defaulting to Tcp variant.
            let api = DynGlobalApi::new_admin(
                peer_id,
                config.consensus.api_endpoints[&peer_id].url.clone(),
                &None,
                &Connector::default(),
            );

            while let Err(e) = api
                .request_admin_no_auth::<u64>(SESSION_COUNT_ENDPOINT, ApiRequestErased::default())
                .await
            {
                sleep_in_test(
                    format!("Waiting for api of peer {peer_id} to come online: {e}"),
                    Duration::from_millis(500),
                )
                .await;
            }
        }

        FederationTest {
            configs,
            server_init: self.server_init,
            client_init: self.client_init,
            primary_client: self.primary_client,
            _task: task_group,
        }
    }
}

/// Creates the config gen params for each peer
///
/// Uses peers * 2 ports offset from `base_port`
pub fn local_config_gen_params(
    peers: &[PeerId],
    base_port: u16,
    server_config_gen: &ServerModuleConfigGenParamsRegistry,
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
            let p2p_bind = parse_host_port(&connections[peer].clone().p2p_url)?;
            let api_bind = parse_host_port(&connections[peer].clone().api_url)?;

            let params = ConfigGenParams {
                local: ConfigGenParamsLocal {
                    our_id: *peer,
                    our_private_key: tls_keys[peer].1.clone(),
                    api_auth: ApiAuth("pass".to_string()),
                    p2p_bind: p2p_bind.parse().expect("Valid address"),
                    api_bind: api_bind.parse().expect("Valid address"),
                    max_connections: 10,
                },
                consensus: ConfigGenParamsConsensus {
                    peers: connections.clone(),
                    meta: BTreeMap::from([(
                        META_FEDERATION_NAME_KEY.to_owned(),
                        "\"federation_name\"".to_string(),
                    )]),
                    modules: server_config_gen.clone(),
                },
            };
            Ok((*peer, params))
        })
        .collect::<anyhow::Result<HashMap<_, _>>>()
}
