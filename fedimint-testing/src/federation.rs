use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use fedimint_api_client::api::net::Connector;
use fedimint_api_client::api::{DynGlobalApi, FederationApiExt};
use fedimint_client::module_init::ClientModuleInitRegistry;
use fedimint_client::{Client, ClientHandleArc};
use fedimint_client_module::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client_module::AdminCreds;
use fedimint_core::config::{
    ClientConfig, FederationId, ServerModuleConfigGenParamsRegistry, META_FEDERATION_NAME_KEY,
};
use fedimint_core::core::ModuleKind;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::Database;
use fedimint_core::endpoint_constants::SESSION_COUNT_ENDPOINT;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::{ApiAuth, ApiRequestErased};
use fedimint_core::net::peers::IP2PConnections;
use fedimint_core::task::{block_in_place, sleep_in_test, TaskGroup};
use fedimint_core::PeerId;
use fedimint_gateway_common::ConnectFedPayload;
use fedimint_gateway_server::Gateway;
use fedimint_logging::LOG_TEST;
use fedimint_rocksdb::RocksDb;
use fedimint_server::config::{
    gen_cert_and_key, ConfigGenParams, PeerConnectionInfo, PeerEndpoints, ServerConfig,
};
use fedimint_server::consensus;
use fedimint_server::core::ServerModuleInitRegistry;
use fedimint_server::net::p2p::{p2p_status_channels, ReconnectP2PConnections};
use fedimint_server::net::p2p_connector::{IP2PConnector, TlsTcpConnector};
use tokio_rustls::rustls;
use tracing::info;

pub static API_AUTH: LazyLock<ApiAuth> = LazyLock::new(|| ApiAuth("pass".to_string()));

/// Test fixture for a running fedimint federation
#[derive(Clone)]
pub struct FederationTest {
    configs: BTreeMap<PeerId, ServerConfig>,
    server_init: ServerModuleInitRegistry,
    client_init: ClientModuleInitRegistry,
    primary_module_kind: ModuleKind,
    _task: TaskGroup,
    num_peers: u16,
    num_offline: u16,
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

    /// Create a new admin api for the given PeerId
    pub fn new_admin_api(&self, peer_id: PeerId) -> DynGlobalApi {
        let config = self.configs.get(&peer_id).expect("peer to have config");
        DynGlobalApi::new_admin(
            peer_id,
            config.consensus.api_endpoints()[&peer_id].url.clone(),
            &None,
            &Connector::default(),
        )
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
        client_builder.with_primary_module_kind(self.primary_module_kind.clone());
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
            use_tor: Some(false),
            recover: Some(false),
        })
        .await
        .expect("Failed to connect federation");
    }

    /// Return all online PeerIds
    pub fn online_peer_ids(&self) -> impl Iterator<Item = PeerId> {
        // we can assume this ordering since peers are started in ascending order
        (0..(self.num_peers - self.num_offline)).map(PeerId::from)
    }

    /// Returns true if the federation is running in a degraded state
    pub fn is_degraded(&self) -> bool {
        self.num_offline > 0
    }
}

/// Builder struct for creating a `FederationTest`.
#[derive(Clone, Debug)]
pub struct FederationTestBuilder {
    num_peers: u16,
    num_offline: u16,
    base_port: u16,
    primary_module_kind: ModuleKind,
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
        primary_module_kind: ModuleKind,
        num_offline: u16,
    ) -> FederationTestBuilder {
        let num_peers = 4;
        Self {
            num_peers,
            num_offline,
            base_port: block_in_place(|| fedimint_portalloc::port_alloc(num_peers * 2))
                .expect("Failed to allocate a port range"),
            primary_module_kind,
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

    pub fn primary_module_kind(mut self, primary_module_kind: ModuleKind) -> FederationTestBuilder {
        self.primary_module_kind = primary_module_kind;
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
        for (peer_id, cfg) in configs.clone() {
            let p2p_bind_addr = params.get(&peer_id).expect("Must exist").p2p_bind;
            let api_bind_addr = params.get(&peer_id).expect("Must exist").api_bind;
            if u16::from(peer_id) >= self.num_peers - self.num_offline {
                continue;
            }

            let instances = cfg.consensus.iter_module_instances();
            let decoders = self.server_init.available_decoders(instances).unwrap();
            let db = Database::new(MemDatabase::new(), decoders);
            let module_init_registry = self.server_init.clone();
            let subgroup = task_group.make_subgroup();
            let checkpoint_dir = tempfile::Builder::new().tempdir().unwrap().into_path();
            let code_version_str = env!("CARGO_PKG_VERSION");

            let connector = TlsTcpConnector::new(
                cfg.tls_config(),
                p2p_bind_addr,
                cfg.local.p2p_endpoints.clone(),
                cfg.local.identity,
            )
            .await
            .into_dyn();

            let (p2p_status_senders, p2p_status_receivers) = p2p_status_channels(connector.peers());

            let connections = ReconnectP2PConnections::new(
                cfg.local.identity,
                connector,
                &task_group,
                p2p_status_senders,
            )
            .into_dyn();

            task_group.spawn("fedimintd", move |_| async move {
                Box::pin(consensus::run(
                    connections,
                    p2p_status_receivers,
                    api_bind_addr,
                    cfg.clone(),
                    db.clone(),
                    module_init_registry,
                    &subgroup,
                    fedimint_server::net::api::ApiSecrets::default(),
                    checkpoint_dir,
                    code_version_str.to_string(),
                ))
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
                config.consensus.api_endpoints()[&peer_id].url.clone(),
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
            primary_module_kind: self.primary_module_kind,
            _task: task_group,
            num_peers: self.num_peers,
            num_offline: self.num_offline,
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
    let connections: BTreeMap<PeerId, PeerConnectionInfo> = peers
        .iter()
        .map(|peer| {
            let peer_port = base_port + u16::from(*peer) * 2;

            let p2p_url = format!("fedimint://127.0.0.1:{peer_port}");
            let api_url = format!("ws://127.0.0.1:{}", peer_port + 1);

            let params = PeerConnectionInfo {
                endpoints: PeerEndpoints::Tcp {
                    cert: tls_keys[peer].0.clone().0,
                    p2p_url: p2p_url.parse().expect("Should parse"),
                    api_url: api_url.parse().expect("Should parse"),
                },
                name: format!("peer-{}", peer.to_usize()),
                federation_name: None,
            };
            (*peer, params)
        })
        .collect();

    peers
        .iter()
        .map(|peer| {
            let peer_port = base_port + u16::from(*peer) * 2;

            let p2p_bind = format!("127.0.0.1:{peer_port}");
            let api_bind = format!("127.0.0.1:{}", peer_port + 1);

            let params = ConfigGenParams {
                identity: *peer,
                api_auth: API_AUTH.clone(),
                tls_key: Some(tls_keys[peer].1.clone()),
                iroh_api_sk: None,
                iroh_p2p_sk: None,
                p2p_bind: p2p_bind.parse().expect("Valid address"),
                api_bind: api_bind.parse().expect("Valid address"),
                peers: connections.clone(),
                meta: BTreeMap::from([(
                    META_FEDERATION_NAME_KEY.to_owned(),
                    "\"federation_name\"".to_string(),
                )]),
                modules: server_config_gen.clone(),
            };
            Ok((*peer, params))
        })
        .collect()
}
