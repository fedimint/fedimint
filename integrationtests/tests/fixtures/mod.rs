use std::collections::{BTreeMap, HashMap};
use std::env;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{secp256k1, KeyPair};
use cln_rpc::ClnRpc;
use fedimint_bitcoind::bitcoincore_rpc::{make_bitcoind_rpc, make_electrum_rpc, make_esplora_rpc};
use fedimint_bitcoind::DynBitcoindRpc;
use fedimint_client::module::gen::{ClientModuleGenRegistry, DynClientModuleGen};
use fedimint_client_legacy::mint::SpendableNote;
use fedimint_client_legacy::{module_decode_stubs, GatewayClientConfig, UserClientConfig};
use fedimint_core::admin_client::PeerServerParams;
use fedimint_core::api::WsClientConnectInfo;
use fedimint_core::bitcoin_rpc::read_bitcoin_backend_from_global_env;
use fedimint_core::cancellable::Cancellable;
use fedimint_core::config::{ClientConfig, ServerModuleGenParamsRegistry, ServerModuleGenRegistry};
use fedimint_core::core::{
    DynModuleConsensusItem, ModuleConsensusItem, ModuleInstanceId, LEGACY_HARDCODED_INSTANCE_ID_LN,
    LEGACY_HARDCODED_INSTANCE_ID_MINT, LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::Database;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{ApiAuth, DynServerModuleGen, ModuleCommon};
use fedimint_core::outcome::TransactionStatus;
use fedimint_core::task::{timeout, RwLock, TaskGroup};
use fedimint_core::{
    core, msats, Amount, OutPoint, PeerId, ServerModule, TieredMulti, TransactionId,
};
use fedimint_ln_client::{LightningClientGen, LightningGateway};
use fedimint_ln_server::LightningGen;
use fedimint_logging::TracingSetup;
use fedimint_mint_client::MintClientGen;
use fedimint_mint_server::common::db::NonceKeyPrefix;
use fedimint_mint_server::common::MintOutput;
use fedimint_mint_server::MintGen;
use fedimint_server::config::api::ConfigGenSettings;
use fedimint_server::config::{gen_cert_and_key, ConfigGenParams, ServerConfig};
use fedimint_server::consensus::server::{ConsensusServer, EpochMessage};
use fedimint_server::consensus::{
    ConsensusProposal, HbbftConsensusOutcome, TransactionSubmissionError,
};
use fedimint_server::net::connect::mock::{MockNetwork, StreamReliability};
use fedimint_server::net::connect::{parse_host_port, Connector, TlsTcpConnector};
use fedimint_server::net::peers::PeerConnector;
use fedimint_server::{consensus, FedimintServer};
use fedimint_testing::btc::bitcoind::FakeWalletGen;
use fedimint_testing::btc::fixtures::FakeBitcoinTest;
use fedimint_testing::btc::BitcoinTest;
use fedimint_testing::ln::fixtures::FakeLightningTest;
use fedimint_testing::ln::LightningTest;
use fedimint_wallet_client::{WalletClientGen, WalletConsensusItem};
use fedimint_wallet_server::common::config::WalletConfig;
use fedimint_wallet_server::common::db::UTXOKey;
use fedimint_wallet_server::common::SpendableUTXO;
use fedimint_wallet_server::{Wallet, WalletGen};
use futures::executor::block_on;
use futures::future::{join_all, select_all};
use futures::{FutureExt, StreamExt};
use hbbft::honey_badger::Batch;
use legacy::LegacyTestUser;
use ln_gateway::actor::GatewayActor;
use ln_gateway::client::{DynGatewayClientBuilder, MemDbFactory, StandardGatewayClientBuilder};
use ln_gateway::lnd::GatewayLndClient;
use ln_gateway::lnrpc_client::{ILnRpcClient, NetworkLnRpcClient};
use ln_gateway::Gateway;
use rand::rngs::OsRng;
use rand::RngCore;
use real::{RealBitcoinTest, RealLightningTest};
use tokio::sync::Mutex;
use tokio_rustls::rustls;
use tonic_lnd::connect;
use tracing::{debug, info};
use url::Url;

use crate::fixtures::user::{IGatewayClient, ILegacyTestClient};
use crate::fixtures::utils::LnRpcAdapter;
use crate::ConsensusItem;

mod legacy;
mod real;
pub mod user;
mod utils;

// 21 denominations, up to ~1048 sats which is big enough for our tests
const MAX_MSAT_DENOMINATION: u64 = u64::pow(2, 20);
const DEFAULT_P2P_PORT: u16 = 8173;
const BASE_PORT_INIT: u16 = DEFAULT_P2P_PORT + 20000;
static BASE_PORT: AtomicU16 = AtomicU16::new(BASE_PORT_INIT);

// Helper functions for easier test writing
pub fn rng() -> OsRng {
    OsRng
}

pub fn sha256(data: &[u8]) -> sha256::Hash {
    bitcoin::hashes::sha256::Hash::hash(data)
}

pub fn secp() -> secp256k1::Secp256k1<secp256k1::All> {
    bitcoin::secp256k1::Secp256k1::new()
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum GatewayNode {
    Cln,
    Lnd,
}

#[non_exhaustive]
pub struct Fixtures {
    pub fed: FederationTest,
    pub user: Box<dyn ILegacyTestClient>,
    pub bitcoin: Box<dyn BitcoinTest>,
    pub gateway: GatewayTest,
    pub lightning: Box<dyn LightningTest>,
    pub task_group: TaskGroup,
}

/// Helper for generating fixtures, passing them into test code, then shutting
/// down the task thread when the test is complete.
///
/// Used by `lightning_test` and `non_lightning_test`
async fn test<B>(
    num_peers: u16,
    gateway_nodes: Vec<GatewayNode>,
    f: impl FnOnce(
            FederationTest,
            Box<dyn ILegacyTestClient>,
            Box<dyn BitcoinTest>,
            GatewayTest,
            Box<dyn LightningTest>,
        ) -> B
        + Copy,
) -> anyhow::Result<()>
where
    B: Future<Output = ()>,
{
    for gateway_node in gateway_nodes {
        debug!("Running tests with {:?}", gateway_node);
        let fixtures = fixtures(num_peers, gateway_node).await?;
        f(
            fixtures.fed,
            fixtures.user,
            fixtures.bitcoin,
            fixtures.gateway,
            fixtures.lightning,
        )
        .await;
        fixtures
            .task_group
            // it's a test; you have 1 second to wrap up, or you
            // get killed
            .shutdown_join_all(Some(Duration::from_secs(1)))
            .await?;
    }
    Ok(())
}

/// Helper for running tests that don't involve lightning payments
pub async fn non_lightning_test<B>(
    num_peers: u16,
    f: impl FnOnce(FederationTest, Box<dyn ILegacyTestClient>, Box<dyn BitcoinTest>) -> B + Copy,
) -> anyhow::Result<()>
where
    B: Future<Output = ()>,
{
    // default to using LND
    let gateway_nodes = vec![GatewayNode::Lnd];
    test(num_peers, gateway_nodes, |fed, client, btc, _, _| {
        f(fed, client, btc)
    })
    .await
}

/// Helper for running tests that involve lightning payments. Test callback will
/// be run twice - once using LND as the gateway, once using CLN as the gateway.
pub async fn lightning_test<B>(
    num_peers: u16,
    f: impl FnOnce(
            FederationTest,
            Box<dyn ILegacyTestClient>,
            Box<dyn BitcoinTest>,
            GatewayTest,
            Box<dyn LightningTest>,
        ) -> B
        + Copy,
) -> anyhow::Result<()>
where
    B: Future<Output = ()>,
{
    let gateway_nodes = vec![GatewayNode::Cln, GatewayNode::Lnd];
    test(num_peers, gateway_nodes, f).await
}

/// Generates the fixtures for an integration test and spawns API and HBBFT
/// consensus threads for federation nodes starting at port DEFAULT_P2P_PORT.
///
/// * `gateway_node` - whether to use CLN or LND as the gateway node
pub async fn fixtures(num_peers: u16, gateway_node: GatewayNode) -> anyhow::Result<Fixtures> {
    let mut task_group = TaskGroup::new();
    let base_port = BASE_PORT.fetch_add(num_peers * 10, Ordering::Relaxed);

    // in case we need to output logs using 'cargo test -- --nocapture'
    if base_port == BASE_PORT_INIT {
        let chrome = env::var_os("FEDIMINT_TRACE_CHROME").map_or(false, |x| !x.is_empty());
        TracingSetup::default().with_chrome(chrome).init()?;
    }

    let peers = (0..num_peers).map(PeerId::from).collect::<Vec<_>>();
    let mut module_gens_params = ServerModuleGenParamsRegistry::default();
    fedimintd::attach_default_module_gen_params(
        &mut module_gens_params,
        msats(MAX_MSAT_DENOMINATION),
        bitcoin::network::constants::Network::Regtest,
        10,
    );
    let params = gen_local(&peers, base_port, "test", module_gens_params).unwrap();

    let client_module_inits = ClientModuleGenRegistry::from(vec![
        DynClientModuleGen::from(WalletClientGen),
        DynClientModuleGen::from(MintClientGen),
        DynClientModuleGen::from(LightningClientGen),
    ]);

    let decoders = module_decode_stubs();

    let fixtures = match env::var("FM_TEST_USE_REAL_DAEMONS") {
        Ok(s) if s == "1" => {
            let server_module_inits = ServerModuleGenRegistry::from(vec![
                DynServerModuleGen::from(WalletGen),
                DynServerModuleGen::from(MintGen),
                DynServerModuleGen::from(LightningGen),
            ]);

            info!("Testing with REAL Bitcoin and Lightning services");
            let mut config_task_group = task_group.make_subgroup().await;
            let (server_config, client_config) = distributed_config(
                &peers,
                params,
                server_module_inits.clone(),
                &mut config_task_group,
            )
            .await
            .expect("distributed config should not be canceled");
            config_task_group
                .shutdown_join_all(None)
                .await
                .expect("Distributed config did not exit cleanly");

            // bitcoin
            let dir = env::var("FM_TEST_DIR").expect("Must have test dir defined for real tests");
            let url = env::var("FM_TEST_BITCOIND_RPC")
                .expect("Must have bitcoind RPC defined for real tests")
                .parse()
                .expect("Invalid bitcoind RPC URL");
            let bitcoin_rpc =
                match read_bitcoin_backend_from_global_env().expect("invalid bitcoin rpc url") {
                    fedimint_core::bitcoin_rpc::BitcoindRpcBackend::Bitcoind(url) => {
                        info!("Running tests with Bitcoin rpc");
                        make_bitcoind_rpc(&url, task_group.make_handle())
                            .expect("Could not create Bitcoin rpc")
                    }
                    fedimint_core::bitcoin_rpc::BitcoindRpcBackend::Electrum(url) => {
                        info!("Running tests with Electrum rpc");
                        make_electrum_rpc(&url, task_group.make_handle())
                            .expect("Could not create Electrum rpc")
                    }
                    fedimint_core::bitcoin_rpc::BitcoindRpcBackend::Esplora(url) => {
                        info!("Running tests with Esplora rpc");
                        make_esplora_rpc(&url, task_group.make_handle())
                            .expect("Could not create Esplora rpc")
                    }
                };
            let bitcoin = RealBitcoinTest::new(&url, bitcoin_rpc.clone());

            // lightning - we create one LND RPC client, and one CLN RPC client. one will be
            // used as the gateway's lightning node, and the other is an external node
            // outside the federation that can be used to test lightnining
            // payments through the gateway
            let socket_cln = PathBuf::from(dir.clone()).join("cln/regtest/lightning-rpc");
            let rpc_cln = Arc::new(Mutex::new(ClnRpc::new(socket_cln).await.unwrap()));
            let lnd_rpc_addr = env::var("FM_LND_RPC_ADDR").unwrap();
            let lnd_macaroon = env::var("FM_LND_MACAROON").unwrap();
            let lnd_tls_cert = env::var("FM_LND_TLS_CERT").unwrap();
            let lnd_client = connect(
                lnd_rpc_addr.clone(),
                lnd_tls_cert.clone(),
                lnd_macaroon.clone(),
            )
            .await
            .unwrap();
            let rpc_lnd = Arc::new(Mutex::new(lnd_client.clone()));
            let lightning = RealLightningTest::new(rpc_cln, rpc_lnd, gateway_node.clone()).await;

            // federation
            let connect_gen = |cfg: &ServerConfig| {
                TlsTcpConnector::new(cfg.tls_config(), cfg.local.identity).into_dyn()
            };
            let fed_db = |decoders| Database::new(rocks(dir.clone()), decoders);
            let fed = FederationTest::new(
                server_config,
                &fed_db,
                &|| bitcoin_rpc.clone(),
                &connect_gen,
                server_module_inits.clone(),
                &mut task_group,
            )
            .await;

            // user
            let user_db = if env::var("FM_CLIENT_SQLITE") == Ok(s) {
                let db_name = format!("client-{}", rng().next_u64());
                Database::new(sqlite(dir.clone(), db_name).await, decoders.clone())
            } else {
                Database::new(rocks(dir.clone()), decoders.clone())
            };
            let user_cfg = UserClientConfig(client_config.clone());
            let user = Box::new(LegacyTestUser::new(
                user_cfg,
                decoders.clone(),
                client_module_inits.clone(),
                peers,
                user_db,
            ));
            user.client.await_consensus_block_height(0).await?;

            let gateway = GatewayTest::new(
                create_lightning_adapter(gateway_node.clone(), task_group.make_subgroup().await)
                    .await,
                client_config.clone(),
                decoders,
                client_module_inits.clone(),
                lightning.gateway_node_pub_key,
                base_port + (2 * num_peers) + 1,
                gateway_node,
            )
            .await;

            Fixtures {
                fed,
                user,
                bitcoin: Box::new(bitcoin),
                gateway,
                lightning: Box::new(lightning),
                task_group,
            }
        }
        _ => {
            info!("Testing with FAKE Bitcoin and Lightning services");
            let bitcoin = FakeBitcoinTest::new();
            let bitcoin_rpc = || bitcoin.clone().into();

            let server_module_inits = ServerModuleGenRegistry::from(vec![
                DynServerModuleGen::from(FakeWalletGen::new(bitcoin.clone().into())),
                DynServerModuleGen::from(MintGen),
                DynServerModuleGen::from(LightningGen),
            ]);

            let server_config = ServerConfig::trusted_dealer_gen(
                &params,
                server_module_inits.clone().legacy_init_modules(),
            );
            let client_config = server_config[&PeerId::from(0)]
                .consensus
                .to_config_response(&server_module_inits)
                .client;

            let lightning = FakeLightningTest::new();
            let ln_arc = Arc::new(RwLock::new(lightning.clone()));
            let lnrpc_adapter = LnRpcAdapter::new(ln_arc.clone());

            let net = MockNetwork::new();
            let net_ref = &net;
            let connect_gen = move |cfg: &ServerConfig| {
                net_ref
                    .connector(cfg.local.identity, StreamReliability::INTEGRATION_TEST)
                    .into_dyn()
            };

            let fed_db = |decoders| Database::new(MemDatabase::new(), decoders);
            let fed = FederationTest::new(
                server_config,
                &fed_db,
                &bitcoin_rpc,
                &connect_gen,
                server_module_inits.clone(),
                &mut task_group.clone(),
            )
            .await;

            let user_db = Database::new(MemDatabase::new(), module_decode_stubs());
            let user_cfg = UserClientConfig(client_config.clone());
            let user = Box::new(LegacyTestUser::new(
                user_cfg,
                decoders.clone(),
                client_module_inits.clone(),
                peers,
                user_db,
            ));
            user.client.await_consensus_block_height(0).await?;

            let gateway = GatewayTest::new(
                lnrpc_adapter,
                client_config.clone(),
                decoders,
                client_module_inits,
                lightning.gateway_node_pub_key,
                base_port + (2 * num_peers) + 1,
                gateway_node.clone(),
            )
            .await;

            // Always be prepared to fund bitcoin wallet
            bitcoin.prepare_funding_wallet().await;

            Fixtures {
                fed,
                user,
                bitcoin: Box::new(bitcoin),
                gateway,
                lightning: Box::new(lightning),
                task_group,
            }
        }
    };

    // Wait till the gateway has registered itself
    while fixtures.user.fetch_active_gateway().await.is_err() {
        tokio::time::sleep(Duration::from_millis(100)).await;
        info!("Waiting for gateway to register");
    }

    Ok(fixtures)
}

/// config for servers running on different ports on our localhost
pub fn gen_local(
    peers: &[PeerId],
    base_port: u16,
    federation_name: &str,
    modules: ServerModuleGenParamsRegistry,
) -> anyhow::Result<HashMap<PeerId, ConfigGenParams>> {
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
            let p2p_url = format!("ws://127.0.0.1:{peer_port}");
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
            let bind_p2p = parse_host_port(peer_params[peer].clone().p2p_url)?;
            let bind_api = parse_host_port(peer_params[peer].clone().api_url)?;

            let params: ConfigGenParams = ConfigGenParams::new(
                ApiAuth("dummy_password".to_string()),
                bind_p2p.parse().context("when parsing bind_p2p")?,
                bind_api.parse().context("when parsing bind_api")?,
                keys[peer].1.clone(),
                *peer,
                peer_params.clone(),
                federation_name.to_string(),
                Some(1),
                modules.clone(),
            );
            Ok((*peer, params))
        })
        .collect::<anyhow::Result<HashMap<_, _>>>()
}

pub async fn create_lightning_adapter(
    gateway_node: GatewayNode,
    task_group: TaskGroup,
) -> LnRpcAdapter {
    match env::var("FM_TEST_USE_REAL_DAEMONS") {
        Ok(s) if s == "1" => {
            let lnrpc_addr = env::var("FM_GATEWAY_LIGHTNING_ADDR")
                .expect("FM_GATEWAY_LIGHTNING_ADDR not set")
                .parse::<Url>()
                .expect("Invalid FM_GATEWAY_LIGHTNING_ADDR");
            match gateway_node {
                GatewayNode::Cln => {
                    let lnrpc: Arc<RwLock<dyn ILnRpcClient>> = Arc::new(RwLock::new(
                        NetworkLnRpcClient::new(lnrpc_addr).await.unwrap(),
                    ));
                    LnRpcAdapter::new(lnrpc)
                }
                GatewayNode::Lnd => {
                    let gateway_lnd_client = GatewayLndClient::new(
                        env::var("FM_LND_RPC_ADDR").unwrap(),
                        env::var("FM_LND_TLS_CERT").unwrap(),
                        env::var("FM_LND_MACAROON").unwrap(),
                        task_group.make_subgroup().await,
                    )
                    .await
                    .unwrap();
                    let lnrpc = Arc::new(RwLock::new(gateway_lnd_client));
                    LnRpcAdapter::new(lnrpc)
                }
            }
        }
        _ => {
            let lightning = FakeLightningTest::new();
            let ln_arc = Arc::new(RwLock::new(lightning));
            LnRpcAdapter::new(ln_arc)
        }
    }
}

pub fn peers(peers: &[u16]) -> Vec<PeerId> {
    peers
        .iter()
        .map(|i| PeerId::from(*i))
        .collect::<Vec<PeerId>>()
}

async fn distributed_config(
    peers: &[PeerId],
    params: HashMap<PeerId, ConfigGenParams>,
    registry: ServerModuleGenRegistry,
    task_group: &mut TaskGroup,
) -> Cancellable<(BTreeMap<PeerId, ServerConfig>, ClientConfig)> {
    let configs: Vec<(PeerId, ServerConfig)> = join_all(peers.iter().map(|peer| {
        let params = params.clone();

        let mut task_group = task_group.clone();
        let registry = registry.clone();

        async move {
            let our_params = params[peer].clone();

            let cfg = ServerConfig::distributed_gen(
                &our_params,
                registry.legacy_init_modules(),
                Default::default(),
                &mut task_group,
            );
            (*peer, cfg.await.expect("generation failed"))
        }
    }))
    .await
    .into_iter()
    .collect();

    let (_, config) = configs.first().unwrap().clone();

    Ok((
        configs.into_iter().collect(),
        config.consensus.to_config_response(&registry).client,
    ))
}

fn rocks(dir: String) -> fedimint_rocksdb::RocksDb {
    let db_dir = PathBuf::from(dir).join(format!("db-{}", rng().next_u64()));
    fedimint_rocksdb::RocksDb::open(db_dir).unwrap()
}

async fn sqlite(dir: String, db_name: String) -> fedimint_sqlite::SqliteDb {
    let connection_string = format!("sqlite://{dir}/{db_name}.db");
    fedimint_sqlite::SqliteDb::open(connection_string.as_str())
        .await
        .unwrap()
}

pub struct GatewayTest {
    pub actor: GatewayActor,
    pub adapter: Arc<RwLock<LnRpcAdapter>>,
    pub keys: LightningGateway,
    pub user: Box<dyn ILegacyTestClient>,
    pub client: Box<dyn IGatewayClient>,
    pub node: GatewayNode,
}

impl GatewayTest {
    async fn new(
        adapter: LnRpcAdapter,
        client_config: ClientConfig,
        decoders: ModuleDecoderRegistry,
        module_gens: ClientModuleGenRegistry,
        node_pub_key: secp256k1::PublicKey,
        bind_port: u16,
        node: GatewayNode,
    ) -> Self {
        let mut rng = OsRng;
        let ctx = bitcoin::secp256k1::Secp256k1::new();
        let kp = KeyPair::new(&ctx, &mut rng);

        let mint_channel_id: u64 = 0;

        let keys = LightningGateway {
            mint_channel_id,
            mint_pub_key: kp.x_only_public_key().0,
            node_pub_key,
            api: Url::parse("http://example.com")
                .expect("Could not parse URL to generate GatewayClientConfig API endpoint"),
            route_hints: vec![],
            valid_until: fedimint_core::time::now(),
        };

        let bind_addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();
        let announce_addr = Url::parse(format!("http://{bind_addr}").as_str())
            .expect("Could not parse URL to generate GatewayClientConfig API endpoint");

        let gw_client_cfg = GatewayClientConfig {
            mint_channel_id,
            client_config: client_config.clone(),
            redeem_key: kp,
            timelock_delta: 10,
            api: announce_addr.clone(),
            node_pub_key,
        };

        // Create federation client builder for the gateway
        let client_builder: DynGatewayClientBuilder = StandardGatewayClientBuilder::new(
            PathBuf::new(),
            MemDbFactory.into(),
            announce_addr.clone(),
        )
        .into();

        let mut gateway = Gateway::new_with_lightning_connection(
            Arc::new(RwLock::new(adapter.clone())),
            client_builder.clone(),
            decoders.clone(),
            module_gens.clone(),
            TaskGroup::new(),
        )
        .await
        .unwrap();

        let client = Arc::new(
            client_builder
                .build(gw_client_cfg.clone(), decoders.clone(), module_gens.clone())
                .await
                .expect("Could not build gateway client"),
        );

        let actor = gateway
            .load_actor(client.clone(), vec![])
            .await
            .expect("Could not connect federation");
        // Note: We don't run the gateway in test scenarios

        // Create a user test from gateway federation client
        let config = client.config();
        let user = Box::new(LegacyTestUser::new(
            UserClientConfig(config.client_config.clone()),
            decoders.clone(),
            module_gens.clone(),
            config.client_config.api_endpoints.keys().cloned().collect(),
            client.context().db.clone(),
        ));
        let client = Box::new(LegacyTestUser { client, config });

        GatewayTest {
            actor,
            adapter: Arc::new(RwLock::new(adapter)),
            keys,
            user,
            client,
            node,
        }
    }
}

pub struct FederationTest {
    servers: Vec<Arc<Mutex<ServerTest>>>,
    last_consensus: Arc<Mutex<HbbftConsensusOutcome>>,
    max_balance_sheet: Arc<AtomicI64>,
    pub wallet: WalletConfig,
    pub cfg: ServerConfig,
    decoders: ModuleDecoderRegistry,
    pub mint_id: ModuleInstanceId,
    pub ln_id: ModuleInstanceId,
    pub wallet_id: ModuleInstanceId,
    pub connect_info: WsClientConnectInfo,
}

struct ServerTest {
    fedimint: ConsensusServer,
    last_consensus: Vec<HbbftConsensusOutcome>,
    bitcoin_rpc: DynBitcoindRpc,
    database: Database,
    override_proposal: Option<ConsensusProposal>,
    dropped_peers: Vec<PeerId>,
}

/// Represents a collection of fedimint peer servers
impl FederationTest {
    /// Returns the first item with the given module id from the last consensus
    /// outcome
    pub async fn find_module_item(&self, id: ModuleInstanceId) -> Option<DynModuleConsensusItem> {
        self.last_consensus
            .lock()
            .await
            .clone()
            .contributions
            .values()
            .flat_map(|items| items.clone())
            .find_map(|ci| match ci {
                ConsensusItem::Module(mci) if mci.module_instance_id() == id => Some(mci),
                _ => None,
            })
    }

    /// Sends a custom proposal, ignoring whatever is in FedimintConsensus
    ///
    /// Useful for simulating malicious federation nodes
    /// Keeps round consensus and signature shares
    pub async fn override_proposal(&self, items: Vec<ConsensusItem>) {
        for server in &self.servers {
            let mut epoch_sig = server
                .lock()
                .await
                .fedimint
                .consensus
                .get_consensus_proposal()
                .await
                .items
                .into_iter()
                .filter(|item| match item {
                    ConsensusItem::EpochOutcomeSignatureShare(_) => true,
                    ConsensusItem::Module(module) if module.module_instance_id() == LEGACY_HARDCODED_INSTANCE_ID_WALLET => {
                        let wallet_item = module.as_any().downcast_ref::<<<Wallet as ServerModule>::Common as ModuleCommon>::ConsensusItem>().expect("test should use fixed module instances");
                        match wallet_item {
                            WalletConsensusItem::RoundConsensus(_) => true,
                            WalletConsensusItem::PegOutSignature(_) => false
                        }
                    },
                    _ => false
                })
                .collect();

            let mut items = items.clone();
            items.append(&mut epoch_sig);

            let proposal = ConsensusProposal {
                items,
                drop_peers: vec![],
                // if we force it, we want to trigger an epoch
                force_new_epoch: true,
            };

            server.lock().await.override_proposal = Some(proposal.clone());
        }
    }

    /// Submit a fedimint transaction to all federation servers
    #[allow(clippy::await_holding_refcell_ref)] // TODO: fix, it's just a test
    pub async fn submit_transaction(
        &self,
        transaction: fedimint_server::transaction::Transaction,
    ) -> Result<(), TransactionSubmissionError> {
        for server in &self.servers {
            server
                .lock()
                .await
                .fedimint
                .consensus
                .api
                .submit_transaction(transaction.clone())
                .await?;
        }
        Ok(())
    }

    /// Get fedimint transaction status from all federation servers
    #[allow(clippy::await_holding_refcell_ref)] // TODO: fix, it's just a test
    pub async fn transaction_status(&self, txid: TransactionId) -> Vec<Option<TransactionStatus>> {
        let mut result = Vec::new();
        for server in &self.servers {
            let status = server
                .lock()
                .await
                .fedimint
                .consensus
                .api
                .transaction_status(txid)
                .await;
            result.push(status);
        }
        result
    }

    /// Returns a fixture that only calls on a subset of the peers.  Note that
    /// PeerIds are always starting at 0 in tests.
    pub async fn subset_peers(&self, peers: &[u16]) -> Self {
        let peers = peers
            .iter()
            .map(|i| PeerId::from(*i))
            .collect::<Vec<PeerId>>();

        FederationTest {
            servers: futures::stream::iter(self.servers.iter())
                .filter(|s| async { peers.contains(&s.lock().await.fedimint.cfg.local.identity) })
                .map(Clone::clone)
                .collect()
                .await,
            wallet: self.wallet.clone(),
            cfg: self.cfg.clone(),
            last_consensus: self.last_consensus.clone(),
            max_balance_sheet: self.max_balance_sheet.clone(),
            decoders: self.decoders.clone(),
            mint_id: self.mint_id,
            ln_id: self.ln_id,
            wallet_id: self.wallet_id,
            connect_info: self.connect_info.clone(),
        }
    }

    /// Spends ecash whether or not the user has exact change
    ///
    /// If the change is not exact, reissues ecash and runs epochs
    pub async fn spend_ecash(
        &self,
        user: &dyn ILegacyTestClient,
        amount: Amount,
    ) -> TieredMulti<SpendableNote> {
        let notes = user.get_stored_ecash(amount).await.unwrap();
        if notes.total_amount() != amount {
            user.reissue(notes).await.unwrap();
            self.run_consensus_epochs(2).await;
            user.await_all_issued().await.unwrap();
        }

        let notes = user.get_stored_ecash(amount).await.unwrap();
        assert_eq!(notes.total_amount(), amount);
        user.remove_stored_ecash(notes.clone()).await;
        notes
    }

    /// Mines a UTXO then mints notes for user, assuring that the balance sheet
    /// of the federation nets out to zero.
    pub async fn mine_and_mint(
        &self,
        user: &dyn ILegacyTestClient,
        bitcoin: &dyn BitcoinTest,
        amount: Amount,
    ) {
        assert_eq!(amount.msats % 1000, 0);
        let sats = bitcoin::Amount::from_sat(amount.msats / 1000);
        self.mine_spendable_utxo(user, bitcoin, sats).await;
        self.mint_notes_for_user(user, amount).await;
    }

    /// Inserts notes directly into the databases of federation nodes, runs
    /// consensus to sign them then fetches the notes for the user client.
    pub async fn mint_notes_for_user(&self, user: &dyn ILegacyTestClient, amount: Amount) {
        self.database_add_notes_for_user(user, amount).await;
        self.run_consensus_epochs(1).await;
        user.await_all_issued().await.unwrap();
    }

    /// Mines a UTXO owned by the federation.
    pub async fn mine_spendable_utxo(
        &self,
        user: &dyn ILegacyTestClient,
        bitcoin: &dyn BitcoinTest,
        amount: bitcoin::Amount,
    ) {
        let address = user.get_new_peg_in_address().await;
        let (txout_proof, btc_transaction) = bitcoin.send_and_mine_block(&address, amount).await;
        let input = user.create_peg_in_proof(txout_proof, btc_transaction);

        for server in &self.servers {
            let svr = server.lock().await;
            let mut dbtx = svr.database.begin_transaction().await;

            {
                let mut module_dbtx = dbtx.with_module_prefix(self.wallet_id);
                module_dbtx
                    .insert_new_entry(
                        &UTXOKey(input.outpoint()),
                        &SpendableUTXO {
                            tweak: input.tweak_contract_key().serialize(),
                            amount: bitcoin::Amount::from_sat(input.tx_output().value),
                        },
                    )
                    .await;
            }

            dbtx.commit_tx().await;
        }
        bitcoin.mine_blocks(10).await;
    }

    /// Removes the ecash nonces from the fed DB to simulate the fed losing
    /// track of what ecash has already been spent
    pub async fn clear_spent_mint_nonces(&self) {
        for server in &self.servers {
            block_on(async {
                let svr = server.lock().await;
                let mut dbtx = svr.database.begin_transaction().await;

                {
                    let mut module_dbtx = dbtx.with_module_prefix(self.mint_id);

                    module_dbtx.remove_by_prefix(&NonceKeyPrefix).await;
                }

                dbtx.commit_tx().await;
            });
        }
    }

    /// Returns the maximum the fed's balance sheet has reached during the test.
    pub fn max_balance_sheet(&self) -> u64 {
        assert!(self.max_balance_sheet.load(Ordering::SeqCst) >= 0);
        self.max_balance_sheet.load(Ordering::SeqCst) as u64
    }

    /// Returns true if all fed members have dropped this peer
    pub async fn has_dropped_peer(&self, peer: u16) -> bool {
        for server in &self.servers {
            let mut s = server.lock().await;
            let proposal = s.fedimint.consensus.get_consensus_proposal().await;
            s.dropped_peers.append(&mut proposal.drop_peers.clone());
            if !s.dropped_peers.contains(&PeerId::from(peer)) {
                return false;
            }
        }
        true
    }

    /// Inserts notes directly into the databases of federation nodes
    pub async fn database_add_notes_for_user(
        &self,
        user: &dyn ILegacyTestClient,
        amount: Amount,
    ) -> OutPoint {
        let bytes: [u8; 32] = rand::random();
        let out_point = OutPoint {
            txid: fedimint_core::TransactionId::from_inner(bytes),
            out_idx: 0,
        };

        let (notes, callback) = user.payable_ecash_tx(amount).await;

        for server in &self.servers {
            let svr = server.lock().await;
            let mut dbtx = svr.database.begin_transaction().await;
            let transaction = fedimint_server::transaction::Transaction {
                inputs: vec![],
                outputs: vec![core::DynOutput::from_typed(
                    self.mint_id,
                    MintOutput(notes.clone()),
                )],
                signature: None,
            };

            dbtx.insert_entry(
                &fedimint_server::db::AcceptedTransactionKey(out_point.txid),
                &fedimint_server::consensus::AcceptedTransaction {
                    epoch: 0,
                    transaction,
                },
            )
            .await;

            svr.fedimint
                .consensus
                .modules
                .get_expect(self.mint_id)
                .apply_output(
                    &mut dbtx.with_module_prefix(self.mint_id),
                    &core::DynOutput::from_typed(self.mint_id, MintOutput(notes.clone())),
                    out_point,
                )
                .await
                .unwrap();
            dbtx.commit_tx().await;
        }
        callback(out_point);
        out_point
    }

    /// Has every federation node broadcast any transactions pending to the
    /// Bitcoin network, otherwise transactions will only get broadcast
    /// every 10 seconds.
    pub async fn broadcast_transactions(&self) {
        for server in &self.servers {
            let svr = server.lock().await;
            let db = svr.database.new_isolated(self.wallet_id);
            let dbtx = block_on(db.begin_transaction());
            block_on(fedimint_wallet_server::broadcast_pending_tx(
                dbtx,
                &svr.bitcoin_rpc,
            ));
        }
    }

    /// Runs `n` epochs in the federation (each guardian node)
    ///
    /// Call this method in tests when some conditions that trigger
    /// new epoch(s) are already in place.
    ///
    /// Wallet chain height can trigger epoch randomly, but since
    /// they will be processed along-side any other epochs you
    /// already expect, nothing is being done about it. It should
    /// not matter, but is worth pointing out.
    ///
    /// # Panics
    ///
    /// Panics if there's an empty proposal.
    #[allow(clippy::await_holding_refcell_ref)]
    pub async fn run_consensus_epochs(&self, epochs: usize) {
        for _ in 0..(epochs) {
            if !self.has_pending_epoch().await {
                panic!("Empty proposals, fed might wait forever");
            }
            self.run_consensus_epochs_wait(1).await.unwrap();
        }
    }

    /// Runs consensus epochs even if the epochs are empty
    pub async fn run_empty_epochs(&self, epochs: usize) {
        for server in &self.servers {
            server.lock().await.fedimint.run_empty_epochs = epochs as u64;
        }

        self.run_consensus_epochs_wait(epochs).await.unwrap();
    }

    /// Process n consensus epoch. Wait for events triggering them in case of
    /// empty proposals.
    ///
    /// If proposals are empty you will need to run a concurrent task that
    /// triggers a new epoch or it will wait forever.
    ///
    /// When conditions triggering proposals are already in place, calling this
    /// functions has the same effect as calling [`run_consensus_epochs`],
    /// as blocking conditions can't happen. However in that situation
    /// calling [`run_consensus_epochs`] is preferable, as it will snappily
    /// panic, instead of hanging indefinitely in case of a bug.
    ///
    /// When called concurrently with actions triggering new epochs, care must
    /// be taken as random epochs due to wallet module height changes can be
    /// triggered randomly, making the use of this function flaky. Typically
    /// `bitcoin.lock_exclusive()` should be called to avoid flakiness, but
    /// that makes the whole test run serially, which is very undesirable.
    /// Prefer structuring your test to not require that (so you can use
    /// `run_consensus_wait` instead).
    pub async fn run_consensus_epochs_wait(&self, epochs: usize) -> anyhow::Result<()> {
        for _ in 0..(epochs) {
            let mut task_group = TaskGroup::new();
            for (i, server) in self.servers.iter().enumerate() {
                let server = server.clone();
                task_group
                    .spawn(format!("server-{i}-consensu_epoch"), move |_| async {
                        Self::consensus_epoch(server, Duration::from_millis(0)).await
                    })
                    .await;
            }
            task_group.join_all(None).await?;

            self.update_last_consensus().await;
        }
        Ok(())
    }

    /// Does any of the modules return consensus proposal that forces a new
    /// epoch
    #[allow(clippy::await_holding_refcell_ref)]
    pub async fn has_pending_epoch(&self) -> bool {
        for server in &self.servers {
            let mut server = server.lock().await;
            let fedimint_server = &mut server.fedimint;

            // Pending transactions will trigger an epoch
            if let Some(Some(_)) = Pin::new(&mut fedimint_server.api_receiver)
                .peek()
                .now_or_never()
            {
                return true;
            }

            let consensus_proposal = fedimint_server.consensus.get_consensus_proposal().await;
            if consensus_proposal.force_new_epoch {
                return true;
            }
        }
        false
    }

    /// Get the consensus items proposed by all the peers
    ///
    /// Notably, unlike [`has_pending_epoch`] this does not return
    /// pending transactions, neither does it ignore consensus items that
    /// actually do not trigger epoch on their own.
    #[allow(clippy::await_holding_refcell_ref)]
    pub async fn get_pending_epoch_proposals(&self) -> Vec<ConsensusItem> {
        let mut proposals = vec![];
        for server in &self.servers {
            for item in server
                .lock()
                .await
                .fedimint
                .consensus
                .get_consensus_proposal()
                .await
                .items
            {
                if !proposals.contains(&item) {
                    proposals.push(item);
                }
            }
        }
        proposals
    }

    /// Runs consensus, but delay peers and only wait for one to complete.
    /// Useful for testing if a peer has become disconnected.
    pub async fn race_consensus_epoch(&self, durations: Vec<Duration>) -> anyhow::Result<()> {
        assert_eq!(durations.len(), self.servers.len());
        // must drop `res` before calling `update_last_consensus`
        {
            let res = select_all(
                self.servers
                    .iter()
                    .zip(durations)
                    .map(|(server, duration)| {
                        Box::pin(Self::consensus_epoch(server.clone(), duration))
                    }),
            )
            .await;

            res.0?;
        }
        self.update_last_consensus().await;
        Ok(())
    }

    /// Force these peers to rejoin consensus, simulating what happens upon node
    /// restart
    #[allow(clippy::await_holding_refcell_ref)]
    pub async fn rejoin_consensus(&self) -> Cancellable<()> {
        for server in &self.servers {
            let mut s = server.lock().await;
            while timeout(Duration::from_millis(500), s.fedimint.connections.receive())
                .await
                .is_ok()
            {
                // clear message buffers, simulating a restarted connection
            }
            s.fedimint.start_consensus().await;
        }
        Ok(())
    }

    // Necessary to allow servers to progress concurrently, should be fine since the
    // same server will never run an epoch concurrently with itself.
    #[allow(clippy::await_holding_refcell_ref)]
    async fn consensus_epoch(
        server: Arc<Mutex<ServerTest>>,
        delay: Duration,
    ) -> anyhow::Result<()> {
        tokio::time::sleep(delay).await;
        let mut server = server.lock().await;
        let mut proposal = server.fedimint.consensus.get_consensus_proposal().await;
        let override_proposal = server.override_proposal.clone();

        server.dropped_peers.append(&mut proposal.drop_peers);

        server.last_consensus = server
            .fedimint
            .run_consensus_epoch(override_proposal, &mut rng())
            .await?;

        for outcome in server.last_consensus.clone() {
            server
                .fedimint
                .process_outcome(outcome)
                .await
                .expect("failed");
        }

        Ok(())
    }

    async fn update_last_consensus(&self) {
        let new_consensus = futures::stream::iter(self.servers.iter())
            .then(|s| s.lock())
            .flat_map(|s| futures::stream::iter(s.last_consensus.clone()))
            .fold(None, |prev: Option<HbbftConsensusOutcome>, c| async {
                if let Some(prev) = prev {
                    if prev.epoch <= c.epoch {
                        Some(c)
                    } else {
                        Some(prev)
                    }
                } else {
                    Some(c)
                }
            })
            .await
            .unwrap();
        let mut last_consensus = self.last_consensus.lock().await;
        let current_consensus = &self
            .servers
            .first()
            .unwrap()
            .lock()
            .await
            .fedimint
            .consensus;

        let audit = block_on(current_consensus.audit());

        if last_consensus.is_empty() || last_consensus.epoch < new_consensus.epoch {
            info!("{}", consensus::debug::epoch_message(&new_consensus));
            info!("\n{}", audit);
            let bs = std::cmp::max(
                self.max_balance_sheet.load(Ordering::SeqCst),
                audit.sum().milli_sat,
            );
            self.max_balance_sheet.store(bs, Ordering::SeqCst);
            *last_consensus = new_consensus;
        }
    }

    async fn new(
        server_config: BTreeMap<PeerId, ServerConfig>,
        database_gen: &impl Fn(ModuleDecoderRegistry) -> Database,
        bitcoin_gen: &impl Fn() -> DynBitcoindRpc,
        connect_gen: &impl Fn(&ServerConfig) -> PeerConnector<EpochMessage>,
        module_inits: ServerModuleGenRegistry,
        task_group: &mut TaskGroup,
    ) -> Self {
        let servers = join_all(server_config.values().map(|cfg| async {
            let btc_rpc = bitcoin_gen();
            let decoders = module_inits.decoders(cfg.iter_module_instances()).unwrap();
            let db = database_gen(decoders.clone());
            let mut task_group = task_group.clone();

            let fedimint = ConsensusServer::new_with(
                cfg.clone(),
                db.clone(),
                module_inits.clone(),
                connect_gen(cfg),
                Default::default(),
                &mut task_group,
            )
            .await
            .expect("failed to init server");

            let api = FedimintServer {
                data_dir: Default::default(),
                settings: ConfigGenSettings {
                    download_token_limit: cfg.local.download_token_limit,
                    p2p_bind: cfg.local.fed_bind,
                    api_bind: cfg.local.api_bind,
                    p2p_url: cfg.local.p2p_endpoints[&cfg.local.identity].url.clone(),
                    api_url: cfg.consensus.api_endpoints[&cfg.local.identity].url.clone(),
                    default_params: Default::default(),
                    module_gens: module_inits.legacy_init_modules(),
                    registry: module_inits.clone(),
                },
                db: db.clone(),
                upgrade_epoch: None,
            };
            api.run_consensus_api(&fedimint.consensus.api, &mut task_group)
                .await
                .expect("api starts");

            Arc::new(Mutex::new(ServerTest {
                fedimint,
                bitcoin_rpc: btc_rpc,
                database: db,
                last_consensus: vec![],
                override_proposal: None,
                dropped_peers: vec![],
            }))
        }))
        .await;

        // Consumes the empty epoch 0 outcome from all servers
        let cfg = server_config.iter().last().unwrap().1.clone();
        let wallet = cfg
            .get_module_config_typed(cfg.get_module_id_by_kind("wallet").unwrap())
            .unwrap();
        let last_consensus = Arc::new(Mutex::new(Batch {
            epoch: 0,
            contributions: BTreeMap::new(),
        }));
        let max_balance_sheet = Arc::new(AtomicI64::new(0));

        FederationTest {
            servers,
            max_balance_sheet,
            last_consensus,
            decoders: module_inits.decoders(cfg.iter_module_instances()).unwrap(),
            cfg: cfg.clone(),
            wallet,
            mint_id: LEGACY_HARDCODED_INSTANCE_ID_MINT,
            ln_id: LEGACY_HARDCODED_INSTANCE_ID_LN,
            wallet_id: LEGACY_HARDCODED_INSTANCE_ID_WALLET,
            connect_info: cfg.get_connect_info(),
        }
    }
}

/// Unwraps a dyn consensus item into a specific one for making assertions
#[track_caller]
pub fn unwrap_item<M: ModuleConsensusItem>(mci: &Option<DynModuleConsensusItem>) -> &M {
    mci.as_ref()
        .expect("Module item exists")
        .as_any()
        .downcast_ref()
        .expect("Unexpected type found")
}
