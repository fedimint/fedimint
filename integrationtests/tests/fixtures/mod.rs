use std::collections::{BTreeMap, HashMap};
use std::env;
use std::future::Future;
use std::iter::repeat;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::{secp256k1, Address, KeyPair};
use fedimint_bitcoind::bitcoincore_rpc::{make_bitcoind_rpc, make_electrum_rpc, make_esplora_rpc};
use fedimint_bitcoind::DynBitcoindRpc;
use fedimint_core::api::WsFederationApi;
use fedimint_core::bitcoin_rpc::read_bitcoin_backend_from_global_env;
use fedimint_core::cancellable::Cancellable;
use fedimint_core::config::{ClientConfig, ClientModuleGenRegistry, ServerModuleGenRegistry};
use fedimint_core::core::{
    DynModuleConsensusItem, ModuleConsensusItem, ModuleInstanceId, LEGACY_HARDCODED_INSTANCE_ID_LN,
    LEGACY_HARDCODED_INSTANCE_ID_MINT, LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::Database;
use fedimint_core::module::registry::{ModuleDecoderRegistry, ModuleRegistry};
use fedimint_core::module::DynServerModuleGen;
use fedimint_core::server::DynServerModule;
use fedimint_core::task::{timeout, TaskGroup};
use fedimint_core::{core, sats, Amount, OutPoint, PeerId, TieredMulti};
use fedimint_ln_client::LightningGateway;
use fedimint_ln_server::LightningGen;
use fedimint_logging::TracingSetup;
use fedimint_mint_server::common::db::NonceKeyPrefix;
use fedimint_mint_server::common::MintOutput;
use fedimint_mint_server::MintGen;
use fedimint_server::config::{ServerConfig, ServerConfigParams};
use fedimint_server::consensus::{
    ConsensusProposal, FedimintConsensus, HbbftConsensusOutcome, TransactionSubmissionError,
};
use fedimint_server::db::GLOBAL_DATABASE_VERSION;
use fedimint_server::net::connect::mock::MockNetwork;
use fedimint_server::net::connect::{Connector, TlsTcpConnector};
use fedimint_server::net::peers::PeerConnector;
use fedimint_server::{consensus, EpochMessage, FedimintServer};
use fedimint_testing::btc::fixtures::FakeBitcoinTest;
use fedimint_testing::btc::BitcoinTest;
use fedimint_testing::ln::fixtures::FakeLightningTest;
use fedimint_testing::ln::LightningTest;
use fedimint_wallet_server::common::config::WalletConfig;
use fedimint_wallet_server::common::db::UTXOKey;
use fedimint_wallet_server::common::{PegOutFees, SpendableUTXO};
use fedimint_wallet_server::{Wallet, WalletGen};
use futures::executor::block_on;
use futures::future::{join_all, select_all};
use futures::{FutureExt, StreamExt};
use hbbft::honey_badger::Batch;
use itertools::Itertools;
use ln_gateway::actor::GatewayActor;
use ln_gateway::client::{DynGatewayClientBuilder, MemDbFactory, StandardGatewayClientBuilder};
use ln_gateway::lnrpc_client::{DynLnRpcClient, NetworkLnRpcClient};
use ln_gateway::Gateway;
use mint_client::mint::SpendableNote;
use mint_client::transaction::legacy::Transaction;
use mint_client::transaction::TransactionBuilder;
use mint_client::{
    module_decode_stubs, Client, GatewayClient, GatewayClientConfig, UserClient, UserClientConfig,
};
use rand::rngs::OsRng;
use rand::RngCore;
use real::{RealBitcoinTest, RealLightningTest};
use tokio::sync::Mutex;
use tracing::info;
use url::Url;

use crate::fixtures::utils::LnRpcAdapter;
use crate::ConsensusItem;

mod real;
mod utils;

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

#[non_exhaustive]
pub struct Fixtures {
    pub fed: FederationTest,
    pub user: UserTest<UserClientConfig>,
    pub bitcoin: Box<dyn BitcoinTest>,
    pub gateway: GatewayTest,
    pub lightning: Box<dyn LightningTest>,
    pub task_group: TaskGroup,
}

/// Helper for generating fixtures, passing them into test code, then shutting
/// down the task thread when the test is complete.
pub async fn test<B>(
    num_peers: u16,
    f: impl FnOnce(
        FederationTest,
        UserTest<UserClientConfig>,
        Box<dyn BitcoinTest>,
        GatewayTest,
        Box<dyn LightningTest>,
    ) -> B,
) -> anyhow::Result<()>
where
    B: Future<Output = ()>,
{
    let fixtures = fixtures(num_peers).await?;
    f(
        fixtures.fed,
        fixtures.user,
        fixtures.bitcoin,
        fixtures.gateway,
        fixtures.lightning,
    )
    .await;
    fixtures.task_group.shutdown_join_all(None).await
}

/// Generates the fixtures for an integration test and spawns API and HBBFT
/// consensus threads for federation nodes starting at port DEFAULT_P2P_PORT.
pub async fn fixtures(num_peers: u16) -> anyhow::Result<Fixtures> {
    let mut task_group = TaskGroup::new();
    let base_port = BASE_PORT.fetch_add(num_peers * 10, Ordering::Relaxed);

    // in case we need to output logs using 'cargo test -- --nocapture'
    if base_port == BASE_PORT_INIT {
        let chrome = env::var_os("FEDIMINT_TRACE_CHROME").map_or(false, |x| !x.is_empty());
        TracingSetup::default().with_chrome(chrome).init()?;
    }

    let peers = (0..num_peers).map(PeerId::from).collect::<Vec<_>>();
    let modules = fedimintd::configure_modules(
        sats(100000),
        bitcoin::network::constants::Network::Regtest,
        10,
    );
    let params = ServerConfigParams::gen_local(&peers, base_port, "test", modules).unwrap();

    let module_inits = ServerModuleGenRegistry::from(vec![
        DynServerModuleGen::from(WalletGen),
        DynServerModuleGen::from(MintGen),
        DynServerModuleGen::from(LightningGen),
    ]);

    let decoders = module_decode_stubs();

    let fixtures = match env::var("FM_TEST_USE_REAL_DAEMONS") {
        Ok(s) if s == "1" => {
            info!("Testing with REAL Bitcoin and Lightning services");
            let mut config_task_group = task_group.make_subgroup().await;
            let (server_config, client_config) =
                distributed_config(&peers, params, module_inits.clone(), &mut config_task_group)
                    .await
                    .expect("distributed config should not be canceled");
            config_task_group
                .shutdown_join_all(None)
                .await
                .expect("Distributed config did not exit cleanly");

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

            let socket_gateway = PathBuf::from(dir.clone()).join("ln1/regtest/lightning-rpc");
            let socket_other = PathBuf::from(dir.clone()).join("ln2/regtest/lightning-rpc");
            let lightning =
                RealLightningTest::new(socket_gateway.clone(), socket_other.clone()).await;

            let lnrpc_addr = env::var("FM_GATEWAY_LIGHTNING_ADDR")
                .expect("FM_GATEWAY_LIGHTNING_ADDR not set")
                .parse::<Url>()
                .expect("Invalid FM_GATEWAY_LIGHTNING_ADDR");
            let lnrpc: DynLnRpcClient = NetworkLnRpcClient::new(lnrpc_addr).await.unwrap().into();
            let lnrpc_adapter = LnRpcAdapter::new(lnrpc);

            let connect_gen =
                |cfg: &ServerConfig| TlsTcpConnector::new(cfg.tls_config()).into_dyn();
            let fed_db = |decoders| Database::new(rocks(dir.clone()), decoders);
            let fed = FederationTest::new(
                server_config,
                &fed_db,
                &|| bitcoin_rpc.clone(),
                &connect_gen,
                module_inits.clone(),
                |_cfg: ServerConfig, _db| Box::pin(async { BTreeMap::default() }),
                &mut task_group,
            )
            .await;

            let user_db = if env::var("FM_CLIENT_SQLITE") == Ok(s) {
                let db_name = format!("client-{}", rng().next_u64());
                Database::new(sqlite(dir.clone(), db_name).await, decoders.clone())
            } else {
                Database::new(rocks(dir.clone()), decoders.clone())
            };

            let user_cfg = UserClientConfig(client_config.clone());
            let user = UserTest::new(Arc::new(
                create_user_client(
                    user_cfg,
                    decoders.clone(),
                    module_inits.to_client(),
                    peers,
                    user_db,
                )
                .await,
            ));
            user.client.await_consensus_block_height(0).await?;

            let gateway = GatewayTest::new(
                lnrpc_adapter,
                client_config.clone(),
                decoders,
                module_inits.to_client(),
                lightning.gateway_node_pub_key,
                base_port + (2 * num_peers) + 1,
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
            let server_config = ServerConfig::trusted_dealer_gen(&params, module_inits.clone());
            let client_config = server_config[&PeerId::from(0)]
                .consensus
                .to_config_response(&module_inits)
                .client;

            let bitcoin = FakeBitcoinTest::new();
            let bitcoin_rpc = || bitcoin.clone().into();
            let bitcoin_rpc_2: DynBitcoindRpc = bitcoin.clone().into();

            let lightning = FakeLightningTest::new();
            let lnrpc_adapter = LnRpcAdapter::new(lightning.clone().into());

            let net = MockNetwork::new();
            let net_ref = &net;
            let connect_gen =
                move |cfg: &ServerConfig| net_ref.connector(cfg.local.identity).into_dyn();

            let fed_db = |decoders| Database::new(MemDatabase::new(), decoders);
            let fed = FederationTest::new(
                server_config,
                &fed_db,
                &bitcoin_rpc,
                &connect_gen,
                module_inits.clone(),
                // the things dealing with async makes us do...
                // if you know how to make it better, please do --dpc
                |cfg: ServerConfig, db: Database| {
                    Box::pin({
                        let bitcoin_rpc_2 = bitcoin_rpc_2.clone();
                        let mut task_group = task_group.clone();
                        async move {
                            BTreeMap::from([(
                                "wallet",
                                Wallet::new_with_bitcoind(
                                    cfg.get_module_config_typed(
                                        cfg.get_module_id_by_kind("wallet").unwrap(),
                                    )
                                    .unwrap(),
                                    db,
                                    bitcoin_rpc_2.clone(),
                                    &mut task_group,
                                )
                                .await
                                .expect("Couldn't create wallet")
                                .into(),
                            )])
                        }
                    })
                },
                &mut task_group.clone(),
            )
            .await;

            let user_db = Database::new(MemDatabase::new(), module_decode_stubs());
            let user_cfg = UserClientConfig(client_config.clone());
            let user = UserTest::new(Arc::new(
                create_user_client(
                    user_cfg,
                    decoders.clone(),
                    module_inits.to_client(),
                    peers,
                    user_db,
                )
                .await,
            ));
            user.client.await_consensus_block_height(0).await?;

            let gateway = GatewayTest::new(
                lnrpc_adapter,
                client_config.clone(),
                decoders,
                module_inits.to_client(),
                lightning.gateway_node_pub_key,
                base_port + (2 * num_peers) + 1,
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
    while fixtures.user.client.fetch_active_gateway().await.is_err() {
        tokio::time::sleep(Duration::from_millis(100)).await;
        info!("Waiting for gateway to register");
    }

    Ok(fixtures)
}

pub fn peers(peers: &[u16]) -> Vec<PeerId> {
    peers
        .iter()
        .map(|i| PeerId::from(*i))
        .collect::<Vec<PeerId>>()
}

/// Creates a new user client connected to the given peers
pub async fn create_user_client(
    config: UserClientConfig,
    decoders: ModuleDecoderRegistry,
    module_gens: ClientModuleGenRegistry,
    peers: Vec<PeerId>,
    db: Database,
) -> UserClient {
    let api = WsFederationApi::new(
        config
            .0
            .nodes
            .iter()
            .enumerate()
            .filter(|(id, _)| peers.contains(&PeerId::from(*id as u16)))
            .map(|(id, node)| (PeerId::from(id as u16), node.url.clone()))
            .collect(),
    )
    .into();

    UserClient::new_with_api(config, decoders, module_gens, db, api, Default::default()).await
}

async fn distributed_config(
    peers: &[PeerId],
    params: HashMap<PeerId, ServerConfigParams>,
    registry: ServerModuleGenRegistry,
    task_group: &mut TaskGroup,
) -> Cancellable<(BTreeMap<PeerId, ServerConfig>, ClientConfig)> {
    let configs: Vec<(PeerId, ServerConfig)> = join_all(peers.iter().map(|peer| {
        let params = params.clone();

        let mut task_group = task_group.clone();
        let registry = registry.clone();

        async move {
            let our_params = params[peer].clone();

            let cfg = ServerConfig::distributed_gen(&our_params, registry, &mut task_group);
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
    pub actor: Arc<GatewayActor>,
    pub adapter: Arc<LnRpcAdapter>,
    pub keys: LightningGateway,
    pub user: UserTest<GatewayClientConfig>,
    pub client: Arc<GatewayClient>,
}

impl GatewayTest {
    async fn new(
        adapter: LnRpcAdapter,
        client_config: ClientConfig,
        decoders: ModuleDecoderRegistry,
        module_gens: ClientModuleGenRegistry,
        node_pub_key: secp256k1::PublicKey,
        bind_port: u16,
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

        let gateway = Gateway::new(
            adapter.clone().into(),
            client_builder.clone(),
            decoders.clone(),
            module_gens.clone(),
            TaskGroup::new(),
        )
        .await;

        let client = Arc::new(
            client_builder
                .build(gw_client_cfg.clone(), decoders, module_gens)
                .await
                .expect("Could not build gateway client"),
        );

        let actor = gateway
            .connect_federation(client.clone(), vec![])
            .await
            .expect("Could not connect federation");
        // Note: We don't run the gateway in test scenarios

        // Create a user test from gateway federation client
        let user = UserTest::new(client.clone());

        GatewayTest {
            actor,
            adapter: Arc::new(adapter),
            keys,
            user,
            client,
        }
    }
}

#[derive(Clone)]
pub struct UserTest<C> {
    pub client: Arc<Client<C>>,
    pub config: C,
}

impl UserTest<UserClientConfig> {
    /// Create a user that communicates only with a subset of peers
    pub async fn new_user_with_peers(&self, peers: Vec<PeerId>) -> UserTest<UserClientConfig> {
        let user = create_user_client(
            self.config.clone(),
            self.client.decoders().clone(),
            self.client.module_gens().clone(),
            peers,
            Database::new(MemDatabase::new(), module_decode_stubs()),
        )
        .await;
        UserTest::new(Arc::new(user))
    }
}

impl<T: AsRef<ClientConfig> + Clone + Send> UserTest<T> {
    pub fn new(client: Arc<Client<T>>) -> Self {
        let config = client.config();
        UserTest { client, config }
    }

    /// Creates a transaction for testing submissions to the federation
    pub async fn tx_with_change(&self, builder: TransactionBuilder, change: Amount) -> Transaction {
        let mint = self.client.mint_client();
        let mut dbtx = mint.start_dbtx().await;

        builder
            .build_with_change(
                self.client.mint_client(),
                &mut dbtx,
                rng(),
                vec![change],
                &secp(),
            )
            .await
    }

    /// Helper for readability
    pub async fn set_notes_per_denomination(&self, notes: u16) {
        self.client
            .mint_client()
            .set_notes_per_denomination(notes)
            .await;
    }

    /// Helper to simplify the peg_out method calls
    pub async fn peg_out(&self, amount: u64, address: &Address) -> (PegOutFees, OutPoint) {
        let peg_out = self
            .client
            .new_peg_out_with_fees(bitcoin::Amount::from_sat(amount), address.clone())
            .await
            .unwrap();
        let out_point = self.client.peg_out(peg_out.clone(), rng()).await.unwrap();
        (peg_out.fees, out_point)
    }

    /// Returns sum total of all notes
    pub async fn total_notes(&self) -> Amount {
        self.client.notes().await.total_amount()
    }

    pub async fn assert_total_notes(&self, amount: Amount) {
        self.client.fetch_all_notes().await.unwrap();
        assert_eq!(self.total_notes().await, amount);
    }

    /// Asserts the amounts are equal to the denominations held by the user
    pub fn assert_note_amounts(&self, amounts: Vec<Amount>) {
        block_on(self.client.fetch_all_notes()).unwrap();
        let notes = block_on(self.client.notes());
        let user_amounts = notes
            .iter()
            .flat_map(|(a, c)| repeat(*a).take(c.len()))
            .sorted()
            .collect::<Vec<Amount>>();

        assert_eq!(user_amounts, amounts);
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
}

struct ServerTest {
    fedimint: FedimintServer,
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
    /// Useful for simulating malicious federation nodes
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
                .filter(|item| matches!(item, ConsensusItem::EpochOutcomeSignatureShare(_)))
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
                .submit_transaction(transaction.clone())
                .await?;
        }
        Ok(())
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
        }
    }

    /// Helper to issue change for a user
    pub async fn spend_ecash<C: AsRef<ClientConfig> + Clone + Send>(
        &self,
        user: &UserTest<C>,
        amount: Amount,
    ) -> TieredMulti<SpendableNote> {
        // We mimic the logic in the spend_ecash function because we need to know
        // whether we will be running 2 epochs for a reissue or not
        let notes = user.client.mint_client().select_notes(amount).await;
        if notes.unwrap().total_amount() == amount {
            return user.client.spend_ecash(amount, rng()).await.unwrap();
        }
        user.client.remint_ecash(amount, rng()).await.unwrap();
        self.run_consensus_epochs(2).await;
        user.client.remint_ecash_await(amount).await.unwrap()
    }

    /// Mines a UTXO then mints notes for user, assuring that the balance sheet
    /// of the federation nets out to zero.
    pub async fn mine_and_mint<C: AsRef<ClientConfig> + Clone + Send>(
        &self,
        user: &UserTest<C>,
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
    pub async fn mint_notes_for_user<C: AsRef<ClientConfig> + Clone + Send>(
        &self,
        user: &UserTest<C>,
        amount: Amount,
    ) {
        self.database_add_notes_for_user(user, amount).await;
        self.run_consensus_epochs(1).await;
        user.client.fetch_all_notes().await.unwrap();
    }

    /// Mines a UTXO owned by the federation.
    pub async fn mine_spendable_utxo<C: AsRef<ClientConfig> + Clone + Send>(
        &self,
        user: &UserTest<C>,
        bitcoin: &dyn BitcoinTest,
        amount: bitcoin::Amount,
    ) {
        let address = user.client.get_new_pegin_address(rng()).await;
        let (txout_proof, btc_transaction) = bitcoin.send_and_mine_block(&address, amount).await;
        let (_, input) = user
            .client
            .wallet_client()
            .create_pegin_input(txout_proof, btc_transaction)
            .await
            .unwrap();

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
                    .await
                    .expect("DB Error");
            }

            dbtx.commit_tx().await.expect("DB Error");
        }
        bitcoin
            .mine_blocks(user.client.wallet_client().config.finality_delay as u64)
            .await;
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

                    module_dbtx
                        .remove_by_prefix(&NonceKeyPrefix)
                        .await
                        .expect("DB Error");
                }

                dbtx.commit_tx().await.expect("DB Error");
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
    pub async fn database_add_notes_for_user<C: AsRef<ClientConfig> + Clone + Send>(
        &self,
        user: &UserTest<C>,
        amount: Amount,
    ) -> OutPoint {
        let bytes: [u8; 32] = rand::random();
        let out_point = OutPoint {
            txid: fedimint_core::TransactionId::from_inner(bytes),
            out_idx: 0,
        };

        user.client
            .receive_notes(amount, |notes| async move {
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
                    .await
                    .expect("DB Error");

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
                    dbtx.commit_tx().await.expect("DB Error");
                }
                out_point
            })
            .await;
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
            if let Some(Some(_)) = Pin::new(&mut fedimint_server.tx_receiver)
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
        let consensus = server.fedimint.consensus.clone();

        let overrider = server.override_proposal.clone();
        let proposal = async { overrider.unwrap_or(consensus.get_consensus_proposal().await) };
        server
            .dropped_peers
            .append(&mut consensus.get_consensus_proposal().await.drop_peers);

        server.last_consensus = server
            .fedimint
            .run_consensus_epoch(proposal, &mut rng())
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
        override_modules: impl Fn(
            ServerConfig,
            Database,
        ) -> Pin<
            Box<dyn Future<Output = BTreeMap<&'static str, DynServerModule>>>,
        >,
        task_group: &mut TaskGroup,
    ) -> Self {
        let servers = join_all(server_config.values().map(|cfg| async {
            let btc_rpc = bitcoin_gen();
            let decoders = module_inits.decoders(cfg.iter_module_instances()).unwrap();
            let db = database_gen(decoders.clone());
            let mut task_group = task_group.clone();

            let mut override_modules = override_modules(cfg.clone(), db.clone()).await;

            let mut modules = BTreeMap::new();
            let env_vars = FedimintConsensus::get_env_vars_map();

            fedimint_core::db::apply_migrations(
                &db,
                "Global".to_string(),
                GLOBAL_DATABASE_VERSION,
                fedimint_server::db::get_global_database_migrations(),
            )
            .await
            .unwrap_or_else(|_| panic!("Error while applying global database migrations"));

            for (kind, gen) in module_inits.legacy_init_order_iter() {
                let id = cfg.get_module_id_by_kind(kind.clone()).unwrap();
                if let Some(module) = override_modules.remove(kind.as_str()) {
                    info!(module_instance_id = id, kind = %kind, "Use overriden module");
                    modules.insert(id, module);
                } else {
                    info!(module_instance_id = id, kind = %kind, "Init module");

                    let isolated_db = db.new_isolated(id);
                    fedimint_core::db::apply_migrations(
                        &isolated_db,
                        kind.to_string(),
                        gen.database_version(),
                        gen.get_database_migrations(),
                    )
                    .await
                    .unwrap_or_else(|_| {
                        panic!("Error while applying database migrations for module {kind}")
                    });

                    let module = gen
                        .init(
                            cfg.get_module_config(id).unwrap(),
                            isolated_db,
                            &env_vars,
                            &mut task_group,
                        )
                        .await
                        .unwrap();
                    modules.insert(id, module);
                }
            }

            let (consensus, tx_receiver) = FedimintConsensus::new_with_modules(
                cfg.clone(),
                db.clone(),
                module_inits.clone(),
                ModuleRegistry::from(modules),
            );
            let decoders = consensus.decoders();

            let fedimint = FedimintServer::new_with(
                cfg.clone(),
                consensus,
                tx_receiver,
                connect_gen(cfg),
                decoders,
                &mut task_group,
            )
            .await;

            let cfg = cfg.clone();
            let consensus = fedimint.consensus.clone();
            task_group
                .spawn("rpc server", move |handle| async {
                    fedimint_server::net::api::run_server(cfg, consensus, handle).await
                })
                .await;

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
            cfg,
            wallet,
            mint_id: LEGACY_HARDCODED_INSTANCE_ID_MINT,
            ln_id: LEGACY_HARDCODED_INSTANCE_ID_LN,
            wallet_id: LEGACY_HARDCODED_INSTANCE_ID_WALLET,
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
