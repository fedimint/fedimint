use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::future::Future;
use std::iter::repeat;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::KeyPair;
use bitcoin::{secp256k1, Address};
use cln_rpc::ClnRpc;
use fake::FakeLightningTest;
use fedimint_api::cancellable::Cancellable;
use fedimint_api::config::ClientConfig;
use fedimint_api::core::{
    ConsensusItem as PerModuleConsensusItem, PluginConsensusItem, MODULE_KEY_MINT,
    MODULE_KEY_WALLET,
};
use fedimint_api::db::mem_impl::MemDatabase;
use fedimint_api::db::Database;
use fedimint_api::net::peers::IMuxPeerConnections;
use fedimint_api::task::{timeout, TaskGroup};
use fedimint_api::OutPoint;
use fedimint_api::PeerId;
use fedimint_api::TieredMulti;
use fedimint_api::{sats, Amount};
use fedimint_bitcoind::BitcoindRpc;
use fedimint_ln::LightningGateway;
use fedimint_ln::LightningModule;
use fedimint_mint::{Mint, MintOutput};
use fedimint_server::config::ServerConfigParams;
use fedimint_server::config::{connect, ServerConfig};
use fedimint_server::consensus::{ConsensusProposal, HbbftConsensusOutcome};
use fedimint_server::consensus::{FedimintConsensus, TransactionSubmissionError};
use fedimint_server::multiplexed::PeerConnectionMultiplexer;
use fedimint_server::net::connect::mock::MockNetwork;
use fedimint_server::net::connect::{Connector, TlsTcpConnector};
use fedimint_server::net::peers::PeerConnector;
use fedimint_server::{all_decoders, consensus, EpochMessage, FedimintServer};
use fedimint_testing::btc::{fixtures::FakeBitcoinTest, BitcoinTest};
use fedimint_wallet::config::WalletConfig;
use fedimint_wallet::db::UTXOKey;
use fedimint_wallet::SpendableUTXO;
use fedimint_wallet::Wallet;
use fedimint_wallet::WalletConsensusItem;
use futures::executor::block_on;
use futures::future::{join_all, select_all};
use hbbft::honey_badger::Batch;
use itertools::Itertools;
use lightning_invoice::Invoice;
use ln_gateway::{
    actor::GatewayActor,
    client::{GatewayClientBuilder, MemDbFactory, StandardGatewayClientBuilder},
    config::GatewayConfig,
    rpc::GatewayRequest,
    LnGateway,
};
use mint_client::{
    api::WsFederationApi, mint::SpendableNote, Client, FederationId, GatewayClient,
    GatewayClientConfig, UserClient, UserClientConfig,
};
use rand::rngs::OsRng;
use rand::RngCore;
use real::{RealBitcoinTest, RealLightningTest};
use tokio::sync::Mutex;
use tracing::info;
use tracing_subscriber::EnvFilter;
use url::Url;

use crate::fixtures::utils::LnRpcAdapter;
use crate::ConsensusItem;

mod fake;
mod real;
mod utils;

static BASE_PORT: AtomicU16 = AtomicU16::new(4000_u16);

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

/// Helper for generating fixtures, passing them into test code, then shutting down the task thread
/// when the test is complete.
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
    fixtures.task_group.shutdown_join_all().await
}

/// Generates the fixtures for an integration test and spawns API and HBBFT consensus threads for
/// federation nodes starting at port 4000.
pub async fn fixtures(num_peers: u16) -> anyhow::Result<Fixtures> {
    let mut task_group = TaskGroup::new();
    let base_port = BASE_PORT.fetch_add(num_peers * 10, Ordering::Relaxed);

    // in case we need to output logs using 'cargo test -- --nocapture'
    if base_port == 4000 {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new("info,fedimint::consensus=warn")),
            )
            .init();
    }
    let peers = (0..num_peers as u16).map(PeerId::from).collect::<Vec<_>>();
    let params =
        ServerConfigParams::gen_local(&peers, sats(1000), base_port, "test", "127.0.0.1:18443");
    let max_evil = hbbft::util::max_faulty(peers.len());

    match env::var("FM_TEST_DISABLE_MOCKS") {
        Ok(s) if s == "1" => {
            info!("Testing with REAL Bitcoin and Lightning services");
            let (server_config, client_config) =
                distributed_config(&peers, params, max_evil, &mut task_group)
                    .await
                    .expect("distributed config should not be canceled");

            let dir = env::var("FM_TEST_DIR").expect("Must have test dir defined for real tests");
            let wallet_config: WalletConfig = server_config
                .iter()
                .last()
                .unwrap()
                .1
                .get_module_config("wallet")
                .unwrap();
            let bitcoin_rpc = fedimint_bitcoind::bitcoincore_rpc::make_bitcoind_rpc(
                &wallet_config.btc_rpc,
                task_group.make_handle(),
            )
            .expect("Could not create bitcoinrpc");
            let bitcoin = RealBitcoinTest::new(&wallet_config.btc_rpc);
            let socket_gateway = PathBuf::from(dir.clone()).join("ln1/regtest/lightning-rpc");
            let socket_other = PathBuf::from(dir.clone()).join("ln2/regtest/lightning-rpc");
            let lightning =
                RealLightningTest::new(socket_gateway.clone(), socket_other.clone()).await;
            let gateway_lightning_rpc = Mutex::new(
                ClnRpc::new(socket_gateway.clone())
                    .await
                    .expect("connect to ln_socket"),
            );
            let lightning_rpc_adapter = LnRpcAdapter::new(Box::new(gateway_lightning_rpc));

            let connect_gen =
                |cfg: &ServerConfig| TlsTcpConnector::new(cfg.tls_config()).into_dyn();
            let fed_db = || rocks(dir.clone()).into();
            let fed = FederationTest::new(
                server_config,
                &fed_db,
                &|| bitcoin_rpc.clone(),
                &connect_gen,
                &mut task_group,
            )
            .await;

            let user_db = rocks(dir.clone()).into();
            let user_cfg = UserClientConfig(client_config.clone());
            let user = UserTest::new(Arc::new(create_user_client(user_cfg, peers, user_db).await));
            user.client.await_consensus_block_height(0).await?;

            let gateway = GatewayTest::new(
                lightning_rpc_adapter,
                client_config.clone(),
                lightning.gateway_node_pub_key,
                base_port + (2 * num_peers) + 1,
            )
            .await;

            Ok(Fixtures {
                fed,
                user,
                bitcoin: Box::new(bitcoin),
                gateway,
                lightning: Box::new(lightning),
                task_group,
            })
        }
        _ => {
            info!("Testing with FAKE Bitcoin and Lightning services");
            let (server_config, client_config) =
                ServerConfig::trusted_dealer_gen(&peers, &params, OsRng);

            let bitcoin = FakeBitcoinTest::new();
            let bitcoin_rpc = || bitcoin.clone().into();
            let lightning = FakeLightningTest::new();
            let ln_rpc_adapter = LnRpcAdapter::new(Box::new(lightning.clone()));
            let net = MockNetwork::new();
            let net_ref = &net;
            let connect_gen = move |cfg: &ServerConfig| net_ref.connector(cfg.identity).into_dyn();

            let fed_db = || MemDatabase::new().into();
            let fed = FederationTest::new(
                server_config,
                &fed_db,
                &bitcoin_rpc,
                &connect_gen,
                &mut task_group,
            )
            .await;

            let user_db = MemDatabase::new().into();
            let user_cfg = UserClientConfig(client_config.clone());
            let user = UserTest::new(Arc::new(create_user_client(user_cfg, peers, user_db).await));
            user.client.await_consensus_block_height(0).await?;

            let gateway = GatewayTest::new(
                ln_rpc_adapter,
                client_config.clone(),
                lightning.gateway_node_pub_key,
                base_port + (2 * num_peers) + 1,
            )
            .await;

            Ok(Fixtures {
                fed,
                user,
                bitcoin: Box::new(bitcoin),
                gateway,
                lightning: Box::new(lightning),
                task_group,
            })
        }
    }
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

    UserClient::new_with_api(config, db, api, Default::default()).await
}

async fn distributed_config(
    peers: &[PeerId],
    params: HashMap<PeerId, ServerConfigParams>,
    _max_evil: usize,
    task_group: &mut TaskGroup,
) -> Cancellable<(BTreeMap<PeerId, ServerConfig>, ClientConfig)> {
    let configs: Cancellable<Vec<(PeerId, ServerConfig)>> = join_all(peers.iter().map(|peer| {
        let params = params.clone();
        let peers = peers.to_vec();

        let mut task_group = task_group.clone();

        async move {
            let our_params = params[peer].clone();
            let server_conn = connect(
                our_params.server_dkg.clone(),
                our_params.tls.clone(),
                &mut task_group,
            )
            .await;
            let connections = PeerConnectionMultiplexer::new(server_conn).into_dyn();

            let rng = OsRng;
            let cfg = ServerConfig::distributed_gen(
                &connections,
                peer,
                &peers,
                &our_params,
                rng,
                &mut task_group,
            );
            (*peer, cfg.await.expect("generation failed"))
        }
    }))
    .await
    .into_iter()
    .map(|(peer_id, maybe_cancelled)| maybe_cancelled.map(|v| (peer_id, v)))
    .collect();

    let configs = configs?;

    let (_, config) = configs.first().unwrap().clone();

    Ok((configs.into_iter().collect(), config.to_client_config()))
}

fn rocks(dir: String) -> fedimint_rocksdb::RocksDb {
    let db_dir = PathBuf::from(dir).join(format!("db-{}", rng().next_u64()));
    fedimint_rocksdb::RocksDb::open(db_dir).unwrap()
}

#[async_trait]
pub trait LightningTest {
    /// Creates invoice from a non-gateway LN node
    async fn invoice(&self, amount: Amount, expiry_time: Option<u64>) -> Invoice;

    /// Returns the amount that the gateway LN node has sent
    async fn amount_sent(&self) -> Amount;
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
        ln_client_adapter: LnRpcAdapter,
        client_config: ClientConfig,
        node_pub_key: secp256k1::PublicKey,
        bind_port: u16,
    ) -> Self {
        let mut rng = OsRng;
        let ctx = bitcoin::secp256k1::Secp256k1::new();
        let kp = KeyPair::new(&ctx, &mut rng);

        let keys = LightningGateway {
            mint_pub_key: kp.x_only_public_key().0,
            node_pub_key,
            api: Url::parse("http://example.com")
                .expect("Could not parse URL to generate GatewayClientConfig API endpoint"),
        };

        let bind_addr: SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
        let announce_addr = Url::parse(format!("http://{}", bind_addr).as_str())
            .expect("Could not parse URL to generate GatewayClientConfig API endpoint");
        let gw_client_cfg = GatewayClientConfig {
            client_config: client_config.clone(),
            redeem_key: kp,
            timelock_delta: 10,
            api: announce_addr.clone(),
            node_pub_key,
        };

        // Create federation client builder for the gateway
        let client_builder: GatewayClientBuilder =
            StandardGatewayClientBuilder::new(PathBuf::new(), MemDbFactory.into()).into();

        let (sender, receiver) = tokio::sync::mpsc::channel::<GatewayRequest>(100);
        let adapter = Arc::new(ln_client_adapter);
        let ln_rpc = Arc::clone(&adapter);

        let gw_cfg = GatewayConfig {
            bind_address: bind_addr,
            announce_address: announce_addr,
            password: "abc".into(),
            default_federation: FederationId(gw_client_cfg.client_config.federation_name.clone()),
        };

        let gateway = LnGateway::new(
            gw_cfg,
            ln_rpc,
            client_builder.clone(),
            sender,
            receiver,
            TaskGroup::new(),
        )
        .await;

        let client = Arc::new(
            client_builder
                .build(gw_client_cfg.clone())
                .await
                .expect("Could not build gateway client"),
        );

        let actor = gateway
            .connect_federation(client.clone())
            .await
            .expect("Could not connect federation");
        // Note: We don't run the gateway in test scenarios

        // Create a user test from gateway federation client
        let user = UserTest::new(client.clone());

        GatewayTest {
            actor,
            adapter,
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
    pub async fn new_user_with_peers(&self, peers: Vec<PeerId>) -> UserTest<UserClientConfig> {
        let user = create_user_client(self.config.clone(), peers, MemDatabase::new().into()).await;
        UserTest::new(Arc::new(user))
    }
}

impl<T: AsRef<ClientConfig> + Clone> UserTest<T> {
    pub fn new(client: Arc<Client<T>>) -> Self {
        let config = client.config();
        UserTest { client, config }
    }

    /// Helper to simplify the peg_out method calls
    pub async fn peg_out(&self, amount: u64, address: &Address) -> (Amount, OutPoint) {
        let peg_out = self
            .client
            .new_peg_out_with_fees(bitcoin::Amount::from_sat(amount), address.clone())
            .await
            .unwrap();
        let out_point = self.client.peg_out(peg_out.clone(), rng()).await.unwrap();
        (peg_out.fees.amount().into(), out_point)
    }

    /// Returns the amount denominations of all coins from lowest to highest
    pub async fn coin_amounts(&self) -> Vec<Amount> {
        self.client
            .coins()
            .await
            .iter_tiers()
            .flat_map(|(a, c)| repeat(*a).take(c.len()))
            .sorted()
            .collect::<Vec<Amount>>()
    }

    /// Returns sum total of all coins
    pub async fn total_coins(&self) -> Amount {
        self.client.coins().await.total_amount()
    }

    pub async fn assert_total_coins(&self, amount: Amount) {
        self.client.fetch_all_coins().await;
        assert_eq!(self.total_coins().await, amount);
    }
    pub async fn assert_coin_amounts(&self, amounts: Vec<Amount>) {
        self.client.fetch_all_coins().await;
        assert_eq!(self.coin_amounts().await, amounts);
    }
}

pub struct FederationTest {
    servers: Vec<Rc<RefCell<ServerTest>>>,
    last_consensus: Rc<RefCell<HbbftConsensusOutcome>>,
    max_balance_sheet: Rc<RefCell<i64>>,
    pub wallet: WalletConfig,
    pub cfg: ServerConfig,
}

struct ServerTest {
    fedimint: FedimintServer,
    last_consensus: Vec<HbbftConsensusOutcome>,
    bitcoin_rpc: BitcoindRpc,
    database: Database,
    override_proposal: Option<ConsensusProposal>,
    dropped_peers: Vec<PeerId>,
}

/// Represents a collection of fedimint peer servers
impl FederationTest {
    /// Returns the outcome of the last consensus epoch
    pub fn last_consensus(&self) -> HbbftConsensusOutcome {
        self.last_consensus.borrow().clone()
    }

    /// Returns the items that were in the last consensus
    /// Filters out redundant consensus rounds where the block height doesn't change
    pub fn last_consensus_items(&self) -> Vec<ConsensusItem> {
        self.last_consensus()
            .contributions
            .values()
            .flat_map(|items| items.clone())
            .collect()
    }

    /// Sends a custom proposal, ignoring whatever is in FedimintConsensus
    /// Useful for simulating malicious federation nodes
    pub fn override_proposal(&self, items: Vec<ConsensusItem>) {
        for server in &self.servers {
            let mut epoch_sig =
                block_on(server.borrow().fedimint.consensus.get_consensus_proposal())
                    .items
                    .into_iter()
                    .filter(|item| matches!(item, ConsensusItem::EpochOutcomeSignatureShare(_)))
                    .collect();

            let mut items = items.clone();
            items.append(&mut epoch_sig);

            let proposal = ConsensusProposal {
                items,
                drop_peers: vec![],
            };

            server.borrow_mut().override_proposal = Some(proposal.clone());
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
                .borrow_mut()
                .fedimint
                .consensus
                .submit_transaction(transaction.clone())
                .await?;
        }
        Ok(())
    }

    /// Returns a fixture that only calls on a subset of the peers.  Note that PeerIds are always
    /// starting at 0 in tests.
    pub fn subset_peers(&self, peers: &[u16]) -> Self {
        let peers = peers
            .iter()
            .map(|i| PeerId::from(*i))
            .collect::<Vec<PeerId>>();

        FederationTest {
            servers: self
                .servers
                .iter()
                .filter(|s| peers.contains(&s.as_ref().borrow().fedimint.cfg.identity))
                .map(Rc::clone)
                .collect(),
            wallet: self.wallet.clone(),
            cfg: self.cfg.clone(),
            last_consensus: self.last_consensus.clone(),
            max_balance_sheet: self.max_balance_sheet.clone(),
        }
    }

    /// Helper to issue change for a user
    pub async fn spend_ecash<C: AsRef<ClientConfig> + Clone>(
        &self,
        user: &UserTest<C>,
        amount: Amount,
    ) -> TieredMulti<SpendableNote> {
        let coins = user
            .client
            .mint_client()
            .select_coins(amount)
            .await
            .unwrap();
        if coins.total_amount() == amount {
            return user.client.spend_ecash(amount, rng()).await.unwrap();
        }

        tokio::join!(
            user.client.spend_ecash(amount, rng()),
            self.await_consensus_epochs(2)
        )
        .0
        .unwrap()
    }

    /// Mines a UTXO then mints coins for user, assuring that the balance sheet of the federation
    /// nets out to zero.
    pub async fn mine_and_mint<C: AsRef<ClientConfig> + Clone>(
        &self,
        user: &UserTest<C>,
        bitcoin: &dyn BitcoinTest,
        amount: Amount,
    ) {
        assert_eq!(amount.msats % 1000, 0);
        let sats = bitcoin::Amount::from_sat(amount.msats / 1000);
        self.mine_spendable_utxo(user, bitcoin, sats).await;
        self.mint_coins_for_user(user, amount).await;
    }

    /// Inserts coins directly into the databases of federation nodes, runs consensus to sign them
    /// then fetches the coins for the user client.
    pub async fn mint_coins_for_user<C: AsRef<ClientConfig> + Clone>(
        &self,
        user: &UserTest<C>,
        amount: Amount,
    ) {
        self.database_add_coins_for_user(user, amount).await;
        self.run_consensus_epochs(1).await;
        user.client.fetch_all_coins().await;
    }

    /// Mines a UTXO owned by the federation.
    pub async fn mine_spendable_utxo<C: AsRef<ClientConfig> + Clone>(
        &self,
        user: &UserTest<C>,
        bitcoin: &dyn BitcoinTest,
        amount: bitcoin::Amount,
    ) {
        let address = user.client.get_new_pegin_address(rng()).await;
        let (txout_proof, btc_transaction) = bitcoin.send_and_mine_block(&address, amount);
        let (_, input) = user
            .client
            .wallet_client()
            .create_pegin_input(txout_proof, btc_transaction)
            .await
            .unwrap();

        for server in &self.servers {
            block_on(async {
                let svr = server.borrow_mut();
                let mut dbtx = svr.database.begin_transaction(all_decoders()).await;

                dbtx.insert_new_entry(
                    &UTXOKey(input.outpoint()),
                    &SpendableUTXO {
                        tweak: input.tweak_contract_key().serialize(),
                        amount: bitcoin::Amount::from_sat(input.tx_output().value),
                    },
                )
                .await
                .expect("DB Error");
                dbtx.commit_tx().await.expect("DB Error");
            });
        }
    }

    /// Returns the maximum the fed's balance sheet has reached during the test.
    pub fn max_balance_sheet(&self) -> u64 {
        assert!(*self.max_balance_sheet.borrow() >= 0);
        *self.max_balance_sheet.borrow() as u64
    }

    /// Returns true if all fed members have dropped this peer
    pub fn has_dropped_peer(&self, peer: u16) -> bool {
        for server in &self.servers {
            let mut s = server.borrow_mut();
            let proposal = block_on(s.fedimint.consensus.get_consensus_proposal());
            s.dropped_peers.append(&mut proposal.drop_peers.clone());
            if !s.dropped_peers.contains(&PeerId::from(peer)) {
                return false;
            }
        }
        true
    }

    /// Inserts coins directly into the databases of federation nodes
    pub async fn database_add_coins_for_user<C: AsRef<ClientConfig> + Clone>(
        &self,
        user: &UserTest<C>,
        amount: Amount,
    ) -> OutPoint {
        let bytes: [u8; 32] = rand::random();
        let out_point = OutPoint {
            txid: fedimint_api::TransactionId::from_inner(bytes),
            out_idx: 0,
        };

        user.client
            .receive_coins(amount, |tokens| async move {
                for server in &self.servers {
                    let svr = server.borrow_mut();
                    let mut dbtx = svr.database.begin_transaction(all_decoders()).await;
                    let transaction = fedimint_server::transaction::Transaction {
                        inputs: vec![],
                        outputs: vec![MintOutput(tokens.clone()).into()],
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
                        .module(MODULE_KEY_MINT)
                        .apply_output(&mut dbtx, &MintOutput(tokens.clone()).into(), out_point)
                        .await
                        .unwrap();
                    dbtx.commit_tx().await.expect("DB Error");
                }
                out_point
            })
            .await;
        out_point
    }

    /// Has every federation node broadcast any transactions pending to the Bitcoin network, otherwise
    /// transactions will only get broadcast every 10 seconds.
    pub async fn broadcast_transactions(&self) {
        for server in &self.servers {
            let svr = server.borrow();
            let dbtx = block_on(svr.database.begin_transaction(all_decoders()));
            block_on(fedimint_wallet::broadcast_pending_tx(
                dbtx,
                &svr.bitcoin_rpc,
            ));
        }
    }

    /// Has every federation node send new consensus proposals then process the outcome.
    /// If the epoch has empty proposals (no new information) then panic
    pub async fn run_consensus_epochs(&self, epochs: usize) {
        for _ in 0..(epochs) {
            if self
                .servers
                .iter()
                .all(|s| Self::empty_proposal(&s.borrow().fedimint))
            {
                panic!("Empty proposals, fed might wait forever");
            }

            self.await_consensus_epochs(1).await.unwrap();
        }
    }

    /// Runs a consensus epoch
    /// If proposals are empty you will need to run a concurrent task that triggers a new epoch or
    /// it will wait forever
    pub async fn await_consensus_epochs(&self, epochs: usize) -> Cancellable<()> {
        for _ in 0..(epochs) {
            for maybe_cancelled in join_all(
                self.servers
                    .iter()
                    .map(|server| Self::consensus_epoch(server.clone(), Duration::from_millis(0))),
            )
            .await
            {
                maybe_cancelled?;
            }
            self.update_last_consensus();
        }
        Ok(())
    }

    /// Returns true if the fed would produce an empty epoch proposal (no new information)
    fn empty_proposal(server: &FedimintServer) -> bool {
        let wallet = server
            .consensus
            .modules
            .module(MODULE_KEY_WALLET)
            .as_any()
            .downcast_ref::<Wallet>()
            .unwrap();
        let mut dbtx = block_on(server.consensus.db.begin_transaction(all_decoders()));
        let height = block_on(wallet.consensus_height(&mut dbtx)).unwrap_or(0);
        let proposal = block_on(server.consensus.get_consensus_proposal());

        for item in proposal.items {
            match item {
                // ignore items that get automatically generated
                ConsensusItem::Module(mci) => {
                    if mci.module_key() != MODULE_KEY_WALLET {
                        return false;
                    }

                    let wci = assert_module_ci(&mci);
                    if let WalletConsensusItem::RoundConsensus(rci) = wci {
                        if rci.block_height == height {
                            continue;
                        }
                    }
                    return false;
                }
                ConsensusItem::EpochOutcomeSignatureShare(_) => continue,
                _ => return false,
            }
        }
        true
    }

    /// Runs consensus, but delay peers and only wait for one to complete.
    /// Useful for testing if a peer has become disconnected.
    pub async fn race_consensus_epoch(&self, durations: Vec<Duration>) -> Cancellable<()> {
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
        self.update_last_consensus();
        Ok(())
    }

    /// Force these peers to rejoin consensus, simulating what happens upon node restart
    #[allow(clippy::await_holding_refcell_ref)]
    pub async fn rejoin_consensus(&self) -> Cancellable<()> {
        for server in &self.servers {
            let mut s = server.borrow_mut();
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

    // Necessary to allow servers to progress concurrently, should be fine since the same server
    // will never run an epoch concurrently with itself.
    #[allow(clippy::await_holding_refcell_ref)]
    async fn consensus_epoch(server: Rc<RefCell<ServerTest>>, delay: Duration) -> Cancellable<()> {
        tokio::time::sleep(delay).await;
        let mut s = server.borrow_mut();
        let consensus = s.fedimint.consensus.clone();

        let overrider = s.override_proposal.clone();
        let proposal = async { overrider.unwrap_or(consensus.get_consensus_proposal().await) };
        s.dropped_peers
            .append(&mut consensus.get_consensus_proposal().await.drop_peers);

        s.last_consensus = s.fedimint.run_consensus_epoch(proposal, &mut rng()).await?;

        for outcome in s.last_consensus.clone() {
            s.fedimint.process_outcome(outcome).await.expect("failed");
        }

        Ok(())
    }

    fn update_last_consensus(&self) {
        let new_consensus = self
            .servers
            .iter()
            .flat_map(|s| s.borrow().last_consensus.clone())
            .max_by_key(|c| c.epoch)
            .unwrap();
        let mut last_consensus = self.last_consensus.borrow_mut();
        let current_consensus = &self.servers.first().unwrap().borrow().fedimint.consensus;

        let audit = block_on(current_consensus.audit());

        if last_consensus.is_empty() || last_consensus.epoch < new_consensus.epoch {
            info!("{}", consensus::debug::epoch_message(&new_consensus));
            info!("\n{}", audit);
            let bs = std::cmp::max(*self.max_balance_sheet.borrow(), audit.sum().milli_sat);
            *self.max_balance_sheet.borrow_mut() = bs;
            *last_consensus = new_consensus;
        }
    }

    async fn new(
        server_config: BTreeMap<PeerId, ServerConfig>,
        database_gen: &impl Fn() -> Database,
        bitcoin_gen: &impl Fn() -> BitcoindRpc,
        connect_gen: &impl Fn(&ServerConfig) -> PeerConnector<EpochMessage>,
        task_group: &mut TaskGroup,
    ) -> Self {
        let servers = join_all(server_config.values().map(|cfg| async {
            let btc_rpc = bitcoin_gen();
            let db = database_gen();
            let mut task_group = task_group.clone();

            let mint = Mint::new(cfg.get_module_config("mint").unwrap());

            let wallet = Wallet::new_with_bitcoind(
                cfg.get_module_config("wallet").unwrap(),
                db.clone(),
                btc_rpc.clone(),
                &mut task_group.clone(),
                all_decoders(),
            )
            .await
            .expect("Couldn't create wallet");

            let ln = LightningModule::new(cfg.get_module_config("ln").unwrap());

            let mut consensus = FedimintConsensus::new(cfg.clone(), db.clone());
            consensus.register_module(mint.into());
            consensus.register_module(wallet.into());
            consensus.register_module(ln.into());

            let fedimint =
                FedimintServer::new_with(cfg.clone(), consensus, connect_gen(cfg), &mut task_group)
                    .await;

            let cfg = cfg.clone();
            let consensus = fedimint.consensus.clone();
            task_group
                .spawn("rpc server", move |handle| async {
                    fedimint_server::net::api::run_server(cfg, consensus, handle).await
                })
                .await;

            Rc::new(RefCell::new(ServerTest {
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
        let wallet = cfg.get_module_config("wallet").unwrap();
        let last_consensus = Rc::new(RefCell::new(Batch {
            epoch: 0,
            contributions: BTreeMap::new(),
        }));
        let max_balance_sheet = Rc::new(RefCell::new(0));

        FederationTest {
            servers,
            max_balance_sheet,
            last_consensus,
            cfg,
            wallet,
        }
    }
}

pub fn assert_ci<M: PluginConsensusItem>(ci: &ConsensusItem) -> &M {
    if let ConsensusItem::Module(mci) = ci {
        assert_module_ci(mci)
    } else {
        panic!("Not a module consensus item");
    }
}

pub fn assert_module_ci<M: PluginConsensusItem>(mci: &PerModuleConsensusItem) -> &M {
    mci.as_any().downcast_ref().unwrap()
}
