use std::cell::RefCell;
use std::collections::BTreeMap;
use std::env;
use std::iter::repeat;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::KeyPair;
use bitcoin::{secp256k1, Address, Transaction};
use cln_rpc::ClnRpc;
use futures::executor::block_on;
use futures::future::{join_all, select_all};
use hbbft::honey_badger::Batch;
use hbbft::honey_badger::Message;

use itertools::Itertools;
use lightning_invoice::Invoice;
use minimint_api::task::spawn;
use minimint_wallet::bitcoincore_rpc;
use rand::rngs::OsRng;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::info;
use tracing_subscriber::EnvFilter;

use fake::{FakeBitcoinTest, FakeLightningTest};
use ln_gateway::ln::LnRpc;
use ln_gateway::LnGateway;
use minimint::config::ServerConfigParams;
use minimint::config::{ClientConfig, FeeConsensus, ServerConfig};
use minimint::consensus::{ConsensusItem, ConsensusOutcome, ConsensusProposal};
use minimint::net::connect::mock::MockNetwork;
use minimint::net::connect::{Connector, InsecureTcpConnector};
use minimint::net::peers::PeerConnector;
use minimint::transaction::Output;
use minimint::{consensus, MinimintServer};
use minimint_api::config::GenerateConfig;
use minimint_api::db::batch::DbBatch;
use minimint_api::db::mem_impl::MemDatabase;
use minimint_api::db::Database;
use minimint_api::{Amount, FederationModule, OutPoint, PeerId, TransactionId};
use minimint_wallet::bitcoind::BitcoindRpc;
use minimint_wallet::config::WalletConfig;
use minimint_wallet::db::UTXOKey;
use minimint_wallet::txoproof::TxOutProof;
use minimint_wallet::SpendableUTXO;
use mint_client::api::HttpFederationApi;
use mint_client::clients::gateway::{GatewayClient, GatewayClientConfig};
use mint_client::ln::gateway::LightningGateway;
use mint_client::UserClient;
use real::{RealBitcoinTest, RealLightningTest};

mod fake;
mod real;

static BASE_PORT: AtomicU16 = AtomicU16::new(4000_u16);

// Helper functions for easier test writing
pub fn rng() -> OsRng {
    OsRng::new().unwrap()
}

pub fn sats(amount: u64) -> Amount {
    Amount::from_sat(amount)
}

pub fn sha256(data: &[u8]) -> sha256::Hash {
    bitcoin::hashes::sha256::Hash::hash(data)
}

pub fn secp() -> secp256k1::Secp256k1<secp256k1::All> {
    bitcoin::secp256k1::Secp256k1::new()
}

/// Generates the fixtures for an integration test and spawns API and HBBFT consensus threads for
/// federation nodes starting at port 4000.
pub async fn fixtures(
    num_peers: u16,
    amount_tiers: &[Amount],
) -> (
    FederationTest,
    UserTest,
    Box<dyn BitcoinTest>,
    GatewayTest,
    Box<dyn LightningTest>,
) {
    let base_port = BASE_PORT.fetch_add(num_peers * 2, Ordering::Relaxed);

    // in case we need to output logs using 'cargo test -- --nocapture'
    if base_port == 4000 {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new("info,tide=error,minimint::consensus=warn")),
            )
            .init();
    }

    let params = ServerConfigParams {
        hbbft_base_port: base_port,
        api_base_port: base_port + num_peers,
        amount_tiers: amount_tiers.to_vec(),
    };
    let peers = (0..num_peers as u16).map(PeerId::from).collect::<Vec<_>>();

    let max_evil = hbbft::util::max_faulty(peers.len());
    let (server_config, client_config) =
        ServerConfig::trusted_dealer_gen(&peers, max_evil, &params, OsRng::new().unwrap());

    match env::var("MINIMINT_TEST_REAL") {
        Ok(s) if s == "1" => {
            info!("Testing with REAL Bitcoin and Lightning services");
            let dir =
                env::var("MINIMINT_TEST_DIR").expect("Must have test dir defined for real tests");
            let wallet_config = server_config.iter().last().unwrap().1.wallet.clone();
            let bitcoin_rpc = bitcoincore_rpc::bitcoind_gen(wallet_config.clone());
            let bitcoin = RealBitcoinTest::new(wallet_config);
            let socket_gateway = PathBuf::from(dir.clone()).join("ln1/regtest/lightning-rpc");
            let socket_other = PathBuf::from(dir).join("ln2/regtest/lightning-rpc");
            let lightning =
                RealLightningTest::new(socket_gateway.clone(), socket_other.clone(), &bitcoin)
                    .await;
            let lightning_rpc = Mutex::new(
                ClnRpc::new(socket_gateway.clone())
                    .await
                    .expect("connect to ln_socket"),
            );
            let connect_gen = |peer| InsecureTcpConnector::new(peer).to_any();
            let fed = FederationTest::new(server_config.clone(), &bitcoin_rpc, &connect_gen).await;
            let user = UserTest::new(client_config.clone(), peers);
            let gateway = GatewayTest::new(
                Box::new(lightning_rpc),
                client_config,
                lightning.gateway_node_pub_key,
            )
            .await;

            (fed, user, Box::new(bitcoin), gateway, Box::new(lightning))
        }
        _ => {
            info!("Testing with FAKE Bitcoin and Lightning services");
            let bitcoin = FakeBitcoinTest::new();
            let bitcoin_rpc = || Box::new(bitcoin.clone()) as Box<dyn BitcoindRpc>;
            let lightning = FakeLightningTest::new();
            let net = MockNetwork::new();
            let net_ref = &net;
            let connect_gen = move |peer| net_ref.connector(peer).to_any();
            let fed = FederationTest::new(server_config.clone(), &bitcoin_rpc, &connect_gen).await;
            let user = UserTest::new(client_config.clone(), peers);
            let gateway = GatewayTest::new(
                Box::new(lightning.clone()),
                client_config,
                lightning.gateway_node_pub_key,
            )
            .await;

            (fed, user, Box::new(bitcoin), gateway, Box::new(lightning))
        }
    }
}

pub trait BitcoinTest {
    /// Mines a given number of blocks
    fn mine_blocks(&self, block_num: u64);

    /// Send some bitcoin to an address then mine a block to confirm it.
    /// Returns the proof that the transaction occurred.
    fn send_and_mine_block(
        &self,
        address: &Address,
        amount: bitcoin::Amount,
    ) -> (TxOutProof, Transaction);

    /// Returns a new address.
    fn get_new_address(&self) -> Address;

    /// Mine a block to include any pending transactions then get the amount received to an address
    fn mine_block_and_get_received(&self, address: &Address) -> Amount;
}

pub trait LightningTest {
    /// Creates invoice from a non-gateway LN node
    fn invoice(&self, amount: Amount) -> Invoice;

    /// Returns the amount that the gateway LN node has sent
    fn amount_sent(&self) -> Amount;
}

pub struct GatewayTest {
    pub server: LnGateway,
    pub keys: LightningGateway,
    pub user: UserTest,
    pub client: Arc<GatewayClient>,
}

impl GatewayTest {
    async fn new(
        ln_client: Box<dyn LnRpc>,
        client_config: ClientConfig,
        node_pub_key: secp256k1::PublicKey,
    ) -> Self {
        let mut rng = OsRng::new().unwrap();
        let ctx = bitcoin::secp256k1::Secp256k1::new();
        let kp = KeyPair::new(&ctx, &mut rng);

        let federation_client = GatewayClientConfig {
            common: client_config.clone(),
            redeem_key: kp,
            timelock_delta: 10,
        };

        let keys = LightningGateway {
            mint_pub_key: kp.public_key(),
            node_pub_key,
            api: "".to_string(),
        };

        let database = Box::new(MemDatabase::new());
        let user_client =
            UserClient::new(client_config.clone(), database.clone(), Default::default());
        let user = UserTest {
            client: user_client,
            config: client_config,
            database: database.clone(),
        };
        let client = Arc::new(GatewayClient::new(federation_client, database.clone()));
        let server = LnGateway::new(client.clone(), ln_client).await;

        GatewayTest {
            server,
            keys,
            user,
            client,
        }
    }
}

pub struct UserTest {
    pub client: UserClient,
    pub config: ClientConfig,
    database: Box<dyn Database>,
}

impl UserTest {
    /// Returns a new user client connected to a subset of peers.
    pub fn new_client(&self, peers: &[u16]) -> Self {
        let peers = peers
            .iter()
            .map(|i| PeerId::from(*i))
            .collect::<Vec<PeerId>>();
        Self::new(self.config.clone(), peers)
    }

    /// Helper to simplify the peg_out method call
    pub async fn peg_out(&self, amount: u64, address: &Address) -> TransactionId {
        self.client
            .peg_out(bitcoin::Amount::from_sat(amount), address.clone(), rng())
            .await
            .unwrap()
    }

    /// Returns the amount denominations of all coins from lowest to highest
    pub fn coin_amounts(&self) -> Vec<Amount> {
        self.client
            .coins()
            .coins
            .into_iter()
            .flat_map(|(a, c)| repeat(a).take(c.len()))
            .sorted()
            .collect::<Vec<Amount>>()
    }

    /// Returns sum total of all coins
    pub fn total_coins(&self) -> Amount {
        self.client.coins().amount()
    }

    fn new(config: ClientConfig, peers: Vec<PeerId>) -> Self {
        let api = Box::new(HttpFederationApi::new(
            config
                .api_endpoints
                .iter()
                .enumerate()
                .filter(|(id, _)| peers.contains(&PeerId::from(*id as u16)))
                .map(|(id, url)| {
                    (
                        PeerId::from(id as u16),
                        url.parse().expect("Invalid URL in config"),
                    )
                })
                .collect(),
        ));

        let database = Box::new(MemDatabase::new());
        let client =
            UserClient::new_with_api(config.clone(), database.clone(), api, Default::default());

        UserTest {
            client,
            config,
            database,
        }
    }
}

pub struct FederationTest {
    servers: Vec<Rc<RefCell<ServerTest>>>,
    last_consensus: Rc<RefCell<ConsensusOutcome>>,
    pub wallet: WalletConfig,
    pub fee_consensus: FeeConsensus,
}

struct ServerTest {
    minimint: MinimintServer,
    last_consensus: Vec<ConsensusOutcome>,
    bitcoin_rpc: Box<dyn BitcoindRpc>,
    database: Arc<dyn Database>,
    override_proposal: Option<ConsensusProposal>,
    dropped_peers: Vec<PeerId>,
}

impl FederationTest {
    /// Returns the items that were in the last consensus
    /// Filters out redundant consensus rounds where the block height doesn't change
    pub fn last_consensus_items(&self) -> Vec<ConsensusItem> {
        self.last_consensus
            .borrow()
            .contributions
            .values()
            .flat_map(|items| items.clone())
            .collect()
    }

    /// Sends a custom proposal, ignoring whatever is in MinimintConsensus
    /// Useful for simulating malicious federation nodes
    pub fn override_proposal(&self, items: Vec<ConsensusItem>) {
        let proposal = ConsensusProposal {
            items,
            drop_peers: vec![],
        };

        for server in &self.servers {
            server.borrow_mut().override_proposal = Some(proposal.clone());
        }
    }

    /// Submit a minimint transaction to all federation servers
    pub fn submit_transaction(&self, transaction: minimint::transaction::Transaction) {
        for server in &self.servers {
            server
                .borrow_mut()
                .minimint
                .consensus
                .submit_transaction(transaction.clone())
                .unwrap();
        }
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
                .filter(|s| peers.contains(&s.as_ref().borrow().minimint.cfg.identity))
                .map(Rc::clone)
                .collect(),
            wallet: self.wallet.clone(),
            fee_consensus: self.fee_consensus.clone(),
            last_consensus: self.last_consensus.clone(),
        }
    }

    /// Inserts coins directly into the databases of federation nodes, runs consensus to sign them
    /// then fetches the coins for the user client.
    pub async fn mint_coins_for_user(&self, user: &UserTest, amount: Amount) {
        self.database_add_coins_for_user(user, amount);
        self.run_consensus_epochs(1).await;
        user.client.fetch_all_coins().await.unwrap();
    }

    pub fn mine_spendable_utxo(
        &self,
        user: &UserTest,
        bitcoin: &dyn BitcoinTest,
        amount: bitcoin::Amount,
    ) {
        let address = user.client.get_new_pegin_address(rng());
        let (txout_proof, btc_transaction) = bitcoin.send_and_mine_block(&address, amount);
        let (_, input) = user
            .client
            .wallet_client()
            .create_pegin_input(txout_proof, btc_transaction)
            .unwrap();

        for server in &self.servers {
            let mut batch = DbBatch::new();
            let mut batch_tx = batch.transaction();

            batch_tx.append_insert_new(
                UTXOKey(input.outpoint()),
                SpendableUTXO {
                    tweak: input.tweak_contract_key().serialize(),
                    amount: bitcoin::Amount::from_sat(input.tx_output().value),
                },
            );
            batch_tx.commit();

            server.borrow_mut().database.apply_batch(batch).unwrap();
        }
    }

    pub fn has_dropped_peer(&self, peer: u16) -> bool {
        for server in &self.servers {
            let mut s = server.borrow_mut();
            let proposal = block_on(s.minimint.consensus.get_consensus_proposal());
            s.dropped_peers.append(&mut proposal.drop_peers.clone());
            if !s.dropped_peers.contains(&PeerId::from(peer)) {
                return false;
            }
        }
        true
    }

    /// Inserts coins directly into the databases of federation nodes
    pub fn database_add_coins_for_user(&self, user: &UserTest, amount: Amount) -> OutPoint {
        let mut batch = DbBatch::new();
        let out_point = OutPoint {
            txid: Default::default(),
            out_idx: 0,
        };

        user.client.mint_client().create_coin_output(
            batch.transaction(),
            amount,
            OsRng::new().unwrap(),
            |tokens| {
                for server in &self.servers {
                    let mut batch = DbBatch::new();
                    let mut batch_tx = batch.transaction();
                    let transaction = minimint::transaction::Transaction {
                        inputs: vec![],
                        outputs: vec![Output::Mint(tokens.clone())],
                        signature: None,
                    };

                    batch_tx.append_insert(
                        minimint::db::AcceptedTransactionKey(out_point.txid),
                        minimint::consensus::AcceptedTransaction {
                            epoch: 0,
                            transaction,
                        },
                    );

                    batch_tx.commit();
                    server
                        .borrow_mut()
                        .minimint
                        .consensus
                        .mint
                        .apply_output(batch.transaction(), &tokens, out_point)
                        .unwrap();
                    server.borrow_mut().database.apply_batch(batch).unwrap();
                }
                out_point
            },
        );
        user.database.apply_batch(batch).unwrap();
        out_point
    }

    /// Has every federation node broadcast any transactions pending to the Bitcoin network, otherwise
    /// transactions will only get broadcast every 10 seconds.
    pub async fn broadcast_transactions(&self) {
        for server in &self.servers {
            block_on(minimint_wallet::broadcast_pending_tx(
                &server.borrow().database,
                server.borrow().bitcoin_rpc.as_ref(),
            ));
        }
    }

    /// Has every federation node send new consensus proposals then process the outcome.
    pub async fn run_consensus_epochs(&self, epochs: usize) {
        for _ in 0..(epochs) {
            let consensus = join_all(
                self.servers
                    .iter()
                    .map(|server| Self::consensus_epoch(server.clone(), Duration::from_millis(0))),
            );
            if (timeout(Duration::from_secs(15), consensus).await).is_err() {
                let proposals: Vec<ConsensusProposal> = self
                    .servers
                    .iter()
                    .map(|s| block_on(s.borrow().minimint.consensus.get_consensus_proposal()))
                    .collect();
                panic!("Timed out waiting for consensus, try reducing epochs if proposals are empty: {:?}", proposals);
            }
            self.update_last_consensus();
        }
    }

    /// Runs consensus, but delay peers and only wait for one to complete.
    /// Useful for testing if a peer has become disconnected.
    pub async fn race_consensus_epoch(&self, durations: Vec<Duration>) {
        assert_eq!(durations.len(), self.servers.len());
        select_all(
            self.servers
                .iter()
                .zip(durations)
                .map(|(server, duration)| {
                    Box::pin(Self::consensus_epoch(server.clone(), duration))
                }),
        )
        .await;
        self.update_last_consensus();
    }

    // Necessary to allow servers to progress concurrently, should be fine since the same server
    // will never run an epoch concurrently with itself.
    #[allow(clippy::await_holding_refcell_ref)]
    async fn consensus_epoch(server: Rc<RefCell<ServerTest>>, delay: Duration) {
        tokio::time::sleep(delay).await;
        let mut s = server.borrow_mut();
        let consensus = s.minimint.consensus.clone();

        let overrider = s.override_proposal.clone();
        let proposal = async { overrider.unwrap_or(consensus.get_consensus_proposal().await) };
        s.dropped_peers
            .append(&mut consensus.get_consensus_proposal().await.drop_peers);

        s.last_consensus = s
            .minimint
            .run_consensus_epoch(proposal, &mut OsRng::new().unwrap())
            .await;

        for outcome in &s.last_consensus {
            consensus.process_consensus_outcome(outcome.clone()).await;
        }
    }

    fn update_last_consensus(&self) {
        let new_consensus = self
            .servers
            .iter()
            .flat_map(|s| s.borrow().last_consensus.clone())
            .max_by_key(|c| c.epoch)
            .unwrap();
        let mut last_consensus = self.last_consensus.borrow_mut();

        if last_consensus.is_empty() || last_consensus.epoch < new_consensus.epoch {
            info!("{}", consensus::debug::epoch_message(&new_consensus));
            *last_consensus = new_consensus;
        }
    }

    async fn new(
        server_config: BTreeMap<PeerId, ServerConfig>,
        bitcoin_gen: &impl Fn() -> Box<dyn BitcoindRpc>,
        connect_gen: &impl Fn(PeerId) -> PeerConnector<Message<PeerId>>,
    ) -> Self {
        let servers = join_all(server_config.values().map(|cfg| async move {
            let bitcoin_rpc = bitcoin_gen();
            let database = Arc::new(MemDatabase::new());

            let minimint = MinimintServer::new_with(
                cfg.clone(),
                database.clone(),
                bitcoin_gen,
                connect_gen(cfg.identity),
            )
            .await;

            spawn(minimint::net::api::run_server(
                cfg.clone(),
                minimint.consensus.clone(),
            ));

            Rc::new(RefCell::new(ServerTest {
                minimint,
                bitcoin_rpc,
                database,
                last_consensus: vec![],
                override_proposal: None,
                dropped_peers: vec![],
            }))
        }))
        .await;

        // Consumes the empty epoch 0 outcome from all servers
        let server_config = server_config.iter().last().unwrap().1.clone();
        let fee_consensus = server_config.fee_consensus;
        let wallet = server_config.wallet;
        let last_consensus = Rc::new(RefCell::new(Batch {
            epoch: 0,
            contributions: BTreeMap::new(),
        }));

        FederationTest {
            servers,
            last_consensus,
            fee_consensus,
            wallet,
        }
    }
}
