use std::cell::RefCell;
use std::collections::BTreeMap;
use std::env;
use std::fmt::Write;
use std::iter::repeat;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use bitcoin::{secp256k1, Address, Transaction};
use cln_rpc::ClnRpc;
use futures::executor::block_on;
use futures::future::join_all;
use itertools::Itertools;
use lightning_invoice::Invoice;
use rand::rngs::OsRng;
use tokio::spawn;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use fake::{FakeBitcoinTest, FakeLightningTest};
use ln_gateway::ln::LnRpc;
use ln_gateway::LnGateway;
use minimint::config::ServerConfigParams;
use minimint::config::{ClientConfig, FeeConsensus, ServerConfig};
use minimint::consensus::{ConsensusItem, ConsensusOutcome, MinimintConsensus};
use minimint::transaction::{Input, Output};
use minimint::MinimintServer;
use minimint_api::config::GenerateConfig;
use minimint_api::db::batch::DbBatch;
use minimint_api::db::mem_impl::MemDatabase;
use minimint_api::db::Database;
use minimint_api::{Amount, FederationModule, OutPoint, PeerId};
use minimint_ln::contracts::Contract;
use minimint_ln::{ContractOrOfferOutput, ContractOutput};
use minimint_mint::PartiallySignedRequest;
use minimint_wallet::bitcoind::BitcoindRpc;
use minimint_wallet::config::WalletConfig;
use minimint_wallet::db::UnsignedTransactionKey;
use minimint_wallet::txoproof::TxOutProof;
use minimint_wallet::{Wallet, WalletConsensusItem};
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

/// Generates the fixtures for an integration test and spawns API and HBBFT consensus threads for
/// federation nodes starting at port 4000.
pub async fn fixtures(
    num_peers: u16,
    max_evil_threshold: usize,
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
                    .unwrap_or_else(|_| EnvFilter::new("info,tide=error")),
            )
            .init();
    }

    let params = ServerConfigParams {
        hbbft_base_port: base_port,
        api_base_port: base_port + num_peers,
        amount_tiers: amount_tiers.to_vec(),
    };
    let peers = (0..num_peers as u16).map(PeerId::from).collect::<Vec<_>>();

    let (server_config, client_config) = ServerConfig::trusted_dealer_gen(
        &peers,
        max_evil_threshold,
        &params,
        OsRng::new().unwrap(),
    );

    match env::var("MINIMINT_TEST_REAL") {
        Ok(s) if s == "1" => {
            info!("Testing with REAL Bitcoin and Lightning services");
            let dir =
                env::var("MINIMINT_TEST_DIR").expect("Must have test dir defined for real tests");
            let wallet_config = server_config.iter().last().unwrap().1.wallet.clone();
            let bitcoin_rpc = Wallet::bitcoind(wallet_config.clone());
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
            let fed = FederationTest::new(server_config.clone(), &bitcoin_rpc).await;
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
            let fed = FederationTest::new(server_config.clone(), &bitcoin_rpc).await;
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
    /// Creates an invoice from a non-gateway LN node
    fn invoice(&self, amount: Amount) -> Invoice;

    /// Returns the amount that the gateway LN node has sent
    fn amount_sent(&self) -> Amount;
}

pub struct GatewayTest {
    pub server: LnGateway,
    pub keys: LightningGateway,
    pub user_client: UserClient,
    pub client: Arc<GatewayClient>,
}

impl GatewayTest {
    async fn new(
        ln_client: Box<dyn LnRpc>,
        client: ClientConfig,
        node_pub_key: secp256k1::PublicKey,
    ) -> Self {
        let mut rng = OsRng::new().unwrap();
        let ctx = bitcoin::secp256k1::Secp256k1::new();
        let (secret_key_fed, public_key_fed) = ctx.generate_schnorrsig_keypair(&mut rng);

        let federation_client = GatewayClientConfig {
            common: client.clone(),
            redeem_key: secret_key_fed,
            timelock_delta: 10,
        };

        let keys = LightningGateway {
            mint_pub_key: public_key_fed,
            node_pub_key,
            api: "".to_string(),
        };

        let database = Box::new(MemDatabase::new());
        let user_client = UserClient::new(client, database.clone(), Default::default());

        let client = Arc::new(GatewayClient::new(federation_client, database.clone()));
        let server = LnGateway::new(client.clone(), ln_client).await;

        GatewayTest {
            server,
            keys,
            user_client,
            client,
        }
    }
}

pub struct UserTest {
    pub client: UserClient,
    config: ClientConfig,
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
    last_consensus_items: RefCell<Vec<ConsensusItem>>,
    pub wallet: WalletConfig,
    pub fee_consensus: FeeConsensus,
}

struct ServerTest {
    outcome_receiver: Receiver<ConsensusOutcome>,
    proposal_sender: Sender<Vec<ConsensusItem>>,
    consensus: Arc<MinimintConsensus<OsRng>>,
    cfg: ServerConfig,
    bitcoin_rpc: Box<dyn BitcoindRpc>,
    database: Arc<dyn Database>,
}

impl FederationTest {
    /// Returns the items that were in the last consensus
    /// Filters out redundant consensus rounds where the block height doesn't change
    pub fn last_consensus(&self) -> Vec<ConsensusItem> {
        self.last_consensus_items.borrow().clone()
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
                .filter(|s| peers.contains(&s.as_ref().borrow().cfg.identity))
                .map(Rc::clone)
                .collect(),
            wallet: self.wallet.clone(),
            fee_consensus: self.fee_consensus.clone(),
            last_consensus_items: self.last_consensus_items.clone(),
        }
    }

    /// Inserts coins directly into the databases of federation nodes, runs consensus to sign them
    /// then fetches the coins for the user client.
    pub async fn mint_coins_for_user(&self, user: &UserTest, amount: Amount) {
        let (finalization, coins) = user
            .client
            .mint_client()
            .create_coin_output(amount, OsRng::new().unwrap());
        let out_point = OutPoint {
            txid: Default::default(),
            out_idx: 0,
        };
        for server in &self.servers {
            let mut batch = DbBatch::new();
            let mut batch_tx = batch.transaction();
            let transaction = minimint::transaction::Transaction {
                inputs: vec![],
                outputs: vec![Output::Mint(coins.clone())],
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
                .consensus
                .mint
                .apply_output(batch.transaction(), &coins, out_point)
                .unwrap();
            server.borrow_mut().database.apply_batch(batch).unwrap();
        }
        let mut batch = DbBatch::new();
        user.client.mint_client().save_coin_finalization_data(
            batch.transaction(),
            out_point,
            finalization,
        );
        user.database.apply_batch(batch).unwrap();

        self.run_consensus_epochs(2).await;
        user.client.fetch_all_coins().await.unwrap();
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

    /// Has every federation node process the consensus outcome from the HBBFT thread then send new
    /// consensus proposals to the HBBFT thread.  Anything currently pending will take an additional
    /// epoch to get processed.
    pub async fn run_consensus_epochs(&self, epochs: usize) {
        for _ in 0..(epochs) {
            for server in &self.servers {
                let consensus_outcome = block_on(server.borrow_mut().outcome_receiver.recv())
                    .expect("other thread died");
                let height = server.borrow().consensus.wallet.consensus_height();

                // only need to update last_consensus_items and print one output since consensus is always the same
                if server.borrow().cfg.identity == PeerId::from(0) {
                    let filtered_consensus =
                        FederationTest::remove_redundant_round_items(&consensus_outcome, height);
                    let new_items = filtered_consensus
                        .contributions
                        .values()
                        .flat_map(|items| items.clone());
                    *self.last_consensus_items.borrow_mut() = new_items.collect();
                    warn!(
                        "{}",
                        FederationTest::epoch_debug_message(
                            &filtered_consensus,
                            &server.borrow().database
                        )
                    )
                }

                let consensus = server.borrow().consensus.clone();
                let proposal_sender = server.borrow().proposal_sender.clone();
                let cfg = server.borrow().cfg.clone();

                minimint::run_consensus_epoch(
                    &consensus,
                    consensus_outcome,
                    &proposal_sender,
                    &cfg,
                    0,
                )
                .await;
            }
        }
    }

    async fn new(
        server_config: BTreeMap<PeerId, ServerConfig>,
        bitcoin_gen: &impl Fn() -> Box<dyn BitcoindRpc>,
    ) -> Self {
        let servers = join_all(server_config.values().map(|cfg| async move {
            let bitcoin_rpc = bitcoin_gen();
            let database = Arc::new(MemDatabase::new());

            let MinimintServer {
                outcome_sender,
                proposal_receiver,
                outcome_receiver,
                proposal_sender,
                mint_consensus,
                cfg,
            } = minimint::minimint_server_with(cfg.clone(), database.clone(), bitcoin_gen).await;

            let initial_cis = mint_consensus.get_consensus_proposal().await;
            spawn(minimint::net::api::run_server(
                cfg.clone(),
                mint_consensus.clone(),
            ));
            spawn(minimint::hbbft(
                outcome_sender,
                proposal_receiver,
                cfg.clone(),
                initial_cis,
                OsRng::new().unwrap(),
            ));

            Rc::new(RefCell::new(ServerTest {
                outcome_receiver,
                proposal_sender,
                bitcoin_rpc,
                consensus: mint_consensus,
                cfg,
                database,
            }))
        }))
        .await;

        let server_config = server_config.iter().last().unwrap().1.clone();
        let fee_consensus = server_config.fee_consensus;
        let wallet = server_config.wallet;
        let last_consensus_items = RefCell::new(vec![]);

        FederationTest {
            servers,
            fee_consensus,
            wallet,
            last_consensus_items,
        }
    }

    fn remove_redundant_round_items(
        consensus: &ConsensusOutcome,
        prev_block_height: Option<u32>,
    ) -> ConsensusOutcome {
        let mut contributions = BTreeMap::new();

        for (peer, items) in consensus.contributions.iter() {
            let filtered = items
                .iter()
                .filter(|item| match item {
                    ConsensusItem::Wallet(WalletConsensusItem::RoundConsensus(
                        minimint_wallet::RoundConsensusItem { block_height, .. },
                    )) => Some(*block_height) != prev_block_height,
                    _ => true,
                })
                .cloned()
                .collect();
            contributions.insert(*peer, filtered);
        }

        ConsensusOutcome {
            epoch: consensus.epoch,
            contributions,
        }
    }

    // outputs a useful debug message for epochs indicating what happened
    fn epoch_debug_message(consensus: &ConsensusOutcome, database: &Arc<dyn Database>) -> String {
        let mut debug = format!("\n- Epoch: {} -", consensus.epoch);

        for (peer, items) in consensus.contributions.iter() {
            for item in items {
                let item_debug = Self::item_debug_message(item, database);
                write!(debug, "\n  Peer {}: {}", peer, item_debug).unwrap();
            }
        }
        debug
    }

    fn item_debug_message(item: &ConsensusItem, database: &Arc<dyn Database>) -> String {
        match item {
            ConsensusItem::Wallet(WalletConsensusItem::RoundConsensus(
                minimint_wallet::RoundConsensusItem { block_height, .. },
            )) => format!("Wallet Block Height {}", block_height),
            ConsensusItem::Wallet(WalletConsensusItem::PegOutSignature(
                minimint_wallet::PegOutSignatureItem { txid, .. },
            )) => {
                let sigs = database
                    .get_value(&UnsignedTransactionKey(*txid))
                    .unwrap()
                    .unwrap()
                    .inputs
                    .first()
                    .unwrap()
                    .partial_sigs
                    .len();
                format!("Wallet Peg Out PSBT {:.8} with {} signatures", txid, sigs)
            }
            ConsensusItem::Mint(PartiallySignedRequest {
                out_point,
                partial_signature,
            }) => format!(
                "Mint Signed Coins {} with TxId {:.8}",
                partial_signature.0.amount(),
                out_point.txid
            ),
            ConsensusItem::LN(minimint_ln::DecryptionShareCI { contract_id, .. }) => {
                format!("LN Decrytion Share for contract {:.8}", contract_id)
            }
            ConsensusItem::Transaction(minimint::transaction::Transaction {
                inputs,
                outputs,
                ..
            }) => {
                let mut tx_debug = "Transaction".to_string();
                for input in inputs.iter() {
                    let input_debug = match input {
                        Input::Mint(t) => format!("Mint Coins {}", t.amount()),
                        Input::Wallet(t) => {
                            format!("Wallet PegIn with TxId {:.8}", t.outpoint().txid)
                        }
                        Input::LN(t) => {
                            format!("LN Contract {} with id {:.8}", t.amount, t.crontract_id)
                        }
                    };
                    write!(tx_debug, "\n    Input: {}", input_debug).unwrap();
                }
                for output in outputs.iter() {
                    let output_debug = match output {
                        Output::Mint(t) => format!("Mint Coins {}", t.amount()),
                        Output::Wallet(t) => {
                            format!("Wallet PegOut {} to address {:.8}", t.amount, t.recipient)
                        }
                        Output::LN(ContractOrOfferOutput::Offer(o)) => {
                            format!("LN Offer for {} with hash {:.8}", o.amount, o.hash)
                        }
                        Output::LN(ContractOrOfferOutput::Contract(ContractOutput {
                            amount,
                            contract,
                        })) => match contract {
                            Contract::Account(a) => {
                                format!("LN Account Contract for {} key {:.8}", amount, a.key)
                            }
                            Contract::Incoming(a) => {
                                format!("LN Incoming Contract for {} hash {:.8}", amount, a.hash)
                            }
                            Contract::Outgoing(a) => {
                                format!("LN Outgoing Contract for {} hash {:.8}", amount, a.hash)
                            }
                        },
                    };
                    write!(tx_debug, "\n    Output: {}", output_debug).unwrap();
                }
                tx_debug
            }
        }
    }
}
