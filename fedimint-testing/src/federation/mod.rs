use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::Duration;

use bitcoin::hashes::Hash;
use fedimint_api::cancellable::Cancellable;
use fedimint_api::config::ClientConfig;
use fedimint_api::core::{MODULE_KEY_MINT, MODULE_KEY_WALLET};
use fedimint_api::db::Database;
use fedimint_api::task::TaskGroup;
use fedimint_api::Amount;
use fedimint_api::OutPoint;
use fedimint_api::PeerId;
use fedimint_api::TieredMulti;
use fedimint_bitcoind::BitcoindRpc;
use fedimint_ln::LightningModule;
use fedimint_mint::{Mint, MintOutput};
use fedimint_server::config::ServerConfig;
use fedimint_server::consensus::{ConsensusOutcome, ConsensusProposal};
use fedimint_server::consensus::{FedimintConsensus, TransactionSubmissionError};
use fedimint_server::epoch::ConsensusItem;
use fedimint_server::net::peers::PeerConnector;
use fedimint_server::{all_decoders, consensus, EpochMessage, FedimintServer};
use fedimint_wallet::config::WalletConfig;
use fedimint_wallet::db::UTXOKey;
use fedimint_wallet::SpendableUTXO;
use fedimint_wallet::Wallet;
use fedimint_wallet::WalletConsensusItem;
use futures::executor::block_on;
use futures::future::{join_all, select_all};
use hbbft::honey_badger::Batch;
use mint_client::mint::SpendableNote;
use tracing::info;

use crate::btc::BitcoinTest;
use crate::user::UserTest;
use crate::{assert_module_ci, rng};

pub struct FederationTest {
    servers: Vec<Rc<RefCell<ServerTest>>>,
    last_consensus: Rc<RefCell<ConsensusOutcome>>,
    max_balance_sheet: Rc<RefCell<i64>>,
    pub wallet: WalletConfig,
    pub cfg: ServerConfig,
}

struct ServerTest {
    fedimint: FedimintServer,
    last_consensus: Vec<ConsensusOutcome>,
    bitcoin_rpc: BitcoindRpc,
    database: Database,
    override_proposal: Option<ConsensusProposal>,
    dropped_peers: Vec<PeerId>,
}

/// Represents a collection of fedimint peer servers
impl FederationTest {
    /// Returns the outcome of the last consensus epoch
    pub fn last_consensus(&self) -> ConsensusOutcome {
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
                    .filter(|item| matches!(item, ConsensusItem::EpochInfo(_)))
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
        assert_eq!(amount.milli_sat % 1000, 0);
        let sats = bitcoin::Amount::from_sat(amount.milli_sat / 1000);
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
                let mut dbtx = svr.database.begin_transaction(all_decoders());

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
                    let mut dbtx = svr.database.begin_transaction(all_decoders());
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
                        .get(&MODULE_KEY_MINT)
                        .unwrap()
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
            block_on(fedimint_wallet::broadcast_pending_tx(
                server.borrow().database.begin_transaction(all_decoders()),
                &server.borrow().bitcoin_rpc,
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
            .get(&MODULE_KEY_WALLET)
            .unwrap()
            .as_any()
            .downcast_ref::<Wallet>()
            .unwrap();
        let height = block_on(
            wallet.consensus_height(&mut server.consensus.db.begin_transaction(all_decoders())),
        )
        .unwrap_or(0);
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
                ConsensusItem::EpochInfo(_) => continue,
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
            s.fedimint
                .rejoin_consensus(Duration::from_secs(1), &mut rng())
                .await?;
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

        for outcome in &s.last_consensus {
            consensus.process_consensus_outcome(outcome.clone()).await;
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

    pub async fn new(
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
