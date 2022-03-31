use crate::api::{ApiError, FederationApi};
use crate::ln::gateway::LightningGateway;
use crate::ln::{LnClient, LnClientError};
use crate::mint::{CoinFinalizationData, MintClient, MintClientError, SpendableCoin};
use crate::wallet::{WalletClient, WalletClientError};
use crate::{api, OwnedClientContext};
use bitcoin::{Address, Transaction};
use lightning_invoice::Invoice;
use minimint::config::ClientConfig;
use minimint::modules::ln::contracts::{ContractId, IdentifyableContract};
use minimint::modules::ln::{ContractAccount, ContractOrOfferOutput};
use minimint::modules::mint::tiered::coins::Coins;
use minimint::modules::wallet::txoproof::TxOutProof;
use minimint::outcome::TransactionStatus;
use minimint::transaction as mint_tx;
use minimint::transaction::{Output, TransactionItem};
use minimint_api::db::batch::DbBatch;
use minimint_api::db::Database;
use minimint_api::{Amount, TransactionId};
use minimint_api::{OutPoint, PeerId};
use rand::{CryptoRng, RngCore};
use secp256k1_zkp::{All, Secp256k1};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

const TIMELOCK: u64 = 100;

pub struct UserClient {
    context: OwnedClientContext<ClientConfig>,
}

impl UserClient {
    pub fn new(cfg: ClientConfig, db: Box<dyn Database>, secp: Secp256k1<All>) -> Self {
        let api = api::HttpFederationApi::new(
            cfg.api_endpoints
                .iter()
                .enumerate()
                .map(|(id, url)| {
                    let peer_id = PeerId::from(id as u16); // FIXME: potentially wrong, currently works imo
                    let url = url.parse().expect("Invalid URL in config");
                    (peer_id, url)
                })
                .collect(),
        );
        Self::new_with_api(cfg, db, Box::new(api), secp)
    }

    pub fn new_with_api(
        config: ClientConfig,
        db: Box<dyn Database>,
        api: Box<dyn FederationApi>,
        secp: Secp256k1<All>,
    ) -> UserClient {
        UserClient {
            context: OwnedClientContext {
                config,
                db,
                api,
                secp,
            },
        }
    }

    fn ln_client(&self) -> LnClient {
        LnClient {
            context: self.context.borrow_with_module_config(|cfg| &cfg.ln),
        }
    }

    fn mint_client(&self) -> MintClient {
        MintClient {
            context: self.context.borrow_with_module_config(|cfg| &cfg.mint),
        }
    }

    fn wallet_client(&self) -> WalletClient {
        WalletClient {
            context: self.context.borrow_with_module_config(|cfg| &cfg.wallet),
            fee_consensus: self.context.config.fee_consensus.clone(), // TODO: remove or put into context
        }
    }

    pub async fn peg_in<R: RngCore + CryptoRng>(
        &self,
        txout_proof: TxOutProof,
        btc_transaction: Transaction,
        mut rng: R,
    ) -> Result<TransactionId, ClientError> {
        let mut batch = DbBatch::new();

        let (peg_in_key, peg_in_proof) = self
            .wallet_client()
            .create_pegin_input(txout_proof, btc_transaction)?;

        let amount = Amount::from_sat(peg_in_proof.tx_output().value)
            .saturating_sub(self.context.config.fee_consensus.fee_peg_in_abs);
        if amount == Amount::ZERO {
            return Err(ClientError::PegInAmountTooSmall);
        }

        let (coin_finalization_data, coin_output) =
            self.mint_client().create_coin_output(amount, &mut rng);

        let inputs = vec![mint_tx::Input::Wallet(Box::new(peg_in_proof))];
        let outputs = vec![mint_tx::Output::Mint(coin_output)];
        let txid = mint_tx::Transaction::tx_hash_from_parts(&inputs, &outputs);

        self.mint_client().save_coin_finalization_data(
            batch.transaction(),
            OutPoint { txid, out_idx: 0 },
            coin_finalization_data,
        );

        let peg_in_req_sig = minimint::transaction::agg_sign(
            &[peg_in_key],
            txid.as_hash(),
            &self.context.secp,
            &mut rng,
        );

        let mint_transaction = mint_tx::Transaction {
            inputs,
            outputs,
            signature: Some(peg_in_req_sig),
        };

        let mint_tx_id = self
            .context
            .api
            .submit_transaction(mint_transaction)
            .await?;
        // TODO: make check part of submit_transaction
        assert_eq!(
            txid, mint_tx_id,
            "Federation is faulty, returned wrong tx id."
        );

        self.context.db.apply_batch(batch).expect("DB error");
        Ok(txid)
    }

    /// Exchanges `coins` received from an untrusted third party for newly issued ones to prevent
    /// double spends. Users must ensure that the reissuance transaction is accepted before
    /// accepting `coins` as a valid payment.
    ///
    /// On success the out point of the newly issued e-cash tokens is returned. It can be used to
    /// easily poll the transaction status using [`MintClient::fetch_coins`] until it returns
    /// `Ok(())`, indicating we received our newly issued e-cash tokens.
    pub async fn reissue<R: RngCore + CryptoRng>(
        &self,
        coins: Coins<SpendableCoin>,
        mut rng: R,
    ) -> Result<OutPoint, ClientError> {
        const OUT_IDX: u64 = 0;

        let mut batch = DbBatch::new();

        let amount = coins.amount();
        let (coin_keys, coin_input) = self.mint_client().create_coin_input_from_coins(coins)?;
        // FIXME: implement fees (currently set to zero, so ignoring them works for now)
        let (coin_finalization_data, coin_output) =
            self.mint_client().create_coin_output(amount, &mut rng);

        let inputs = vec![mint_tx::Input::Mint(coin_input)];
        let outputs = vec![mint_tx::Output::Mint(coin_output)];
        let txid = mint_tx::Transaction::tx_hash_from_parts(&inputs, &outputs);

        self.mint_client().save_coin_finalization_data(
            batch.transaction(),
            OutPoint {
                txid,
                out_idx: OUT_IDX,
            },
            coin_finalization_data,
        );

        let signature = minimint::transaction::agg_sign(
            &coin_keys,
            txid.as_hash(),
            &self.context.secp,
            &mut rng,
        );

        let transaction = mint_tx::Transaction {
            inputs,
            outputs,
            signature: Some(signature),
        };

        let mint_tx_id = self.context.api.submit_transaction(transaction).await?;
        // TODO: make check part of submit_transaction
        assert_eq!(
            txid, mint_tx_id,
            "Federation is faulty, returned wrong tx id."
        );

        self.context.db.apply_batch(batch).expect("DB error");
        Ok(OutPoint {
            txid,
            out_idx: OUT_IDX,
        })
    }

    pub async fn peg_out<R: RngCore + CryptoRng>(
        &self,
        amt: bitcoin::Amount,
        address: bitcoin::Address,
        mut rng: R,
    ) -> Result<TransactionId, ClientError> {
        let mut batch = DbBatch::new();

        let funding_amount = Amount::from(amt) + self.context.config.fee_consensus.fee_peg_out_abs;
        let (coin_keys, coin_input) = self
            .mint_client()
            .create_coin_input(batch.transaction(), funding_amount)?;
        let pegout_output = self.wallet_client().create_pegout_output(amt, address);

        let inputs = vec![mint_tx::Input::Mint(coin_input)];
        let outputs = vec![mint_tx::Output::Wallet(pegout_output)];
        let txid = mint_tx::Transaction::tx_hash_from_parts(&inputs, &outputs);

        let signature = minimint::transaction::agg_sign(
            &coin_keys,
            txid.as_hash(),
            &self.context.secp,
            &mut rng,
        );

        let transaction = mint_tx::Transaction {
            inputs,
            outputs,
            signature: Some(signature),
        };
        let tx_id = transaction.tx_hash();

        let mint_tx_id = self.context.api.submit_transaction(transaction).await?;
        assert_eq!(
            tx_id, mint_tx_id,
            "Federation is faulty, returned wrong tx id."
        );

        self.context.db.apply_batch(batch).expect("DB error");
        Ok(tx_id)
    }

    pub fn get_new_pegin_address<R: RngCore + CryptoRng>(&self, rng: R) -> Address {
        let mut batch = DbBatch::new();
        let address = self
            .wallet_client()
            .get_new_pegin_address(batch.transaction(), rng);
        self.context.db.apply_batch(batch).expect("DB error");
        address
    }

    pub fn select_and_spend_coins(
        &self,
        amount: Amount,
    ) -> Result<Coins<SpendableCoin>, MintClientError> {
        let mut batch = DbBatch::new();
        let coins = self
            .mint_client()
            .select_and_spend_coins(batch.transaction(), amount)?;
        self.context.db.apply_batch(batch).expect("DB error");
        Ok(coins)
    }

    /// Tries to fetch e-cash tokens from a certain out point. An error may just mean having queried
    /// the federation too early. Use [`MintClientError::is_retryable_fetch_coins`] to determine
    /// if the operation should be retried at a later time.
    pub async fn fetch_coins<'a>(&self, outpoint: OutPoint) -> Result<(), MintClientError> {
        let mut batch = DbBatch::new();
        self.mint_client()
            .fetch_coins(batch.transaction(), outpoint)
            .await?;
        self.context.db.apply_batch(batch).expect("DB error");
        Ok(())
    }

    pub async fn fetch_all_coins<'a>(&self) -> Result<Vec<TransactionId>, MintClientError> {
        let mut batch = DbBatch::new();
        let res = self
            .mint_client()
            .fetch_all_coins(batch.transaction())
            .await?;
        self.context.db.apply_batch(batch).expect("DB error");
        Ok(res)
    }

    pub fn coins(&self) -> Coins<SpendableCoin> {
        self.mint_client().coins()
    }

    pub async fn fund_outgoing_ln_contract<R: RngCore + CryptoRng>(
        &self,
        gateway: &LightningGateway,
        invoice: Invoice,
        mut rng: R,
    ) -> Result<ContractId, ClientError> {
        let mut batch = DbBatch::new();

        let consensus_height = self.context.api.fetch_consensus_block_height().await?;
        let absolute_timelock = consensus_height + TIMELOCK;

        let contract = self
            .ln_client()
            .create_outgoing_output(
                batch.transaction(),
                invoice,
                gateway,
                absolute_timelock as u32,
                &mut rng,
            )
            .await?;
        let contract_id = match &contract {
            ContractOrOfferOutput::Contract(c) => c.contract.contract_id(),
            ContractOrOfferOutput::Offer(_) => {
                panic!()
            } // FIXME: impl TryFrom
        };
        let ln_output = Output::LN(contract);

        let amount = ln_output.amount();
        let (coin_keys, coin_input) = self
            .mint_client()
            .create_coin_input(batch.transaction(), amount)?;

        let inputs = vec![mint_tx::Input::Mint(coin_input)];
        let outputs = vec![ln_output];
        let txid = mint_tx::Transaction::tx_hash_from_parts(&inputs, &outputs);

        let signature = minimint::transaction::agg_sign(
            &coin_keys,
            txid.as_hash(),
            &self.context.secp,
            &mut rng,
        );

        let transaction = mint_tx::Transaction {
            inputs,
            outputs,
            signature: Some(signature),
        };

        let mint_tx_id = self.context.api.submit_transaction(transaction).await?;
        // TODO: make check part of submit_transaction
        assert_eq!(
            txid, mint_tx_id,
            "Federation is faulty, returned wrong tx id."
        );

        self.context.db.apply_batch(batch).expect("DB error");
        Ok(contract_id)
    }

    pub async fn wait_contract(
        &self,
        contract: ContractId,
    ) -> Result<ContractAccount, ClientError> {
        loop {
            match self.ln_client().get_contract_account(contract).await {
                Ok(contract) => return Ok(contract),
                Err(LnClientError::ApiError(e)) => {
                    if e.is_retryable_fetch_coins() {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    } else {
                        return Err(ClientError::MintApiError(e));
                    }
                }
                Err(e) => return Err(ClientError::LnClientError(e)),
            }
        }
    }

    pub async fn wait_contract_timeout(
        &self,
        contract: ContractId,
        timeout: Duration,
    ) -> Result<ContractAccount, ClientError> {
        tokio::time::timeout(timeout, self.wait_contract(contract))
            .await
            .map_err(|_| ClientError::WaitContractTimeout)?
    }

    /// Fetches the TransactionStatus for a txid
    /// Polling should *only* be set to true if it is anticipated that the txid is valid but has not yet been processed
    pub async fn fetch_tx_outcome(
        &self,
        tx: TransactionId,
        polling: bool,
    ) -> Result<TransactionStatus, ClientError> {
        //did not choose to use the MintClientError is_retryable logic because the 404 error should normaly
        //not be retryable just in this specific case...
        let status;
        loop {
            match self.context.api.fetch_tx_outcome(tx).await {
                Ok(s) => {
                    status = s;
                    break;
                }
                Err(_e) if polling => tokio::time::sleep(Duration::from_secs(1)).await,
                Err(e) => return Err(ClientError::MintApiError(e)),
            }
        }
        Ok(status)
    }

    //TODO: check if this even makes sense, just wanted to get things working after rebase for now
    pub fn fetch_active_issuances(&self) -> Vec<CoinFinalizationData> {
        let coins: Vec<CoinFinalizationData> = self.mint_client().get_active_issuances().to_vec();
        coins
    }
}

// -> clientd
/// Holds all possible Responses of the RPC-CLient can also be used to parse responses (for client-cli)
#[derive(Serialize, Deserialize, Clone)]
pub enum ResBody {
    ///The clients holdings : The quantity of coins for each tier. For total holdings sum(Infoi.quantity * Infoi.tier) with i = 0 - n
    /// Also contains the [`ResBody::Pending`] variant.
    Info {
        coins: Vec<CoinsByTier>,
        pending: Box<ResBody>,
    },
    /// Active issuances : Not yet (bey the federation) signed BUT accepted coins
    Pending {
        //TODO: Also return Vec<TransactionId> (?)
        transactions: usize,
        acc_qty_coins: usize,
        acc_val_amount: Amount,
    },
    /// Holds the serialized [`Coins<SpendableCoin>`]
    Spend { token: String },
    /// Holds the from the federation returned [`OutPoint`] (regarding the reissuance) and the [`TransactionStatus`]
    Reissue {
        out_point: OutPoint,
        status: TransactionStatus,
    },
    /// Holds events which could not be sent to the client but were triggered by some action from him. This will be cleared after querying it
    EventDump { events: Vec<ResBody> },
    /// Represents an event which occurred. Might be an Error or Non-Error
    Event { time: u64, msg: String },
    /// Represents an empty response
    Empty,
}
/// Holds quantity of coins per tier
#[derive(Serialize, Deserialize, Clone)]
pub struct CoinsByTier {
    tier: u64,
    quantity: usize,
}

impl ResBody {
    /// Builds the [`ResBody::Info`] variant.
    pub fn build_info(coins: Coins<SpendableCoin>, cfd: Vec<CoinFinalizationData>) -> Self {
        let info_coins: Vec<CoinsByTier> = coins
            .coins
            .iter()
            .map(|(tier, c)| CoinsByTier {
                quantity: c.len(),
                tier: tier.milli_sat,
            })
            .collect();
        ResBody::Info {
            coins: info_coins,
            pending: Box::new(ResBody::build_pending(cfd)),
        }
    }
    /// Builds the [`ResBody::Pending`] variant.
    pub fn build_pending(all_pending: Vec<CoinFinalizationData>) -> Self {
        let acc_qty_coins = all_pending.iter().map(|cfd| cfd.coin_count()).sum();
        let acc_val_amount = all_pending.iter().map(|cfd| cfd.coin_amount()).sum();
        ResBody::Pending {
            transactions: all_pending.len(),
            acc_qty_coins,
            acc_val_amount,
        }
    }
    /// Builds the [`ResBody::Spend`] variant.
    pub fn build_spend(token: String) -> Self {
        ResBody::Spend { token }
    }
    /// Builds the [`ResBody::Reissue`] variant.
    pub fn build_reissue(out_point: OutPoint, status: TransactionStatus) -> Self {
        ResBody::Reissue { out_point, status }
    }
    /// Builds the [`ResBody::Event`] variant, by taking the event message and adding a timestamp
    pub fn build_event(msg: String) -> Self {
        let time = SystemTime::now();
        let d = time.duration_since(UNIX_EPOCH).unwrap(); // hrmph - unwrap doesn't seem ideal
        let time = (d.as_secs() as u64) * 1000 + (u64::from(d.subsec_nanos()) / 1_000_000);
        ResBody::Event { time, msg }
    }
    /// Builds the [`ResBody::EventDump`] variant. The supplied event stack will be cleared.
    pub fn build_event_dump(events: &mut Vec<ResBody>) -> Self {
        let e = events.clone();
        events.clear();
        ResBody::EventDump { events: e }
    }
}
//TODO: implement Display trait for ResBody/CoinsByTier (for client-cli)

pub fn serialize_coins(c: &Coins<SpendableCoin>) -> String {
    let bytes = bincode::serialize(&c).unwrap();
    base64::encode(&bytes)
}

pub fn parse_coins(s: &str) -> Coins<SpendableCoin> {
    let bytes = base64::decode(s).unwrap();
    bincode::deserialize(&bytes).unwrap()
}
// <- clientd

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Error querying federation: {0}")]
    MintApiError(ApiError),
    #[error("Wallet client error: {0}")]
    WalletClientError(WalletClientError),
    #[error("Mint client error: {0}")]
    MintClientError(MintClientError),
    #[error("Lightning client error: {0}")]
    LnClientError(LnClientError),
    #[error("Peg-in amount must be greater than peg-in fee")]
    PegInAmountTooSmall,
    #[error("Timed out while waiting for contract to be accepted")]
    WaitContractTimeout,
}

impl From<ApiError> for ClientError {
    fn from(e: ApiError) -> Self {
        ClientError::MintApiError(e)
    }
}

impl From<WalletClientError> for ClientError {
    fn from(e: WalletClientError) -> Self {
        ClientError::WalletClientError(e)
    }
}

impl From<MintClientError> for ClientError {
    fn from(e: MintClientError) -> Self {
        ClientError::MintClientError(e)
    }
}

impl From<LnClientError> for ClientError {
    fn from(e: LnClientError) -> Self {
        ClientError::LnClientError(e)
    }
}
