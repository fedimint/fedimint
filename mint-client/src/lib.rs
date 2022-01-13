use std::sync::Arc;

use bitcoin::{Address, Transaction};
use lightning_invoice::Invoice;
use rand::{CryptoRng, RngCore};
use secp256k1_zkp::{All, Secp256k1};
use thiserror::Error;

use minimint::config::ClientConfig;
use minimint::modules::mint::tiered::coins::Coins;
use minimint::modules::wallet::txoproof::{PegInProofError, TxOutProof};
use minimint::transaction as mint_tx;
use minimint::transaction::{Output, TransactionItem};
use minimint_api::db::batch::DbBatch;
use minimint_api::db::{Database, RawDatabase};
use minimint_api::{Amount, TransactionId};
use minimint_api::{OutPoint, PeerId};

use crate::api::{ApiError, FederationApi};
use crate::ln::gateway::LightningGateway;
use crate::ln::LnClientError;
use crate::mint::{MintClientError, SpendableCoin};
use crate::wallet::WalletClientError;

mod api;
pub mod ln;
pub mod mint;
pub mod wallet;

pub struct MintClient {
    cfg: ClientConfig,
    db: Arc<dyn RawDatabase>,
    api: Arc<dyn api::FederationApi>,
    secp: Secp256k1<All>,
    wallet: wallet::WalletClient,
    mint: mint::MintClient,
    #[allow(dead_code)]
    ln: ln::LnClient,
}

impl MintClient {
    pub fn new(cfg: ClientConfig, db: Arc<dyn RawDatabase>, secp: Secp256k1<All>) -> Self {
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
        Self::new_with_api(cfg, db, Arc::new(api), secp)
    }

    pub fn new_with_api(
        cfg: ClientConfig,
        db: Arc<dyn RawDatabase>,
        api: Arc<dyn FederationApi>,
        secp: Secp256k1<All>,
    ) -> MintClient {
        // TODO: don't clone, maybe make sub-clients only borrow context?
        let wallet = wallet::WalletClient {
            db: db.clone(),
            cfg: cfg.wallet.clone(),
            api: api.clone(),
            secp: secp.clone(),
            fee_consensus: cfg.fee_consensus.clone(),
        };
        let mint = mint::MintClient {
            db: db.clone(),
            cfg: cfg.mint.clone(),
            api: api.clone(),
            secp: secp.clone(),
        };
        let ln = ln::LnClient {
            db: db.clone(),
            cfg: cfg.ln.clone(),
            api: api.clone(),
            secp: secp.clone(),
        };
        MintClient {
            cfg,
            db,
            api,
            secp,
            wallet,
            mint,
            ln,
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
            .wallet
            .create_pegin_input(txout_proof, btc_transaction)?;

        let amount = Amount::from_sat(peg_in_proof.tx_output().value)
            .saturating_sub(self.cfg.fee_consensus.fee_peg_in_abs);
        if amount == Amount::ZERO {
            return Err(ClientError::PegInAmountTooSmall);
        }

        let (coin_finalization_data, coin_output) = self.mint.create_coin_output(amount, &mut rng);

        let inputs = vec![mint_tx::Input::Wallet(Box::new(peg_in_proof))];
        let outputs = vec![mint_tx::Output::Mint(coin_output)];
        let txid = mint_tx::Transaction::tx_hash_from_parts(&inputs, &outputs);

        self.mint.save_coin_finalization_data(
            batch.transaction(),
            OutPoint { txid, out_idx: 0 },
            coin_finalization_data,
        );

        let peg_in_req_sig =
            minimint::transaction::agg_sign(&[peg_in_key], txid.as_hash(), &self.secp, &mut rng);

        let mint_transaction = mint_tx::Transaction {
            inputs,
            outputs,
            signature: Some(peg_in_req_sig),
        };

        let mint_tx_id = self.api.submit_transaction(mint_transaction).await?;
        // TODO: make check part of submit_transaction
        assert_eq!(
            txid, mint_tx_id,
            "Federation is faulty, returned wrong tx id."
        );

        self.db.apply_batch(batch).expect("DB error");
        Ok(txid)
    }

    pub async fn reissue<R: RngCore + CryptoRng>(
        &self,
        coins: Coins<SpendableCoin>,
        mut rng: R,
    ) -> Result<TransactionId, ClientError> {
        let mut batch = DbBatch::new();

        let amount = coins.amount();
        let (coin_keys, coin_input) = self.mint.create_coin_input_from_coins(coins)?;
        // FIXME: implement fees (currently set to zero, so ignoring them works for now)
        let (coin_finalization_data, coin_output) = self.mint.create_coin_output(amount, &mut rng);

        let inputs = vec![mint_tx::Input::Mint(coin_input)];
        let outputs = vec![mint_tx::Output::Mint(coin_output)];
        let txid = mint_tx::Transaction::tx_hash_from_parts(&inputs, &outputs);

        self.mint.save_coin_finalization_data(
            batch.transaction(),
            OutPoint { txid, out_idx: 0 },
            coin_finalization_data,
        );

        let signature =
            minimint::transaction::agg_sign(&coin_keys, txid.as_hash(), &self.secp, &mut rng);

        let transaction = mint_tx::Transaction {
            inputs,
            outputs,
            signature: Some(signature),
        };

        let mint_tx_id = self.api.submit_transaction(transaction).await?;
        // TODO: make check part of submit_transaction
        assert_eq!(
            txid, mint_tx_id,
            "Federation is faulty, returned wrong tx id."
        );

        self.db.apply_batch(batch).expect("DB error");
        Ok(txid)
    }

    pub async fn peg_out<R: RngCore + CryptoRng>(
        &self,
        amt: bitcoin::Amount,
        address: bitcoin::Address,
        mut rng: R,
    ) -> Result<TransactionId, ClientError> {
        let mut batch = DbBatch::new();

        let funding_amount = Amount::from(amt) + self.cfg.fee_consensus.fee_peg_out_abs;
        let (coin_keys, coin_input) = self
            .mint
            .create_coin_input(batch.transaction(), funding_amount)?;
        let pegout_output = self.wallet.create_pegout_output(amt, address);

        let inputs = vec![mint_tx::Input::Mint(coin_input)];
        let outputs = vec![mint_tx::Output::Wallet(pegout_output)];
        let txid = mint_tx::Transaction::tx_hash_from_parts(&inputs, &outputs);

        let signature =
            minimint::transaction::agg_sign(&coin_keys, txid.as_hash(), &self.secp, &mut rng);

        let transaction = mint_tx::Transaction {
            inputs,
            outputs,
            signature: Some(signature),
        };
        let tx_id = transaction.tx_hash();

        let mint_tx_id = self.api.submit_transaction(transaction).await?;
        assert_eq!(
            tx_id, mint_tx_id,
            "Federation is faulty, returned wrong tx id."
        );

        self.db.apply_batch(batch).expect("DB error");
        Ok(tx_id)
    }

    pub fn get_new_pegin_address<R: RngCore + CryptoRng>(&self, rng: R) -> Address {
        let mut batch = DbBatch::new();
        let address = self.wallet.get_new_pegin_address(batch.transaction(), rng);
        self.db.apply_batch(batch).expect("DB error");
        address
    }

    pub fn select_and_spend_coins(
        &self,
        amount: Amount,
    ) -> Result<Coins<SpendableCoin>, MintClientError> {
        let mut batch = DbBatch::new();
        let coins = self
            .mint
            .select_and_spend_coins(batch.transaction(), amount)?;
        self.db.apply_batch(batch).expect("DB error");
        Ok(coins)
    }

    pub async fn fetch_coins<'a>(&self, outpoint: OutPoint) -> Result<(), MintClientError> {
        let mut batch = DbBatch::new();
        self.mint.fetch_coins(batch.transaction(), outpoint).await?;
        self.db.apply_batch(batch).expect("DB error");
        Ok(())
    }

    pub async fn fetch_all_coins<'a>(&self) -> Result<Vec<TransactionId>, MintClientError> {
        let mut batch = DbBatch::new();
        let res = self.mint.fetch_all_coins(batch.transaction()).await?;
        self.db.apply_batch(batch).expect("DB error");
        Ok(res)
    }

    pub fn coins(&self) -> Coins<SpendableCoin> {
        self.mint.coins()
    }

    pub async fn fund_outgoing_ln_contract<R: RngCore + CryptoRng>(
        &self,
        gateway: &LightningGateway,
        invoice: Invoice,
        absolute_timelock: u32,
        mut rng: R,
    ) -> Result<TransactionId, ClientError> {
        let mut batch = DbBatch::new();

        let ln_output = Output::LN(
            self.ln
                .create_outgoing_output(
                    batch.transaction(),
                    invoice,
                    gateway,
                    absolute_timelock,
                    &mut rng,
                )
                .await?,
        );

        let amount = ln_output.amount();
        let (coin_keys, coin_input) = self.mint.create_coin_input(batch.transaction(), amount)?;

        let inputs = vec![mint_tx::Input::Mint(coin_input)];
        let outputs = vec![ln_output];
        let txid = mint_tx::Transaction::tx_hash_from_parts(&inputs, &outputs);

        let signature =
            minimint::transaction::agg_sign(&coin_keys, txid.as_hash(), &self.secp, &mut rng);

        let transaction = mint_tx::Transaction {
            inputs,
            outputs,
            signature: Some(signature),
        };

        let mint_tx_id = self.api.submit_transaction(transaction).await?;
        // TODO: make check part of submit_transaction
        assert_eq!(
            txid, mint_tx_id,
            "Federation is faulty, returned wrong tx id."
        );

        self.db.apply_batch(batch).expect("DB error");
        Ok(txid)
    }
}

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
