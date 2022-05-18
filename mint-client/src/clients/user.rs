use crate::api::{ApiError, FederationApi};
use crate::ln::gateway::LightningGateway;
use crate::ln::{LnClient, LnClientError};
use crate::mint::{MintClient, MintClientError, SpendableCoin};
use crate::wallet::{WalletClient, WalletClientError};
use crate::{api, ClientAndGatewayConfig, OwnedClientContext};
use bitcoin::{Address, Transaction};
use bitcoin_hashes::Hash;
use lightning::ln::PaymentSecret;
use lightning::routing::network_graph::RoutingFees;
use lightning::routing::router::{RouteHint, RouteHintHop};
use lightning_invoice::{CreationError, Currency, Invoice, InvoiceBuilder};
use minimint::modules::ln::contracts::{ContractId, IdentifyableContract};
use minimint::modules::ln::{ContractAccount, ContractOrOfferOutput};
use minimint::modules::mint::tiered::coins::Coins;
use minimint::modules::wallet::txoproof::TxOutProof;
use minimint::transaction as mint_tx;
use minimint::transaction::{Output, TransactionItem};
use minimint_api::db::batch::DbBatch;
use minimint_api::db::Database;
use minimint_api::{Amount, TransactionId};
use minimint_api::{OutPoint, PeerId};
use rand::{CryptoRng, RngCore};
use secp256k1_zkp::{All, Secp256k1};
use std::time::Duration;
use thiserror::Error;

const TIMELOCK: u64 = 100;

pub struct UserClient {
    context: OwnedClientContext<ClientAndGatewayConfig>,
}

impl UserClient {
    pub fn new(cfg: ClientAndGatewayConfig, db: Box<dyn Database>, secp: Secp256k1<All>) -> Self {
        let api = api::HttpFederationApi::new(
            cfg.client
                .api_endpoints
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
        config: ClientAndGatewayConfig,
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
            context: self.context.borrow_with_module_config(|cfg| &cfg.client.ln),
        }
    }

    fn mint_client(&self) -> MintClient {
        MintClient {
            context: self
                .context
                .borrow_with_module_config(|cfg| &cfg.client.mint),
        }
    }

    fn wallet_client(&self) -> WalletClient {
        WalletClient {
            context: self
                .context
                .borrow_with_module_config(|cfg| &cfg.client.wallet),
            fee_consensus: self.context.config.client.fee_consensus.clone(), // TODO: remove or put into context
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
            .saturating_sub(self.context.config.client.fee_consensus.fee_peg_in_abs);
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

        let funding_amount =
            Amount::from(amt) + self.context.config.client.fee_consensus.fee_peg_out_abs;
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

    pub fn create_invoice<R: RngCore + CryptoRng>(
        &self,
        amount: Amount,
        mut rng: R,
    ) -> Result<Invoice, ClientError> {
        // Hard-coding preimage (pubkey) for now
        let raw_payment_secret = [0; 32];
        let payment_hash = bitcoin::secp256k1::hashes::sha256::Hash::hash(&raw_payment_secret);
        let payment_secret = PaymentSecret(raw_payment_secret);

        // Final route to the user's contract inside the federation
        let (node_secret_key, node_public_key) = self.context.secp.generate_keypair(&mut rng);

        // Route hint instructing payer how to route to gateway
        let gateway_route_hint = RouteHint(vec![RouteHintHop {
            src_node_id: self.context.config.gateway.node_pub_key,
            short_channel_id: 8,
            fees: RoutingFees {
                base_msat: 0,
                proportional_millionths: 0,
            },
            cltv_expiry_delta: (8 << 4) | 1,
            htlc_minimum_msat: None,
            htlc_maximum_msat: None,
        }]);

        let invoice = InvoiceBuilder::new(Currency::Regtest)
            .amount_milli_satoshis(amount.milli_sat)
            .description("description".into())
            .payment_hash(payment_hash)
            .payment_secret(payment_secret)
            .current_timestamp()
            .min_final_cltv_expiry(144)
            .payee_pub_key(node_public_key)
            .private_route(gateway_route_hint)
            .build_signed(|hash| self.context.secp.sign_recoverable(hash, &node_secret_key))?;

        // TODO: submit ContractOrOfferOutput::Offer to federation to offer payment_secret for sale
        // TODO: wait for gateway to execute contract?

        Ok(invoice)
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
    #[error("Timed out while waiting for contract to be accepted")]
    WaitContractTimeout,
    #[error("Failed to create lightning invoice: {0}")]
    InvoiceError(CreationError),
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

impl From<CreationError> for ClientError {
    fn from(e: CreationError) -> Self {
        ClientError::InvoiceError(e)
    }
}
