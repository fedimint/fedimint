use crate::api::{ApiError, FederationApi};
use crate::clients::transaction::TransactionBuilder;
use crate::ln::gateway::LightningGateway;
use crate::ln::incoming::ConfirmedInvoice;
use crate::ln::{LnClient, LnClientError};
use crate::mint::{MintClient, MintClientError, SpendableCoin};
use crate::wallet::{WalletClient, WalletClientError};
use crate::{api, OwnedClientContext};
use bitcoin::util::key::KeyPair;
use bitcoin::{Address, Network, Transaction as BitcoinTransaction};
use bitcoin_hashes::Hash;
use lightning::ln::PaymentSecret;
use lightning::routing::gossip::RoutingFees;
use lightning::routing::router::{RouteHint, RouteHintHop};
use lightning_invoice::{CreationError, Currency, Invoice, InvoiceBuilder};
use minimint_api::db::batch::{Accumulator, BatchItem, DbBatch};
use minimint_api::db::Database;
use minimint_api::{Amount, TransactionId};
use minimint_api::{OutPoint, PeerId};
use minimint_core::config::ClientConfig;
use minimint_core::modules::ln::contracts::incoming::OfferId;
use minimint_core::modules::ln::contracts::{
    ContractId, IdentifyableContract, OutgoingContractOutcome,
};
use minimint_core::modules::ln::ContractOrOfferOutput;
use minimint_core::modules::mint::tiered::coins::Coins;
use minimint_core::modules::mint::BlindToken;
use minimint_core::modules::wallet::txoproof::TxOutProof;
use minimint_core::transaction::{Input, Output, TransactionItem};
use rand::{CryptoRng, RngCore};
use secp256k1_zkp::{All, Secp256k1};
use std::time::Duration;
use thiserror::Error;

const TIMELOCK: u64 = 100;

fn network_to_currency(network: Network) -> Currency {
    match network {
        Network::Bitcoin => Currency::Bitcoin,
        Network::Regtest => Currency::Regtest,
        Network::Testnet => Currency::BitcoinTestnet,
        Network::Signet => Currency::Signet,
    }
}

pub struct UserClient {
    context: OwnedClientContext<ClientConfig>,
}

impl UserClient {
    pub async fn new(cfg: ClientConfig, db: Box<dyn Database>, secp: Secp256k1<All>) -> Self {
        let api = api::WsFederationApi::new(
            cfg.max_evil,
            cfg.api_endpoints
                .iter()
                .enumerate()
                .map(|(id, url)| {
                    let peer_id = PeerId::from(id as u16); // FIXME: potentially wrong, currently works imo
                    let url = url.parse().expect("Invalid URL in config");
                    (peer_id, url)
                })
                .collect(),
        )
        .await;
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

    pub fn ln_client(&self) -> LnClient {
        LnClient {
            context: self.context.borrow_with_module_config(|cfg| &cfg.ln),
        }
    }

    pub fn mint_client(&self) -> MintClient {
        MintClient {
            context: self.context.borrow_with_module_config(|cfg| &cfg.mint),
        }
    }

    pub fn wallet_client(&self) -> WalletClient {
        WalletClient {
            context: self.context.borrow_with_module_config(|cfg| &cfg.wallet),
            fee_consensus: self.context.config.fee_consensus.clone(), // TODO: remove or put into context
        }
    }

    pub async fn peg_in<R: RngCore + CryptoRng>(
        &self,
        txout_proof: TxOutProof,
        btc_transaction: BitcoinTransaction,
        mut rng: R,
    ) -> Result<TransactionId, ClientError> {
        let mut tx = TransactionBuilder::default();

        let (peg_in_key, peg_in_proof) = self
            .wallet_client()
            .create_pegin_input(txout_proof, btc_transaction)?;

        let amount = Amount::from_sat(peg_in_proof.tx_output().value)
            .saturating_sub(self.context.config.fee_consensus.fee_peg_in_abs);
        if amount == Amount::ZERO {
            return Err(ClientError::PegInAmountTooSmall);
        }

        tx.input(&mut vec![peg_in_key], Input::Wallet(Box::new(peg_in_proof)));

        self.submit_tx_with_change(tx, DbBatch::new(), &mut rng)
            .await
    }

    async fn submit_tx_with_change<R: RngCore + CryptoRng>(
        &self,
        tx: TransactionBuilder,
        mut batch: Accumulator<BatchItem>,
        mut rng: R,
    ) -> Result<TransactionId, ClientError> {
        let change = tx.change_required(&self.context.config.fee_consensus);
        let final_tx =
            self.mint_client()
                .finalize_change(change, batch.transaction(), tx, &mut rng);
        let txid = final_tx.tx_hash();
        let mint_tx_id = self.context.api.submit_transaction(final_tx).await?;
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
        let mut tx = TransactionBuilder::default();

        let (mut coin_keys, coin_input) = self.mint_client().create_coin_input_from_coins(coins)?;
        tx.input(&mut coin_keys, Input::Mint(coin_input));
        let txid = self
            .submit_tx_with_change(tx, DbBatch::new(), &mut rng)
            .await?;

        Ok(OutPoint { txid, out_idx: 0 })
    }

    pub async fn pay_for_coins<R: RngCore + CryptoRng>(
        &self,
        coins: Coins<BlindToken>,
        mut rng: R,
    ) -> Result<OutPoint, ClientError> {
        let mut batch = DbBatch::new();
        let mut tx = TransactionBuilder::default();

        let (mut coin_keys, coin_input) = self
            .mint_client()
            .create_coin_input(batch.transaction(), coins.amount())?;

        tx.input(&mut coin_keys, Input::Mint(coin_input));
        tx.output(Output::Mint(coins));
        let txid = self.submit_tx_with_change(tx, batch, &mut rng).await?;

        Ok(OutPoint { txid, out_idx: 0 })
    }

    pub fn receive_coins<R: RngCore + CryptoRng>(
        &self,
        amount: Amount,
        rng: R,
        create_tx: impl FnMut(Coins<BlindToken>) -> OutPoint,
    ) {
        let mut batch = DbBatch::new();

        self.mint_client()
            .create_coin_output(batch.transaction(), amount, rng, create_tx);

        self.context.db.apply_batch(batch).expect("DB error");
    }

    pub async fn peg_out<R: RngCore + CryptoRng>(
        &self,
        amt: bitcoin::Amount,
        address: Address,
        mut rng: R,
    ) -> Result<TransactionId, ClientError> {
        let mut batch = DbBatch::new();
        let mut tx = TransactionBuilder::default();

        let funding_amount = Amount::from(amt) + self.context.config.fee_consensus.fee_peg_out_abs;
        let (mut coin_keys, coin_input) = self
            .mint_client()
            .create_coin_input(batch.transaction(), funding_amount)?;
        let pegout_output = self.wallet_client().create_pegout_output(amt, address);

        tx.input(&mut coin_keys, Input::Mint(coin_input));
        tx.output(Output::Wallet(pegout_output));

        self.submit_tx_with_change(tx, batch, &mut rng).await
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
    /// the federation too early. Use [`MintClientError::is_retryable`] to determine
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
    ) -> Result<(ContractId, OutPoint), ClientError> {
        let mut batch = DbBatch::new();
        let mut tx = TransactionBuilder::default();

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
        let (mut coin_keys, coin_input) = self
            .mint_client()
            .create_coin_input(batch.transaction(), amount)?;

        tx.input(&mut coin_keys, Input::Mint(coin_input));
        tx.output(ln_output);
        let txid = self.submit_tx_with_change(tx, batch, &mut rng).await?;
        let outpoint = OutPoint { txid, out_idx: 0 };

        Ok((contract_id, outpoint))
    }

    pub async fn await_outgoing_contract_acceptance(
        &self,
        outpoint: OutPoint,
    ) -> Result<(), ClientError> {
        self.context
            .api
            .await_output_outcome::<OutgoingContractOutcome>(outpoint, Duration::from_secs(30))
            .await
            .map_err(ClientError::MintApiError)?;
        Ok(())
    }

    pub async fn generate_invoice<R: RngCore + CryptoRng>(
        &self,
        amount: Amount,
        description: String,
        gateway: &LightningGateway,
        mut rng: R,
    ) -> Result<ConfirmedInvoice, ClientError> {
        let payment_keypair = KeyPair::new(&self.context.secp, &mut rng);
        let raw_payment_secret = payment_keypair.public_key().serialize();
        let payment_hash = bitcoin::secp256k1::hashes::sha256::Hash::hash(&raw_payment_secret);
        let payment_secret = PaymentSecret(raw_payment_secret);

        // Temporary lightning node pubkey
        let (node_secret_key, node_public_key) = self.context.secp.generate_keypair(&mut rng);

        // Route hint instructing payer how to route to gateway
        let gateway_route_hint = RouteHint(vec![RouteHintHop {
            src_node_id: gateway.node_pub_key,
            short_channel_id: 8,
            fees: RoutingFees {
                base_msat: 0,
                proportional_millionths: 0,
            },
            cltv_expiry_delta: 30,
            htlc_minimum_msat: None,
            htlc_maximum_msat: None,
        }]);

        let invoice = InvoiceBuilder::new(network_to_currency(self.context.config.wallet.network))
            .amount_milli_satoshis(amount.milli_sat)
            .description(description)
            .payment_hash(payment_hash)
            .payment_secret(payment_secret)
            .current_timestamp()
            .min_final_cltv_expiry(18)
            .payee_pub_key(node_public_key)
            .private_route(gateway_route_hint)
            .build_signed(|hash| {
                self.context
                    .secp
                    .sign_ecdsa_recoverable(hash, &node_secret_key)
            })?;

        let offer_output =
            self.ln_client()
                .create_offer_output(amount, payment_hash, raw_payment_secret);
        let ln_output = Output::LN(offer_output);

        // There is no input here because this is just an announcement
        let mut tx = TransactionBuilder::default();
        tx.output(ln_output);
        let txid = self
            .submit_tx_with_change(tx, DbBatch::new(), &mut rng)
            .await?;

        // Await acceptance by the federation
        let timeout = std::time::Duration::from_secs(10);
        let outpoint = OutPoint { txid, out_idx: 0 };
        self.context
            .api
            .await_output_outcome::<OfferId>(outpoint, timeout)
            .await?;

        let confirmed = ConfirmedInvoice {
            invoice,
            keypair: payment_keypair,
        };
        self.ln_client().save_confirmed_invoice(&confirmed);

        Ok(confirmed)
    }

    pub async fn claim_incoming_contract(
        &self,
        contract_id: ContractId,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<OutPoint, ClientError> {
        // Lookup contract and "confirmed invoice"
        let contract = self.ln_client().get_incoming_contract(contract_id).await?;
        let ci = self.ln_client().get_confirmed_invoice(contract_id)?;

        // Input claims this contract
        let mut tx = TransactionBuilder::default();
        tx.input(&mut vec![ci.keypair], Input::LN(contract.claim()));
        let txid = self
            .submit_tx_with_change(tx, DbBatch::new(), &mut rng)
            .await?;

        // TODO: Update database if invoice is paid or expired

        Ok(OutPoint { txid, out_idx: 0 })
    }
}

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Error querying federation: {0}")]
    MintApiError(#[from] ApiError),
    #[error("Wallet client error: {0}")]
    WalletClientError(#[from] WalletClientError),
    #[error("Mint client error: {0}")]
    MintClientError(#[from] MintClientError),
    #[error("Lightning client error: {0}")]
    LnClientError(#[from] LnClientError),
    #[error("Peg-in amount must be greater than peg-in fee")]
    PegInAmountTooSmall,
    #[error("Timed out while waiting for contract to be accepted")]
    WaitContractTimeout,
    #[error("Error fetching offer")]
    FetchOfferError,
    #[error("Failed to create lightning invoice: {0}")]
    InvoiceError(#[from] CreationError),
}
