pub mod api;
pub mod ln;
pub mod mint;
pub mod transaction;
pub mod utils;
pub mod wallet;

use std::{sync::Arc, time::Duration};

use bitcoin::util::key::KeyPair;
use bitcoin::{Address, Transaction as BitcoinTransaction};
use bitcoin_hashes::Hash;
use lightning::ln::PaymentSecret;
use lightning::routing::gossip::RoutingFees;
use lightning::routing::router::{RouteHint, RouteHintHop};
use lightning_invoice::{CreationError, Invoice, InvoiceBuilder};
use minimint_api::{
    db::{
        batch::{Accumulator, BatchItem, DbBatch},
        Database,
    },
    Amount, OutPoint, PeerId, TransactionId,
};
use minimint_core::modules::ln::contracts::incoming::{
    DecryptedPreimage, IncomingContract, IncomingContractOffer, OfferId, Preimage,
};
use minimint_core::modules::ln::contracts::{outgoing, Contract, IdentifyableContract};
use minimint_core::modules::ln::ContractOutput;
use minimint_core::transaction::TransactionItem;
use minimint_core::{
    config::ClientConfig,
    modules::{
        ln::{
            contracts::{ContractId, OutgoingContractOutcome},
            ContractOrOfferOutput,
        },
        mint::{tiered::coins::Coins, BlindToken},
        wallet::txoproof::TxOutProof,
    },
    transaction::{Input, Output},
};
use rand::{CryptoRng, RngCore};
use secp256k1_zkp::{All, Secp256k1};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ln::db::{
    OutgoingContractAccountKey, OutgoingContractAccountKeyPrefix, OutgoingPaymentClaimKey,
    OutgoingPaymentClaimKeyPrefix,
};
use crate::ln::outgoing::OutgoingContractAccount;
use crate::ln::LnClientError;
use crate::mint::MintClientError;
use crate::transaction::TransactionBuilder;
use crate::utils::{network_to_currency, OwnedClientContext};
use crate::wallet::WalletClientError;
use crate::{
    api::{ApiError, FederationApi},
    ln::{gateway::LightningGateway, incoming::ConfirmedInvoice, LnClient},
    mint::{MintClient, SpendableCoin},
    wallet::WalletClient,
};

const TIMELOCK: u64 = 100;

type Result<T> = std::result::Result<T, ClientError>;
pub type GatewayClient = Client<GatewayClientConfig>;
pub type UserClient = Client<UserClientConfig>;

#[derive(Debug)]
pub struct PaymentParameters {
    pub max_delay: u64,
    // FIXME: change to absolute fee to avoid rounding errors
    pub max_fee_percent: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserClientConfig {
    pub client_config: ClientConfig,
    pub gateway: LightningGateway,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GatewayClientConfig {
    pub client_config: ClientConfig,
    #[serde(with = "serde_keypair")]
    pub redeem_key: bitcoin::KeyPair,
    pub timelock_delta: u64,
}

pub struct Client<C> {
    context: Arc<OwnedClientContext<C>>,
}

impl AsRef<ClientConfig> for GatewayClientConfig {
    fn as_ref(&self) -> &ClientConfig {
        &self.client_config
    }
}

impl AsRef<ClientConfig> for UserClientConfig {
    fn as_ref(&self) -> &ClientConfig {
        &self.client_config
    }
}

impl<T: AsRef<ClientConfig>> Client<T> {
    pub fn ln_client(&self) -> LnClient {
        LnClient {
            context: self
                .context
                .borrow_with_module_config(|cfg| &cfg.as_ref().ln),
        }
    }

    pub fn mint_client(&self) -> MintClient {
        MintClient {
            context: self
                .context
                .borrow_with_module_config(|cfg| &cfg.as_ref().mint),
        }
    }

    pub fn wallet_client(&self) -> WalletClient {
        WalletClient {
            context: self
                .context
                .borrow_with_module_config(|cfg| &cfg.as_ref().wallet),
            fee_consensus: self.context.config.as_ref().fee_consensus.clone(), // TODO: remove or put into context
        }
    }

    pub async fn new(config: T, db: Box<dyn Database>, secp: Secp256k1<All>) -> Self {
        let api = api::WsFederationApi::new(
            config.as_ref().max_evil,
            config
                .as_ref()
                .api_endpoints
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
        Self::new_with_api(config, db, Box::new(api), secp)
    }

    pub fn new_with_api(
        config: T,
        db: Box<dyn Database>,
        api: Box<dyn FederationApi>,
        secp: Secp256k1<All>,
    ) -> Client<T> {
        let context = Arc::new(OwnedClientContext {
            config,
            db,
            api,
            secp,
        });
        Self { context }
    }

    pub async fn peg_in<R: RngCore + CryptoRng>(
        &self,
        txout_proof: TxOutProof,
        btc_transaction: BitcoinTransaction,
        mut rng: R,
    ) -> Result<TransactionId> {
        let mut tx = TransactionBuilder::default();

        let (peg_in_key, peg_in_proof) = self
            .wallet_client()
            .create_pegin_input(txout_proof, btc_transaction)?;

        let amount = Amount::from_sat(peg_in_proof.tx_output().value)
            .saturating_sub(self.context.config.as_ref().fee_consensus.fee_peg_in_abs);
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
    ) -> Result<TransactionId> {
        let change = tx.change_required(&self.context.config.as_ref().fee_consensus);
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
    ) -> Result<OutPoint> {
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
    ) -> Result<OutPoint> {
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
    ) -> Result<TransactionId> {
        let mut batch = DbBatch::new();
        let mut tx = TransactionBuilder::default();

        let funding_amount =
            Amount::from(amt) + self.context.config.as_ref().fee_consensus.fee_peg_out_abs;
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

    pub fn select_and_spend_coins(&self, amount: Amount) -> Result<Coins<SpendableCoin>> {
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
    pub async fn fetch_coins<'a>(&self, outpoint: OutPoint) -> Result<()> {
        let mut batch = DbBatch::new();
        self.mint_client()
            .fetch_coins(batch.transaction(), outpoint)
            .await?;
        self.context.db.apply_batch(batch).expect("DB error");
        Ok(())
    }

    pub async fn fetch_all_coins<'a>(&self) -> Vec<Result<OutPoint>> {
        self.mint_client()
            .fetch_all_coins()
            .await
            .into_iter()
            .map(|res| res.map_err(|e| e.into()))
            .collect()
    }

    pub fn coins(&self) -> Coins<SpendableCoin> {
        self.mint_client().coins()
    }
}

impl Client<UserClientConfig> {
    pub async fn fund_outgoing_ln_contract<R: RngCore + CryptoRng>(
        &self,
        gateway: &LightningGateway,
        invoice: Invoice,
        mut rng: R,
    ) -> Result<(ContractId, OutPoint)> {
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

    pub async fn await_outgoing_contract_acceptance(&self, outpoint: OutPoint) -> Result<()> {
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
    ) -> Result<ConfirmedInvoice> {
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

        let invoice = InvoiceBuilder::new(network_to_currency(
            self.context.config.client_config.wallet.network,
        ))
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
    ) -> Result<OutPoint> {
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

impl Client<GatewayClientConfig> {
    /// Fetch the specified outgoing payment contract account
    pub async fn fetch_outgoing_contract(
        &self,
        contract_id: ContractId,
    ) -> Result<OutgoingContractAccount> {
        self.ln_client()
            .get_outgoing_contract(contract_id)
            .await
            .map_err(ClientError::LnClientError)
    }

    /// Check if we can claim the contract account and returns the max delay in blocks for how long
    /// other nodes on the route are allowed to delay the payment.
    pub async fn validate_outgoing_account(
        &self,
        account: &OutgoingContractAccount,
    ) -> Result<PaymentParameters> {
        let our_pub_key =
            secp256k1_zkp::XOnlyPublicKey::from_keypair(&self.context.config.redeem_key);

        if account.contract.gateway_key != our_pub_key {
            return Err(ClientError::NotOurKey);
        }

        let invoice: Invoice = account
            .contract
            .invoice
            .parse()
            .map_err(ClientError::InvalidInvoice)?;
        let invoice_amount = Amount::from_msat(
            invoice
                .amount_milli_satoshis()
                .ok_or(ClientError::InvoiceMissingAmount)?,
        );

        if account.amount < invoice_amount {
            return Err(ClientError::Underfunded(invoice_amount, account.amount));
        }

        let max_absolute_fee = account.amount - invoice_amount;
        let max_fee_percent =
            (max_absolute_fee.milli_sat as f64) / (invoice_amount.milli_sat as f64);

        let consensus_block_height = self.context.api.fetch_consensus_block_height().await?;
        // Calculate max delay taking into account current consensus block height and our safety
        // margin.
        let max_delay = (account.contract.timelock as u64)
            .checked_sub(consensus_block_height)
            .and_then(|delta| delta.checked_sub(self.context.config.timelock_delta))
            .ok_or(ClientError::TimeoutTooClose)?;

        Ok(PaymentParameters {
            max_delay,
            max_fee_percent,
        })
    }

    /// Save the details about an outgoing payment the client is about to process. This function has
    /// to be called prior to instructing the lightning node to pay the invoice since otherwise a
    /// crash could lead to loss of funds.
    ///
    /// Note though that extended periods of staying offline will result in loss of funds anyway if
    /// the client can not claim the respective contract in time.
    pub fn save_outgoing_payment(&self, contract: OutgoingContractAccount) {
        self.context
            .db
            .insert_entry(
                &OutgoingContractAccountKey(contract.contract.contract_id()),
                &contract,
            )
            .expect("DB error");
    }

    /// Lists all previously saved transactions that have not been driven to completion so far
    pub fn list_pending_outgoing(&self) -> Vec<OutgoingContractAccount> {
        self.context
            .db
            .find_by_prefix(&OutgoingContractAccountKeyPrefix)
            .map(|res| res.expect("DB error").1)
            .collect()
    }

    /// Abort payment if our node can't route it
    pub fn abort_outgoing_payment(&self, contract_id: ContractId) {
        // FIXME: implement abort by gateway to give funds back to user prematurely
        self.context
            .db
            .remove_entry(&OutgoingContractAccountKey(contract_id))
            .expect("DB error");
    }

    /// Claim an outgoing contract after acquiring the preimage by paying the associated invoice and
    /// initiates e-cash issuances to receive the bitcoin from the contract (these still need to be
    /// fetched later to finalize them).
    ///
    /// Callers need to make sure that the contract can still be claimed by the gateway and has not
    /// timed out yet. Otherwise the transaction will fail.
    pub async fn claim_outgoing_contract(
        &self,
        contract_id: ContractId,
        preimage: [u8; 32],
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<OutPoint> {
        let mut batch = DbBatch::new();
        let mut tx = TransactionBuilder::default();

        let contract = self.ln_client().get_outgoing_contract(contract_id).await?;
        let input = Input::LN(contract.claim(outgoing::Preimage(preimage)));

        tx.input(&mut vec![self.context.config.redeem_key], input);
        let change = tx.change_required(&self.context.config.client_config.fee_consensus);
        let final_tx =
            self.mint_client()
                .finalize_change(change, batch.transaction(), tx, &mut rng);
        let txid = final_tx.tx_hash();

        batch.autocommit(|batch| {
            batch.append_delete(OutgoingContractAccountKey(contract_id));
            batch.append_insert(OutgoingPaymentClaimKey(contract_id), final_tx.clone());
        });

        self.context.db.apply_batch(batch).expect("DB error");
        self.context.api.submit_transaction(final_tx).await?;

        Ok(OutPoint { txid, out_idx: 0 })
    }

    pub async fn buy_preimage_offer(
        &self,
        payment_hash: &bitcoin_hashes::sha256::Hash,
        amount: &Amount,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<(OutPoint, ContractId)> {
        let mut batch = DbBatch::new();

        // Fetch offer for this payment hash
        let offer: IncomingContractOffer = self.ln_client().get_offer(*payment_hash).await?;
        if &offer.amount > amount || &offer.hash != payment_hash {
            return Err(ClientError::InvalidOffer);
        }

        // Inputs
        let (mut coin_keys, coin_input) = self
            .mint_client()
            .create_coin_input(batch.transaction(), offer.amount)?;

        // Outputs
        let our_pub_key =
            secp256k1_zkp::XOnlyPublicKey::from_keypair(&self.context.config.redeem_key);
        let contract = Contract::Incoming(IncomingContract {
            hash: offer.hash,
            encrypted_preimage: offer.encrypted_preimage.clone(),
            decrypted_preimage: DecryptedPreimage::Pending,
            gateway_key: our_pub_key,
        });
        let incoming_output = minimint_core::transaction::Output::LN(
            ContractOrOfferOutput::Contract(ContractOutput {
                amount: *amount,
                contract: contract.clone(),
            }),
        );

        // Submit transaction
        let mut builder = TransactionBuilder::default();
        builder.input(&mut coin_keys, Input::Mint(coin_input));
        builder.output(incoming_output);
        let change = builder.change_required(&self.context.config.client_config.fee_consensus);
        let tx = self
            .mint_client()
            .finalize_change(change, batch.transaction(), builder, &mut rng);
        let txid = self.context.api.submit_transaction(tx).await?;
        let outpoint = OutPoint { txid, out_idx: 0 };

        // FIXME: Save this contract in DB

        self.context.db.apply_batch(batch).expect("DB error");

        Ok((outpoint, contract.contract_id()))
    }

    /// Claw back funds after outgoing contract that had invalid preimage
    pub async fn refund_incoming_contract(
        &self,
        contract_id: ContractId,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<TransactionId> {
        let mut batch = DbBatch::new();
        let contract_account = self.ln_client().get_incoming_contract(contract_id).await?;

        let mut builder = TransactionBuilder::default();

        // Input claims this contract
        builder.input(
            &mut vec![self.context.config.redeem_key],
            Input::LN(contract_account.claim()),
        );
        let change = builder.change_required(&self.context.config.client_config.fee_consensus);
        let tx = self
            .mint_client()
            .finalize_change(change, batch.transaction(), builder, &mut rng);
        let mint_tx_id = self.context.api.submit_transaction(tx).await?;
        self.context.db.apply_batch(batch).expect("DB error");
        Ok(mint_tx_id)
    }

    /// Lists all claim transactions for outgoing contracts that we have submitted but were not part
    /// of the consensus yet.
    pub fn list_pending_claimed_outgoing(&self) -> Vec<ContractId> {
        self.context
            .db
            .find_by_prefix(&OutgoingPaymentClaimKeyPrefix)
            .map(|res| res.expect("DB error").0 .0)
            .collect()
    }

    /// Wait for a lightning preimage gateway has purchased to be decrypted by the federation
    pub async fn await_preimage_decryption(&self, outpoint: OutPoint) -> Result<Preimage> {
        Ok(self
            .context
            .api
            .await_output_outcome::<Preimage>(outpoint, Duration::from_secs(10))
            .await?)
    }

    // TODO: improve error propagation on tx transmission
    /// Waits for a outgoing contract claim transaction to be confirmed and retransmits it
    /// periodically if this does not happen.
    pub async fn await_outgoing_contract_claimed(
        &self,
        contract_id: ContractId,
        outpoint: OutPoint,
    ) -> Result<()> {
        self.context
            .api
            .await_output_outcome::<OutgoingContractOutcome>(outpoint, Duration::from_secs(10))
            .await?;
        // We remove the entry that indicates we are still waiting for transaction
        // confirmation. This does not mean we are finished yet. As a last step we need
        // to fetch the blind signatures for the newly issued tokens, but as long as the
        // federation is honest as a whole they will produce the signatures, so we don't
        // have to worry
        self.context
            .db
            .remove_entry(&OutgoingPaymentClaimKey(contract_id))
            .expect("DB error");
        Ok(())
    }

    pub fn list_fetchable_coins(&self) -> Vec<OutPoint> {
        self.mint_client()
            .list_active_issuances()
            .into_iter()
            .map(|(outpoint, _)| outpoint)
            .collect()
    }
}

// FIXME: move this elsewhere. maybe into "core".
pub mod serde_keypair {
    use bitcoin::KeyPair;
    use secp256k1_zkp::SecretKey;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[allow(missing_docs)]
    pub fn serialize<S>(key: &KeyPair, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SecretKey::from_keypair(key).serialize(serializer)
    }

    #[allow(missing_docs)]
    pub fn deserialize<'de, D>(deserializer: D) -> Result<KeyPair, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secret_key = SecretKey::deserialize(deserializer)?;

        Ok(KeyPair::from_secret_key(
            secp256k1_zkp::SECP256K1,
            secret_key,
        ))
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
    #[error("The Account or offer is keyed to another gateway")]
    NotOurKey,
    #[error("Can't parse contract's invoice: {0:?}")]
    InvalidInvoice(lightning_invoice::ParseOrSemanticError),
    #[error("Invoice is missing amount")]
    InvoiceMissingAmount,
    #[error("Outgoing contract is underfunded, wants us to pay {0}, but only contains {1}")]
    Underfunded(Amount, Amount),
    #[error("The contract's timeout is in the past or does not allow for a safety margin")]
    TimeoutTooClose,
    #[error("No offer")]
    NoOffer,
    #[error("Invalid offer")]
    InvalidOffer,
    #[error("Wrong contract type")]
    WrongContractType,
    #[error("Wrong transaction type")]
    WrongTransactionType,
    #[error("Invalid transaction {0}")]
    InvalidTransaction(String),
    #[error("Invalid preimage")]
    InvalidPreimage,
}
