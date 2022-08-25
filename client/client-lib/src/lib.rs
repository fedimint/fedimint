pub mod api;
pub mod ln;
pub mod mint;
pub mod transaction;
pub mod utils;
pub mod wallet;

use std::time::Duration;
#[cfg(not(target_family = "wasm"))]
use std::time::SystemTime;

use futures::StreamExt;

use bitcoin::util::key::KeyPair;
use bitcoin::{secp256k1, Address, Transaction as BitcoinTransaction};

use bitcoin_hashes::Hash;
use futures::stream::FuturesUnordered;

use fedimint_api::task::sleep;
use fedimint_api::{
    db::{
        batch::{Accumulator, BatchItem, DbBatch},
        Database,
    },
    Amount, OutPoint, PeerId, TransactionId,
};
use fedimint_core::epoch::EpochHistory;
use fedimint_core::modules::ln::contracts::incoming::{
    DecryptedPreimage, IncomingContract, IncomingContractOffer, OfferId, Preimage,
};
use fedimint_core::modules::ln::contracts::{outgoing, Contract, IdentifyableContract};
use fedimint_core::modules::ln::{ContractOutput, LightningGateway};
use fedimint_core::modules::wallet::PegOut;
use fedimint_core::outcome::TransactionStatus;
use fedimint_core::transaction::TransactionItem;
use fedimint_core::{
    config::ClientConfig,
    modules::{
        ln::{
            contracts::{ContractId, OutgoingContractOutcome},
            ContractOrOfferOutput,
        },
        mint::{tiered::TieredMulti, BlindToken, InvalidAmountTierError},
        wallet::txoproof::TxOutProof,
    },
    transaction::{Input, Output},
};
use lightning::ln::PaymentSecret;
use lightning::routing::gossip::RoutingFees;
use lightning::routing::router::{RouteHint, RouteHintHop};
use lightning_invoice::{CreationError, Invoice, InvoiceBuilder};
use ln::db::LightningGatewayKey;
use rand::{CryptoRng, RngCore};
use secp256k1_zkp::{All, Secp256k1};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::ln::db::{
    OutgoingContractAccountKey, OutgoingContractAccountKeyPrefix, OutgoingPaymentClaimKey,
    OutgoingPaymentClaimKeyPrefix,
};
use crate::ln::outgoing::OutgoingContractAccount;
use crate::ln::LnClientError;
use crate::mint::db::{CoinKey, PendingCoinsKeyPrefix};
use crate::mint::{CoinFinalizationData, MintClientError};
use crate::transaction::TransactionBuilder;
use crate::utils::{network_to_currency, ClientContext};
use crate::wallet::WalletClientError;
use crate::{
    api::{ApiError, FederationApi},
    ln::{incoming::ConfirmedInvoice, LnClient},
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
pub struct UserClientConfig(pub ClientConfig);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GatewayClientConfig {
    pub client_config: ClientConfig,
    #[serde(with = "serde_keypair")]
    pub redeem_key: bitcoin::KeyPair,
    pub timelock_delta: u64,
    pub api: Url,
    pub node_pub_key: bitcoin::secp256k1::PublicKey,
}

impl From<GatewayClientConfig> for LightningGateway {
    fn from(config: GatewayClientConfig) -> Self {
        LightningGateway {
            mint_pub_key: config.redeem_key.public_key(),
            node_pub_key: config.node_pub_key,
            api: config.api,
        }
    }
}

pub struct Client<C> {
    config: C,
    context: ClientContext,
}

impl AsRef<ClientConfig> for GatewayClientConfig {
    fn as_ref(&self) -> &ClientConfig {
        &self.client_config
    }
}

impl AsRef<ClientConfig> for UserClientConfig {
    fn as_ref(&self) -> &ClientConfig {
        &self.0
    }
}

impl<T: AsRef<ClientConfig> + Clone> Client<T> {
    pub fn ln_client(&self) -> LnClient {
        LnClient {
            config: &self.config.as_ref().ln,
            context: &self.context,
        }
    }

    pub fn mint_client(&self) -> MintClient {
        MintClient {
            config: &self.config.as_ref().mint,
            context: &self.context,
        }
    }

    pub fn wallet_client(&self) -> WalletClient {
        WalletClient {
            config: &self.config.as_ref().wallet,
            context: &self.context,
        }
    }

    pub fn config(&self) -> T {
        self.config.clone()
    }

    pub fn new(config: T, db: Box<dyn Database>, secp: Secp256k1<All>) -> Self {
        let api = api::WsFederationApi::new(
            config.as_ref().max_evil,
            config
                .as_ref()
                .api_endpoints
                .iter()
                .enumerate()
                .map(|(id, url)| {
                    let peer_id = PeerId::from(id as u16); // FIXME: potentially wrong, currently works imo
                    let url = url.clone();
                    (peer_id, url)
                })
                .collect(),
        );
        Self::new_with_api(config, db, Box::new(api), secp)
    }

    pub fn new_with_api(
        config: T,
        db: Box<dyn Database>,
        api: Box<dyn FederationApi>,
        secp: Secp256k1<All>,
    ) -> Client<T> {
        Self {
            config,
            context: ClientContext { db, api, secp },
        }
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

        tx.input(&mut vec![peg_in_key], Input::Wallet(Box::new(peg_in_proof)));

        self.submit_tx_with_change(tx, DbBatch::new(), &mut rng)
            .await
    }

    async fn submit_tx_with_change<R: RngCore + CryptoRng>(
        &self,
        tx: TransactionBuilder,
        batch: Accumulator<BatchItem>,
        rng: R,
    ) -> Result<TransactionId> {
        Ok(self
            .mint_client()
            .submit_tx_with_change(&self.config.as_ref().fee_consensus(), tx, batch, rng)
            .await?)
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
        coins: TieredMulti<SpendableCoin>,
        mut rng: R,
    ) -> Result<OutPoint> {
        let mut tx = TransactionBuilder::default();
        tx.input_coins(coins, &self.context.secp)?;
        let txid = self
            .submit_tx_with_change(tx, DbBatch::new(), &mut rng)
            .await?;

        Ok(OutPoint { txid, out_idx: 0 })
    }

    /// Validate tokens without claiming them. This function checks if signatures are valid
    /// based on the federation public key. It does not check if the nonce is unspent.
    pub async fn validate_tokens(&self, coins: &TieredMulti<SpendableCoin>) -> Result<()> {
        let tbs_pks = &self.mint_client().config.tbs_pks;
        coins.iter_items().try_for_each(|(amt, coin)| {
            if coin.coin.verify(*tbs_pks.tier(&amt)?) {
                Ok(())
            } else {
                Err(ClientError::InvalidSignature)
            }
        })
    }

    pub async fn pay_for_coins<R: RngCore + CryptoRng>(
        &self,
        coins: TieredMulti<BlindToken>,
        mut rng: R,
    ) -> Result<OutPoint> {
        let batch = DbBatch::new();
        let mut tx = TransactionBuilder::default();

        let input_coins = self.mint_client().select_coins(coins.total_amount())?;
        tx.input_coins(input_coins, &self.context.secp)?;
        tx.output(Output::Mint(coins));
        let txid = self.submit_tx_with_change(tx, batch, &mut rng).await?;

        Ok(OutPoint { txid, out_idx: 0 })
    }

    pub fn receive_coins<R: RngCore + CryptoRng>(
        &self,
        amount: Amount,
        rng: R,
        create_tx: impl FnMut(TieredMulti<BlindToken>) -> OutPoint,
    ) {
        let mut batch = DbBatch::new();
        self.mint_client()
            .receive_coins(amount, batch.transaction(), rng, create_tx);
        self.context.db.apply_batch(batch).expect("DB error");
    }

    pub async fn new_peg_out_with_fees(
        &self,
        amount: bitcoin::Amount,
        recipient: Address,
    ) -> Result<PegOut> {
        let fees = self
            .context
            .api
            .fetch_peg_out_fees(&recipient, &amount)
            .await?;
        fees.map(|fees| PegOut {
            recipient,
            amount,
            fees,
        })
        .ok_or(ClientError::PegOutWaitingForUTXOs)
    }

    pub async fn peg_out<R: RngCore + CryptoRng>(
        &self,
        peg_out: PegOut,
        mut rng: R,
    ) -> Result<OutPoint> {
        let batch = DbBatch::new();
        let mut tx = TransactionBuilder::default();

        let funding_amount = self.config.as_ref().wallet.fee_consensus.peg_out_abs
            + (peg_out.amount + peg_out.fees.amount()).into();
        let coins = self.mint_client().select_coins(funding_amount)?;
        tx.input_coins(coins, &self.context.secp)?;
        let peg_out_idx = tx.output(Output::Wallet(peg_out));

        let fedimint_tx_id = self.submit_tx_with_change(tx, batch, &mut rng).await?;

        Ok(OutPoint {
            txid: fedimint_tx_id,
            out_idx: peg_out_idx,
        })
    }

    /// Returns a bitcoin address suited to perform a fedimint [peg-in](Self::peg_in)
    ///
    /// This function requires a cryptographically secure randomness source, and utilizes the [wallet-clients](crate::wallet::WalletClient)
    /// [get_new_pegin_address](crate::wallet::WalletClient::get_new_pegin_address) to **derive** a bitcoin-address from the federations
    /// public descriptor by tweaking it.
    /// - this function will write to the clients DB
    ///
    /// read more on fedimints address derivation: <https://fedimint.org/Fedimint/wallet/>
    pub fn get_new_pegin_address<R: RngCore + CryptoRng>(&self, rng: R) -> Address {
        let mut batch = DbBatch::new();
        let address = self
            .wallet_client()
            .get_new_pegin_address(batch.transaction(), rng);
        self.context.db.apply_batch(batch).expect("DB error");
        address
    }

    /// **WARNING** this selects and removes coins from the database without confirming whether
    /// we have successfully spent them in a transaction.
    pub fn select_and_spend_coins(&self, amount: Amount) -> Result<TieredMulti<SpendableCoin>> {
        let mut batch = DbBatch::new();
        let mut tx = batch.transaction();
        let coins = self.mint_client().select_coins(amount)?;
        tx.append_from_iter(coins.iter_items().map(|(amount, coin)| {
            BatchItem::delete(CoinKey {
                amount,
                nonce: coin.coin.0.clone(),
            })
        }));
        tx.commit();
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

    /// Should be called after any transaction that might have failed in order to get any coin
    /// inputs back.
    pub async fn reissue_pending_coins<R: RngCore + CryptoRng>(&self, rng: R) -> Result<OutPoint> {
        let pending = self
            .context
            .db
            .find_by_prefix(&PendingCoinsKeyPrefix)
            .map(|res| res.expect("DB error"));

        let stream = pending
            .map(|(key, coins)| async move {
                loop {
                    match self.context.api.fetch_tx_outcome(key.0).await {
                        Ok(TransactionStatus::Rejected(_)) => return (key, coins),
                        Ok(TransactionStatus::Accepted { .. }) => {
                            return (key, TieredMulti::<SpendableCoin>::default())
                        }
                        _ => {}
                    }
                }
            })
            .collect::<FuturesUnordered<_>>();

        let mut batch = DbBatch::new();
        let mut tx = batch.transaction();
        let mut all_coins = TieredMulti::<SpendableCoin>::default();
        for (key, coins) in stream.collect::<Vec<_>>().await {
            all_coins.extend(coins);
            tx.append_delete(key);
        }
        tx.commit();
        self.context.db.apply_batch(batch).unwrap();

        self.reissue(all_coins, rng).await
    }

    pub async fn await_consensus_block_height(&self, block_height: u64) -> u64 {
        loop {
            match self.context.api.fetch_consensus_block_height().await {
                Ok(height) if height >= block_height => return height,
                _ => sleep(Duration::from_millis(100)).await,
            }
        }
    }

    pub async fn fetch_all_coins<'a>(&self) -> Vec<Result<OutPoint>> {
        self.mint_client()
            .fetch_all_coins()
            .await
            .into_iter()
            .map(|res| res.map_err(|e| e.into()))
            .collect()
    }

    pub fn coins(&self) -> TieredMulti<SpendableCoin> {
        self.mint_client().coins()
    }

    pub fn list_active_issuances(&self) -> Vec<(OutPoint, CoinFinalizationData)> {
        self.mint_client().list_active_issuances()
    }

    pub async fn fetch_epoch_history(&self, epoch: u64) -> Result<EpochHistory> {
        self.context
            .api
            .fetch_epoch_history(epoch)
            .await
            .map_err(|e| e.into())
    }
}

impl Client<UserClientConfig> {
    pub async fn fetch_registered_gateways(&self) -> Result<Vec<LightningGateway>> {
        Ok(self.context.api.fetch_gateways().await?)
    }
    pub async fn fetch_active_gateway(&self) -> Result<LightningGateway> {
        if let Some(gateway) = self
            .context
            .db
            .get_value(&LightningGatewayKey)
            .expect("DB error")
        {
            Ok(gateway)
        } else {
            Ok(self.switch_active_gateway(None).await?)
        }
    }
    /// Switches the clients active gateway to a registered gateway with the given node pubkey.
    /// If no pubkey is given (node_pub_key == None) the first available registered gateway is activated.
    /// This behavior is useful for scenarios where we don't know any registered gateways in advance.
    pub async fn switch_active_gateway(
        &self,
        node_pub_key: Option<secp256k1::PublicKey>,
    ) -> Result<LightningGateway> {
        let gateways = self.fetch_registered_gateways().await?;
        if gateways.is_empty() {
            return Err(ClientError::NoGateways);
        };
        let gateway = match node_pub_key {
            // If a pubkey was provided, try to select and activate a gateway with that pubkey.
            Some(pub_key) => gateways
                .into_iter()
                .find(|g| g.node_pub_key == pub_key)
                .ok_or(ClientError::GatewayNotFound)?,
            // Otherwise (no pubkey provided), select and activate the first registered gateway.
            None => gateways[0].clone(),
        };
        self.context
            .db
            .insert_entry(&LightningGatewayKey, &gateway)
            .expect("DB error");
        Ok(gateway)
    }

    pub async fn fund_outgoing_ln_contract<R: RngCore + CryptoRng>(
        &self,
        invoice: Invoice,
        mut rng: R,
    ) -> Result<(ContractId, OutPoint)> {
        let gateway = self.fetch_active_gateway().await?;
        let mut batch = DbBatch::new();
        let mut tx = TransactionBuilder::default();

        let consensus_height = self.context.api.fetch_consensus_block_height().await?;
        let absolute_timelock = consensus_height + TIMELOCK;

        let contract = self.ln_client().create_outgoing_output(
            batch.transaction(),
            invoice,
            &gateway,
            absolute_timelock as u32,
            &mut rng,
        )?;

        let contract_id = match &contract {
            ContractOrOfferOutput::Contract(c) => c.contract.contract_id(),
            ContractOrOfferOutput::Offer(_) => {
                panic!()
            } // FIXME: impl TryFrom
        };
        let ln_output = Output::LN(contract);

        let coins = self.mint_client().select_coins(ln_output.amount())?;
        tx.input_coins(coins, &self.context.secp)?;
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
        mut rng: R,
    ) -> Result<ConfirmedInvoice> {
        let gateway = self.fetch_active_gateway().await?;
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

        #[cfg(not(target_family = "wasm"))]
        let duration_since_epoch = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        #[cfg(target_family = "wasm")]
        let duration_since_epoch =
            Duration::from_secs_f64(js_sys::Date::new_0().get_time() / 1000.);

        let invoice = InvoiceBuilder::new(network_to_currency(self.config.0.wallet.network))
            .amount_milli_satoshis(amount.milli_sat)
            .description(description)
            .payment_hash(payment_hash)
            .payment_secret(payment_secret)
            .duration_since_epoch(duration_since_epoch)
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
        let timeout = std::time::Duration::from_secs(15);
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

    /// Notify gateway that we've escrowed tokens they can claim by routing our payment and wait
    /// for them to do so
    pub async fn await_outgoing_contract_execution(&self, contract_id: ContractId) -> Result<()> {
        let gateway = self.fetch_active_gateway().await?;
        let future = reqwest::Client::new()
            .post(
                gateway
                    .api
                    .join("pay_invoice")
                    .expect("'pay_invoice' contains no invalid characters for a URL")
                    .as_str(),
            )
            .json(&contract_id)
            .send();
        fedimint_api::task::timeout(Duration::from_secs(15), future)
            .await
            .map_err(|_| ClientError::OutgoingPaymentTimeout)??;
        Ok(())
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
        let our_pub_key = secp256k1_zkp::XOnlyPublicKey::from_keypair(&self.config.redeem_key);

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
            .and_then(|delta| delta.checked_sub(self.config.timelock_delta))
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
        rng: impl RngCore + CryptoRng,
    ) -> Result<OutPoint> {
        let mut batch = DbBatch::new();
        let mut tx = TransactionBuilder::default();

        let contract = self.ln_client().get_outgoing_contract(contract_id).await?;
        let input = Input::LN(contract.claim(outgoing::Preimage(preimage)));

        batch.autocommit(|batch| {
            batch.append_delete(OutgoingContractAccountKey(contract_id));
            batch.append_insert(OutgoingPaymentClaimKey(contract_id), ());
        });

        tx.input(&mut vec![self.config.redeem_key], input);
        let txid = self.submit_tx_with_change(tx, batch, rng).await?;

        Ok(OutPoint { txid, out_idx: 0 })
    }

    pub async fn buy_preimage_offer(
        &self,
        payment_hash: &bitcoin_hashes::sha256::Hash,
        amount: &Amount,
        rng: impl RngCore + CryptoRng,
    ) -> Result<(OutPoint, ContractId)> {
        let batch = DbBatch::new();

        // Fetch offer for this payment hash
        let offer: IncomingContractOffer = self.ln_client().get_offer(*payment_hash).await?;
        if &offer.amount > amount || &offer.hash != payment_hash {
            return Err(ClientError::InvalidOffer);
        }

        // Inputs
        let mut builder = TransactionBuilder::default();
        let coins = self.mint_client().select_coins(offer.amount)?;
        builder.input_coins(coins, &self.context.secp)?;

        // Outputs
        let our_pub_key = secp256k1_zkp::XOnlyPublicKey::from_keypair(&self.config.redeem_key);
        let contract = Contract::Incoming(IncomingContract {
            hash: offer.hash,
            encrypted_preimage: offer.encrypted_preimage.clone(),
            decrypted_preimage: DecryptedPreimage::Pending,
            gateway_key: our_pub_key,
        });
        let incoming_output = fedimint_core::transaction::Output::LN(
            ContractOrOfferOutput::Contract(ContractOutput {
                amount: *amount,
                contract: contract.clone(),
            }),
        );

        // Submit transaction
        builder.output(incoming_output);
        let txid = self.submit_tx_with_change(builder, batch, rng).await?;
        let outpoint = OutPoint { txid, out_idx: 0 };

        // FIXME: Save this contract in DB
        Ok((outpoint, contract.contract_id()))
    }

    /// Claw back funds after outgoing contract that had invalid preimage
    pub async fn refund_incoming_contract(
        &self,
        contract_id: ContractId,
        rng: impl RngCore + CryptoRng,
    ) -> Result<TransactionId> {
        let batch = DbBatch::new();
        let contract_account = self.ln_client().get_incoming_contract(contract_id).await?;

        let mut builder = TransactionBuilder::default();

        // Input claims this contract
        builder.input(
            &mut vec![self.config.redeem_key],
            Input::LN(contract_account.claim()),
        );
        let mint_tx_id = self.submit_tx_with_change(builder, batch, rng).await?;
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

    /// Register this gateway with the federation
    pub async fn register_with_federation(&self, config: LightningGateway) -> Result<()> {
        self.context
            .api
            .register_gateway(config)
            .await
            .map_err(ClientError::MintApiError)
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
    #[error("Peg-out waiting for UTXOs")]
    PegOutWaitingForUTXOs,
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
    #[error("Federation has no lightning gateways")]
    NoGateways,
    #[error("Federation has no registered lightning gateway with the given node public key")]
    GatewayNotFound,
    #[error("HTTP Error {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("Outgoing payment timeout")]
    OutgoingPaymentTimeout,
    #[error("Invalid amount tier {0:?}")]
    InvalidAmountTier(Amount),
    #[error("Invalid signature")]
    InvalidSignature,
}

impl From<InvalidAmountTierError> for ClientError {
    fn from(e: InvalidAmountTierError) -> Self {
        ClientError::InvalidAmountTier(e.0)
    }
}
