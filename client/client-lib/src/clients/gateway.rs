use std::time::Duration;

use crate::api::{ApiError, FederationApi};
use crate::clients::gateway::db::{
    OutgoingPaymentClaimKey, OutgoingPaymentClaimKeyPrefix, OutgoingPaymentKey,
};
use crate::clients::transaction::TransactionBuilder;
use crate::ln::outgoing::OutgoingContractAccount;
use crate::ln::{LnClient, LnClientError};
use crate::mint::{MintClient, MintClientError};
use crate::{api, OwnedClientContext};
use lightning_invoice::Invoice;
use minimint_api::db::batch::DbBatch;
use minimint_api::db::Database;
use minimint_api::{Amount, OutPoint, PeerId, TransactionId};
use minimint_core::config::ClientConfig;
use minimint_core::modules::ln::contracts::{
    incoming::{DecryptedPreimage, IncomingContract, IncomingContractOffer, Preimage},
    outgoing, Contract, ContractId, IdentifyableContract, OutgoingContractOutcome,
};
use minimint_core::modules::ln::{ContractOrOfferOutput, ContractOutput};
use minimint_core::transaction::Input;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub struct GatewayClient {
    context: OwnedClientContext<GatewayClientConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GatewayClientConfig {
    pub common: ClientConfig,
    #[serde(with = "serde_keypair")]
    pub redeem_key: secp256k1_zkp::schnorrsig::KeyPair,
    pub timelock_delta: u64,
}

#[derive(Debug)]
pub struct PaymentParameters {
    pub max_delay: u64,
    // FIXME: change to absolute fee to avoid rounding errors
    pub max_fee_percent: f64,
}

impl GatewayClient {
    pub fn new(cfg: GatewayClientConfig, db: Box<dyn Database>) -> Self {
        let api = api::HttpFederationApi::new(
            cfg.common
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
        Self::new_with_api(cfg, db, Box::new(api))
    }

    pub fn new_with_api(
        config: GatewayClientConfig,
        db: Box<dyn Database>,
        api: Box<dyn FederationApi>,
    ) -> GatewayClient {
        GatewayClient {
            context: OwnedClientContext {
                config,
                db,
                api,
                secp: secp256k1_zkp::Secp256k1::new(),
            },
        }
    }

    fn ln_client(&self) -> LnClient {
        LnClient {
            context: self.context.borrow_with_module_config(|cfg| &cfg.common.ln),
        }
    }

    fn mint_client(&self) -> MintClient {
        MintClient {
            context: self
                .context
                .borrow_with_module_config(|cfg| &cfg.common.mint),
        }
    }

    /// Fetch the specified outgoing payment contract account
    pub async fn fetch_outgoing_contract(
        &self,
        contract_id: ContractId,
    ) -> Result<OutgoingContractAccount> {
        self.ln_client()
            .get_outgoing_contract(contract_id)
            .await
            .map_err(GatewayClientError::LnClientError)
    }

    /// Check if we can claim the contract account and returns the max delay in blocks for how long
    /// other nodes on the route are allowed to delay the payment.
    pub async fn validate_outgoing_account(
        &self,
        account: &OutgoingContractAccount,
    ) -> Result<PaymentParameters> {
        let our_pub_key = secp256k1_zkp::schnorrsig::PublicKey::from_keypair(
            &self.context.secp,
            &self.context.config.redeem_key,
        );

        if account.contract.gateway_key != our_pub_key {
            return Err(GatewayClientError::NotOurKey);
        }

        let invoice: Invoice = account
            .contract
            .invoice
            .parse()
            .map_err(GatewayClientError::InvalidInvoice)?;
        let invoice_amount = Amount::from_msat(
            invoice
                .amount_milli_satoshis()
                .ok_or(GatewayClientError::InvoiceMissingAmount)?,
        );

        if account.amount < invoice_amount {
            return Err(GatewayClientError::Underfunded(
                invoice_amount,
                account.amount,
            ));
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
            .ok_or(GatewayClientError::TimeoutTooClose)?;

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
                &db::OutgoingPaymentKey(contract.contract.contract_id()),
                &contract,
            )
            .expect("DB error");
    }

    /// Lists all previously saved transactions that have not been driven to completion so far
    pub fn list_pending_outgoing(&self) -> Vec<OutgoingContractAccount> {
        self.context
            .db
            .find_by_prefix(&db::OutgoingPaymentKeyPrefix)
            .map(|res| res.expect("DB error").1)
            .collect()
    }

    /// Abort payment if our node can't route it
    pub fn abort_outgoing_payment(&self, contract_id: ContractId) {
        // FIXME: implement abort by gateway to give funds back to user prematurely
        self.context
            .db
            .remove_entry(&db::OutgoingPaymentKey(contract_id))
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
        let change = tx.change_required(&self.context.config.common.fee_consensus);
        let final_tx =
            self.mint_client()
                .finalize_change(change, batch.transaction(), tx, &mut rng);
        let txid = final_tx.tx_hash();

        batch.autocommit(|batch| {
            batch.append_delete(OutgoingPaymentKey(contract_id));
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
    ) -> Result<(minimint_api::TransactionId, ContractId)> {
        let mut batch = DbBatch::new();

        // Fetch offer for this payment hash
        let offer: IncomingContractOffer = self.ln_client().get_offer(*payment_hash).await?;
        if &offer.amount > amount || &offer.hash != payment_hash {
            return Err(GatewayClientError::InvalidOffer);
        }

        // Inputs
        let (mut coin_keys, coin_input) = self
            .mint_client()
            .create_coin_input(batch.transaction(), offer.amount)?;

        // Outputs
        let our_pub_key = secp256k1_zkp::schnorrsig::PublicKey::from_keypair(
            &self.context.secp,
            &self.context.config.redeem_key,
        );
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
        let change = builder.change_required(&self.context.config.common.fee_consensus);
        let tx = self
            .mint_client()
            .finalize_change(change, batch.transaction(), builder, &mut rng);
        let mint_tx_id = self.context.api.submit_transaction(tx).await?;

        self.context.db.apply_batch(batch).expect("DB error");

        Ok((mint_tx_id, contract.contract_id()))
    }

    /// Claw back funds after outgoing contract that had invalid preimage
    pub async fn claim_incoming_contract(
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
        let change = builder.change_required(&self.context.config.common.fee_consensus);
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
        self.mint_client().list_active_issuances()
    }

    /// Tries to fetch e-cash tokens from a certain out point. An error may just mean having queried
    /// the federation too early. Use [`MintClientError::is_retryable_fetch_coins`] to determine
    /// if the operation should be retried at a later time.
    pub async fn fetch_coins<'a>(
        &self,
        outpoint: OutPoint,
    ) -> std::result::Result<(), MintClientError> {
        let mut batch = DbBatch::new();
        self.mint_client()
            .fetch_coins(batch.transaction(), outpoint)
            .await?;
        self.context.db.apply_batch(batch).expect("DB error");
        Ok(())
    }
}

type Result<T> = std::result::Result<T, GatewayClientError>;

#[derive(Error, Debug)]
pub enum GatewayClientError {
    #[error("Error querying federation: {0}")]
    MintApiError(#[from] ApiError),
    #[error("Mint client error: {0}")]
    MintClientError(#[from] MintClientError),
    #[error("Lightning client error: {0}")]
    LnClientError(#[from] LnClientError),
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

mod db {
    use crate::ln::outgoing::OutgoingContractAccount;
    use minimint_api::db::DatabaseKeyPrefixConst;
    use minimint_api::encoding::{Decodable, Encodable};
    use minimint_core::modules::ln::contracts::ContractId;
    use minimint_core::transaction::Transaction;

    const DB_PREFIX_OUTGOING_PAYMENT: u8 = 0x50;
    const DB_PREFIX_OUTGOING_PAYMENT_CLAIM: u8 = 0x51;

    #[derive(Debug, Encodable, Decodable)]
    pub struct OutgoingPaymentKey(pub ContractId);

    impl DatabaseKeyPrefixConst for OutgoingPaymentKey {
        const DB_PREFIX: u8 = DB_PREFIX_OUTGOING_PAYMENT;
        type Key = Self;
        type Value = OutgoingContractAccount;
    }

    #[derive(Debug, Encodable, Decodable)]
    pub struct OutgoingPaymentKeyPrefix;

    impl DatabaseKeyPrefixConst for OutgoingPaymentKeyPrefix {
        const DB_PREFIX: u8 = DB_PREFIX_OUTGOING_PAYMENT;
        type Key = OutgoingPaymentKey;
        type Value = OutgoingContractAccount;
    }

    #[derive(Debug, Encodable, Decodable)]
    pub struct OutgoingPaymentClaimKey(pub ContractId);

    impl DatabaseKeyPrefixConst for OutgoingPaymentClaimKey {
        const DB_PREFIX: u8 = DB_PREFIX_OUTGOING_PAYMENT_CLAIM;
        type Key = Self;
        type Value = Transaction;
    }

    #[derive(Debug, Encodable, Decodable)]
    pub struct OutgoingPaymentClaimKeyPrefix;

    impl DatabaseKeyPrefixConst for OutgoingPaymentClaimKeyPrefix {
        const DB_PREFIX: u8 = DB_PREFIX_OUTGOING_PAYMENT_CLAIM;
        type Key = OutgoingPaymentClaimKey;
        type Value = Transaction;
    }
}

pub mod serde_keypair {
    use secp256k1_zkp::schnorrsig::KeyPair;
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
