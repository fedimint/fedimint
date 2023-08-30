pub mod api;
pub mod db;
pub mod ln;
pub mod mint;
pub mod outcome;
pub mod transaction;
pub mod utils;
pub mod wallet;

pub mod modules {
    pub use {
        fedimint_ln_client as ln, fedimint_mint_client as mint, fedimint_wallet_client as wallet,
    };
}

use std::fmt::{Debug, Formatter};
use std::iter::once;
use std::ops::Add;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::anyhow;
use api::{LnFederationApi, WalletFederationApi};
use bitcoin::util::key::KeyPair;
use bitcoin::{secp256k1, Address, Transaction as BitcoinTransaction};
use bitcoin_hashes::{sha256, Hash};
use fedimint_client::module::gen::ClientModuleGenRegistry;
use fedimint_core::api::{
    DynGlobalApi, FederationError, GlobalFederationApi, OutputOutcomeError, PeerError,
    WsFederationApi,
};
use fedimint_core::config::ClientConfig;
use fedimint_core::core::{
    LEGACY_HARDCODED_INSTANCE_ID_LN, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_core::db::Database;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::epoch::SignedEpochOutcome;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{CommonModuleGen, ModuleCommon};
use fedimint_core::outcome::TransactionStatus;
use fedimint_core::task::{self, sleep, MaybeSend};
use fedimint_core::tiered::InvalidAmountTierError;
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::{Amount, OutPoint, TieredMulti, TieredSummary, TransactionId};
use fedimint_derive_secret::{ChildId, DerivableSecret};
use fedimint_ln_client::{
    serde_routing_fees, LightningClientModule, LightningCommonGen, LightningModuleTypes,
    LightningOutputOutcome,
};
use fedimint_logging::LOG_WALLET;
use fedimint_mint_client::{MintClientModule, MintCommonGen, MintModuleTypes};
use fedimint_wallet_client::WalletModuleTypes;
use fedimint_wallet_common::{Rbf, WalletCommonGen};
use futures::stream::{self, FuturesUnordered};
use futures::StreamExt;
use itertools::{Either, Itertools};
use lightning::ln::PaymentSecret;
use lightning::routing::gossip::RoutingFees;
use lightning::routing::router::{RouteHint, RouteHintHop};
use lightning_invoice::{CreationError, Invoice, InvoiceBuilder, DEFAULT_EXPIRY_TIME};
use ln::db::LightningGatewayKey;
use ln::PayInvoicePayload;
use mint::NoteIssuanceRequests;
use modules::mint::MintOutputOutcome;
use rand::distributions::Standard;
use rand::prelude::*;
use rand::rngs::OsRng;
use rand::{thread_rng, CryptoRng, Rng, RngCore};
use secp256k1_zkp::{All, Secp256k1};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use threshold_crypto::PublicKey;
use tokio::sync::{Mutex, MutexGuard};
use tracing::{debug, info, instrument, trace};
use url::Url;

use crate::db::ClientSecretKey;
use crate::ln::db::{
    OutgoingContractAccountKey, OutgoingContractAccountKeyPrefix, OutgoingPaymentClaimKey,
    OutgoingPaymentClaimKeyPrefix, OutgoingPaymentKey,
};
use crate::ln::incoming::ConfirmedInvoice;
use crate::ln::outgoing::OutgoingContractAccount;
use crate::ln::{LnClient, LnClientError};
use crate::mint::db::{NoteKey, PendingNotesKeyPrefix};
use crate::mint::{MintClient, MintClientError, SpendableNote};
use crate::modules::ln::config::LightningClientConfig;
use crate::modules::ln::contracts::incoming::{IncomingContract, IncomingContractOffer};
use crate::modules::ln::contracts::{
    Contract, ContractId, DecryptedPreimage, IdentifiableContract, Preimage,
};
use crate::modules::ln::{ContractOutput, LightningGateway, LightningOutput};
use crate::modules::mint::config::MintClientConfig;
use crate::modules::mint::{BlindNonce, MintOutput};
use crate::modules::wallet::config::WalletClientConfig;
use crate::modules::wallet::{PegOut, WalletInput, WalletOutput};
use crate::outcome::legacy::OutputOutcome;
use crate::transaction::legacy::{Input, Output, Transaction as LegacyTransaction};
use crate::transaction::TransactionBuilder;
use crate::utils::{network_to_currency, ClientContext};
use crate::wallet::{WalletClient, WalletClientError};

/// Number of blocks until outgoing lightning contracts times out and user
/// client can get refund
const OUTGOING_LN_CONTRACT_TIMELOCK: u64 = 500;
/// Mint module's secret key derivation child id
pub const MINT_SECRET_CHILD_ID: ChildId = ChildId(0);

pub type Result<T> = std::result::Result<T, ClientError>;
pub type GatewayClient = Client<GatewayClientConfig>;
pub type UserClient = Client<UserClientConfig>;

#[derive(Debug)]
pub struct PaymentParameters {
    pub max_delay: u64,
    pub invoice_amount: Amount,
    pub max_send_amount: Amount,
    pub payment_hash: sha256::Hash,
    pub maybe_internal: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserClientConfig(pub ClientConfig);

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct GatewayClientConfig {
    pub client_config: ClientConfig,
    #[serde(with = "serde_keypair")]
    pub redeem_key: bitcoin::KeyPair,
    pub timelock_delta: u64,
    pub api: Url,
    pub node_pub_key: bitcoin::secp256k1::PublicKey,
    /// Channel identifier assigned to the mint by the gateway.
    /// All clients in this federation should use this value as
    /// `short_channel_id` when creating invoices to be settled by this
    /// gateway.
    pub mint_channel_id: u64,
    // Gateway configured routing fees
    #[serde(with = "serde_routing_fees")]
    pub fees: RoutingFees,
}

impl GatewayClientConfig {
    pub fn to_gateway_registration_info(
        &self,
        route_hints: Vec<modules::ln::route_hints::RouteHint>,
        time_to_live: Duration,
        gateway_id: secp256k1::PublicKey,
    ) -> LightningGateway {
        LightningGateway {
            mint_channel_id: self.mint_channel_id,
            gateway_redeem_key: self.redeem_key.x_only_public_key().0,
            node_pub_key: self.node_pub_key,
            api: self.api.clone(),
            route_hints,
            valid_until: fedimint_core::time::now() + time_to_live,
            fees: self.fees,
            gateway_id,
        }
    }
}

/// Use [`Client::concurrency_lock`] to obtain
pub struct ConcurrencyLock;

pub struct Client<C> {
    concurrency_lock: tokio::sync::Mutex<ConcurrencyLock>,
    config: C,
    context: Arc<ClientContext>,
    #[allow(unused)]
    root_secret: DerivableSecret,
}

impl<C> Client<C> {
    pub async fn concurrency_lock(&self) -> MutexGuard<'_, ConcurrencyLock> {
        self.concurrency_lock.lock().await
    }

    pub fn decoders(&self) -> &ModuleDecoderRegistry {
        &self.context.decoders
    }

    pub fn module_gens(&self) -> &ClientModuleGenRegistry {
        &self.context.module_gens
    }

    pub fn context(&self) -> &Arc<ClientContext> {
        &self.context
    }

    pub fn root_secret(&self) -> &DerivableSecret {
        &self.root_secret
    }
}

#[derive(Encodable, Decodable)]
pub struct ClientSecret([u8; 64]);

impl Serialize for ClientSecret {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
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

impl PaymentParameters {
    // FIXME: change to absolute fee to avoid rounding errors
    pub fn max_fee_percent(&self) -> f64 {
        let max_absolute_fee = self.max_send_amount - self.invoice_amount;
        (max_absolute_fee.msats as f64) / (self.invoice_amount.msats as f64)
    }
}

impl<T> Client<T> {
    pub fn mint_secret_static(root_secret: &DerivableSecret) -> DerivableSecret {
        root_secret.child_key(MINT_SECRET_CHILD_ID)
    }
}

// TODO: `get_module` is parsing `serde_json::Value` every time, which is not
// best for performance
impl<T: AsRef<ClientConfig> + Clone + MaybeSend> Client<T> {
    pub fn db(&self) -> &Database {
        &self.context.db
    }

    pub fn ln_client(&self) -> LnClient {
        LnClient {
            config: self
                .config
                .as_ref()
                .get_first_module_by_kind::<LightningClientConfig>("ln")
                .expect("needs lightning module client config")
                .1
                .clone(),
            context: self.context.clone(),
        }
    }

    pub fn mint_client(&self) -> MintClient {
        MintClient {
            config: self
                .config
                .as_ref()
                .get_first_module_by_kind::<MintClientConfig>("mint")
                .expect("needs mint module client config")
                .1
                .clone(),
            epoch_pk: self.config.as_ref().epoch_pk,
            context: self.context.clone(),
            secret: Self::mint_secret_static(&self.root_secret),
        }
    }

    pub fn wallet_client(&self) -> WalletClient {
        WalletClient {
            config: self
                .config
                .as_ref()
                .get_first_module_by_kind::<WalletClientConfig>("wallet")
                .expect("needs wallet module client config")
                .1
                .clone(),

            context: self.context.clone(),
        }
    }

    pub fn config(&self) -> T {
        self.config.clone()
    }

    pub fn config_ref(&self) -> &T {
        &self.config
    }

    pub async fn new(
        config: T,
        decoders: ModuleDecoderRegistry,
        module_gens: ClientModuleGenRegistry,
        db: Database,
        secp: Secp256k1<All>,
    ) -> Self {
        let api = WsFederationApi::from_config(config.as_ref());
        Self::new_with_api(config, decoders, module_gens, db, api.into(), secp).await
    }

    pub async fn new_with_api(
        config: T,
        decoders: ModuleDecoderRegistry,
        module_gens: ClientModuleGenRegistry,
        db: Database,
        api: DynGlobalApi,
        secp: Secp256k1<All>,
    ) -> Client<T> {
        let root_secret = Self::get_secret(&db).await;
        Self {
            concurrency_lock: Mutex::new(ConcurrencyLock),
            config,
            context: Arc::new(ClientContext {
                decoders,
                module_gens,
                db,
                api,
                secp,
            }),
            root_secret,
        }
    }

    /// Fetches the client secret from the database or generates a new one if
    /// none is present
    async fn get_secret(db: &Database) -> DerivableSecret {
        let mut tx = db.begin_transaction().await;
        let client_secret = tx.get_value(&ClientSecretKey).await;
        let secret = if let Some(client_secret) = client_secret {
            client_secret
        } else {
            let secret: ClientSecret = thread_rng().gen();
            let no_replacement = tx.insert_entry(&ClientSecretKey, &secret).await.is_none();
            assert!(
                no_replacement,
                "We would have overwritten our secret key, aborting!"
            );
            secret
        };
        tx.commit_tx().await;
        secret.into_root_secret()
    }

    pub async fn peg_in<R: RngCore + CryptoRng>(
        &self,
        txout_proof: TxOutProof,
        btc_transaction: BitcoinTransaction,
        mut rng: R,
    ) -> Result<TransactionId> {
        let guard = self.concurrency_lock().await;
        let mut tx = TransactionBuilder::default();

        let (peg_in_key, peg_in_proof) = self
            .wallet_client()
            .create_pegin_input(txout_proof, btc_transaction)
            .await?;

        tx.input(
            &mut vec![peg_in_key],
            Input::Wallet(WalletInput(Box::new(peg_in_proof))),
        );

        self.submit_tx_with_change(guard, tx, &mut rng).await
    }

    /// Submits a transaction to the fed, making change using our change module
    ///
    /// TODO: For safety, if the submission fails, the DB write still occurs.
    /// We should instead ensure the state of the client and consensus are
    /// always the same.
    pub async fn submit_tx_with_change<R: RngCore + CryptoRng>(
        &self,
        // when using this command, the code calling it should be protected by the guard
        guard: MutexGuard<'_, ConcurrencyLock>,
        tx: TransactionBuilder,
        rng: R,
    ) -> Result<TransactionId> {
        let mut dbtx = self.context.db.begin_transaction().await;
        let final_tx = tx.build(self, &mut dbtx, rng).await;
        dbtx.commit_tx().await;

        drop(guard);
        let result = self
            .context
            .api
            .submit_transaction(final_tx.into_type_erased())
            .await?;

        Ok(result)
    }

    /// Spent some [`SpendableNote`]s to receive a freshly minted ones
    ///
    /// This is useful in scenarios where certain notes were handed over
    /// directly to us by another user as a payment. By spending them we can
    /// make sure they can no longer be potentially double-spent.
    ///
    /// On success the out point of the newly issued e-cash notes is returned.
    /// It can be used to easily poll the transaction status using
    /// [`MintClient::fetch_notes`] until it returns `Ok(())`, indicating we
    /// received our newly issued e-cash notes.
    pub async fn reissue<R: RngCore + CryptoRng>(
        &self,
        notes: TieredMulti<SpendableNote>,
        mut rng: R,
    ) -> Result<OutPoint> {
        let guard = self.concurrency_lock().await;
        // Ensure we have the notes in the DB (in case we received them from another
        // user)
        let mut dbtx = self.context.db.begin_transaction().await;
        for (amount, note) in notes.clone() {
            let key = NoteKey {
                amount,
                nonce: note.note.0,
            };
            dbtx.insert_entry(&key, &note).await;
        }
        dbtx.commit_tx().await;

        let mut tx = TransactionBuilder::default();
        let (mut keys, input) = MintClient::ecash_input(notes)?;
        tx.input(&mut keys, input);
        let txid = self.submit_tx_with_change(guard, tx, &mut rng).await?;

        Ok(OutPoint { txid, out_idx: 0 })
    }

    /// Validate signatures on notes.
    ///
    /// This function checks if signatures are valid
    /// based on the federation public key. It does not check if the nonce is
    /// unspent.
    pub async fn validate_note_signatures(&self, notes: &TieredMulti<SpendableNote>) -> Result<()> {
        let tbs_pks = &self.mint_client().config.tbs_pks;
        notes.iter_items().try_for_each(|(amt, note)| {
            if note.note.verify(*tbs_pks.tier(&amt)?) {
                Ok(())
            } else {
                Err(ClientError::InvalidSignature)
            }
        })
    }

    /// Pay by creating notes provided (and most probably controlled) by the
    /// recipient.
    ///
    /// A standard way to facilitate a payment between users of a mint.
    /// Generate a transaction spending notes we own as inputs and
    /// creating new notes from [`BlindNonce`]s provided by the recipient as
    /// outputs.
    ///
    /// Returns a `OutPoint` of a fedimint transaction created and submitted as
    /// a payment.
    ///
    /// The name is derived from Bitcoin's terminology of "pay to
    /// `<address-type>`".
    pub async fn pay_to_blind_nonces<R: RngCore + CryptoRng>(
        &self,
        blind_nonces: TieredMulti<BlindNonce>,
        mut rng: R,
    ) -> Result<OutPoint> {
        let guard = self.concurrency_lock().await;
        let mut tx = TransactionBuilder::default();

        let (mut keys, input) = self
            .mint_client()
            .select_input(blind_nonces.total_amount())
            .await?;
        tx.input(&mut keys, input);

        tx.output(Output::Mint(MintOutput(blind_nonces)));
        let txid = self.submit_tx_with_change(guard, tx, &mut rng).await?;

        Ok(OutPoint { txid, out_idx: 0 })
    }

    /// Receive e-cash directly from another user when online (vs. offline
    /// transfer)
    ///
    /// Generates notes that another user will pay for and let us know the
    /// OutPoint in `create_tx` Payer can use the `pay_to_blind_nonces`
    /// function Allows transfer of e-cash without risk of double-spend or
    /// not having exact change
    pub async fn receive_notes(
        &self,
        amount: Amount,
    ) -> (TieredMulti<BlindNonce>, Box<dyn Fn(OutPoint)>) {
        self.mint_client().receive_notes(amount).await
    }

    pub async fn new_peg_out_with_fees(
        &self,
        amount: bitcoin::Amount,
        recipient: Address,
    ) -> Result<PegOut> {
        let fees = self
            .context
            .api
            .fetch_peg_out_fees(&recipient, amount)
            .await?;
        fees.map(|fees| PegOut {
            recipient,
            amount,
            fees,
        })
        .ok_or(ClientError::PegOutWaitingForUTXOs)
    }

    pub async fn rbf_tx(&self, rbf: Rbf) -> Result<OutPoint> {
        let guard = self.concurrency_lock().await;
        let mut tx = TransactionBuilder::default();

        let amount = rbf.fees.amount().into();
        let (mut keys, input) = self.mint_client().select_input(amount).await?;
        tx.input(&mut keys, input);
        let peg_out_idx = tx.output(Output::Wallet(WalletOutput::Rbf(rbf)));

        let fedimint_tx_id = self.submit_tx_with_change(guard, tx, &mut OsRng).await?;

        Ok(OutPoint {
            txid: fedimint_tx_id,
            out_idx: peg_out_idx,
        })
    }

    pub async fn peg_out<R: RngCore + CryptoRng>(
        &self,
        peg_out: PegOut,
        mut rng: R,
    ) -> Result<OutPoint> {
        let funding_amount = self
            .config
            .as_ref()
            .get_first_module_by_kind::<WalletClientConfig>("wallet")
            .expect("missing wallet module config")
            .1
            .fee_consensus
            .peg_out_abs
            + (peg_out.amount + peg_out.fees.amount()).into();

        let guard = self.concurrency_lock().await;
        let mut tx = TransactionBuilder::default();

        let (mut keys, input) = self.mint_client().select_input(funding_amount).await?;
        tx.input(&mut keys, input);
        let peg_out_idx = tx.output(Output::Wallet(WalletOutput::PegOut(peg_out)));

        let fedimint_tx_id = self.submit_tx_with_change(guard, tx, &mut rng).await?;

        Ok(OutPoint {
            txid: fedimint_tx_id,
            out_idx: peg_out_idx,
        })
    }

    /// Returns a bitcoin address suited to perform a fedimint
    /// [peg-in](Self::peg_in)
    ///
    /// This function requires a cryptographically secure randomness source, and
    /// utilizes the [wallet-clients](crate::wallet::WalletClient)
    /// [get_new_pegin_address](crate::wallet::WalletClient::get_new_pegin_address) to **derive** a bitcoin-address from the federations
    /// public descriptor by tweaking it.
    /// - this function will write to the clients DB
    ///
    /// read more on fedimints address derivation: <https://fedimint.org/Fedimint/wallet/>
    pub async fn get_new_pegin_address<R: RngCore + CryptoRng>(&self, rng: R) -> Address {
        let mut dbtx = self.context.db.begin_transaction().await;
        let address = self
            .wallet_client()
            .get_new_pegin_address(&mut dbtx, rng)
            .await;
        dbtx.commit_tx().await;
        address
    }

    /// Issues a spendable amount of ecash
    ///
    /// **WARNING** the ecash will be deleted from the database, the returned
    /// ecash must be `reissued` or it will be lost
    pub async fn spend_ecash<R: RngCore + CryptoRng>(
        &self,
        amount: Amount,
        rng: R,
    ) -> Result<TieredMulti<SpendableNote>> {
        let guard = self.concurrency_lock().await;
        let notes = self.mint_client().select_notes(amount).await?;
        let mut dbtx = self.context.db.begin_transaction().await;

        let final_notes = if notes.total_amount() == amount {
            notes
        } else {
            let mut tx = TransactionBuilder::default();

            let (mut keys, input) = MintClient::ecash_input(notes)?;
            tx.input(&mut keys, input);
            let txid = self.submit_tx_with_change(guard, tx, rng).await?;
            let outpoint = OutPoint { txid, out_idx: 0 };

            self.mint_client()
                .await_fetch_notes(&mut dbtx, &outpoint)
                .await?;
            self.mint_client().select_notes(amount).await?
        };
        if final_notes.total_amount() != amount {
            return Err(ClientError::SpendReusedNote);
        }

        for (amount, note) in final_notes.iter_items() {
            dbtx.remove_entry(&NoteKey {
                amount,
                nonce: note.note.0,
            })
            .await;
        }
        dbtx.commit_tx().await;

        Ok(final_notes)
    }

    /// Removes spent ecash from the database
    pub async fn remove_ecash(&self, ecash: TieredMulti<SpendableNote>) {
        let mut dbtx = self.context.db.begin_transaction().await;

        for (amount, note) in ecash.iter_items() {
            dbtx.remove_entry(&NoteKey {
                amount,
                nonce: note.note.0,
            })
            .await;
        }
        dbtx.commit_tx().await;
    }

    /// For tests only: Select notes of a given amount, and then remint them,
    /// remove the amount of notes from the database and return it to the user.
    ///
    /// This is a respin of `spent_ecash` for tests, where it is necessary
    /// to process epochs after `self.submit_tx_with_change`. Then
    /// `remint_ecash_await` can be called to do the rest.
    ///
    /// TODO: Like `spend_ecash`, I think this function works in tests mostly
    /// by accident.
    pub async fn remint_ecash<R: RngCore + CryptoRng>(&self, amount: Amount, rng: R) -> Result<()> {
        let guard = self.concurrency_lock().await;
        let notes = self.mint_client().select_notes(amount).await?;

        let mut tx = TransactionBuilder::default();

        let (mut keys, input) = MintClient::ecash_input(notes)?;
        tx.input(&mut keys, input);
        self.submit_tx_with_change(guard, tx, rng).await?;

        Ok(())
    }

    /// Continuation of `remint_notes`
    pub async fn remint_ecash_await(&self, amount: Amount) -> Result<TieredMulti<SpendableNote>> {
        self.fetch_all_notes().await?;
        let notes = self.mint_client().select_notes(amount).await?;
        assert_eq!(notes.total_amount(), amount, "should have exact change");

        let mut dbtx = self.context.db.begin_transaction().await;
        for (amount, note) in notes.iter_items() {
            dbtx.remove_entry(&NoteKey {
                amount,
                nonce: note.note.0,
            })
            .await;
        }
        dbtx.commit_tx().await;

        Ok(notes)
    }

    /// Tries to fetch e-cash notes from a certain out point. An error may just
    /// mean having queried the federation too early. Use
    /// [`MintClientError::is_retryable`] to determine if the operation
    /// should be retried at a later time.
    pub async fn fetch_notes<'a>(&self, outpoint: OutPoint) -> Result<()> {
        let mut dbtx = self.context.db.begin_transaction().await;
        self.mint_client().fetch_notes(&mut dbtx, outpoint).await?;
        dbtx.commit_tx().await;
        Ok(())
    }

    /// Should be called after any transaction that might have failed in order
    /// to get any note inputs back.
    #[instrument(skip_all, level = "debug")]
    pub async fn reissue_pending_notes<R: RngCore + CryptoRng>(&self, rng: R) -> Result<OutPoint> {
        let mut dbtx = self.context.db.begin_transaction().await;
        let pending: Vec<_> = dbtx
            .find_by_prefix(&PendingNotesKeyPrefix)
            .await
            .collect()
            .await;

        debug!(target: LOG_WALLET, ?pending);

        let stream = stream::iter(pending)
            .map(|(key, notes)| async move {
                match self.context.api.await_tx_outcome(&key.0).await {
                    Ok(TransactionStatus::Rejected(_)) => Ok((key, notes)),
                    Ok(TransactionStatus::Accepted { .. }) => {
                        Ok((key, TieredMulti::<SpendableNote>::default()))
                    }
                    Err(err) => Err(err),
                }
            })
            .collect::<FuturesUnordered<_>>()
            .await;

        let mut dbtx = self.context.db.begin_transaction().await;
        let mut notes_to_reissue = TieredMulti::<SpendableNote>::default();
        for result in stream.collect::<Vec<_>>().await {
            let (key, notes) = result?;
            notes_to_reissue.extend(notes);
            dbtx.remove_entry(&key).await;
        }
        dbtx.commit_tx().await;

        debug!(target: LOG_WALLET, notes_to_reissue = ?notes_to_reissue.summary(), total = %notes_to_reissue.total_amount());
        trace!(target: LOG_WALLET, ?notes_to_reissue, "foo");

        self.reissue(notes_to_reissue, rng).await
    }

    pub async fn await_consensus_block_count(
        &self,
        block_count: u64,
    ) -> std::result::Result<u64, task::Elapsed> {
        task::timeout(Duration::from_secs(30), async {
            self.await_consensus_block_count_inner(block_count).await
        })
        .await
    }

    async fn await_consensus_block_count_inner(&self, requested_count: u64) -> u64 {
        loop {
            match self.context.api.fetch_consensus_block_count().await {
                Ok(current_count) if requested_count <= current_count => return current_count,
                _ => sleep(Duration::from_millis(100)).await,
            }
        }
    }

    pub async fn fetch_all_notes<'a>(&self) -> Result<Vec<OutPoint>> {
        let mut guard = self.concurrency_lock().await;
        let (errors, outpoints): (Vec<_>, Vec<_>) = self
            .mint_client()
            .fetch_all_notes(&mut guard)
            .await
            .into_iter()
            .partition_map(|result| match result {
                Ok(outpoint) => Either::Right(outpoint),
                Err(error) => Either::Left(error.into()),
            });

        if errors.is_empty() {
            Ok(outpoints)
        } else {
            Err(ClientError::UnableToFetchAllNotes(errors, outpoints))
        }
    }

    pub async fn summary(&self) -> TieredSummary {
        self.mint_client().summary().await
    }

    // FIXME: loading all notes on memory isn't ideal, consider changing the API
    pub async fn notes(&self) -> TieredMulti<SpendableNote> {
        self.mint_client().notes().await
    }

    pub async fn list_active_issuances(&self) -> Vec<(OutPoint, NoteIssuanceRequests)> {
        self.mint_client().list_active_issuances().await
    }

    pub async fn fetch_epoch_history(
        &self,
        epoch: u64,
        epoch_pk: PublicKey,
    ) -> Result<SignedEpochOutcome> {
        Ok(self
            .context
            .api
            .fetch_epoch_history(epoch, epoch_pk, &self.context.decoders)
            .await?)
    }
}

impl Client<UserClientConfig> {
    pub async fn fetch_registered_gateways(&self) -> Result<Vec<LightningGateway>> {
        Ok(self.context.api.fetch_gateways().await?)
    }

    pub async fn fetch_active_gateway(&self) -> Result<LightningGateway> {
        // FIXME: forgetting about old gws might not always be ideal. We assume that the
        // gateway stays the same except for route hints for now.
        if let Some(gateway) = self
            .context
            .db
            .begin_transaction()
            .await
            .get_value(&LightningGatewayKey)
            .await
            .filter(|gw| gw.valid_until > fedimint_core::time::now())
        {
            return Ok(gateway);
        }

        self.switch_active_gateway(None).await
    }
    /// Switches the clients active gateway to a registered gateway with the
    /// given node pubkey. If no pubkey is given (node_pub_key == None) the
    /// first available registered gateway is activated. This behavior is
    /// useful for scenarios where we don't know any registered gateways in
    /// advance.
    pub async fn switch_active_gateway(
        &self,
        gateway_id: Option<secp256k1::PublicKey>,
    ) -> Result<LightningGateway> {
        let gateways = self.fetch_registered_gateways().await?;
        if gateways.is_empty() {
            debug!("Could not find any gateways");
            return Err(ClientError::NoGateways);
        };
        let gateway = match gateway_id {
            // If a pubkey was provided, try to select and activate a gateway with that pubkey.
            Some(pub_key) => gateways
                .into_iter()
                .find(|g| g.gateway_id == pub_key)
                .ok_or_else(|| {
                    debug!(
                        "Could not find gateway with gateway public key {:?}",
                        gateway_id
                    );
                    ClientError::GatewayNotFound
                })?,
            // Otherwise (no pubkey provided), select and activate the first registered gateway.
            None => {
                debug!("No public key for gateway supplied, using first registered one");
                gateways[0].clone()
            }
        };
        let mut dbtx = self.context.db.begin_transaction().await;
        dbtx.insert_entry(&LightningGatewayKey, &gateway).await;
        dbtx.commit_tx().await;
        Ok(gateway)
    }

    pub async fn fund_outgoing_ln_contract<R: RngCore + CryptoRng>(
        &self,
        invoice: Invoice,
        mut rng: R,
    ) -> Result<(ContractId, OutPoint)> {
        let gateway = self.fetch_active_gateway().await?;
        let mut dbtx = self.context.db.begin_transaction().await;
        let mut tx = TransactionBuilder::default();

        let consensus_count = self.context.api.fetch_consensus_block_count().await?;
        let absolute_timelock = consensus_count + OUTGOING_LN_CONTRACT_TIMELOCK - 1;

        let contract = self
            .ln_client()
            .create_outgoing_output(
                &mut dbtx,
                invoice,
                &gateway,
                absolute_timelock as u32,
                &mut rng,
            )
            .await?;

        dbtx.commit_tx().await;

        let (contract_id, amount) = match &contract {
            LightningOutput::Contract(c) => {
                let contract_id = c.contract.contract_id();
                let amount = c.amount;
                (contract_id, amount)
            }
            LightningOutput::Offer(_) | LightningOutput::CancelOutgoing { .. } => {
                panic!()
            } // FIXME: impl TryFrom
        };

        let guard = self.concurrency_lock().await;
        let (mut keys, input) = self.mint_client().select_input(amount).await?;
        tx.input(&mut keys, input);
        tx.output(Output::LN(contract));
        let txid = self.submit_tx_with_change(guard, tx, &mut rng).await?;
        let outpoint = OutPoint { txid, out_idx: 0 };

        debug!("Funded outgoing contract {} in {}", contract_id, outpoint);
        Ok((contract_id, outpoint))
    }

    /// Claims a refund for an expired or cancelled outgoing contract
    ///
    /// This can be necessary when the Lightning gateway cannot route the
    /// payment, is malicious or offline. The function returns the out point
    /// of the e-cash output generated as change.
    pub async fn try_refund_outgoing_contract(
        &self,
        contract_id: ContractId,
        rng: impl RngCore + CryptoRng,
    ) -> Result<OutPoint> {
        let contract_data = self
            .context
            .db
            .begin_transaction()
            .await
            .get_value(&OutgoingPaymentKey(contract_id))
            .await
            .ok_or(ClientError::RefundUnknownOutgoingContract)?;

        let guard = self.concurrency_lock().await;
        let mut tx = TransactionBuilder::default();
        let (refund_key, refund_input) = self
            .ln_client()
            .create_refund_outgoing_contract_input(&contract_data);
        tx.input(&mut vec![*refund_key], Input::LN(refund_input));
        let txid = self.submit_tx_with_change(guard, tx, rng).await?;

        let mut dbtx = self.context.db.begin_transaction().await;
        dbtx.remove_entry(&OutgoingPaymentKey(contract_id))
            .await
            .ok_or(ClientError::DeleteUnknownOutgoingContract)?;
        dbtx.commit_tx().await;

        Ok(OutPoint { txid, out_idx: 0 })
    }

    pub async fn await_outgoing_contract_acceptance(&self, outpoint: OutPoint) -> Result<()> {
        self.context
            .api
            .await_output_outcome::<LightningOutputOutcome>(
                outpoint,
                Duration::from_secs(30),
                &<LightningClientModule as fedimint_client::module::ClientModule>::decoder(),
            )
            .await?;
        Ok(())
    }

    /// Waits for the federation to sign an ecash note.
    ///
    /// This function will poll until the returned result includes a SigResponse
    /// from the federation or it will timeout.
    pub async fn await_outpoint_outcome(&self, outpoint: OutPoint) -> Result<()> {
        let poll = || async {
            let interval = Duration::from_secs(1);
            loop {
                let res = self
                    .context
                    .api
                    .await_output_outcome::<MintOutputOutcome>(
                        outpoint,
                        Duration::from_secs(30),
                        &<MintClientModule as fedimint_client::module::ClientModule>::decoder(),
                    )
                    .await;
                if matches!(res, Ok(MintOutputOutcome(Some(_)))) {
                    return Ok(());
                }
                tracing::info!("Signature response not returned yet");
                fedimint_core::task::sleep(interval).await
            }
        };

        fedimint_core::task::timeout(Duration::from_secs(40), poll())
            .await
            .map_err(|_| ClientError::Timeout)?
    }

    pub async fn generate_confirmed_invoice<R: RngCore + CryptoRng>(
        &self,
        amount: Amount,
        description: String,
        mut rng: R,
        expiry_time: Option<u64>,
    ) -> Result<ConfirmedInvoice> {
        let (txid, invoice, payment_keypair) = self
            .generate_unconfirmed_invoice_and_submit(amount, description, &mut rng, expiry_time)
            .await?;

        self.await_invoice_confirmation(txid, invoice, payment_keypair)
            .await
    }
    pub async fn generate_unconfirmed_invoice_and_submit<R: RngCore + CryptoRng>(
        &self,
        amount: Amount,
        description: String,
        mut rng: R,
        expiry_time: Option<u64>,
    ) -> Result<(TransactionId, Invoice, KeyPair)> {
        let payment_keypair = KeyPair::new(&self.context.secp, &mut rng);
        let (invoice, ln_output) = self
            .generate_unconfirmed_invoice(
                amount,
                description,
                payment_keypair,
                &mut rng,
                expiry_time,
            )
            .await?;

        // There is no input here because this is just an announcement
        let guard = self.concurrency_lock().await;
        let mut tx = TransactionBuilder::default();
        tx.output(ln_output);
        let txid = self.submit_tx_with_change(guard, tx, &mut rng).await?;

        Ok((txid, invoice, payment_keypair))
    }

    pub async fn generate_unconfirmed_invoice<R: RngCore + CryptoRng>(
        &self,
        amount: Amount,
        description: String,
        payment_keypair: KeyPair,
        mut rng: R,
        expiry_time: Option<u64>,
    ) -> Result<(Invoice, Output)> {
        let gateway = self.fetch_active_gateway().await?;
        let preimage: [u8; 32] = payment_keypair.x_only_public_key().0.serialize();
        let payment_hash = bitcoin::secp256k1::hashes::sha256::Hash::hash(&preimage);

        // Temporary lightning node pubkey
        let (node_secret_key, node_public_key) = self.context.secp.generate_keypair(&mut rng);

        // Route hint instructing payer how to route to gateway
        let route_hint_last_hop = RouteHintHop {
            src_node_id: gateway.node_pub_key,
            short_channel_id: gateway.mint_channel_id,
            fees: RoutingFees {
                base_msat: 0,
                proportional_millionths: 0,
            },
            cltv_expiry_delta: 30,
            htlc_minimum_msat: None,
            htlc_maximum_msat: None,
        };
        let route_hints = if gateway.route_hints.is_empty() {
            vec![RouteHint(vec![route_hint_last_hop])]
        } else {
            gateway
                .route_hints
                .iter()
                .map(|rh| {
                    RouteHint(
                        rh.to_ldk_route_hint()
                            .0
                            .iter()
                            .cloned()
                            .chain(once(route_hint_last_hop.clone()))
                            .collect(),
                    )
                })
                .collect()
        };

        let duration_since_epoch = fedimint_core::time::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        let mut invoice_builder = InvoiceBuilder::new(network_to_currency(
            self.config
                .0
                .get_first_module_by_kind::<WalletClientConfig>("wallet")
                .expect("must have wallet config available")
                .1
                .network,
        ))
        .amount_milli_satoshis(amount.msats)
        .description(description)
        .payment_hash(payment_hash)
        .payment_secret(PaymentSecret(rng.gen()))
        .duration_since_epoch(duration_since_epoch)
        .min_final_cltv_expiry(18)
        .payee_pub_key(node_public_key)
        .expiry_time(Duration::from_secs(
            expiry_time.unwrap_or(DEFAULT_EXPIRY_TIME),
        ));

        for rh in route_hints {
            invoice_builder = invoice_builder.private_route(rh);
        }

        let invoice = invoice_builder.build_signed(|hash| {
            self.context
                .secp
                .sign_ecdsa_recoverable(hash, &node_secret_key)
        })?;

        let offer_output = self.ln_client().create_offer_output(
            amount,
            payment_hash,
            Preimage(preimage),
            expiry_time,
        );
        let ln_output = Output::LN(offer_output);

        Ok((invoice, ln_output))
    }

    pub async fn await_invoice_confirmation(
        &self,
        txid: TransactionId,
        invoice: Invoice,
        payment_keypair: KeyPair,
    ) -> Result<ConfirmedInvoice> {
        // Await acceptance by the federation
        let timeout = std::time::Duration::from_secs(15);
        let outpoint = OutPoint { txid, out_idx: 0 };
        self.context
            .api
            .await_output_outcome::<LightningOutputOutcome>(
                outpoint,
                timeout,
                &<LightningClientModule as fedimint_client::module::ClientModule>::decoder(),
            )
            .await?;
        let confirmed = ConfirmedInvoice {
            invoice,
            keypair: payment_keypair,
        };
        self.ln_client().save_confirmed_invoice(&confirmed).await;
        Ok(confirmed)
    }

    pub async fn claim_incoming_contract(
        &self,
        contract_id: ContractId,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<OutPoint> {
        // Lookup contract and "confirmed invoice"
        let contract = self.ln_client().get_incoming_contract(contract_id).await?;
        let ci = self.ln_client().get_confirmed_invoice(contract_id).await?;

        // Input claims this contract

        let guard = self.concurrency_lock().await;
        let mut tx = TransactionBuilder::default();
        tx.input(&mut vec![ci.keypair], Input::LN(contract.claim()));
        let txid = self.submit_tx_with_change(guard, tx, &mut rng).await?;

        // TODO: Update database if invoice is paid or expired

        Ok(OutPoint { txid, out_idx: 0 })
    }

    /// Notify gateway that we've escrowed notes they can claim by routing our
    /// payment and wait for them to do so
    pub async fn await_outgoing_contract_execution(
        &self,
        contract_id: ContractId,
        rng: impl RngCore + CryptoRng,
    ) -> Result<()> {
        let gateway = self.fetch_active_gateway().await?;

        let payload = PayInvoicePayload::new(self.config.0.federation_id, contract_id);

        let future = reqwest::Client::new()
            .post(
                gateway
                    .api
                    .join("pay_invoice")
                    .expect("'pay_invoice' contains no invalid characters for a URL")
                    .as_str(),
            )
            .json(&payload)
            .send();
        let result = fedimint_core::task::timeout(Duration::from_secs(120), future)
            .await
            .map_err(|_| ClientError::OutgoingPaymentTimeout)?
            .map_err(ClientError::HttpError);

        match result {
            Ok(response) => {
                if response.status().is_success() {
                    return Ok(());
                }

                fedimint_core::task::timeout(
                    Duration::from_secs(10),
                    self.ln_client().await_outgoing_refundable(contract_id),
                )
                .await
                .map_err(|_| ClientError::FailedPaymentNoRefund)??;

                self.try_refund_outgoing_contract(contract_id, rng).await?;
                Err(ClientError::RefundedFailedPayment)
            }
            Err(e) => Err(e),
        }
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

    /// Check if we can claim the contract account and returns the max delay in
    /// blocks for how long other nodes on the route are allowed to delay
    /// the payment.
    pub async fn validate_outgoing_account(
        &self,
        account: &OutgoingContractAccount,
    ) -> Result<PaymentParameters> {
        let our_pub_key = secp256k1_zkp::XOnlyPublicKey::from_keypair(&self.config.redeem_key).0;

        if account.contract.cancelled {
            return Err(ClientError::CancelledContract);
        }

        if account.contract.gateway_key != our_pub_key {
            return Err(ClientError::NotOurKey);
        }

        let invoice: Invoice = account.contract.invoice.clone();
        let invoice_amount = Amount::from_msats(
            invoice
                .amount_milli_satoshis()
                .ok_or(ClientError::InvoiceMissingAmount)?,
        );

        if account.amount < invoice_amount {
            return Err(ClientError::Underfunded(invoice_amount, account.amount));
        }

        let consensus_block_count = self.context.api.fetch_consensus_block_count().await?;
        // Calculate max delay taking into account current consensus block count and
        // our safety margin.
        let max_delay = (account.contract.timelock as u64)
            .checked_sub(consensus_block_count.saturating_sub(1))
            .and_then(|delta| delta.checked_sub(self.config.timelock_delta))
            .ok_or(ClientError::TimeoutTooClose)?;

        Ok(PaymentParameters {
            max_delay,
            invoice_amount,
            max_send_amount: account.amount,
            payment_hash: *invoice.payment_hash(),
            maybe_internal: self.is_maybe_internal_payment(&invoice),
        })
    }

    /// Returns true if the invoice contains us as a routing hint
    fn is_maybe_internal_payment(&self, invoice: &Invoice) -> bool {
        let maybe_route_hint_first_id = invoice
            .route_hints()
            .first()
            .and_then(|rh| rh.0.last())
            .map(|hop| hop.src_node_id);

        Some(self.config().node_pub_key) == maybe_route_hint_first_id
    }

    /// Save the details about an outgoing payment the client is about to
    /// process. This function has to be called prior to instructing the
    /// lightning node to pay the invoice since otherwise a crash could lead
    /// to loss of funds.
    ///
    /// Note though that extended periods of staying offline will result in loss
    /// of funds anyway if the client can not claim the respective contract
    /// in time.
    pub async fn save_outgoing_payment(&self, contract: OutgoingContractAccount) {
        let mut dbtx = self.context.db.begin_transaction().await;
        dbtx.insert_entry(
            &OutgoingContractAccountKey(contract.contract.contract_id()),
            &contract,
        )
        .await;
        dbtx.commit_tx().await;
    }

    /// Lists all previously saved transactions that have not been driven to
    /// completion so far
    pub async fn list_pending_outgoing(&self) -> Vec<OutgoingContractAccount> {
        self.context
            .db
            .begin_transaction()
            .await
            .find_by_prefix(&OutgoingContractAccountKeyPrefix)
            .await
            .map(|(_, contract)| contract)
            .collect()
            .await
    }

    /// Abort payment if our node can't route it and give money back to user
    pub async fn abort_outgoing_payment(&self, contract_id: ContractId) -> Result<()> {
        // FIXME: needs outbox pattern
        let mut dbtx = self.context.db.begin_transaction().await;
        let contract_account = dbtx
            .remove_entry(&OutgoingContractAccountKey(contract_id))
            .await
            .ok_or(ClientError::CancelUnknownOutgoingContract)?;
        dbtx.commit_tx().await;

        self.cancel_outgoing_contract(contract_account).await
    }

    /// Cancel an outgoing contract we haven't accepted yet, possibly because it
    /// was underfunded
    pub async fn cancel_outgoing_contract(
        &self,
        contract_account: OutgoingContractAccount,
    ) -> Result<()> {
        let cancel_signature = self.context.secp.sign_schnorr(
            &contract_account.contract.cancellation_message().into(),
            &self.config.redeem_key,
        );
        let cancel_output = self.ln_client().create_cancel_outgoing_output(
            contract_account.contract.contract_id(),
            cancel_signature,
        );
        let cancel_tx = LegacyTransaction {
            inputs: vec![],
            outputs: vec![Output::LN(cancel_output)],
            signature: None,
        };

        // TODO: protect against crashes, but the timeout being hit eventually anyway
        // makes this less of an issue
        self.context
            .api
            .submit_transaction(cancel_tx.into_type_erased())
            .await?;

        Ok(())
    }

    /// Claim an outgoing contract after acquiring the preimage by paying the
    /// associated invoice and initiates e-cash issuances to receive the
    /// bitcoin from the contract (these still need to be fetched later to
    /// finalize them).
    ///
    /// Callers need to make sure that the contract can still be claimed by the
    /// gateway and has not timed out yet. Otherwise the transaction will
    /// fail.
    pub async fn claim_outgoing_contract(
        &self,
        contract_id: ContractId,
        preimage: Preimage,
        rng: impl RngCore + CryptoRng,
    ) -> Result<OutPoint> {
        let guard = self.concurrency_lock().await;
        let mut dbtx = self.context.db.begin_transaction().await;
        let mut tx = TransactionBuilder::default();

        let contract = self.ln_client().get_outgoing_contract(contract_id).await?;
        let input = Input::LN(contract.claim(preimage));

        dbtx.remove_entry(&OutgoingContractAccountKey(contract_id))
            .await;
        dbtx.insert_entry(&OutgoingPaymentClaimKey(contract_id), &())
            .await;
        dbtx.commit_tx().await;

        tx.input(&mut vec![self.config.redeem_key], input);
        let txid = self.submit_tx_with_change(guard, tx, rng).await?;

        Ok(OutPoint { txid, out_idx: 0 })
    }

    /// Buy a lightning preimage listed for sale inside the federation
    ///
    /// Called when a lightning gateway attempts to satisfy a contract on behalf
    /// of a user
    ///
    /// * `payment_hash` - hash of the preimage we want to buy. It is included
    ///   inside a bolt11 invoice and should match the offer hash
    /// * `htlc_amount` - amount from the htlc the gateway wants to pay. Should
    ///   be less than or equal to the offer amount depending on gateway fee
    ///   policy
    #[instrument(name = "Client::buy_preimage_offer", skip(self, rng))]
    pub async fn buy_preimage_offer(
        &self,
        payment_hash: &bitcoin_hashes::sha256::Hash,
        htlc_amount: &Amount,
        rng: impl RngCore + CryptoRng,
    ) -> Result<(OutPoint, ContractId)> {
        // first span to show the span start
        info!("buy_preimage_offer");
        // Fetch offer for this payment hash
        let offer: IncomingContractOffer = self.ln_client().get_offer(*payment_hash).await?;

        if &offer.amount > htlc_amount {
            return Err(ClientError::ViolatedFeePolicy);
        }
        if &offer.hash != payment_hash {
            return Err(ClientError::InvalidOffer);
        }

        // Inputs
        let guard = self.concurrency_lock().await;
        let mut builder = TransactionBuilder::default();
        let (mut keys, input) = self.mint_client().select_input(offer.amount).await?;
        builder.input(&mut keys, input);

        // Outputs
        let our_pub_key = secp256k1_zkp::XOnlyPublicKey::from_keypair(&self.config.redeem_key).0;
        let contract = Contract::Incoming(IncomingContract {
            hash: offer.hash,
            encrypted_preimage: offer.encrypted_preimage.clone(),
            decrypted_preimage: DecryptedPreimage::Pending,
            gateway_key: our_pub_key,
        });
        let incoming_output = Output::LN(LightningOutput::Contract(ContractOutput {
            amount: offer.amount,
            contract: contract.clone(),
        }));

        // Submit transaction
        builder.output(incoming_output);
        let txid = self.submit_tx_with_change(guard, builder, rng).await?;
        let outpoint = OutPoint { txid, out_idx: 0 };

        // FIXME: Save this contract in DB
        Ok((outpoint, contract.contract_id()))
    }

    /// Claw back funds after incoming contract that had invalid preimage
    #[instrument(name = "Client::refund_incoming_contract", skip(self, rng))]
    pub async fn refund_incoming_contract(
        &self,
        contract_id: ContractId,
        rng: impl RngCore + CryptoRng,
    ) -> Result<TransactionId> {
        let contract_account = self.ln_client().get_incoming_contract(contract_id).await?;

        let guard = self.concurrency_lock().await;
        let mut builder = TransactionBuilder::default();

        // Input claims this contract
        builder.input(
            &mut vec![self.config.redeem_key],
            Input::LN(contract_account.claim()),
        );
        let mint_tx_id = self.submit_tx_with_change(guard, builder, rng).await?;
        Ok(mint_tx_id)
    }

    /// Lists all claim transactions for outgoing contracts that we have
    /// submitted but were not part of the consensus yet.
    pub async fn list_pending_claimed_outgoing(&self) -> Vec<ContractId> {
        self.context
            .db
            .begin_transaction()
            .await
            .find_by_prefix(&OutgoingPaymentClaimKeyPrefix)
            .await
            .map(|(key, _)| key.0)
            .collect()
            .await
    }

    /// Wait for a lightning preimage gateway has purchased to be decrypted by
    /// the federation
    pub async fn await_preimage_decryption(&self, outpoint: OutPoint) -> Result<Preimage> {
        let deadline = Instant::now().add(Duration::from_secs(30));

        let poll = || async {
            loop {
                match self
                    .context
                    .api
                    .await_output_outcome::<LightningOutputOutcome>(
                        outpoint,
                        deadline.saturating_duration_since(Instant::now()),
                        &<LightningClientModule as fedimint_client::module::ClientModule>::decoder(
                        ),
                    )
                    .await
                    .map(OutputOutcome::LN)
                {
                    Ok(OutputOutcome::LN(o)) if !o.is_permanent() => {
                        info!(outcome = %o, "Retrying on temporary outcome");
                        sleep(Duration::from_secs(1)).await;
                    }
                    Ok(t) => {
                        return t.try_into_variant::<DecryptedPreimage>().and_then(|maybe_preimage| {
                            match maybe_preimage {
                                DecryptedPreimage::Some(preimage) => Ok(preimage),
                                DecryptedPreimage::Pending => panic!("Pending outcomes are temporary and covered by the previous match arm"),
                                DecryptedPreimage::Invalid => Err(OutputOutcomeError::ResponseDeserialization(anyhow!("Federation says we submitted an invalid encrypted preimage, we disagree"))),
                            }
                        });
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
        };
        Ok(
            fedimint_core::task::timeout(
                deadline.saturating_duration_since(Instant::now()),
                poll(),
            )
            .await
            .map_err(|_| ClientError::Timeout)??,
        )
    }

    // TODO: improve error propagation on tx transmission
    /// Waits for a outgoing contract claim transaction to be confirmed and
    /// retransmits it periodically if this does not happen.
    pub async fn await_outgoing_contract_claimed(
        &self,
        contract_id: ContractId,
        outpoint: OutPoint,
    ) -> Result<()> {
        self.context
            .api
            .await_output_outcome::<MintOutputOutcome>(
                outpoint,
                Duration::from_secs(10),
                &<MintClientModule as fedimint_client::module::ClientModule>::decoder(),
            )
            .await?;
        // We remove the entry that indicates we are still waiting for transaction
        // confirmation. This does not mean we are finished yet. As a last step we need
        // to fetch the blind signatures for the newly issued notes, but as long as the
        // federation is honest as a whole they will produce the signatures, so we don't
        // have to worry
        let mut dbtx = self.context.db.begin_transaction().await;
        dbtx.remove_entry(&OutgoingPaymentClaimKey(contract_id))
            .await;
        dbtx.commit_tx().await;
        Ok(())
    }

    pub async fn list_fetchable_notes(&self) -> Vec<OutPoint> {
        self.mint_client()
            .list_active_issuances()
            .await
            .into_iter()
            .map(|(outpoint, _)| outpoint)
            .collect()
    }

    /// Register this gateway with the federation
    pub async fn register_with_federation(&self, config: LightningGateway) -> Result<()> {
        self.context
            .api
            .register_gateway(&config)
            .await
            .map_err(ClientError::MintApiError)
    }
}

impl Distribution<ClientSecret> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ClientSecret {
        let mut secret = [0u8; 64];
        rng.fill(&mut secret);
        ClientSecret(secret)
    }
}

impl ClientSecret {
    fn into_root_secret(self) -> DerivableSecret {
        const FEDIMINT_CLIENT_NONCE: &[u8] = b"Fedimint Client Salt";
        DerivableSecret::new_root(&self.0, FEDIMINT_CLIENT_NONCE)
    }
}

impl Debug for ClientSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClientSecret([redacted])")
    }
}

/// Builds a fake module registry which is only usable for decoding messages
/// since the client isn't modularized yet but we need the decoding
/// functionality.
pub fn module_decode_stubs() -> ModuleDecoderRegistry {
    ModuleDecoderRegistry::from_iter([
        (
            LEGACY_HARDCODED_INSTANCE_ID_LN,
            LightningCommonGen::KIND,
            LightningModuleTypes::decoder(),
        ),
        (
            LEGACY_HARDCODED_INSTANCE_ID_WALLET,
            WalletCommonGen::KIND,
            WalletModuleTypes::decoder(),
        ),
        (
            LEGACY_HARDCODED_INSTANCE_ID_MINT,
            MintCommonGen::KIND,
            MintModuleTypes::decoder(),
        ),
    ])
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
            &secret_key,
        ))
    }
}

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Error querying federation: {0}")]
    MintApiError(#[from] FederationError),
    #[error("Output outcome error: {0}")]
    OutputOutcome(#[from] OutputOutcomeError),
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
    #[error("Violated fee policy")]
    ViolatedFeePolicy,
    #[error("Tried to cancel outgoing contract that we don't know about")]
    CancelUnknownOutgoingContract,
    #[error("Tried to refund outgoing contract that we don't know about")]
    RefundUnknownOutgoingContract,
    #[error("Routing outgoing payment failed but we got a refund")]
    RefundedFailedPayment,
    #[error("Routing outgoing payment failed, we didn't get a refund (yet)")]
    FailedPaymentNoRefund,
    #[error("Failed to delete unknown outgoing contract")]
    DeleteUnknownOutgoingContract,
    #[error("Timeout")]
    Timeout,
    #[error("Failed to spend ecash, we tried to double-spend an ecash note")]
    SpendReusedNote,
    #[error("The contract is already cancelled and can't be processed by the gateway")]
    CancelledContract,
    #[error("The client config cannot be verified because {0:?}")]
    ConfigVerify(ConfigVerifyError),
    #[error("Failed to fetch notes we expected to be issued {0:?}")]
    UnableToFetchAllNotes(Vec<ClientError>, Vec<OutPoint>),
}

#[derive(Debug, Error)]
pub enum ConfigVerifyError {
    #[error("Our hash doesn't match the federation")]
    MismatchingConfigs,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Cannot hash configs")]
    CannotHash,
}

impl From<InvalidAmountTierError> for ClientError {
    fn from(e: InvalidAmountTierError) -> Self {
        ClientError::InvalidAmountTier(e.0)
    }
}
