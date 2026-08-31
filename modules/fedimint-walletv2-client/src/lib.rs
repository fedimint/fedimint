#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::module_name_repetitions)]

pub use fedimint_walletv2_common as common;

mod api;
#[cfg(feature = "cli")]
mod cli;
pub mod db;
pub mod events;
mod receive_sm;
mod send_sm;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, anyhow};
use api::WalletFederationApi;
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, ScriptBuf};
use db::{
    NextOutputIndexKey, PendingReceive, PendingReceiveKey, PendingReceivePrefix,
    ReceiveOperationKey, ValidAddressIndexKey, ValidAddressIndexPrefix,
};
use events::{ReceivePaymentEvent, SendPaymentEvent};
use fedimint_api_client::api::{DynModuleApi, FederationResult};
use fedimint_client::DynGlobalClientContext;
use fedimint_client::transaction::{
    ClientInput, ClientInputBundle, ClientInputSM, ClientOutput, ClientOutputBundle,
    ClientOutputSM, FeeQuote, FeeQuoteRequest, TransactionBuilder, max_affordable_send_amount,
};
use fedimint_client_module::db::ClientModuleMigrationFn;
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{ClientContext, ClientModule, OutPointRange};
use fedimint_client_module::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client_module::sm_enum_variant_translation;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{
    Database, DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    AmountUnit, Amounts, ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::task::{TaskGroup, TaskHandle, sleep};
use fedimint_core::util::FmtCompactAnyhow as _;
use fedimint_core::{Amount, OutPoint, TransactionId, apply, async_trait_maybe_send};
use fedimint_derive_secret::{ChildId, DerivableSecret};
use fedimint_eventlog::{Event, EventLogId};
use fedimint_logging::LOG_CLIENT_MODULE_WALLETV2;
use fedimint_walletv2_common::config::WalletClientConfig;
use fedimint_walletv2_common::{
    CONFIRMATION_FINALITY_DELAY, KIND, OutputInfo, StandardScript, TxInfo, WalletCommonInit,
    WalletInput, WalletInputV0, WalletModuleTypes, WalletOutput, WalletOutputV0, descriptor,
    is_potential_receive,
};
use futures::{Stream, StreamExt};
use receive_sm::{ReceiveSMCommon, ReceiveSMState, ReceiveStateMachine};
use secp256k1::Keypair;
use send_sm::{SendSMCommon, SendSMState, SendStateMachine};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator as _;
use thiserror::Error;
use tracing::{debug, warn};

/// Number of output info entries to scan per batch.
const SLICE_SIZE: u64 = 1000;

/// Number of event log entries to read per batch.
const EVENT_LOG_PAGE_SIZE: u64 = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletOperationMeta {
    Send(SendMeta),
    Receive(ReceiveMeta),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMeta {
    pub change_outpoint_range: OutPointRange,
    pub address: Address<NetworkUnchecked>,
    pub value: bitcoin::Amount,
    pub fee: bitcoin::Amount,
    #[serde(default)]
    pub custom_meta: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiveMeta {
    pub change_outpoint_range: OutPointRange,
    pub value: bitcoin::Amount,
    pub fee: bitcoin::Amount,
    pub address: Option<Address<NetworkUnchecked>>,
    pub outpoint: Option<bitcoin::OutPoint>,
}

/// The final state of an operation sending bitcoin onchain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalSendOperationState {
    /// The transaction was successful.
    Success(bitcoin::Txid),
    /// The funding transaction was aborted.
    Aborted,
    /// A programming error has occurred or the federation is malicious.
    Failure,
}

/// The final state of an operation receiving bitcoin onchain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalReceiveOperationState {
    /// The federation accepted the claiming transaction.
    Success,
    /// The federation rejected the claiming transaction.
    Aborted,
}

/// Progress of an incoming peg-in to one of our addresses.
///
/// The [`ReceiveProgress::Confirming`] variant is derived from advisory,
/// non-consensus data reported by individual guardians, so it is **not**
/// authoritative and may move backwards: a reorg can unmine a peg-in and return
/// the stream to [`ReceiveProgress::AwaitingTransaction`]. Only
/// [`ReceiveProgress::Claiming`] and later reflect federation consensus. Do not
/// treat anything before that as money received.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiveProgress {
    /// No guardian has seen a transaction paying the address.
    ///
    /// This does not always mean nothing was sent. A federation whose guardians
    /// all run a bitcoin backend that cannot enumerate a mempool stays here
    /// until the peg-in is mined, so it also covers "sent, but nobody can see
    /// it yet".
    AwaitingTransaction,
    /// A transaction paying the address is in a guardian's mempool but is not
    /// mined.
    ///
    /// The weakest signal there is: an unmined transaction can be replaced or
    /// evicted, and this state can revert to
    /// [`ReceiveProgress::AwaitingTransaction`]. Treat it as "we have seen your
    /// payment", never as money received.
    Mempool {
        value: bitcoin::Amount,
        outpoint: bitcoin::OutPoint,
    },
    /// A transaction paying the address has been mined but is not yet deep
    /// enough for the federation to act on it.
    Confirming {
        value: bitcoin::Amount,
        outpoint: bitcoin::OutPoint,
        /// Confirmations counting the block that mined the transaction as the
        /// first, matching what a block explorer displays.
        confirmations: u64,
        /// Confirmations needed before the federation records the output.
        required: u64,
    },
    /// The federation has recorded the output and the client is claiming it.
    Claiming,
    /// The peg-in has been claimed and the ecash issued.
    Claimed,
}

#[derive(Debug, Clone)]
pub struct WalletClientModule {
    root_secret: DerivableSecret,
    cfg: WalletClientConfig,
    notifier: ModuleNotifier<WalletClientStateMachines>,
    client_ctx: ClientContext<Self>,
    db: Database,
    module_api: DynModuleApi,
}

#[derive(Debug, Clone)]
pub struct WalletClientContext {
    pub client_ctx: ClientContext<WalletClientModule>,
}

impl Context for WalletClientContext {
    const KIND: Option<ModuleKind> = Some(KIND);
}

#[apply(async_trait_maybe_send!)]
impl ClientModule for WalletClientModule {
    type Init = WalletClientInit;
    type Common = WalletModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = WalletClientContext;
    type States = WalletClientStateMachines;

    fn context(&self) -> Self::ModuleStateMachineContext {
        WalletClientContext {
            client_ctx: self.client_ctx.clone(),
        }
    }

    fn input_fee(
        &self,
        amount: &Amounts,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amounts> {
        amount
            .get(&AmountUnit::BITCOIN)
            .map(|a| Amounts::new_bitcoin(self.cfg.fee_consensus.fee(*a)))
    }

    fn output_fee(
        &self,
        amount: &Amounts,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts> {
        amount
            .get(&AmountUnit::BITCOIN)
            .map(|a| Amounts::new_bitcoin(self.cfg.fee_consensus.fee(*a)))
    }

    #[cfg(feature = "cli")]
    async fn handle_cli_command(
        &self,
        args: &[std::ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        cli::handle_cli_command(self, args).await
    }
}

#[derive(Debug, Clone, Default)]
pub struct WalletClientInit;

impl ModuleInit for WalletClientInit {
    type Common = WalletCommonInit;

    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        Box::new(BTreeMap::new().into_iter())
    }
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for WalletClientInit {
    type Module = WalletClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        let module = WalletClientModule {
            root_secret: args.module_root_secret().clone(),
            cfg: args.cfg().clone(),
            notifier: args.notifier().clone(),
            client_ctx: args.context(),
            db: args.db().clone(),
            module_api: args.module_api().clone(),
        };

        module.spawn_output_scanner(args.task_group(), args.client_span());
        module.spawn_pending_receive_scanner(args.task_group(), args.client_span());

        Ok(module)
    }

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientModuleMigrationFn> {
        BTreeMap::new()
    }

    fn used_db_prefixes(&self) -> Option<BTreeSet<u8>> {
        Some(db::DbKeyPrefix::iter().map(|p| p as u8).collect())
    }
}

impl WalletClientModule {
    /// Returns the Bitcoin network for this federation.
    pub fn get_network(&self) -> bitcoin::Network {
        self.cfg.network
    }

    /// Fetch the total value of bitcoin controlled by the federation.
    pub async fn total_value(&self) -> FederationResult<bitcoin::Amount> {
        self.module_api
            .federation_wallet()
            .await
            .map(|tx_out| tx_out.map_or(bitcoin::Amount::ZERO, |tx_out| tx_out.value))
    }

    /// Fetch the consensus block count of the federation.
    pub async fn block_count(&self) -> FederationResult<u64> {
        self.module_api.consensus_block_count().await
    }

    /// Fetch the current consensus feerate.
    pub async fn feerate(&self) -> FederationResult<Option<u64>> {
        self.module_api.consensus_feerate().await
    }

    /// Fetch information on the chain of pending bitcoin transactions.
    pub async fn pending_tx_chain(&self) -> FederationResult<Vec<TxInfo>> {
        self.module_api.pending_tx_chain().await
    }

    /// Display log of bitcoin transactions.
    pub async fn tx_chain(&self) -> FederationResult<Vec<TxInfo>> {
        self.module_api.tx_chain().await
    }

    /// Fetch the current fee required to send an onchain payment.
    pub async fn send_fee(&self) -> Result<bitcoin::Amount, SendError> {
        self.module_api
            .send_fee()
            .await
            .map_err(|e| SendError::FederationError(e.to_string()))?
            .ok_or(SendError::NoConsensusFeerateAvailable)
    }

    /// Computes the federation fee an onchain send of an output worth `amount`
    /// (the payment amount plus the on-chain miner fee) would incur, without
    /// submitting anything.
    ///
    /// A send submits a single wallet output worth `amount`; the primary module
    /// balances it by spending ecash to fund the output and minting any change.
    /// This quotes the fee of that transaction — the wallet output fee, the
    /// mint input fees on the funding notes, any mint change output fees,
    /// and sub-denomination dust — via the shared, module-agnostic fee
    /// quote.
    ///
    /// The on-chain Bitcoin miner fee is deliberately excluded: it is part of
    /// the output `amount` (see [`Self::send_fee`]), not the on-federation
    /// transaction fee.
    pub async fn send_fee_quote(&self, amount: bitcoin::Amount) -> anyhow::Result<FeeQuote> {
        let amount = Amount::from_sats(amount.to_sat());
        self.client_ctx
            .fee_quote(
                OperationId::new_random(),
                FeeQuoteRequest {
                    input_amount: Amounts::ZERO,
                    output_amount: Amounts::new_bitcoin(amount),
                    input_fee: Amounts::ZERO,
                    output_fee: Amounts::new_bitcoin(self.cfg.fee_consensus.fee(amount)),
                },
            )
            .await
    }

    /// Finds the largest value that can be sent on chain in full out of
    /// `balance` — the amount a "send everything" sweep should use.
    ///
    /// Sending `value` costs `value + fee` (the on-chain miner fee is carried
    /// inside the wallet output, see [`Self::send`]) *plus* the federation fee
    /// of funding that output — the wallet output fee, the mint input fees on
    /// the funding notes, any mint change output fees and sub-denomination
    /// dust — as quoted by [`Self::send_fee_quote`]. This returns the largest
    /// `value` satisfying
    ///
    /// ```text
    /// value + fee + send_fee_quote(value + fee).total() <= balance
    /// ```
    ///
    /// `balance` is the client's current Bitcoin balance (e.g. from
    /// `Client::get_balance_for_btc`). `fee` is the on-chain fee from
    /// [`Self::send_fee`]; pass the *same* value on to [`Self::send`], since
    /// the required feerate rises with each pending federation transaction and
    /// a value computed against a stale fee would be rejected.
    ///
    /// The maximum is found by binary search over the real fee quote (see
    /// [`max_affordable_send_amount`]) rather than by subtracting a single
    /// quote: the federation fee is charged per note, so note selection,
    /// denomination rounding, change and dust move it in steps as the value
    /// crosses thresholds, and a quote taken at the full balance would fail
    /// outright — funding it is the very thing that is unaffordable.
    ///
    /// The quote is point-in-time and moves with the balance; [`Self::send`]
    /// remains the source of truth. Note that it cannot account for the
    /// federation's own on-chain constraints — a send whose change UTXO would
    /// fall below the dust limit is still rejected by the guardians.
    ///
    /// Returns an error if the balance cannot cover even the dust limit plus
    /// fees.
    pub async fn max_sendable_amount(
        &self,
        balance: Amount,
        fee: bitcoin::Amount,
    ) -> anyhow::Result<bitcoin::Amount> {
        let fee_msats = Amount::from_sats(fee.to_sat());

        let max = max_affordable_send_amount(
            balance,
            Amount::from_sats(self.cfg.dust_limit.to_sat()),
            balance,
            // The solver searches millisatoshis, but a send funds a whole
            // number of satoshis. Rounding the probe up to the next satoshi
            // keeps the predicate conservative and makes the value handed to
            // the quote below an exact satoshi multiple.
            |value: Amount| Amount::from_sats(value.msats.div_ceil(1000)) + fee_msats,
            |funded: Amount| self.send_fee_quote(bitcoin::Amount::from_sat(funded.msats / 1000)),
        )
        .await
        .ok_or_else(|| anyhow!("Balance is too low to send any amount on chain after fees"))?;

        // `gross_up` rounded up to whole satoshis, so the largest affordable
        // amount already sits on a satoshi boundary; no value is lost here.
        Ok(bitcoin::Amount::from_sat(max.msats.div_ceil(1000)))
    }

    /// Fetch the current fee required to claim an onchain deposit (peg-in).
    pub async fn receive_fee(&self) -> Result<bitcoin::Amount, ReceiveError> {
        self.module_api
            .receive_fee()
            .await
            .map_err(|e| ReceiveError::FederationError(e.to_string()))?
            .ok_or(ReceiveError::NoConsensusFeerateAvailable)
    }

    /// Send an onchain payment with the given fee.
    pub async fn send(
        &self,
        address: Address<NetworkUnchecked>,
        value: bitcoin::Amount,
        fee: Option<bitcoin::Amount>,
        custom_meta: serde_json::Value,
    ) -> Result<OperationId, SendError> {
        if !address.is_valid_for_network(self.cfg.network) {
            return Err(SendError::WrongNetwork);
        }

        if value < self.cfg.dust_limit {
            return Err(SendError::DustValue);
        }

        let fee = match fee {
            Some(value) => value,
            None => self
                .module_api
                .send_fee()
                .await
                .map_err(|e| SendError::FederationError(e.to_string()))?
                .ok_or(SendError::NoConsensusFeerateAvailable)?,
        };

        let operation_id = OperationId::new_random();

        let destination = StandardScript::from_address(&address.clone().assume_checked())
            .ok_or(SendError::UnsupportedAddress)?;

        let client_output = ClientOutput::<WalletOutput> {
            output: WalletOutput::V0(WalletOutputV0 {
                destination,
                value,
                fee,
            }),
            amounts: Amounts::new_bitcoin(Amount::from_sats((value + fee).to_sat())),
        };

        let client_output_sm = ClientOutputSM::<WalletClientStateMachines> {
            state_machines: Arc::new(move |range: OutPointRange| {
                vec![WalletClientStateMachines::Send(SendStateMachine {
                    common: SendSMCommon {
                        operation_id,
                        outpoint: OutPoint {
                            txid: range.txid(),
                            out_idx: 0,
                        },
                        value,
                        fee,
                    },
                    state: SendSMState::Funding,
                })]
            }),
        };

        let client_output_bundle = self.client_ctx.make_client_outputs(ClientOutputBundle::new(
            vec![client_output],
            vec![client_output_sm],
        ));

        let address_clone = address.clone();

        self.client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                WalletCommonInit::KIND.as_str(),
                move |change_outpoint_range| {
                    WalletOperationMeta::Send(SendMeta {
                        change_outpoint_range,
                        address: address_clone.clone(),
                        value,
                        fee,
                        custom_meta: custom_meta.clone(),
                    })
                },
                TransactionBuilder::new().with_outputs(client_output_bundle),
            )
            .await
            .map_err(|_| SendError::InsufficientFunds)?;

        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

        self.client_ctx
            .log_event(
                &mut dbtx,
                SendPaymentEvent {
                    operation_id,
                    address,
                    value,
                    fee,
                },
            )
            .await;

        dbtx.commit_tx().await;

        Ok(operation_id)
    }

    /// Await the final state of the send operation.
    pub async fn await_final_send_operation_state(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<FinalSendOperationState> {
        let operation = self.client_ctx.get_operation(operation_id).await?;
        let mut stream = self.notifier.subscribe(operation_id).await;

        let mut stream = self
            .client_ctx
            .outcome_or_updates(&operation, operation_id, |_| true, move || {
                async_stream::stream! {
                    loop {
                        if let Some(WalletClientStateMachines::Send(state)) = stream.next().await {
                            match state.state {
                                SendSMState::Funding => {}
                                SendSMState::Success(txid) => {
                                    yield FinalSendOperationState::Success(txid);
                                    return;
                                }
                                SendSMState::Aborted(..) => {
                                    yield FinalSendOperationState::Aborted;
                                    return;
                                }
                                SendSMState::Failure => {
                                    yield FinalSendOperationState::Failure;
                                    return;
                                }
                            }
                        }
                    }
                }
            })
            .into_stream();

        let mut final_state = None;

        while let Some(state) = stream.next().await {
            final_state = Some(state);
        }

        Ok(final_state.expect("Stream contains one final state"))
    }

    /// Await the final state of the receive operation.
    pub async fn await_final_receive_operation_state(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<FinalReceiveOperationState> {
        let operation = self.client_ctx.get_operation(operation_id).await?;
        let mut stream = self.notifier.subscribe(operation_id).await;

        let mut stream = self
            .client_ctx
            .outcome_or_updates(&operation, operation_id, |_| true, move || {
                async_stream::stream! {
                    loop {
                        if let Some(WalletClientStateMachines::Receive(state)) = stream.next().await {
                            match state.state {
                                ReceiveSMState::Funding => {}
                                ReceiveSMState::Success => {
                                    yield FinalReceiveOperationState::Success;
                                    return;
                                }
                                ReceiveSMState::Aborted(..) => {
                                    yield FinalReceiveOperationState::Aborted;
                                    return;
                                }
                            }
                        }
                    }
                }
            })
            .into_stream();

        let mut final_state = None;

        while let Some(state) = stream.next().await {
            final_state = Some(state);
        }

        Ok(final_state.expect("Stream contains one final state"))
    }

    /// Resolves one of our receive addresses back to the index it was derived
    /// at.
    ///
    /// Only addresses handed out by [`Self::receive`] resolve; the set of valid
    /// indices is small, so this is a short scan rather than a stored reverse
    /// index.
    async fn address_index(&self, address: &Address) -> Option<u64> {
        let script = address.script_pubkey();

        let indices: Vec<u64> = self
            .db
            .begin_transaction_nc()
            .await
            .find_by_prefix(&ValidAddressIndexPrefix)
            .await
            .map(|entry| entry.0.0)
            .collect()
            .await;

        indices
            .into_iter()
            .find(|index| self.derive_address(*index).script_pubkey() == script)
    }

    /// The current progress of an incoming peg-in to `address`.
    ///
    /// See [`ReceiveProgress`] for why everything short of
    /// [`ReceiveProgress::Claiming`] is advisory and may move backwards.
    ///
    /// Errors if `address` was not handed out by [`Self::receive`].
    pub async fn receive_progress(&self, address: &Address) -> anyhow::Result<ReceiveProgress> {
        let address_index = self
            .address_index(address)
            .await
            .context("Address was not derived by this client")?;

        Ok(self.receive_progress_by_index(address_index).await)
    }

    async fn receive_progress_by_index(&self, address_index: u64) -> ReceiveProgress {
        let mut dbtx = self.db.begin_transaction_nc().await;

        if dbtx
            .get_value(&ReceiveOperationKey(address_index))
            .await
            .is_some()
        {
            return ReceiveProgress::Claiming;
        }

        // The module counts finality from the block after the one that mined the
        // transaction, so a peg-in is claimable one standard confirmation later
        // than the delay itself.
        let required = CONFIRMATION_FINALITY_DELAY + 1;

        let Some(pending) = dbtx.get_value(&PendingReceiveKey(address_index)).await else {
            return ReceiveProgress::AwaitingTransaction;
        };

        match pending.confirmations() {
            Some(confirmations) => ReceiveProgress::Confirming {
                value: pending.value,
                outpoint: pending.outpoint,
                // Guardians keep reporting an output for a while after it turns
                // final, so that progress does not blank out before the claim
                // begins. Clamp so a progress display cannot run past its own
                // target during that overlap.
                confirmations: confirmations.min(required),
                required,
            },
            None => ReceiveProgress::Mempool {
                value: pending.value,
                outpoint: pending.outpoint,
            },
        }
    }

    /// Streams the progress of an incoming peg-in to `address`, yielding only
    /// on change.
    ///
    /// The stream ends once the peg-in is claimed. It is driven by polling
    /// rather than server push, so updates arrive within roughly the client's
    /// scan interval of the federation observing them.
    ///
    /// Errors if `address` was not handed out by [`Self::receive`].
    pub async fn subscribe_receive_progress(
        &self,
        address: &Address,
    ) -> anyhow::Result<impl Stream<Item = ReceiveProgress> + use<>> {
        let address_index = self
            .address_index(address)
            .await
            .context("Address was not derived by this client")?;

        let module = self.clone();

        Ok(async_stream::stream! {
            let mut last: Option<ReceiveProgress> = None;

            loop {
                let progress = module.receive_progress_by_index(address_index).await;

                if progress == ReceiveProgress::Claiming {
                    if last != Some(ReceiveProgress::Claiming) {
                        yield ReceiveProgress::Claiming;
                        last = Some(ReceiveProgress::Claiming);
                    }

                    let operation_id = module
                        .db
                        .begin_transaction_nc()
                        .await
                        .get_value(&ReceiveOperationKey(address_index))
                        .await
                        .expect("Receive operation was present a moment ago");

                    // An aborted claim is retried as a fresh operation against
                    // the still unspent output, so fall back to polling and
                    // pick the new operation up once it is recorded.
                    if let Ok(FinalReceiveOperationState::Success) = module
                        .await_final_receive_operation_state(operation_id)
                        .await
                    {
                        yield ReceiveProgress::Claimed;
                        return;
                    }
                } else if last.as_ref() != Some(&progress) {
                    yield progress.clone();
                    last = Some(progress);
                }

                sleep(fedimint_walletv2_common::sleep_duration()).await;
            }
        })
    }

    /// Returns the highest valid receive address index that the background
    /// scanner has derived so far, or `None` if it has not derived one yet.
    async fn valid_index(&self) -> Option<u64> {
        self.db
            .begin_transaction_nc()
            .await
            .find_by_prefix_sorted_descending(&ValidAddressIndexPrefix)
            .await
            .next()
            .await
            .map(|entry| entry.0.0)
    }

    /// Returns the next unused receive address.
    ///
    /// To wait for a payment to this address race-free, read the client's
    /// current event log position (via the global `get_next_event_log_id`)
    /// *before* calling this, then pass that position to
    /// [`Self::await_receive`]; it will only consider payments received
    /// after that position.
    ///
    /// If the background scanner has already derived a valid address index this
    /// returns immediately. Otherwise it blocks, letting the scanner grind
    /// until it finds the next valid index, and returns once one is
    /// available.
    pub async fn receive(&self) -> Address {
        loop {
            if let Some(index) = self.valid_index().await {
                return self.derive_address(index);
            }

            sleep(Duration::from_secs(1)).await;
        }
    }

    /// Block until the next on-chain payment recorded at or after `position` is
    /// received and successfully claimed by the federation.
    ///
    /// Returns the peg-in's final state together with the event log position
    /// just past it, so that a subsequent call can resume from there to wait
    /// for the following receive.
    ///
    /// A peg-in attempt may be aborted (rejected by the federation), in which
    /// case the still-unspent output is reprocessed into a new receive
    /// operation; this keeps waiting until one succeeds.
    pub async fn await_receive(
        &self,
        position: EventLogId,
    ) -> anyhow::Result<(FinalReceiveOperationState, EventLogId)> {
        let mut position = position;

        loop {
            let (operation_id, next_position) = self.next_receive_operation(position).await;

            position = next_position;

            let state = self
                .await_final_receive_operation_state(operation_id)
                .await?;

            // A successful peg-in is terminal; an aborted one is retried as a
            // new receive operation, so keep waiting.
            if state == FinalReceiveOperationState::Success {
                // Reaching `Success` only means the peg-in claim transaction was
                // accepted into consensus. The ecash it mints is issued
                // asynchronously by the primary module, so wait for those
                // outputs before returning; otherwise the freshly claimed funds
                // may not yet be reflected in the client's balance.
                let operation = self.client_ctx.get_operation(operation_id).await?;

                if let WalletOperationMeta::Receive(ReceiveMeta {
                    change_outpoint_range,
                    ..
                }) = operation.meta::<WalletOperationMeta>()
                {
                    self.client_ctx
                        .await_primary_module_outputs(
                            operation_id,
                            change_outpoint_range.into_iter().collect(),
                        )
                        .await?;
                }

                return Ok((state, position));
            }
        }
    }

    /// Scan the event log from `position` for the next [`ReceivePaymentEvent`],
    /// blocking until one is found, and return its operation id together with
    /// the event log position just past it.
    async fn next_receive_operation(&self, position: EventLogId) -> (OperationId, EventLogId) {
        let mut position = position;

        loop {
            let events = self
                .client_ctx
                .get_event_log(Some(position), EVENT_LOG_PAGE_SIZE)
                .await;

            for entry in &events {
                position = entry.id().saturating_add(1);

                if entry.module_kind() == Some(&KIND)
                    && entry.kind == ReceivePaymentEvent::KIND
                    && let Some(event) = entry.to_event::<ReceivePaymentEvent>()
                {
                    return (event.operation_id, position);
                }
            }

            if events.is_empty() {
                // Caught up with the log; wait for new events to be written.
                sleep(Duration::from_secs(1)).await;
            }
        }
    }

    fn derive_address(&self, index: u64) -> Address {
        descriptor(
            &self.cfg.bitcoin_pks,
            &self.derive_tweak(index).public_key().consensus_hash(),
        )
        .address(self.cfg.network)
    }

    fn derive_tweak(&self, index: u64) -> Keypair {
        self.root_secret
            .child_key(ChildId(index))
            .to_secp_key(secp256k1::SECP256K1)
    }

    /// Find the next valid index starting from (and including) `start_index`.
    ///
    /// Only ~1/65536 indices are valid, so the search is CPU-bound and may scan
    /// many indices before finding one. The scan runs in bounded batches and
    /// yields to the executor between them, so it does not stall the runtime —
    /// important on wasm, which is single-threaded. It stops and returns `None`
    /// once the task group begins shutting down.
    async fn next_valid_index(&self, start_index: u64, handle: &TaskHandle) -> Option<u64> {
        /// Indices to scan per batch before yielding to the executor.
        const SCAN_BATCH: u64 = 256;

        let pks_hash = self.cfg.bitcoin_pks.consensus_hash();

        let mut index = start_index;

        while !handle.is_shutting_down() {
            for _ in 0..SCAN_BATCH {
                if is_potential_receive(&self.derive_address(index).script_pubkey(), &pks_hash) {
                    return Some(index);
                }

                index += 1;
            }

            // Hand control back to the executor between batches.
            sleep(Duration::ZERO).await;
        }

        None
    }

    /// Issue ecash for an unspent output with a given fee.
    ///
    /// Returns `None` if the output value cannot cover the fee, or if the
    /// remainder is too small to fund the claim transaction's fees.
    async fn receive_output(
        &self,
        output_index: u64,
        value: bitcoin::Amount,
        address_index: u64,
        fee: bitcoin::Amount,
        outpoint: Option<bitcoin::OutPoint>,
    ) -> Option<(OperationId, TransactionId)> {
        let operation_id = OperationId::new_random();

        let client_input = ClientInput::<WalletInput> {
            input: WalletInput::V0(WalletInputV0 {
                output_index,
                fee,
                tweak: self.derive_tweak(address_index).public_key(),
            }),
            keys: vec![self.derive_tweak(address_index)],
            amounts: Amounts::new_bitcoin(Amount::from_sats(value.checked_sub(fee)?.to_sat())),
        };

        let client_input_sm = ClientInputSM::<WalletClientStateMachines> {
            state_machines: Arc::new(move |range: OutPointRange| {
                vec![WalletClientStateMachines::Receive(ReceiveStateMachine {
                    common: ReceiveSMCommon {
                        operation_id,
                        txid: range.txid(),
                        value,
                        fee,
                    },
                    state: ReceiveSMState::Funding,
                })]
            }),
        };

        let client_input_bundle = self.client_ctx.make_client_inputs(ClientInputBundle::new(
            vec![client_input],
            vec![client_input_sm],
        ));

        let address = self.derive_address(address_index).as_unchecked().clone();

        let meta_address = address.clone();
        let range = self
            .client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                WalletCommonInit::KIND.as_str(),
                move |change_outpoint_range| {
                    WalletOperationMeta::Receive(ReceiveMeta {
                        change_outpoint_range,
                        value,
                        fee,
                        address: Some(meta_address.clone()),
                        outpoint,
                    })
                },
                TransactionBuilder::new().with_inputs(client_input_bundle),
            )
            .await
            .ok()?;

        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

        self.client_ctx
            .log_event(
                &mut dbtx,
                ReceivePaymentEvent {
                    operation_id,
                    value,
                    fee,
                    address,
                    outpoint,
                },
            )
            .await;

        // Recorded alongside the event so that receive progress for this
        // address resolves with a point lookup. A retry after an aborted claim
        // overwrites this with the new operation.
        dbtx.insert_entry(&ReceiveOperationKey(address_index), &operation_id)
            .await;

        dbtx.commit_tx().await;

        Some((operation_id, range.txid()))
    }

    fn spawn_output_scanner(&self, task_group: &TaskGroup, client_span: &tracing::Span) {
        let module = self.clone();
        let handle = task_group.make_handle();

        task_group.spawn_cancellable_with_span(client_span.clone(), "output-scanner", async move {
            let mut dbtx = module.db.begin_transaction().await;

            if dbtx
                .find_by_prefix(&ValidAddressIndexPrefix)
                .await
                .next()
                .await
                .is_none()
            {
                let Some(index) = module.next_valid_index(0, &handle).await else {
                    return;
                };

                dbtx.insert_new_entry(&ValidAddressIndexKey(index), &())
                    .await;
            }

            dbtx.commit_tx().await;

            loop {
                match module.check_outputs(&handle).await {
                    Ok(skip_wait) => {
                        if skip_wait {
                            continue;
                        }
                    }
                    Err(e) => {
                        warn!(target: LOG_CLIENT_MODULE_WALLETV2, "Failed to fetch outputs: {e}");
                    }
                }

                sleep(fedimint_walletv2_common::sleep_duration()).await;
            }
        });
    }

    /// Tracks peg-ins that are mined but not yet final, so a user who has just
    /// sent bitcoin sees confirmation progress instead of nothing at all.
    ///
    /// Kept separate from the output scanner because the two answer different
    /// questions on different cadences: that one walks an append-only consensus
    /// log and may not rewind, whereas this one mirrors a revocable view of the
    /// chain tip and must be free to drop entries again.
    fn spawn_pending_receive_scanner(&self, task_group: &TaskGroup, client_span: &tracing::Span) {
        let module = self.clone();

        task_group.spawn_cancellable_with_span(
            client_span.clone(),
            "pending-receive-scanner",
            async move {
                loop {
                    if let Err(err) = module.check_pending_receives().await {
                        warn!(
                            target: LOG_CLIENT_MODULE_WALLETV2,
                            err = %err.fmt_compact_anyhow(),
                            "Failed to fetch pending receives"
                        );
                    }

                    sleep(fedimint_walletv2_common::sleep_duration()).await;
                }
            },
        );
    }

    /// Refreshes the pending receive table from the guardians' local views.
    ///
    /// The table is rebuilt wholesale rather than appended to: entries have to
    /// disappear when a reorg unmines a peg-in, or when the output becomes
    /// final and the real receive operation takes over.
    async fn check_pending_receives(&self) -> anyhow::Result<()> {
        let pending = self.module_api.pending_outputs().await;

        let address_map: BTreeMap<ScriptBuf, u64> = self
            .db
            .begin_transaction_nc()
            .await
            .find_by_prefix(&ValidAddressIndexPrefix)
            .await
            .map(|entry| entry.0.0)
            .map(|index| (self.derive_address(index).script_pubkey(), index))
            .collect()
            .await;

        let matched: BTreeMap<u64, PendingReceive> = pending
            .outputs
            .iter()
            .filter_map(|output| {
                let address_index = address_map.get(&output.script)?;

                Some((
                    *address_index,
                    PendingReceive {
                        outpoint: output.outpoint,
                        value: output.value,
                        height: output.height,
                        block_count: pending.block_count,
                    },
                ))
            })
            .collect();

        let mut dbtx = self.db.begin_transaction().await;

        let existing: Vec<u64> = dbtx
            .find_by_prefix(&PendingReceivePrefix)
            .await
            .map(|entry| entry.0.0)
            .collect()
            .await;

        for address_index in existing
            .into_iter()
            .filter(|index| !matched.contains_key(index))
        {
            dbtx.remove_entry(&PendingReceiveKey(address_index)).await;
        }

        for (address_index, pending_receive) in &matched {
            dbtx.insert_entry(&PendingReceiveKey(*address_index), pending_receive)
                .await;
        }

        dbtx.commit_tx_result().await?;

        debug!(
            target: LOG_CLIENT_MODULE_WALLETV2,
            block_count = pending.block_count,
            reported_num = pending.outputs.len(),
            matched_num = matched.len(),
            "Scanning for pending receives"
        );

        Ok(())
    }

    async fn check_outputs(&self, handle: &TaskHandle) -> anyhow::Result<bool> {
        let mut dbtx = self.db.begin_transaction_nc().await;

        let next_output_index = dbtx.get_value(&NextOutputIndexKey).await.unwrap_or(0);

        let mut valid_indices: Vec<u64> = dbtx
            .find_by_prefix(&ValidAddressIndexPrefix)
            .await
            .map(|entry| entry.0.0)
            .collect()
            .await;

        let mut address_map: BTreeMap<ScriptBuf, u64> = valid_indices
            .iter()
            .map(|&i| (self.derive_address(i).script_pubkey(), i))
            .collect();

        let outputs = self
            .module_api
            .output_info_slice(next_output_index, next_output_index + SLICE_SIZE)
            .await?;

        let returned_num = outputs.len();
        let mut matched_num: usize = 0;

        for output in &outputs {
            if let Some(&address_index) = address_map.get(&output.script) {
                matched_num += 1;

                // Claim before extending the valid index list: the index search
                // below is CPU-bound and can take longer than a short-lived
                // client process (e.g. a cli invocation) lives. The claim is
                // quick and the extension can be retried on the next scan.
                if !output.spent && !self.process_unspent_output(output, address_index).await? {
                    return Ok(false);
                }

                let next_address_index = valid_indices
                    .last()
                    .copied()
                    .expect("we have at least one address index");

                // If we used the highest valid index, add the next valid one
                if address_index == next_address_index {
                    let Some(index) = self.next_valid_index(next_address_index + 1, handle).await
                    else {
                        return Ok(false);
                    };

                    let mut dbtx = self.db.begin_transaction().await;

                    dbtx.insert_entry(&ValidAddressIndexKey(index), &()).await;

                    dbtx.commit_tx_result().await?;

                    valid_indices.push(index);

                    address_map.insert(self.derive_address(index).script_pubkey(), index);
                }
            }

            let mut dbtx = self.db.begin_transaction().await;

            dbtx.insert_entry(&NextOutputIndexKey, &(output.index + 1))
                .await;

            dbtx.commit_tx_result().await?;
        }

        debug!(
            target: LOG_CLIENT_MODULE_WALLETV2,
            next_output_index,
            returned_num,
            matched_num,
            valid_indices_num = valid_indices.len(),
            "Scanning for outputs"
        );

        Ok(!outputs.is_empty())
    }

    async fn process_unspent_output(
        &self,
        output: &OutputInfo,
        address_index: u64,
    ) -> anyhow::Result<bool> {
        debug!(
            target: LOG_CLIENT_MODULE_WALLETV2,
            output_index = output.index,
            value_sat = output.value.to_sat(),
            address_index,
            outpoint = ?output.outpoint,
            "Discovered unspent walletv2 receive output"
        );

        // In order to not overpay on fees we choose to wait,
        // the congestion will clear up within a few blocks.
        let pending_tx_chain_len = self.module_api.pending_tx_chain().await?.len();
        if 3 <= pending_tx_chain_len {
            debug!(
                target: LOG_CLIENT_MODULE_WALLETV2,
                output_index = output.index,
                pending_tx_chain_len,
                "Delaying walletv2 receive claim because pending transaction chain is full"
            );
            return Ok(false);
        }

        let receive_fee = self
            .module_api
            .receive_fee()
            .await?
            .ok_or(anyhow!("No consensus feerate is available"))?;

        if let Some((operation_id, txid)) = self
            .receive_output(
                output.index,
                output.value,
                address_index,
                receive_fee,
                output.outpoint,
            )
            .await
        {
            debug!(
                target: LOG_CLIENT_MODULE_WALLETV2,
                output_index = output.index,
                ?operation_id,
                %txid,
                "Waiting for walletv2 receive claim acceptance"
            );
            self.client_ctx
                .transaction_updates(operation_id)
                .await
                .await_tx_accepted(txid)
                .await
                .map_err(|e| anyhow!("Claim transaction was rejected: {e}"))?;
            debug!(
                target: LOG_CLIENT_MODULE_WALLETV2,
                output_index = output.index,
                ?operation_id,
                %txid,
                "Walletv2 receive claim accepted"
            );
        } else {
            debug!(
                target: LOG_CLIENT_MODULE_WALLETV2,
                output_index = output.index,
                value_sat = output.value.to_sat(),
                fee_sat = receive_fee.to_sat(),
                "Skipping walletv2 receive claim; value cannot cover the claim fees"
            );
        }

        Ok(true)
    }
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum SendError {
    #[error("Address is from a different network than the federation.")]
    WrongNetwork,
    #[error("The value is too small")]
    DustValue,
    #[error("Federation returned an error: {0}")]
    FederationError(String),
    #[error("No consensus feerate is available at this time")]
    NoConsensusFeerateAvailable,
    #[error("The client does not have sufficient funds to send the payment")]
    InsufficientFunds,
    #[error("Unsupported address type")]
    UnsupportedAddress,
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum ReceiveError {
    #[error("Federation returned an error: {0}")]
    FederationError(String),
    #[error("No consensus feerate is available at this time")]
    NoConsensusFeerateAvailable,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum WalletClientStateMachines {
    Send(send_sm::SendStateMachine),
    Receive(receive_sm::ReceiveStateMachine),
}

impl State for WalletClientStateMachines {
    type ModuleContext = WalletClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self {
            WalletClientStateMachines::Send(sm) => sm_enum_variant_translation!(
                sm.transitions(context, global_context),
                WalletClientStateMachines::Send
            ),
            WalletClientStateMachines::Receive(sm) => sm_enum_variant_translation!(
                sm.transitions(context, global_context),
                WalletClientStateMachines::Receive
            ),
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            WalletClientStateMachines::Send(sm) => sm.operation_id(),
            WalletClientStateMachines::Receive(sm) => sm.operation_id(),
        }
    }
}

impl IntoDynInstance for WalletClientStateMachines {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}
