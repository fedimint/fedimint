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
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use api::WalletFederationApi;
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, ScriptBuf};
use db::{
    HighestUsedAddressIndexKey, NextOutputIndexKey, RescanKey, RescanState, ReservedAddress,
    ReservedAddressClaim, ReservedAddressKey, ValidAddressIndexKey, ValidAddressIndexPrefix,
};
use events::{ReceivePaymentEvent, SendPaymentEvent};
use fedimint_api_client::api::{DynModuleApi, FederationError, FederationResult};
use fedimint_client::DynGlobalClientContext;
use fedimint_client::transaction::{
    ClientInput, ClientInputBundle, ClientInputSM, ClientOutput, ClientOutputBundle,
    ClientOutputSM, FeeQuote, FeeQuoteRequest, TransactionBuilder, max_affordable_send_amount,
};
use fedimint_client_module::db::ClientModuleMigrationFn;
use fedimint_client_module::error::{
    ClientModuleError, OperationLookupError, TransactionSubmitError,
};
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{ClientContext, ClientModule, OutPointRange};
use fedimint_client_module::oplog::{OperationLogEntry, UpdateStreamOrOutcome};
use fedimint_client_module::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client_module::sm_enum_variant_translation;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{
    AutocommitError, Database, DatabaseError, DatabaseTransaction, DatabaseVersion,
    IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    AmountUnit, Amounts, ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::task::{TaskGroup, TaskHandle, sleep};
use fedimint_core::{Amount, OutPoint, TransactionId, apply, async_trait_maybe_send};
use fedimint_derive_secret::{ChildId, DerivableSecret};
use fedimint_eventlog::{Event, EventLogId};
use fedimint_logging::LOG_CLIENT_MODULE_WALLETV2;
use fedimint_walletv2_common::config::WalletClientConfig;
use fedimint_walletv2_common::{
    KIND, OutputInfo, StandardScript, TxInfo, WalletCommonInit, WalletInput, WalletInputV0,
    WalletModuleTypes, WalletOutput, WalletOutputV0, descriptor, is_potential_receive,
};
use futures::StreamExt;
use receive_sm::{ReceiveSMCommon, ReceiveSMState, ReceiveStateMachine};
use secp256k1::Keypair;
use send_sm::{SendSMCommon, SendSMState, SendStateMachine};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator as _;
use thiserror::Error;
use tokio::sync::{Mutex, Notify, watch};
use tracing::{debug, warn};

/// Number of output info entries to scan per batch.
const SLICE_SIZE: u64 = 1000;

/// Number of event log entries to read per batch.
const EVENT_LOG_PAGE_SIZE: u64 = 1000;

/// The number of addresses that may be reserved ahead of the last address
/// that was paid.
///
/// A wallet restored from its seed has no record of the addresses it reserved.
/// [`WalletClientModule::rescan_reserved_addresses`] finds the payments made to
/// them by deriving this many addresses, and the one
/// [`WalletClientModule::receive`] hands out, ahead of the last address that
/// was paid. A reservation further ahead than that could be paid without the
/// restored wallet ever finding out, and every address in that range costs it
/// a search of about 65536 keys.
pub const MAX_UNPAID_RESERVATIONS: usize = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletOperationMeta {
    Send(SendMeta),
    Receive(ReceiveMeta),
    Reservation(ReservationMeta),
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
    /// The reservation the address was handed out under, if it was reserved.
    pub reservation: Option<OperationId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReservationMeta {
    pub address: Address<NetworkUnchecked>,
    /// The index the address is derived at.
    pub address_index: u64,
}

/// An address reserved with [`WalletClientModule::reserve_address`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Reservation {
    /// The operation following the payments made to the address.
    pub operation_id: OperationId,
    pub address: Address,
}

/// The state of a reservation: of the first payment made to its address.
///
/// A reservation follows one payment. Further payments to the same address
/// are claimed as well, each by a receive operation of its own that names the
/// reservation in its [`ReceiveMeta`] and its
/// [`ReceivePaymentEvent`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReservationState {
    /// No payment to the address is being claimed. Reported again after
    /// [`Self::Claiming`] if the federation rejected the claim and the
    /// payment turned out not to be worth claiming anew.
    Pending,
    /// A payment was found and the given receive operation is claiming it.
    /// Reported again, with another operation, if the federation rejects the
    /// claim and the payment is claimed anew.
    Claiming(OperationId),
    /// The given receive operation claimed the payment, and the ecash for it
    /// has been issued.
    Claimed(OperationId),
    /// The federation accepted the given receive operation's claim, but the
    /// ecash for it could not be issued.
    Failure(OperationId),
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

#[derive(Debug, Clone)]
pub struct WalletClientModule {
    root_secret: DerivableSecret,
    cfg: WalletClientConfig,
    notifier: ModuleNotifier<WalletClientStateMachines>,
    client_ctx: ClientContext<Self>,
    db: Database,
    module_api: DynModuleApi,
    /// Held while an address is reserved or recorded as paid, so that a
    /// reservation is always made against the addresses unused at that moment
    /// and no two reservations are handed the same one.
    reservation_lock: Arc<Mutex<()>>,
    /// Wakes the output scanner ahead of its next scheduled pass, when an
    /// address was reserved or a rescan asked for.
    scanner_wakeup: Arc<Notify>,
    /// Tells those waiting for an unused address that there may be one: the
    /// output scanner derived an address or finished a rescan.
    addresses_changed: watch::Sender<()>,
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
    ) -> Result<serde_json::Value, ClientModuleError> {
        cli::handle_cli_command(self, args)
            .await
            .map_err(ClientModuleError::other)
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

    async fn init(
        &self,
        args: &ClientModuleInitArgs<Self>,
    ) -> Result<Self::Module, ClientModuleError> {
        let module = WalletClientModule {
            root_secret: args.module_root_secret().clone(),
            cfg: args.cfg().clone(),
            notifier: args.notifier().clone(),
            client_ctx: args.context(),
            db: args.db().clone(),
            module_api: args.module_api().clone(),
            reservation_lock: Arc::new(Mutex::new(())),
            scanner_wakeup: Arc::new(Notify::new()),
            addresses_changed: watch::Sender::new(()),
        };

        module.spawn_output_scanner(args.task_group(), args.client_span());

        Ok(module)
    }

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientModuleMigrationFn> {
        let mut migrations: BTreeMap<DatabaseVersion, ClientModuleMigrationFn> = BTreeMap::new();

        // Records the highest address index a payment was found for, which
        // the module did not keep before. Until now the scanner derived an
        // address only once the one before it had been paid, so that is every
        // valid index but the highest.
        migrations.insert(DatabaseVersion(0), |dbtx, _, _| {
            Box::pin(async {
                let mut indices: Vec<u64> = dbtx
                    .find_by_prefix(&ValidAddressIndexPrefix)
                    .await
                    .map(|entry| entry.0.0)
                    .collect()
                    .await;

                indices.sort_unstable();

                if let Some(index) = indices.iter().rev().nth(1) {
                    dbtx.insert_new_entry(&HighestUsedAddressIndexKey, index)
                        .await;
                }

                Ok(None)
            })
        });

        migrations
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
            .map_err(|e| SendError::Federation(Box::new(e)))?
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
    pub async fn send_fee_quote(
        &self,
        amount: bitcoin::Amount,
    ) -> Result<FeeQuote, TransactionSubmitError> {
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
    /// Returns [`SendError::InsufficientFunds`] if the balance cannot cover
    /// the dust limit plus fees, or [`SendError::Failed`] if the fee probe
    /// itself failed.
    pub async fn max_sendable_amount(
        &self,
        balance: Amount,
        fee: bitcoin::Amount,
    ) -> Result<bitcoin::Amount, SendError> {
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
        .map_err(SendError::Failed)?
        .ok_or(SendError::InsufficientFunds)?;

        // `gross_up` rounded up to whole satoshis, so the largest affordable
        // amount already sits on a satoshi boundary; no value is lost here.
        Ok(bitcoin::Amount::from_sat(max.msats.div_ceil(1000)))
    }

    /// Fetch the current fee required to claim an onchain deposit (peg-in).
    pub async fn receive_fee(&self) -> Result<bitcoin::Amount, ReceiveError> {
        self.module_api
            .receive_fee()
            .await
            .map_err(|e| ReceiveError::Federation(Box::new(e)))?
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
                .map_err(|e| SendError::Federation(Box::new(e)))?
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
            .map_err(|error| match error {
                TransactionSubmitError::InsufficientFunds(_) => SendError::InsufficientFunds,
                error => SendError::Failed(error),
            })?;

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
    ) -> Result<FinalSendOperationState, OperationLookupError> {
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
    ) -> Result<FinalReceiveOperationState, OperationLookupError> {
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

    /// Returns the next unused receive address: the same one until it is
    /// paid or reserved with [`Self::reserve_address`].
    ///
    /// To wait for a payment to this address race-free, read the client's
    /// current event log position (via the global `get_next_event_log_id`)
    /// *before* calling this, then pass that position to
    /// [`Self::await_receive`]; it will only consider payments received
    /// after that position.
    ///
    /// If the background scanner has already derived an unused address this
    /// returns immediately. Otherwise it blocks, letting the scanner grind
    /// until it finds the next valid index, and returns once one is
    /// available. It also blocks while a rescan asked for with
    /// [`Self::rescan_reserved_addresses`] is running, since only once that
    /// is over is it known which addresses were paid.
    pub async fn receive(&self) -> Address {
        // Subscribed before the first look, so that a change between a look
        // and the wait that follows it is not missed.
        let mut changed = self.addresses_changed.subscribe();

        loop {
            let unused = {
                let mut dbtx = self.db.begin_transaction_nc().await;

                Self::unused_address_index(&mut dbtx).await.0
            };

            if let Some(index) = unused {
                return self.derive_address(index);
            }

            changed
                .changed()
                .await
                .expect("The module holds the sender");
        }
    }

    /// The lowest address index that is neither paid nor reserved, together
    /// with how many reservations are waiting for their first payment ahead
    /// of the last address that was paid. There is no such index to hand out
    /// while the scanner has not derived one, or while a rescan has yet to
    /// establish which addresses were paid.
    async fn unused_address_index<Cap>(
        dbtx: &mut DatabaseTransaction<'_, Cap>,
    ) -> (Option<u64>, usize)
    where
        Cap: Send,
    {
        let window = AddressWindow::load(dbtx).await;

        if dbtx.get_value(&RescanKey).await.is_some() {
            return (None, window.reserved);
        }

        (window.unused, window.reserved)
    }

    /// Reserves a receive address for the caller alone and starts an
    /// operation that follows the first payment made to it.
    ///
    /// No other call is handed the address, and [`Self::receive`] stops
    /// returning it. It can be an address [`Self::receive`] returned earlier
    /// that has not been paid since. The operation is in the operation log
    /// from the moment this returns, so [`Self::subscribe_reservation`] can
    /// follow it across a restart.
    ///
    /// If the background scanner has not derived an unused address yet, or a
    /// rescan is running, this waits for it, as [`Self::receive`] does.
    ///
    /// # Errors
    ///
    /// Fails with [`ReserveAddressError::TooManyUnpaid`] while
    /// [`MAX_UNPAID_RESERVATIONS`] addresses are reserved ahead of the last
    /// address that was paid. A wallet restored from its seed can only find
    /// payments that far ahead, see [`Self::rescan_reserved_addresses`].
    pub async fn reserve_address(&self) -> Result<Reservation, ReserveAddressError> {
        // Subscribed before the first attempt, so that a change between an
        // attempt and the wait that follows it is not missed.
        let mut changed = self.addresses_changed.subscribe();

        loop {
            let reservation = {
                let _guard = self.reservation_lock.lock().await;

                self.try_reserve_address().await?
            };

            if let Some(reservation) = reservation {
                // The reservation may have taken the last unused address the
                // scanner had derived.
                self.scanner_wakeup.notify_one();

                return Ok(reservation);
            }

            changed
                .changed()
                .await
                .expect("The module holds the sender");
        }
    }

    /// Reserves the next unused address, or returns `None` if there is none
    /// to hand out yet.
    async fn try_reserve_address(&self) -> Result<Option<Reservation>, ReserveAddressError> {
        let operation_id = OperationId::new_random();

        self.client_ctx
            .module_db()
            .autocommit(
                |dbtx, _| {
                    Box::pin(async move {
                        let (unused, reserved) = Self::unused_address_index(dbtx).await;

                        if reserved >= MAX_UNPAID_RESERVATIONS {
                            return Err(ReserveAddressError::TooManyUnpaid);
                        }

                        let Some(address_index) = unused else {
                            return Ok(None);
                        };

                        let address = self.derive_address(address_index);

                        dbtx.insert_new_entry(
                            &ReservedAddressKey(address_index),
                            &ReservedAddress {
                                operation_id,
                                claim: None,
                            },
                        )
                        .await;

                        self.client_ctx
                            .add_operation_log_entry_dbtx(
                                dbtx,
                                operation_id,
                                WalletCommonInit::KIND.as_str(),
                                WalletOperationMeta::Reservation(ReservationMeta {
                                    address: address.as_unchecked().clone(),
                                    address_index,
                                }),
                            )
                            .await;

                        Ok(Some(Reservation {
                            operation_id,
                            address,
                        }))
                    })
                },
                Some(100),
            )
            .await
            .map_err(|error| match error {
                AutocommitError::ClosureError { error, .. } => error,
                AutocommitError::CommitFailed { last_error, .. } => {
                    ReserveAddressError::Database(last_error)
                }
            })
    }

    /// Subscribes to the state of a reservation made with
    /// [`Self::reserve_address`].
    pub async fn subscribe_reservation(
        &self,
        operation_id: OperationId,
    ) -> Result<UpdateStreamOrOutcome<ReservationState>, ReservationError> {
        let (operation, meta) = self.reservation(operation_id).await?;

        let module = self.clone();

        Ok(self.client_ctx.outcome_or_updates(
            &operation,
            operation_id,
            |state| {
                matches!(
                    state,
                    ReservationState::Claimed(_) | ReservationState::Failure(_)
                )
            },
            move || {
                async_stream::stream! {
                    yield ReservationState::Pending;

                    // The claim this stream reported last. Once the federation
                    // has rejected it, the scanner replaces it with the next
                    // claim of the same payment, or removes it if the payment
                    // is not worth claiming anew.
                    let mut reported = None;

                    loop {
                        let claim = module
                            .await_recorded_claim_change(meta.address_index, reported)
                            .await;

                        reported = claim;

                        let Some(claim) = claim else {
                            yield ReservationState::Pending;

                            continue;
                        };

                        yield ReservationState::Claiming(claim);

                        let state = module
                            .await_final_receive_operation_state(claim)
                            .await
                            .expect("A claim is recorded in the transaction that creates its operation");

                        if state == FinalReceiveOperationState::Aborted {
                            continue;
                        }

                        match module.await_receive_issuance(claim).await {
                            Ok(()) => yield ReservationState::Claimed(claim),
                            Err(..) => yield ReservationState::Failure(claim),
                        }

                        return;
                    }
                }
            },
        ))
    }

    /// Returns the receive operation claiming the first payment made to a
    /// reserved address, or `None` while no payment has been found.
    ///
    /// If the federation rejects the claim the payment is claimed anew, and
    /// this returns the receive operation doing that instead, or `None` again
    /// if the payment turned out not to be worth claiming anew.
    pub async fn reservation_claim(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<OperationId>, ReservationError> {
        let (_, meta) = self.reservation(operation_id).await?;

        Ok(self
            .recorded_claim(meta.address_index)
            .await
            .map(|claim| claim.operation_id))
    }

    /// Looks up a reservation's operation and what it was made for.
    async fn reservation(
        &self,
        operation_id: OperationId,
    ) -> Result<(OperationLogEntry, ReservationMeta), ReservationError> {
        let operation = self.client_ctx.get_operation(operation_id).await?;

        let WalletOperationMeta::Reservation(meta) = operation.meta::<WalletOperationMeta>() else {
            return Err(ReservationError::NotAReservation { operation_id });
        };

        Ok((operation, meta))
    }

    /// The claim recorded for the first payment to the address at
    /// `address_index`, if the address is reserved and a payment was found.
    async fn recorded_claim(&self, address_index: u64) -> Option<ReservedAddressClaim> {
        self.db
            .begin_transaction_nc()
            .await
            .get_value(&ReservedAddressKey(address_index))
            .await
            .and_then(|reserved| reserved.claim)
    }

    /// Waits until the claim recorded for the first payment to a reserved
    /// address is no longer `known`, and returns what it is instead: another
    /// claim, or none.
    async fn await_recorded_claim_change(
        &self,
        address_index: u64,
        known: Option<OperationId>,
    ) -> Option<OperationId> {
        self.db
            .wait_key_check(&ReservedAddressKey(address_index), |reserved| {
                let claim = reserved
                    .and_then(|reserved| reserved.claim)
                    .map(|claim| claim.operation_id);

                (claim != known).then_some(claim)
            })
            .await
            .0
    }

    /// Searches the federation's outputs again, from the first one, for
    /// payments to addresses this wallet reserved before its database was
    /// created.
    ///
    /// A wallet restored from its seed has no record of its reservations. It
    /// finds the payments made to its addresses by deriving the next address
    /// only once the one before it was paid, so it stops at the first
    /// reserved address that never was, and misses a payment to one reserved
    /// after it. Call this after restoring a wallet that used
    /// [`Self::reserve_address`]: the scanner then starts over with
    /// [`MAX_UNPAID_RESERVATIONS`] more addresses derived ahead of the last
    /// one paid, which are all the addresses a reservation could have been
    /// made for.
    ///
    /// The search runs in the background and claims what it finds like any
    /// other payment. The reservations themselves are not restored. Until it
    /// has caught up, [`Self::receive`] and [`Self::reserve_address`] wait.
    pub async fn rescan_reserved_addresses(&self) {
        self.db
            .autocommit::<_, _, Infallible>(
                |dbtx, _| {
                    Box::pin(async {
                        dbtx.insert_entry(&RescanKey, &RescanState::Requested).await;

                        Ok(())
                    })
                },
                None,
            )
            .await
            .expect("Autocommit retries until the transaction commits");

        self.scanner_wakeup.notify_one();
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
    ) -> Result<(FinalReceiveOperationState, EventLogId), AwaitReceiveError> {
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
                self.await_receive_issuance(operation_id).await?;

                return Ok((state, position));
            }
        }
    }

    /// Waits for the ecash a successful receive operation mints.
    ///
    /// Reaching `Success` only means the peg-in claim transaction was accepted
    /// into consensus. The ecash it mints is issued asynchronously by the
    /// primary module, so until those outputs are final the freshly claimed
    /// funds may not be reflected in the client's balance yet.
    async fn await_receive_issuance(
        &self,
        operation_id: OperationId,
    ) -> Result<(), AwaitReceiveError> {
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

        Ok(())
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

        let client_input_bundle = ClientInputBundle::new(vec![client_input], vec![client_input_sm]);

        let address = self.derive_address(address_index).as_unchecked().clone();

        // The claim, its operation, its event and its place in the address's
        // reservation are written in one transaction. A reservation would
        // otherwise never learn of a claim submitted right before a crash.
        let range = self
            .client_ctx
            .module_db()
            .autocommit(
                |dbtx, _| {
                    let client_input_bundle = client_input_bundle.clone();
                    let address = address.clone();

                    Box::pin(async move {
                        let reserved = dbtx.get_value(&ReservedAddressKey(address_index)).await;

                        let range = self
                            .client_ctx
                            .claim_inputs(dbtx, client_input_bundle, operation_id)
                            .await?;

                        self.client_ctx
                            .add_operation_log_entry_dbtx(
                                dbtx,
                                operation_id,
                                WalletCommonInit::KIND.as_str(),
                                WalletOperationMeta::Receive(ReceiveMeta {
                                    change_outpoint_range: range,
                                    value,
                                    fee,
                                    address: Some(address.clone()),
                                    outpoint,
                                    reservation: reserved
                                        .as_ref()
                                        .map(|reserved| reserved.operation_id),
                                }),
                            )
                            .await;

                        self.client_ctx
                            .log_event(
                                dbtx,
                                ReceivePaymentEvent {
                                    operation_id,
                                    value,
                                    fee,
                                    address,
                                    outpoint,
                                    reservation: reserved
                                        .as_ref()
                                        .map(|reserved| reserved.operation_id),
                                },
                            )
                            .await;

                        // A reservation follows the first payment to its
                        // address, through every claim of it.
                        if let Some(reserved) = reserved
                            && reserved
                                .claim
                                .as_ref()
                                .is_none_or(|claim| claim.output_index == output_index)
                        {
                            dbtx.insert_entry(
                                &ReservedAddressKey(address_index),
                                &ReservedAddress {
                                    operation_id: reserved.operation_id,
                                    claim: Some(ReservedAddressClaim {
                                        output_index,
                                        operation_id,
                                    }),
                                },
                            )
                            .await;
                        }

                        Ok::<_, TransactionSubmitError>(range)
                    })
                },
                Some(100),
            )
            .await
            .ok()?;

        Some((operation_id, range.txid()))
    }

    fn spawn_output_scanner(&self, task_group: &TaskGroup, client_span: &tracing::Span) {
        let module = self.clone();
        let handle = task_group.make_handle();

        task_group.spawn_cancellable_with_span(client_span.clone(), "output-scanner", async move {
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

                if handle.is_shutting_down() {
                    return;
                }

                tokio::select! {
                    () = sleep(fedimint_walletv2_common::sleep_duration()) => {}
                    () = module.scanner_wakeup.notified() => {}
                }
            }
        });
    }

    async fn check_outputs(&self, handle: &TaskHandle) -> Result<bool, CheckOutputsError> {
        self.start_requested_rescan().await?;

        // Also where the first address is derived, and the next one after a
        // reservation took the last unused one.
        if self.derive_addresses(handle).await?.is_none() {
            return Ok(false);
        }

        let (next_output_index, mut valid_indices) = {
            let mut dbtx = self.db.begin_transaction_nc().await;

            let next_output_index = dbtx.get_value(&NextOutputIndexKey).await.unwrap_or(0);

            let valid_indices: Vec<u64> = dbtx
                .find_by_prefix(&ValidAddressIndexPrefix)
                .await
                .map(|entry| entry.0.0)
                .collect()
                .await;

            (next_output_index, valid_indices)
        };

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

                // An address is used from the moment a payment to it is
                // found, whatever becomes of the claim. Recording that first
                // keeps the address from being reserved while the claim is
                // under way, which would tie the reservation to this payment.
                self.mark_address_used(address_index).await?;

                // Claim before deriving more addresses: the index search
                // below is CPU-bound and can take longer than a short-lived
                // client process (e.g. a cli invocation) lives. The claim is
                // quick and the derivation can be retried on the next scan.
                let processed =
                    output.spent || self.process_unspent_output(output, address_index).await?;

                // The address just paid may have been the last unused one,
                // and during a rescan the addresses derived ahead have to
                // stay ahead of it for the outputs that follow.
                let Some(derived) = self.derive_addresses(handle).await? else {
                    return Ok(false);
                };

                for index in derived {
                    valid_indices.push(index);

                    address_map.insert(self.derive_address(index).script_pubkey(), index);
                }

                if !processed {
                    return Ok(false);
                }
            }

            let mut dbtx = self.db.begin_transaction().await;

            dbtx.insert_entry(&NextOutputIndexKey, &(output.index + 1))
                .await;

            dbtx.commit_tx_result().await?;
        }

        if outputs.is_empty() {
            self.finish_rescan().await?;
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

    /// Derives valid address indices until one of those still handed out is
    /// unused. While a rescan is running, derives all the addresses a
    /// reservation could have been made for instead.
    ///
    /// Returns the indices it derived, or `None` if the task group began
    /// shutting down first.
    async fn derive_addresses(
        &self,
        handle: &TaskHandle,
    ) -> Result<Option<Vec<u64>>, DatabaseError> {
        let mut derived = Vec::new();

        loop {
            // The window is read with a short-lived transaction, the search
            // runs with no transaction open, and the result is inserted in
            // its own short transaction. This avoids holding a transaction
            // snapshot across a long-running CPU-bound search that might
            // outlive RocksDB's retained write history, causing a
            // SnapshotTooOld error on commit.
            // See: https://github.com/fedimint/fedimint/issues/9202
            let (window, rescanning) = {
                let mut dbtx = self.db.begin_transaction_nc().await;

                (
                    AddressWindow::load(&mut dbtx).await,
                    dbtx.get_value(&RescanKey).await == Some(RescanState::Running),
                )
            };

            let wanted = if rescanning {
                MAX_UNPAID_RESERVATIONS + 1
            } else {
                window.reserved + 1
            };

            if wanted <= window.len {
                return Ok(Some(derived));
            }

            let Some(index) = self.next_valid_index(window.next_index, handle).await else {
                return Ok(None);
            };

            let mut dbtx = self.db.begin_transaction().await;

            dbtx.insert_entry(&ValidAddressIndexKey(index), &()).await;

            dbtx.commit_tx_result().await?;

            self.addresses_changed.send_replace(());

            derived.push(index);
        }
    }

    /// Records that a payment to the address at `address_index` was found, so
    /// that neither it nor any address below it is handed out again.
    async fn mark_address_used(&self, address_index: u64) -> Result<(), DatabaseError> {
        // A reservation reads which addresses are unused and writes other
        // keys than this does, so the two would not conflict as transactions.
        let _guard = self.reservation_lock.lock().await;

        let mut dbtx = self.db.begin_transaction().await;

        if dbtx
            .get_value(&HighestUsedAddressIndexKey)
            .await
            .is_none_or(|used| used < address_index)
        {
            dbtx.insert_entry(&HighestUsedAddressIndexKey, &address_index)
                .await;

            dbtx.commit_tx_result().await?;
        }

        Ok(())
    }

    /// Starts over from the federation's first output if
    /// [`Self::rescan_reserved_addresses`] asked for it.
    async fn start_requested_rescan(&self) -> Result<(), DatabaseError> {
        let mut dbtx = self.db.begin_transaction().await;

        if dbtx.get_value(&RescanKey).await == Some(RescanState::Requested) {
            dbtx.insert_entry(&RescanKey, &RescanState::Running).await;

            dbtx.insert_entry(&NextOutputIndexKey, &0).await;

            dbtx.commit_tx_result().await?;
        }

        Ok(())
    }

    /// Ends a rescan that has caught up with the federation's outputs.
    async fn finish_rescan(&self) -> Result<(), DatabaseError> {
        let mut dbtx = self.db.begin_transaction().await;

        if dbtx.get_value(&RescanKey).await == Some(RescanState::Running) {
            dbtx.remove_entry(&RescanKey).await;

            dbtx.commit_tx_result().await?;

            self.addresses_changed.send_replace(());
        }

        Ok(())
    }

    /// Removes the claim of the output at `output_index` from the reservation
    /// of the address it paid, once that claim was rejected and the output
    /// is not claimed anew. The reservation then follows the next payment.
    async fn forget_claim(
        &self,
        address_index: u64,
        output_index: u64,
    ) -> Result<(), DatabaseError> {
        let mut dbtx = self.db.begin_transaction().await;

        if let Some(reserved) = dbtx.get_value(&ReservedAddressKey(address_index)).await
            && reserved
                .claim
                .as_ref()
                .is_some_and(|claim| claim.output_index == output_index)
        {
            dbtx.insert_entry(
                &ReservedAddressKey(address_index),
                &ReservedAddress {
                    operation_id: reserved.operation_id,
                    claim: None,
                },
            )
            .await;

            dbtx.commit_tx_result().await?;
        }

        Ok(())
    }

    async fn process_unspent_output(
        &self,
        output: &OutputInfo,
        address_index: u64,
    ) -> Result<bool, ProcessOutputError> {
        debug!(
            target: LOG_CLIENT_MODULE_WALLETV2,
            output_index = output.index,
            value_sat = output.value.to_sat(),
            address_index,
            outpoint = ?output.outpoint,
            "Discovered unspent walletv2 receive output"
        );

        // A claim recorded for this output is one a restart or a rescan cut
        // short of its outcome. Claiming the output again would replace it in
        // the reservation with a claim the federation rejects if the first
        // one went through, so its outcome is awaited instead.
        if let Some(claim) = self.recorded_claim(address_index).await
            && claim.output_index == output.index
            && self
                .await_final_receive_operation_state(claim.operation_id)
                .await?
                == FinalReceiveOperationState::Success
        {
            return Ok(true);
        }

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
            .ok_or(ProcessOutputError::NoFeerate)?;

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
                .map_err(ProcessOutputError::ClaimRejected)?;
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

            self.forget_claim(address_index, output.index).await?;
        }

        Ok(true)
    }
}

/// The valid address indices above the highest one a payment was found for.
/// These are the only addresses still handed out.
struct AddressWindow {
    /// How many of them there are.
    len: usize,
    /// How many of them are reserved.
    reserved: usize,
    /// The lowest of them that is not reserved.
    unused: Option<u64>,
    /// Where the search for the next valid index starts.
    next_index: u64,
}

impl AddressWindow {
    async fn load<Cap>(dbtx: &mut DatabaseTransaction<'_, Cap>) -> Self
    where
        Cap: Send,
    {
        let highest_used = dbtx.get_value(&HighestUsedAddressIndexKey).await;

        let mut valid_indices: Vec<u64> = dbtx
            .find_by_prefix(&ValidAddressIndexPrefix)
            .await
            .map(|entry| entry.0.0)
            .collect()
            .await;

        valid_indices.sort_unstable();

        let mut window = Self {
            len: 0,
            reserved: 0,
            unused: None,
            next_index: valid_indices.last().map_or(0, |index| index + 1),
        };

        for index in valid_indices {
            if highest_used.is_some_and(|used| index <= used) {
                continue;
            }

            window.len += 1;

            if dbtx.get_value(&ReservedAddressKey(index)).await.is_some() {
                window.reserved += 1;
            } else if window.unused.is_none() {
                window.unused = Some(index);
            }
        }

        window
    }
}

/// A failure to send an on-chain payment.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum SendError {
    /// The destination address is not valid on the federation's network.
    #[error("Address is from a different network than the federation")]
    WrongNetwork,

    /// The value to send is below the federation's dust limit.
    #[error("The value is too small")]
    DustValue,

    /// The federation could not be asked for the current on-chain fee.
    #[error("The federation returned an error")]
    Federation(#[source] Box<FederationError>),

    /// The guardians have not agreed a feerate yet, so no on-chain fee can be
    /// quoted.
    #[error("No consensus feerate is available at this time")]
    NoConsensusFeerateAvailable,

    /// The client cannot fund the wallet output this send needs.
    #[error("The client does not have sufficient funds to send the payment")]
    InsufficientFunds,

    /// The destination is not an address type the federation can pay.
    #[error("Unsupported address type")]
    UnsupportedAddress,

    /// The send transaction could not be submitted for a reason that is not
    /// about funding.
    #[error("The send transaction could not be submitted")]
    Failed(#[source] TransactionSubmitError),
}

/// A failure to quote the fee for claiming an on-chain deposit.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ReceiveError {
    /// The federation could not be asked for the current claim fee.
    #[error("The federation returned an error")]
    Federation(#[source] Box<FederationError>),

    /// The guardians have not agreed a feerate yet, so no claim fee can be
    /// quoted.
    #[error("No consensus feerate is available at this time")]
    NoConsensusFeerateAvailable,
}

/// A failure to reserve a receive address.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ReserveAddressError {
    /// [`MAX_UNPAID_RESERVATIONS`] addresses are reserved ahead of the last
    /// address that was paid, and none of them has been paid.
    #[error("Too many reserved addresses are waiting for their first payment")]
    TooManyUnpaid,

    /// The reservation could not be written.
    #[error("The reservation could not be written to the database")]
    Database(#[source] DatabaseError),
}

/// A failure to follow a reservation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ReservationError {
    /// The operation could not be looked up.
    #[error("The reservation could not be looked up")]
    Operation(#[from] OperationLookupError),

    /// The operation is one of this module's, but not a reservation.
    #[error("Operation {} is not a reservation", .operation_id.fmt_short())]
    NotAReservation { operation_id: OperationId },
}

/// A failure to wait for the next on-chain payment to be received.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AwaitReceiveError {
    /// The receive operation could not be looked up.
    #[error("The receive operation could not be looked up")]
    Operation(#[from] OperationLookupError),

    /// The deposit was claimed, but the ecash it mints was never issued.
    #[error("The ecash for the claimed deposit could not be issued")]
    Issuance(#[from] TransactionSubmitError),
}

/// A failure while scanning the federation's outputs for payments to this
/// client.
#[derive(Debug, Error)]
enum CheckOutputsError {
    /// The federation did not serve the scan.
    #[error(transparent)]
    Federation(#[from] FederationError),

    /// The scan's progress could not be committed.
    #[error(transparent)]
    Database(#[from] DatabaseError),

    /// An unspent output paid to this client could not be claimed.
    #[error(transparent)]
    ProcessOutput(#[from] ProcessOutputError),
}

/// A failure to claim an unspent output paid to this client.
#[derive(Debug, Error)]
enum ProcessOutputError {
    /// The federation could not report its pending transactions or the
    /// receive fee.
    #[error(transparent)]
    Federation(#[from] FederationError),

    /// The federation has no consensus feerate to price the claim with.
    #[error("No consensus feerate is available")]
    NoFeerate,

    /// The claim transaction was rejected.
    #[error("Claim transaction was rejected: {0}")]
    ClaimRejected(String),

    /// A claim recorded for the output could not be looked up.
    #[error(transparent)]
    Operation(#[from] OperationLookupError),

    /// The reservation of the address the output paid could not be updated.
    #[error(transparent)]
    Database(#[from] DatabaseError),
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
