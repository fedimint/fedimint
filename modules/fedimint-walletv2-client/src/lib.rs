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
mod migrations;
mod receive_sm;
mod send_sm;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use api::WalletFederationApi;
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, ScriptBuf};
use db::{
    NextOutputIndexKey, ValidAddressIndexAccountPrefix, ValidAddressIndexKey,
    ValidAddressIndexPrefix,
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
use fedimint_client_module::secret::DeriveableSecretClientExt;
use fedimint_client_module::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client_module::sm_enum_variant_translation;
use fedimint_core::core::{Account, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{
    Database, DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped,
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

#[derive(Debug, Clone)]
pub struct WalletClientModule {
    /// Every account's derivation root, derived once so the address grind
    /// pays a single child derivation per index.
    account_secrets: [DerivableSecret; Account::ALL.len()],
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

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientModuleMigrationFn> {
        let mut migrations: BTreeMap<DatabaseVersion, ClientModuleMigrationFn> = BTreeMap::new();

        migrations.insert(DatabaseVersion(0), |dbtx, active, inactive| {
            Box::pin(migrations::migrate_to_accounts_v1(dbtx, active, inactive))
        });

        migrations
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        let module = WalletClientModule {
            account_secrets: Account::ALL
                .map(|account| args.module_root_secret().derive_account_secret(account)),
            cfg: args.cfg().clone(),
            notifier: args.notifier().clone(),
            client_ctx: args.context(),
            db: args.db().clone(),
            module_api: args.module_api().clone(),
        };

        module.spawn_output_scanner(args.task_group(), args.client_span());

        Ok(module)
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
    pub async fn send_fee_quote(
        &self,
        account: Account,
        amount: bitcoin::Amount,
    ) -> anyhow::Result<FeeQuote> {
        let amount = Amount::from_sats(amount.to_sat());
        self.client_ctx
            .fee_quote(
                OperationId::new_random(),
                FeeQuoteRequest {
                    input_amount: Amounts::ZERO,
                    output_amount: Amounts::new_bitcoin(amount),
                    input_fee: Amounts::ZERO,
                    output_fee: Amounts::new_bitcoin(self.cfg.fee_consensus.fee(amount)),
                    account,
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
        account: Account,
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
            |funded: Amount| {
                self.send_fee_quote(account, bitcoin::Amount::from_sat(funded.msats / 1000))
            },
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
        account: Account,
        address: Address<NetworkUnchecked>,
        value: bitcoin::Amount,
        fee: Option<bitcoin::Amount>,
        custom_meta: serde_json::Value,
    ) -> Result<OperationId, SendError> {
        if !self
            .client_ctx
            .supports_account(AmountUnit::BITCOIN, account)
        {
            return Err(SendError::AccountNotSupported);
        }

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
                TransactionBuilder::new(account).with_outputs(client_output_bundle),
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
                    account,
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

    /// Returns the highest valid receive address index that the background
    /// scanner has derived so far, or `None` if it has not derived one yet.
    /// All accounts share one table, so this reads the tail of the account's
    /// own key prefix rather than the table's.
    async fn valid_index(&self, account: Account) -> Option<u64> {
        self.db
            .begin_transaction_nc()
            .await
            .find_by_prefix_sorted_descending(&ValidAddressIndexAccountPrefix(account))
            .await
            .next()
            .await
            .map(|entry| entry.0.1)
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
    ///
    /// Refuses an account the primary module cannot hold a balance for before
    /// handing out an address, since a deposit to it could never be claimed.
    pub async fn receive(&self, account: Account) -> Result<Address, ReceiveError> {
        if !self
            .client_ctx
            .supports_account(AmountUnit::BITCOIN, account)
        {
            return Err(ReceiveError::AccountNotSupported);
        }

        loop {
            if let Some(index) = self.valid_index(account).await {
                return Ok(self.derive_address(account, index));
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

    fn derive_address(&self, account: Account, index: u64) -> Address {
        descriptor(
            &self.cfg.bitcoin_pks,
            &self
                .derive_tweak(account, index)
                .public_key()
                .consensus_hash(),
        )
        .address(self.cfg.network)
    }

    fn derive_tweak(&self, account: Account, index: u64) -> Keypair {
        self.account_secrets[usize::from(account.index())]
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
    async fn next_valid_index(
        &self,
        account: Account,
        start_index: u64,
        handle: &TaskHandle,
    ) -> Option<u64> {
        /// Indices to scan per batch before yielding to the executor.
        const SCAN_BATCH: u64 = 256;

        let pks_hash = self.cfg.bitcoin_pks.consensus_hash();

        let mut index = start_index;

        while !handle.is_shutting_down() {
            for _ in 0..SCAN_BATCH {
                if is_potential_receive(
                    &self.derive_address(account, index).script_pubkey(),
                    &pks_hash,
                ) {
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
        account: Account,
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
                tweak: self.derive_tweak(account, address_index).public_key(),
            }),
            keys: vec![self.derive_tweak(account, address_index)],
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

        let address = self
            .derive_address(account, address_index)
            .as_unchecked()
            .clone();

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
                TransactionBuilder::new(account).with_inputs(client_input_bundle),
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
                    account,
                },
            )
            .await;

        dbtx.commit_tx().await;

        Some((operation_id, range.txid()))
    }

    fn spawn_output_scanner(&self, task_group: &TaskGroup, client_span: &tracing::Span) {
        let module = self.clone();
        let handle = task_group.make_handle();

        task_group.spawn_cancellable_with_span(client_span.clone(), "output-scanner", async move {
            let mut dbtx = module.db.begin_transaction().await;

            // Every account is seeded, not just the ones the user has opened:
            // a restored seed may have been paid into any of them, and an
            // account whose frontier was never derived would never be scanned
            // for. Not filtered by what the primary module supports: this runs
            // from `init`, before the client handle the query needs is set.
            for account in Account::ALL {
                if dbtx
                    .find_by_prefix(&ValidAddressIndexAccountPrefix(account))
                    .await
                    .next()
                    .await
                    .is_some()
                {
                    continue;
                }

                let Some(index) = module.next_valid_index(account, 0, &handle).await else {
                    return;
                };

                dbtx.insert_new_entry(&ValidAddressIndexKey(account, index), &())
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

    async fn check_outputs(&self, handle: &TaskHandle) -> anyhow::Result<bool> {
        let mut dbtx = self.db.begin_transaction_nc().await;

        let next_output_index = dbtx.get_value(&NextOutputIndexKey).await.unwrap_or(0);

        // Every account's indices come out of one prefix scan, already tagged
        // with the account they belong to.
        let valid_indices: Vec<(Account, u64)> = dbtx
            .find_by_prefix(&ValidAddressIndexPrefix)
            .await
            .map(|entry| (entry.0.0, entry.0.1))
            .collect()
            .await;

        let mut address_map: BTreeMap<ScriptBuf, (Account, u64)> = valid_indices
            .iter()
            .map(|&(account, i)| {
                (
                    self.derive_address(account, i).script_pubkey(),
                    (account, i),
                )
            })
            .collect();

        // Highest index reached per account, so a match on one account's
        // frontier extends that account rather than the whole table's.
        let mut frontier: BTreeMap<Account, u64> = BTreeMap::new();

        for &(account, i) in &valid_indices {
            frontier
                .entry(account)
                .and_modify(|highest| *highest = (*highest).max(i))
                .or_insert(i);
        }

        let outputs = self
            .module_api
            .output_info_slice(next_output_index, next_output_index + SLICE_SIZE)
            .await?;

        let returned_num = outputs.len();
        let mut matched_num: usize = 0;

        for output in &outputs {
            if let Some(&(account, address_index)) = address_map.get(&output.script) {
                matched_num += 1;

                // Claim before extending the valid index list: the index search
                // below is CPU-bound and can take longer than a short-lived
                // client process (e.g. a cli invocation) lives. The claim is
                // quick and the extension can be retried on the next scan.
                if !output.spent
                    && !self
                        .process_unspent_output(account, output, address_index)
                        .await?
                {
                    return Ok(false);
                }

                let next_address_index = *frontier
                    .get(&account)
                    .expect("every account in the map has a frontier");

                // If we used this account's highest valid index, add its next
                if address_index == next_address_index {
                    let Some(index) = self
                        .next_valid_index(account, next_address_index + 1, handle)
                        .await
                    else {
                        return Ok(false);
                    };

                    let mut dbtx = self.db.begin_transaction().await;

                    dbtx.insert_entry(&ValidAddressIndexKey(account, index), &())
                        .await;

                    dbtx.commit_tx_result().await?;

                    frontier.insert(account, index);

                    address_map.insert(
                        self.derive_address(account, index).script_pubkey(),
                        (account, index),
                    );
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
        account: Account,
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
                account,
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
    #[error("The primary module only holds a balance for the primary account")]
    AccountNotSupported,
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
    #[error("The primary module only holds a balance for the primary account")]
    AccountNotSupported,
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
