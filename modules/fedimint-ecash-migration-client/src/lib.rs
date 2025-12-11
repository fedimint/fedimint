#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

use std::collections::BTreeMap;
use std::path::Path;
use std::pin::Pin;
use std::time::Duration;

use anyhow::Context as _;
use async_stream::stream;
use db::DbKeyPrefix;
use fedimint_api_client::api::DynModuleApi;
use fedimint_client_module::db::ClientModuleMigrationFn;
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{ClientContext, ClientModule, IClientModule, OutPointRange};
use fedimint_client_module::oplog::UpdateStreamOrOutcome;
use fedimint_client_module::sm::{Context, ModuleNotifier};
use fedimint_client_module::transaction::{
    ClientInput, ClientInputBundle, ClientOutput, ClientOutputBundle, TransactionBuilder,
};
use fedimint_core::config::{JsonClientConfig, JsonWithKind};
use fedimint_core::core::{Decoder, ModuleKind, OperationId};
use fedimint_core::db::{Database, DatabaseTransaction, DatabaseVersion};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::module::{
    AmountUnit, Amounts, ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::secp256k1::{All, Secp256k1};
use fedimint_core::util::backoff_util::custom_backoff;
use fedimint_core::util::retry;
use fedimint_core::{Amount, OutPoint, Tiered, TieredMulti, apply, async_trait_maybe_send};
use fedimint_derive_secret::{ChildId, DerivableSecret};
pub use fedimint_ecash_migration_common as common;
use fedimint_ecash_migration_common::api::{
    REQUEST_ACTIVATION_ENDPOINT, RequestActivationRequest, UPLOAD_KEY_SET_ENDPOINT,
    UPLOAD_SPEND_BOOK_BATCH_ENDPOINT, UploadKeySetRequest, UploadSpendBookBatchRequest,
    UploadSpendBookBatchResponse,
};
use fedimint_ecash_migration_common::config::EcashMigrationClientConfig;
use fedimint_ecash_migration_common::naive_threshold::NaiveThresholdKey;
use fedimint_ecash_migration_common::{
    EcashMigrationCommonInit, EcashMigrationCreateTransferOutput, EcashMigrationFundTransferOutput,
    EcashMigrationInput, EcashMigrationModuleTypes, EcashMigrationOutput, KeySetHash,
    SpendBookHash, TransferId, hash_and_count_spend_book,
};
use fedimint_mint_client::SpendableNote;
use fedimint_mint_common::config::MintClientConfig;
use fedimint_mint_common::{MintCommonInit, Nonce, Note};
use futures::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use states::{
    EcashMigrationStateMachine, FundTransferCommon, FundTransferState, FundTransferStateMachine,
    FundTransferStates, RedeemOriginEcashCommon, RedeemOriginEcashState,
    RedeemOriginEcashStateMachine, RedeemOriginEcashStates, RegisterTransferCommon,
    RegisterTransferState, RegisterTransferStateMachine, RegisterTransferStates,
};
use strum::IntoEnumIterator;
use tbs::AggregatePublicKey;
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{info, warn};

pub mod api;
#[cfg(feature = "cli")]
mod cli;
pub mod db;
pub mod states;

/// Child ID for deriving the controller key from the module secret
const CONTROLLER_KEY_CHILD_ID: ChildId = ChildId(0);

#[derive(Debug)]
pub struct EcashMigrationClientModule {
    #[allow(dead_code)]
    cfg: EcashMigrationClientConfig,
    client_ctx: ClientContext<Self>,
    #[allow(dead_code)]
    db: Database,
    /// Module root secret for deriving keys
    module_secret: DerivableSecret,
    /// Module API client
    module_api: DynModuleApi,
    /// Allows the module to subscribe to its own state machine changes
    notifier: ModuleNotifier<EcashMigrationStateMachine>,
}

/// Data needed by the state machine
#[derive(Debug, Clone)]
pub struct EcashMigrationClientContext {
    pub ecash_migration_decoder: Decoder,
    pub module_api: DynModuleApi,
}

// TODO: Boiler-plate
impl Context for EcashMigrationClientContext {
    const KIND: Option<ModuleKind> = None;
}

#[apply(async_trait_maybe_send!)]
impl ClientModule for EcashMigrationClientModule {
    type Init = EcashMigrationClientInit;
    type Common = EcashMigrationModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = EcashMigrationClientContext;
    type States = EcashMigrationStateMachine;

    fn context(&self) -> Self::ModuleStateMachineContext {
        EcashMigrationClientContext {
            ecash_migration_decoder: self.decoder(),
            module_api: self.module_api.clone(),
        }
    }

    fn input_fee(
        &self,
        _amount: &Amounts,
        input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amounts> {
        let fee_btc = match input {
            fedimint_ecash_migration_common::EcashMigrationInput::RedeemOriginEcash { .. } => {
                self.cfg.fee_config.transfer_redeem_fee
            }
            fedimint_ecash_migration_common::EcashMigrationInput::Default { .. } => {
                unreachable!("We never produce default inputs")
            }
        };

        Some(Amounts::new_bitcoin(fee_btc))
    }

    fn output_fee(
        &self,
        _amount: &Amounts,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts> {
        let fee_btc = match output {
            EcashMigrationOutput::CreateTransfer(ecash_migration_create_transfer_output) => self
                .cfg
                .fee_config
                .creation_fee(ecash_migration_create_transfer_output.spend_book_entries)
                .expect("Can't overflow unless fee is unreasonable or spend book is ginormous"),
            EcashMigrationOutput::FundTransfer(_) => self.cfg.fee_config.transfer_funding_fee,
            EcashMigrationOutput::Default { .. } => {
                unreachable!("We never produce default outputs")
            }
        };

        Some(Amounts::new_bitcoin(fee_btc))
    }

    async fn get_balance(&self, _dbtx: &mut DatabaseTransaction<'_>, _unit: AmountUnit) -> Amount {
        Amount::ZERO
    }

    #[cfg(feature = "cli")]
    async fn handle_cli_command(
        &self,
        args: &[std::ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        cli::handle_cli_command(self, args).await
    }
}

/// Metadata stored with the register transfer operation
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct RegisterTransferOperationMeta {
    pub spend_book_hash: SpendBookHash,
    pub spend_book_entries: u64,
    pub key_set_hash: KeySetHash,
    pub out_point: OutPoint,
}

/// Metadata stored with the fund transfer operation
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct FundTransferOperationMeta {
    pub transfer_id: TransferId,
    pub amount: Amount,
    pub change: OutPointRange,
}

/// Metadata stored with the redeem origin ecash operation
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct RedeemOriginEcashOperationMeta {
    pub transfer_id: TransferId,
    pub amount: Amount,
    pub change: OutPointRange,
}

/// Read the origin federation's mint keyset from a config file.
///
/// The config file should be in JSON format as produced by
/// `fedimint-cli --data-dir <data-dir> config` on the origin federation.
///
/// # Errors
/// - If the origin config file cannot be read or parsed.
pub async fn read_origin_keyset(
    origin_config_path: impl AsRef<Path>,
) -> anyhow::Result<Tiered<AggregatePublicKey>> {
    let origin_config_path = origin_config_path.as_ref();

    let origin_config_json = tokio::fs::read_to_string(origin_config_path)
        .await
        .with_context(|| {
            format!(
                "Failed to read origin config file: {}",
                origin_config_path.display()
            )
        })?;

    let origin_client_config: JsonClientConfig = serde_json::from_str(&origin_config_json)
        .with_context(|| {
            format!(
                "Failed to parse origin config as ClientConfig: {}",
                origin_config_path.display()
            )
        })?;

    let origin_mint_config_json: JsonWithKind = origin_client_config
        .modules
        .values()
        .find(|module_config| module_config.kind() == &MintCommonInit::KIND)
        .context("Mint module not found in origin config")?
        .clone();

    let origin_mint_config: MintClientConfig =
        serde_json::from_value(origin_mint_config_json.value().clone()).with_context(|| {
            format!(
                "Failed to parse origin config as MintClientConfig: {}",
                origin_config_path.display()
            )
        })?;

    Ok(origin_mint_config.tbs_pks)
}

/// Compute the hash of a tiered keyset.
pub fn hash_keyset(keyset: &Tiered<AggregatePublicKey>) -> KeySetHash {
    KeySetHash(keyset.consensus_hash_sha256())
}

/// Open a spend book file and return a stream of nonces.
///
/// The file should contain hex-encoded nonces, one per line, in sorted order.
/// Empty lines are skipped. The stream yields `Nonce`s.
///
/// # Errors
/// - If opening the spend book file fails.
///
/// # Panics
/// - If an error occurs while reading the spend book file.
pub async fn stream_nonces_from_file(
    spend_book_path: impl AsRef<Path>,
) -> anyhow::Result<Pin<Box<dyn Stream<Item = Nonce> + Send>>> {
    let path = spend_book_path.as_ref().to_path_buf();
    let file = tokio::fs::File::open(&path)
        .await
        .with_context(|| format!("Failed to open spend book file: {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    let mut line_num = 0u64;

    Ok(Box::pin(stream! {
        while let Some(line) = lines.next_line().await.with_context(|| {
            format!("Failed to read line {} of spend book file", line_num + 1)
        }).expect("Failed to read line of spend book file") {
            line_num += 1;
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }

            let nonce = Nonce::consensus_decode_hex(&line, &ModuleRegistry::default())
                .with_context(|| {
                    format!("Failed to decode nonce on line {line_num} of spend book file")
                })
                .expect("Failed to decode spend book file");

            yield nonce;
        }
    }))
}

impl EcashMigrationClientModule {
    /// Create a `RegisterTransferInput` by reading and processing input files.
    ///
    /// This streams the spend book file to avoid loading it entirely into
    /// memory.
    #[allow(clippy::missing_errors_doc)]
    pub async fn create_transfer_output(
        origin_config_path: impl AsRef<Path>,
        spend_book_path: impl AsRef<Path>,
        creator_keys: NaiveThresholdKey,
    ) -> anyhow::Result<EcashMigrationCreateTransferOutput> {
        // Read and hash the keyset
        let origin_tbs_pks = read_origin_keyset(origin_config_path).await?;
        let key_set_hash = hash_keyset(&origin_tbs_pks);

        // Stream and hash the spend book
        let nonce_stream = stream_nonces_from_file(spend_book_path).await?;
        let (spend_book_hash, spend_book_entries) = hash_and_count_spend_book(nonce_stream).await?;

        Ok(EcashMigrationCreateTransferOutput {
            spend_book_hash,
            spend_book_entries,
            key_set_hash,
            creator_keys,
        })
    }

    /// Register a new liability transfer with the federation.
    ///
    /// This starts a client operation that creates a transfer request with the
    /// destinationfederationthat allows ecash from the origin federation to
    /// be redeemed after the transfer is funded and activated.
    ///
    /// Returns the operation ID and transfer ID.
    ///
    /// # Errors
    /// - If the origin config file or spend book file is invalid or cannot be
    ///   opened
    /// - If the spend book is not sorted in ascending order.
    ///
    /// # Panics
    /// - If the creation fee calculation overflows (shouldn't happen unless fee
    ///   is unreasonable or spend book is beyon what fits on a few harddrives)
    pub async fn register_transfer(
        &self,
        origin_config_path: impl AsRef<Path>,
        spend_book_path: impl AsRef<Path>,
    ) -> anyhow::Result<OperationId> {
        let creator_keys = {
            let controller_keypair = self.controller_keypair();
            NaiveThresholdKey::new_single(controller_keypair.public_key())
        };

        let create_transfer_output =
            Self::create_transfer_output(origin_config_path, spend_book_path, creator_keys).await?;
        let creation_fee = self
            .cfg
            .fee_config
            .creation_fee(create_transfer_output.spend_book_entries)
            .expect("Can't overflow unless fee is unreasonable or spend book is ginormous");

        // Create the output
        let output = ClientOutput {
            output: EcashMigrationOutput::CreateTransfer(create_transfer_output.clone()),
            amounts: Amounts::new_bitcoin(creation_fee),
        };

        // Create the state machine
        let operation_id = OperationId::new_random();

        let sm_gen = move |out_point_range: fedimint_client_module::module::OutPointRange| {
            let out_point = OutPoint {
                txid: out_point_range.txid(),
                out_idx: out_point_range.start_idx(),
            };
            vec![EcashMigrationStateMachine::RegisterTransfer(
                RegisterTransferStateMachine {
                    common: RegisterTransferCommon {
                        operation_id,
                        txid: out_point_range.txid(),
                        out_point,
                    },
                    state: RegisterTransferStates::Created,
                },
            )]
        };

        // Build the transaction with state machine
        let output_bundle = ClientOutputBundle::new(
            vec![output],
            vec![fedimint_client_module::transaction::ClientOutputSM {
                state_machines: std::sync::Arc::new(sm_gen),
            }],
        );

        let tx = TransactionBuilder::new()
            .with_outputs(self.client_ctx.make_client_outputs(output_bundle));

        // Compute out_point for metadata (will be determined after tx is created)
        let meta_gen =
            move |out_point_range: fedimint_client_module::module::OutPointRange| -> RegisterTransferOperationMeta {
                RegisterTransferOperationMeta {
                    spend_book_hash: create_transfer_output.spend_book_hash,
                    spend_book_entries: create_transfer_output.spend_book_entries,
                    key_set_hash: create_transfer_output.key_set_hash,
                    out_point: OutPoint {
                        txid: out_point_range.txid(),
                        out_idx: out_point_range.start_idx(),
                    },
                }
            };

        // Submit the transaction
        self.client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                fedimint_ecash_migration_common::KIND.as_str(),
                meta_gen,
                tx,
            )
            .await
            .context("Failed to submit transfer creation transaction")?;

        Ok(operation_id)
    }

    /// Subscribe to updates on the progress of a register transfer operation
    /// started with [`Self::register_transfer`].
    ///
    /// # Errors
    /// - If the operation does not exist.
    pub async fn subscribe_register_transfer(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<RegisterTransferState>> {
        let operation = self
            .client_ctx
            .get_operation(operation_id)
            .await
            .context("Operation not found")?;

        let meta = operation.meta::<RegisterTransferOperationMeta>();
        let out_point = meta.out_point;
        let client_ctx = self.client_ctx.clone();

        let mut sm_updates = client_ctx
            .self_ref()
            .notifier
            .subscribe(operation_id)
            .await
            .map(|state| match state {
                EcashMigrationStateMachine::RegisterTransfer(register_transfer_state_machine) => {
                    register_transfer_state_machine.state
                }
                EcashMigrationStateMachine::FundTransfer(_)
                | EcashMigrationStateMachine::RedeemOriginEcash(_) => {
                    // This shouldn't happen, but return Created as a no-op
                    RegisterTransferStates::Created
                }
            });

        Ok(self
            .client_ctx
            .outcome_or_updates(operation, operation_id, move || {
                stream! {
                    yield RegisterTransferState::Created;

                    // Wait for transaction to be accepted
                    match client_ctx
                        .transaction_updates(operation_id)
                        .await
                        .await_tx_accepted(out_point.txid)
                        .await
                    {
                        Ok(()) => {
                            yield RegisterTransferState::TxAccepted;
                        }
                        Err(e) => {
                            yield RegisterTransferState::Failed {
                                error: format!("Transaction not accepted: {e:?}"),
                            };
                            return;
                        }
                    }

                    // Await state machine to transition to success
                    while let Some(state) = sm_updates.next().await {
                        match state {
                            RegisterTransferStates::Created => {}
                            RegisterTransferStates::Aborted(register_transfer_aborted) => {
                                // Technically this should never happen since we check for transaction rejection first
                                yield RegisterTransferState::Failed { error: register_transfer_aborted.reason };
                                return;
                            }
                            RegisterTransferStates::Success(register_transfer_success) => {
                                yield RegisterTransferState::Success { transfer_id: register_transfer_success.transfer_id };
                                return;
                            }
                        }
                    }

                    unreachable!("State machine update stream ended unexpectedly");
                }
            }))
    }

    /// Get the controller keypair derived from the module secret.
    ///
    /// This keypair is used to authenticate requests to the federation
    /// for operations on transfers created by this client.
    pub fn controller_keypair(&self) -> fedimint_core::secp256k1::Keypair {
        let secp = Secp256k1::<All>::new();
        self.module_secret
            .child_key(CONTROLLER_KEY_CHILD_ID)
            .to_secp_key(&secp)
    }

    /// Fund an existing liability transfer with Bitcoin.
    ///
    /// This deposits the specified amount of Bitcoin into the transfer
    /// contract, making it available for redemption of origin federation
    /// ecash.
    ///
    /// Returns the operation ID that can be used to subscribe to updates.
    ///
    /// # Errors
    /// - If submitting the transaction fails.
    pub async fn fund_transfer(
        &self,
        transfer_id: TransferId,
        amount: Amount,
    ) -> anyhow::Result<OperationId> {
        // Create the output
        let output = ClientOutput {
            output: EcashMigrationOutput::FundTransfer(EcashMigrationFundTransferOutput {
                transfer_id,
                amount,
            }),
            amounts: Amounts::new_bitcoin(amount),
        };

        // Create the state machine
        let operation_id = OperationId::new_random();

        let sm_gen = move |out_point_range: fedimint_client_module::module::OutPointRange| {
            vec![EcashMigrationStateMachine::FundTransfer(
                FundTransferStateMachine {
                    common: FundTransferCommon {
                        operation_id,
                        txid: out_point_range.txid(),
                        transfer_id,
                        amount,
                    },
                    state: FundTransferStates::Created,
                },
            )]
        };

        // Build the transaction with state machine
        let output_bundle = ClientOutputBundle::new(
            vec![output],
            vec![fedimint_client_module::transaction::ClientOutputSM {
                state_machines: std::sync::Arc::new(sm_gen),
            }],
        );

        let tx = TransactionBuilder::new()
            .with_outputs(self.client_ctx.make_client_outputs(output_bundle));

        // Metadata for the operation log
        let meta_gen =
            move |out_point_range: fedimint_client_module::module::OutPointRange| -> FundTransferOperationMeta {
                FundTransferOperationMeta {
                    transfer_id,
                    amount,
                    change: out_point_range,
                }
            };

        // Submit the transaction
        self.client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                fedimint_ecash_migration_common::KIND.as_str(),
                meta_gen,
                tx,
            )
            .await
            .context("Failed to submit fund transfer transaction")?;

        Ok(operation_id)
    }

    /// Subscribe to updates on the progress of a fund transfer operation
    /// started with [`Self::fund_transfer`].
    ///
    /// # Errors
    /// - If the operation does not exist.
    pub async fn subscribe_fund_transfer(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<FundTransferState>> {
        let operation = self
            .client_ctx
            .get_operation(operation_id)
            .await
            .context("Operation not found")?;

        let meta = operation.meta::<FundTransferOperationMeta>();
        let change = meta.change;
        let client_ctx = self.client_ctx.clone();

        let mut sm_updates = client_ctx
            .self_ref()
            .notifier
            .subscribe(operation_id)
            .await
            .map(|state| match state {
                EcashMigrationStateMachine::FundTransfer(fund_transfer_state_machine) => {
                    fund_transfer_state_machine.state
                }
                EcashMigrationStateMachine::RegisterTransfer(_)
                | EcashMigrationStateMachine::RedeemOriginEcash(_) => {
                    // This shouldn't happen, but return Created as a no-op
                    FundTransferStates::Created
                }
            });

        Ok(self
            .client_ctx
            .outcome_or_updates(operation, operation_id, move || {
                stream! {
                    yield FundTransferState::Created;

                    // Wait for transaction to be accepted
                    match client_ctx
                        .transaction_updates(operation_id)
                        .await
                        .await_tx_accepted(change.txid)
                        .await
                    {
                        Ok(()) => {}
                        Err(e) => {
                            yield FundTransferState::Failed {
                                error: format!("Transaction not accepted: {e:?}"),
                            };
                            return;
                        }
                    }

                    // Await state machine to transition to success
                    while let Some(state) = sm_updates.next().await {
                        match state {
                            FundTransferStates::Created => {}
                            FundTransferStates::Aborted(fund_transfer_aborted) => {
                                yield FundTransferState::Failed { error: fund_transfer_aborted.reason };
                                return;
                            }
                            FundTransferStates::Success(fund_transfer_success) => {
                                match client_ctx.await_primary_module_outputs(operation_id, change.into_iter().collect::<Vec<_>>()).await {
                                    Ok(()) => {}
                                    Err(e) => {
                                        warn!(?operation_id, "Error occurred while waiting for ecash change: {e:?}");
                                    }
                                }
                                yield FundTransferState::Success {
                                    transfer_id: fund_transfer_success.transfer_id,
                                    amount: fund_transfer_success.amount,
                                };
                                return;
                            }
                        }
                    }

                    unreachable!("State machine update stream ended unexpectedly");
                }
            }))
    }

    /// Upload the origin federation's keyset to the destination federation.
    ///
    /// This reads the keyset from the origin config file and uploads it
    /// to associate with the given transfer. The keyset is uploaded to all
    /// federation peers.
    ///
    /// # Errors
    /// - If the origin config file cannot be read or parsed.
    /// - If uploading to any peer fails.
    pub async fn upload_keyset(
        &self,
        transfer_id: TransferId,
        origin_config_path: impl AsRef<Path>,
    ) -> anyhow::Result<()> {
        use fedimint_api_client::api::FederationApiExt as _;
        use fedimint_core::module::ApiRequestErased;

        let tier_keys = read_origin_keyset(origin_config_path).await?;

        let request = UploadKeySetRequest {
            transfer_id,
            tier_keys,
        };

        // Upload to all peers
        let params = ApiRequestErased::new(request);
        let results = futures::future::join_all(self.module_api.all_peers().iter().map(|&peer| {
            let params = params.clone();
            async move {
                (
                    peer,
                    self.module_api
                        .request_single_peer::<()>(
                            UPLOAD_KEY_SET_ENDPOINT.to_string(),
                            params,
                            peer,
                        )
                        .await,
                )
            }
        }))
        .await;

        // Check for errors
        let errors: Vec<_> = results
            .into_iter()
            .filter_map(|(peer, result)| result.err().map(|e| (peer, e)))
            .collect();

        if !errors.is_empty() {
            anyhow::bail!(
                "Failed to upload keyset to peers: {:?}",
                errors
                    .into_iter()
                    .map(|(p, e)| format!("{p}: {e}"))
                    .collect::<Vec<_>>()
            );
        }

        Ok(())
    }

    /// Upload the spend book entries in batches to the destination federation.
    ///
    /// This streams the spend book file and uploads entries in batches of
    /// `batch_size` to avoid memory issues with large spend books.
    /// Each batch is uploaded to all federation peers.
    ///
    /// Returns the total number of entries uploaded.
    ///
    /// # Errors
    /// - If opening the spend book file fails.
    /// - If uploading to any peer fails.
    ///
    /// # Panics
    /// - If an error occurs while reading the spend book file.
    pub async fn upload_spend_book(
        &self,
        transfer_id: TransferId,
        spend_book_path: impl AsRef<Path>,
        batch_size: usize,
    ) -> anyhow::Result<UploadSpendBookProgress> {
        use fedimint_api_client::api::FederationApiExt as _;
        use fedimint_core::module::ApiRequestErased;

        let mut nonce_stream = stream_nonces_from_file(spend_book_path).await?;

        let mut total_uploaded = 0u64;
        let mut batches_uploaded = 0u64;

        loop {
            let batch = nonce_stream
                .by_ref()
                .take(batch_size)
                .collect::<Vec<_>>()
                .await;
            let batch_len = batch.len() as u64;

            if batch.is_empty() {
                break;
            }

            info!("Uploading spend book batch {batches_uploaded} with {batch_len} entries");

            let request = UploadSpendBookBatchRequest {
                transfer_id,
                entries: batch,
            };

            // Upload batch to all peers
            let params = ApiRequestErased::new(request);
            let results =
                futures::future::join_all(self.module_api.all_peers().iter().map(|&peer| {
                    let params = params.clone();
                    async move {
                        let res = retry(
                            format!("Upload spend book batch {batches_uploaded} to peer {peer}"),
                            custom_backoff(
                                Duration::from_millis(50),
                                Duration::from_secs(10),
                                Some(10),
                            ),
                            || async {
                                self.module_api
                                    .request_single_peer::<UploadSpendBookBatchResponse>(
                                        UPLOAD_SPEND_BOOK_BATCH_ENDPOINT.to_string(),
                                        params.clone(),
                                        peer,
                                    )
                                    .await?;
                                Ok(())
                            },
                        )
                        .await;

                        (peer, res)
                    }
                }))
                .await;

            // Check for errors
            let errors: Vec<_> = results
                .iter()
                .filter_map(|(peer, result)| result.as_ref().err().map(|e| (*peer, e)))
                .collect();

            if !errors.is_empty() {
                anyhow::bail!(
                    "Failed to upload spend book batch to peers: {:?}",
                    errors
                        .into_iter()
                        .map(|(p, e)| format!("{p}: {e}"))
                        .collect::<Vec<_>>()
                );
            }

            total_uploaded += batch_len as u64;
            batches_uploaded += 1;
        }

        Ok(UploadSpendBookProgress {
            total_uploaded,
            batches_uploaded,
        })
    }

    /// Request activation of a transfer.
    ///
    /// This signals to all federation peers that the transfer is ready to be
    /// activated. Once all peers have voted, the transfer becomes active and
    /// origin ecash can be redeemed.
    ///
    /// Prerequisites:
    /// - The keyset must have been uploaded
    /// - The spend book must have been fully uploaded
    ///
    /// # Errors
    /// - If any prerequisite is not met
    /// - If the request fails on any peer
    pub async fn request_activation(&self, transfer_id: TransferId) -> anyhow::Result<()> {
        use fedimint_api_client::api::FederationApiExt as _;
        use fedimint_core::module::ApiRequestErased;

        let request = RequestActivationRequest { transfer_id };

        // Send activation request to all peers
        let params = ApiRequestErased::new(request);
        let results = futures::future::join_all(self.module_api.all_peers().iter().map(|&peer| {
            let params = params.clone();
            async move {
                (
                    peer,
                    self.module_api
                        .request_single_peer::<()>(
                            REQUEST_ACTIVATION_ENDPOINT.to_string(),
                            params,
                            peer,
                        )
                        .await,
                )
            }
        }))
        .await;

        // Check for errors
        let errors: Vec<_> = results
            .into_iter()
            .filter_map(|(peer, result)| result.err().map(|e| (peer, e)))
            .collect();

        if !errors.is_empty() {
            anyhow::bail!(
                "Failed to request activation from peers: {:?}",
                errors
                    .into_iter()
                    .map(|(p, e)| format!("{p}: {e}"))
                    .collect::<Vec<_>>()
            );
        }

        Ok(())
    }

    /// Redeem origin federation ecash notes for local federation ecash.
    ///
    /// Takes a set of spendable notes from the origin federation and submits
    /// them to the ecash migration module. The received amount (minus fees)
    /// is deposited as local ecash into the client's wallet.
    ///
    /// # Errors
    /// - If submitting the transaction fails.
    pub async fn redeem_origin_ecash(
        &self,
        transfer_id: TransferId,
        notes: TieredMulti<SpendableNote>,
    ) -> anyhow::Result<OperationId> {
        let total_amount = notes.total_amount();

        // Create inputs from the notes
        let inputs: Vec<_> = notes
            .into_iter_items()
            .map(|(amount, spendable_note)| ClientInput {
                input: EcashMigrationInput::RedeemOriginEcash {
                    transfer_id,
                    note: Note {
                        nonce: spendable_note.nonce(),
                        signature: spendable_note.signature,
                    },
                    amount,
                },
                amounts: Amounts::new_bitcoin(amount),
                keys: vec![spendable_note.spend_key],
            })
            .collect();

        let operation_id = OperationId::new_random();

        // Create the state machine
        let sm_gen = move |_out_point_range: OutPointRange| {
            vec![EcashMigrationStateMachine::RedeemOriginEcash(
                RedeemOriginEcashStateMachine {
                    common: RedeemOriginEcashCommon {
                        operation_id,
                        txid: _out_point_range.txid(),
                        transfer_id,
                        amount: total_amount,
                    },
                    state: RedeemOriginEcashStates::Created,
                },
            )]
        };

        // Build the transaction with inputs
        let input_bundle = ClientInputBundle::new(
            inputs,
            vec![fedimint_client_module::transaction::ClientInputSM {
                state_machines: std::sync::Arc::new(sm_gen),
            }],
        );

        let tx =
            TransactionBuilder::new().with_inputs(self.client_ctx.make_client_inputs(input_bundle));

        // Metadata for the operation log
        let meta_gen = move |change_range: OutPointRange| -> RedeemOriginEcashOperationMeta {
            RedeemOriginEcashOperationMeta {
                transfer_id,
                amount: total_amount,
                change: change_range,
            }
        };

        // Submit the transaction
        self.client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                fedimint_ecash_migration_common::KIND.as_str(),
                meta_gen,
                tx,
            )
            .await
            .context("Failed to submit redeem origin ecash transaction")?;

        Ok(operation_id)
    }

    /// Subscribe to updates on the progress of a redeem origin ecash operation
    /// started with [`Self::redeem_origin_ecash`].
    ///
    /// # Errors
    /// - If the operation does not exist.
    pub async fn subscribe_redeem_origin_ecash(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<RedeemOriginEcashState>> {
        let operation = self
            .client_ctx
            .get_operation(operation_id)
            .await
            .context("Operation not found")?;

        let meta = operation.meta::<RedeemOriginEcashOperationMeta>();
        let change = meta.change;
        let transfer_id = meta.transfer_id;
        let amount = meta.amount;
        let client_ctx = self.client_ctx.clone();

        let mut sm_updates = client_ctx
            .self_ref()
            .notifier
            .subscribe(operation_id)
            .await
            .map(|state| match state {
                EcashMigrationStateMachine::RedeemOriginEcash(redeem_state_machine) => {
                    redeem_state_machine.state
                }
                _ => RedeemOriginEcashStates::Created,
            });

        Ok(self
            .client_ctx
            .outcome_or_updates(operation, operation_id, move || {
                stream! {
                    yield RedeemOriginEcashState::Created;

                    // Wait for transaction to be accepted
                    match client_ctx
                        .transaction_updates(operation_id)
                        .await
                        .await_tx_accepted(change.txid())
                        .await
                    {
                        Ok(()) => {}
                        Err(e) => {
                            yield RedeemOriginEcashState::Failed {
                                error: format!("Transaction not accepted: {e:?}"),
                            };
                            return;
                        }
                    }

                    // Await state machine to transition to success and await change
                    while let Some(state) = sm_updates.next().await {
                        match state {
                            RedeemOriginEcashStates::Created => {}
                            RedeemOriginEcashStates::Aborted(error) => {
                                yield RedeemOriginEcashState::Failed { error };
                                return;
                            }
                            RedeemOriginEcashStates::Success => {
                                // Wait for the change (local ecash) to be received
                                match client_ctx.await_primary_module_outputs(operation_id, change.into_iter().collect::<Vec<_>>()).await {
                                    Ok(()) => {}
                                    Err(e) => {
                                        warn!(?operation_id, "Error occurred while waiting for ecash change: {e:?}");
                                    }
                                }
                                yield RedeemOriginEcashState::Success {
                                    transfer_id,
                                    amount,
                                };
                                return;
                            }
                        }
                    }

                    unreachable!("State machine update stream ended unexpectedly");
                }
            }))
    }
}

/// Progress information from uploading a spend book.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSpendBookProgress {
    /// Total number of entries uploaded to the server.
    pub total_uploaded: u64,
    /// Number of batches sent.
    pub batches_uploaded: u64,
}

#[derive(Debug, Clone)]
pub struct EcashMigrationClientInit;

// TODO: Boilerplate-code
impl ModuleInit for EcashMigrationClientInit {
    type Common = EcashMigrationCommonInit;

    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        #[allow(clippy::never_loop)]
        for table in filtered_prefixes {
            match table {}
        }

        Box::new(items.into_iter())
    }
}

/// Generates the client module
#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for EcashMigrationClientInit {
    type Module = EcashMigrationClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(EcashMigrationClientModule {
            cfg: args.cfg().clone(),
            client_ctx: args.context(),
            db: args.db().clone(),
            module_secret: args.module_root_secret().clone(),
            module_api: args.module_api().clone(),
            notifier: args.notifier().clone(),
        })
    }

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientModuleMigrationFn> {
        BTreeMap::new()
    }
}
