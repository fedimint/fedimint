#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

use std::collections::BTreeMap;
use std::path::Path;
use std::pin::Pin;

use anyhow::Context as _;
use async_stream::stream;
use db::DbKeyPrefix;
use fedimint_api_client::api::DynModuleApi;
use fedimint_client_module::db::ClientModuleMigrationFn;
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{ClientContext, ClientModule, IClientModule};
use fedimint_client_module::oplog::UpdateStreamOrOutcome;
use fedimint_client_module::sm::{Context, ModuleNotifier};
use fedimint_client_module::transaction::{ClientOutput, ClientOutputBundle, TransactionBuilder};
use fedimint_core::config::{JsonClientConfig, JsonWithKind};
use fedimint_core::core::{Decoder, ModuleKind, OperationId};
use fedimint_core::db::{Database, DatabaseTransaction, DatabaseVersion};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::module::{
    AmountUnit, Amounts, ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::secp256k1::{All, Secp256k1};
use fedimint_core::{Amount, OutPoint, Tiered, apply, async_trait_maybe_send};
use fedimint_derive_secret::{ChildId, DerivableSecret};
pub use fedimint_ecash_migration_common as common;
use fedimint_ecash_migration_common::config::EcashMigrationClientConfig;
use fedimint_ecash_migration_common::naive_threshold::NaiveThresholdKey;
use fedimint_ecash_migration_common::{
    EcashMigrationCommonInit, EcashMigrationCreateTransferOutput, EcashMigrationModuleTypes,
    EcashMigrationOutput, KeySetHash, SpendBookHash, hash_and_count_spend_book,
};
use fedimint_mint_common::config::MintClientConfig;
use fedimint_mint_common::{MintCommonInit, Nonce};
use futures::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use states::{
    EcashMigrationStateMachine, RegisterTransferCommon, RegisterTransferState,
    RegisterTransferStateMachine, RegisterTransferStates,
};
use strum::IntoEnumIterator;
use tbs::AggregatePublicKey;
use tokio::io::{AsyncBufReadExt, BufReader};

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
