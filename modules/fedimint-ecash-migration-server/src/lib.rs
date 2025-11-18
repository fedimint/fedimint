#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, ensure};
use async_trait::async_trait;
use bitcoin_hashes::{Hash as BitcoinHash, HashEngine, sha256};
use fedimint_core::config::{
    ConfigGenModuleParams, ServerModuleConfig, ServerModuleConsensusConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    Amounts, ApiEndpoint, ApiError, ApiVersion, CORE_CONSENSUS_VERSION, CoreConsensusVersion,
    InputMeta, ModuleConsensusVersion, ModuleInit, SupportedModuleApiVersions,
    TransactionItemAmounts, api_endpoint,
};
use fedimint_core::{
    Amount, InPoint, NumPeers, OutPoint, PeerId, apply, async_trait_maybe_send, push_db_pair_items,
};
use fedimint_ecash_migration_common::config::{
    EcashMigrationClientConfig, EcashMigrationConfig, EcashMigrationConfigConsensus,
    EcashMigrationConfigPrivate, EcashMigrationGenParams,
};
use fedimint_ecash_migration_common::{
    CreateTransferRequest, CreateTransferResponse, EcashMigrationCommonInit,
    EcashMigrationConsensusItem, EcashMigrationInput, EcashMigrationInputError,
    EcashMigrationModuleTypes, EcashMigrationOutput, EcashMigrationOutputError,
    EcashMigrationOutputOutcome, FinalizeUploadRequest, FinalizeUploadResponse,
    GetSpendBookHashRequest, GetSpendBookHashResponse, GetTransferStatusRequest,
    GetTransferStatusResponse, MODULE_CONSENSUS_VERSION, RequestActivationRequest, SpendBookHash,
    TransferId, TransferPhase, UploadSpendBookBatchRequest, UploadSpendBookBatchResponse,
};
use fedimint_mint_common::Nonce;
use fedimint_server_core::config::PeerHandleOps;
use fedimint_server_core::migration::ServerModuleDbMigrationFn;
use fedimint_server_core::{ServerModule, ServerModuleInit, ServerModuleInitArgs};
use futures::StreamExt;
use strum::IntoEnumIterator;
use tracing::{debug, info, trace};

use crate::db::{
    ActivationVote, ActivationVoteKey, ActivationVotePrefix, DbKeyPrefix, RedeemedNonceKey,
    RedeemedNoncePrefix, SpendBookEntryKey, SpendBookEntryPrefix, TransferMetadata,
    TransferMetadataKey, TransferMetadataKeyPrefix,
};

pub mod db;

/// Log target for the ecash migration module
const LOG_MODULE_ECASH_MIGRATION: &str = "fedimint_ecash_migration_server";

/// Generates the module
#[derive(Debug, Clone)]
pub struct EcashMigrationInit;

// TODO: Boilerplate-code
impl ModuleInit for EcashMigrationInit {
    type Common = EcashMigrationCommonInit;

    /// Dumps all database items for debugging
    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let mut items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        // TODO: Implement proper database dumping
        // For now, we skip detailed database dumping as it requires
        // iterating through complex prefix structures
        let _ = filtered_prefixes;

        Box::new(items.into_iter())
    }
}

/// Implementation of server module non-consensus functions
#[async_trait]
impl ServerModuleInit for EcashMigrationInit {
    type Module = EcashMigration;
    type Params = EcashMigrationGenParams;

    /// Returns the version of this module
    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[MODULE_CONSENSUS_VERSION]
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw(
            (CORE_CONSENSUS_VERSION.major, CORE_CONSENSUS_VERSION.minor),
            (
                MODULE_CONSENSUS_VERSION.major,
                MODULE_CONSENSUS_VERSION.minor,
            ),
            &[(0, 0)],
        )
    }

    /// Initialize the module
    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(EcashMigration::new(
            args.cfg().to_typed()?,
            args.num_peers(),
        ))
    }

    /// Generates configs for all peers in a trusted manner for testing
    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
        _disable_base_fees: bool,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let _params = self.parse_params(params).unwrap();
        // Generate a config for each peer
        peers
            .iter()
            .map(|&peer| {
                let config = EcashMigrationConfig {
                    private: EcashMigrationConfigPrivate,
                    consensus: EcashMigrationConfigConsensus,
                };
                (peer, config.to_erased())
            })
            .collect()
    }

    /// Generates configs for all peers in an untrusted manner
    async fn distributed_gen(
        &self,
        _peers: &(dyn PeerHandleOps + Send + Sync),
        params: &ConfigGenModuleParams,
        _disable_base_fees: bool,
    ) -> anyhow::Result<ServerModuleConfig> {
        let _params = self.parse_params(params).unwrap();

        Ok(EcashMigrationConfig {
            private: EcashMigrationConfigPrivate,
            consensus: EcashMigrationConfigConsensus,
        }
        .to_erased())
    }

    /// Converts the consensus config into the client config
    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<EcashMigrationClientConfig> {
        let _config = EcashMigrationConfigConsensus::from_erased(config)?;
        Ok(EcashMigrationClientConfig)
    }

    fn validate_config(
        &self,
        _identity: &PeerId,
        config: ServerModuleConfig,
    ) -> anyhow::Result<()> {
        config.to_typed::<EcashMigrationConfig>()?;
        Ok(())
    }

    /// DB migrations to move from old to newer versions
    fn get_database_migrations(
        &self,
    ) -> BTreeMap<DatabaseVersion, ServerModuleDbMigrationFn<EcashMigration>> {
        BTreeMap::new()
    }
}

/// Ecash Migration module
#[derive(Debug)]
pub struct EcashMigration {
    pub cfg: EcashMigrationConfig,
    pub num_peers: NumPeers,
}

/// Implementation of consensus for the server module
#[apply(async_trait_maybe_send!)]
impl ServerModule for EcashMigration {
    /// Define the consensus types
    type Common = EcashMigrationModuleTypes;
    type Init = EcashMigrationInit;

    async fn consensus_proposal(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<EcashMigrationConsensusItem> {
        let mut proposals = Vec::new();

        // Find all transfers in ReadyForActivation phase
        let transfers: Vec<(TransferId, TransferMetadata)> = dbtx
            .find_by_prefix(&TransferMetadataKeyPrefix)
            .await
            .map(|(TransferMetadataKey(id), metadata)| (id, metadata))
            .collect()
            .await;

        for (transfer_id, metadata) in transfers {
            if metadata.phase == TransferPhase::ReadyForActivation {
                if let (Some(spend_book_hash), total_amount) =
                    (metadata.spend_book_hash, metadata.total_liability)
                {
                    trace!(
                        target: LOG_MODULE_ECASH_MIGRATION,
                        transfer_id = %transfer_id,
                        spend_book_hash = %spend_book_hash,
                        total_amount = %total_amount,
                        "Proposing transfer activation"
                    );
                    proposals.push(EcashMigrationConsensusItem::ActivateTransfer {
                        transfer_id,
                        spend_book_hash,
                        total_amount,
                    });
                }
            }
        }

        proposals
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        consensus_item: EcashMigrationConsensusItem,
        peer_id: PeerId,
    ) -> anyhow::Result<()> {
        match consensus_item {
            EcashMigrationConsensusItem::ActivateTransfer {
                transfer_id,
                spend_book_hash,
                total_amount,
            } => {
                // Get transfer metadata
                let metadata = dbtx
                    .get_value(&TransferMetadataKey(transfer_id))
                    .await
                    .ok_or_else(|| anyhow!("Transfer {} does not exist", transfer_id))?;

                // If already active, this is a redundant proposal
                if metadata.phase == TransferPhase::Active {
                    bail!("Transfer {} is already active", transfer_id);
                }

                // Verify we're in ReadyForActivation phase
                ensure!(
                    metadata.phase == TransferPhase::ReadyForActivation,
                    "Transfer {} is not ready for activation (phase: {})",
                    transfer_id,
                    metadata.phase
                );

                // Compute local spend book hash and total
                let (local_hash, local_total) =
                    compute_spend_book_hash_and_total(dbtx, transfer_id).await?;

                // Verify hash matches
                ensure!(
                    local_hash == spend_book_hash,
                    "Spend book hash mismatch for transfer {}: local={}, proposed={}",
                    transfer_id,
                    local_hash,
                    spend_book_hash
                );

                // Verify amount matches
                ensure!(
                    local_total == total_amount,
                    "Total amount mismatch for transfer {}: local={}, proposed={}",
                    transfer_id,
                    local_total,
                    total_amount
                );

                // Record this peer's vote
                dbtx.insert_new_entry(
                    &ActivationVoteKey {
                        transfer_id,
                        peer_id,
                    },
                    &ActivationVote {
                        spend_book_hash,
                        total_amount,
                    },
                )
                .await;

                // Count votes for this transfer
                let votes: Vec<_> = dbtx
                    .find_by_prefix(&ActivationVotePrefix { transfer_id })
                    .await
                    .collect()
                    .await;

                // Simple majority threshold
                let threshold = self.num_peers.threshold();

                if votes.len() >= threshold {
                    info!(
                        target: LOG_MODULE_ECASH_MIGRATION,
                        transfer_id = %transfer_id,
                        votes = votes.len(),
                        threshold = threshold,
                        "Activating transfer"
                    );

                    // Activate the transfer
                    let mut activated_metadata = metadata;
                    activated_metadata.phase = TransferPhase::Active;
                    dbtx.insert_entry(&TransferMetadataKey(transfer_id), &activated_metadata)
                        .await;

                    // Clear activation votes
                    for (vote_key, _) in votes {
                        dbtx.remove_entry(&vote_key).await;
                    }
                }

                Ok(())
            }
            EcashMigrationConsensusItem::Default { variant, .. } => {
                bail!("Unknown consensus item variant: {}", variant)
            }
        }
    }

    fn verify_input(&self, input: &EcashMigrationInput) -> Result<(), EcashMigrationInputError> {
        match input {
            EcashMigrationInput::RedeemOriginEcash { amount, .. } => {
                // Basic validation: amount must be non-zero
                if *amount == Amount::ZERO {
                    return Err(EcashMigrationInputError::AmountMismatch {
                        expected: Amount::from_sats(1),
                        actual: *amount,
                    });
                }
                Ok(())
            }
            EcashMigrationInput::Default { variant, .. } => {
                Err(EcashMigrationInputError::UnknownInputVariant(*variant))
            }
        }
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b EcashMigrationInput,
        in_point: InPoint,
    ) -> Result<InputMeta, EcashMigrationInputError> {
        match input {
            EcashMigrationInput::RedeemOriginEcash {
                transfer_id,
                note,
                amount,
            } => {
                // Get transfer metadata
                let metadata = dbtx
                    .get_value(&TransferMetadataKey(*transfer_id))
                    .await
                    .ok_or_else(|| EcashMigrationInputError::InvalidTransfer(*transfer_id))?;

                // Check transfer is active
                if metadata.phase != TransferPhase::Active {
                    return Err(EcashMigrationInputError::TransferNotActive(
                        *transfer_id,
                        metadata.phase,
                    ));
                }

                // Check nonce exists in spend book
                let spend_book_amount = dbtx
                    .get_value(&SpendBookEntryKey {
                        transfer_id: *transfer_id,
                        nonce: note.nonce,
                    })
                    .await
                    .ok_or_else(|| EcashMigrationInputError::NotInSpendBook(note.nonce))?;

                // Verify amount matches
                if spend_book_amount != *amount {
                    return Err(EcashMigrationInputError::AmountMismatch {
                        expected: spend_book_amount,
                        actual: *amount,
                    });
                }

                // Check not already redeemed
                if dbtx
                    .get_value(&RedeemedNonceKey {
                        transfer_id: *transfer_id,
                        nonce: note.nonce,
                    })
                    .await
                    .is_some()
                {
                    return Err(EcashMigrationInputError::AlreadyRedeemed(note.nonce));
                }

                // NOTE: We don't verify the note signature here because:
                // 1. The spend book is provided by a trusted party
                // 2. The spend book only contains valid nonces from the origin federation
                // 3. We trust the origin federation's validation
                // The signature is primarily for the user to prove ownership when creating the
                // transaction, but the destination federation doesn't need to verify it since
                // we're relying on the trusted party's spend book

                // Mark nonce as redeemed
                dbtx.insert_new_entry(
                    &RedeemedNonceKey {
                        transfer_id: *transfer_id,
                        nonce: note.nonce,
                    },
                    &in_point,
                )
                .await;

                debug!(
                    target: LOG_MODULE_ECASH_MIGRATION,
                    transfer_id = %transfer_id,
                    nonce = %note.nonce,
                    amount = %amount,
                    "Redeemed origin federation ecash"
                );

                Ok(InputMeta {
                    amount: TransactionItemAmounts {
                        amounts: Amounts::new_bitcoin(*amount),
                        fees: Amounts::new_bitcoin(Amount::ZERO),
                    },
                    pub_key: note.nonce.0,
                })
            }
            EcashMigrationInput::Default { variant, .. } => {
                Err(EcashMigrationInputError::UnknownInputVariant(*variant))
            }
        }
    }

    async fn process_output<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _output: &'a EcashMigrationOutput,
        _out_point: OutPoint,
    ) -> Result<TransactionItemAmounts, EcashMigrationOutputError> {
        // This module does not produce outputs
        Err(EcashMigrationOutputError::NotSupported)
    }

    #[allow(deprecated)]
    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<EcashMigrationOutputOutcome> {
        None
    }

    async fn audit(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        _audit: &mut Audit,
        _module_instance_id: ModuleInstanceId,
    ) {
        // The ecash migration module doesn't hold any assets
        // Liabilities are tracked by the spend book, but they are external
        // to the destination federation (origin federation's responsibility)
        // Once redeemed, the destination mint module holds the liabilities
        trace!(
            target: LOG_MODULE_ECASH_MIGRATION,
            "Audit: ecash migration module holds no assets or liabilities"
        );
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            api_endpoint! {
                CREATE_TRANSFER_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &EcashMigration, context, request: CreateTransferRequest| -> CreateTransferResponse {
                    module.create_transfer(&mut context.dbtx().into_nc(), request).await
                }
            },
            api_endpoint! {
                UPLOAD_SPEND_BOOK_BATCH_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &EcashMigration, context, request: UploadSpendBookBatchRequest| -> UploadSpendBookBatchResponse {
                    module.upload_spend_book_batch(&mut context.dbtx().into_nc(), request).await
                }
            },
            api_endpoint! {
                FINALIZE_UPLOAD_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &EcashMigration, context, request: FinalizeUploadRequest| -> FinalizeUploadResponse {
                    module.finalize_upload(&mut context.dbtx().into_nc(), request).await
                }
            },
            api_endpoint! {
                REQUEST_ACTIVATION_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &EcashMigration, context, request: RequestActivationRequest| -> () {
                    module.request_activation(&mut context.dbtx().into_nc(), request).await
                }
            },
            api_endpoint! {
                GET_TRANSFER_STATUS_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &EcashMigration, context, request: GetTransferStatusRequest| -> GetTransferStatusResponse {
                    module.get_transfer_status(&mut context.dbtx().into_nc(), request).await
                }
            },
            api_endpoint! {
                GET_SPEND_BOOK_HASH_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &EcashMigration, context, request: GetSpendBookHashRequest| -> GetSpendBookHashResponse {
                    module.get_spend_book_hash(&mut context.dbtx().into_nc(), request).await
                }
            },
        ]
    }
}

impl EcashMigration {
    /// Create new module instance
    pub fn new(cfg: EcashMigrationConfig, num_peers: NumPeers) -> EcashMigration {
        EcashMigration { cfg, num_peers }
    }

    /// Create a new transfer
    async fn create_transfer(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        request: CreateTransferRequest,
    ) -> Result<CreateTransferResponse, ApiError> {
        // Find the highest existing transfer ID using reverse iteration
        let next_id = dbtx
            .find_by_prefix_sorted_descending(&TransferMetadataKeyPrefix)
            .await
            .next()
            .await
            .map(|(TransferMetadataKey(id), _): (TransferMetadataKey, TransferMetadata)| id.0 + 1)
            .unwrap_or(0);

        let transfer_id = TransferId(next_id);

        // Compute HMAC of secret for authentication
        let secret_hash = sha256::Hash::hash(request.secret.as_bytes());

        let metadata = TransferMetadata {
            secret_hash,
            phase: TransferPhase::Initializing,
            origin_keys: request.origin_keys,
            spend_book_hash: None,
            total_liability: Amount::ZERO,
        };

        dbtx.insert_new_entry(&TransferMetadataKey(transfer_id), &metadata)
            .await;

        info!(
            target: LOG_MODULE_ECASH_MIGRATION,
            transfer_id = %transfer_id,
            "Created new transfer"
        );

        Ok(CreateTransferResponse { transfer_id })
    }

    /// Upload a batch of spend book entries
    async fn upload_spend_book_batch(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        request: UploadSpendBookBatchRequest,
    ) -> Result<UploadSpendBookBatchResponse, ApiError> {
        // Get transfer metadata
        let mut metadata = dbtx
            .get_value(&TransferMetadataKey(request.transfer_id))
            .await
            .ok_or_else(|| ApiError::not_found("Transfer not found".to_string()))?;

        // Verify HMAC
        let provided_hash = sha256::Hash::hash(request.auth_hmac.as_bytes());
        if provided_hash != metadata.secret_hash {
            return Err(ApiError::unauthorized());
        }

        // Transition to Uploading phase if in Initializing
        if metadata.phase == TransferPhase::Initializing {
            metadata.phase = TransferPhase::Uploading;
        }

        // Verify we're in correct phase
        if metadata.phase != TransferPhase::Uploading {
            return Err(ApiError::bad_request(format!(
                "Transfer is in {:?} phase, cannot upload",
                metadata.phase
            )));
        }

        // Insert spend book entries (idempotent)
        for (nonce, amount) in &request.entries {
            let key = SpendBookEntryKey {
                transfer_id: request.transfer_id,
                nonce: *nonce,
            };
            dbtx.insert_entry(&key, amount).await;
        }

        // Update metadata
        dbtx.insert_entry(&TransferMetadataKey(request.transfer_id), &metadata)
            .await;

        // Count total entries and amount
        let mut total_entries = 0u64;
        let mut total_amount = Amount::ZERO;
        let entries: Vec<(SpendBookEntryKey, Amount)> = dbtx
            .find_by_prefix(&SpendBookEntryPrefix {
                transfer_id: request.transfer_id,
            })
            .await
            .collect()
            .await;

        for (_, amount) in entries {
            total_entries += 1;
            total_amount += amount;
        }

        debug!(
            target: LOG_MODULE_ECASH_MIGRATION,
            transfer_id = %request.transfer_id,
            batch_size = request.entries.len(),
            total_entries = total_entries,
            total_amount = %total_amount,
            "Uploaded spend book batch"
        );

        Ok(UploadSpendBookBatchResponse {
            total_entries,
            total_amount,
        })
    }

    /// Finalize spend book upload
    async fn finalize_upload(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        request: FinalizeUploadRequest,
    ) -> Result<FinalizeUploadResponse, ApiError> {
        // Get transfer metadata
        let mut metadata = dbtx
            .get_value(&TransferMetadataKey(request.transfer_id))
            .await
            .ok_or_else(|| ApiError::not_found("Transfer not found".to_string()))?;

        // Verify HMAC
        let provided_hash = sha256::Hash::hash(request.auth_hmac.as_bytes());
        if provided_hash != metadata.secret_hash {
            return Err(ApiError::unauthorized());
        }

        // Verify phase
        if metadata.phase != TransferPhase::Uploading {
            return Err(ApiError::bad_request(format!(
                "Transfer is in {:?} phase, cannot finalize",
                metadata.phase
            )));
        }

        // Compute spend book hash and total
        let (spend_book_hash, total_amount) =
            compute_spend_book_hash_and_total(dbtx, request.transfer_id)
                .await
                .map_err(|e| ApiError::server_error(e.to_string()))?;

        // Update metadata
        metadata.phase = TransferPhase::ReadyForActivation;
        metadata.spend_book_hash = Some(spend_book_hash);
        metadata.total_liability = total_amount;
        dbtx.insert_entry(&TransferMetadataKey(request.transfer_id), &metadata)
            .await;

        info!(
            target: LOG_MODULE_ECASH_MIGRATION,
            transfer_id = %request.transfer_id,
            spend_book_hash = %spend_book_hash,
            total_amount = %total_amount,
            "Finalized spend book upload"
        );

        Ok(FinalizeUploadResponse {
            spend_book_hash,
            total_amount,
        })
    }

    /// Request activation of a transfer
    async fn request_activation(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        request: RequestActivationRequest,
    ) -> Result<(), ApiError> {
        // Get transfer metadata
        let metadata = dbtx
            .get_value(&TransferMetadataKey(request.transfer_id))
            .await
            .ok_or_else(|| ApiError::not_found("Transfer not found".to_string()))?;

        // Verify HMAC
        let provided_hash = sha256::Hash::hash(request.auth_hmac.as_bytes());
        if provided_hash != metadata.secret_hash {
            return Err(ApiError::unauthorized());
        }

        // Verify phase
        if metadata.phase != TransferPhase::ReadyForActivation {
            return Err(ApiError::bad_request(format!(
                "Transfer is in {:?} phase, must be ReadyForActivation",
                metadata.phase
            )));
        }

        info!(
            target: LOG_MODULE_ECASH_MIGRATION,
            transfer_id = %request.transfer_id,
            "Activation requested, will be proposed in next consensus round"
        );

        Ok(())
    }

    /// Get transfer status
    async fn get_transfer_status(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        request: GetTransferStatusRequest,
    ) -> Result<GetTransferStatusResponse, ApiError> {
        // Get transfer metadata
        let metadata = dbtx
            .get_value(&TransferMetadataKey(request.transfer_id))
            .await
            .ok_or_else(|| ApiError::not_found("Transfer not found".to_string()))?;

        // Count entries
        let mut total_entries = 0u64;
        let mut total_amount = Amount::ZERO;
        let entries: Vec<(SpendBookEntryKey, Amount)> = dbtx
            .find_by_prefix(&SpendBookEntryPrefix {
                transfer_id: request.transfer_id,
            })
            .await
            .collect()
            .await;

        for (_, amount) in entries {
            total_entries += 1;
            total_amount += amount;
        }

        // Count redeemed
        let mut redeemed_count = 0u64;
        let mut redeemed_amount = Amount::ZERO;
        let redeemed: Vec<(RedeemedNonceKey, InPoint)> = dbtx
            .find_by_prefix(&RedeemedNoncePrefix {
                transfer_id: request.transfer_id,
            })
            .await
            .collect()
            .await;

        for (redeemed_key, _) in redeemed {
            redeemed_count += 1;
            if let Some(amount) = dbtx
                .get_value(&SpendBookEntryKey {
                    transfer_id: request.transfer_id,
                    nonce: redeemed_key.nonce,
                })
                .await
            {
                redeemed_amount += amount;
            }
        }

        Ok(GetTransferStatusResponse {
            phase: metadata.phase,
            total_entries,
            total_amount,
            spend_book_hash: metadata.spend_book_hash,
            redeemed_count,
            redeemed_amount,
        })
    }

    /// Get spend book hash
    async fn get_spend_book_hash(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        request: GetSpendBookHashRequest,
    ) -> Result<GetSpendBookHashResponse, ApiError> {
        // Get transfer metadata
        let metadata = dbtx
            .get_value(&TransferMetadataKey(request.transfer_id))
            .await
            .ok_or_else(|| ApiError::not_found("Transfer not found".to_string()))?;

        let spend_book_hash = metadata
            .spend_book_hash
            .ok_or_else(|| ApiError::bad_request("Spend book not finalized".to_string()))?;

        Ok(GetSpendBookHashResponse {
            spend_book_hash,
            total_amount: metadata.total_liability,
        })
    }
}

/// Compute spend book hash and total amount for a transfer
async fn compute_spend_book_hash_and_total(
    dbtx: &mut DatabaseTransaction<'_>,
    transfer_id: TransferId,
) -> anyhow::Result<(SpendBookHash, Amount)> {
    // Collect all spend book entries in sorted order (deterministic)
    let mut entries: Vec<(Nonce, Amount)> = dbtx
        .find_by_prefix(&SpendBookEntryPrefix { transfer_id })
        .await
        .map(|(key, amount): (SpendBookEntryKey, Amount)| (key.nonce, amount))
        .collect()
        .await;

    entries.sort_by_key(|(nonce, _)| *nonce);

    // Compute hash
    let mut engine = sha256::Hash::engine();
    let mut total = Amount::ZERO;

    for (nonce, amount) in &entries {
        // Hash nonce
        engine.input(&nonce.0.serialize());
        // Hash amount
        engine.input(&amount.msats.to_le_bytes());
        total += *amount;
    }

    let hash = SpendBookHash(sha256::Hash::from_engine(engine));

    Ok((hash, total))
}

// API endpoint paths
const CREATE_TRANSFER_ENDPOINT: &str = "create_transfer";
const UPLOAD_SPEND_BOOK_BATCH_ENDPOINT: &str = "upload_spend_book_batch";
const FINALIZE_UPLOAD_ENDPOINT: &str = "finalize_upload";
const REQUEST_ACTIVATION_ENDPOINT: &str = "request_activation";
const GET_TRANSFER_STATUS_ENDPOINT: &str = "get_transfer_status";
const GET_SPEND_BOOK_HASH_ENDPOINT: &str = "get_spend_book_hash";
