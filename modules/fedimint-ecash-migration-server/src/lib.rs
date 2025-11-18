#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

use std::collections::BTreeMap;

use anyhow::{anyhow, bail};
use async_trait::async_trait;
use fedimint_core::config::{
    ConfigGenModuleParams, ServerModuleConfig, ServerModuleConsensusConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::Encodable;
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    Amounts, ApiEndpoint, ApiEndpointContext, ApiError, ApiVersion, CORE_CONSENSUS_VERSION,
    CoreConsensusVersion, InputMeta, ModuleConsensusVersion, ModuleInit,
    SupportedModuleApiVersions, TransactionItemAmounts, api_endpoint,
};
use fedimint_core::secp256k1::Message;
use fedimint_core::{
    Amount, InPoint, NumPeers, OutPoint, PeerId, Tiered, apply, async_trait_maybe_send,
};
use fedimint_ecash_migration_common::api::{
    CHECK_SPEND_BOOK_HASH_ENDPOINT, GET_TRANSFER_ID_ENDPOINT, GET_TRANSFER_STATUS_ENDPOINT,
    GET_UPLOADED_SPEND_BOOK_ENTRIES_ENDPOINT, GetTransferStatusRequest, GetTransferStatusResponse,
    UPLOAD_KEY_SET_ENDPOINT, UPLOAD_SPEND_BOOK_BATCH_ENDPOINT, UploadKeySetRequest,
    UploadSpendBookBatchRequest, UploadSpendBookBatchResponse,
};
use fedimint_ecash_migration_common::config::{
    EcashMigrationClientConfig, EcashMigrationConfig, EcashMigrationConfigConsensus,
    EcashMigrationConfigPrivate, EcashMigrationGenParams, FeeConfig,
};
use fedimint_ecash_migration_common::naive_threshold::NaiveThresholdSignature;
use fedimint_ecash_migration_common::{
    EcashMigrationCommonInit, EcashMigrationConsensusItem, EcashMigrationInput,
    EcashMigrationInputError, EcashMigrationModuleTypes, EcashMigrationOutput,
    EcashMigrationOutputError, EcashMigrationOutputOutcome, MODULE_CONSENSUS_VERSION,
    SpendBookHash, TransferId, hash_spend_book,
};
use fedimint_mint_common::Nonce;
use fedimint_server_core::config::PeerHandleOps;
use fedimint_server_core::migration::ServerModuleDbMigrationFn;
use fedimint_server_core::{ServerModule, ServerModuleInit, ServerModuleInitArgs};
use futures::StreamExt;
use tbs::AggregatePublicKey;
use tracing::warn;

use crate::db::{
    ActivationRequestKey, ActivationRequestPrefix, ActivationVote, ActivationVoteKey,
    ActivationVoteTransferPrefix, DenominationKeyKey, DepositedAmountKey, DepositedAmountPrefix,
    LocalSpendBookKey, OriginSpendBookKey, OriginSpendBookTransferPrefix, OutPointTransferIdKey,
    TransferMetadata, TransferMetadataKey, TransferMetadataKeyPrefix, UploadedSpendBookEntriesKey,
    WithdrawnAmountKey, WithdrawnAmountPrefix,
};

pub mod db;

/// Log target for the ecash migration module
#[allow(unused)]
const LOG_MODULE_ECASH_MIGRATION: &str = "fm::module::ecash_migration";

/// Generates the module
#[derive(Debug, Clone)]
pub struct EcashMigrationInit;

// TODO: Boilerplate-code
impl ModuleInit for EcashMigrationInit {
    type Common = EcashMigrationCommonInit;

    /// Dumps all database items for debugging
    #[allow(clippy::too_many_lines)]
    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        db::dump_database(dbtx, prefix_names).await
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
        Ok(EcashMigration {
            cfg: args.cfg().to_typed()?,
            own_peer_id: args.our_peer_id(),
            num_peers: args.num_peers(),
        })
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
                    consensus: EcashMigrationConfigConsensus {
                        fee_config: FeeConfig::default(),
                    },
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
            consensus: EcashMigrationConfigConsensus {
                fee_config: FeeConfig::default(),
            },
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
    pub own_peer_id: PeerId,
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
        dbtx.find_by_prefix(&ActivationRequestPrefix)
            .await
            .map(|(ActivationRequestKey { transfer_id }, ())| {
                EcashMigrationConsensusItem::ActivateTransfer { transfer_id }
            })
            .collect()
            .await
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        consensus_item: EcashMigrationConsensusItem,
        peer_id: PeerId,
    ) -> anyhow::Result<()> {
        let EcashMigrationConsensusItem::ActivateTransfer { transfer_id } = consensus_item else {
            bail!("Unknown consensus item variant: {}", consensus_item);
        };

        // Check that the transfer exists
        dbtx.get_value(&TransferMetadataKey(transfer_id))
            .await
            .ok_or_else(|| anyhow!("Transfer {} does not exist", transfer_id))?;

        // Insert vote and check that the peer has already voted. If so, return an error
        // so we can prune the vote from the consensus log.
        if dbtx
            .insert_entry(
                &ActivationVoteKey {
                    transfer_id,
                    peer_id,
                },
                &ActivationVote,
            )
            .await
            .is_some()
        {
            bail!(
                "Peer {} has already voted for transfer {}",
                peer_id,
                transfer_id
            );
        }

        // Remove the activation request once we've seen our own vote so we stop
        // proposing our activation vote
        if peer_id != self.own_peer_id {
            dbtx.remove_entry(&ActivationRequestKey { transfer_id })
                .await;
        }

        Ok(())
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b EcashMigrationInput,
        _in_point: InPoint,
    ) -> Result<InputMeta, EcashMigrationInputError> {
        let (transfer_id, note, amount) = match input {
            EcashMigrationInput::RedeemOriginEcash {
                transfer_id,
                note,
                amount,
            } => (transfer_id, note, amount),
            EcashMigrationInput::Default { variant, .. } => {
                return Err(EcashMigrationInputError::UnknownInputVariant(*variant));
            }
        };

        // Check transfer is active and exists
        if !is_transfer_active(dbtx, *transfer_id, self.num_peers).await {
            return Err(EcashMigrationInputError::InvalidTransfer(*transfer_id));
        }

        // Get current balance in the transfer
        let deposited_amount = dbtx
            .get_value(&DepositedAmountKey(*transfer_id))
            .await
            .expect("Deposited amount not found for existing transfer");
        let withdrawn_amount = dbtx
            .get_value(&WithdrawnAmountKey(*transfer_id))
            .await
            .expect("Withdrawn amount not found for existing transfer");
        let transfer_balance = deposited_amount
            .checked_sub(withdrawn_amount)
            .expect("Liability transfer balance cannot be negative");

        // Check amount is within transfer balance
        if transfer_balance < *amount {
            return Err(EcashMigrationInputError::UnderfundedTransfer);
        }

        // Check note signature
        let denomination_key = dbtx
            .get_value(&DenominationKeyKey {
                transfer_id: *transfer_id,
                amount: *amount,
            })
            .await
            .ok_or(EcashMigrationInputError::InvalidAmountTier(*amount))?;
        if !note.verify(denomination_key) {
            return Err(EcashMigrationInputError::InvalidSignature);
        }

        // Check if already redeemed on either the origin or local spend book
        let is_spent_on_origin = dbtx
            .get_value(&OriginSpendBookKey {
                transfer_id: *transfer_id,
                nonce: note.nonce,
            })
            .await
            .is_some();
        let is_spent_on_local = dbtx
            .get_value(&LocalSpendBookKey {
                transfer_id: *transfer_id,
                nonce: note.nonce,
            })
            .await
            .is_some();
        if is_spent_on_origin || is_spent_on_local {
            return Err(EcashMigrationInputError::AlreadyRedeemed(note.nonce));
        }

        // Insert into local spend book
        dbtx.insert_entry(
            &LocalSpendBookKey {
                transfer_id: *transfer_id,
                nonce: note.nonce,
            },
            amount,
        )
        .await;

        // Update withdrawn amount
        dbtx.insert_entry(
            &WithdrawnAmountKey(*transfer_id),
            &withdrawn_amount
                .checked_add(*amount)
                .ok_or(EcashMigrationInputError::Overflow)?,
        )
        .await;

        Ok(InputMeta {
            amount: TransactionItemAmounts {
                amounts: Amounts::new_bitcoin(*amount),
                fees: Amounts::new_bitcoin(self.cfg.consensus.fee_config.transfer_redeem_fee),
            },
            pub_key: *(note.spend_key()),
        })
    }

    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a EcashMigrationOutput,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmounts, EcashMigrationOutputError> {
        match output {
            EcashMigrationOutput::CreateTransfer {
                spend_book_hash,
                spend_book_entries,
                key_set_hash,
                creator_keys,
            } => {
                let transfer_id = get_next_transfer_id(dbtx).await;

                dbtx.insert_entry(
                    &TransferMetadataKey(transfer_id),
                    &TransferMetadata {
                        origin_spend_book_hash: *spend_book_hash,
                        origin_key_set_hash: *key_set_hash,
                        num_spend_book_entries: *spend_book_entries,
                        creator_keys: creator_keys.clone(),
                    },
                )
                .await;
                dbtx.insert_entry(&OutPointTransferIdKey(out_point), &transfer_id)
                    .await;
                dbtx.insert_entry(&DepositedAmountKey(transfer_id), &Amount::ZERO)
                    .await;
                dbtx.insert_entry(&WithdrawnAmountKey(transfer_id), &Amount::ZERO)
                    .await;

                let creation_fee = self
                    .cfg
                    .consensus
                    .fee_config
                    .creation_fee(*spend_book_entries)
                    .ok_or(EcashMigrationOutputError::CreationFeeCalculationOverflow {
                        spend_book_entries: *spend_book_entries,
                    })?;

                Ok(TransactionItemAmounts {
                    amounts: Amounts::ZERO,
                    fees: Amounts::new_bitcoin(creation_fee),
                })
            }
            EcashMigrationOutput::FundTransfer {
                transfer_id,
                amount,
            } => {
                let transfer_balance = dbtx
                    .get_value(&DepositedAmountKey(*transfer_id))
                    .await
                    .expect("Deposited amount not found for existing transfer");

                let new_transfer_balance = transfer_balance
                    .checked_add(*amount)
                    .ok_or(EcashMigrationOutputError::FundingOverflow)?;

                dbtx.insert_entry(&DepositedAmountKey(*transfer_id), &new_transfer_balance)
                    .await;

                Ok(TransactionItemAmounts {
                    amounts: Amounts::new_bitcoin(*amount),
                    fees: Amounts::new_bitcoin(self.cfg.consensus.fee_config.transfer_funding_fee),
                })
            }
            EcashMigrationOutput::Default { variant, .. } => {
                Err(EcashMigrationOutputError::UnknownOutputVariant(*variant))
            }
        }
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
        audit: &mut Audit,
        module_instance_id: ModuleInstanceId,
    ) {
        audit
            .add_items(dbtx, module_instance_id, &DepositedAmountPrefix, |_, v| {
                v.msats
                    .try_into()
                    .expect("Audit conversion to signed integer failed")
            })
            .await;
        audit
            .add_items(dbtx, module_instance_id, &WithdrawnAmountPrefix, |_, v| {
                -(i64::try_from(v.msats).expect("Audit conversion to signed integer failed"))
            })
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            api_endpoint! {
                GET_TRANSFER_ID_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &EcashMigration, context, request: OutPoint| -> TransferId {
                    module.get_transfer_id(&mut context.dbtx().into_nc(), request)
                        .await
                        .ok_or_else(|| ApiError::not_found("Transfer ID not found for out point".to_owned()))
                }
            },
            // Idempotent to allow retries for fault tolerance
            api_endpoint! {
                UPLOAD_KEY_SET_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &EcashMigration, context, request: UploadKeySetRequest| -> () {
                    check_auth(context, request.transfer_id, &request).await?;
                    module.upload_key_set(&mut context.dbtx().into_nc(), request.transfer_id, request.tier_keys)
                        .await
                }
            },
            api_endpoint! {
                UPLOAD_SPEND_BOOK_BATCH_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &EcashMigration, context, request: UploadSpendBookBatchRequest| -> UploadSpendBookBatchResponse {
                    check_auth(context, request.transfer_id, &request).await?;
                    module.upload_spend_book_batch(&mut context.dbtx().into_nc(), request.transfer_id, request.entries)
                        .await
                }
            },
            // Used to resume aborted uploads
            api_endpoint! {
                GET_UPLOADED_SPEND_BOOK_ENTRIES_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &EcashMigration, context, request: TransferId| -> u64 {
                    module.get_uploaded_spend_book_entries(&mut context.dbtx().into_nc(), request)
                        .await
                }
            },
            api_endpoint! {
                CHECK_SPEND_BOOK_HASH_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &EcashMigration, context, request: TransferId| -> SpendBookHash {
                    // TODO: check auth
                    module.check_spend_book_hash(&mut context.dbtx().into_nc(), request)
                        .await
                }
            },
            api_endpoint! {
                GET_TRANSFER_STATUS_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &EcashMigration, context, request: GetTransferStatusRequest| -> GetTransferStatusResponse {
                    module.get_transfer_status(&mut context.dbtx().into_nc(), request.transfer_id)
                        .await
                }
            },
        ]
    }
}

impl EcashMigration {
    /// Returns the transfer ID of the transfer created by the output
    async fn get_transfer_id(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        out_point: OutPoint,
    ) -> Option<TransferId> {
        dbtx.get_value(&OutPointTransferIdKey(out_point)).await
    }

    async fn upload_key_set(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        transfer_id: TransferId,
        key_set: Tiered<AggregatePublicKey>,
    ) -> Result<(), ApiError> {
        let transfer_metadata = dbtx
            .get_value(&TransferMetadataKey(transfer_id))
            .await
            .ok_or(ApiError::not_found("Transfer not found".to_owned()))?;

        let key_set_hash = key_set.consensus_hash_sha256();
        if key_set_hash != transfer_metadata.origin_key_set_hash.0 {
            return Err(ApiError::bad_request(
                "Key set hash does not match pre-committed hash".to_owned(),
            ));
        }

        for (amount, public_key) in key_set {
            if dbtx
                .insert_entry(
                    &DenominationKeyKey {
                        transfer_id,
                        amount,
                    },
                    &public_key,
                )
                .await
                .is_some()
            {
                // We can assume that finding a collision of the key set hash is impossible,
                // hence if we see one of the keys we can assume all the other keys are also
                // present.
                return Ok(());
            }
        }

        Ok(())
    }

    async fn upload_spend_book_batch(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        transfer_id: TransferId,
        spend_book_batch: Vec<Nonce>,
    ) -> Result<UploadSpendBookBatchResponse, ApiError> {
        let transfer_metadata = dbtx
            .get_value(&TransferMetadataKey(transfer_id))
            .await
            .ok_or(ApiError::not_found("Transfer not found".to_owned()))?;

        let mut new_spend_book_entries = 0;
        for nonce in spend_book_batch {
            if dbtx
                .insert_entry(&OriginSpendBookKey { transfer_id, nonce }, &())
                .await
                .is_none()
            {
                new_spend_book_entries += 1;
            } else {
                warn!(
                    target: LOG_MODULE_ECASH_MIGRATION,
                    ?transfer_id,
                    ?nonce,
                    "Nonce already uploaded to origin spend book, skipping"
                );
            }
        }

        let old_uploaded_spend_book_entries = dbtx
            .get_value(&UploadedSpendBookEntriesKey { transfer_id })
            .await
            .unwrap_or(0);
        let new_uploaded_spend_book_entries = old_uploaded_spend_book_entries
            .checked_add(new_spend_book_entries)
            .ok_or(ApiError::server_error(
                "Spend book batch size overflow".to_owned(),
            ))?;
        if transfer_metadata.num_spend_book_entries < new_uploaded_spend_book_entries {
            return Err(ApiError::bad_request(
                "Uploaded spend book entries exceeds pre-committed size".to_owned(),
            ));
        }

        dbtx.insert_entry(
            &UploadedSpendBookEntriesKey { transfer_id },
            &new_uploaded_spend_book_entries,
        )
        .await;

        Ok(UploadSpendBookBatchResponse {
            new_entries: new_spend_book_entries,
            total_entries_uploaded: new_uploaded_spend_book_entries,
        })
    }

    async fn get_uploaded_spend_book_entries(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        transfer_id: TransferId,
    ) -> Result<u64, ApiError> {
        let uploaded_spend_book_entries = dbtx
            .get_value(&UploadedSpendBookEntriesKey { transfer_id })
            .await
            .unwrap_or_default();
        Ok(uploaded_spend_book_entries)
    }

    async fn check_spend_book_hash(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        transfer_id: TransferId,
    ) -> Result<SpendBookHash, ApiError> {
        let transfer_metadata = dbtx
            .get_value(&TransferMetadataKey(transfer_id))
            .await
            .ok_or(ApiError::not_found("Transfer not found".to_owned()))?;
        let uploaded_spend_book_entries = dbtx
            .get_value(&UploadedSpendBookEntriesKey { transfer_id })
            .await
            .unwrap_or(0);

        if uploaded_spend_book_entries != transfer_metadata.num_spend_book_entries {
            return Err(ApiError::bad_request(format!(
                "Uploaded spend book entries does not match pre-committed size (expected: {}; got: {})",
                transfer_metadata.num_spend_book_entries, uploaded_spend_book_entries,
            )));
        }

        let spend_book_hash = hash_spend_book(
            dbtx.find_by_prefix(&OriginSpendBookTransferPrefix { transfer_id })
                .await
                .map(|(OriginSpendBookKey { nonce, .. }, ())| nonce),
        )
        .await;

        if spend_book_hash != transfer_metadata.origin_spend_book_hash {
            return Err(ApiError::bad_request(format!(
                "Spend book hash does not match pre-committed hash (expected: {}; got: {})",
                transfer_metadata.origin_spend_book_hash, spend_book_hash,
            )));
        }

        Ok(spend_book_hash)
    }

    async fn get_transfer_status(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        transfer_id: TransferId,
    ) -> Result<GetTransferStatusResponse, ApiError> {
        let transfer_metadata = dbtx
            .get_value(&TransferMetadataKey(transfer_id))
            .await
            .ok_or(ApiError::not_found("Transfer not found".to_owned()))?;

        let is_active = is_transfer_active(dbtx, transfer_id, self.num_peers).await;

        let deposited_amount = dbtx
            .get_value(&DepositedAmountKey(transfer_id))
            .await
            .unwrap_or(Amount::ZERO);

        let withdrawn_amount = dbtx
            .get_value(&WithdrawnAmountKey(transfer_id))
            .await
            .unwrap_or(Amount::ZERO);

        Ok(GetTransferStatusResponse {
            is_active,
            spend_book_merkle_root: transfer_metadata.origin_spend_book_merkle_root,
            key_set_hash: transfer_metadata.origin_key_set_hash,
            total_entries: transfer_metadata.num_spend_book_entries,
            total_amount: deposited_amount,
            redeemed_amount: withdrawn_amount,
        })
    }
}

/// Check if a transfer is active (has enough votes)
async fn is_transfer_active(
    dbtx: &mut DatabaseTransaction<'_>,
    transfer_id: TransferId,
    num_peers: NumPeers,
) -> bool {
    let vote_count = dbtx
        .find_by_prefix(&ActivationVoteTransferPrefix { transfer_id })
        .await
        .count()
        .await;

    vote_count == num_peers.total()
}

async fn get_next_transfer_id(dbtx: &mut DatabaseTransaction<'_>) -> TransferId {
    let max_id = dbtx
        .find_by_prefix_sorted_descending(&TransferMetadataKeyPrefix)
        .await
        .next()
        .await
        .map_or(0, |(TransferMetadataKey(id), _)| id.0);

    TransferId(max_id + 1)
}

async fn check_auth(
    context: &mut ApiEndpointContext<'_>,
    transfer_id: TransferId,
    request: &impl Encodable,
) -> Result<(), ApiError> {
    let transfer_metadata = context
        .dbtx()
        .get_value(&TransferMetadataKey(transfer_id))
        .await
        .ok_or(ApiError::not_found("Transfer not found".to_owned()))?;
    let creator_keys = transfer_metadata.creator_keys;

    let auth = context.request_auth().ok_or(ApiError::unauthorized())?;
    let signature: NaiveThresholdSignature =
        auth.0.parse().map_err(|_| ApiError::unauthorized())?;

    let request_hash = Message::from_digest_slice(request.consensus_hash_sha256().as_ref())
        .expect("Hash has correct length");

    if !signature.verify(request_hash, &creator_keys) {
        return Err(ApiError::unauthorized());
    }

    Ok(())
}
