use std::collections::BTreeMap;

use fedimint_core::config::{
    ServerModuleConfig, ServerModuleConsensusConfig, TypedServerModuleConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::envs::{FM_ENABLE_MODULE_ESCROW_ENV, is_env_var_set_opt};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    Amounts, ApiEndpoint, ApiVersion, CORE_CONSENSUS_VERSION, CoreConsensusVersion, InputMeta,
    ModuleConsensusVersion, ModuleInit, SupportedModuleApiVersions, TransactionItemAmounts,
    api_endpoint,
};
use fedimint_core::{
    InPoint, OutPoint, PeerId, apply, async_trait_maybe_send, push_db_pair_items, secp256k1,
};
use fedimint_escrow_common::config::{
    EscrowClientConfig, EscrowConfig, EscrowConfigConsensus, EscrowConfigPrivate,
};
use fedimint_escrow_common::{
    ContractHash, EscrowCommonInit, EscrowConsensusItem, EscrowContract, EscrowId, EscrowInput,
    EscrowInputError, EscrowMessage, EscrowModuleTypes, EscrowOutput, EscrowOutputError,
    EscrowOutputOutcome, GET_CONTRACT_ENDPOINT, GET_PENDING_ARBITER_FEE_ENDPOINT, KIND,
    MODULE_CONSENSUS_VERSION, Outcome, PendingArbiterFee, Resolution, compute_contract_hash,
    compute_escrow_message,
};
use fedimint_logging::LOG_MODULE_ESCROW;
use fedimint_server_core::config::PeerHandleOps;
use fedimint_server_core::migration::ServerModuleDbMigrationFn;
use fedimint_server_core::{
    ConfigGenModuleArgs, ServerModule, ServerModuleInit, ServerModuleInitArgs,
};
use futures::StreamExt;
use strum::IntoEnumIterator;
use tracing::{debug, info};

mod db;
use crate::db::{
    DbKeyPrefix, EscrowContractKey, EscrowContractPrefix, EscrowOutputOutcomeKey,
    EscrowOutputOutcomePrefix, PendingArbiterFeeKey, PendingArbiterFeePrefix,
};

#[derive(Debug, Clone)]
pub struct EscrowInit;

impl ModuleInit for EscrowInit {
    type Common = EscrowCommonInit;

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let mut contracts: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> =
            BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::EscrowContract => {
                    push_db_pair_items!(
                        dbtx,
                        EscrowContractPrefix,
                        EscrowContractKey,
                        EscrowContract,
                        contracts,
                        "Escrow Contracts"
                    );
                }
                DbKeyPrefix::PendingArbiterFee => {
                    push_db_pair_items!(
                        dbtx,
                        PendingArbiterFeePrefix,
                        PendingArbiterFeeKey,
                        PendingArbiterFee,
                        contracts,
                        "Pending Arbiter Fee Claim"
                    );
                }
                DbKeyPrefix::OutputOutcome => {
                    push_db_pair_items!(
                        dbtx,
                        EscrowOutputOutcomePrefix,
                        EscrowOutputOutcomeKey,
                        EscrowOutputOutcome,
                        contracts,
                        "Escrow Output Outcomes"
                    );
                }
            }
        }

        Box::new(contracts.into_iter())
    }
}

#[apply(async_trait_maybe_send!)]
impl ServerModuleInit for EscrowInit {
    type Module = Escrow;
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

    fn kind() -> fedimint_core::core::ModuleKind {
        KIND
    }

    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(Escrow {
            cfg: args.cfg().to_typed()?,
        })
    }

    fn is_enabled_by_default(&self) -> bool {
        is_env_var_set_opt(FM_ENABLE_MODULE_ESCROW_ENV).unwrap_or(true)
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        _args: &ConfigGenModuleArgs,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        peers
            .iter()
            .map(|&peer| {
                let config = EscrowConfig {
                    private: EscrowConfigPrivate,
                    consensus: EscrowConfigConsensus,
                };
                (peer, config.to_erased())
            })
            .collect()
    }

    fn get_client_config(
        &self,
        _config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<EscrowClientConfig> {
        Ok(EscrowClientConfig)
    }

    async fn distributed_gen(
        &self,
        _peers: &(dyn PeerHandleOps + Send + Sync),
        _args: &ConfigGenModuleArgs,
    ) -> anyhow::Result<ServerModuleConfig> {
        Ok(EscrowConfig {
            private: EscrowConfigPrivate,
            consensus: EscrowConfigConsensus,
        }
        .to_erased())
    }

    fn validate_config(
        &self,
        _identity: &PeerId,
        _config: ServerModuleConfig,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    fn get_database_migrations(
        &self,
    ) -> BTreeMap<DatabaseVersion, ServerModuleDbMigrationFn<Escrow>> {
        BTreeMap::new()
    }
}

#[derive(Debug)]
pub struct Escrow {
    pub cfg: EscrowConfig,
}

#[apply(async_trait_maybe_send!)]
impl ServerModule for Escrow {
    type Common = EscrowModuleTypes;
    type Init = EscrowInit;

    async fn consensus_proposal(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<EscrowConsensusItem> {
        Vec::new()
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _consensus_item: EscrowConsensusItem,
        _peer_id: PeerId,
    ) -> anyhow::Result<()> {
        anyhow::bail!("The escrow module does not use consensus items");
    }

    // Contract Resolution
    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b EscrowInput,
        _in_point: InPoint,
    ) -> Result<InputMeta, EscrowInputError> {
        info!(target: LOG_MODULE_ESCROW, "Resolving the escrow contract");

        match &input.resolution {
            Resolution::BuyerRelease { buyer_signature } => {
                let contract = dbtx
                    .get_value(&EscrowContractKey(input.escrow_id))
                    .await
                    .ok_or(EscrowInputError::ContractNotFound)?;

                debug!(target: LOG_MODULE_ESCROW, "Loaded escrow contract for escrow_id={:?}",contract.escrow_id);

                let verified = verify_contract_hash(&contract.contract_hash.0, &contract);
                if !verified {
                    return Err(EscrowInputError::ContractHashMismatch);
                }
                let resolution_message = EscrowMessage::Resolution {
                    escrow_id: contract.escrow_id,
                    federation_id: contract.federation_id,
                    outcome: Outcome::Release,
                    contract_hash: contract.contract_hash,
                };
                let msg_bytes = compute_escrow_message(&resolution_message);
                info!(target: LOG_MODULE_ESCROW, "Computed resolution message");

                let msg = secp256k1::Message::from_digest(msg_bytes);
                let xonly_public_key = contract.buyer_key.x_only_public_key().0;
                secp256k1::global::SECP256K1
                    .verify_schnorr(buyer_signature, &msg, &xonly_public_key)
                    .map_err(|_| EscrowInputError::InvalidBuyerSignature)?;

                dbtx.remove_entry(&EscrowContractKey(input.escrow_id)).await;

                info!(target: LOG_MODULE_ESCROW, "Escrow contract resolved and removed: escrow_id={:?}",contract.escrow_id);
                Ok(InputMeta {
                    amount: TransactionItemAmounts {
                        amounts: Amounts::new_bitcoin(contract.amount),
                        fees: Amounts::ZERO,
                    },
                    pub_key: contract.seller_key,
                })
            }
            Resolution::ArbiterOutcome {
                arbiter_signature,
                outcome,
            } => {
                let contract = dbtx
                    .get_value(&EscrowContractKey(input.escrow_id))
                    .await
                    .ok_or(EscrowInputError::ContractNotFound)?;

                debug!(target: LOG_MODULE_ESCROW, "Loaded escrow contract for escrow_id={:?}",contract.escrow_id);

                let verified = verify_contract_hash(&contract.contract_hash.0, &contract);
                if !verified {
                    return Err(EscrowInputError::ContractHashMismatch);
                }
                let now = fedimint_core::time::duration_since_epoch().as_secs();
                if now < contract.timeout {
                    return Err(EscrowInputError::TimeoutNotReached);
                }

                let payout_amount = contract
                    .amount
                    .checked_sub(contract.arbiter_fee)
                    .ok_or_else(|| {
                        EscrowInputError::InternalError(
                            "arbiter fee exceeds contract amount".into(),
                        )
                    })?;

                let resolution_message = EscrowMessage::Resolution {
                    escrow_id: contract.escrow_id,
                    federation_id: contract.federation_id,
                    outcome: *outcome,
                    contract_hash: contract.contract_hash,
                };
                let msg_bytes = compute_escrow_message(&resolution_message);
                let msg = secp256k1::Message::from_digest(msg_bytes);
                let xonly = contract.arbiter_key.x_only_public_key().0;
                secp256k1::global::SECP256K1
                    .verify_schnorr(arbiter_signature, &msg, &xonly)
                    .map_err(|_| EscrowInputError::InvalidArbiterSignature)?;

                let recipient_key = match outcome {
                    Outcome::Release => contract.seller_key,
                    Outcome::Refund => contract.buyer_key,
                };

                dbtx.insert_entry(
                    &PendingArbiterFeeKey(input.escrow_id),
                    &PendingArbiterFee {
                        escrow_id: input.escrow_id,
                        arbiter_key: contract.arbiter_key,
                        fee_amount: contract.arbiter_fee,
                    },
                )
                .await;

                dbtx.remove_entry(&EscrowContractKey(input.escrow_id)).await;

                info!(target: LOG_MODULE_ESCROW, "Escrow contract resolved and removed: escrow_id={:?}",contract.escrow_id);
                Ok(InputMeta {
                    amount: TransactionItemAmounts {
                        amounts: Amounts::new_bitcoin(payout_amount),
                        fees: Amounts::ZERO,
                    },
                    pub_key: recipient_key,
                })
            }
            Resolution::ArbiterFeeClaim { arbiter_signature } => {
                let pending = dbtx
                    .get_value(&PendingArbiterFeeKey(input.escrow_id))
                    .await
                    .ok_or(EscrowInputError::ContractNotFound)?;

                let arbiter_message = EscrowMessage::ArbiterFeeClaim {
                    escrow_id: input.escrow_id,
                    fee_amount: pending.fee_amount,
                };
                let msg_bytes = compute_escrow_message(&arbiter_message);
                let msg = secp256k1::Message::from_digest(msg_bytes);
                let xonly = pending.arbiter_key.x_only_public_key().0;
                secp256k1::global::SECP256K1
                    .verify_schnorr(arbiter_signature, &msg, &xonly)
                    .map_err(|_| EscrowInputError::InvalidArbiterSignature)?;

                dbtx.remove_entry(&PendingArbiterFeeKey(input.escrow_id))
                    .await;

                Ok(InputMeta {
                    amount: TransactionItemAmounts {
                        amounts: Amounts::new_bitcoin(pending.fee_amount),
                        fees: Amounts::ZERO,
                    },
                    pub_key: pending.arbiter_key,
                })
            }
        }
    }

    // Contract creation
    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a EscrowOutput,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmounts, EscrowOutputError> {
        let contract = &output.contract;
        let verified = verify_contract_hash(&contract.contract_hash.0, contract);
        if !verified {
            return Err(EscrowOutputError::ContractHashMismatch);
        }

        if dbtx
            .get_value(&EscrowContractKey(contract.escrow_id))
            .await
            .is_some()
        {
            return Err(EscrowOutputError::AlreadyExists);
        }

        info!(target: LOG_MODULE_ESCROW, "Creating escrow contract: escrow_id={:?}",contract.escrow_id);

        dbtx.insert_entry(&EscrowContractKey(contract.escrow_id), contract)
            .await;

        dbtx.insert_entry(&EscrowOutputOutcomeKey(out_point), &EscrowOutputOutcome)
            .await;

        debug!(target: LOG_MODULE_ESCROW, "Escrow contract stored successfully for escrow_id: {:?}",contract.escrow_id);

        Ok(TransactionItemAmounts {
            amounts: Amounts::new_bitcoin(contract.amount),
            fees: Amounts::ZERO,
        })
    }

    async fn output_status(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        out_point: OutPoint,
    ) -> Option<EscrowOutputOutcome> {
        dbtx.get_value(&EscrowOutputOutcomeKey(out_point)).await
    }

    // Every stored contract is a liability as federation owes this amount to buyer
    // or seller
    async fn audit(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        audit: &mut Audit,
        module_instance_id: ModuleInstanceId,
    ) {
        // contracts are liabilities
        audit
            .add_items(
                dbtx,
                module_instance_id,
                &EscrowContractPrefix,
                |_, contract: EscrowContract| -(contract.amount.msats as i64),
            )
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            api_endpoint! {
                GET_CONTRACT_ENDPOINT,
                ApiVersion::new(0, 1),
                async |_module: &Escrow, context, escrow_id: EscrowId|
                    -> Option<EscrowContract>
                {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(dbtx.get_value(&EscrowContractKey(escrow_id)).await)
                }
            },
            api_endpoint! {
                GET_PENDING_ARBITER_FEE_ENDPOINT,
                ApiVersion::new(0, 1),
                async |_module: &Escrow, context, escrow_id: EscrowId|
                    -> Option<PendingArbiterFee>
                {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(dbtx.get_value(&PendingArbiterFeeKey(escrow_id)).await)
                }
            },
        ]
    }
}

fn verify_contract_hash(contract_hash: &[u8; 32], contract: &EscrowContract) -> bool {
    compute_contract_hash(
        &contract.buyer_key,
        &contract.seller_key,
        &contract.arbiter_key,
        &contract.amount,
        &contract.timeout,
        &contract.federation_id,
    ) == ContractHash(*contract_hash)
}

impl Escrow {
    pub fn new(cfg: EscrowConfig) -> Self {
        Self { cfg }
    }
}
