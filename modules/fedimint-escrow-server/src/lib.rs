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
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::{
    Amount, BitcoinHash, InPoint, OutPoint, PeerId, apply, async_trait_maybe_send,
    push_db_pair_items, secp256k1,
};
use fedimint_escrow_common::config::{
    EscrowClientConfig, EscrowConfig, EscrowConfigConsensus, EscrowConfigPrivate,
};
use fedimint_escrow_common::{
    ContractHash, EscrowCommonInit, EscrowConsensusItem, EscrowContract, EscrowId, EscrowInput,
    EscrowInputError, EscrowMessage, EscrowModuleTypes, EscrowOutput, EscrowOutputError,
    EscrowOutputOutcome, EscrowStatus, EscrowTransition, FallbackPolicy, GET_CONTRACT_DOMAIN,
    GET_CONTRACT_ENDPOINT, GET_PENDING_ARBITER_FEE_ENDPOINT, GET_PENDING_FEE_DOMAIN,
    GetContractParams, GetPendinFeeParams, KIND, LIST_CONTRACT_BY_KEY_ENDPOINT,
    LIST_CONTRACT_DOMAIN, ListContractParams, MODULE_CONSENSUS_VERSION, Outcome,
    PendingArbiterFeePool, PendingSplitPool, Resolution, compute_contract_hash,
    compute_escrow_message, compute_proof_message, validate_split_bps,
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
    EscrowOutputOutcomePrefix, PendingArbiterFeePoolKey, PendingArbiterFeePrefix,
    PendingSplitPoolKey, PendingSplitPoolPrefix,
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
                DbKeyPrefix::PendingArbiterFeePool => {
                    push_db_pair_items!(
                        dbtx,
                        PendingArbiterFeePrefix,
                        PendingArbiterFeeKey,
                        PendingArbiterFeePool,
                        contracts,
                        "Pending Arbiter Fee Claim"
                    );
                }
                DbKeyPrefix::PendingSplitPool => {
                    push_db_pair_items!(
                        dbtx,
                        PendingSplitPoolPrefix,
                        PendingSplitPoolKey,
                        PendingSplitPool,
                        contracts,
                        "Pending Split Pool"
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
            Resolution::FunderRelease { funder_signature } => {
                self.handle_funder_release(dbtx, input, funder_signature)
                    .await
            }
            Resolution::ArbiterOutcome {
                arbiter_signature,
                outcome,
                claimer_pubkey,
            } => {
                self.handle_arbiter_decision(
                    input,
                    dbtx,
                    arbiter_signature,
                    outcome,
                    claimer_pubkey,
                )
                .await
            }
            Resolution::ArbiterEngaged {
                disputant_pubkey,
                disputant_signature,
                arbiter_signature,
            } => {
                self.handle_arbiter_engage(
                    input,
                    dbtx,
                    disputant_pubkey,
                    disputant_signature,
                    arbiter_signature,
                )
                .await
            }
            Resolution::ArbiterFeeClaim {
                arbiter_claim_pubkey,
                arbiter_signature,
            } => {
                self.handle_fee_claim(dbtx, input, arbiter_claim_pubkey, arbiter_signature)
                    .await
            }
            Resolution::ResolveFallbackPolicy {
                claimer_pubkey,
                fallback: _,
            } => {
                self.handle_fallback_resolution(input, dbtx, claimer_pubkey)
                    .await
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

        if contract.amount == Amount::ZERO {
            return Err(EscrowOutputError::InvalidInputs);
        }
        if contract.arbiter_fee >= contract.amount {
            return Err(EscrowOutputError::InvalidInputs);
        }
        let now = fedimint_core::time::duration_since_epoch().as_secs();
        if contract.timeout <= now {
            return Err(EscrowOutputError::InvalidInputs);
        }
        if contract.resolution_timeout <= contract.timeout {
            return Err(EscrowOutputError::InvalidInputs);
        }
        // in process_output, alongside the other contract.* checks
        if let FallbackPolicy::Split {
            funder_split_bps,
            recipient_split_bps,
        } = contract.default_fallback
            && !validate_split_bps(funder_split_bps, recipient_split_bps)
        {
            return Err(EscrowOutputError::InvalidInputs);
        }
        if contract.funder_key == contract.recipient_key
            || contract.funder_key == contract.arbiter_key
            || contract.recipient_key == contract.arbiter_key
        {
            return Err(EscrowOutputError::InvalidInputs);
        }

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

    // Every stored contract is a liability as federation owes this amount to funder
    // or recipient
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
                |_, contract: EscrowContract| match contract.status {
                    EscrowStatus::Active | EscrowStatus::Disputed => {
                        -(contract.amount.msats as i64)
                    }
                    EscrowStatus::Released | EscrowStatus::Refunded | EscrowStatus::Split => 0,
                },
            )
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            api_endpoint! {
                GET_CONTRACT_ENDPOINT,
                ApiVersion::new(0, 1),
                async |_module: &Escrow, context, params: GetContractParams|
                    -> Option<EscrowContract>
                {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;

                    let Some(contract) = dbtx
                        .get_value(&EscrowContractKey(params.escrow_id))
                        .await
                    else {
                        return Ok(None);
                    };

                    let msg = compute_proof_message(
                        GET_CONTRACT_DOMAIN.as_bytes(),
                        &params.escrow_id.0,
                        &params.pubkey,
                        Some(&contract.federation_id),
                    );

                    let participant = params.pubkey == contract.funder_key
                        || params.pubkey == contract.recipient_key
                        || params.pubkey == contract.arbiter_key;

                    if !participant {
                        return Ok(None);
                    }

                    let authorized =
                        verify_signature(&params.pubkey, msg, &params.sign);

                    if authorized {
                        Ok(Some(contract))
                    } else {
                        Ok(None)
                    }
                }
            },
            api_endpoint! {
                GET_PENDING_ARBITER_FEE_ENDPOINT,
                ApiVersion::new(0, 1),
                async |_module: &Escrow, context, params: GetPendinFeeParams|
                    -> Option<(PublicKey, Amount)>
                {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;

                    let Some(pool) = dbtx
                        .get_value(&PendingArbiterFeePoolKey(params.escrow_id))
                        .await
                    else {
                        return Ok(None);
                    };

                    let (arbiter_pubkey, share) =
                        match get_pending_arbiter_fee(&params.pubkey, &pool) {
                            Ok(result) => result,
                            Err(_) => return Ok(None),
                        };

                    let msg = compute_proof_message(
                        GET_PENDING_FEE_DOMAIN.as_bytes(),
                        &params.escrow_id.0,
                        &params.pubkey,
                        None,
                    );

                    let authorized =
                        verify_signature(&arbiter_pubkey, msg, &params.sign);

                    if !authorized {
                        return Ok(None);
                    }

                    Ok(Some((arbiter_pubkey, share)))
                }
            },
            api_endpoint! {
                LIST_CONTRACT_BY_KEY_ENDPOINT,
                ApiVersion::new(0, 1),
                async |_module: &Escrow, context, params: ListContractParams|
                    -> Vec<EscrowContract>
                {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;

                    let msg = compute_proof_message(
                        LIST_CONTRACT_DOMAIN.as_bytes(),
                        &params.federation_id.0.to_byte_array(),
                        &params.pubkey,
                        Some(&params.federation_id),
                    );

                    if !verify_signature(&params.pubkey, msg, &params.sig) {
                        return Ok(vec![]);
                    }

                    let pubkey = params.pubkey;

                    let contracts: Vec<EscrowContract> = dbtx
                        .find_by_prefix(&EscrowContractPrefix)
                        .await
                        .filter_map(move |(_, contract)| {
                            let pubkey = pubkey;

                            async move {
                                if contract.funder_key == pubkey
                                    || contract.recipient_key == pubkey
                                    || contract.arbiter_key == pubkey
                                {
                                    Some(contract)
                                } else {
                                    None
                                }
                            }
                        })
                        .collect()
                        .await;

                    Ok(contracts)
                }
            },
        ]
    }
}

fn verify_contract_hash(contract_hash: &[u8; 32], contract: &EscrowContract) -> bool {
    compute_contract_hash(
        &contract.funder_key,
        &contract.recipient_key,
        &contract.arbiter_key,
        &contract.amount,
        &contract.timeout,
        &contract.federation_id,
        &contract.resolution_timeout,
        &contract.default_fallback,
    ) == ContractHash(*contract_hash)
}

fn verify_signature(
    pubkey: &PublicKey,
    msg_bytes: [u8; 32],
    sig: &secp256k1::schnorr::Signature,
) -> bool {
    let msg = secp256k1::Message::from_digest(msg_bytes);

    secp256k1::global::SECP256K1
        .verify_schnorr(sig, &msg, &pubkey.x_only_public_key().0)
        .is_ok()
}

fn get_pending_arbiter_fee(
    claimer_pubkey: &PublicKey,
    pool: &PendingArbiterFeePool,
) -> Result<(PublicKey, Amount), EscrowInputError> {
    let arbiter_pubkey = pool
        .remaining_arbiters
        .contains(claimer_pubkey)
        .then_some(claimer_pubkey)
        .ok_or(EscrowInputError::InvalidArbiterSignature)?;

    let share = Amount::from_msats(
        pool.remaining_amount
            .msats
            .checked_div(pool.remaining_arbiters.len().try_into().unwrap())
            .ok_or(EscrowInputError::InternalError(
                "Invalid amount share".into(),
            ))?,
    );

    Ok((*arbiter_pubkey, share))
}

impl Escrow {
    pub fn new(cfg: EscrowConfig) -> Self {
        Self { cfg }
    }

    async fn load_contract(
        &self,
        escrow_id: EscrowId,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Result<EscrowContract, EscrowInputError> {
        let contract = dbtx
            .get_value(&EscrowContractKey(escrow_id))
            .await
            .ok_or(EscrowInputError::ContractNotFound)?;

        debug!(target: LOG_MODULE_ESCROW, "Loaded escrow contract for escrow_id={:?}",contract.escrow_id);

        let verified = verify_contract_hash(&contract.contract_hash.0, &contract);
        if !verified {
            return Err(EscrowInputError::ContractHashMismatch);
        }

        Ok(contract)
    }

    async fn handle_funder_release(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        input: &EscrowInput,
        funder_signature: &Signature,
    ) -> Result<InputMeta, EscrowInputError> {
        let mut contract = self.load_contract(input.escrow_id, dbtx).await?;
        if contract.status == EscrowStatus::Disputed {
            return Err(EscrowInputError::ContractDisputed);
        }

        let resolution_message = contract.resolution_message(Outcome::Release);

        let msg_bytes = compute_escrow_message(&resolution_message);
        info!(target: LOG_MODULE_ESCROW, "Computed resolution message");

        if !verify_signature(&contract.funder_key, msg_bytes, funder_signature) {
            return Err(EscrowInputError::InvalidFunderSignature);
        }

        contract.transition(EscrowTransition::FunderRelease)?;
        dbtx.insert_entry(&EscrowContractKey(input.escrow_id), &contract)
            .await;

        info!(target: LOG_MODULE_ESCROW, "Escrow contract resolved with funder release");
        Ok(InputMeta {
            amount: TransactionItemAmounts {
                amounts: Amounts::new_bitcoin(contract.amount),
                fees: Amounts::ZERO,
            },
            pub_key: contract.recipient_key,
        })
    }

    async fn resolve_dispute(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        outcome: Outcome,
        contract: &mut EscrowContract,
        claimer_pubkey: PublicKey,
        is_arbiter_resolution: bool,
    ) -> Result<InputMeta, EscrowInputError> {
        let (arbiter_fee, transition) = if is_arbiter_resolution {
            (
                contract.arbiter_fee,
                EscrowTransition::ArbiterOutcome(outcome),
            )
        } else {
            (Amount::ZERO, EscrowTransition::Fallback)
        };
        let payout_amount = contract.amount.checked_sub(arbiter_fee).ok_or_else(|| {
            EscrowInputError::InternalError("arbiter fee exceeds contract amount".into())
        })?;

        match outcome {
            Outcome::Release | Outcome::Refund => {
                let recipient_key = match outcome {
                    Outcome::Release => contract.recipient_key,
                    Outcome::Refund => contract.funder_key,
                    Outcome::Split { .. } => unreachable!(),
                };

                if claimer_pubkey != recipient_key {
                    return Err(EscrowInputError::InvalidArbiterSignature);
                }

                self.set_pending_arbiter_fee(dbtx, contract, arbiter_fee)
                    .await;

                contract.transition(transition)?;
                dbtx.insert_entry(&EscrowContractKey(contract.escrow_id), contract)
                    .await;

                Ok(InputMeta {
                    amount: TransactionItemAmounts {
                        amounts: Amounts::new_bitcoin(payout_amount),
                        fees: Amounts::ZERO,
                    },
                    pub_key: recipient_key,
                })
            }
            Outcome::Split {
                funder_split_bps,
                recipient_split_bps,
            } => {
                if claimer_pubkey != contract.funder_key && claimer_pubkey != contract.recipient_key
                {
                    return Err(EscrowInputError::InvalidArbiterSignature);
                }
                if !validate_split_bps(funder_split_bps, recipient_split_bps) {
                    return Err(EscrowInputError::InvalidSplitRatio);
                }

                if let Some(pending) = dbtx
                    .get_value(&PendingSplitPoolKey(contract.escrow_id))
                    .await
                {
                    if pending.claimant_key != claimer_pubkey {
                        return Err(EscrowInputError::NoPendingSplitClaim);
                    }
                    dbtx.remove_entry(&PendingSplitPoolKey(contract.escrow_id))
                        .await;

                    return Ok(InputMeta {
                        amount: TransactionItemAmounts {
                            amounts: Amounts::new_bitcoin(pending.amount),
                            fees: Amounts::ZERO,
                        },
                        pub_key: claimer_pubkey,
                    });
                }

                let funder_amount = Amount::from_msats(
                    payout_amount
                        .msats
                        .saturating_mul(u64::from(funder_split_bps))
                        / 10_000u64,
                );
                let recipient_amount = payout_amount
                    .checked_sub(funder_amount)
                    .ok_or_else(|| EscrowInputError::InternalError("split overflow".into()))?;

                let (claim_amount, other_pubkey, other_amount) =
                    if claimer_pubkey == contract.funder_key {
                        (funder_amount, contract.recipient_key, recipient_amount)
                    } else {
                        (recipient_amount, contract.funder_key, funder_amount)
                    };

                contract.transition(transition)?;
                dbtx.insert_entry(&EscrowContractKey(contract.escrow_id), contract)
                    .await;

                self.set_pending_arbiter_fee(dbtx, contract, arbiter_fee)
                    .await;

                dbtx.insert_entry(
                    &PendingSplitPoolKey(contract.escrow_id),
                    &PendingSplitPool {
                        escrow_id: contract.escrow_id,
                        claimant_key: other_pubkey,
                        amount: other_amount,
                    },
                )
                .await;

                Ok(InputMeta {
                    amount: TransactionItemAmounts {
                        amounts: Amounts::new_bitcoin(claim_amount),
                        fees: Amounts::ZERO,
                    },
                    pub_key: claimer_pubkey,
                })
            }
        }
    }

    async fn set_pending_arbiter_fee(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        contract: &EscrowContract,
        arbiter_fee: Amount,
    ) {
        if arbiter_fee == Amount::ZERO {
            return;
        }
        dbtx.insert_entry(
            &PendingArbiterFeePoolKey(contract.escrow_id),
            &PendingArbiterFeePool {
                escrow_id: contract.escrow_id,
                remaining_arbiters: vec![contract.arbiter_key],
                remaining_amount: arbiter_fee,
            },
        )
        .await;
    }

    async fn handle_arbiter_engage(
        &self,
        input: &EscrowInput,
        dbtx: &mut DatabaseTransaction<'_>,
        disputant_pubkey: &PublicKey,
        disputatnt_signature: &Signature,
        arbiter_signature: &Signature,
    ) -> Result<InputMeta, EscrowInputError> {
        let mut contract = self.load_contract(input.escrow_id, dbtx).await?;

        let now = fedimint_core::time::duration_since_epoch().as_secs();
        if now > contract.timeout {
            return Err(EscrowInputError::TimeoutNotReached);
        }
        let is_valid_disputant =
            *disputant_pubkey == contract.funder_key || *disputant_pubkey == contract.recipient_key;
        if !is_valid_disputant {
            return Err(EscrowInputError::InvalidFunderSignature);
        }

        let engage_message = contract.engage_message();
        let msg_bytes = compute_escrow_message(&engage_message);
        if !verify_signature(disputant_pubkey, msg_bytes, disputatnt_signature) {
            return Err(EscrowInputError::InvalidFunderSignature);
        }

        if !verify_signature(&contract.arbiter_key, msg_bytes, arbiter_signature) {
            return Err(EscrowInputError::InvalidFunderSignature);
        }

        contract.transition(EscrowTransition::ArbiterEngaged)?;
        dbtx.insert_entry(&EscrowContractKey(input.escrow_id), &contract)
            .await;

        Ok(InputMeta {
            amount: TransactionItemAmounts {
                amounts: Amounts::ZERO,
                fees: Amounts::ZERO,
            },
            pub_key: contract.arbiter_key,
        })
    }

    async fn handle_arbiter_decision(
        &self,
        input: &EscrowInput,
        dbtx: &mut DatabaseTransaction<'_>,
        arbiter_signature: &Signature,
        outcome: &Outcome,
        claimer_pubkey: &PublicKey,
    ) -> Result<InputMeta, EscrowInputError> {
        let mut contract = self.load_contract(input.escrow_id, dbtx).await?;
        if contract.status != EscrowStatus::Disputed {
            return Err(EscrowInputError::ContractNotDisputed);
        }

        let resolution_message = contract.resolution_message(*outcome);

        let msg_bytes = compute_escrow_message(&resolution_message);
        if !verify_signature(&contract.arbiter_key, msg_bytes, arbiter_signature) {
            return Err(EscrowInputError::InvalidArbiterSignature);
        }

        self.resolve_dispute(dbtx, *outcome, &mut contract, *claimer_pubkey, true)
            .await
    }

    async fn handle_fallback_resolution(
        &self,
        input: &EscrowInput,
        dbtx: &mut DatabaseTransaction<'_>,
        claimer_pubkey: &PublicKey,
    ) -> Result<InputMeta, EscrowInputError> {
        let mut contract = self.load_contract(input.escrow_id, dbtx).await?;

        let now = fedimint_core::time::duration_since_epoch().as_secs();
        if now <= contract.resolution_timeout {
            return Err(EscrowInputError::FallbackNotAvailable);
        }

        let outcome = match contract.default_fallback {
            FallbackPolicy::Refund => Outcome::Refund,
            FallbackPolicy::Split {
                funder_split_bps,
                recipient_split_bps,
            } => Outcome::Split {
                funder_split_bps,
                recipient_split_bps,
            },
        };

        // No arbiter fee: they didn't do the work, they don't get paid.
        self.resolve_dispute(dbtx, outcome, &mut contract, *claimer_pubkey, false)
            .await
    }

    async fn handle_fee_claim(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        input: &EscrowInput,
        claimer_pubkey: &PublicKey,
        arbiter_signature: &Signature,
    ) -> Result<InputMeta, EscrowInputError> {
        let mut pool = dbtx
            .get_value(&PendingArbiterFeePoolKey(input.escrow_id))
            .await
            .ok_or(EscrowInputError::ContractNotFound)?;

        let (arbiter_pubkey, arbiter_fee) = get_pending_arbiter_fee(claimer_pubkey, &pool)?;

        let arbiter_message = EscrowMessage::ArbiterFeeClaim {
            escrow_id: input.escrow_id,
            fee_amount: arbiter_fee,
        };
        let msg_bytes = compute_escrow_message(&arbiter_message);
        if !verify_signature(&arbiter_pubkey, msg_bytes, arbiter_signature) {
            return Err(EscrowInputError::InvalidArbiterSignature);
        }

        pool.remaining_amount = pool
            .remaining_amount
            .checked_sub(arbiter_fee)
            .ok_or(EscrowInputError::InternalError("pool underflow".into()))?;

        pool.remaining_arbiters.retain(|k| *k != *claimer_pubkey);

        if pool.remaining_arbiters.is_empty() {
            dbtx.remove_entry(&PendingArbiterFeePoolKey(input.escrow_id))
                .await;
        } else {
            dbtx.insert_entry(&PendingArbiterFeePoolKey(input.escrow_id), &pool)
                .await;
        }

        Ok(InputMeta {
            amount: TransactionItemAmounts {
                amounts: Amounts::new_bitcoin(arbiter_fee),
                fees: Amounts::ZERO,
            },
            pub_key: arbiter_pubkey,
        })
    }
}

#[cfg(test)]
mod tests;
