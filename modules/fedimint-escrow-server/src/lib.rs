use std::collections::BTreeMap;

use fedimint_core::config::{
    ServerModuleConfig, ServerModuleConsensusConfig, TypedServerModuleConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::envs::{FM_ENABLE_MODULE_ESCROW_ENV, is_env_var_set_opt};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    Amounts, ApiEndpoint, ApiVersion, CoreConsensusVersion, InputMeta, ModuleConsensusVersion,
    ModuleInit, TransactionItemAmounts, public_api_endpoint,
};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::time::duration_since_epoch;
use fedimint_core::{
    InPoint, NumPeers, OutPoint, PeerId, apply, async_trait_maybe_send, push_db_pair_items,
};
use fedimint_escrow_common::config::{
    EscrowClientConfig, EscrowConfig, EscrowConfigConsensus, EscrowConfigPrivate,
};
use fedimint_escrow_common::endpoint_constants::{
    CONSENSUS_UNIX_TIME_ENDPOINT, GET_CLAIM_AMOUNT_ENDPOINT, GET_CONTRACT_ENDPOINT, GetClaimAmount,
    GetContractParams, LIST_CONTRACT_BY_KEY_ENDPOINT, ListContractParams,
};
use fedimint_escrow_common::rules::{Settlement, check_resolution};
use fedimint_escrow_common::{
    ClaimPool, ContractHash, EscrowCommonInit, EscrowConsensusItem, EscrowContract, EscrowId,
    EscrowInput, EscrowInputError, EscrowModuleTypes, EscrowOutput, EscrowOutputError,
    EscrowOutputOutcome, EscrowStatus, KIND, MODULE_CONSENSUS_VERSION, Resolution,
    compute_contract_hash, validate_contract_fields, x_only,
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
    ClaimPoolKey, ClaimPoolPrefix, ContractByKeyKey, DbKeyPrefix, EscrowContractKey,
    EscrowContractPrefix, EscrowOutputOutcomeKey, EscrowOutputOutcomePrefix, UnixTimeVoteKey,
    UnixTimeVotePrefix,
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
                DbKeyPrefix::ClaimPool => {
                    push_db_pair_items!(
                        dbtx,
                        ClaimPoolPrefix,
                        ClaimPoolKey,
                        ClaimPool,
                        contracts,
                        "Claim Pool"
                    );
                }
                DbKeyPrefix::UnixTimeVote => {
                    push_db_pair_items!(
                        dbtx,
                        UnixTimeVotePrefix,
                        UnixTimeVoteKey,
                        u64,
                        contracts,
                        "Unix Time Votes"
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
                DbKeyPrefix::ContractByKey => {}
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

    fn kind() -> fedimint_core::core::ModuleKind {
        KIND
    }

    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(Escrow {
            cfg: args.cfg().to_typed()?,
            num_peers: args.num_peers(),
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
    num_peers: NumPeers,
}

#[apply(async_trait_maybe_send!)]
impl ServerModule for Escrow {
    type Common = EscrowModuleTypes;
    type Init = EscrowInit;

    async fn consensus_proposal(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<EscrowConsensusItem> {
        // the local clock is only used here, for voting. 60s granularity so
        // identical votes are deduplicated instead of stored every second
        vec![EscrowConsensusItem::UnixTimeVote(
            60 * (duration_since_epoch().as_secs() / 60),
        )]
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        item: EscrowConsensusItem,
        peer: PeerId,
    ) -> anyhow::Result<()> {
        match item {
            EscrowConsensusItem::UnixTimeVote(vote) => {
                let current = dbtx
                    .insert_entry(&UnixTimeVoteKey(peer), &vote)
                    .await
                    .unwrap_or(0);
                anyhow::ensure!(current < vote, "Unix time vote is redundant");
                Ok(())
            }
            EscrowConsensusItem::Default { variant, .. } => {
                anyhow::bail!("unknown escrow consensus item variant {variant}")
            }
        }
    }

    // Contract Resolution
    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b EscrowInput,
        _in_point: InPoint,
    ) -> Result<InputMeta, EscrowInputError> {
        let input = input.ensure_v0_ref()?;
        info!(target: LOG_MODULE_ESCROW, "Resolving the escrow contract");

        match &input.resolution {
            Resolution::ClaimPayout { claimer_pubkey } => {
                self.handle_claim(dbtx, input.escrow_id, claimer_pubkey)
                    .await
            }
            resolution => {
                self.handle_resolution(dbtx, input.escrow_id, resolution)
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
        let output = output.ensure_v0_ref()?;
        let contract = &output.contract;

        let now = self.consensus_unix_time(dbtx).await;
        validate_contract_fields(contract, now).map_err(EscrowOutputError::InvalidInputs)?;

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

        for key in contract.all_keys() {
            dbtx.insert_entry(
                &ContractByKeyKey {
                    key: x_only(&key).serialize(),
                    escrow_id: contract.escrow_id,
                },
                &(),
            )
            .await;
        }

        dbtx.insert_entry(
            &EscrowOutputOutcomeKey(out_point),
            &EscrowOutputOutcome::new_v0(),
        )
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
                    EscrowStatus::Active | EscrowStatus::Disputed { .. } => {
                        -(contract.amount.msats as i64)
                    }
                    EscrowStatus::Released | EscrowStatus::Refunded | EscrowStatus::Split => 0,
                },
            )
            .await;
        audit
            .add_items(
                dbtx,
                module_instance_id,
                &ClaimPoolPrefix,
                |_, pool: ClaimPool| {
                    -(pool.claimer.iter().map(|(_, a)| a.msats).sum::<u64>() as i64)
                },
            )
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            public_api_endpoint! {
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
                    Ok(Some(contract))
                }
            },
            public_api_endpoint! {
                GET_CLAIM_AMOUNT_ENDPOINT,
                ApiVersion::new(0, 1),
                async |_module: &Escrow, context, params: GetClaimAmount|
                    -> Option<ClaimPool>
                {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;

                    let Some(pool) = dbtx
                        .get_value(&ClaimPoolKey(params.escrow_id))
                        .await
                    else {
                        return Ok(None);
                    };

                    Ok(Some(pool))
                }
            },
            public_api_endpoint! {
                LIST_CONTRACT_BY_KEY_ENDPOINT,
                ApiVersion::new(0, 1),
                async |_module: &Escrow, context, params: ListContractParams|
                    -> Vec<EscrowContract>
                {
                    let limit = params.limit.map_or(usize::MAX, |l| l as usize);

                    let key = x_only(&params.pubkey).serialize();
                    let Some(end_key) = next_key(key) else {
                        return Ok(vec![]);
                    };

                    let start = ContractByKeyKey {
                        key,
                        escrow_id: params.last_seen.unwrap_or(EscrowId([0u8; 32])),
                    };
                    let end = ContractByKeyKey {
                        key: end_key,
                        escrow_id: EscrowId([0u8; 32]),
                    };

                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;

                    let ids: Vec<EscrowId> = dbtx
                        .find_by_range(start..end)
                        .await
                        .map(|(index_key, ())| index_key.escrow_id)
                        .filter(|id| futures::future::ready(Some(*id) != params.last_seen))
                        .take(limit)
                        .collect()
                        .await;

                    let mut contracts = Vec::with_capacity(ids.len());
                    for id in ids {
                        if let Some(contract) = dbtx.get_value(&EscrowContractKey(id)).await {
                            contracts.push(contract);
                        }
                    }
                    Ok(contracts)
                }
            },
            public_api_endpoint! {
                CONSENSUS_UNIX_TIME_ENDPOINT,
                ApiVersion::new(0, 1),
                async |module: &Escrow, context, _params: ()| -> u64 {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.consensus_unix_time(&mut dbtx).await)
                }
            },
        ]
    }
}

// smallest 32 byte value bigger than every row of `key`, none if `key` is all
// 0xff
fn next_key(key: [u8; 32]) -> Option<[u8; 32]> {
    let mut next = key;
    for byte in next.iter_mut().rev() {
        if *byte == u8::MAX {
            *byte = 0;
        } else {
            *byte += 1;
            return Some(next);
        }
    }
    None
}

fn verify_contract_hash(contract_hash: &[u8; 32], contract: &EscrowContract) -> bool {
    compute_contract_hash(
        &contract.funder_key,
        &contract.recipient_key,
        &contract.arbiter_key,
        &contract.arbiter_fee,
        &contract.amount,
        &contract.timeout,
        &contract.federation_id,
        &contract.resolution_period,
        &contract.arbiter_fee_key,
        &contract.default_fallback,
    ) == ContractHash(*contract_hash)
}

impl Escrow {
    async fn consensus_unix_time(&self, dbtx: &mut DatabaseTransaction<'_>) -> u64 {
        let mut times: Vec<u64> = dbtx
            .find_by_prefix(&UnixTimeVotePrefix)
            .await
            .map(|(_, t)| t)
            .collect()
            .await;
        times.sort_unstable();
        times.reverse();
        // highest time that a threshold of guardians has reached
        times
            .get(self.num_peers.threshold() - 1)
            .copied()
            .unwrap_or(0)
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

        Ok(contract)
    }

    async fn handle_resolution(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        escrow_id: EscrowId,
        resolution: &Resolution,
    ) -> Result<InputMeta, EscrowInputError> {
        let mut contract = self.load_contract(escrow_id, dbtx).await?;
        let now = self.consensus_unix_time(dbtx).await;

        let accepted = check_resolution(&contract, resolution, now)?;
        contract.transition(accepted.transition)?;

        let amounts = match accepted.settlement {
            Settlement::None => Amounts::ZERO,
            Settlement::PayRecipient(amount) => Amounts::new_bitcoin(amount),
            Settlement::WriteClaims(claimer) => {
                // A contract that is not resolved yet never has a pool.
                if dbtx.get_value(&ClaimPoolKey(escrow_id)).await.is_some() {
                    return Err(EscrowInputError::InvalidStateTransition);
                }
                dbtx.insert_entry(&ClaimPoolKey(escrow_id), &ClaimPool { escrow_id, claimer })
                    .await;
                Amounts::ZERO
            }
        };

        dbtx.insert_entry(&EscrowContractKey(escrow_id), &contract)
            .await;

        Ok(InputMeta {
            amount: TransactionItemAmounts {
                amounts,
                fees: Amounts::ZERO,
            },
            pub_key: accepted.input_key,
        })
    }

    async fn handle_claim(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        escrow_id: EscrowId,
        claimer: &PublicKey,
    ) -> Result<InputMeta, EscrowInputError> {
        let contract = self.load_contract(escrow_id, dbtx).await?;
        if !contract.contains_key(claimer) {
            return Err(EscrowInputError::NotAParticipant);
        }

        let mut pool = dbtx
            .get_value(&ClaimPoolKey(escrow_id))
            .await
            .ok_or(EscrowInputError::NoPendingClaim)?;

        let (stored_key, amount) = pool
            .take_claim(claimer)
            .ok_or(EscrowInputError::NoPendingClaim)?;

        if pool.claimer.is_empty() {
            dbtx.remove_entry(&ClaimPoolKey(escrow_id)).await;
        } else {
            dbtx.insert_entry(&ClaimPoolKey(escrow_id), &pool).await;
        }

        Ok(InputMeta {
            amount: TransactionItemAmounts {
                amounts: Amounts::new_bitcoin(amount),
                fees: Amounts::ZERO,
            },
            pub_key: stored_key,
        })
    }
}

#[cfg(test)]
mod tests;
