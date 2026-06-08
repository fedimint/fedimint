use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Error, bail};
use fedimint_client_module::module::init::{
    ClientModuleInit, ClientModuleInitArgs, ClientModuleRecoverArgs,
};
use fedimint_client_module::module::{
    ClientContext, ClientModule, OutPointRange, PrimaryModuleSupport,
};
use fedimint_client_module::oplog::{OperationLogEntry, UpdateStreamOrOutcome};
use fedimint_client_module::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client_module::transaction::{
    ClientInput, ClientInputBundle, ClientInputSM, ClientOutput, ClientOutputBundle,
    ClientOutputSM, TransactionBuilder,
};
use fedimint_client_module::{DynGlobalClientContext, sm_enum_variant_translation};
use fedimint_core::bitcoin::hashes::{HashEngine, sha256};
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{Amounts, ApiVersion, ModuleInit, MultiApiVersion};
use fedimint_core::secp256k1::{Keypair, PublicKey, Secp256k1, schnorr};
use fedimint_core::{Amount, BitcoinHash, apply, async_trait_maybe_send, push_db_pair_items};
use fedimint_escrow_common::config::EscrowClientConfig;
use fedimint_escrow_common::{
    EscrowCommonInit, EscrowContract, EscrowId, EscrowInput, EscrowModuleTypes, EscrowOutput, KIND,
    Outcome, PendingArbiterFee, Resolution, compute_contract_hash, compute_resolution_message,
};
use fedimint_logging::LOG_CLIENT_MODULE_ESCROW;
use futures::StreamExt;
use ring::rand::{SecureRandom, SystemRandom};
use strum::IntoEnumIterator;
use tracing::info;

use crate::api::EscrowFederationApi;
use crate::backup::{EscrowBackup, EscrowRecovery};
use crate::client_db::{
    ClientEscrowKey, ClientEscrowKeyPrefix, DbKeyPrefix, EscrowAction, EscrowClientRecord,
    EscrowClientStatus, EscrowOperationMeta,
};
use crate::input::{EscrowInputSMCommon, EscrowInputSMState, EscrowInputStateMachine};
use crate::output::{EscrowOutputSMCommon, EscrowOutputSMState, EscrowOutputStateMachine};
pub mod api;
pub mod backup;
mod client_db;
pub mod input;
pub mod output;

#[cfg(feature = "cli")]
pub mod cli;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum EscrowStateMachine {
    Input(EscrowInputStateMachine),
    Output(EscrowOutputStateMachine),
}

impl State for EscrowStateMachine {
    type ModuleContext = EscrowClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self {
            EscrowStateMachine::Input(sm) => {
                sm_enum_variant_translation!(
                    sm.transitions(context, global_context),
                    EscrowStateMachine::Input
                )
            }
            EscrowStateMachine::Output(sm) => {
                sm_enum_variant_translation!(
                    sm.transitions(context, global_context),
                    EscrowStateMachine::Output
                )
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            EscrowStateMachine::Input(sm) => sm.common.operation_id,
            EscrowStateMachine::Output(sm) => sm.common.operation_id,
        }
    }
}

impl IntoDynInstance for EscrowStateMachine {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

#[derive(Clone)]
pub struct EscrowClientContext {
    escrow_decoder: Decoder,
    client_ctx: ClientContext<EscrowClientModule>,
    notifier: ModuleNotifier<EscrowStateMachine>,
}

impl Context for EscrowClientContext {
    const KIND: Option<ModuleKind> = Some(KIND);
}

impl fmt::Debug for EscrowClientContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EscrowClientContext")
            .field("escrow_decoder", &self.escrow_decoder)
            .field("client_ctx", &self.client_ctx)
            .field("notifier", &self.notifier)
            .finish_non_exhaustive()
    }
}

pub struct EscrowClientModule {
    federation_id: FederationId,
    cfg: EscrowClientConfig,
    pub client_ctx: ClientContext<Self>,
    pub keypair: Keypair,
    notifier: ModuleNotifier<EscrowStateMachine>,
}

impl fmt::Debug for EscrowClientModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EscrowClientModule")
            .field("federation_id", &self.federation_id)
            .field("cfg", &self.cfg)
            .field("notifier", &self.notifier)
            .field("client_ctx", &self.client_ctx)
            .field("keypair", &self.keypair)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct EscrowClientInit;

impl ModuleInit for EscrowClientInit {
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
                DbKeyPrefix::ClientEscrows => {
                    push_db_pair_items!(
                        dbtx,
                        ClientEscrowKeyPrefix,
                        ClientEscrowKey,
                        EscrowClientRecord,
                        contracts,
                        "Client Escrow Contracts"
                    );
                }
                DbKeyPrefix::ExternalReservedStart
                | DbKeyPrefix::RecoveryState
                | DbKeyPrefix::RecoveryFinalized
                | DbKeyPrefix::CoreInternalReservedStart
                | DbKeyPrefix::CoreInternalReservedEnd => {}
            }
        }

        Box::new(contracts.into_iter())
    }
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for EscrowClientInit {
    type Module = EscrowClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(EscrowClientModule {
            federation_id: args.federation_id,
            cfg: args.cfg.clone(),
            client_ctx: args.context.clone(),
            keypair: args
                .module_root_secret()
                .clone()
                .to_secp_key(&Secp256k1::new()),
            notifier: args.notifier().clone(),
        })
    }

    async fn recover(
        &self,
        args: &ClientModuleRecoverArgs<Self>,
        snapshot: Option<&EscrowBackup>,
    ) -> anyhow::Result<()> {
        args.recover_from_history::<EscrowRecovery>(&self, snapshot)
            .await
    }
}

#[apply(async_trait_maybe_send!)]
impl ClientModule for EscrowClientModule {
    type Init = EscrowClientInit;
    type Common = EscrowModuleTypes;
    type Backup = EscrowBackup;
    type ModuleStateMachineContext = EscrowClientContext;
    type States = EscrowStateMachine;

    fn context(&self) -> EscrowClientContext {
        EscrowClientContext {
            escrow_decoder: <EscrowClientModule as ClientModule>::decoder(),
            client_ctx: self.client_ctx.clone(),
            notifier: self.notifier.clone(),
        }
    }

    fn supports_being_primary(&self) -> PrimaryModuleSupport {
        PrimaryModuleSupport::None
    }

    fn supports_backup(&self) -> bool {
        true
    }

    async fn backup(&self) -> anyhow::Result<EscrowBackup> {
        let session_count = self.client_ctx.global_api().session_count().await?;

        let contracts = self.list_escrow_operation().await;
        Ok(EscrowBackup {
            session_count,
            records: contracts,
        })
    }

    fn input_fee(&self, _amount: &Amounts, _input: &EscrowInput) -> Option<Amounts> {
        Some(Amounts::ZERO)
    }

    fn output_fee(&self, _amount: &Amounts, _output: &EscrowOutput) -> Option<Amounts> {
        Some(Amounts::ZERO)
    }

    #[cfg(feature = "cli")]
    async fn handle_cli_command(
        &self,
        args: &[std::ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        cli::handle_cli_command(&self, args).await
    }
}

impl EscrowClientModule {
    pub async fn create_escrow(
        &self,
        seller_key: PublicKey,
        arbiter_key: PublicKey,
        arbiter_fee: Amount,
        amount: Amount,
        timeout: Duration,
    ) -> Result<(OperationId, EscrowId), anyhow::Error> {
        let buyer_key = self.keypair.public_key();
        let timeout_deadline =
            fedimint_core::time::duration_since_epoch().as_secs() + timeout.as_secs();

        anyhow::ensure!(buyer_key != seller_key, "buyer and seller keys must differ");
        anyhow::ensure!(
            buyer_key != arbiter_key,
            "buyer and arbiter keys must differ"
        );
        anyhow::ensure!(
            seller_key != arbiter_key,
            "seller and arbiter keys must differ"
        );
        anyhow::ensure!(amount > Amount::ZERO, "amount must be greater than zero");
        anyhow::ensure!(arbiter_fee < amount, "arbiter fee must be less than amount");
        anyhow::ensure!(!timeout.is_zero(), "timeout must be non-zero");

        let contract_hash = compute_contract_hash(
            &buyer_key,
            &seller_key,
            &arbiter_key,
            &amount,
            &timeout_deadline,
            &self.federation_id,
        );

        let rng = SystemRandom::new();
        let mut nonce = [0u8; 32];
        let _ = rng.fill(&mut nonce);

        let operation_id = OperationId::new_random();
        let escrow_id: EscrowId = {
            let mut engine = sha256::HashEngine::default();
            engine.input(b"escrow_id");
            engine.input(&contract_hash);
            engine.input(&nonce);
            EscrowId(sha256::Hash::from_engine(engine).to_byte_array())
        };

        let contract = EscrowContract {
            escrow_id,
            buyer_key,
            seller_key,
            arbiter_key,
            amount,
            arbiter_fee,
            contract_hash,
            timeout: timeout_deadline,
            federation_id: self.federation_id,
        };

        info!(target: LOG_CLIENT_MODULE_ESCROW, "Created escrow contract locally");

        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;
        dbtx.insert_entry(
            &ClientEscrowKey(escrow_id),
            &EscrowClientRecord {
                operation_id,
                escrow_id,
                amount,
                status: EscrowClientStatus::Creating,
            },
        )
        .await;

        dbtx.commit_tx().await;

        let output_sm = ClientOutputSM {
            state_machines: Arc::new(move |out_point_range: OutPointRange| {
                out_point_range
                    .into_iter()
                    .map(|out_point| {
                        EscrowStateMachine::Output(EscrowOutputStateMachine {
                            common: EscrowOutputSMCommon {
                                operation_id,
                                out_point,
                                escrow_id,
                                amount,
                            },
                            state: EscrowOutputSMState::Creating,
                        })
                    })
                    .collect()
            }),
        };

        let output = ClientOutput {
            output: EscrowOutput { contract },
            amounts: Amounts::new_bitcoin(amount),
        };

        let tx = TransactionBuilder::new().with_outputs(
            self.client_ctx
                .make_client_outputs(ClientOutputBundle::new(vec![output], vec![output_sm])),
        );

        let operation_meta_gen = move |out_point_range: OutPointRange| {
            let txid = out_point_range.txid();
            let out_point_indices = out_point_range
                .into_iter()
                .map(|out_point| out_point.out_idx)
                .collect();

            EscrowOperationMeta {
                escrow_id,
                amount,
                action: EscrowAction::Created,
                txid,
                out_point_indices,
            }
        };

        self.client_ctx
            .finalize_and_submit_transaction(operation_id, KIND.as_str(), operation_meta_gen, tx)
            .await?;

        Ok((operation_id, escrow_id))
    }

    pub async fn resolve_escrow(
        &self,
        escrow_id: EscrowId,
        buyer_signature: schnorr::Signature,
    ) -> Result<OperationId, anyhow::Error> {
        let operation_id = OperationId::new_random();
        let contract = self
            .get_contract(escrow_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Escrow contract not found"))?;

        let input = ClientInput {
            amounts: Amounts::new_bitcoin(contract.amount),
            keys: vec![self.keypair],
            input: EscrowInput {
                escrow_id,
                resolution: Resolution::BuyerRelease { buyer_signature },
            },
        };

        let input_sm = ClientInputSM {
            state_machines: Arc::new(move |out_point_range: OutPointRange| {
                out_point_range
                    .into_iter()
                    .map(|out_point| {
                        EscrowStateMachine::Input(EscrowInputStateMachine {
                            common: EscrowInputSMCommon {
                                operation_id,
                                out_point,
                                escrow_id,
                                amount: contract.amount,
                                resolution: Resolution::BuyerRelease { buyer_signature },
                            },
                            state: EscrowInputSMState::Pending,
                        })
                    })
                    .collect()
            }),
        };

        let tx = TransactionBuilder::new().with_inputs(
            self.client_ctx
                .make_dyn(ClientInputBundle::new(vec![input], vec![input_sm])),
        );

        let operation_meta_gen = move |out_point_range: OutPointRange| {
            let txid = out_point_range.txid();
            let out_point_indices = out_point_range
                .into_iter()
                .map(|out_point| out_point.out_idx)
                .collect();

            EscrowOperationMeta {
                escrow_id,
                amount: contract.amount,
                action: EscrowAction::Released,
                txid,
                out_point_indices,
            }
        };

        self.client_ctx
            .finalize_and_submit_transaction(operation_id, KIND.as_str(), operation_meta_gen, tx)
            .await?;

        Ok(operation_id)
    }

    pub async fn submit_arbiter_decision(
        &self,
        escrow_id: EscrowId,
        outcome: Outcome,
        arbiter_signature: schnorr::Signature,
    ) -> anyhow::Result<OperationId> {
        let operation_id = OperationId::new_random();
        let contract = self
            .get_contract(escrow_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Escrow contract not found"))?;

        let payout_amount = contract
            .amount
            .checked_sub(contract.arbiter_fee)
            .ok_or_else(|| anyhow::anyhow!("arbiter fee exceeds contract amount"))?;

        let input = ClientInput {
            amounts: Amounts::new_bitcoin(payout_amount),
            keys: vec![self.keypair],
            input: EscrowInput {
                escrow_id,
                resolution: Resolution::ArbiterOutcome {
                    arbiter_signature,
                    outcome,
                },
            },
        };

        let input_sm = ClientInputSM {
            state_machines: Arc::new(move |out_point_range: OutPointRange| {
                out_point_range
                    .into_iter()
                    .map(|out_point| {
                        EscrowStateMachine::Input(EscrowInputStateMachine {
                            common: EscrowInputSMCommon {
                                operation_id,
                                out_point,
                                escrow_id,
                                amount: contract.amount,
                                resolution: Resolution::ArbiterOutcome {
                                    arbiter_signature,
                                    outcome,
                                },
                            },
                            state: EscrowInputSMState::Pending,
                        })
                    })
                    .collect()
            }),
        };

        let tx = TransactionBuilder::new().with_inputs(
            self.client_ctx
                .make_dyn(ClientInputBundle::new(vec![input], vec![input_sm])),
        );

        let operation_meta_gen = move |out_point_range: OutPointRange| {
            let txid = out_point_range.txid();
            let out_point_indices = out_point_range
                .into_iter()
                .map(|out_point| out_point.out_idx)
                .collect();

            EscrowOperationMeta {
                escrow_id,
                amount: contract.amount,
                action: match outcome {
                    Outcome::Release => EscrowAction::Released,
                    Outcome::Refund => EscrowAction::Refunded,
                },
                txid,
                out_point_indices,
            }
        };

        self.client_ctx
            .finalize_and_submit_transaction(operation_id, KIND.as_str(), operation_meta_gen, tx)
            .await?;

        Ok(operation_id)
    }

    pub async fn claim_arbiter_fee(
        &self,
        escrow_id: EscrowId,
        arbiter_signature: schnorr::Signature,
    ) -> anyhow::Result<OperationId> {
        let operation_id = OperationId::new_random();

        let pending: PendingArbiterFee = self
            .client_ctx
            .module_api()
            .get_pending_arbiter_fee(escrow_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("No pending arbiter fee for escrow"))?;

        let input = ClientInput {
            amounts: Amounts::new_bitcoin(pending.fee_amount),
            keys: vec![self.keypair],
            input: EscrowInput {
                escrow_id,
                resolution: Resolution::ArbiterFeeClaim { arbiter_signature },
            },
        };

        let input_sm = ClientInputSM {
            state_machines: Arc::new(move |out_point_range: OutPointRange| {
                out_point_range
                    .into_iter()
                    .map(|out_point| {
                        EscrowStateMachine::Input(EscrowInputStateMachine {
                            common: EscrowInputSMCommon {
                                operation_id,
                                out_point,
                                escrow_id,
                                amount: pending.fee_amount,
                                resolution: Resolution::ArbiterFeeClaim { arbiter_signature },
                            },
                            state: EscrowInputSMState::FeeClaiming,
                        })
                    })
                    .collect()
            }),
        };

        let tx = TransactionBuilder::new().with_inputs(
            self.client_ctx
                .make_dyn(ClientInputBundle::new(vec![input], vec![input_sm])),
        );

        let operation_meta_gen = move |out_point_range: OutPointRange| EscrowOperationMeta {
            escrow_id,
            amount: pending.fee_amount,
            action: EscrowAction::ArbiterFeeClaimed,
            txid: out_point_range.txid(),
            out_point_indices: out_point_range.into_iter().map(|op| op.out_idx).collect(),
        };

        self.client_ctx
            .finalize_and_submit_transaction(operation_id, KIND.as_str(), operation_meta_gen, tx)
            .await?;

        Ok(operation_id)
    }

    pub async fn subscribe_fee_claim(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<EscrowInputSMState>> {
        let operation: OperationLogEntry = self.escrow_operation(operation_id).await?;
        let meta = operation.meta::<EscrowOperationMeta>();
        let txid = meta.txid;

        let client_ctx = self.client_ctx.clone();

        Ok(self
            .client_ctx
            .outcome_or_updates(operation, operation_id, move || {
                let client_ctx = client_ctx.clone();
                async_stream::stream! {
                    yield EscrowInputSMState::FeeClaiming;

                    match client_ctx
                        .transaction_updates(operation_id)
                        .await
                        .await_tx_accepted(txid)
                        .await
                    {
                        Ok(()) => {
                            yield EscrowInputSMState::FeeClaimed;
                        }
                        Err(e) => {
                            yield EscrowInputSMState::Failed { reason: e.to_string() };
                        }
                    }
                }
            }))
    }

    pub async fn get_contract(
        &self,
        escrow_id: EscrowId,
    ) -> Result<Option<EscrowContract>, anyhow::Error> {
        let contract: Option<EscrowContract> =
            self.client_ctx.module_api().get_contract(escrow_id).await?;
        Ok(contract)
    }

    async fn escrow_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<OperationLogEntry, Error> {
        let operation_log = self.client_ctx.get_operation(operation_id).await?;
        if operation_log.operation_module_kind() != KIND.as_str() {
            bail!("Operation is not an escrow operation");
        }
        Ok(operation_log)
    }

    pub async fn list_escrow_operation(&self) -> Vec<EscrowClientRecord> {
        let mut dbtx = self.client_ctx.module_db().begin_transaction_nc().await;

        let records: Vec<EscrowClientRecord> = dbtx
            .find_by_prefix(&ClientEscrowKeyPrefix)
            .await
            .map(|(_, record)| record)
            .collect()
            .await;

        records
    }

    pub async fn subscribe_escrow_creation(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<EscrowOutputSMState>> {
        let operation: OperationLogEntry = self.escrow_operation(operation_id).await?;
        let meta = operation.meta::<EscrowOperationMeta>();
        let txid = meta.txid;
        // let out_points: Vec<OutPoint> = meta
        //     .out_point_indices
        //     .into_iter()
        //     .map(|out_idx| OutPoint { txid, out_idx })
        //     .collect();

        let client_ctx = self.client_ctx.clone();

        Ok(self
            .client_ctx
            .outcome_or_updates(operation, operation_id, move || {
                let client_ctx = client_ctx.clone();
                async_stream::stream! {
                    yield EscrowOutputSMState::Creating;

                    match client_ctx
                        .transaction_updates(operation_id)
                        .await
                        .await_tx_accepted(txid)
                        .await
                    {
                        Ok(()) => {
                            yield EscrowOutputSMState::Active;
                        }
                        Err(e) => {
                            yield EscrowOutputSMState::Failed { reason: e.to_string() };
                            return;
                        }
                    }

                    // Should we use outpoints from EscrowOutputOutcome
                    // for out_point in out_points {
                    //     if let Err(e) = client_ctx
                    //         .await_output_outcome::<EscrowOutputOutcome>(
                    //             out_point,
                    //             operation_id,
                    //         )
                    //         .await
                    //     {
                    //         yield EscrowOutputSMState::Failed { reason: e.to_string() };
                    //         return;
                    //     }
                    // }
                }
            }))
    }

    pub async fn subscribe_escrow_resolution(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<EscrowInputSMState>> {
        let operation: OperationLogEntry = self.escrow_operation(operation_id).await?;
        let meta = operation.meta::<EscrowOperationMeta>();
        let txid = meta.txid;

        let client_ctx = self.client_ctx.clone();

        Ok(self
            .client_ctx
            .outcome_or_updates(operation, operation_id, move || {
                let client_ctx = client_ctx.clone();
                async_stream::stream! {
                    yield EscrowInputSMState::Pending;

                    // Waiting for resolution tx to be accepted
                    match client_ctx
                        .transaction_updates(operation_id)
                        .await
                        .await_tx_accepted(txid)
                        .await
                    {
                        Ok(()) => {
                            match meta.action {
                                EscrowAction::Released => yield EscrowInputSMState::Released,
                                EscrowAction::Refunded  => yield EscrowInputSMState::Refunded,
                                EscrowAction::Created   => {
                                    yield EscrowInputSMState::Failed {
                                        reason: "unexpected error in resolution".to_string()
                                    };
                                }
                                EscrowAction::ArbiterFeeClaimed => yield EscrowInputSMState::FeeClaimed,
                            }
                        }
                        Err(e) => {
                            yield EscrowInputSMState::Failed { reason: e.to_string() };
                        }
                    }
                }
            }))
    }

    pub fn sign_release_message(
        &self,
        escrow_id: EscrowId,
        contract: &EscrowContract,
    ) -> schnorr::Signature {
        let msg_bytes = compute_resolution_message(
            &contract.federation_id,
            &escrow_id,
            &Outcome::Release,
            &contract.contract_hash,
        );
        let msg = fedimint_core::secp256k1::Message::from_digest(msg_bytes);
        Secp256k1::new().sign_schnorr(&msg, &self.keypair)
    }
}
