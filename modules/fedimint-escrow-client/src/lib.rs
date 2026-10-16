use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Error, anyhow, bail};
use async_stream::{stream, try_stream};
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{
    ClientContext, ClientModule, OutPointRange, PrimaryModuleSupport,
};
use fedimint_client_module::oplog::{OperationLogEntry, UpdateStreamOrOutcome};
use fedimint_client_module::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client_module::transaction::{
    ClientInput, ClientInputBundle, ClientInputSM, ClientOutput, ClientOutputBundle,
    ClientOutputSM, TransactionBuilder,
};
use fedimint_client_module::{
    ClientModuleError, DynGlobalClientContext, sm_enum_variant_translation,
};
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{Amounts, ApiVersion, ModuleInit, MultiApiVersion};
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::secp256k1::{Keypair, Message, PublicKey, Secp256k1, schnorr};
use fedimint_core::util::BoxStream;
use fedimint_core::{Amount, OutPoint, apply, async_trait_maybe_send, push_db_pair_items};
use fedimint_derive_secret::{ChildId, DerivableSecret};
use fedimint_escrow_common::config::EscrowClientConfig;
use fedimint_escrow_common::{
    ClaimPool, ContractHash, EscrowCommonInit, EscrowContract, EscrowId, EscrowInput,
    EscrowMessage, EscrowModuleTypes, EscrowOutput, FallbackPolicy, GetClaimAmount,
    GetContractParams, KIND, ListContractParams, Outcome, Resolution, compute_contract_hash,
    compute_escrow_message, x_only_eq,
};
use frost_secp256k1_tr::Identifier;
use futures::lock::Mutex;
use futures::{StreamExt, TryStreamExt};
use iroh::{NodeAddr, SecretKey};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;

use crate::api::EscrowFederationApi;
use crate::client_db::{
    DbKeyPrefix, EscrowAction, EscrowOperationMeta, FrostDkgSessionKey, FrostDkgSessionPrefix,
    FrostDkgSessionRecordPrefix, FrostDkgSessionRecordkey,
};
use crate::frost::dkg::{DkgError, DkgResult};
use crate::frost::session::{FrostDkgSession, FrostDkgSessionRecord, FrostParticipant, SessionId};
use crate::frost::transport::DkgTransport;
use crate::frost::transport::iroh::IrohDkgTransport;
use crate::input::{EscrowInputSMCommon, EscrowInputSMState, EscrowInputStateMachine};
use crate::output::{EscrowOutputSMCommon, EscrowOutputSMState, EscrowOutputStateMachine};
pub mod api;
mod client_db;
pub mod frost;
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

enum EscrowChildKeys {
    Escrow = 0,
    ArbiterFee = 1,
    IrohKey = 3,
}

pub struct EscrowClientModule {
    federation_id: FederationId,
    cfg: EscrowClientConfig,
    pub client_ctx: ClientContext<Self>,
    escrow_key: Keypair,
    arbiter_fee_key: Keypair,
    secret: DerivableSecret,
    notifier: ModuleNotifier<EscrowStateMachine>,
    dkg_transports: Mutex<BTreeMap<SessionId, Arc<IrohDkgTransport>>>,
}

impl fmt::Debug for EscrowClientModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EscrowClientModule")
            .field("federation_id", &self.federation_id)
            .field("cfg", &self.cfg)
            .field("notifier", &self.notifier)
            .field("client_ctx", &self.client_ctx)
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
                DbKeyPrefix::FrostDkgSession => {
                    push_db_pair_items!(
                        dbtx,
                        FrostDkgSessionPrefix,
                        FrostDkgSessionKey,
                        FrostDkgSession,
                        contracts,
                        "Frost Consortium Session"
                    );
                }
                DbKeyPrefix::FrostDkgSessionRecord => {
                    push_db_pair_items!(
                        dbtx,
                        FrostDkgSessionRecordPrefix,
                        FrostDkgSessionRecordkey,
                        FrostDkgSessionRecord,
                        contracts,
                        "Frost Consortium Record"
                    );
                }
                DbKeyPrefix::ExternalReservedStart
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

    async fn init(
        &self,
        args: &ClientModuleInitArgs<Self>,
    ) -> Result<Self::Module, ClientModuleError> {
        Ok(EscrowClientModule {
            federation_id: args.federation_id,
            cfg: args.cfg.clone(),
            client_ctx: args.context.clone(),
            escrow_key: args
                .module_root_secret()
                .child_key(ChildId(EscrowChildKeys::Escrow as u64))
                .to_secp_key(&Secp256k1::new()),
            arbiter_fee_key: args
                .module_root_secret()
                .child_key(ChildId(EscrowChildKeys::ArbiterFee as u64))
                .to_secp_key(&Secp256k1::new()),
            secret: args.module_root_secret.clone(),
            notifier: args.notifier().clone(),
            dkg_transports: Default::default(),
        })
    }
}

#[apply(async_trait_maybe_send!)]
impl ClientModule for EscrowClientModule {
    type Init = EscrowClientInit;
    type Common = EscrowModuleTypes;
    type Backup = NoModuleBackup;
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
        false
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
    ) -> Result<serde_json::Value, ClientModuleError> {
        cli::handle_cli_command(&self, args)
            .await
            .map_err(ClientModuleError::other)
    }

    async fn handle_rpc(
        &self,
        method: String,
        request: serde_json::Value,
    ) -> BoxStream<'_, Result<serde_json::Value, ClientModuleError>> {
        let stream: BoxStream<'_, anyhow::Result<serde_json::Value>> = Box::pin(try_stream! {
            match method.as_str() {
                "get_client_escrow_pubkey"=>{
                    let pubkey=self.escrow_key.public_key().to_string();
                    yield serde_json::to_value(pubkey)?;
                }
                "get_arbiter_fee_pubkey"=>{
                    let pubkey=self.arbiter_fee_key.public_key().to_string();
                    yield serde_json::to_value(pubkey)?;
                }
                "get_contract" => {
                    let req:GetContractRequest= serde_json::from_value(request)?;
                    let result= self.get_contract(req.escrow_id).await?;
                    yield serde_json::to_value(result)?;
                }
                "list_escrows"=>{
                    let result=self.list_contracts().await?;
                    yield serde_json::to_value(result)?;
                }
                "create_contract"=>{
                    let req:CreateContractRequest= serde_json::from_value(request)?;
                    let result=self.create_escrow(
                        req.recipient_key,
                        req.arbiter_key,
                        req.arbiter_fee,
                        req.amount,
                        req.timeout,
                        req.arbiter_fee_key,
                        req.resolution_period,
                        req.default_fallback
                    ).await?;
                    yield serde_json::to_value(result)?;
                }
                "subscribe_escrow_creation"=>{
                    let req:SubscribeCreationRequest=serde_json::from_value(request)?;
                    let stream=self.subscribe_escrow_creation(req.operation_id).await?;
                    for await state in stream.into_stream() {
                        yield serde_json::to_value(state)?;
                    }
                }
                "resolve_escrow"=>{
                    let req:ResolveEscrowRequest=serde_json::from_value(request)?;
                    let result=self.resolve_escrow(
                        req.escrow_id,
                        req.funder_signature
                    ).await?;
                    yield serde_json::to_value(result)?;
                }
                "engage_arbiter"=>{
                    let req:EngageArbiterRequest=serde_json::from_value(request)?;
                    let result=self.engage_arbiter(req.escrow_id).await?;
                    yield serde_json::to_value(result)?;
                }
                "submit_arbiter_decision"=>{
                    let req:SubmitArbiterDecisionRequest=serde_json::from_value(request)?;
                    let result=self.submit_arbiter_decision(
                        req.escrow_id,
                        req.outcome,
                        req.arbiter_signature
                    ).await?;
                    yield serde_json::to_value(result)?;
                }
                "subscribe_escrow_resolution"=>{
                    let req:SubscribeResolveRequest=serde_json::from_value(request)?;
                    let stream=self.subscribe_escrow_resolution(req.operation_id).await?;
                    for await state in stream.into_stream() {
                        yield serde_json::to_value(state)?;
                    }
                }
                "subscribe_claim_payout"=>{
                    let req:SubscribeClaimPayoutRequest=serde_json::from_value(request)?;
                    let stream=self.subscribe_claim_payout(req.operation_id).await?;
                    for await state in stream.into_stream(){
                        yield serde_json::to_value(state)?;
                    }
                }
                "claim_payout"=>{
                    let req:ClaimPayoutRequest=serde_json::from_value(request)?;
                    let result=self.claim_payout(req.escrow_id).await?;
                    yield serde_json::to_value(result)?;
                }
                "trigger_fallback"=>{
                    let req:FallbackRequest=serde_json::from_value(request)?;
                    let result=self.trigger_fallback(req.escrow_id).await?;
                    yield serde_json::to_value(result)?;
                }
                "get_claim_pool" => {
                    let req: GetClaimPoolRequest = serde_json::from_value(request)?;
                    yield serde_json::to_value(self.get_claim_pool(req.escrow_id).await?)?;
                }
                "sign_message"=>{
                    let req:SignClientMessageRequest=serde_json::from_value(request)?;
                    let result=self.sign_message(req.message)?;
                    yield serde_json::to_value(result)?;
                }
                _ => {
                    Err(anyhow::format_err!("Unknown method: {method}"))?;
                    unreachable!()
                },
            }
        });
        Box::pin(stream.map_err(ClientModuleError::other))
    }
}

#[derive(Deserialize)]
struct GetContractRequest {
    escrow_id: EscrowId,
}

#[derive(Deserialize)]
struct CreateContractRequest {
    recipient_key: PublicKey,
    arbiter_key: PublicKey,
    arbiter_fee: Amount,
    amount: Amount,
    timeout: Duration,
    arbiter_fee_key: Vec<PublicKey>,
    resolution_period: Duration,
    default_fallback: FallbackPolicy,
}

#[derive(Deserialize)]
struct SubscribeCreationRequest {
    operation_id: OperationId,
}

#[derive(Deserialize)]
struct ResolveEscrowRequest {
    escrow_id: EscrowId,
    funder_signature: schnorr::Signature,
}

#[derive(Deserialize)]
struct EngageArbiterRequest {
    escrow_id: EscrowId,
}

#[derive(Deserialize)]
struct FallbackRequest {
    escrow_id: EscrowId,
}

#[derive(Deserialize)]
struct SubmitArbiterDecisionRequest {
    escrow_id: EscrowId,
    outcome: Outcome,
    arbiter_signature: schnorr::Signature,
}

#[derive(Deserialize)]
struct ClaimPayoutRequest {
    escrow_id: EscrowId,
}

#[derive(Deserialize)]
struct GetClaimPoolRequest {
    escrow_id: EscrowId,
}

#[derive(Deserialize)]
struct SubscribeResolveRequest {
    operation_id: OperationId,
}

#[derive(Deserialize)]
struct SubscribeClaimPayoutRequest {
    operation_id: OperationId,
}

#[derive(Deserialize)]
struct SignClientMessageRequest {
    message: EscrowMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateContractResponse {
    pub operation_id: OperationId,
    pub escrow_id: EscrowId,
    pub contract_hash: ContractHash,
    pub timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsortiumSession {
    record: FrostDkgSessionRecord,
    session: FrostDkgSession,
}

impl EscrowClientModule {
    fn iroh_identity_key(&self) -> Keypair {
        self.secret
            .child_key(ChildId(EscrowChildKeys::IrohKey as u64))
            .to_secp_key(&Secp256k1::new())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_escrow(
        &self,
        recipient_key: PublicKey,
        arbiter_key: PublicKey,
        arbiter_fee: Amount,
        amount: Amount,
        timeout: Duration,
        arbiter_fee_key: Vec<PublicKey>,
        resolution_period: Duration,
        default_fallback: FallbackPolicy,
    ) -> Result<CreateContractResponse, anyhow::Error> {
        let funder_key = self.escrow_key.public_key();
        let timeout_deadline =
            fedimint_core::time::duration_since_epoch().as_secs() + timeout.as_secs();
        // resolution deadline will be calculated once the contract goes into disputed
        // state
        let resolution_period = resolution_period.as_secs();

        let contract_hash = compute_contract_hash(
            &funder_key,
            &recipient_key,
            &arbiter_key,
            &arbiter_fee,
            &amount,
            &timeout_deadline,
            &self.federation_id,
            &resolution_period,
            &arbiter_fee_key,
            &default_fallback,
        );

        let operation_id = OperationId::new_random();
        let escrow_id = EscrowId::build(&contract_hash)?;

        let contract = EscrowContract::new(
            escrow_id,
            funder_key,
            recipient_key,
            arbiter_key,
            arbiter_fee_key,
            amount,
            arbiter_fee,
            contract_hash,
            timeout_deadline,
            self.federation_id,
            resolution_period,
            default_fallback,
            fedimint_core::time::duration_since_epoch().as_secs(),
        )
        .await?;

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

        let result = CreateContractResponse {
            operation_id,
            escrow_id,
            contract_hash,
            timeout: timeout_deadline,
        };
        Ok(result)
    }

    pub async fn resolve_escrow(
        &self,
        escrow_id: EscrowId,
        funder_signature: schnorr::Signature,
    ) -> Result<OperationId, anyhow::Error> {
        let operation_id = OperationId::new_random();
        let contract = self
            .get_contract(escrow_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Escrow contract not found"))?;

        anyhow::ensure!(
            x_only_eq(&contract.recipient_key, &self.escrow_key.public_key()),
            "only the recipient can submit the release"
        );

        let input = ClientInput {
            amounts: Amounts::new_bitcoin(contract.amount),
            keys: vec![self.escrow_key],
            input: EscrowInput {
                escrow_id,
                resolution: Resolution::FunderRelease { funder_signature },
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
                                resolution: Resolution::FunderRelease { funder_signature },
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

    pub async fn engage_arbiter(&self, escrow_id: EscrowId) -> anyhow::Result<OperationId> {
        let operation_id = OperationId::new_random();
        let contract = self
            .get_contract(escrow_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Escrow contract not found"))?;

        let is_valid_disputant = x_only_eq(&self.escrow_key.public_key(), &contract.funder_key)
            || x_only_eq(&self.escrow_key.public_key(), &contract.recipient_key);

        anyhow::ensure!(
            is_valid_disputant,
            "Should be submitted by funder/reciepient"
        );

        let message = contract.engage_message();
        let disputant_signature = self.sign_message(message)?;

        let input = ClientInput {
            amounts: Amounts::ZERO,
            keys: vec![self.escrow_key],
            input: EscrowInput {
                escrow_id,
                resolution: Resolution::ArbiterEngaged {
                    disputant_pubkey: self.escrow_key.public_key(),
                    disputant_signature,
                },
            },
        };
        let disputant_pubkey = self.escrow_key.public_key();

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
                                amount: Amount::ZERO,
                                resolution: Resolution::ArbiterEngaged {
                                    disputant_pubkey,
                                    disputant_signature,
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
                amount: Amount::ZERO,
                action: EscrowAction::ArbiterEngaged,
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

        let now = fedimint_core::time::duration_since_epoch().as_secs();
        anyhow::ensure!(now >= contract.timeout, "arbiter cannot act before timeout");

        let input = ClientInput {
            amounts: Amounts::ZERO,
            keys: vec![self.arbiter_fee_key],
            input: EscrowInput {
                escrow_id,
                resolution: Resolution::ArbiterOutcome {
                    arbiter_signature,
                    outcome,
                    submitter_pubkey: self.arbiter_fee_key.public_key(),
                },
            },
        };

        let submitter_pubkey = self.arbiter_fee_key.public_key();

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
                                amount: Amount::ZERO,
                                resolution: Resolution::ArbiterOutcome {
                                    arbiter_signature,
                                    outcome,
                                    submitter_pubkey,
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
                amount: Amount::ZERO,
                action: match outcome {
                    Outcome::Release => EscrowAction::Released,
                    Outcome::Refund => EscrowAction::Refunded,
                    Outcome::Split { .. } => EscrowAction::Split,
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

    /// The key stored in the pool is the key that must sign the claim.
    fn keypair_for(&self, key: &PublicKey) -> Option<Keypair> {
        [self.escrow_key, self.arbiter_fee_key]
            .into_iter()
            .find(|kp| x_only_eq(&kp.public_key(), key))
    }

    pub async fn claim_payout(&self, escrow_id: EscrowId) -> anyhow::Result<OperationId> {
        let operation_id = OperationId::new_random();
        let pool = self
            .client_ctx
            .module_api()
            .get_claim_amount(GetClaimAmount { escrow_id })
            .await?
            .ok_or_else(|| anyhow!("No pool found"))?;

        let (signing_key, amount) = pool
            .claimer
            .iter()
            .find_map(|(key, amount)| {
                self.keypair_for(key)
                    .map(|signing_key| (signing_key, *amount))
            })
            .ok_or_else(|| anyhow::anyhow!("No matching signing key found"))?;

        let input = ClientInput {
            amounts: Amounts::new_bitcoin(amount),
            keys: vec![signing_key],
            input: EscrowInput {
                escrow_id,
                resolution: Resolution::ClaimPayout {
                    claimer_pubkey: signing_key.public_key(),
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
                                amount,
                                resolution: Resolution::ClaimPayout {
                                    claimer_pubkey: signing_key.public_key(),
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

        let operation_meta_gen = move |out_point_range: OutPointRange| EscrowOperationMeta {
            escrow_id,
            amount,
            action: EscrowAction::Claimed,
            txid: out_point_range.txid(),
            out_point_indices: out_point_range.into_iter().map(|op| op.out_idx).collect(),
        };

        self.client_ctx
            .finalize_and_submit_transaction(operation_id, KIND.as_str(), operation_meta_gen, tx)
            .await?;

        Ok(operation_id)
    }

    pub async fn trigger_fallback(&self, escrow_id: EscrowId) -> anyhow::Result<OperationId> {
        let operation_id = OperationId::new_random();
        let contract = self
            .get_contract(escrow_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Escrow contract not found"))?;

        let is_valid_claimer = x_only_eq(&self.escrow_key.public_key(), &contract.funder_key)
            || x_only_eq(&self.escrow_key.public_key(), &contract.recipient_key);

        anyhow::ensure!(is_valid_claimer, "Should be triggered by funder/reciepient");
        let claimer_pubkey = self.escrow_key.public_key();
        let fallback = contract.default_fallback;
        let resolution = Resolution::ResolveFallbackPolicy {
            claimer_pubkey,
            fallback,
        };

        let input = ClientInput {
            amounts: Amounts::ZERO,
            keys: vec![self.escrow_key],
            input: EscrowInput {
                escrow_id,
                resolution,
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
                                amount: Amount::ZERO,
                                resolution,
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
                amount: Amount::ZERO,
                action: match fallback {
                    FallbackPolicy::Refund => EscrowAction::Refunded,
                    FallbackPolicy::Split { .. } => EscrowAction::Split,
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

    pub fn get_frost_identity(&self) -> anyhow::Result<FrostParticipant> {
        FrostParticipant::from_pubkey(self.escrow_key.public_key())
    }

    pub async fn create_arbiter_consortium(
        &self,
        participants: Vec<FrostParticipant>,
        iroh_peers: BTreeMap<Identifier, NodeAddr>,
    ) -> Result<DkgResult, DkgError> {
        let db = self.client_ctx.module_db();
        let self_participant_id = self.get_frost_identity()?;
        let session =
            FrostDkgSessionRecord::new(self_participant_id, participants, self.federation_id, db)
                .await?;

        let transport = {
            let mut transports = self.dkg_transports.lock().await;
            match transports.get(&session.session_id) {
                Some(t) => t.clone(),
                None => {
                    let iroh_secret = SecretKey::from_bytes(
                        &self.iroh_identity_key().secret_key().secret_bytes(),
                    );
                    let t = Arc::new(
                        IrohDkgTransport::new(session.session_id, iroh_secret, iroh_peers).await?,
                    );
                    transports.insert(session.session_id, t.clone());
                    t
                }
            }
        };

        let result = session.run(db, transport).await;

        // Keep the transport only if the caller can retry the same
        // attempt. On success or a non-transient error, drop it.
        let keep = matches!(&result, Err(e) if e.is_transient());
        if !keep {
            self.dkg_transports.lock().await.remove(&session.session_id);
        }
        result
    }

    /// Give up on a consortium attempt and close its transport.
    pub async fn abort_arbiter_consortium(&self, session_id: SessionId) {
        self.dkg_transports.lock().await.remove(&session_id);
    }

    pub async fn create_arbiter_consortium_with_custom_transport<T: DkgTransport>(
        &self,
        participants: Vec<FrostParticipant>,
        transport: T,
    ) -> Result<DkgResult, DkgError> {
        let db = self.client_ctx.module_db();
        let self_participant_id = self.get_frost_identity()?;
        let session =
            FrostDkgSessionRecord::new(self_participant_id, participants, self.federation_id, db)
                .await?;

        let result = session.run(db, transport).await?;
        Ok(result)
    }

    pub async fn get_consortium_state(
        &self,
        session_id: SessionId,
    ) -> anyhow::Result<ConsortiumSession> {
        let mut dbtx = self.client_ctx.module_db().begin_transaction_nc().await;
        let record = dbtx
            .get_value(&FrostDkgSessionRecordkey(session_id))
            .await
            .ok_or_else(|| anyhow::anyhow!("no consortium record found for {session_id:?}"))?;

        let state = dbtx
            .get_value(&FrostDkgSessionKey(session_id))
            .await
            .ok_or_else(|| anyhow::anyhow!("no consortium state found for {session_id:?}"))?;

        anyhow::Ok(ConsortiumSession {
            record,
            session: state,
        })
    }

    pub async fn get_contract(
        &self,
        escrow_id: EscrowId,
    ) -> Result<Option<EscrowContract>, anyhow::Error> {
        let contract: Option<EscrowContract> = self
            .client_ctx
            .module_api()
            .get_contract(GetContractParams { escrow_id })
            .await?;

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

    pub async fn list_contracts(&self) -> anyhow::Result<Vec<EscrowContract>> {
        let mut all = BTreeMap::new();
        for pubkey in [
            self.escrow_key.public_key(),
            self.arbiter_fee_key.public_key(),
        ] {
            let found = self
                .client_ctx
                .module_api()
                .list_contracts_by_key(ListContractParams {
                    pubkey,
                    federation_id: self.federation_id,
                })
                .await?;
            for contract in found {
                all.insert(contract.escrow_id, contract);
            }
        }
        Ok(all.into_values().collect())
    }

    pub async fn get_claim_pool(&self, escrow_id: EscrowId) -> anyhow::Result<Option<ClaimPool>> {
        Ok(self
            .client_ctx
            .module_api()
            .get_claim_amount(GetClaimAmount { escrow_id })
            .await?)
    }

    pub async fn subscribe_escrow_creation(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<EscrowOutputSMState>> {
        let operation: OperationLogEntry = self.escrow_operation(operation_id).await?;
        let meta = operation.meta::<EscrowOperationMeta>();
        let txid = meta.txid;
        let client_ctx = self.client_ctx.clone();

        Ok(self.client_ctx.outcome_or_updates(
            &operation,
            operation_id,
            |state| {
                matches!(
                    state,
                    EscrowOutputSMState::Active | EscrowOutputSMState::Failed { .. }
                )
            },
            move || {
                let client_ctx = client_ctx.clone();
                stream! {
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
                }
            },
        ))
    }

    pub async fn subscribe_escrow_resolution(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<EscrowInputSMState>> {
        let operation: OperationLogEntry = self.escrow_operation(operation_id).await?;
        let meta = operation.meta::<EscrowOperationMeta>();
        let txid = meta.txid;
        let client_ctx = self.client_ctx.clone();

        Ok(self.client_ctx.outcome_or_updates(
            &operation,
            operation_id,
            |state| !matches!(state, EscrowInputSMState::Pending),
            move || {
                let client_ctx = client_ctx.clone();
                stream! {
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
                                EscrowAction::Split => yield EscrowInputSMState::Split,
                                EscrowAction::ArbiterEngaged => yield EscrowInputSMState::Disputed,
                                _ => yield EscrowInputSMState::Failed {
                                        reason: "unexpected action in resolution stream".to_string()
                                }
                            }
                        }
                        Err(e) => {
                            yield EscrowInputSMState::Failed { reason: e.to_string() };
                        }
                    }
                }
            },
        ))
    }

    pub async fn subscribe_claim_payout(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<UpdateStreamOrOutcome<EscrowInputSMState>> {
        let operation = self.escrow_operation(operation_id).await?;
        let meta = operation.meta::<EscrowOperationMeta>();
        let txid = meta.txid;
        let out_points: Vec<OutPoint> = meta
            .out_point_indices
            .into_iter()
            .map(|out_idx| OutPoint { txid, out_idx })
            .collect();
        let client_ctx = self.client_ctx.clone();

        Ok(self.client_ctx.outcome_or_updates(
            &operation,
            operation_id,
            |state| {
                matches!(
                    state,
                    EscrowInputSMState::Claimed | EscrowInputSMState::Failed { .. }
                )
            },
            move || {
                let client_ctx = client_ctx.clone();
                stream! {
                    yield EscrowInputSMState::Pending;
                    if let Err(e) = client_ctx
                        .transaction_updates(operation_id)
                        .await
                        .await_tx_accepted(txid)
                        .await
                    {
                        yield EscrowInputSMState::Failed { reason: e.to_string() };
                        return;
                    }

                    match client_ctx
                        .await_primary_module_outputs(operation_id, out_points)
                        .await
                    {
                        Ok(()) => yield EscrowInputSMState::Claimed,
                        Err(err) => yield EscrowInputSMState::Failed { reason: err.to_string() },
                    }
                }
            },
        ))
    }

    pub fn sign_message(&self, message: EscrowMessage) -> anyhow::Result<Signature> {
        let secp = Secp256k1::new();

        let msg_bytes = compute_escrow_message(&message);
        let msg = Message::from_digest(msg_bytes);

        Ok(secp.sign_schnorr(&msg, &self.escrow_key))
    }
}
