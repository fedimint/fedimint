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
use fedimint_core::runtime::{sleep, spawn};
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::secp256k1::{self, Keypair, Message, PublicKey, Secp256k1, schnorr};
use fedimint_core::util::BoxStream;
use fedimint_core::{Amount, OutPoint, apply, async_trait_maybe_send, push_db_pair_items};
use fedimint_derive_secret::{ChildId, DerivableSecret};
use fedimint_escrow_common::config::EscrowClientConfig;
use fedimint_escrow_common::endpoint_constants::{
    GetClaimAmount, GetContractParams, ListContractParams,
};
use fedimint_escrow_common::rules::check_resolution;
use fedimint_escrow_common::{
    ClaimPool, ContractHash, EscrowCommonInit, EscrowContract, EscrowId, EscrowInput,
    EscrowMessage, EscrowModuleTypes, EscrowOutput, FallbackPolicy, KIND, Outcome, Resolution,
    compute_contract_hash, compute_escrow_message, x_only_eq,
};
use futures::lock::Mutex;
use futures::{StreamExt, TryStreamExt};
use iroh::{NodeAddr, NodeId, SecretKey};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;

use crate::api::EscrowFederationApi;
use crate::client_db::{
    DbKeyPrefix, EscrowAction, EscrowOperationMeta, FrostDkgSessionKey, FrostDkgSessionPrefix,
    FrostDkgSessionRecordPrefix, FrostDkgSessionRecordkey,
};
use crate::frost::binding::{PeerBinding, verify_peers};
use crate::frost::dkg::{DkgError, DkgResult};
use crate::frost::secret::StateKey;
use crate::frost::session::{
    DkgStage, FrostDkgSession, FrostDkgSessionRecord, FrostParticipant, SessionId,
};
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

const DKG_TRANSPORT_GRACE_PERIOD: Duration = Duration::from_secs(10 * 60);

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
    DkgStateKey = 4,
}

#[derive(Clone)]
struct DkgSlot {
    transport: Arc<IrohDkgTransport>,
    running: Arc<Mutex<()>>,
}

/// Client-side implementation of the Fedimint escrow module.
///
/// Provides the APIs required to create and manage escrow contracts,
/// initiate dispute resolution, submit arbiter decisions, claim payouts,
/// and coordinate FROST based arbiter consortiums.
///
/// The escrow module does not support being the primary module and
/// does not currently support client backups.
pub struct EscrowClientModule {
    federation_id: FederationId,
    cfg: EscrowClientConfig,
    pub client_ctx: ClientContext<Self>,
    secp: Secp256k1<secp256k1::All>,
    escrow_key: Keypair,
    arbiter_fee_key: Keypair,
    secret: DerivableSecret,
    notifier: ModuleNotifier<EscrowStateMachine>,
    dkg_transports: Arc<Mutex<BTreeMap<SessionId, DkgSlot>>>,
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
        let secp = Secp256k1::new();

        let escrow_key = args
            .module_root_secret()
            .child_key(ChildId(EscrowChildKeys::Escrow as u64))
            .to_secp_key(&secp);

        let arbiter_fee_key = args
            .module_root_secret()
            .child_key(ChildId(EscrowChildKeys::ArbiterFee as u64))
            .to_secp_key(&secp);

        Ok(EscrowClientModule {
            federation_id: args.federation_id,
            cfg: args.cfg.clone(),
            client_ctx: args.context.clone(),
            secp,
            escrow_key,
            arbiter_fee_key,
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
                    let pubkey=self.escrow_pubkey().to_string();
                    yield serde_json::to_value(pubkey)?;
                }
                "get_arbiter_fee_pubkey"=>{
                    let pubkey=self.arbiter_fee_pubkey().to_string();
                    yield serde_json::to_value(pubkey)?;
                }
                "get_contract" => {
                    let req:GetContractRequest= serde_json::from_value(request)?;
                    let result= self.get_contract(req.escrow_id).await?;
                    yield serde_json::to_value(result)?;
                }
                "list_escrows"=>{
                    let req:ListContractsRequest= serde_json::from_value(request)?;
                    let result=self.list_contracts(req.pubkey,req.limit,req.last_seen).await?;
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

#[derive(Default, Deserialize)]
#[serde(default)]
struct ListContractsRequest {
    pubkey: Option<PublicKey>,
    limit: Option<u32>,
    last_seen: Option<EscrowId>,
}

/// Response returned after submitting an escrow creation transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateContractResponse {
    pub operation_id: OperationId,
    pub escrow_id: EscrowId,
    pub contract_hash: ContractHash,
    pub timeout: u64,
}

/// A persisted FROST arbiter consortium session.
///
/// Contains the consortium session record and the current DKG
/// protocol state.
///
/// This type is returned by
/// [`EscrowClientModule::get_consortium_state`] and can be used
/// to inspect the progress and persisted information of a
/// consortium attempt.
#[derive(Debug, Clone, Serialize)]
pub struct ConsortiumSession {
    pub record: FrostDkgSessionRecord,
    pub stage: DkgStage,
}

/// Public result of a finished consortium DKG. The key share stays sealed in
/// the client db, use `get_consortium_signing_keys` when you need to sign.
#[derive(Debug, Clone)]
pub struct ConsortiumInfo {
    pub session_id: SessionId,
    pub consortium_pubkey: PublicKey,
}

impl ConsortiumInfo {
    fn from_result(session_id: SessionId, result: &DkgResult) -> Result<Self, DkgError> {
        Ok(Self {
            session_id,
            consortium_pubkey: FrostDkgSessionRecord::consortium_pubkey(&result.pubkey_package)?,
        })
    }
}

impl EscrowClientModule {
    /// Get the Iroh identity key
    fn iroh_identity_key(&self) -> Keypair {
        self.secret
            .child_key(ChildId(EscrowChildKeys::IrohKey as u64))
            .to_secp_key(&self.secp)
    }

    /// key that seals the dkg state in the client db, derived from the module
    /// root secret
    fn dkg_state_key(&self) -> StateKey {
        let bytes = self
            .secret
            .child_key(ChildId(EscrowChildKeys::DkgStateKey as u64))
            .to_secp_key(&self.secp)
            .secret_key()
            .secret_bytes();
        StateKey::new(&bytes)
    }

    /// Returns the public key identifying this client's escrow identity.
    ///
    /// This key is derived from the client's module root secret and is
    /// used as the parties identity when creating escrow contracts and
    /// authorizing operations
    pub fn escrow_pubkey(&self) -> PublicKey {
        self.escrow_key.public_key()
    }

    /// Returns the public key used by this client to receive arbiter fees.
    ///
    /// This key is derived independently from the client's module root
    /// secret and should be used as arbiter fee recipient when
    /// creating an escrow contract.
    pub fn arbiter_fee_pubkey(&self) -> PublicKey {
        self.arbiter_fee_key.public_key()
    }

    fn iroh_secret_key(&self) -> SecretKey {
        SecretKey::from_bytes(&self.iroh_identity_key().secret_key().secret_bytes())
    }

    /// the node id other arbiters will get for this client
    pub fn local_node_id(&self) -> NodeId {
        self.iroh_secret_key().public()
    }

    /// Build [`PeerBinding`] for this arbiter client and should be given to
    /// other participants
    pub fn sign_peer_binding(
        &self,
        session_id: SessionId,
        node_addr: NodeAddr,
    ) -> anyhow::Result<PeerBinding> {
        anyhow::ensure!(
            node_addr.node_id == self.local_node_id(),
            "node_addr is not the node of this client"
        );
        PeerBinding::sign(&session_id, &self.escrow_key, node_addr)
    }

    /// Creates a new escrow contract and submits a transaction locking
    /// the client's e-cash in the federation
    ///
    /// Once the transaction is submitted, the returned operation ID can
    /// be used with [`Self::subscribe_escrow_creation`] to monitor the
    /// creation process.
    ///
    /// Returns [`CreateContractResponse`] containing the operation ID,
    /// escrow ID, contract hash, and calculated timeout deadline.
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

        let now = self.federation_unix_time().await?;
        let timeout_deadline = now
            .checked_add(timeout.as_secs())
            .ok_or_else(|| anyhow!("escrow timeout exceeds"))?;

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
            now,
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

    /// Initiates the funder authorized release of an escrow contract.
    ///
    /// This method allows the recipient to submit a release transaction
    /// using a Schnorr signature provided by the funder. On successful
    /// resolution, the settlement pays the recipient in
    /// the same transaction rather than creating a claim pool.
    ///
    /// Use [`Self::subscribe_escrow_resolution`] to monitor the operation.
    ///
    /// Returns an operation ID that can be used to track the resolution.
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

        let now = self.federation_unix_time().await?;

        let resolution = Resolution::FunderRelease { funder_signature };
        check_resolution(&contract, &resolution, now)?;

        let input = ClientInput {
            amounts: Amounts::new_bitcoin(contract.amount),
            keys: vec![self.escrow_key],
            input: EscrowInput {
                escrow_id,
                resolution: resolution.clone(),
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
                                resolution: resolution.clone(),
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

    /// Initiates the arbiter dispute resolution process for an escrow contract.
    ///
    /// Arbiter engagement is only permitted after the contract timeout
    /// has been reached and the caller is a recognized contract participant. No
    /// funds will be moved with this method.
    ///
    /// Use [`Self::subscribe_escrow_resolution`] to monitor the operation.
    ///
    /// Returns an operation ID for tracking the arbiter engagement.
    pub async fn engage_arbiter(&self, escrow_id: EscrowId) -> anyhow::Result<OperationId> {
        let operation_id = OperationId::new_random();
        let contract = self
            .get_contract(escrow_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Escrow contract not found"))?;

        let now = self.federation_unix_time().await?;

        let message = contract.engage_message();
        let disputant_signature = self.sign_message(message)?;

        let disputant_pubkey = self.escrow_key.public_key();

        let resolution = Resolution::ArbiterEngaged {
            disputant_pubkey,
            disputant_signature,
        };
        check_resolution(&contract, &resolution, now)?;

        let input = ClientInput {
            amounts: Amounts::ZERO,
            keys: vec![self.escrow_key],
            input: EscrowInput {
                escrow_id,
                resolution: resolution.clone(),
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
                                resolution: resolution.clone(),
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

    /// Submits an arbiter decision for a disputed escrow contract.
    ///
    /// The arbiter provides a Schnorr signature authorizing the selected
    /// outcome. Could be submitted by either party.
    ///
    /// Supported outcomes are:
    ///
    /// - [`Outcome::Release`] - Allocates the payout to the recipient.
    /// - [`Outcome::Refund`] - Allocates the payout to the funder.
    /// - [`Outcome::Split`] - Divides the payout between the funder and
    ///   recipient according to the configured split ratio.
    ///
    /// Accepted arbiter outcomes create a claim pool. Beneficiaries must
    /// subsequently claim their allocated amounts using
    /// [`Self::claim_payout`].
    ///
    /// Use [`Self::subscribe_escrow_resolution`] to monitor the operation.
    ///
    /// Returns an operation ID for tracking the submitted decision.
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

        let now = self.federation_unix_time().await?;

        let signing_key = [self.escrow_key, self.arbiter_fee_key]
            .into_iter()
            .find(|key| contract.contains_key(&key.public_key()))
            .ok_or_else(|| anyhow!("No matching key found in contract"))?;

        let submitter_pubkey = signing_key.public_key();

        let resolution = Resolution::ArbiterOutcome {
            arbiter_signature,
            outcome,
            submitter_pubkey,
        };
        check_resolution(&contract, &resolution, now)?;

        let input = ClientInput {
            amounts: Amounts::ZERO,
            keys: vec![signing_key],
            input: EscrowInput {
                escrow_id,
                resolution: resolution.clone(),
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
                                resolution: resolution.clone(),
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

    /// Claims the payout assigned to a locally controlled key in an
    /// escrow contract's claim pool.
    /// This operation is used after arbiter or fallback resolution has
    /// created a claim pool. It does not initiate contract resolution.
    ///
    /// Use [`Self::subscribe_claim_payout`] to monitor the claim operation,
    /// including confirmation that the resulting primary module outputs
    /// have been received.
    ///
    /// Returns an operation ID for tracking the payout claim.
    pub async fn claim_payout(&self, escrow_id: EscrowId) -> anyhow::Result<OperationId> {
        let operation_id = OperationId::new_random();
        let pool = self
            .client_ctx
            .module_api()
            .get_claim_amount(GetClaimAmount { escrow_id })
            .await?
            .ok_or_else(|| anyhow!("No claim pool exists for escrow {escrow_id:?}"))?;

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

    /// Triggers the configured fallback policy for a disputed escrow contract.
    ///
    /// This operation is available to a contract participant after the
    /// arbiter's resolution deadline has passed.
    /// Fallback settlement does not include an arbiter fee.
    ///
    /// Use [`Self::subscribe_escrow_resolution`] to monitor the operation.
    /// If a claim pool is created, use [`Self::claim_payout`] to claim
    /// locally controlled allocations.
    ///
    /// Returns an operation ID for tracking the fallback operation.
    pub async fn trigger_fallback(&self, escrow_id: EscrowId) -> anyhow::Result<OperationId> {
        let operation_id = OperationId::new_random();

        let contract = self
            .get_contract(escrow_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Escrow contract not found"))?;

        let now = self.federation_unix_time().await?;

        let claimer_pubkey = self.escrow_key.public_key();
        let fallback = contract.effective_fallback();

        let resolution = Resolution::ResolveFallbackPolicy {
            claimer_pubkey,
            fallback: fallback.clone(),
        };
        check_resolution(&contract, &resolution, now)?;

        let action = if contract.can_swap_arbiter() {
            EscrowAction::ArbiterSwapped
        } else {
            match Outcome::from(&fallback) {
                Outcome::Release => EscrowAction::Released,
                Outcome::Refund => EscrowAction::Refunded,
                Outcome::Split { .. } => EscrowAction::Split,
            }
        };

        let input = ClientInput {
            amounts: Amounts::ZERO,
            keys: vec![self.escrow_key],
            input: EscrowInput {
                escrow_id,
                resolution: resolution.clone(),
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
                                resolution: resolution.clone(),
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
                action: action.clone(),
                txid,
                out_point_indices,
            }
        };

        self.client_ctx
            .finalize_and_submit_transaction(operation_id, KIND.as_str(), operation_meta_gen, tx)
            .await?;

        Ok(operation_id)
    }

    /// Returns the FROST participant identity derived from the client's
    /// escrow public key.
    ///
    /// The returned identity is used to identify this client as a
    /// participant in distributed key generation (DKG) sessions.
    ///
    /// Returns the client's [`FrostParticipant`] identity.
    pub fn get_frost_identity(&self) -> anyhow::Result<FrostParticipant> {
        FrostParticipant::from_pubkey(self.escrow_key.public_key())
    }

    /// Creates or resumes a FROST arbiter consortium using Iroh transport.
    ///
    /// This method initializes a DKG session for the supplied participants
    /// and coordinates the distributed key generation protocol over the
    /// provided Iroh peer addresses.
    /// The caller needs to be in the participants list.
    ///
    /// Transient failures retain the transport so that the same attempt
    /// can be retried. Non-transient failures and successful completion
    /// remove the cached transport.
    ///
    /// Only one DKG for a given session can run at a time.
    ///
    /// Returns the [`ConsortiumInfo`] containing the result of the distributed
    /// key generation protocol.
    pub async fn run_arbiter_consortium(
        &self,
        participants: Vec<FrostParticipant>,
        peer_bindings: Vec<PeerBinding>,
    ) -> Result<ConsortiumInfo, DkgError> {
        let db = self.client_ctx.module_db();
        let state_key = self.dkg_state_key();
        let self_participant_id = self.get_frost_identity()?;
        let session = FrostDkgSessionRecord::new(
            self_participant_id.clone(),
            participants,
            self.federation_id,
            db,
        )
        .await?;

        let slot = {
            let mut slots = self.dkg_transports.lock().await;
            match slots.get(&session.session_id) {
                Some(slot) => slot.clone(),
                None => {
                    let iroh_secret = self.iroh_secret_key();
                    let peers = verify_peers(
                        &session.session_id,
                        &self_participant_id,
                        iroh_secret.public(),
                        &session.participants,
                        peer_bindings,
                    )?;
                    let transport =
                        IrohDkgTransport::new(session.session_id, iroh_secret, peers).await?;
                    let slot = DkgSlot {
                        transport: Arc::new(transport),
                        running: Arc::new(Mutex::new(())),
                    };
                    slots.insert(session.session_id, slot.clone());
                    slot
                }
            }
        };

        let Some(_running) = slot.running.try_lock() else {
            return Err(DkgError::Other(anyhow!(
                "a DKG for this consortium is already running"
            )));
        };

        let result = session.run(db, slot.transport.clone(), &state_key).await;

        match &result {
            // done: keep answering late peers for a while, then let go
            Ok(_) => {
                let slots = self.dkg_transports.clone();
                let session_id = session.session_id;
                spawn("dkg-serve-late-peers", async move {
                    sleep(DKG_TRANSPORT_GRACE_PERIOD).await;
                    slots.lock().await.remove(&session_id);
                });
            }
            // for transient error keep it so the caller can retry the same attempt
            Err(e) if e.is_transient() => {}
            // the state was wiped, start the next attempt with a fresh transport
            Err(_) => {
                self.dkg_transports.lock().await.remove(&session.session_id);
            }
        }

        let done = result?;
        ConsortiumInfo::from_result(session.session_id, &done)
    }

    /// Aborts a cached arbiter consortium attempt by removing its
    /// in-memory Iroh transport.
    ///
    /// This method prevents the client from reusing the cached transport
    /// associated with the specified session ID. This does not cancel an
    /// already-running DKG execution. The running execution retains its own
    /// reference to the transport.
    ///
    /// It does not reset or delete the persisted DKG session record.
    /// Use [`Self::reset_arbiter_consortium`] when the intention is to
    /// discard the unfinished DKG attempt and start again.
    pub async fn abort_arbiter_consortium(&self, session_id: SessionId) {
        self.dkg_transports.lock().await.remove(&session_id);
    }

    /// Resets an unfinished FROST consortium DKG attempt. Removes the persisted
    /// DKG session state and cached transport associated with the specified
    /// session ID,
    /// The reset is rejected if a DKG execution for the session
    /// is currently running.
    ///
    /// Returns `Ok(())` if the session was successfully reset.
    pub async fn reset_arbiter_consortium(&self, session_id: SessionId) -> anyhow::Result<()> {
        let db = self.client_ctx.module_db();
        let record = {
            let mut dbtx = db.begin_transaction_nc().await;
            dbtx.get_value(&FrostDkgSessionRecordkey(session_id))
                .await
                .ok_or_else(|| anyhow!("no consortium record found for {session_id:?}"))?
        };

        let mut slots = self.dkg_transports.lock().await;
        if let Some(slot) = slots.get(&session_id) {
            anyhow::ensure!(
                slot.running.try_lock().is_some(),
                "cannot reset while the DKG is running"
            );
        }
        record.reset(db).await?;
        slots.remove(&session_id);
        Ok(())
    }

    /// Creates and executes a FROST arbiter consortium using a custom
    /// DKG transport implementation.
    ///
    /// This method allows integrators to provide their own implementation
    /// of [`DkgTransport`] instead of using the built-in Iroh transport.
    ///
    /// Returns the [`DkgResult`] produced by the DKG protocol.
    pub async fn create_arbiter_consortium_with_custom_transport<T: DkgTransport>(
        &self,
        participants: Vec<FrostParticipant>,
        transport: T,
    ) -> Result<DkgResult, DkgError> {
        let db = self.client_ctx.module_db();
        let state_key = self.dkg_state_key();
        let self_participant_id = self.get_frost_identity()?;
        let session =
            FrostDkgSessionRecord::new(self_participant_id, participants, self.federation_id, db)
                .await?;

        let result = session.run(db, transport, &state_key).await?;
        Ok(result)
    }

    /// Retrieves the persisted state of a FROST arbiter consortium session.
    ///
    /// Returns [`ConsortiumSession`] containing the session record and DKG
    /// stage
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
            stage: state.stage(),
        })
    }

    /// Retrieves an escrow contract from the federation.
    ///
    /// Returns `Some(EscrowContract)` if the contract exists, or `None`
    /// if no matching contract is found.
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

    /// Lists escrow contracts that contain `pubkey` (the escrow key by default,
    /// pass the arbiter fee key to list its contracts).
    pub async fn list_contracts(
        &self,
        pubkey: Option<PublicKey>,
        limit: Option<u32>,
        last_seen: Option<EscrowId>,
    ) -> anyhow::Result<Vec<EscrowContract>> {
        Ok(self
            .client_ctx
            .module_api()
            .list_contracts_by_key(ListContractParams {
                pubkey: pubkey.unwrap_or_else(|| self.escrow_pubkey()),
                federation_id: self.federation_id,
                limit,
                last_seen,
            })
            .await?)
    }

    async fn federation_unix_time(&self) -> anyhow::Result<u64> {
        Ok(self.client_ctx.module_api().consensus_unix_time().await?)
    }

    /// Retrieves the claim pool associated with an escrow contract.
    ///
    /// The claim pool contains the payout allocations created when an
    /// arbiter decision or fallback policy settles an escrow contract.
    ///
    /// Each allocation associates a public key with the amount that
    /// the corresponding key is entitled to claim.
    pub async fn get_claim_pool(&self, escrow_id: EscrowId) -> anyhow::Result<Option<ClaimPool>> {
        Ok(self
            .client_ctx
            .module_api()
            .get_claim_amount(GetClaimAmount { escrow_id })
            .await?)
    }

    /// Subscribes to updates for an escrow creation operation.
    ///
    /// Returns a stream that reports the progress of the escrow output
    /// state machine.
    ///
    /// The stream initially reports `Creating` and subsequently reports:
    ///
    /// - `Active` when the creation transaction is accepted by the federation.
    /// - `Failed` when the transaction is rejected or cannot be accepted.
    ///
    /// # Returns
    ///
    /// Returns an [`UpdateStreamOrOutcome`] containing escrow creation
    /// state updates or the previously recorded outcome.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation does not exist, belongs to
    /// another module, or its metadata cannot be retrieved.
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

    /// Subscribes to updates for an escrow resolution operation.
    ///
    /// Tracks operations that modify the escrow contract state, including
    /// funder release, arbiter engagement, arbiter decisions, and fallback
    /// transitions.
    ///
    /// The stream initially reports `Pending` and then reports the
    /// corresponding resolution result:
    ///
    /// - `Released` when the escrow is released.
    /// - `Refunded` when the escrow is refunded.
    /// - `Split` when the escrow is split between the parties.
    /// - `Disputed` when an arbiter is engaged or replaced.
    /// - `Failed` when the transaction cannot be accepted or an unexpected
    ///   operation action is encountered.
    ///
    /// # Returns
    ///
    /// Returns an [`UpdateStreamOrOutcome`] containing resolution state
    /// updates or the previously recorded outcome.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation does not exist, belongs to
    /// another module, or its metadata cannot be retrieved.
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
                                EscrowAction::ArbiterEngaged | EscrowAction::ArbiterSwapped => yield EscrowInputSMState::Disputed,
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

    /// Subscribes to updates for an escrow payout claim operation.
    ///
    /// Tracks both transaction acceptance and the retrieval of the
    /// resulting primary module outputs.
    ///
    /// The stream initially reports `Pending` and subsequently reports:
    ///
    /// - `Claimed` when the transaction is accepted and the resulting primary
    ///   module outputs have been received.
    /// - `Failed` if transaction acceptance or output retrieval fails.
    ///
    /// # Returns
    ///
    /// Returns an [`UpdateStreamOrOutcome`] containing payout claim
    /// state updates or the previously recorded outcome.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation does not exist, belongs to
    /// another module, or its metadata cannot be retrieved.
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

    /// Signs an escrow protocol message using the client's escrow identity.
    ///
    /// This method can be used by integrators to generate signatures
    /// required by escrow protocol operations, such as arbiter engagement
    pub fn sign_message(&self, message: EscrowMessage) -> anyhow::Result<Signature> {
        let msg_bytes = compute_escrow_message(&message);
        let msg = Message::from_digest(msg_bytes);

        Ok(self.secp.sign_schnorr(&msg, &self.escrow_key))
    }
}
