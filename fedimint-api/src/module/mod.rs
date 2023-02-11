pub mod audit;
pub mod interconnect;
pub mod registry;

use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;

use async_trait::async_trait;
use futures::future::BoxFuture;
use secp256k1_zkp::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::instrument;

use crate::cancellable::Cancellable;
use crate::config::{ConfigGenParams, DkgPeerMsg, ServerModuleConfig};
use crate::core::{
    Decoder, DynDecoder, Input, ModuleConsensusItem, ModuleInstanceId, ModuleKind, Output,
    OutputOutcome,
};
use crate::db::{Database, DatabaseTransaction};
use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::module::audit::Audit;
use crate::module::interconnect::ModuleInterconect;
use crate::net::peers::MuxPeerConnections;
use crate::server::{DynServerModule, VerificationCache};
use crate::task::TaskGroup;
use crate::{dyn_newtype_define, Amount, OutPoint, PeerId};

pub struct InputMeta {
    pub amount: TransactionItemAmount,
    pub puk_keys: Vec<XOnlyPublicKey>,
}

/// Information about the amount represented by an input or output.
///
/// * For **inputs** the amount is funding the transaction while the fee is consuming funding
/// * For **outputs** the amount and the fee consume funding
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct TransactionItemAmount {
    pub amount: Amount,
    pub fee: Amount,
}

impl TransactionItemAmount {
    pub const ZERO: TransactionItemAmount = TransactionItemAmount {
        amount: Amount::ZERO,
        fee: Amount::ZERO,
    };
}

#[derive(Debug)]
pub struct ApiError {
    pub code: i32,
    pub message: String,
}

impl ApiError {
    pub fn new(code: i32, message: String) -> Self {
        Self { code, message }
    }

    pub fn not_found(message: String) -> Self {
        Self::new(404, message)
    }

    pub fn bad_request(message: String) -> Self {
        Self::new(400, message)
    }
}

#[async_trait]
pub trait TypedApiEndpoint {
    type State: Sync;

    /// example: /transaction
    const PATH: &'static str;

    type Param: serde::de::DeserializeOwned + Send;
    type Response: serde::Serialize;

    async fn handle<'a, 'b>(
        state: &'a Self::State,
        dbtx: &'a mut fedimint_api::db::DatabaseTransaction<'b>,
        params: Self::Param,
    ) -> Result<Self::Response, ApiError>;
}

/// # Example
///
/// ```rust
/// # use fedimint_api::module::{api_endpoint, ApiEndpoint};
/// struct State;
///
/// let _: ApiEndpoint<State> = api_endpoint! {
///     "/foobar",
///     async |state: &State, _dbtx, params: ()| -> i32 {
///         Ok(0)
///     }
/// };
/// ```
#[macro_export]
macro_rules! __api_endpoint {
    (
        $path:expr,
        async |$state:ident: &$state_ty:ty, $dbtx:ident, $param:ident: $param_ty:ty| -> $resp_ty:ty $body:block
    ) => {{
        struct Endpoint;

        #[async_trait::async_trait]
        impl $crate::module::TypedApiEndpoint for Endpoint {
            const PATH: &'static str = $path;
            type State = $state_ty;
            type Param = $param_ty;
            type Response = $resp_ty;

            async fn handle<'a, 'b>(
                $state: &'a Self::State,
                $dbtx: &'a mut fedimint_api::db::DatabaseTransaction<'b>,
                $param: Self::Param,
            ) -> ::std::result::Result<Self::Response, $crate::module::ApiError> {
                $body
            }
        }

        $crate::module::ApiEndpoint::from_typed::<Endpoint>()
    }};
}

pub use __api_endpoint as api_endpoint;
use fedimint_api::config::ModuleConfigResponse;

use self::registry::ModuleDecoderRegistry;

type HandlerFnReturn<'a> = BoxFuture<'a, Result<serde_json::Value, ApiError>>;
type HandlerFn<M> = Box<
    dyn for<'a> Fn(
            &'a M,
            fedimint_api::db::DatabaseTransaction<'a>,
            serde_json::Value,
            Option<ModuleInstanceId>,
        ) -> HandlerFnReturn<'a>
        + Send
        + Sync,
>;

/// Definition of an API endpoint defined by a module `M`.
pub struct ApiEndpoint<M> {
    /// Path under which the API endpoint can be reached. It should start with a `/`
    /// e.g. `/transaction`. E.g. this API endpoint would be reachable under `/module/module_instance_id/transaction`
    /// depending on the module name returned by `[FedertionModule::api_base_name]`.
    pub path: &'static str,
    /// Handler for the API call that takes the following arguments:
    ///   * Reference to the module which defined it
    ///   * Request parameters parsed into JSON `[Value](serde_json::Value)`
    pub handler: HandlerFn<M>,
}

// <()> is used to avoid specify state.
impl ApiEndpoint<()> {
    pub fn from_typed<E: TypedApiEndpoint>() -> ApiEndpoint<E::State>
    where
        <E as TypedApiEndpoint>::Response: std::marker::Send,
        E::Param: Debug,
        E::Response: Debug,
    {
        #[instrument(
            target = "fedimint_server::request",
            level = "trace",
            skip_all,
            fields(method = E::PATH),
            ret,
        )]
        async fn handle_request<'a, 'b, E>(
            state: &'a E::State,
            dbtx: &mut fedimint_api::db::DatabaseTransaction<'b>,
            param: E::Param,
        ) -> Result<E::Response, ApiError>
        where
            E: TypedApiEndpoint,
            E::Param: Debug,
            E::Response: Debug,
        {
            tracing::trace!(target: "fedimint_server::request", ?param, "recieved request");
            let result = E::handle(state, dbtx, param).await;
            if let Err(error) = &result {
                tracing::trace!(target: "fedimint_server::request", ?error, "error");
            }
            result
        }

        ApiEndpoint {
            path: E::PATH,
            handler: Box::new(|m, mut dbtx, param, module_instance_id| {
                Box::pin(async move {
                    let params = serde_json::from_value(param)
                        .map_err(|e| ApiError::bad_request(e.to_string()))?;

                    let ret = match module_instance_id {
                        Some(module_instance_id) => {
                            let mut module_dbtx = dbtx.with_module_prefix(module_instance_id);
                            handle_request::<E>(m, &mut module_dbtx, params).await?
                        }
                        None => handle_request::<E>(m, &mut dbtx, params).await?,
                    };

                    dbtx.commit_tx()
                        .await
                        .map_err(|_err| fedimint_api::module::ApiError {
                            code: 500,
                            message: "Internal Server Error".to_string(),
                        })?;
                    Ok(serde_json::to_value(ret).expect("encoding error"))
                })
            }),
        }
    }
}

#[derive(Error, Debug)]
pub enum ModuleError {
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Extension trait with a function to map `Result`s used by modules to `ModuleError`
///
/// Currently each module defined it's own `enum XyzError { ... }` and is not using
/// `anyhow::Error`. For `?` to work seamlessly two conversion would have to be made:
/// `enum-Error -> anyhow::Error -> enum-Error`, while `Into`/`From` can only do one.
///
/// To avoid the boilerplate, this trait defines an easy conversion method.
pub trait IntoModuleError {
    type Target;
    fn into_module_error_other(self) -> Self::Target;
}

impl<O, E> IntoModuleError for Result<O, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    type Target = Result<O, ModuleError>;

    fn into_module_error_other(self) -> Self::Target {
        self.map_err(|e| ModuleError::Other(e.into()))
    }
}

/// Interface for Module Generation
///
/// This trait contains the methods responsible for the module's
/// - initialization
/// - config generation
/// - config validation
///
/// Once the module configuration is ready, the module can be instantiated via `[Self::init]`.
#[async_trait]
pub trait IModuleGen: Debug {
    fn decoder(&self) -> DynDecoder;

    fn module_kind(&self) -> ModuleKind;

    /// Initialize the [`DynServerModule`] instance from its config
    async fn init(
        &self,
        cfg: ServerModuleConfig,
        db: Database,
        env: &BTreeMap<OsString, OsString>,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<DynServerModule>;

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig>;

    async fn distributed_gen(
        &self,
        connections: &MuxPeerConnections<ModuleInstanceId, DkgPeerMsg>,
        our_id: &PeerId,
        module_id: ModuleInstanceId,
        peers: &[PeerId],
        params: &ConfigGenParams,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<Cancellable<ServerModuleConfig>>;

    fn to_config_response(&self, config: serde_json::Value)
        -> anyhow::Result<ModuleConfigResponse>;

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()>;
}

dyn_newtype_define!(
    #[derive(Clone)]
    pub DynModuleGen(Arc<IModuleGen>)
);

/// Module Generation trait with associated types
///
/// Needs to be implemented by module generation type
///
/// For examples, take a look at one of the `MintConfigGenerator`, `WalletConfigGenerator`, or
/// `LightningConfigGenerator` structs.
#[async_trait]
pub trait ModuleGen: Debug + Sized {
    const KIND: ModuleKind;

    type Decoder: Decoder;

    fn decoder(&self) -> Self::Decoder;

    /// Initialize the [`DynServerModule`] instance from its config
    async fn init(
        &self,
        cfg: ServerModuleConfig,
        db: Database,
        env: &BTreeMap<OsString, OsString>,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<DynServerModule>;

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig>;

    async fn distributed_gen(
        &self,
        connections: &MuxPeerConnections<ModuleInstanceId, DkgPeerMsg>,
        our_id: &PeerId,
        module_id: ModuleInstanceId,
        peers: &[PeerId],
        params: &ConfigGenParams,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<Cancellable<ServerModuleConfig>>;

    fn to_config_response(&self, config: serde_json::Value)
        -> anyhow::Result<ModuleConfigResponse>;

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()>;
}

#[async_trait]
impl<T> IModuleGen for T
where
    T: ModuleGen + 'static + Sync,
{
    fn decoder(&self) -> DynDecoder {
        DynDecoder::from_typed(ModuleGen::decoder(self))
    }

    fn module_kind(&self) -> ModuleKind {
        <Self as ModuleGen>::KIND
    }

    async fn init(
        &self,
        cfg: ServerModuleConfig,
        db: Database,
        env: &BTreeMap<OsString, OsString>,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<DynServerModule> {
        <Self as ModuleGen>::init(self, cfg, db, env, task_group).await
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        <Self as ModuleGen>::trusted_dealer_gen(self, peers, params)
    }

    async fn distributed_gen(
        &self,
        connections: &MuxPeerConnections<ModuleInstanceId, DkgPeerMsg>,
        our_id: &PeerId,
        module_id: ModuleInstanceId,
        peers: &[PeerId],
        params: &ConfigGenParams,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<Cancellable<ServerModuleConfig>> {
        <Self as ModuleGen>::distributed_gen(
            self,
            connections,
            our_id,
            module_id,
            peers,
            params,
            task_group,
        )
        .await
    }

    fn to_config_response(
        &self,
        config: serde_json::Value,
    ) -> anyhow::Result<ModuleConfigResponse> {
        <Self as ModuleGen>::to_config_response(self, config)
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        <Self as ModuleGen>::validate_config(self, identity, config)
    }
}

#[async_trait]
pub trait ServerModule: Debug + Sized {
    const KIND: ModuleKind;

    type Decoder: Decoder;
    type Input: Input;
    type Output: Output;
    type OutputOutcome: OutputOutcome;
    type ConsensusItem: ModuleConsensusItem;
    type VerificationCache: VerificationCache;

    fn module_kind() -> ModuleKind {
        // Note: All modules should define kinds as &'static str, so this doesn't allocate
        Self::KIND
    }

    fn decoder(&self) -> Self::Decoder;

    /// Blocks until a new `consensus_proposal` is available.
    async fn await_consensus_proposal<'a>(&'a self, dbtx: &mut DatabaseTransaction<'_>);

    /// This module's contribution to the next consensus proposal
    async fn consensus_proposal<'a>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<Self::ConsensusItem>;

    /// This function is called once before transaction processing starts. All module consensus
    /// items of this round are supplied as `consensus_items`. The batch will be committed to the
    /// database after all other modules ran `begin_consensus_epoch`, so the results are available
    /// when processing transactions.
    async fn begin_consensus_epoch<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        consensus_items: Vec<(PeerId, Self::ConsensusItem)>,
    );

    /// Some modules may have slow to verify inputs that would block transaction processing. If the
    /// slow part of verification can be modeled as a pure function not involving any system state
    /// we can build a lookup table in a hyper-parallelized manner. This function is meant for
    /// constructing such lookup tables.
    fn build_verification_cache<'a>(
        &'a self,
        inputs: impl Iterator<Item = &'a Self::Input> + Send,
    ) -> Self::VerificationCache;

    /// Validate a transaction input before submitting it to the unconfirmed transaction pool. This
    /// function has no side effects and may be called at any time. False positives due to outdated
    /// database state are ok since they get filtered out after consensus has been reached on them
    /// and merely generate a warning.
    async fn validate_input<'a, 'b>(
        &self,
        interconnect: &dyn ModuleInterconect,
        dbtx: &mut DatabaseTransaction<'b>,
        verification_cache: &Self::VerificationCache,
        input: &'a Self::Input,
    ) -> Result<InputMeta, ModuleError>;

    /// Try to spend a transaction input. On success all necessary updates will be part of the
    /// database `batch`. On failure (e.g. double spend) the batch is reset and the operation will
    /// take no effect.
    ///
    /// This function may only be called after `begin_consensus_epoch` and before
    /// `end_consensus_epoch`. Data is only written to the database once all transaction have been
    /// processed.
    async fn apply_input<'a, 'b, 'c>(
        &'a self,
        interconnect: &'a dyn ModuleInterconect,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b Self::Input,
        verification_cache: &Self::VerificationCache,
    ) -> Result<InputMeta, ModuleError>;

    /// Validate a transaction output before submitting it to the unconfirmed transaction pool. This
    /// function has no side effects and may be called at any time. False positives due to outdated
    /// database state are ok since they get filtered out after consensus has been reached on them
    /// and merely generate a warning.
    async fn validate_output(
        &self,
        dbtx: &mut DatabaseTransaction,
        output: &Self::Output,
    ) -> Result<TransactionItemAmount, ModuleError>;

    /// Try to create an output (e.g. issue notes, peg-out BTC, …). On success all necessary updates
    /// to the database will be part of the `batch`. On failure (e.g. double spend) the batch is
    /// reset and the operation will take no effect.
    ///
    /// The supplied `out_point` identifies the operation (e.g. a peg-out or note issuance) and can
    /// be used to retrieve its outcome later using `output_status`.
    ///
    /// This function may only be called after `begin_consensus_epoch` and before
    /// `end_consensus_epoch`. Data is only written to the database once all transactions have been
    /// processed.
    async fn apply_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a Self::Output,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmount, ModuleError>;

    /// This function is called once all transactions have been processed and changes were written
    /// to the database. This allows running finalization code before the next epoch.
    ///
    /// Passes in the `consensus_peers` that contributed to this epoch and returns a list of peers
    /// to drop if any are misbehaving.
    async fn end_consensus_epoch<'a, 'b>(
        &'a self,
        consensus_peers: &HashSet<PeerId>,
        dbtx: &mut DatabaseTransaction<'b>,
    ) -> Vec<PeerId>;

    /// Retrieve the current status of the output. Depending on the module this might contain data
    /// needed by the client to access funds or give an estimate of when funds will be available.
    /// Returns `None` if the output is unknown, **NOT** if it is just not ready yet.
    async fn output_status(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        out_point: OutPoint,
    ) -> Option<Self::OutputOutcome>;

    /// Queries the database and returns all assets and liabilities of the module.
    ///
    /// Summing over all modules, if liabilities > assets then an error has occurred in the database
    /// and consensus should halt.
    async fn audit(&self, dbtx: &mut DatabaseTransaction<'_>, audit: &mut Audit);

    /// Returns a list of custom API endpoints defined by the module. These are made available both
    /// to users as well as to other modules. They thus should be deterministic, only dependant on
    /// their input and the current epoch.
    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>>;
}

/// Creates a struct that can be used to make our module-decodable structs interact with
/// `serde`-based APIs (HBBFT, jsonrpsee). It creates a wrapper that holds the data as serialized
// bytes internally.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SerdeModuleEncoding<T: Encodable + Decodable>(Vec<u8>, #[serde(skip)] PhantomData<T>);

impl<T: Encodable + Decodable> From<&T> for SerdeModuleEncoding<T> {
    fn from(value: &T) -> Self {
        let mut bytes = vec![];
        fedimint_api::encoding::Encodable::consensus_encode(value, &mut bytes)
            .expect("Writing to buffer can never fail");
        Self(bytes, PhantomData)
    }
}

impl<T: Encodable + Decodable> SerdeModuleEncoding<T> {
    pub fn try_into_inner(&self, modules: &ModuleDecoderRegistry) -> Result<T, DecodeError> {
        let mut reader = std::io::Cursor::new(&self.0);
        Decodable::consensus_decode(&mut reader, modules)
    }
}
