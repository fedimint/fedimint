//! Fedimint supports modules to allow extending it's functionality.
//! Some of the standard functionality is implemented in form of modules as
//! well.
//!
//! The top level server-side types are:
//!
//! * [`fedimint_core::module::ModuleInit`]
//! * [`fedimint_core::module::ServerModule`]
//!
//! Top level client-side types are:
//!
//! * `ClientModuleInit` (in `fedimint_client`)
//! * `ClientModule` (in `fedimint_client`)
pub mod audit;
pub mod registry;

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::marker::{self, PhantomData};
use std::pin::Pin;
use std::sync::Arc;

use fedimint_logging::LOG_NET_API;
use futures::Future;
use jsonrpsee_core::JsonValue;
use serde::{Deserialize, Serialize};
use tracing::instrument;

// TODO: Make this module public and remove the wildcard `pub use` below
mod version;
pub use self::version::*;
use crate::config::{
    ClientModuleConfig, ConfigGenModuleParams, DkgPeerMsg, ModuleInitParams, ServerModuleConfig,
    ServerModuleConsensusConfig,
};
use crate::core::{
    ClientConfig, Decoder, DecoderBuilder, Input, InputError, ModuleConsensusItem,
    ModuleInstanceId, ModuleKind, Output, OutputError, OutputOutcome,
};
use crate::db::{
    Committable, Database, DatabaseKey, DatabaseKeyWithNotify, DatabaseRecord, DatabaseTransaction,
    DatabaseVersion, ServerMigrationFn,
};
use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::fmt_utils::AbbreviateHexBytes;
use crate::module::audit::Audit;
use crate::net::peers::MuxPeerConnections;
use crate::server::DynServerModule;
use crate::task::{MaybeSend, TaskGroup};
use crate::{
    apply, async_trait_maybe_send, maybe_add_send, maybe_add_send_sync, Amount, NumPeers, OutPoint,
    PeerId,
};

#[derive(Debug, PartialEq)]
pub struct InputMeta {
    pub amount: TransactionItemAmount,
    pub pub_key: secp256k1_zkp::PublicKey,
}

/// Information about the amount represented by an input or output.
///
/// * For **inputs** the amount is funding the transaction while the fee is
///   consuming funding
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

/// All requests from client to server contain these fields
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiRequest<T> {
    /// Hashed user password if the API requires authentication
    pub auth: Option<ApiAuth>,
    /// Parameters required by the API
    pub params: T,
}

pub type ApiRequestErased = ApiRequest<JsonValue>;

impl Default for ApiRequestErased {
    fn default() -> Self {
        Self {
            auth: None,
            params: JsonValue::Null,
        }
    }
}

impl ApiRequestErased {
    pub fn new<T: Serialize>(params: T) -> ApiRequestErased {
        Self {
            auth: None,
            params: serde_json::to_value(params)
                .expect("parameter serialization error - this should not happen"),
        }
    }

    pub fn to_json(&self) -> JsonValue {
        serde_json::to_value(self).expect("parameter serialization error - this should not happen")
    }

    pub fn with_auth(self, auth: ApiAuth) -> Self {
        Self {
            auth: Some(auth),
            params: self.params,
        }
    }

    pub fn to_typed<T: serde::de::DeserializeOwned>(
        self,
    ) -> Result<ApiRequest<T>, serde_json::Error> {
        Ok(ApiRequest {
            auth: self.auth,
            params: serde_json::from_value::<T>(self.params)?,
        })
    }
}

/// Authentication uses the hashed user password in PHC format
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiAuth(pub String);

impl Debug for ApiAuth {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ApiAuth(****)")
    }
}

#[derive(Debug, Clone)]
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

    pub fn unauthorized() -> Self {
        Self::new(401, "Invalid authorization".to_string())
    }

    pub fn server_error(message: String) -> Self {
        Self::new(500, message)
    }
}

/// State made available to all API endpoints for handling a request
pub struct ApiEndpointContext<'dbtx> {
    db: Database,
    dbtx: DatabaseTransaction<'dbtx, Committable>,
    has_auth: bool,
    request_auth: Option<ApiAuth>,
}

impl<'a> ApiEndpointContext<'a> {
    /// `db` and `dbtx` should be isolated.
    pub fn new(
        db: Database,
        dbtx: DatabaseTransaction<'a, Committable>,
        has_auth: bool,
        request_auth: Option<ApiAuth>,
    ) -> Self {
        Self {
            db,
            dbtx,
            has_auth,
            request_auth,
        }
    }

    /// Database tx handle, will be committed
    pub fn dbtx<'s, 'mtx>(&'s mut self) -> DatabaseTransaction<'mtx, Committable>
    where
        'a: 'mtx,
        's: 'mtx,
    {
        // dbtx is already isolated.
        self.dbtx.to_ref()
    }

    /// Returns the auth set on the request (regardless of whether it was
    /// correct)
    pub fn request_auth(&self) -> Option<ApiAuth> {
        self.request_auth.clone()
    }

    /// Whether the request was authenticated as the guardian who controls this
    /// fedimint server
    pub fn has_auth(&self) -> bool {
        self.has_auth
    }

    /// Waits for key to be present in database.
    pub fn wait_key_exists<K>(&self, key: K) -> impl Future<Output = K::Value>
    where
        K: DatabaseKey + DatabaseRecord + DatabaseKeyWithNotify,
    {
        let db = self.db.clone();
        // self contains dbtx which is !Send
        // try removing this and see the error.
        async move { db.wait_key_exists(&key).await }
    }

    /// Waits for key to have a value that matches.
    pub fn wait_value_matches<K>(
        &self,
        key: K,
        matcher: impl Fn(&K::Value) -> bool + Copy,
    ) -> impl Future<Output = K::Value>
    where
        K: DatabaseKey + DatabaseRecord + DatabaseKeyWithNotify,
    {
        let db = self.db.clone();
        async move { db.wait_key_check(&key, |v| v.filter(matcher)).await.0 }
    }

    /// Attempts to commit the dbtx or returns an ApiError
    pub async fn commit_tx_result(self, path: &'static str) -> Result<(), ApiError> {
        self.dbtx.commit_tx_result().await.map_err(|_err| {
            tracing::warn!(
                target: fedimint_logging::LOG_NET_API,
                path,
                "API server error when writing to database: {:?}",
                _err
            );
            ApiError {
                code: 500,
                message: "API server error when writing to database".to_string(),
            }
        })
    }
}

#[apply(async_trait_maybe_send!)]
pub trait TypedApiEndpoint {
    type State: Sync;

    /// example: /transaction
    const PATH: &'static str;

    type Param: serde::de::DeserializeOwned + Send;
    type Response: serde::Serialize;

    async fn handle<'state, 'context, 'dbtx>(
        state: &'state Self::State,
        context: &'context mut ApiEndpointContext<'dbtx>,
        request: Self::Param,
    ) -> Result<Self::Response, ApiError>
    where
        'dbtx: 'context;
}

#[doc(hidden)]
pub mod __reexports {
    pub use serde_json;
}

/// # Example
///
/// ```rust
/// # use fedimint_core::module::ApiVersion;
/// # use fedimint_core::module::{api_endpoint, ApiEndpoint, registry::ModuleInstanceId};
/// struct State;
///
/// let _: ApiEndpoint<State> = api_endpoint! {
///     "/foobar",
///     ApiVersion::new(0, 3),
///     async |state: &State, _dbtx, params: ()| -> i32 {
///         Ok(0)
///     }
/// };
/// ```
#[macro_export]
macro_rules! __api_endpoint {
    (
        $path:expr,
        // Api Version this endpoint was introduced in, at the current consensus level
        // Currently for documentation purposes only.
        $version_introduced:expr,
        async |$state:ident: &$state_ty:ty, $context:ident, $param:ident: $param_ty:ty| -> $resp_ty:ty $body:block
    ) => {{
        struct Endpoint;

        #[$crate::apply($crate::async_trait_maybe_send!)]
        impl $crate::module::TypedApiEndpoint for Endpoint {
            const PATH: &'static str = $path;
            type State = $state_ty;
            type Param = $param_ty;
            type Response = $resp_ty;

            async fn handle<'state, 'context, 'dbtx>(
                $state: &'state Self::State,
                $context: &'context mut $crate::module::ApiEndpointContext<'dbtx>,
                $param: Self::Param,
            ) -> ::std::result::Result<Self::Response, $crate::module::ApiError> {
                {
                    // just to enforce the correct type
                    const __API_VERSION: $crate::module::ApiVersion = $version_introduced;
                }
                $body
            }
        }

        $crate::module::ApiEndpoint::from_typed::<Endpoint>()
    }};
}

pub use __api_endpoint as api_endpoint;
use fedimint_core::config::DkgResult;

use self::registry::ModuleDecoderRegistry;

type HandlerFnReturn<'a> =
    Pin<Box<maybe_add_send!(dyn Future<Output = Result<serde_json::Value, ApiError>> + 'a)>>;
type HandlerFn<M> = Box<
    maybe_add_send_sync!(
        dyn for<'a> Fn(&'a M, ApiEndpointContext<'a>, ApiRequestErased) -> HandlerFnReturn<'a>
    ),
>;

/// Definition of an API endpoint defined by a module `M`.
pub struct ApiEndpoint<M> {
    /// Path under which the API endpoint can be reached. It should start with a
    /// `/` e.g. `/transaction`. E.g. this API endpoint would be reachable
    /// under `module_module_instance_id_transaction` depending on the
    /// module name returned by `[FedertionModule::api_base_name]`.
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
        <E as TypedApiEndpoint>::Response: MaybeSend,
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
        async fn handle_request<'state, 'context, 'dbtx, E>(
            state: &'state E::State,
            context: &'context mut ApiEndpointContext<'dbtx>,
            request: ApiRequest<E::Param>,
        ) -> Result<E::Response, ApiError>
        where
            'dbtx: 'context,
            E: TypedApiEndpoint,
            E::Param: Debug,
            E::Response: Debug,
        {
            tracing::debug!(target: LOG_NET_API, path = E::PATH, ?request, "received request");
            let result = E::handle(state, context, request.params).await;
            if let Err(error) = &result {
                tracing::warn!(target: LOG_NET_API, path = E::PATH, ?error, "api request error");
            } else {
                tracing::debug!(target: LOG_NET_API, path = E::PATH, "api request complete");
            }
            result
        }

        ApiEndpoint {
            path: E::PATH,
            handler: Box::new(|m, mut context, request| {
                Box::pin(async move {
                    let request = request
                        .to_typed()
                        .map_err(|e| ApiError::bad_request(e.to_string()))?;

                    let ret = handle_request::<E>(m, &mut context, request).await?;

                    context.commit_tx_result(E::PATH).await?;

                    Ok(serde_json::to_value(ret).expect("encoding error"))
                })
            }),
        }
    }
}

/// Operations common to Server and Client side module gen dyn newtypes
///
/// Due to conflict of `impl Trait for T` for both `ServerModuleInit` and
/// `ClientModuleInit`, we can't really have a `ICommonModuleInit`, so to unify
/// them in `ModuleInitRegistry` we move the common functionality to be an
/// interface over their dyn newtype wrappers. A bit weird, but works.
#[apply(async_trait_maybe_send!)]
pub trait IDynCommonModuleInit: Debug {
    fn decoder(&self) -> Decoder;

    fn module_kind(&self) -> ModuleKind;

    fn to_dyn_common(&self) -> DynCommonModuleInit;

    fn database_version(&self) -> DatabaseVersion;

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_>;
}

/// Trait implemented by every `*ModuleInit` (server or client side)
#[apply(async_trait_maybe_send!)]
pub trait ModuleInit: Debug + Clone + Send + Sync + 'static {
    type Common: CommonModuleInit;

    /// This represents the module's database version that the current code is
    /// compatible with. It is important to increment this value whenever a
    /// key or a value that is persisted to the database within the module
    /// changes. It is also important to add the corresponding
    /// migration function in `get_database_migrations` which should define how
    /// to move from the previous database version to the current version.
    const DATABASE_VERSION: DatabaseVersion;

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_>;
}

#[apply(async_trait_maybe_send!)]
impl<T> IDynCommonModuleInit for T
where
    T: ModuleInit,
{
    fn decoder(&self) -> Decoder {
        T::Common::decoder()
    }

    fn module_kind(&self) -> ModuleKind {
        T::Common::KIND
    }

    fn to_dyn_common(&self) -> DynCommonModuleInit {
        DynCommonModuleInit::from_inner(Arc::new(self.clone()))
    }

    fn database_version(&self) -> DatabaseVersion {
        <Self as ModuleInit>::DATABASE_VERSION
    }

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        <Self as ModuleInit>::dump_database(self, dbtx, prefix_names).await
    }
}

/// Interface for Module Generation
///
/// This trait contains the methods responsible for the module's
/// - initialization
/// - config generation
/// - config validation
///
/// Once the module configuration is ready, the module can be instantiated via
/// `[Self::init]`.
#[apply(async_trait_maybe_send!)]
pub trait IServerModuleInit: IDynCommonModuleInit {
    fn as_common(&self) -> &(dyn IDynCommonModuleInit + Send + Sync + 'static);

    fn supported_api_versions(&self) -> SupportedModuleApiVersions;

    /// Initialize the [`DynServerModule`] instance from its config
    async fn init(
        &self,
        peer_num: NumPeers,
        cfg: ServerModuleConfig,
        db: Database,
        task_group: &TaskGroup,
        our_peer_id: PeerId,
    ) -> anyhow::Result<DynServerModule>;

    fn validate_params(&self, params: &ConfigGenModuleParams) -> anyhow::Result<()>;

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig>;

    async fn distributed_gen(
        &self,
        peers: &PeerHandle,
        params: &ConfigGenModuleParams,
    ) -> DkgResult<ServerModuleConfig>;

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()>;

    fn get_client_config(
        &self,
        module_instance_id: ModuleInstanceId,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<ClientModuleConfig>;

    /// Retrieves the migrations map from the server module to be applied to the
    /// database before the module is initialized. The migrations map is
    /// indexed on the from version.
    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ServerMigrationFn>;
}

dyn_newtype_define!(
    #[derive(Clone)]
    pub DynCommonModuleInit(Arc<IDynCommonModuleInit>)
);

impl AsRef<maybe_add_send_sync!(dyn IDynCommonModuleInit + 'static)> for DynCommonModuleInit {
    fn as_ref(&self) -> &(maybe_add_send_sync!(dyn IDynCommonModuleInit + 'static)) {
        self.inner.as_ref()
    }
}

impl DynCommonModuleInit {
    pub fn from_inner(
        inner: Arc<maybe_add_send_sync!(dyn IDynCommonModuleInit + 'static)>,
    ) -> Self {
        DynCommonModuleInit { inner }
    }
}

dyn_newtype_define!(
    #[derive(Clone)]
    pub DynServerModuleInit(Arc<IServerModuleInit>)
);

impl AsRef<dyn IDynCommonModuleInit + Send + Sync + 'static> for DynServerModuleInit {
    fn as_ref(&self) -> &(dyn IDynCommonModuleInit + Send + Sync + 'static) {
        self.inner.as_common()
    }
}

/// Logic and constant common between server side and client side modules
#[apply(async_trait_maybe_send!)]
pub trait CommonModuleInit: Debug + Sized {
    const CONSENSUS_VERSION: ModuleConsensusVersion;
    const KIND: ModuleKind;

    type ClientConfig: ClientConfig;

    fn decoder() -> Decoder;
}

pub struct ServerModuleInitArgs<S>
where
    S: ServerModuleInit,
{
    cfg: ServerModuleConfig,
    db: Database,
    task_group: TaskGroup,
    our_peer_id: PeerId,
    num_peers: NumPeers,
    // ClientModuleInitArgs needs a bound because sometimes we need
    // to pass associated-types data, so let's just put it here right away
    _marker: marker::PhantomData<S>,
}

impl<S> ServerModuleInitArgs<S>
where
    S: ServerModuleInit,
{
    pub fn cfg(&self) -> &ServerModuleConfig {
        &self.cfg
    }

    pub fn db(&self) -> &Database {
        &self.db
    }

    pub fn num_peers(&self) -> NumPeers {
        self.num_peers
    }

    pub fn task_group(&self) -> &TaskGroup {
        &self.task_group
    }

    pub fn our_peer_id(&self) -> PeerId {
        self.our_peer_id
    }
}
/// Module Generation trait with associated types
///
/// Needs to be implemented by module generation type
///
/// For examples, take a look at one of the `MintConfigGenerator`,
/// `WalletConfigGenerator`, or `LightningConfigGenerator` structs.
#[apply(async_trait_maybe_send!)]
pub trait ServerModuleInit: ModuleInit + Sized {
    type Params: ModuleInitParams;

    /// Version of the module consensus supported by this implementation given a
    /// certain [`CoreConsensusVersion`].
    ///
    /// Refer to [`ModuleConsensusVersion`] for more information about
    /// versioning.
    ///
    /// One module implementation ([`ServerModuleInit`] of a given
    /// [`ModuleKind`]) can potentially implement multiple versions of the
    /// consensus, and depending on the config module instance config,
    /// instantiate the desired one. This method should expose all the
    /// available versions, purely for information, setup UI and sanity
    /// checking purposes.
    fn versions(&self, core: CoreConsensusVersion) -> &[ModuleConsensusVersion];

    fn supported_api_versions(&self) -> SupportedModuleApiVersions;

    fn kind() -> ModuleKind {
        <Self as ModuleInit>::Common::KIND
    }

    /// Initialize the [`DynServerModule`] instance from its config
    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<DynServerModule>;

    fn parse_params(&self, params: &ConfigGenModuleParams) -> anyhow::Result<Self::Params> {
        params.to_typed::<Self::Params>()
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig>;

    async fn distributed_gen(
        &self,
        peer: &PeerHandle,
        params: &ConfigGenModuleParams,
    ) -> DkgResult<ServerModuleConfig>;

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()>;

    /// Converts the consensus config into the client config
    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<<<Self as ModuleInit>::Common as CommonModuleInit>::ClientConfig>;

    /// Retrieves the migrations map from the server module to be applied to the
    /// database before the module is initialized. The migrations map is
    /// indexed on the from version.
    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ServerMigrationFn> {
        BTreeMap::new()
    }
}

#[apply(async_trait_maybe_send!)]
impl<T> IServerModuleInit for T
where
    T: ServerModuleInit + 'static + Sync,
{
    fn as_common(&self) -> &(dyn IDynCommonModuleInit + Send + Sync + 'static) {
        self
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        <Self as ServerModuleInit>::supported_api_versions(self)
    }

    async fn init(
        &self,
        num_peers: NumPeers,
        cfg: ServerModuleConfig,
        db: Database,
        task_group: &TaskGroup,
        our_peer_id: PeerId,
    ) -> anyhow::Result<DynServerModule> {
        <Self as ServerModuleInit>::init(
            self,
            &ServerModuleInitArgs {
                num_peers,
                cfg,
                db,
                task_group: task_group.clone(),
                our_peer_id,
                _marker: Default::default(),
            },
        )
        .await
    }

    fn validate_params(&self, params: &ConfigGenModuleParams) -> anyhow::Result<()> {
        <Self as ServerModuleInit>::parse_params(self, params)?;
        Ok(())
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        <Self as ServerModuleInit>::trusted_dealer_gen(self, peers, params)
    }

    async fn distributed_gen(
        &self,
        peers: &PeerHandle,
        params: &ConfigGenModuleParams,
    ) -> DkgResult<ServerModuleConfig> {
        <Self as ServerModuleInit>::distributed_gen(self, peers, params).await
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        <Self as ServerModuleInit>::validate_config(self, identity, config)
    }

    fn get_client_config(
        &self,
        module_instance_id: ModuleInstanceId,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<ClientModuleConfig> {
        ClientModuleConfig::from_typed(
            module_instance_id,
            <Self as ServerModuleInit>::kind(),
            config.version,
            <Self as ServerModuleInit>::get_client_config(self, config)?,
        )
    }

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ServerMigrationFn> {
        <Self as ServerModuleInit>::get_database_migrations(self)
    }
}

/// Module associated types required by both client and server
pub trait ModuleCommon {
    type ClientConfig: ClientConfig;
    type Input: Input;
    type Output: Output;
    type OutputOutcome: OutputOutcome;
    type ConsensusItem: ModuleConsensusItem;
    type InputError: InputError;
    type OutputError: OutputError;

    fn decoder_builder() -> DecoderBuilder {
        let mut decoder_builder = Decoder::builder();
        decoder_builder.with_decodable_type::<Self::ClientConfig>();
        decoder_builder.with_decodable_type::<Self::Input>();
        decoder_builder.with_decodable_type::<Self::Output>();
        decoder_builder.with_decodable_type::<Self::OutputOutcome>();
        decoder_builder.with_decodable_type::<Self::ConsensusItem>();
        decoder_builder.with_decodable_type::<Self::InputError>();
        decoder_builder.with_decodable_type::<Self::OutputError>();

        decoder_builder
    }

    fn decoder() -> Decoder {
        Self::decoder_builder().build()
    }
}

#[apply(async_trait_maybe_send!)]
pub trait ServerModule: Debug + Sized {
    type Common: ModuleCommon;

    type Init: ServerModuleInit;

    fn module_kind() -> ModuleKind {
        // Note: All modules should define kinds as &'static str, so this doesn't
        // allocate
        <Self::Init as ModuleInit>::Common::KIND
    }

    /// Returns a decoder for the following associated types of this module:
    /// * `Input`
    /// * `Output`
    /// * `OutputOutcome`
    /// * `ConsensusItem`
    fn decoder() -> Decoder {
        Self::Common::decoder_builder().build()
    }

    /// This module's contribution to the next consensus proposal
    async fn consensus_proposal<'a>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<<Self::Common as ModuleCommon>::ConsensusItem>;

    /// This function is called once for every consensus item. The function
    /// returns an error if and only if the consensus item does not change
    /// our state and therefore may be safely discarded by the atomic broadcast.
    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        consensus_item: <Self::Common as ModuleCommon>::ConsensusItem,
        peer_id: PeerId,
    ) -> anyhow::Result<()>;

    /// Try to spend a transaction input. On success all necessary updates will
    /// be part of the database transaction. On failure (e.g. double spend)
    /// the database transaction is rolled back and the operation will take
    /// no effect.
    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b <Self::Common as ModuleCommon>::Input,
    ) -> Result<InputMeta, <Self::Common as ModuleCommon>::InputError>;

    /// Try to create an output (e.g. issue notes, peg-out BTC, …). On success
    /// all necessary updates to the database will be part of the database
    /// transaction. On failure (e.g. double spend) the database transaction
    /// is rolled back and the operation will take no effect.
    ///
    /// The supplied `out_point` identifies the operation (e.g. a peg-out or
    /// note issuance) and can be used to retrieve its outcome later using
    /// `output_status`.
    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a <Self::Common as ModuleCommon>::Output,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmount, <Self::Common as ModuleCommon>::OutputError>;

    /// Retrieve the current status of the output. Depending on the module this
    /// might contain data needed by the client to access funds or give an
    /// estimate of when funds will be available. Returns `None` if the
    /// output is unknown, **NOT** if it is just not ready yet.
    async fn output_status(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        out_point: OutPoint,
    ) -> Option<<Self::Common as ModuleCommon>::OutputOutcome>;

    /// Queries the database and returns all assets and liabilities of the
    /// module.
    ///
    /// Summing over all modules, if liabilities > assets then an error has
    /// occurred in the database and consensus should halt.
    async fn audit(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        audit: &mut Audit,
        module_instance_id: ModuleInstanceId,
    );

    /// Returns a list of custom API endpoints defined by the module. These are
    /// made available both to users as well as to other modules. They thus
    /// should be deterministic, only dependant on their input and the
    /// current epoch.
    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>>;
}

/// Creates a struct that can be used to make our module-decodable structs
/// interact with `serde`-based APIs (AlephBFT, jsonrpsee). It creates a wrapper
/// that holds the data as serialized
// bytes internally.
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SerdeModuleEncoding<T: Encodable + Decodable>(
    #[serde(with = "::fedimint_core::encoding::as_hex")] Vec<u8>,
    #[serde(skip)] PhantomData<T>,
);

impl<T> fmt::Debug for SerdeModuleEncoding<T>
where
    T: Encodable + Decodable,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("SerdeModuleEncoding(")?;
        fmt::Debug::fmt(&AbbreviateHexBytes(&self.0), f)?;
        f.write_str(")")?;
        Ok(())
    }
}

impl<T: Encodable + Decodable> From<&T> for SerdeModuleEncoding<T> {
    fn from(value: &T) -> Self {
        let mut bytes = vec![];
        fedimint_core::encoding::Encodable::consensus_encode(value, &mut bytes)
            .expect("Writing to buffer can never fail");
        Self(bytes, PhantomData)
    }
}

impl<T: Encodable + Decodable + 'static> SerdeModuleEncoding<T> {
    pub fn try_into_inner(&self, modules: &ModuleDecoderRegistry) -> Result<T, DecodeError> {
        let mut reader = std::io::Cursor::new(&self.0);
        Decodable::consensus_decode(&mut reader, modules)
    }

    /// In cases where we know exactly which module kind we expect but don't
    /// have access to all decoders this function can be used instead.
    ///
    /// Note that it just assumes the decoded module instance id to be valid
    /// since it cannot validate against the decoder registry. The lack of
    /// access to a decoder registry also makes decoding structs impossible that
    /// themselves contain module dyn-types (e.g. a module output containing a
    /// fedimint transaction).
    pub fn try_into_inner_known_module_kind(&self, decoder: &Decoder) -> Result<T, DecodeError> {
        let mut reader = std::io::Cursor::new(&self.0);
        let module_instance =
            ModuleInstanceId::consensus_decode(&mut reader, &ModuleDecoderRegistry::default())?;

        let total_len = u64::consensus_decode(&mut reader, &ModuleDecoderRegistry::default())?;

        // No recursive module decoding is supported since we give an empty decoder
        // registry to the decode function
        decoder.decode_complete(&mut reader, total_len, module_instance, &Default::default())
    }
}

/// A handle passed to [`ServerModuleInit::distributed_gen`]
///
/// This struct encapsulates dkg data that the module should not have a direct
/// access to, and implements higher level dkg operations available to the
/// module to complete its distributed initialization inside the federation.
#[non_exhaustive]
pub struct PeerHandle<'a> {
    // TODO: this whole type should be a part of a `fedimint-server` and fields here inaccessible
    // to outside crates, but until `ServerModule` is not in `fedimint-server` this is impossible
    #[doc(hidden)]
    pub connections: &'a MuxPeerConnections<(ModuleInstanceId, String), DkgPeerMsg>,
    #[doc(hidden)]
    pub module_instance_id: ModuleInstanceId,
    #[doc(hidden)]
    pub our_id: PeerId,
    #[doc(hidden)]
    pub peers: Vec<PeerId>,
}

impl<'a> PeerHandle<'a> {
    pub fn new(
        connections: &'a MuxPeerConnections<(ModuleInstanceId, String), DkgPeerMsg>,
        module_instance_id: ModuleInstanceId,
        our_id: PeerId,
        peers: Vec<PeerId>,
    ) -> Self {
        Self {
            connections,
            module_instance_id,
            our_id,
            peers,
        }
    }

    pub fn peer_ids(&self) -> &[PeerId] {
        self.peers.as_slice()
    }
}
