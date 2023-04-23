pub mod audit;
pub mod interconnect;
pub mod registry;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;

use bitcoin_hashes::sha256;
use bitcoin_hashes::sha256::Hash;
use futures::Future;
use jsonrpsee_core::JsonValue;
use secp256k1_zkp::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tracing::instrument;

use crate::config::{ConfigGenModuleParams, DkgPeerMsg, ServerModuleConfig};
use crate::core::{
    Decoder, DecoderBuilder, Input, ModuleConsensusItem, ModuleInstanceId, ModuleKind, Output,
    OutputOutcome,
};
use crate::db::{
    Database, DatabaseKey, DatabaseKeyWithNotify, DatabaseRecord, DatabaseTransaction,
    DatabaseVersion, MigrationMap, ModuleDatabaseTransaction,
};
use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::module::audit::Audit;
use crate::module::interconnect::ModuleInterconect;
use crate::net::peers::MuxPeerConnections;
use crate::server::{DynServerModule, VerificationCache};
use crate::task::{MaybeSend, TaskGroup};
use crate::{
    apply, async_trait_maybe_send, dyn_newtype_define, maybe_add_send, maybe_add_send_sync, Amount,
    OutPoint, PeerId,
};

pub struct InputMeta {
    pub amount: TransactionItemAmount,
    pub puk_keys: Vec<XOnlyPublicKey>,
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

    pub fn with_auth(self, auth: &ApiAuth) -> Self {
        Self {
            auth: Some(auth.clone()),
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiAuth(pub String);

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

    pub fn unauthorized() -> Self {
        Self::new(401, "Request missing required authorization".to_string())
    }

    pub fn server_error(message: String) -> Self {
        Self::new(500, message)
    }
}

/// State made available to all API endpoints for handling a request
pub struct ApiEndpointContext<'a> {
    db: Database,
    dbtx: DatabaseTransaction<'a>,
    has_auth: bool,
}

impl<'a> ApiEndpointContext<'a> {
    /// `db` and `dbtx` should be isolated.
    pub fn new(db: Database, dbtx: DatabaseTransaction<'a>, has_auth: bool) -> Self {
        Self { db, dbtx, has_auth }
    }

    /// Database tx handle, will be committed
    pub fn dbtx(&mut self) -> ModuleDatabaseTransaction<'_> {
        // dbtx is already isolated.
        self.dbtx.get_isolated()
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

    /// Attempts to commit the dbtx or returns an ApiError
    pub async fn commit_tx_result(self) -> Result<(), ApiError> {
        self.dbtx.commit_tx_result().await.map_err(|_err| ApiError {
            code: 500,
            message: "API server error when writing to database".to_string(),
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

    async fn handle<'a, 'b>(
        state: &'a Self::State,
        context: &'a mut ApiEndpointContext<'b>,
        request: Self::Param,
    ) -> Result<Self::Response, ApiError>;
}

#[doc(hidden)]
pub mod __reexports {
    pub use serde_json;
}

/// # Example
///
/// ```rust
/// # use fedimint_core::module::{api_endpoint, ApiEndpoint, registry::ModuleInstanceId};
/// struct State;
///
/// let _: ApiEndpoint<State> = api_endpoint! {
///     "foobar",
///     async |state: &State, _dbtx, params: ()| -> i32 {
///         Ok(0)
///     }
/// };
/// ```
#[macro_export]
macro_rules! __api_endpoint {
    (
        $path:expr,
        async |$state:ident: &$state_ty:ty, $context:ident, $param:ident: $param_ty:ty| -> $resp_ty:ty $body:block
    ) => {{
        struct Endpoint;

        #[$crate::apply($crate::async_trait_maybe_send!)]
        impl $crate::module::TypedApiEndpoint for Endpoint {
            const PATH: &'static str = $path;
            type State = $state_ty;
            type Param = $param_ty;
            type Response = $resp_ty;

            async fn handle<'a, 'b>(
                $state: &'a Self::State,
                $context: &'a mut $crate::module::ApiEndpointContext<'b>,
                $param: Self::Param,
            ) -> ::std::result::Result<Self::Response, $crate::module::ApiError> {
                $body
            }
        }

        $crate::module::ApiEndpoint::from_typed::<Endpoint>()
    }};
}

pub use __api_endpoint as api_endpoint;
use fedimint_core::config::{DkgResult, ModuleConfigResponse};

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
        async fn handle_request<'a, 'b, E>(
            state: &'a E::State,
            context: &'a mut ApiEndpointContext<'b>,
            request: ApiRequest<E::Param>,
        ) -> Result<E::Response, ApiError>
        where
            E: TypedApiEndpoint,
            E::Param: Debug,
            E::Response: Debug,
        {
            tracing::trace!(target: "fedimint_server::request", ?request, "received request");
            let result = E::handle(state, context, request.params).await;
            if let Err(error) = &result {
                tracing::trace!(target: "fedimint_server::request", ?error, "error");
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

                    context.commit_tx_result().await?;

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

/// Extension trait with a function to map `Result`s used by modules to
/// `ModuleError`
///
/// Currently each module defined it's own `enum XyzError { ... }` and is not
/// using `anyhow::Error`. For `?` to work seamlessly two conversion would have
/// to be made: `enum-Error -> anyhow::Error -> enum-Error`, while `Into`/`From`
/// can only do one.
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

/// Operations common to Server and Client side module gen dyn newtypes
///
/// Due to conflict of `impl Trait for T` for both `ServerModuleGen` and
/// `ClientModuleGen`, we can't really have a `ICommonModuleGen`, so to unify
/// them in `ModuleGenRegistry` we move the common functionality to be an
/// interface over their dyn newtype wrappers. A bit weird, but works.
pub trait IDynCommonModuleGen: Debug {
    fn decoder(&self) -> Decoder;

    fn module_kind(&self) -> ModuleKind;

    fn hash_client_module(&self, config: serde_json::Value) -> anyhow::Result<sha256::Hash>;

    fn to_dyn_common(&self) -> DynCommonModuleGen;
}

pub trait ExtendsCommonModuleGen: Debug + Clone + Send + Sync + 'static {
    type Common: CommonModuleGen;
}

impl<T> IDynCommonModuleGen for T
where
    T: ExtendsCommonModuleGen,
{
    fn decoder(&self) -> Decoder {
        T::Common::decoder()
    }

    fn module_kind(&self) -> ModuleKind {
        T::Common::KIND
    }

    fn hash_client_module(&self, config: Value) -> anyhow::Result<Hash> {
        T::Common::hash_client_module(config)
    }

    fn to_dyn_common(&self) -> DynCommonModuleGen {
        DynCommonModuleGen::from_inner(Arc::new(self.clone()))
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
pub trait IServerModuleGen: IDynCommonModuleGen {
    fn as_common(&self) -> &(dyn IDynCommonModuleGen + Send + Sync + 'static);

    fn database_version(&self) -> DatabaseVersion;

    /// Initialize the [`DynServerModule`] instance from its config
    async fn init(
        &self,
        cfg: ServerModuleConfig,
        db: Database,
        env: &BTreeMap<OsString, OsString>,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<DynServerModule>;

    /// Retrieves the `MigrationMap` from the module to be applied to the
    /// database before the module is initialized. The `MigrationMap` is
    /// indexed on the from version.
    fn get_database_migrations(&self) -> MigrationMap;

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

    fn to_config_response(&self, config: serde_json::Value)
        -> anyhow::Result<ModuleConfigResponse>;

    fn hash_client_module(&self, config: serde_json::Value) -> anyhow::Result<sha256::Hash>;

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()>;

    async fn dump_database(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_>;
}

dyn_newtype_define!(
    #[derive(Clone)]
    pub DynCommonModuleGen(Arc<IDynCommonModuleGen>)
);

impl AsRef<maybe_add_send_sync!(dyn IDynCommonModuleGen + 'static)> for DynCommonModuleGen {
    fn as_ref(&self) -> &(maybe_add_send_sync!(dyn IDynCommonModuleGen + 'static)) {
        self.0.as_ref()
    }
}

impl DynCommonModuleGen {
    pub fn from_inner(inner: Arc<maybe_add_send_sync!(dyn IDynCommonModuleGen + 'static)>) -> Self {
        DynCommonModuleGen(inner)
    }
}

dyn_newtype_define!(
    #[derive(Clone)]
    pub DynServerModuleGen(Arc<IServerModuleGen>)
);

impl AsRef<dyn IDynCommonModuleGen + Send + Sync + 'static> for DynServerModuleGen {
    fn as_ref(&self) -> &(dyn IDynCommonModuleGen + Send + Sync + 'static) {
        self.0.as_common()
    }
}

/// Consensus version of a core server
///
/// Breaking changes in the Fedimint's core consensus require incrementing it.
///
/// See [`ModuleConsensusVersion`] for more details on how it interacts with
/// module's consensus.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, Encodable)]
pub struct CoreConsensusVersion(pub u32);

/// Consensus version of a specific module instance
///
/// Any breaking change to the module's consensus rules require incrementing it.
///
/// A module instance can run only in one consensus version, which must be the
/// same across all corresponding instances on other nodes of the federation.
///
/// When [`CoreConsensusVersion`] changes, this can but is not requires to be
/// a breaking change for each module's [`ModuleConsensusVersion`].
///
/// Incrementing the module's consensus version can be considered an in-place
/// upgrade path, similar to a blockchain hard-fork consensus upgrade.
///
/// As of time of writing this comment there are no plans to support any kind
/// of "soft-forks" which mean a consensus minor version. As the set of
/// federation member's is closed and limited, it is always preferable to
/// synchronize upgrade and avoid cross-version incompatibilities.
///
/// For many modules it might be preferable to implement a new [`ModuleKind`]
/// "versions" (to be implemented at the time of writing this comment), and
/// by running two instances of the module at the same time (each of different
/// `ModuleKind` version), allow users to slowly migrate to a new one.
/// This avoids complex and error-prone server-side consensus-migration logic.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, Encodable)]
pub struct ModuleConsensusVersion(pub u32);

/// Api version supported by a core server or a client/server module at a given
/// [`ModuleConsensusVersion`]
///
/// Changing [`ModuleConsensusVersion`] implies resetting the api versioning.
///
/// For a client and server to be able to communicate with each other:
///
/// * The client needs API version support for the [`ModuleConsensusVersion`]
///   that the server is currently running with.
/// * Within that [`ModuleConsensusVersion`] during handshake negotiation
///   process client and server must find at least one `Api::major` version
///   where client's `minor` is lower or equal server's `major` version.
///
/// A practical module implementation needs to implement large range of version
/// backward compatibility on both client and server side to accommodate end
/// user client devices receiving updates at a pace hard to control, and
/// technical and coordination challenges of upgrading servers.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct ApiVersion {
    /// Major API version
    ///
    /// Each time [`ModuleConsensusVersion`] is incremented, this number (and
    /// `minor` number as well) should be reset to `0`.
    ///
    /// Should be incremented each time the API was changed in a
    /// backward-incompatible ways (while resetting `minor` to `0`).
    pub major: u32,
    /// Minor API version
    ///
    /// * For clients this means *minimum* supported minor version of the
    ///   `major` version required by client implementation
    /// * For servers this means *maximum* supported minor version of the
    ///   `major` version implemented by the server implementation
    pub minor: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedCoreApiVersions {
    pub consensus: CoreConsensusVersion,
    pub api: Vec<ApiVersion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedModuleApiVersions {
    pub core: CoreConsensusVersion,
    pub module: ModuleConsensusVersion,
    pub api: Vec<ApiVersion>,
}

impl SupportedModuleApiVersions {
    pub fn from_raw(core: u32, module: u32, api_versions: &[(u32, u32)]) -> Self {
        Self {
            core: CoreConsensusVersion(core),
            module: ModuleConsensusVersion(module),
            api: api_versions
                .iter()
                .copied()
                .map(|(major, minor)| ApiVersion { major, minor })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedApiVersionsSummary {
    pub core: SupportedCoreApiVersions,
    pub modules: BTreeMap<ModuleInstanceId, SupportedModuleApiVersions>,
}

pub trait CommonModuleGen: Debug + Sized {
    const KIND: ModuleKind;

    fn decoder() -> Decoder;

    fn hash_client_module(config: serde_json::Value) -> anyhow::Result<sha256::Hash>;
}

/// Module Generation trait with associated types
///
/// Needs to be implemented by module generation type
///
/// For examples, take a look at one of the `MintConfigGenerator`,
/// `WalletConfigGenerator`, or `LightningConfigGenerator` structs.
#[apply(async_trait_maybe_send!)]
pub trait ServerModuleGen: ExtendsCommonModuleGen + Sized {
    /// This represents the module's database version that the current code is
    /// compatible with. It is important to increment this value whenever a
    /// key or a value that is persisted to the database within the module
    /// changes. It is also important to add the corresponding
    /// migration function in `get_database_migrations` which should define how
    /// to move from the previous database version to the current version.
    const DATABASE_VERSION: DatabaseVersion;

    /// Version of the module consensus supported by this implementation given a
    /// certain [`CoreConsensusVersion`].
    ///
    /// Refer to [`ModuleConsensusVersion`] for more information about
    /// versioning.
    ///
    /// One module implementation ([`ServerModuleGen`] of a given
    /// [`ModuleKind`]) can potentially implement multiple versions of the
    /// consensus, and depending on the config module instance config,
    /// instantiate the desired one. This method should expose all the
    /// available versions, purely for information, setup UI and sanity
    /// checking purposes.
    fn versions(&self, core: CoreConsensusVersion) -> &[ModuleConsensusVersion];

    fn kind() -> ModuleKind {
        <Self as ExtendsCommonModuleGen>::Common::KIND
    }

    /// Initialize the [`DynServerModule`] instance from its config
    async fn init(
        &self,
        cfg: ServerModuleConfig,
        db: Database,
        env: &BTreeMap<OsString, OsString>,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<DynServerModule>;

    /// Retrieves the `MigrationMap` from the module to be applied to the
    /// database before the module is initialized. The `MigrationMap` is
    /// indexed on the from version.
    fn get_database_migrations(&self) -> MigrationMap {
        MigrationMap::new()
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

    fn to_config_response(&self, config: serde_json::Value)
        -> anyhow::Result<ModuleConfigResponse>;

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()>;

    async fn dump_database(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_>;
}

#[apply(async_trait_maybe_send!)]
impl<T> IServerModuleGen for T
where
    T: ServerModuleGen + 'static + Sync,
{
    fn as_common(&self) -> &(dyn IDynCommonModuleGen + Send + Sync + 'static) {
        self
    }

    fn database_version(&self) -> DatabaseVersion {
        <Self as ServerModuleGen>::DATABASE_VERSION
    }

    async fn init(
        &self,
        cfg: ServerModuleConfig,
        db: Database,
        env: &BTreeMap<OsString, OsString>,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<DynServerModule> {
        <Self as ServerModuleGen>::init(self, cfg, db, env, task_group).await
    }

    fn get_database_migrations(&self) -> MigrationMap {
        <Self as ServerModuleGen>::get_database_migrations(self)
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        <Self as ServerModuleGen>::trusted_dealer_gen(self, peers, params)
    }

    async fn distributed_gen(
        &self,
        peers: &PeerHandle,
        params: &ConfigGenModuleParams,
    ) -> DkgResult<ServerModuleConfig> {
        <Self as ServerModuleGen>::distributed_gen(self, peers, params).await
    }

    fn to_config_response(
        &self,
        config: serde_json::Value,
    ) -> anyhow::Result<ModuleConfigResponse> {
        <Self as ServerModuleGen>::to_config_response(self, config)
    }

    fn hash_client_module(&self, config: serde_json::Value) -> anyhow::Result<Hash> {
        <Self as ExtendsCommonModuleGen>::Common::hash_client_module(config)
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        <Self as ServerModuleGen>::validate_config(self, identity, config)
    }

    async fn dump_database(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        <Self as ServerModuleGen>::dump_database(self, dbtx, prefix_names).await
    }
}

pub enum ConsensusProposal<CI> {
    /// Trigger new epoch immediately including these consensus items
    Trigger(Vec<CI>),
    /// Contribute consensus items if other module triggers an epoch
    // TODO: turn into `(Vec<CI>, Update)` where `Updates` is a future
    // that will return a new `ConsensusProposal` when updates are available.
    // This wake we can get rid of `await_consensus_proposal`
    Contribute(Vec<CI>),
}

impl<CI> ConsensusProposal<CI> {
    pub fn empty() -> Self {
        ConsensusProposal::Contribute(vec![])
    }

    /// Trigger new epoch if contains any elements, otherwise contribute
    /// nothing.
    pub fn new_auto_trigger(ci: Vec<CI>) -> Self {
        if ci.is_empty() {
            Self::Contribute(vec![])
        } else {
            Self::Trigger(ci)
        }
    }

    pub fn map<F, CIO>(self, f: F) -> ConsensusProposal<CIO>
    where
        F: FnMut(CI) -> CIO,
    {
        match self {
            ConsensusProposal::Trigger(items) => {
                ConsensusProposal::Trigger(items.into_iter().map(f).collect())
            }
            ConsensusProposal::Contribute(items) => {
                ConsensusProposal::Contribute(items.into_iter().map(f).collect())
            }
        }
    }

    pub fn forces_new_epoch(&self) -> bool {
        match self {
            ConsensusProposal::Trigger(_) => true,
            ConsensusProposal::Contribute(_) => false,
        }
    }

    pub fn items(&self) -> &[CI] {
        match self {
            ConsensusProposal::Trigger(items) => items,
            ConsensusProposal::Contribute(items) => items,
        }
    }

    pub fn into_items(self) -> Vec<CI> {
        match self {
            ConsensusProposal::Trigger(items) => items,
            ConsensusProposal::Contribute(items) => items,
        }
    }
}

/// Module associated types required by both client and server
pub trait ModuleCommon {
    type Input: Input;
    type Output: Output;
    type OutputOutcome: OutputOutcome;
    type ConsensusItem: ModuleConsensusItem;

    fn decoder_builder() -> DecoderBuilder {
        let mut decoder_builder = Decoder::builder();
        decoder_builder.with_decodable_type::<Self::Input>();
        decoder_builder.with_decodable_type::<Self::Output>();
        decoder_builder.with_decodable_type::<Self::OutputOutcome>();
        decoder_builder.with_decodable_type::<Self::ConsensusItem>();
        decoder_builder
    }

    fn decoder() -> Decoder {
        Self::decoder_builder().build()
    }
}

#[apply(async_trait_maybe_send!)]
pub trait ServerModule: Debug + Sized {
    type Common: ModuleCommon;

    type Gen: ServerModuleGen;
    type VerificationCache: VerificationCache;

    fn module_kind() -> ModuleKind {
        // Note: All modules should define kinds as &'static str, so this doesn't
        // allocate
        <Self::Gen as ExtendsCommonModuleGen>::Common::KIND
    }

    /// Returns a decoder for the following associated types of this module:
    /// * `Input`
    /// * `Output`
    /// * `OutputOutcome`
    /// * `ConsensusItem`
    fn decoder() -> Decoder {
        Self::Common::decoder_builder().build()
    }

    /// Module consensus version this module is running with and the API
    /// versions it supports in it
    fn supported_api_versions(&self) -> SupportedModuleApiVersions;

    /// Blocks until a new `consensus_proposal` is available.
    async fn await_consensus_proposal<'a>(&'a self, dbtx: &mut ModuleDatabaseTransaction<'_>);

    /// This module's contribution to the next consensus proposal
    async fn consensus_proposal<'a>(
        &'a self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> ConsensusProposal<<Self::Common as ModuleCommon>::ConsensusItem>;

    /// This function is called once before transaction processing starts.
    ///
    /// All module consensus items of this round are supplied as
    /// `consensus_items`. The database transaction will be committed to the
    /// database after all other modules ran `begin_consensus_epoch`, so the
    /// results are available when processing transactions. Returns any
    /// peers that need to be dropped.
    async fn begin_consensus_epoch<'a, 'b>(
        &'a self,
        dbtx: &mut ModuleDatabaseTransaction<'b>,
        consensus_items: Vec<(PeerId, <Self::Common as ModuleCommon>::ConsensusItem)>,
        consensus_peers: &BTreeSet<PeerId>,
    ) -> Vec<PeerId>;

    /// Some modules may have slow to verify inputs that would block transaction
    /// processing. If the slow part of verification can be modeled as a
    /// pure function not involving any system state we can build a lookup
    /// table in a hyper-parallelized manner. This function is meant for
    /// constructing such lookup tables.
    fn build_verification_cache<'a>(
        &'a self,
        inputs: impl Iterator<Item = &'a <Self::Common as ModuleCommon>::Input> + MaybeSend,
    ) -> Self::VerificationCache;

    /// Validate a transaction input before submitting it to the unconfirmed
    /// transaction pool. This function has no side effects and may be
    /// called at any time. False positives due to outdated database state
    /// are ok since they get filtered out after consensus has been reached on
    /// them and merely generate a warning.
    async fn validate_input<'a, 'b>(
        &self,
        interconnect: &dyn ModuleInterconect,
        dbtx: &mut ModuleDatabaseTransaction<'b>,
        verification_cache: &Self::VerificationCache,
        input: &'a <Self::Common as ModuleCommon>::Input,
    ) -> Result<InputMeta, ModuleError>;

    /// Try to spend a transaction input. On success all necessary updates will
    /// be part of the database transaction. On failure (e.g. double spend)
    /// the database transaction is rolled back and the operation will take
    /// no effect.
    ///
    /// This function may only be called after `begin_consensus_epoch` and
    /// before `end_consensus_epoch`. Data is only written to the database
    /// once all transactions have been processed.
    async fn apply_input<'a, 'b, 'c>(
        &'a self,
        interconnect: &'a dyn ModuleInterconect,
        dbtx: &mut ModuleDatabaseTransaction<'c>,
        input: &'b <Self::Common as ModuleCommon>::Input,
        verification_cache: &Self::VerificationCache,
    ) -> Result<InputMeta, ModuleError>;

    /// Validate a transaction output before submitting it to the unconfirmed
    /// transaction pool. This function has no side effects and may be
    /// called at any time. False positives due to outdated database state
    /// are ok since they get filtered out after consensus has been reached on
    /// them and merely generate a warning.
    async fn validate_output(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> Result<TransactionItemAmount, ModuleError>;

    /// Try to create an output (e.g. issue notes, peg-out BTC, …). On success
    /// all necessary updates to the database will be part of the database
    /// transaction. On failure (e.g. double spend) the database transaction
    /// is rolled back and the operation will take no effect.
    ///
    /// The supplied `out_point` identifies the operation (e.g. a peg-out or
    /// note issuance) and can be used to retrieve its outcome later using
    /// `output_status`.
    ///
    /// This function may only be called after `begin_consensus_epoch` and
    /// before `end_consensus_epoch`. Data is only written to the database
    /// once all transactions have been processed.
    async fn apply_output<'a, 'b>(
        &'a self,
        dbtx: &mut ModuleDatabaseTransaction<'b>,
        output: &'a <Self::Common as ModuleCommon>::Output,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmount, ModuleError>;

    /// This function is called once all transactions have been processed and
    /// changes were written to the database. This allows running
    /// finalization code before the next epoch.
    ///
    /// Passes in the `consensus_peers` that contributed to this epoch and
    /// returns a list of peers to drop if any are misbehaving.
    async fn end_consensus_epoch<'a, 'b>(
        &'a self,
        consensus_peers: &BTreeSet<PeerId>,
        dbtx: &mut ModuleDatabaseTransaction<'b>,
    ) -> Vec<PeerId>;

    /// Retrieve the current status of the output. Depending on the module this
    /// might contain data needed by the client to access funds or give an
    /// estimate of when funds will be available. Returns `None` if the
    /// output is unknown, **NOT** if it is just not ready yet.
    async fn output_status(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        out_point: OutPoint,
    ) -> Option<<Self::Common as ModuleCommon>::OutputOutcome>;

    /// Queries the database and returns all assets and liabilities of the
    /// module.
    ///
    /// Summing over all modules, if liabilities > assets then an error has
    /// occurred in the database and consensus should halt.
    async fn audit(&self, dbtx: &mut ModuleDatabaseTransaction<'_>, audit: &mut Audit);

    /// Returns a list of custom API endpoints defined by the module. These are
    /// made available both to users as well as to other modules. They thus
    /// should be deterministic, only dependant on their input and the
    /// current epoch.
    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>>;
}

/// Creates a struct that can be used to make our module-decodable structs
/// interact with `serde`-based APIs (HBBFT, jsonrpsee). It creates a wrapper
/// that holds the data as serialized
// bytes internally.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SerdeModuleEncoding<T: Encodable + Decodable>(Vec<u8>, #[serde(skip)] PhantomData<T>);

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
        // No recursive module decoding is supported since we give an empty decoder
        // registry to the decode function
        decoder.decode(
            &mut reader,
            module_instance,
            &ModuleDecoderRegistry::default(),
        )
    }
}

/// A handle passed to [`ServerModuleGen::distributed_gen`]
///
/// This struct encapsulates dkg data that the module should not have a direct
/// access to, and implements higher level dkg operations available to the
/// module to complete its distributed initialization inside the federation.
#[non_exhaustive]
pub struct PeerHandle<'a> {
    // TODO: this whole type should be a part of a `fedimint-server` and fields here inaccessible
    // to outside crates, but until `ServerModule` is not in `fedimint-server` this is impossible
    #[doc(hidden)]
    pub connections: &'a MuxPeerConnections<ModuleInstanceId, DkgPeerMsg>,
    #[doc(hidden)]
    pub module_instance_id: ModuleInstanceId,
    #[doc(hidden)]
    pub our_id: PeerId,
    #[doc(hidden)]
    pub peers: Vec<PeerId>,
}

impl<'a> PeerHandle<'a> {
    pub fn new(
        connections: &'a MuxPeerConnections<ModuleInstanceId, DkgPeerMsg>,
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
