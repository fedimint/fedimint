pub mod audit;
pub mod interconnect;
pub mod registry;

use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;

use async_trait::async_trait;
use bitcoin_hashes::sha256;
use bitcoin_hashes::sha256::Hash;
use futures::future::BoxFuture;
use secp256k1_zkp::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::instrument;

use crate::config::{ConfigGenParams, DkgPeerMsg, ServerModuleConfig};
use crate::core::{Decoder, DynDecoder, ModuleInstanceId, ModuleKind};
use crate::db::{Database, DatabaseTransaction, DatabaseVersion, MigrationMap};
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
        dbtx: &'a mut fedimint_core::db::DatabaseTransaction<'b>,
        params: Self::Param,
    ) -> Result<Self::Response, ApiError>;
}

#[doc(hidden)]
pub mod __reexports {
    pub use serde_json;
}

/// # Example
///
/// ```rust
/// # use fedimint_core::module::{api_endpoint, ApiEndpoint};
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
                $dbtx: &'a mut fedimint_core::db::DatabaseTransaction<'b>,
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

type HandlerFnReturn<'a> = BoxFuture<'a, Result<serde_json::Value, ApiError>>;
type HandlerFn<M> = Box<
    dyn for<'a> Fn(
            &'a M,
            fedimint_core::db::DatabaseTransaction<'a>,
            serde_json::Value,
            Option<ModuleInstanceId>,
        ) -> HandlerFnReturn<'a>
        + Send
        + Sync,
>;

/// Definition of an API endpoint defined by a module `M`.
pub struct ApiEndpoint<M> {
    /// Path under which the API endpoint can be reached. It should start with a
    /// `/` e.g. `/transaction`. E.g. this API endpoint would be reachable
    /// under `/module/module_instance_id/transaction` depending on the
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
            dbtx: &mut fedimint_core::db::DatabaseTransaction<'b>,
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
                        .map_err(|_err| fedimint_core::module::ApiError {
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

/// Interface for Module Generation
///
/// This trait contains the methods responsible for the module's
/// - initialization
/// - config generation
/// - config validation
///
/// Once the module configuration is ready, the module can be instantiated via
/// `[Self::init]`.
#[async_trait]
pub trait IModuleGen: Debug {
    fn decoder(&self) -> DynDecoder;

    fn versions(&self, core: CoreConsensusVersion) -> Vec<ModuleConsensusVersion>;

    fn module_kind(&self) -> ModuleKind;

    fn database_version(&self) -> DatabaseVersion;

    /// Initialize the [`DynServerModule`] instance from its config
    async fn init(
        &self,
        cfg: ServerModuleConfig,
        db: Database,
        env: &BTreeMap<OsString, OsString>,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<DynServerModule>;

    /// Retreives the `MigrationMap` from the module to be applied to the
    /// database before the module is initialized. The `MigrationMap` is
    /// indexed on the from version.
    fn get_database_migrations(&self) -> MigrationMap;

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
    ) -> DkgResult<ServerModuleConfig>;

    fn to_config_response(&self, config: serde_json::Value)
        -> anyhow::Result<ModuleConfigResponse>;

    fn hash_client_module(&self, config: serde_json::Value) -> anyhow::Result<sha256::Hash>;

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()>;

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_>;
}

dyn_newtype_define!(
    #[derive(Clone)]
    pub DynModuleGen(Arc<IModuleGen>)
);

/// Consensus version of a core server
///
/// Breaking changes in the Fedimint's core consensus require incrementing it.
///
/// See [`ModuleConsensusVersion`] for more details on how it interacts with
/// module's consensus.
#[derive(Debug, Copy, Clone)]
pub struct CoreConsensusVersion(pub u32);

/// Consensus version of a specific module instance
///
/// Any breaking change to the module's consensus rules require incrementing it.
///
/// A module instance can run only in one consensus version, which must be the
/// same accross all corresponding instances on other nodes of the federation.
///
/// When [`CoreConsensusVersion`] changes, this can but is not requires to be
/// a breaking change for each module's [`ModuleConsensusVersion`].
///
/// Incrementing the module's consensus version can be considered an in-place
/// upgrade path, similar to a blockchain hard-fork consensus upgrade.
///
/// As of time of writting this comment there are no plans to support any kind
/// of "soft-forks" which mean a consensus minor version. As the set of
/// federation member's is closed and limited, it is always preferable to
/// synchronize upgrade and avoid cross-version incompatibilities.
///
/// For many modules it might be preferable to implement a new [`ModuleKind`]
/// "versions" (to be implemented at the time of writting this comment), and
/// by running two instances of the module at the same time (each of different
/// `ModuleKind` version), allow users to slowly migrate to a new one.
/// This avoids complex and error-prone server-side consensus-migration logic.
#[derive(Debug, Copy, Clone)]
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
/// * Within that [`ModuleConsensusVersion`] during handshake negotation process
///   client and server must find at least one `Api::major` version where
///   client's `minor` is lower or equal server's `major` version.
///
/// A practical module implementation needs to implement large range of version
/// backward compatibility on both client and server side to accomodate end user
/// client devices receiving updates at a pace hard to control, and technical
/// and coordination challanges of upgrading servers.
#[derive(Debug, Copy, Clone)]
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

/// Module Generation trait with associated types
///
/// Needs to be implemented by module generation type
///
/// For examples, take a look at one of the `MintConfigGenerator`,
/// `WalletConfigGenerator`, or `LightningConfigGenerator` structs.
#[async_trait]
pub trait ModuleGen: Debug + Sized {
    const KIND: ModuleKind;

    /// This represents the module's database version that the current code is
    /// compatible with. It is important to increment this value whenever a
    /// key or a value that is persisted to the database within the module
    /// changes. It is also important to add the corresponding
    /// migration function in `get_database_migrations` which should define how
    /// to move from the previous database version to the current version.
    const DATABASE_VERSION: DatabaseVersion;

    type Decoder: Decoder;

    fn decoder(&self) -> Self::Decoder;

    /// Version of the module consensus supported by this implementation given a
    /// certain [`CoreConsensusVersion`].
    ///
    /// Refer to [`ModuleConsensusVersion`] for more information about
    /// versioning.
    ///
    /// One module implementation ([`ModuleGen`] of a given [`ModuleKind`]) can
    /// potentially implement multiple versions of the consensus, and
    /// depending on the config module instance config, instantiate the
    /// desired one. This method should expose all the available
    /// versions, purely for information, setup UI and sanity checking purposes.
    fn versions(&self, core: CoreConsensusVersion) -> &[ModuleConsensusVersion];

    /// Initialize the [`DynServerModule`] instance from its config
    async fn init(
        &self,
        cfg: ServerModuleConfig,
        db: Database,
        env: &BTreeMap<OsString, OsString>,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<DynServerModule>;

    /// Retreives the `MigrationMap` from the module to be applied to the
    /// database before the module is initialized. The `MigrationMap` is
    /// indexed on the from version.
    fn get_database_migrations(&self) -> MigrationMap {
        MigrationMap::new()
    }

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
    ) -> DkgResult<ServerModuleConfig>;

    fn to_config_response(&self, config: serde_json::Value)
        -> anyhow::Result<ModuleConfigResponse>;

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()>;

    fn hash_client_module(&self, config: serde_json::Value) -> anyhow::Result<sha256::Hash>;

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_>;
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

    fn database_version(&self) -> DatabaseVersion {
        <Self as ModuleGen>::DATABASE_VERSION
    }

    fn versions(&self, core: CoreConsensusVersion) -> Vec<ModuleConsensusVersion> {
        <Self as ModuleGen>::versions(self, core).to_vec()
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

    fn get_database_migrations(&self) -> MigrationMap {
        <Self as ModuleGen>::get_database_migrations(self)
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
    ) -> DkgResult<ServerModuleConfig> {
        <Self as ModuleGen>::distributed_gen(self, connections, our_id, module_id, peers, params)
            .await
    }

    fn to_config_response(
        &self,
        config: serde_json::Value,
    ) -> anyhow::Result<ModuleConfigResponse> {
        <Self as ModuleGen>::to_config_response(self, config)
    }

    fn hash_client_module(&self, config: serde_json::Value) -> anyhow::Result<Hash> {
        <Self as ModuleGen>::hash_client_module(self, config)
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        <Self as ModuleGen>::validate_config(self, identity, config)
    }

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        <Self as ModuleGen>::dump_database(self, dbtx, prefix_names).await
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

#[async_trait]
pub trait ServerModule: Debug + Sized {
    type Gen: ModuleGen;
    type Decoder: Decoder;
    type VerificationCache: VerificationCache;

    fn module_kind() -> ModuleKind {
        // Note: All modules should define kinds as &'static str, so this doesn't
        // allocate
        Self::Gen::KIND
    }

    fn decoder(&self) -> Self::Decoder;

    /// Module consensus version this module is running with and the API
    /// versions it supports in it
    fn versions(&self) -> (ModuleConsensusVersion, &[ApiVersion]);

    /// Blocks until a new `consensus_proposal` is available.
    async fn await_consensus_proposal<'a>(&'a self, dbtx: &mut DatabaseTransaction<'_>);

    /// This module's contribution to the next consensus proposal
    async fn consensus_proposal<'a>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> ConsensusProposal<<Self::Decoder as Decoder>::ConsensusItem>;

    /// This function is called once before transaction processing starts. All
    /// module consensus items of this round are supplied as
    /// `consensus_items`. The database transaction will be committed to the
    /// database after all other modules ran `begin_consensus_epoch`, so the
    /// results are available when processing transactions.
    async fn begin_consensus_epoch<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        consensus_items: Vec<(PeerId, <Self::Decoder as Decoder>::ConsensusItem)>,
    );

    /// Some modules may have slow to verify inputs that would block transaction
    /// processing. If the slow part of verification can be modeled as a
    /// pure function not involving any system state we can build a lookup
    /// table in a hyper-parallelized manner. This function is meant for
    /// constructing such lookup tables.
    fn build_verification_cache<'a>(
        &'a self,
        inputs: impl Iterator<Item = &'a <Self::Decoder as Decoder>::Input> + Send,
    ) -> Self::VerificationCache;

    /// Validate a transaction input before submitting it to the unconfirmed
    /// transaction pool. This function has no side effects and may be
    /// called at any time. False positives due to outdated database state
    /// are ok since they get filtered out after consensus has been reached on
    /// them and merely generate a warning.
    async fn validate_input<'a, 'b>(
        &self,
        interconnect: &dyn ModuleInterconect,
        dbtx: &mut DatabaseTransaction<'b>,
        verification_cache: &Self::VerificationCache,
        input: &'a <Self::Decoder as Decoder>::Input,
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
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b <Self::Decoder as Decoder>::Input,
        verification_cache: &Self::VerificationCache,
    ) -> Result<InputMeta, ModuleError>;

    /// Validate a transaction output before submitting it to the unconfirmed
    /// transaction pool. This function has no side effects and may be
    /// called at any time. False positives due to outdated database state
    /// are ok since they get filtered out after consensus has been reached on
    /// them and merely generate a warning.
    async fn validate_output(
        &self,
        dbtx: &mut DatabaseTransaction,
        output: &<Self::Decoder as Decoder>::Output,
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
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a <Self::Decoder as Decoder>::Output,
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
        consensus_peers: &HashSet<PeerId>,
        dbtx: &mut DatabaseTransaction<'b>,
    ) -> Vec<PeerId>;

    /// Retrieve the current status of the output. Depending on the module this
    /// might contain data needed by the client to access funds or give an
    /// estimate of when funds will be available. Returns `None` if the
    /// output is unknown, **NOT** if it is just not ready yet.
    async fn output_status(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        out_point: OutPoint,
    ) -> Option<<Self::Decoder as Decoder>::OutputOutcome>;

    /// Queries the database and returns all assets and liabilities of the
    /// module.
    ///
    /// Summing over all modules, if liabilities > assets then an error has
    /// occurred in the database and consensus should halt.
    async fn audit(&self, dbtx: &mut DatabaseTransaction<'_>, audit: &mut Audit);

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

impl<T: Encodable + Decodable> SerdeModuleEncoding<T> {
    pub fn try_into_inner(&self, modules: &ModuleDecoderRegistry) -> Result<T, DecodeError> {
        let mut reader = std::io::Cursor::new(&self.0);
        Decodable::consensus_decode(&mut reader, modules)
    }
}
