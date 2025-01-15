//! Core module system traits and types.
//!
//! Fedimint supports modules to allow extending its functionality.
//! Some of the standard functionality is implemented in form of modules as
//! well. This rust module houses the core trait
//! [`fedimint_core::module::ModuleCommon`] used by both the server and client
//! side module traits. Specific server and client traits exist in their
//! respective crates.
//!
//! The top level server-side types are:
//!
//! * `fedimint_server::core::ServerModuleInit`
//! * `fedimint_server::core::ServerModule`
//!
//! Top level client-side types are:
//!
//! * `ClientModuleInit` (in `fedimint_client`)
//! * `ClientModule` (in `fedimint_client`)
pub mod audit;
pub mod registry;

use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use fedimint_logging::LOG_NET_API;
use futures::Future;
use jsonrpsee_core::JsonValue;
use registry::ModuleRegistry;
use serde::{Deserialize, Serialize};
use tracing::Instrument;

// TODO: Make this module public and remove the wildcard `pub use` below
mod version;
pub use self::version::*;
use crate::config::DkgPeerMsg;
use crate::core::{
    ClientConfig, Decoder, DecoderBuilder, Input, InputError, ModuleConsensusItem,
    ModuleInstanceId, ModuleKind, Output, OutputError, OutputOutcome,
};
use crate::db::{
    Committable, Database, DatabaseKey, DatabaseKeyWithNotify, DatabaseRecord, DatabaseTransaction,
};
use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::fmt_utils::AbbreviateHexBytes;
use crate::net::peers::DynP2PConnections;
use crate::task::MaybeSend;
use crate::{apply, async_trait_maybe_send, maybe_add_send, maybe_add_send_sync, Amount, PeerId};

#[derive(Debug, PartialEq, Eq)]
pub struct InputMeta {
    pub amount: TransactionItemAmount,
    pub pub_key: secp256k1::PublicKey,
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
    pub const ZERO: Self = Self {
        amount: Amount::ZERO,
        fee: Amount::ZERO,
    };
}

/// All requests from client to server contain these fields
#[derive(Debug, Serialize, Deserialize, Clone)]
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
    pub fn new<T: Serialize>(params: T) -> Self {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

    pub fn db(&self) -> Database {
        self.db.clone()
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

    /// Attempts to commit the dbtx or returns an `ApiError`
    pub async fn commit_tx_result(self, path: &'static str) -> Result<(), ApiError> {
        self.dbtx.commit_tx_result().await.map_err(|err| {
            tracing::warn!(
                target: fedimint_logging::LOG_NET_API,
                path,
                "API server error when writing to database: {:?}",
                err
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

pub use serde_json;

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
            #[allow(deprecated)]
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
use fedimint_core::NumPeers;

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

/// Global request ID used for logging
static REQ_ID: AtomicU64 = AtomicU64::new(0);

// <()> is used to avoid specify state.
impl ApiEndpoint<()> {
    pub fn from_typed<E: TypedApiEndpoint>() -> ApiEndpoint<E::State>
    where
        <E as TypedApiEndpoint>::Response: MaybeSend,
        E::Param: Debug,
        E::Response: Debug,
    {
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
            tracing::debug!(target: LOG_NET_API, path = E::PATH, ?request, "received api request");
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
                Box::pin(async {
                    let request = request
                        .to_typed()
                        .map_err(|e| ApiError::bad_request(e.to_string()))?;

                    let span = tracing::info_span!(
                        target: LOG_NET_API,
                        "api_req",
                        id = REQ_ID.fetch_add(1, Ordering::SeqCst),
                        method = E::PATH,
                    );
                    let ret = handle_request::<E>(m, &mut context, request)
                        .instrument(span)
                        .await?;

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

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_>;
}

/// Trait implemented by every `*ModuleInit` (server or client side)
pub trait ModuleInit: Debug + Clone + Send + Sync + 'static {
    type Common: CommonModuleInit;

    fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> maybe_add_send!(
        impl Future<
            Output = Box<
                dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_,
            >,
        >
    );
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

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        <Self as ModuleInit>::dump_database(self, dbtx, prefix_names).await
    }
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
        Self { inner }
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

/// Creates a struct that can be used to make our module-decodable structs
/// interact with `serde`-based APIs (AlephBFT, jsonrpsee). It creates a wrapper
/// that holds the data as serialized
// bytes internally.
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SerdeModuleEncoding<T: Encodable + Decodable>(
    #[serde(with = "::fedimint_core::encoding::as_hex")] Vec<u8>,
    #[serde(skip)] PhantomData<T>,
);

/// Same as [`SerdeModuleEncoding`] but uses base64 instead of hex encoding.
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SerdeModuleEncodingBase64<T: Encodable + Decodable>(
    #[serde(with = "::fedimint_core::encoding::as_base64")] Vec<u8>,
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
        Decodable::consensus_decode_whole(&self.0, modules)
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
        let module_instance = ModuleInstanceId::consensus_decode_partial(
            &mut reader,
            &ModuleDecoderRegistry::default(),
        )?;

        let total_len =
            u64::consensus_decode_partial(&mut reader, &ModuleDecoderRegistry::default())?;

        // No recursive module decoding is supported since we give an empty decoder
        // registry to the decode function
        decoder.decode_complete(
            &mut reader,
            total_len,
            module_instance,
            &ModuleRegistry::default(),
        )
    }
}

impl<T> fmt::Debug for SerdeModuleEncodingBase64<T>
where
    T: Encodable + Decodable,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("SerdeModuleEncoding2(")?;
        fmt::Debug::fmt(&AbbreviateHexBytes(&self.0), f)?;
        f.write_str(")")?;
        Ok(())
    }
}

impl<T: Encodable + Decodable> From<&T> for SerdeModuleEncodingBase64<T> {
    fn from(value: &T) -> Self {
        let mut bytes = vec![];
        fedimint_core::encoding::Encodable::consensus_encode(value, &mut bytes)
            .expect("Writing to buffer can never fail");
        Self(bytes, PhantomData)
    }
}

impl<T: Encodable + Decodable + 'static> SerdeModuleEncodingBase64<T> {
    pub fn try_into_inner(&self, modules: &ModuleDecoderRegistry) -> Result<T, DecodeError> {
        Decodable::consensus_decode_whole(&self.0, modules)
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
        let module_instance = ModuleInstanceId::consensus_decode_partial(
            &mut reader,
            &ModuleDecoderRegistry::default(),
        )?;

        let total_len =
            u64::consensus_decode_partial(&mut reader, &ModuleDecoderRegistry::default())?;

        // No recursive module decoding is supported since we give an empty decoder
        // registry to the decode function
        decoder.decode_complete(
            &mut reader,
            total_len,
            module_instance,
            &ModuleRegistry::default(),
        )
    }
}

/// A handle passed to `ServerModuleInit::distributed_gen`
///
/// This struct encapsulates dkg data that the module should not have a direct
/// access to, and implements higher level dkg operations available to the
/// module to complete its distributed initialization inside the federation.
#[non_exhaustive]
pub struct PeerHandle<'a> {
    // TODO: this whole type should be a part of a `fedimint-server` and fields here inaccessible
    // to outside crates, but until `ServerModule` is not in `fedimint-server` this is impossible
    #[doc(hidden)]
    pub num_peers: NumPeers,
    #[doc(hidden)]
    pub identity: PeerId,
    #[doc(hidden)]
    pub connections: &'a DynP2PConnections<DkgPeerMsg>,
}

impl<'a> PeerHandle<'a> {
    pub fn new(
        num_peers: NumPeers,
        identity: PeerId,
        connections: &'a DynP2PConnections<DkgPeerMsg>,
    ) -> Self {
        Self {
            num_peers,
            identity,
            connections,
        }
    }

    pub fn num_peers(&self) -> NumPeers {
        self.num_peers
    }
}
