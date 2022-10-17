pub mod audit;
pub mod interconnect;
pub mod testing;

use std::collections::HashSet;

use async_trait::async_trait;
use futures::future::BoxFuture;
use rand::CryptoRng;
use secp256k1_zkp::rand::RngCore;
use secp256k1_zkp::XOnlyPublicKey;

use crate::db::DatabaseTransaction;
use crate::module::audit::Audit;
use crate::module::interconnect::ModuleInterconect;
use crate::{Amount, PeerId};

pub struct InputMeta<'a> {
    pub amount: TransactionItemAmount,
    pub puk_keys: Box<dyn Iterator<Item = XOnlyPublicKey> + 'a>,
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

    async fn handle(state: &Self::State, params: Self::Param) -> Result<Self::Response, ApiError>;
}

#[doc(hidden)]
pub mod __reexports {
    pub use serde_json;
}

/// # Example
///
/// ```rust
/// # use fedimint_api::module::{api_endpoint, ApiEndpoint};
/// struct State;
///
/// let _: ApiEndpoint<State> = api_endpoint! {
///     "/foobar",
///     async |state: &State, params: ()| -> i32 {
///         Ok(0)
///     }
/// };
/// ```
#[macro_export]
macro_rules! __api_endpoint {
    (
        $path:expr,
        async |$state:ident: &$state_ty:ty, $param:ident: $param_ty:ty| -> $resp_ty:ty $body:block
    ) => {{
        struct Endpoint;

        #[async_trait::async_trait]
        impl $crate::module::TypedApiEndpoint for Endpoint {
            const PATH: &'static str = $path;
            type State = $state_ty;
            type Param = $param_ty;
            type Response = $resp_ty;

            async fn handle(
                $state: &Self::State,
                $param: Self::Param,
            ) -> ::std::result::Result<Self::Response, $crate::module::ApiError> {
                $body
            }
        }

        ApiEndpoint {
            path: <Endpoint as $crate::module::TypedApiEndpoint>::PATH,
            handler: |m, param| {
                Box::pin(async move {
                    let params = $crate::module::__reexports::serde_json::from_value(param)
                        .map_err(|e| $crate::module::ApiError::bad_request(e.to_string()))?;

                    let ret =
                        <Endpoint as $crate::module::TypedApiEndpoint>::handle(m, params).await?;
                    Ok($crate::module::__reexports::serde_json::to_value(ret)
                        .expect("encoding error"))
                })
            },
        }
    }};
}

pub use __api_endpoint as api_endpoint;

/// Definition of an API endpoint defined by a module `M`.
pub struct ApiEndpoint<M> {
    /// Path under which the API endpoint can be reached. It should start with a `/`
    /// e.g. `/transaction`. E.g. this API endpoint would be reachable under `/module_name/transaction`
    /// depending on the module name returned by `[FedertionModule::api_base_name]`.
    pub path: &'static str,
    /// Handler for the API call that takes the following arguments:
    ///   * Reference to the module which defined it
    ///   * Request parameters parsed into JSON `[Value](serde_json::Value)`
    pub handler:
        for<'a> fn(&'a M, serde_json::Value) -> BoxFuture<'a, Result<serde_json::Value, ApiError>>,
}

#[async_trait(?Send)]
pub trait FederationModule: Sized {
    type Error;
    type TxInput: Send + Sync;
    type TxOutput;
    type TxOutputOutcome;
    type ConsensusItem;
    type VerificationCache;

    /// Blocks until a new `consensus_proposal` is available.
    async fn await_consensus_proposal<'a>(&'a self, rng: impl RngCore + CryptoRng + 'a);

    /// This module's contribution to the next consensus proposal
    async fn consensus_proposal<'a>(
        &'a self,
        rng: impl RngCore + CryptoRng + 'a,
    ) -> Vec<Self::ConsensusItem>;

    /// This function is called once before transaction processing starts. All module consensus
    /// items of this round are supplied as `consensus_items`. The batch will be committed to the
    /// database after all other modules ran `begin_consensus_epoch`, so the results are available
    /// when processing transactions.
    async fn begin_consensus_epoch<'a>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'a>,
        consensus_items: Vec<(PeerId, Self::ConsensusItem)>,
        rng: impl RngCore + CryptoRng + 'a,
    );

    /// Some modules may have slow to verify inputs that would block transaction processing. If the
    /// slow part of verification can be modeled as a pure function not involving any system state
    /// we can build a lookup table in a hyper-parallelized manner. This function is meant for
    /// constructing such lookup tables.
    fn build_verification_cache<'a>(
        &'a self,
        inputs: impl Iterator<Item = &'a Self::TxInput> + Send,
    ) -> Self::VerificationCache;

    /// Validate a transaction input before submitting it to the unconfirmed transaction pool. This
    /// function has no side effects and may be called at any time. False positives due to outdated
    /// database state are ok since they get filtered out after consensus has been reached on them
    /// and merely generate a warning.
    fn validate_input<'a>(
        &self,
        interconnect: &dyn ModuleInterconect,
        verification_cache: &Self::VerificationCache,
        input: &'a Self::TxInput,
    ) -> Result<InputMeta<'a>, Self::Error>;

    /// Try to spend a transaction input. On success all necessary updates will be part of the
    /// database `batch`. On failure (e.g. double spend) the batch is reset and the operation will
    /// take no effect.
    ///
    /// This function may only be called after `begin_consensus_epoch` and before
    /// `end_consensus_epoch`. Data is only written to the database once all transaction have been
    /// processed.
    fn apply_input<'a, 'b, 'c>(
        &'a self,
        interconnect: &'a dyn ModuleInterconect,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b Self::TxInput,
        verification_cache: &Self::VerificationCache,
    ) -> Result<InputMeta<'b>, Self::Error>;

    /// Validate a transaction output before submitting it to the unconfirmed transaction pool. This
    /// function has no side effects and may be called at any time. False positives due to outdated
    /// database state are ok since they get filtered out after consensus has been reached on them
    /// and merely generate a warning.
    fn validate_output(
        &self,
        output: &Self::TxOutput,
    ) -> Result<TransactionItemAmount, Self::Error>;

    /// Try to create an output (e.g. issue coins, peg-out BTC, …). On success all necessary updates
    /// to the database will be part of the `batch`. On failure (e.g. double spend) the batch is
    /// reset and the operation will take no effect.
    ///
    /// The supplied `out_point` identifies the operation (e.g. a peg-out or coin issuance) and can
    /// be used to retrieve its outcome later using `output_status`.
    ///
    /// This function may only be called after `begin_consensus_epoch` and before
    /// `end_consensus_epoch`. Data is only written to the database once all transactions have been
    /// processed.
    fn apply_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a Self::TxOutput,
        out_point: crate::OutPoint,
    ) -> Result<TransactionItemAmount, Self::Error>;

    /// This function is called once all transactions have been processed and changes were written
    /// to the database. This allows running finalization code before the next epoch.
    ///
    /// Passes in the `consensus_peers` that contributed to this epoch and returns a list of peers
    /// to drop if any are misbehaving.
    async fn end_consensus_epoch<'a>(
        &'a self,
        consensus_peers: &HashSet<PeerId>,
        dbtx: &mut DatabaseTransaction<'a>,
        rng: impl RngCore + CryptoRng + 'a,
    ) -> Vec<PeerId>;

    /// Retrieve the current status of the output. Depending on the module this might contain data
    /// needed by the client to access funds or give an estimate of when funds will be available.
    /// Returns `None` if the output is unknown, **NOT** if it is just not ready yet.
    fn output_status(&self, out_point: crate::OutPoint) -> Option<Self::TxOutputOutcome>;

    /// Queries the database and returns all assets and liabilities of the module.
    ///
    /// Summing over all modules, if liabilities > assets then an error has occurred in the database
    /// and consensus should halt.
    fn audit(&self, audit: &mut Audit);

    /// Defines the prefix for API endpoints defined by the module.
    ///
    /// E.g. if the module's base path is `foo` and it defines API endpoints `bar` and `baz` then
    /// these endpoints will be reachable under `/foo/bar` and `/foo/baz`.
    fn api_base_name(&self) -> &'static str;

    /// Returns a list of custom API endpoints defined by the module. These are made available both
    /// to users as well as to other modules. They thus should be deterministic, only dependant on
    /// their input and the current epoch.
    fn api_endpoints(&self) -> &'static [ApiEndpoint<Self>];
}
