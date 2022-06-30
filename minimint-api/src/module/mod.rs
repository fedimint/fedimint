pub mod interconnect;
pub mod testing;

use crate::db::batch::BatchTx;
use crate::{Amount, PeerId};
use async_trait::async_trait;
use rand::CryptoRng;
use secp256k1_zkp::rand::RngCore;
use secp256k1_zkp::XOnlyPublicKey;
use std::collections::{HashMap, HashSet};

use crate::module::interconnect::ModuleInterconect;
pub use http_types as http;

pub struct InputMeta<'a> {
    pub amount: Amount,
    pub puk_keys: Box<dyn Iterator<Item = XOnlyPublicKey> + 'a>,
}

/// Map of URL parameters and their values.
pub type Params<'a> = HashMap<&'static str, &'a str>;

/// Definition of an API endpoint defined by a module `M`.
pub struct ApiEndpoint<M> {
    /// Path under which the API endpoint can be reached. It should start with a `/` and may contain
    /// parameters using the `:param` syntax, e.g. `/transaction/:txid`. E.g. this API endpoint
    /// would be reachable under `/module_name/transaction/:txid` depending on the module name
    /// returned by `[FedertionModule::api_base_name]`.
    pub path_spec: &'static str,
    /// List of parameter names used in `path_spec`. // TODO: maybe use lazy_static instead?
    pub params: &'static [&'static str],
    /// HTTP method that the API endpoint expects
    pub method: http_types::Method,
    /// Handler for the API call that takes the following arguments:
    ///   * Reference to the module which defined it
    ///   * URL parameter map
    ///   * Request body parsed into JSON `[Value](serde_json::Value)`
    pub handler: fn(&M, Params, serde_json::Value) -> http_types::Result<http_types::Response>,
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
        batch: BatchTx<'a>,
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
    fn apply_input<'a, 'b>(
        &'a self,
        interconnect: &'a dyn ModuleInterconect,
        batch: BatchTx<'a>,
        input: &'b Self::TxInput,
        verification_cache: &Self::VerificationCache,
    ) -> Result<InputMeta<'b>, Self::Error>;

    /// Validate a transaction output before submitting it to the unconfirmed transaction pool. This
    /// function has no side effects and may be called at any time. False positives due to outdated
    /// database state are ok since they get filtered out after consensus has been reached on them
    /// and merely generate a warning.
    fn validate_output(&self, output: &Self::TxOutput) -> Result<Amount, Self::Error>;

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
    fn apply_output<'a>(
        &'a self,
        batch: BatchTx<'a>,
        output: &'a Self::TxOutput,
        out_point: crate::OutPoint,
    ) -> Result<Amount, Self::Error>;

    /// This function is called once all transactions have been processed and changes were written
    /// to the database. This allows running finalization code before the next epoch.
    ///
    /// Passes in the `consensus_peers` that contributed to this epoch and returns a list of peers
    /// to drop if any are misbehaving.
    async fn end_consensus_epoch<'a>(
        &'a self,
        consensus_peers: &HashSet<PeerId>,
        batch: BatchTx<'a>,
        rng: impl RngCore + CryptoRng + 'a,
    ) -> Vec<PeerId>;

    /// Retrieve the current status of the output. Depending on the module this might contain data
    /// needed by the client to access funds or give an estimate of when funds will be available.
    /// Returns `None` if the output is unknown, **NOT** if it is just not ready yet.
    fn output_status(&self, out_point: crate::OutPoint) -> Option<Self::TxOutputOutcome>;

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
