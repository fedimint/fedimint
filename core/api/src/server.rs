//! Fedimint Core Server module interface
//!
//! Fedimint supports externally implemented modules.
//!
//! This (Rust) module defines common interoperability types
//! and functionality that are only used on the server side.
use async_trait::async_trait;
use bitcoin::XOnlyPublicKey;
use fedimint_api::{
    db::batch::BatchTx,
    encoding::DynEncodable,
    module::{__reexports::serde_json, audit::Audit, interconnect::ModuleInterconect, ApiError},
    Amount, OutPoint, PeerId,
};
use impl_tools::autoimpl;
use std::{collections::HashSet, sync::Arc};
use thiserror::Error;

use super::*;

/// Api Endpoint exposed by a server side module
pub struct ApiEndpoint {
    pub path: String,
    pub handler: ApiHandler,
}

#[async_trait]
pub trait ModuleApiHandler {
    async fn handle(&self, params: &serde_json::Value) -> Result<serde_json::Value, ApiError>;
}

dyn_newtype_define! {
    /// [`ApiEndpoint`] handler exposed by the server side module
    ApiHandler(Box<ModuleApiHandler>)
}

pub trait ModuleConsensusItem: DynEncodable {
    fn as_any(&self) -> &(dyn Any + '_);
    fn module_key(&self) -> ModuleKey;
    fn clone(&self) -> ConsensusItem;
}

dyn_newtype_define! {
    ConsensusItem(Box<ModuleConsensusItem>)
}
dyn_newtype_impl_dyn_clone_passhthrough!(ConsensusItem);
module_plugin_trait_define!(ConsensusItem, PluginConsensusItem, ModuleConsensusItem, {} {});

pub trait ModuleVerificationCache: DynEncodable {
    fn as_any(&self) -> &(dyn Any + '_);
    fn module_key(&self) -> ModuleKey;
    fn clone(&self) -> VerificationCache;
}

dyn_newtype_define! {
    VerificationCache(Box<ModuleVerificationCache>)
}
module_plugin_trait_define!(
    VerificationCache,
    PluginVerificationCache,
    ModuleVerificationCache,
    {} {}
);

#[derive(Error, Debug)]
pub enum Error {
    #[error("oops")]
    SomethingWentWrong,
}

pub struct InputMeta {
    pub amount: Amount,
    pub puk_keys: Vec<XOnlyPublicKey>,
}

/// Backend side module interface
///
/// Server side Fedimint mondule needs to implement this trait.
#[async_trait(?Send)]
pub trait IServerModule: ModuleCommon {
    /// Initialize the module on registration in Fedimint
    fn init(&self);

    /// Blocks until a new `consensus_proposal` is available.
    async fn await_consensus_proposal(&self);

    /// This module's contribution to the next consensus proposal
    async fn consensus_proposal(&self) -> Vec<ConsensusItem>;

    /// This function is called once before transaction processing starts. All module consensus
    /// items of this round are supplied as `consensus_items`. The batch will be committed to the
    /// database after all other modules ran `begin_consensus_epoch`, so the results are available
    /// when processing transactions.
    async fn begin_consensus_epoch(
        &self,
        batch: BatchTx<'_>,
        consensus_items: Vec<(PeerId, ConsensusItem)>,
    );

    /// Some modules may have slow to verify inputs that would block transaction processing. If the
    /// slow part of verification can be modeled as a pure function not involving any system state
    /// we can build a lookup table in a hyper-parallelized manner. This function is meant for
    /// constructing such lookup tables.
    fn build_verification_cache(&self, inputs: &[Input]) -> VerificationCache;

    /// Validate a transaction input before submitting it to the unconfirmed transaction pool. This
    /// function has no side effects and may be called at any time. False positives due to outdated
    /// database state are ok since they get filtered out after consensus has been reached on them
    /// and merely generate a warning.
    fn validate_input(
        &self,
        interconnect: &dyn ModuleInterconect,
        verification_cache: &VerificationCache,
        input: &Input,
    ) -> Result<InputMeta, Error>;

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
        input: &'b Input,
        verification_cache: &VerificationCache,
    ) -> Result<InputMeta, Error>;

    /// Validate a transaction output before submitting it to the unconfirmed transaction pool. This
    /// function has no side effects and may be called at any time. False positives due to outdated
    /// database state are ok since they get filtered out after consensus has been reached on them
    /// and merely generate a warning.
    fn validate_output(&self, output: &Output) -> Result<Amount, Error>;

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
    fn apply_output(
        &self,
        batch: BatchTx<'_>,
        output: &Output,
        out_point: OutPoint,
    ) -> Result<Amount, Error>;

    /// This function is called once all transactions have been processed and changes were written
    /// to the database. This allows running finalization code before the next epoch.
    ///
    /// Passes in the `consensus_peers` that contributed to this epoch and returns a list of peers
    /// to drop if any are misbehaving.
    async fn end_consensus_epoch(
        &self,
        consensus_peers: &HashSet<PeerId>,
        batch: BatchTx<'_>,
    ) -> Vec<PeerId>;

    /// Retrieve the current status of the output. Depending on the module this might contain data
    /// needed by the client to access funds or give an estimate of when funds will be available.
    /// Returns `None` if the output is unknown, **NOT** if it is just not ready yet.
    fn output_status(&self, out_point: OutPoint) -> Option<OutputOutcome>;

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
    fn api_endpoints(&self) -> Vec<ApiEndpoint>;
}

#[derive(Clone)]
#[autoimpl(Deref using self.0)]
pub struct ServerModule(Arc<dyn IServerModule + Send + Sync + 'static>);

impl<I> From<I> for ServerModule
where
    I: IServerModule + Send + Sync + 'static,
{
    fn from(i: I) -> Self {
        Self(Arc::new(i))
    }
}

#[async_trait(?Send)]
pub trait ServerModulePlugin: Sized {
    type Input: PluginInput;
    type Output: PluginOutput;
    type PendingOutput: PluginPendingOutput;
    type SpendableOutput: PluginSpendableOutput;
    type OutputOutcome: PluginOutputOutcome;
    type ConsensusItem: PluginConsensusItem;
    type VerificationCache: PluginVerificationCache;

    fn init(&self);

    /// Blocks until a new `consensus_proposal` is available.
    async fn await_consensus_proposal<'a>(&'a self);

    /// This module's contribution to the next consensus proposal
    async fn consensus_proposal<'a>(&'a self) -> Vec<Self::ConsensusItem>;

    /// This function is called once before transaction processing starts. All module consensus
    /// items of this round are supplied as `consensus_items`. The batch will be committed to the
    /// database after all other modules ran `begin_consensus_epoch`, so the results are available
    /// when processing transactions.
    async fn begin_consensus_epoch<'a>(
        &'a self,
        batch: BatchTx<'a>,
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
    fn validate_input<'a>(
        &self,
        interconnect: &dyn ModuleInterconect,
        verification_cache: &Self::VerificationCache,
        input: &'a Self::Input,
    ) -> Result<InputMeta, Error>;

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
        input: &'b Self::Input,
        verification_cache: &Self::VerificationCache,
    ) -> Result<InputMeta, Error>;

    /// Validate a transaction output before submitting it to the unconfirmed transaction pool. This
    /// function has no side effects and may be called at any time. False positives due to outdated
    /// database state are ok since they get filtered out after consensus has been reached on them
    /// and merely generate a warning.
    fn validate_output(&self, output: &Self::Output) -> Result<Amount, Error>;

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
        output: &'a Self::Output,
        out_point: OutPoint,
    ) -> Result<Amount, Error>;

    /// This function is called once all transactions have been processed and changes were written
    /// to the database. This allows running finalization code before the next epoch.
    ///
    /// Passes in the `consensus_peers` that contributed to this epoch and returns a list of peers
    /// to drop if any are misbehaving.
    async fn end_consensus_epoch<'a>(
        &'a self,
        consensus_peers: &HashSet<PeerId>,
        batch: BatchTx<'a>,
    ) -> Vec<PeerId>;

    /// Retrieve the current status of the output. Depending on the module this might contain data
    /// needed by the client to access funds or give an estimate of when funds will be available.
    /// Returns `None` if the output is unknown, **NOT** if it is just not ready yet.
    fn output_status(&self, out_point: OutPoint) -> Option<Self::OutputOutcome>;

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
    fn api_endpoints(&self) -> Vec<ApiEndpoint>;
}

#[async_trait(?Send)]
impl<T> IServerModule for T
where
    T: ServerModulePlugin,
    T: ModuleCommon,
{
    fn init(&self) {
        <Self as ServerModulePlugin>::init(self)
    }

    /// Blocks until a new `consensus_proposal` is available.
    async fn await_consensus_proposal(&self) {
        <Self as ServerModulePlugin>::await_consensus_proposal(self).await
    }

    /// This module's contribution to the next consensus proposal
    async fn consensus_proposal(&self) -> Vec<ConsensusItem> {
        <Self as ServerModulePlugin>::consensus_proposal(self)
            .await
            .into_iter()
            .map(Into::into)
            .collect()
    }

    /// This function is called once before transaction processing starts. All module consensus
    /// items of this round are supplied as `consensus_items`. The batch will be committed to the
    /// database after all other modules ran `begin_consensus_epoch`, so the results are available
    /// when processing transactions.
    async fn begin_consensus_epoch(
        &self,
        batch: BatchTx<'_>,
        consensus_items: Vec<(PeerId, ConsensusItem)>,
    ) {
        <Self as ServerModulePlugin>::begin_consensus_epoch(
            self,
            batch,
            consensus_items
                .into_iter()
                .map(|(peer, item)| {
                    (
                        peer,
                        Clone::clone(
                            item.as_any()
                                .downcast_ref::<<Self as ServerModulePlugin>::ConsensusItem>()
                                .expect("incorrect consensus item type passed to module plugin"),
                        ),
                    )
                })
                .collect(),
        )
        .await
    }

    /// Some modules may have slow to verify inputs that would block transaction processing. If the
    /// slow part of verification can be modeled as a pure function not involving any system state
    /// we can build a lookup table in a hyper-parallelized manner. This function is meant for
    /// constructing such lookup tables.
    fn build_verification_cache<'a>(&self, inputs: &[Input]) -> VerificationCache {
        <Self as ServerModulePlugin>::build_verification_cache(
            self,
            inputs.iter().map(|i| {
                i.as_any()
                    .downcast_ref::<<Self as ServerModulePlugin>::Input>()
                    .expect("incorrect input type passed to module plugin")
            }),
        )
        .into()
    }

    /// Validate a transaction input before submitting it to the unconfirmed transaction pool. This
    /// function has no side effects and may be called at any time. False positives due to outdated
    /// database state are ok since they get filtered out after consensus has been reached on them
    /// and merely generate a warning.
    fn validate_input(
        &self,
        interconnect: &dyn ModuleInterconect,
        verification_cache: &VerificationCache,
        input: &Input,
    ) -> Result<InputMeta, Error> {
        <Self as ServerModulePlugin>::validate_input(
            self,
            interconnect,
            verification_cache
                .as_any()
                .downcast_ref::<<Self as ServerModulePlugin>::VerificationCache>()
                .expect("incorrect verification cache type passed to module plugin"),
            input
                .as_any()
                .downcast_ref::<<Self as ServerModulePlugin>::Input>()
                .expect("incorrect input type passed to module plugin"),
        )
        .map(Into::into)
    }

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
        input: &'b Input,
        verification_cache: &VerificationCache,
    ) -> Result<InputMeta, Error> {
        <Self as ServerModulePlugin>::apply_input(
            self,
            interconnect,
            batch,
            input
                .as_any()
                .downcast_ref::<<Self as ServerModulePlugin>::Input>()
                .expect("incorrect input type passed to module plugin"),
            verification_cache
                .as_any()
                .downcast_ref::<<Self as ServerModulePlugin>::VerificationCache>()
                .expect("incorrect verification cache type passed to module plugin"),
        )
        .map(Into::into)
    }

    /// Validate a transaction output before submitting it to the unconfirmed transaction pool. This
    /// function has no side effects and may be called at any time. False positives due to outdated
    /// database state are ok since they get filtered out after consensus has been reached on them
    /// and merely generate a warning.
    fn validate_output(&self, output: &Output) -> Result<Amount, Error> {
        <Self as ServerModulePlugin>::validate_output(
            self,
            output
                .as_any()
                .downcast_ref::<<Self as ServerModulePlugin>::Output>()
                .expect("incorrect output type passed to module plugin"),
        )
    }

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
    fn apply_output(
        &self,
        batch: BatchTx<'_>,
        output: &Output,
        out_point: OutPoint,
    ) -> Result<Amount, Error> {
        <Self as ServerModulePlugin>::apply_output(
            self,
            batch,
            output
                .as_any()
                .downcast_ref::<<Self as ServerModulePlugin>::Output>()
                .expect("incorrect output type passed to module plugin"),
            out_point,
        )
    }

    /// This function is called once all transactions have been processed and changes were written
    /// to the database. This allows running finalization code before the next epoch.
    ///
    /// Passes in the `consensus_peers` that contributed to this epoch and returns a list of peers
    /// to drop if any are misbehaving.
    async fn end_consensus_epoch(
        &self,
        consensus_peers: &HashSet<PeerId>,
        batch: BatchTx<'_>,
    ) -> Vec<PeerId> {
        <Self as ServerModulePlugin>::end_consensus_epoch(self, consensus_peers, batch).await
    }

    /// Retrieve the current status of the output. Depending on the module this might contain data
    /// needed by the client to access funds or give an estimate of when funds will be available.
    /// Returns `None` if the output is unknown, **NOT** if it is just not ready yet.
    fn output_status(&self, out_point: OutPoint) -> Option<OutputOutcome> {
        <Self as ServerModulePlugin>::output_status(self, out_point).map(Into::into)
    }

    /// Queries the database and returns all assets and liabilities of the module.
    ///
    /// Summing over all modules, if liabilities > assets then an error has occurred in the database
    /// and consensus should halt.
    fn audit(&self, audit: &mut Audit) {
        <Self as ServerModulePlugin>::audit(self, audit)
    }

    /// Defines the prefix for API endpoints defined by the module.
    ///
    /// E.g. if the module's base path is `foo` and it defines API endpoints `bar` and `baz` then
    /// these endpoints will be reachable under `/foo/bar` and `/foo/baz`.
    fn api_base_name(&self) -> &'static str {
        <Self as ServerModulePlugin>::api_base_name(self)
    }

    /// Returns a list of custom API endpoints defined by the module. These are made available both
    /// to users as well as to other modules. They thus should be deterministic, only dependant on
    /// their input and the current epoch.
    fn api_endpoints(&self) -> Vec<ApiEndpoint> {
        <Self as ServerModulePlugin>::api_endpoints(self)
    }
}

/*
  TODO: oops, this conflicts with `T: ClientModulePlugin`
impl<T> ModuleCommon for T
where
    T: ServerModulePlugin,
{
    fn module_key(&self) -> ModuleKey {
        <Self as ServerModulePlugin>::module_key(self)
    }

    fn decode_spendable_output(
        &self,
        r: &mut dyn io::Read,
    ) -> Result<SpendableOutput, DecodeError> {
        Ok(<Self as ServerModulePlugin>::SpendableOutput::consensus_decode(r)?.into())
    }

    fn decode_input(&self, r: &mut dyn io::Read) -> Result<Input, DecodeError> {
        Ok(<Self as ServerModulePlugin>::Input::consensus_decode(r)?.into())
    }

    fn decode_output(&self, r: &mut dyn io::Read) -> Result<Output, DecodeError> {
        Ok(<Self as ServerModulePlugin>::Output::consensus_decode(r)?.into())
    }

    fn decode_pending_output(&self, r: &mut dyn io::Read) -> Result<PendingOutput, DecodeError> {
        Ok(<Self as ServerModulePlugin>::PendingOutput::consensus_decode(r)?.into())
    }

    fn decode_output_outcome(&self, r: &mut dyn io::Read) -> Result<OutputOutcome, DecodeError> {
        Ok(<Self as ServerModulePlugin>::OutputOutcome::consensus_decode(r)?.into())
    }
}*/
