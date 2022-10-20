//! Fedimint Core Server module interface
//!
//! Fedimint supports externally implemented modules.
//!
//! This (Rust) module defines common interoperability types
//! and functionality that are only used on the server side.
use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;
use bitcoin::XOnlyPublicKey;
use fedimint_api::{
    db::DatabaseTransaction,
    encoding::DynEncodable,
    module::{__reexports::serde_json, audit::Audit, interconnect::ModuleInterconect, ApiError},
    Amount, OutPoint, PeerId,
};
use futures::future::BoxFuture;
use thiserror::Error;

use super::*;

pub trait ModuleConsensusItem: DynEncodable {
    fn as_any(&self) -> &(dyn Any + 'static);
    fn module_key(&self) -> ModuleKey;
    fn clone(&self) -> ConsensusItem;
}

dyn_newtype_define! {
    pub ConsensusItem(Box<ModuleConsensusItem>)
}
dyn_newtype_impl_dyn_clone_passhthrough!(ConsensusItem);
module_plugin_trait_define!(ConsensusItem, PluginConsensusItem, ModuleConsensusItem, {} {});

pub trait ModuleVerificationCache: DynEncodable {
    fn as_any(&self) -> &(dyn Any + 'static);
    fn module_key(&self) -> ModuleKey;
    fn clone(&self) -> VerificationCache;
}

dyn_newtype_define! {
    pub VerificationCache(Box<ModuleVerificationCache>)
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

/// An interface rpc handlers can use to query to access current running context
pub trait RpcHandlerCtx: Sync {}

/// An interface exposed to Fedimint modules
pub trait InitHandle {
    /// Register an rpc handler at a given path
    fn register_endpoint(
        &mut self,
        path: &'static str,
        handler: fn(
            serde_json::Value,
            ctx: &dyn RpcHandlerCtx,
        ) -> BoxFuture<'static, Result<serde_json::Value, ApiError>>,
    );
}

/// Backend side module interface
///
/// Server side Fedimint mondule needs to implement this trait.
#[async_trait(?Send)]
pub trait IServerModule {
    fn module_key(&self) -> ModuleKey;

    fn decode_spendable_output(&self, r: &mut dyn io::Read)
        -> Result<SpendableOutput, DecodeError>;

    fn decode_input(&self, r: &mut dyn io::Read) -> Result<Input, DecodeError>;

    fn decode_output(&self, r: &mut dyn io::Read) -> Result<Output, DecodeError>;

    fn decode_pending_output(&self, r: &mut dyn io::Read) -> Result<PendingOutput, DecodeError>;

    fn decode_output_outcome(&self, r: &mut dyn io::Read) -> Result<OutputOutcome, DecodeError>;

    /// Initialize the module on registration in Fedimint
    fn init(&self, backend: &mut dyn InitHandle);

    /// Blocks until a new `consensus_proposal` is available.
    async fn await_consensus_proposal(&self);

    /// This module's contribution to the next consensus proposal
    async fn consensus_proposal(&self) -> Vec<ConsensusItem>;

    /// This function is called once before transaction processing starts. All module consensus
    /// items of this round are supplied as `consensus_items`. The batch will be committed to the
    /// database after all other modules ran `begin_consensus_epoch`, so the results are available
    /// when processing transactions.
    async fn begin_consensus_epoch<'a>(
        &self,
        dbtx: &mut DatabaseTransaction<'a>,
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
    fn apply_input<'a, 'b, 'c>(
        &'a self,
        interconnect: &'a dyn ModuleInterconect,
        dbtx: &mut DatabaseTransaction<'c>,
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
    fn apply_output<'a>(
        &self,
        dbtx: &mut DatabaseTransaction<'a>,
        output: &Output,
        out_point: OutPoint,
    ) -> Result<Amount, Error>;

    /// This function is called once all transactions have been processed and changes were written
    /// to the database. This allows running finalization code before the next epoch.
    ///
    /// Passes in the `consensus_peers` that contributed to this epoch and returns a list of peers
    /// to drop if any are misbehaving.
    async fn end_consensus_epoch<'a>(
        &self,
        consensus_peers: &HashSet<PeerId>,
        dbtx: &mut DatabaseTransaction<'a>,
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
}

dyn_newtype_define!(
    #[derive(Clone)]
    pub ServerModule(Arc<IServerModule>)
);

#[async_trait(?Send)]
pub trait ServerModulePlugin: Sized {
    type Common: ModuleCommon;
    type Input: PluginInput;
    type Output: PluginOutput;
    type PendingOutput: PluginPendingOutput;
    type SpendableOutput: PluginSpendableOutput;
    type OutputOutcome: PluginOutputOutcome;
    type ConsensusItem: PluginConsensusItem;
    type VerificationCache: PluginVerificationCache;

    fn init(&self, backend: &mut dyn InitHandle);

    /// Blocks until a new `consensus_proposal` is available.
    async fn await_consensus_proposal<'a>(&'a self);

    /// This module's contribution to the next consensus proposal
    async fn consensus_proposal<'a>(&'a self) -> Vec<Self::ConsensusItem>;

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
    fn apply_input<'a, 'b, 'c>(
        &'a self,
        interconnect: &'a dyn ModuleInterconect,
        dbtx: &mut DatabaseTransaction<'c>,
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
    fn apply_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a Self::Output,
        out_point: OutPoint,
    ) -> Result<Amount, Error>;

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
    fn output_status(&self, out_point: OutPoint) -> Option<Self::OutputOutcome>;

    /// Queries the database and returns all assets and liabilities of the module.
    ///
    /// Summing over all modules, if liabilities > assets then an error has occurred in the database
    /// and consensus should halt.
    fn audit(&self, audit: &mut Audit);
}

#[async_trait(?Send)]
impl<T> IServerModule for T
where
    T: ServerModulePlugin,
{
    fn module_key(&self) -> ModuleKey {
        <Self as ServerModulePlugin>::Common::module_key()
    }

    fn decode_spendable_output(
        &self,
        r: &mut dyn io::Read,
    ) -> Result<SpendableOutput, DecodeError> {
        <Self as ServerModulePlugin>::Common::decode_spendable_output(r)
    }

    fn decode_input(&self, r: &mut dyn io::Read) -> Result<Input, DecodeError> {
        <Self as ServerModulePlugin>::Common::decode_input(r)
    }

    fn decode_output(&self, r: &mut dyn io::Read) -> Result<Output, DecodeError> {
        <Self as ServerModulePlugin>::Common::decode_output(r)
    }

    fn decode_pending_output(&self, r: &mut dyn io::Read) -> Result<PendingOutput, DecodeError> {
        <Self as ServerModulePlugin>::Common::decode_pending_output(r)
    }

    fn decode_output_outcome(&self, r: &mut dyn io::Read) -> Result<OutputOutcome, DecodeError> {
        <Self as ServerModulePlugin>::Common::decode_output_outcome(r)
    }

    fn init(&self, backend: &mut dyn InitHandle) {
        <Self as ServerModulePlugin>::init(self, backend)
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
    async fn begin_consensus_epoch<'a>(
        &self,
        dbtx: &mut DatabaseTransaction<'a>,
        consensus_items: Vec<(PeerId, ConsensusItem)>,
    ) {
        <Self as ServerModulePlugin>::begin_consensus_epoch(
            self,
            dbtx,
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
    fn apply_input<'a, 'b, 'c>(
        &'a self,
        interconnect: &'a dyn ModuleInterconect,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b Input,
        verification_cache: &VerificationCache,
    ) -> Result<InputMeta, Error> {
        <Self as ServerModulePlugin>::apply_input(
            self,
            interconnect,
            dbtx,
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
    fn apply_output<'a>(
        &self,
        dbtx: &mut DatabaseTransaction<'a>,
        output: &Output,
        out_point: OutPoint,
    ) -> Result<Amount, Error> {
        <Self as ServerModulePlugin>::apply_output(
            self,
            dbtx,
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
    async fn end_consensus_epoch<'a>(
        &self,
        consensus_peers: &HashSet<PeerId>,
        dbtx: &mut DatabaseTransaction<'a>,
    ) -> Vec<PeerId> {
        <Self as ServerModulePlugin>::end_consensus_epoch(self, consensus_peers, dbtx).await
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
}
