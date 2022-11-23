//! Fedimint Core Server module interface
//!
//! Fedimint supports externally implemented modules.
//!
//! This (Rust) module defines common interoperability types
//! and functionality that are only used on the server side.
use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;
use fedimint_api::{
    db::DatabaseTransaction,
    module::{audit::Audit, interconnect::ModuleInterconect},
    OutPoint, PeerId,
};

use super::*;
use crate::module::{
    ApiEndpoint, InputMeta, ModuleError, ServerModulePlugin, TransactionItemAmount,
};

pub trait ModuleVerificationCache: Debug {
    fn as_any(&self) -> &(dyn Any + 'static);
    fn module_key(&self) -> ModuleKey;
    fn clone(&self) -> VerificationCache;
}

dyn_newtype_define! {
    pub VerificationCache(Box<ModuleVerificationCache>)
}

// TODO: make macro impl that doesn't force en/decodable
pub trait PluginVerificationCache: Clone + Debug + Send + Sync + 'static {
    fn module_key(&self) -> ModuleKey;
}

impl<T> ModuleVerificationCache for T
where
    T: PluginVerificationCache + 'static,
{
    fn as_any(&self) -> &(dyn Any + 'static) {
        self
    }

    fn module_key(&self) -> ModuleKey {
        <Self as PluginVerificationCache>::module_key(self)
    }

    fn clone(&self) -> VerificationCache {
        <Self as Clone>::clone(self).into()
    }
}
/// Backend side module interface
///
/// Server side Fedimint mondule needs to implement this trait.
#[async_trait(?Send)]
pub trait IServerModule: Debug {
    fn module_key(&self) -> ModuleKey;

    fn as_any(&self) -> &(dyn Any + 'static);

    fn decode_input(&self, r: &mut dyn io::Read) -> Result<Input, DecodeError>;

    fn decode_output(&self, r: &mut dyn io::Read) -> Result<Output, DecodeError>;

    fn decode_output_outcome(&self, r: &mut dyn io::Read) -> Result<OutputOutcome, DecodeError>;

    fn decode_consensus_item(&self, r: &mut dyn io::Read) -> Result<ConsensusItem, DecodeError>;

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
    fn validate_input<'a>(
        &self,
        interconnect: &dyn ModuleInterconect,
        dbtx: &DatabaseTransaction<'a>,
        verification_cache: &VerificationCache,
        input: &Input,
    ) -> Result<InputMeta, ModuleError>;

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
    ) -> Result<InputMeta, ModuleError>;

    /// Validate a transaction output before submitting it to the unconfirmed transaction pool. This
    /// function has no side effects and may be called at any time. False positives due to outdated
    /// database state are ok since they get filtered out after consensus has been reached on them
    /// and merely generate a warning.
    fn validate_output(
        &self,
        dbtx: &DatabaseTransaction,
        output: &Output,
    ) -> Result<TransactionItemAmount, ModuleError>;

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
    ) -> Result<TransactionItemAmount, ModuleError>;

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

    /// Defines the prefix for API endpoints defined by the module.
    ///
    /// E.g. if the module's base path is `foo` and it defines API endpoints `bar` and `baz` then
    /// these endpoints will be reachable under `/foo/bar` and `/foo/baz`.
    fn api_base_name(&self) -> &'static str;

    /// Returns a list of custom API endpoints defined by the module. These are made available both
    /// to users as well as to other modules. They thus should be deterministic, only dependant on
    /// their input and the current epoch.
    fn api_endpoints(&self) -> Vec<ApiEndpoint<ServerModule>>;
}

dyn_newtype_define!(
    #[derive(Clone)]
    pub ServerModule(Arc<IServerModule>)
);

impl ModuleDecode for ServerModule {
    fn decode_input(&self, r: &mut dyn io::Read) -> Result<Input, DecodeError> {
        (**self).decode_input(r)
    }

    fn decode_output(&self, r: &mut dyn io::Read) -> Result<Output, DecodeError> {
        (**self).decode_output(r)
    }

    fn decode_output_outcome(&self, r: &mut dyn io::Read) -> Result<OutputOutcome, DecodeError> {
        (**self).decode_output_outcome(r)
    }

    fn decode_consensus_item(&self, r: &mut dyn io::Read) -> Result<ConsensusItem, DecodeError> {
        (**self).decode_consensus_item(r)
    }
}

#[async_trait(?Send)]
impl<T> IServerModule for T
where
    T: ServerModulePlugin + 'static,
{
    fn module_key(&self) -> ModuleKey {
        <Self as ServerModulePlugin>::module_key(self)
    }

    fn as_any(&self) -> &(dyn Any + 'static) {
        self
    }

    fn decode_input(&self, r: &mut dyn io::Read) -> Result<Input, DecodeError> {
        <Self as ServerModulePlugin>::Decoder::decode_input(r)
    }

    fn decode_output(&self, r: &mut dyn io::Read) -> Result<Output, DecodeError> {
        <Self as ServerModulePlugin>::Decoder::decode_output(r)
    }

    fn decode_output_outcome(&self, r: &mut dyn io::Read) -> Result<OutputOutcome, DecodeError> {
        <Self as ServerModulePlugin>::Decoder::decode_output_outcome(r)
    }

    fn decode_consensus_item(&self, r: &mut dyn io::Read) -> Result<ConsensusItem, DecodeError> {
        <Self as ServerModulePlugin>::Decoder::decode_consensus_item(r)
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
    fn validate_input<'a>(
        &self,
        interconnect: &dyn ModuleInterconect,
        dbtx: &DatabaseTransaction<'a>,
        verification_cache: &VerificationCache,
        input: &Input,
    ) -> Result<InputMeta, ModuleError> {
        <Self as ServerModulePlugin>::validate_input(
            self,
            interconnect,
            dbtx,
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
    ) -> Result<InputMeta, ModuleError> {
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
    fn validate_output(
        &self,
        dbtx: &DatabaseTransaction,
        output: &Output,
    ) -> Result<TransactionItemAmount, ModuleError> {
        <Self as ServerModulePlugin>::validate_output(
            self,
            dbtx,
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
    ) -> Result<TransactionItemAmount, ModuleError> {
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

    fn api_base_name(&self) -> &'static str {
        <Self as ServerModulePlugin>::api_base_name(self)
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<ServerModule>> {
        <Self as ServerModulePlugin>::api_endpoints(self)
            .into_iter()
            .map(|ApiEndpoint { path, handler }| ApiEndpoint {
                path,
                handler: Box::new(move |module: &ServerModule, value: serde_json::Value| {
                    let typed_module = module
                        .as_any()
                        .downcast_ref::<T>()
                        .expect("the dispatcher should always call with the right module");
                    Box::pin(handler(typed_module, value))
                }),
            })
            .collect()
    }
}
