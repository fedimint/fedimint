//! Fedimint Core Server module interface
//!
//! Fedimint supports externally implemented modules.
//!
//! This (Rust) module defines common interoperability types
//! and functionality that are only used on the server side.
use std::collections::BTreeSet;
use std::sync::Arc;

use fedimint_core::module::audit::Audit;
use fedimint_core::module::interconnect::ModuleInterconect;
use fedimint_core::{apply, async_trait_maybe_send, OutPoint, PeerId};

use super::*;
use crate::db::ModuleDatabaseTransaction;
use crate::maybe_add_send_sync;
use crate::module::{
    ApiEndpoint, ApiEndpointContext, ApiRequestErased, ConsensusProposal, InputMeta, ModuleCommon,
    ModuleError, ServerModule, SupportedModuleApiVersions, TransactionItemAmount,
};
use crate::task::{MaybeSend, MaybeSync};

pub trait IVerificationCache: Debug {
    fn as_any(&self) -> &(maybe_add_send_sync!(dyn Any));
    fn clone(&self) -> DynVerificationCache;
}

dyn_newtype_define! {
    pub DynVerificationCache(Box<IVerificationCache>)
}

// TODO: make macro impl that doesn't force en/decodable
pub trait VerificationCache: Clone + Debug + MaybeSend + MaybeSync + 'static {}

impl<T> IVerificationCache for T
where
    T: VerificationCache + 'static,
{
    fn as_any(&self) -> &(maybe_add_send_sync!(dyn Any)) {
        self
    }

    fn clone(&self) -> DynVerificationCache {
        <Self as Clone>::clone(self).into()
    }
}

/// Backend side module interface
///
/// Server side Fedimint module needs to implement this trait.
#[apply(async_trait_maybe_send!)]
pub trait IServerModule: Debug {
    fn as_any(&self) -> &dyn Any;

    /// Returns the decoder belonging to the server module
    fn decoder(&self) -> Decoder;

    fn supported_api_versions(&self) -> SupportedModuleApiVersions;

    /// Blocks until a new `consensus_proposal` is available.
    async fn await_consensus_proposal(&self, dbtx: &mut ModuleDatabaseTransaction<'_>);

    /// This module's contribution to the next consensus proposal
    async fn consensus_proposal(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        module_instance_id: ModuleInstanceId,
    ) -> ConsensusProposal<DynModuleConsensusItem>;

    /// This function is called once before transaction processing starts.
    ///
    /// All module consensus items of this round are supplied as
    /// `consensus_items`. The database transaction will be committed to the
    /// database after all other modules ran `begin_consensus_epoch`, so the
    /// results are available when processing transactions. Returns any
    /// peers that need to be dropped.
    async fn begin_consensus_epoch<'a>(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'a>,
        consensus_items: Vec<(PeerId, DynModuleConsensusItem)>,
        consensus_peers: &BTreeSet<PeerId>,
    ) -> Vec<PeerId>;

    /// Some modules may have slow to verify inputs that would block transaction
    /// processing. If the slow part of verification can be modeled as a
    /// pure function not involving any system state we can build a lookup
    /// table in a hyper-parallelized manner. This function is meant for
    /// constructing such lookup tables.
    fn build_verification_cache(&self, inputs: &[DynInput]) -> DynVerificationCache;

    /// Validate a transaction input before submitting it to the unconfirmed
    /// transaction pool. This function has no side effects and may be
    /// called at any time. False positives due to outdated database state
    /// are ok since they get filtered out after consensus has been reached on
    /// them and merely generate a warning.
    async fn validate_input<'a>(
        &self,
        interconnect: &'a dyn ModuleInterconect,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        verification_cache: &DynVerificationCache,
        input: &DynInput,
    ) -> Result<InputMeta, ModuleError>;

    /// Try to spend a transaction input. On success all necessary updates will
    /// be part of the database transaction. On failure (e.g. double spend)
    /// the database transaction is rolled back and the operation will take
    /// no effect.
    ///
    /// This function may only be called after `begin_consensus_epoch` and
    /// before `end_consensus_epoch`. Data is only written to the database
    /// once all transactions have been processed
    async fn apply_input<'a, 'b, 'c>(
        &'a self,
        interconnect: &'a dyn ModuleInterconect,
        dbtx: &mut ModuleDatabaseTransaction<'c>,
        input: &'b DynInput,
        verification_cache: &DynVerificationCache,
    ) -> Result<InputMeta, ModuleError>;

    /// Validate a transaction output before submitting it to the unconfirmed
    /// transaction pool. This function has no side effects and may be
    /// called at any time. False positives due to outdated database state
    /// are ok since they get filtered out after consensus has been reached on
    /// them and merely generate a warning.
    async fn validate_output(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        output: &DynOutput,
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
    async fn apply_output<'a>(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'a>,
        output: &DynOutput,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmount, ModuleError>;

    /// This function is called once all transactions have been processed and
    /// changes were written to the database. This allows running
    /// finalization code before the next epoch.
    ///
    /// Passes in the `consensus_peers` that contributed to this epoch and
    /// returns a list of peers to drop if any are misbehaving.
    async fn end_consensus_epoch<'a>(
        &self,
        consensus_peers: &BTreeSet<PeerId>,
        dbtx: &mut ModuleDatabaseTransaction<'a>,
    ) -> Vec<PeerId>;

    /// Retrieve the current status of the output. Depending on the module this
    /// might contain data needed by the client to access funds or give an
    /// estimate of when funds will be available. Returns `None` if the
    /// output is unknown, **NOT** if it is just not ready yet.
    async fn output_status(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        out_point: OutPoint,
        module_instance_id: ModuleInstanceId,
    ) -> Option<DynOutputOutcome>;

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
    fn api_endpoints(&self) -> Vec<ApiEndpoint<DynServerModule>>;
}

dyn_newtype_define!(
    #[derive(Clone)]
    pub DynServerModule(Arc<IServerModule>)
);

#[apply(async_trait_maybe_send!)]
impl<T> IServerModule for T
where
    T: ServerModule + 'static + Sync,
{
    fn decoder(&self) -> Decoder {
        <T::Common as ModuleCommon>::decoder_builder().build()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        <Self as ServerModule>::supported_api_versions(self)
    }

    /// Blocks until a new `consensus_proposal` is available.
    async fn await_consensus_proposal(&self, dbtx: &mut ModuleDatabaseTransaction<'_>) {
        <Self as ServerModule>::await_consensus_proposal(self, dbtx).await
    }

    /// This module's contribution to the next consensus proposal
    async fn consensus_proposal(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        module_instance_id: ModuleInstanceId,
    ) -> ConsensusProposal<DynModuleConsensusItem> {
        <Self as ServerModule>::consensus_proposal(self, dbtx)
            .await
            .map(|v| DynModuleConsensusItem::from_typed(module_instance_id, v))
    }

    /// This function is called once before transaction processing starts.
    ///
    /// All module consensus items of this round are supplied as
    /// `consensus_items`. The database transaction will be committed to the
    /// database after all other modules ran `begin_consensus_epoch`, so the
    /// results are available when processing transactions. Returns any
    /// peers that need to be dropped.
    async fn begin_consensus_epoch<'a>(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'a>,
        consensus_items: Vec<(PeerId, DynModuleConsensusItem)>,
        consensus_peers: &BTreeSet<PeerId>,
    ) -> Vec<PeerId> {
        <Self as ServerModule>::begin_consensus_epoch(
            self,
            dbtx,
            consensus_items
                .into_iter()
                .map(|(peer, item)| {
                    (
                        peer,
                        Clone::clone(
                            item.as_any()
                                .downcast_ref::<<<Self as ServerModule>::Common as ModuleCommon>::ConsensusItem>(
                                )
                                .expect("incorrect consensus item type passed to module plugin"),
                        ),
                    )
                })
                .collect(),
            consensus_peers
        )
        .await
    }

    /// Some modules may have slow to verify inputs that would block transaction
    /// processing. If the slow part of verification can be modeled as a
    /// pure function not involving any system state we can build a lookup
    /// table in a hyper-parallelized manner. This function is meant for
    /// constructing such lookup tables.
    fn build_verification_cache<'a>(&self, inputs: &[DynInput]) -> DynVerificationCache {
        <Self as ServerModule>::build_verification_cache(
            self,
            inputs.iter().map(|i| {
                i.as_any()
                    .downcast_ref::<<<Self as ServerModule>::Common as ModuleCommon>::Input>()
                    .expect("incorrect input type passed to module plugin")
            }),
        )
        .into()
    }

    /// Validate a transaction input before submitting it to the unconfirmed
    /// transaction pool. This function has no side effects and may be
    /// called at any time. False positives due to outdated database state
    /// are ok since they get filtered out after consensus has been reached on
    /// them and merely generate a warning.
    async fn validate_input<'a>(
        &self,
        interconnect: &'a dyn ModuleInterconect,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        verification_cache: &DynVerificationCache,
        input: &DynInput,
    ) -> Result<InputMeta, ModuleError> {
        <Self as ServerModule>::validate_input(
            self,
            interconnect,
            dbtx,
            verification_cache
                .as_any()
                .downcast_ref::<<Self as ServerModule>::VerificationCache>()
                .expect("incorrect verification cache type passed to module plugin"),
            input
                .as_any()
                .downcast_ref::<<<Self as ServerModule>::Common as ModuleCommon>::Input>()
                .expect("incorrect input type passed to module plugin"),
        )
        .await
        .map(Into::into)
    }

    /// Try to spend a transaction input. On success all necessary updates will
    /// be part of the database transaction. On failure (e.g. double spend)
    /// the database transaction is rolled back and the operation will take
    /// no effect.
    ///
    /// This function may only be called after `begin_consensus_epoch` and
    /// before `end_consensus_epoch`. Data is only written to the database
    /// once all transactions have been processed
    async fn apply_input<'a, 'b, 'c>(
        &'a self,
        interconnect: &'a dyn ModuleInterconect,
        dbtx: &mut ModuleDatabaseTransaction<'c>,
        input: &'b DynInput,
        verification_cache: &DynVerificationCache,
    ) -> Result<InputMeta, ModuleError> {
        <Self as ServerModule>::apply_input(
            self,
            interconnect,
            dbtx,
            input
                .as_any()
                .downcast_ref::<<<Self as ServerModule>::Common as ModuleCommon>::Input>()
                .expect("incorrect input type passed to module plugin"),
            verification_cache
                .as_any()
                .downcast_ref::<<Self as ServerModule>::VerificationCache>()
                .expect("incorrect verification cache type passed to module plugin"),
        )
        .await
        .map(Into::into)
    }

    /// Validate a transaction output before submitting it to the unconfirmed
    /// transaction pool. This function has no side effects and may be
    /// called at any time. False positives due to outdated database state
    /// are ok since they get filtered out after consensus has been reached on
    /// them and merely generate a warning.
    async fn validate_output(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        output: &DynOutput,
    ) -> Result<TransactionItemAmount, ModuleError> {
        <Self as ServerModule>::validate_output(
            self,
            dbtx,
            output
                .as_any()
                .downcast_ref::<<<Self as ServerModule>::Common as ModuleCommon>::Output>()
                .expect("incorrect output type passed to module plugin"),
        )
        .await
    }

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
    async fn apply_output<'a>(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'a>,
        output: &DynOutput,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmount, ModuleError> {
        <Self as ServerModule>::apply_output(
            self,
            dbtx,
            output
                .as_any()
                .downcast_ref::<<<Self as ServerModule>::Common as ModuleCommon>::Output>()
                .expect("incorrect output type passed to module plugin"),
            out_point,
        )
        .await
    }

    /// This function is called once all transactions have been processed and
    /// changes were written to the database. This allows running
    /// finalization code before the next epoch.
    ///
    /// Passes in the `consensus_peers` that contributed to this epoch and
    /// returns a list of peers to drop if any are misbehaving.
    async fn end_consensus_epoch<'a>(
        &self,
        consensus_peers: &BTreeSet<PeerId>,
        dbtx: &mut ModuleDatabaseTransaction<'a>,
    ) -> Vec<PeerId> {
        <Self as ServerModule>::end_consensus_epoch(self, consensus_peers, dbtx).await
    }

    /// Retrieve the current status of the output. Depending on the module this
    /// might contain data needed by the client to access funds or give an
    /// estimate of when funds will be available. Returns `None` if the
    /// output is unknown, **NOT** if it is just not ready yet.
    async fn output_status(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        out_point: OutPoint,
        module_instance_id: ModuleInstanceId,
    ) -> Option<DynOutputOutcome> {
        <Self as ServerModule>::output_status(self, dbtx, out_point)
            .await
            .map(|v| DynOutputOutcome::from_typed(module_instance_id, v))
    }

    /// Queries the database and returns all assets and liabilities of the
    /// module.
    ///
    /// Summing over all modules, if liabilities > assets then an error has
    /// occurred in the database and consensus should halt.
    async fn audit(&self, dbtx: &mut ModuleDatabaseTransaction<'_>, audit: &mut Audit) {
        <Self as ServerModule>::audit(self, dbtx, audit).await
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<DynServerModule>> {
        <Self as ServerModule>::api_endpoints(self)
            .into_iter()
            .map(|ApiEndpoint { path, handler }| ApiEndpoint {
                path,
                handler: Box::new(
                    move |module: &DynServerModule,
                          context: ApiEndpointContext<'_>,
                          value: ApiRequestErased| {
                        let typed_module = module
                            .as_any()
                            .downcast_ref::<T>()
                            .expect("the dispatcher should always call with the right module");
                        Box::pin(handler(typed_module, context, value))
                    },
                ),
            })
            .collect()
    }
}
