//! Fedimint Core Server module interface
//!
//! Fedimint supports externally implemented modules.
//!
//! This (Rust) module defines common interoperability types
//! and functionality that are only used on the server side.
use std::sync::Arc;

use fedimint_core::module::audit::Audit;
use fedimint_core::{apply, async_trait_maybe_send, OutPoint, PeerId};

use super::*;
use crate::db::ModuleDatabaseTransaction;
use crate::maybe_add_send_sync;
use crate::module::{
    ApiEndpoint, ApiEndpointContext, ApiRequestErased, ConsensusProposal, InputMeta, ModuleCommon,
    ModuleError, ServerModule, TransactionItemAmount,
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

    /// Blocks until a new `consensus_proposal` is available.
    async fn await_consensus_proposal(&self, dbtx: &mut ModuleDatabaseTransaction<'_>);

    /// This module's contribution to the next consensus proposal
    async fn consensus_proposal(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        module_instance_id: ModuleInstanceId,
    ) -> ConsensusProposal<DynModuleConsensusItem>;

    /// This function is called once for every consensus item. The function
    /// returns an error if any only if the consensus item does not change
    /// our state and therefore may be safely discarded by the atomic broadcast.
    async fn process_consensus_item<'a>(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'a>,
        consensus_item: DynModuleConsensusItem,
        peer_id: PeerId,
    ) -> anyhow::Result<()>;

    /// Some modules may have slow to verify inputs that would block transaction
    /// processing. If the slow part of verification can be modeled as a
    /// pure function not involving any system state we can build a lookup
    /// table in a hyper-parallelized manner. This function is meant for
    /// constructing such lookup tables.
    fn build_verification_cache(&self, inputs: &[DynInput]) -> DynVerificationCache;

    /// Try to spend a transaction input. On success all necessary updates will
    /// be part of the database transaction. On failure (e.g. double spend)
    /// the database transaction is rolled back and the operation will take
    /// no effect.
    async fn process_input<'a, 'b, 'c>(
        &'a self,
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
    async fn apply_output<'a>(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'a>,
        output: &DynOutput,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmount, ModuleError>;

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

    /// This function is called once for every consensus item. The function
    /// returns an error if any only if the consensus item does not change
    /// our state and therefore may be safely discarded by the atomic broadcast.
    async fn process_consensus_item<'a>(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'a>,
        consensus_item: DynModuleConsensusItem,
        peer_id: PeerId,
    ) -> anyhow::Result<()> {
        <Self as ServerModule>::process_consensus_item(
            self,
            dbtx,
            Clone::clone(
                consensus_item.as_any()
                    .downcast_ref::<<<Self as ServerModule>::Common as ModuleCommon>::ConsensusItem>()
                    .expect("incorrect consensus item type passed to module plugin"),
            ),
            peer_id
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

    /// Try to spend a transaction input. On success all necessary updates will
    /// be part of the database transaction. On failure (e.g. double spend)
    /// the database transaction is rolled back and the operation will take
    /// no effect.
    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut ModuleDatabaseTransaction<'c>,
        input: &'b DynInput,
        verification_cache: &DynVerificationCache,
    ) -> Result<InputMeta, ModuleError> {
        <Self as ServerModule>::process_input(
            self,
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
