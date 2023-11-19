//! Fedimint Core Server module interface
//!
//! Fedimint supports externally implemented modules.
//!
//! This (Rust) module defines common interoperability types
//! and functionality that are only used on the server side.
use std::fmt::Debug;
use std::sync::Arc;

use fedimint_core::module::audit::Audit;
use fedimint_core::{apply, async_trait_maybe_send, OutPoint, PeerId};

use crate::core::{
    Any, Decoder, DynInput, DynInputError, DynModuleConsensusItem, DynOutput, DynOutputError,
    DynOutputOutcome,
};
use crate::db::DatabaseTransaction;
use crate::dyn_newtype_define;
use crate::module::registry::ModuleInstanceId;
use crate::module::{
    ApiEndpoint, ApiEndpointContext, ApiRequestErased, InputMeta, ModuleCommon, ServerModule,
    TransactionItemAmount,
};

/// Backend side module interface
///
/// Server side Fedimint module needs to implement this trait.
#[apply(async_trait_maybe_send!)]
pub trait IServerModule: Debug {
    fn as_any(&self) -> &dyn Any;

    /// Returns the decoder belonging to the server module
    fn decoder(&self) -> Decoder;

    /// This module's contribution to the next consensus proposal
    async fn consensus_proposal(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        module_instance_id: ModuleInstanceId,
    ) -> Vec<DynModuleConsensusItem>;

    /// This function is called once for every consensus item. The function
    /// returns an error if any only if the consensus item does not change
    /// our state and therefore may be safely discarded by the atomic broadcast.
    async fn process_consensus_item<'a>(
        &self,
        dbtx: &mut DatabaseTransaction<'a>,
        consensus_item: DynModuleConsensusItem,
        peer_id: PeerId,
    ) -> anyhow::Result<()>;

    /// Try to spend a transaction input. On success all necessary updates will
    /// be part of the database transaction. On failure (e.g. double spend)
    /// the database transaction is rolled back and the operation will take
    /// no effect.
    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b DynInput,
        module_instance_id: ModuleInstanceId,
    ) -> Result<InputMeta, DynInputError>;

    /// Try to create an output (e.g. issue notes, peg-out BTC, …). On success
    /// all necessary updates to the database will be part of the database
    /// transaction. On failure (e.g. double spend) the database transaction
    /// is rolled back and the operation will take no effect.
    ///
    /// The supplied `out_point` identifies the operation (e.g. a peg-out or
    /// note issuance) and can be used to retrieve its outcome later using
    /// `output_status`.
    async fn process_output<'a>(
        &self,
        dbtx: &mut DatabaseTransaction<'a>,
        output: &DynOutput,
        out_point: OutPoint,
        module_instance_id: ModuleInstanceId,
    ) -> Result<TransactionItemAmount, DynOutputError>;

    /// Retrieve the current status of the output. Depending on the module this
    /// might contain data needed by the client to access funds or give an
    /// estimate of when funds will be available. Returns `None` if the
    /// output is unknown, **NOT** if it is just not ready yet.
    async fn output_status(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        out_point: OutPoint,
        module_instance_id: ModuleInstanceId,
    ) -> Option<DynOutputOutcome>;

    /// Queries the database and returns all assets and liabilities of the
    /// module.
    ///
    /// Summing over all modules, if liabilities > assets then an error has
    /// occurred in the database and consensus should halt.
    async fn audit(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        audit: &mut Audit,
        module_instance_id: ModuleInstanceId,
    );

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

    /// This module's contribution to the next consensus proposal
    async fn consensus_proposal(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        module_instance_id: ModuleInstanceId,
    ) -> Vec<DynModuleConsensusItem> {
        <Self as ServerModule>::consensus_proposal(self, dbtx)
            .await
            .into_iter()
            .map(|v| DynModuleConsensusItem::from_typed(module_instance_id, v))
            .collect()
    }

    /// This function is called once for every consensus item. The function
    /// returns an error if any only if the consensus item does not change
    /// our state and therefore may be safely discarded by the atomic broadcast.
    async fn process_consensus_item<'a>(
        &self,
        dbtx: &mut DatabaseTransaction<'a>,
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

    /// Try to spend a transaction input. On success all necessary updates will
    /// be part of the database transaction. On failure (e.g. double spend)
    /// the database transaction is rolled back and the operation will take
    /// no effect.
    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b DynInput,
        module_instance_id: ModuleInstanceId,
    ) -> Result<InputMeta, DynInputError> {
        <Self as ServerModule>::process_input(
            self,
            dbtx,
            input
                .as_any()
                .downcast_ref::<<<Self as ServerModule>::Common as ModuleCommon>::Input>()
                .expect("incorrect input type passed to module plugin"),
        )
        .await
        .map(Into::into)
        .map_err(|v| DynInputError::from_typed(module_instance_id, v))
    }

    /// Try to create an output (e.g. issue notes, peg-out BTC, …). On success
    /// all necessary updates to the database will be part of the database
    /// transaction. On failure (e.g. double spend) the database transaction
    /// is rolled back and the operation will take no effect.
    ///
    /// The supplied `out_point` identifies the operation (e.g. a peg-out or
    /// note issuance) and can be used to retrieve its outcome later using
    /// `output_status`.
    async fn process_output<'a>(
        &self,
        dbtx: &mut DatabaseTransaction<'a>,
        output: &DynOutput,
        out_point: OutPoint,
        module_instance_id: ModuleInstanceId,
    ) -> Result<TransactionItemAmount, DynOutputError> {
        <Self as ServerModule>::process_output(
            self,
            dbtx,
            output
                .as_any()
                .downcast_ref::<<<Self as ServerModule>::Common as ModuleCommon>::Output>()
                .expect("incorrect output type passed to module plugin"),
            out_point,
        )
        .await
        .map_err(|v| DynOutputError::from_typed(module_instance_id, v))
    }

    /// Retrieve the current status of the output. Depending on the module this
    /// might contain data needed by the client to access funds or give an
    /// estimate of when funds will be available. Returns `None` if the
    /// output is unknown, **NOT** if it is just not ready yet.
    async fn output_status(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
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
    async fn audit(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        audit: &mut Audit,
        module_instance_id: ModuleInstanceId,
    ) {
        <Self as ServerModule>::audit(self, dbtx, audit, module_instance_id).await
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
