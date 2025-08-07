use std::sync::Arc;

use fedimint_api_client::api::{DynGlobalApi, DynModuleApi};
use fedimint_client_module::module::OutPointRange;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, DynState, IState};
use fedimint_client_module::transaction::{TransactionBuilder, TxSubmissionStatesSM};
use fedimint_client_module::{
    AddStateMachinesResult, IGlobalClientContext, InstancelessDynClientInputBundle,
    InstancelessDynClientOutputBundle,
};
use fedimint_core::config::ClientConfig;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::util::BoxStream;
use fedimint_core::{apply, async_trait_maybe_send, maybe_add_send_sync};
use fedimint_eventlog::EventKind;

use super::Client;

/// Global state given to a specific client module and state. It is aware inside
/// which module instance and operation it is used and to avoid module being
/// aware of their instance id etc.
#[derive(Clone, Debug)]
pub(crate) struct ModuleGlobalClientContext {
    pub(crate) client: Arc<Client>,
    pub(crate) module_instance_id: ModuleInstanceId,
    pub(crate) operation: OperationId,
}

#[apply(async_trait_maybe_send!)]
impl IGlobalClientContext for ModuleGlobalClientContext {
    fn module_api(&self) -> DynModuleApi {
        self.api().with_module(self.module_instance_id)
    }

    fn api(&self) -> &DynGlobalApi {
        &self.client.api
    }

    fn decoders(&self) -> &ModuleDecoderRegistry {
        self.client.decoders()
    }

    async fn client_config(&self) -> ClientConfig {
        self.client.config().await
    }

    async fn claim_inputs_dyn(
        &self,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        inputs: InstancelessDynClientInputBundle,
    ) -> anyhow::Result<OutPointRange> {
        let tx_builder =
            TransactionBuilder::new().with_inputs(inputs.into_dyn(self.module_instance_id));

        self.client
            .finalize_and_submit_transaction_inner(
                &mut dbtx.global_tx().to_ref_nc(),
                self.operation,
                tx_builder,
            )
            .await
    }

    async fn fund_output_dyn(
        &self,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        outputs: InstancelessDynClientOutputBundle,
    ) -> anyhow::Result<OutPointRange> {
        let tx_builder =
            TransactionBuilder::new().with_outputs(outputs.into_dyn(self.module_instance_id));

        self.client
            .finalize_and_submit_transaction_inner(
                &mut dbtx.global_tx().to_ref_nc(),
                self.operation,
                tx_builder,
            )
            .await
    }

    async fn add_state_machine_dyn(
        &self,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        sm: Box<maybe_add_send_sync!(dyn IState)>,
    ) -> AddStateMachinesResult {
        let state = DynState::from_parts(self.module_instance_id, sm);

        self.client
            .executor
            .add_state_machines_dbtx(&mut dbtx.global_tx().to_ref_nc(), vec![state])
            .await
    }

    async fn transaction_update_stream(&self) -> BoxStream<TxSubmissionStatesSM> {
        self.client.transaction_update_stream(self.operation).await
    }

    async fn log_event_json(
        &self,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        kind: EventKind,
        module: Option<(ModuleKind, ModuleInstanceId)>,
        payload: serde_json::Value,
        persist: bool,
        trimable: bool,
    ) {
        self.client
            .log_event_raw_dbtx(
                dbtx.global_tx(),
                kind,
                module,
                serde_json::to_vec(&payload).expect("Serialization can't fail"),
                persist,
                trimable,
            )
            .await;
    }
}
