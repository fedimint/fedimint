use std::pin::Pin;

use fedimint_api_client::api::DynGlobalApi;
use fedimint_client_module::TransactionUpdates;
use fedimint_client_module::error::{ModuleLookupError, TransactionSubmitError};
use fedimint_client_module::module::{ClientContextIface, IClientModule};
use fedimint_client_module::sm::executor::{ActiveStateKey, IExecutor, InactiveStateKey};
use fedimint_client_module::transaction::{FeeQuote, FeeQuoteRequest, TransactionBuilder};
use fedimint_core::config::ClientConfig;
use fedimint_core::core::{ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{Database, DatabaseTransaction, NonCommittable};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::AmountUnit;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::{Amount, OutPoint, OutPointRange, PeerId, apply, async_trait_maybe_send};
use fedimint_eventlog::{EventKind, EventPersistence};

/// Only event logging is needed by the outgoing reimbursement transition.
pub(super) struct MockClientContext;

#[apply(async_trait_maybe_send!)]
impl ClientContextIface for MockClientContext {
    fn get_module(&self, _: ModuleInstanceId) -> &(dyn IClientModule + Send + Sync) {
        unimplemented!()
    }
    fn api_clone(&self) -> DynGlobalApi {
        unimplemented!()
    }
    fn decoders(&self) -> &ModuleDecoderRegistry {
        unimplemented!()
    }
    async fn finalize_and_submit_transaction(
        &self,
        _: OperationId,
        _: &str,
        _: Box<dyn Fn(OutPointRange) -> serde_json::Value + Send + Sync>,
        _: TransactionBuilder,
    ) -> Result<OutPointRange, TransactionSubmitError> {
        unimplemented!()
    }
    async fn finalize_and_submit_transaction_dbtx(
        &self,
        _: &mut DatabaseTransaction<'_>,
        _: OperationId,
        _: &str,
        _: Box<dyn Fn(OutPointRange) -> serde_json::Value + Send + Sync>,
        _: TransactionBuilder,
    ) -> Result<OutPointRange, TransactionSubmitError> {
        unimplemented!()
    }
    async fn finalize_and_submit_transaction_inner(
        &self,
        _: &mut DatabaseTransaction<'_>,
        _: OperationId,
        _: TransactionBuilder,
    ) -> Result<OutPointRange, TransactionSubmitError> {
        unimplemented!()
    }
    async fn fee_quote(
        &self,
        _: OperationId,
        _: FeeQuoteRequest,
    ) -> Result<FeeQuote, TransactionSubmitError> {
        unimplemented!()
    }
    async fn get_balance_for_unit(&self, _: AmountUnit) -> Result<Amount, ModuleLookupError> {
        unimplemented!()
    }
    async fn transaction_updates(&self, _: OperationId) -> TransactionUpdates {
        unimplemented!()
    }
    async fn await_primary_module_outputs(
        &self,
        _: OperationId,
        _: Vec<OutPoint>,
    ) -> Result<(), TransactionSubmitError> {
        unimplemented!()
    }
    fn operation_log(&self) -> &dyn fedimint_client_module::oplog::IOperationLog {
        unimplemented!()
    }
    async fn has_active_states(&self, _: OperationId) -> bool {
        unimplemented!()
    }
    async fn await_no_active_states(&self, _: OperationId) {
        unimplemented!()
    }
    async fn operation_exists(&self, _: OperationId) -> bool {
        unimplemented!()
    }
    async fn config(&self) -> ClientConfig {
        unimplemented!()
    }
    fn db(&self) -> &Database {
        unimplemented!()
    }
    fn executor(&self) -> &(dyn IExecutor + Send + Sync + 'static) {
        unimplemented!()
    }
    async fn invite_code(&self, _: PeerId) -> Option<InviteCode> {
        unimplemented!()
    }
    fn get_internal_payment_markers(&self) -> Result<(PublicKey, u64), bitcoin::secp256k1::Error> {
        unimplemented!()
    }
    async fn log_event_json(
        &self,
        _: &mut DatabaseTransaction<'_, NonCommittable>,
        _: Option<ModuleKind>,
        _: ModuleInstanceId,
        _: EventKind,
        _: serde_json::Value,
        _: EventPersistence,
    ) {
    }
    async fn read_operation_active_states<'dbtx>(
        &self,
        _: OperationId,
        _: ModuleInstanceId,
        _: &'dbtx mut DatabaseTransaction<'_>,
    ) -> Pin<
        Box<
            dyn futures::Stream<
                    Item = (ActiveStateKey, fedimint_client_module::sm::ActiveStateMeta),
                > + Send
                + 'dbtx,
        >,
    > {
        unimplemented!()
    }
    async fn read_operation_inactive_states<'dbtx>(
        &self,
        _: OperationId,
        _: ModuleInstanceId,
        _: &'dbtx mut DatabaseTransaction<'_>,
    ) -> Pin<
        Box<
            dyn futures::Stream<
                    Item = (
                        InactiveStateKey,
                        fedimint_client_module::sm::InactiveStateMeta,
                    ),
                > + Send
                + 'dbtx,
        >,
    > {
        unimplemented!()
    }
}
