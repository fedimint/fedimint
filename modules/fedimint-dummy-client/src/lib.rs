#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

use core::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{ClientModule, PrimaryModulePriority, PrimaryModuleSupport};
use fedimint_client_module::sm::{Context, ModuleNotifier};
use fedimint_client_module::transaction::{
    ClientInput, ClientInputBundle, ClientOutput, ClientOutputBundle,
};
use fedimint_core::core::{Decoder, ModuleKind, OperationId};
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion};
use fedimint_core::module::{
    AmountUnit, Amounts, ApiVersion, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::secp256k1::{Keypair, Secp256k1};
use fedimint_core::util::{BoxStream, NextOrPending};
use fedimint_core::{Amount, OutPoint, apply, async_trait_maybe_send};
pub use fedimint_dummy_common as common;
use fedimint_dummy_common::{DummyCommonInit, DummyInput, DummyModuleTypes, DummyOutput};
use futures::{StreamExt, pin_mut};
use states::DummyStateMachine;

pub mod db;
pub mod states;

pub struct DummyClientModule {
    key: Keypair,
    notifier: ModuleNotifier<DummyStateMachine>,
    /// When true, `create_final_inputs_and_outputs` will fail with
    /// "Insufficient funds" when additional inputs are needed
    fail_insufficient_funds: AtomicBool,
}

impl std::fmt::Debug for DummyClientModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DummyClientModule")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

/// Data needed by the state machine
#[derive(Debug, Clone)]
pub struct DummyClientContext {
    pub dummy_decoder: Decoder,
}

impl Context for DummyClientContext {
    const KIND: Option<ModuleKind> = None;
}

#[apply(async_trait_maybe_send!)]
impl ClientModule for DummyClientModule {
    type Init = DummyClientInit;
    type Common = DummyModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = DummyClientContext;
    type States = DummyStateMachine;

    fn context(&self) -> Self::ModuleStateMachineContext {
        DummyClientContext {
            dummy_decoder: <Self::Common as ModuleCommon>::decoder(),
        }
    }

    fn input_fee(
        &self,
        _amount: &Amounts,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amounts> {
        Some(Amounts::ZERO)
    }

    fn output_fee(
        &self,
        _amount: &Amounts,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts> {
        Some(Amounts::ZERO)
    }

    fn supports_being_primary(&self) -> PrimaryModuleSupport {
        PrimaryModuleSupport::selected(PrimaryModulePriority::LOW, [AmountUnit::BITCOIN])
    }

    async fn create_final_inputs_and_outputs(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        _unit: AmountUnit,
        input_amount: Amount,
        output_amount: Amount,
    ) -> anyhow::Result<(
        ClientInputBundle<DummyInput, DummyStateMachine>,
        ClientOutputBundle<DummyOutput, DummyStateMachine>,
    )> {
        match input_amount.cmp(&output_amount) {
            Ordering::Less => {
                // Check if we should simulate insufficient funds
                if self.fail_insufficient_funds.load(AtomicOrdering::SeqCst) {
                    anyhow::bail!("Insufficient funds");
                }

                // Need more inputs - create a dummy input for the missing amount
                // The server will accept any input unconditionally
                let missing_input_amount = output_amount.saturating_sub(input_amount);

                let input = ClientInput {
                    input: DummyInput {
                        amount: missing_input_amount,
                        key: self.key.public_key(),
                    },
                    amounts: Amounts::new_bitcoin(missing_input_amount),
                    keys: vec![self.key],
                };

                Ok((
                    ClientInputBundle::new(vec![input], vec![]),
                    ClientOutputBundle::new(vec![], vec![]),
                ))
            }
            Ordering::Equal => Ok((
                ClientInputBundle::new(vec![], vec![]),
                ClientOutputBundle::new(vec![], vec![]),
            )),
            Ordering::Greater => {
                // Have excess inputs - create a dummy output to receive the change
                let missing_output_amount = input_amount.saturating_sub(output_amount);

                let output = ClientOutput {
                    output: DummyOutput {
                        amount: missing_output_amount,
                    },
                    amounts: Amounts::new_bitcoin(missing_output_amount),
                };

                Ok((
                    ClientInputBundle::new(vec![], vec![]),
                    ClientOutputBundle::new(
                        vec![output],
                        vec![fedimint_client_module::transaction::ClientOutputSM {
                            state_machines: Arc::new(move |out_point_range| {
                                vec![DummyStateMachine::Output(
                                    out_point_range.txid(),
                                    operation_id,
                                )]
                            }),
                        }],
                    ),
                ))
            }
        }
    }

    async fn await_primary_module_output(
        &self,
        operation_id: OperationId,
        out_point: OutPoint,
    ) -> anyhow::Result<()> {
        let stream = self
            .notifier
            .subscribe(operation_id)
            .await
            .filter_map(|state| async move {
                match state {
                    DummyStateMachine::OutputDone(txid, _) => {
                        if txid != out_point.txid {
                            return None;
                        }
                        Some(Ok(()))
                    }
                    DummyStateMachine::Refund(_) => Some(Err(anyhow::anyhow!(
                        "Error occurred processing the dummy transaction"
                    ))),
                    DummyStateMachine::Output(..) => None,
                }
            });

        pin_mut!(stream);

        stream.next_or_pending().await
    }

    async fn get_balance(&self, _dbtx: &mut DatabaseTransaction<'_>, _unit: AmountUnit) -> Amount {
        // Dummy module has infinite funds - no balance tracking needed
        Amount::ZERO
    }

    async fn subscribe_balance_changes(&self) -> BoxStream<'static, ()> {
        Box::pin(futures::stream::empty())
    }
}

impl DummyClientModule {
    /// Set whether to simulate insufficient funds errors.
    /// When enabled, `create_final_inputs_and_outputs` will fail with
    /// "Insufficient funds" when additional inputs are needed.
    pub fn set_fail_insufficient_funds(&self, fail: bool) {
        self.fail_insufficient_funds
            .store(fail, AtomicOrdering::SeqCst);
    }
}

#[derive(Debug, Clone)]
pub struct DummyClientInit;

impl ModuleInit for DummyClientInit {
    type Common = DummyCommonInit;

    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        Box::new(std::iter::empty())
    }
}

/// Generates the client module
#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for DummyClientInit {
    type Module = DummyClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(DummyClientModule {
            key: args
                .module_root_secret()
                .clone()
                .to_secp_key(&Secp256k1::new()),
            notifier: args.notifier().clone(),
            fail_insufficient_funds: AtomicBool::new(false),
        })
    }

    fn get_database_migrations(
        &self,
    ) -> BTreeMap<DatabaseVersion, fedimint_client_module::db::ClientModuleMigrationFn> {
        BTreeMap::new()
    }
}
