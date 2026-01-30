#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

use core::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::Arc;

use db::{DbKeyPrefix, DummyClientFundsKey, DummyClientFundsKeyPrefixAll};
use fedimint_client_module::db::ClientModuleMigrationFn;
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{
    ClientContext, ClientModule, OutPointRange, PrimaryModulePriority, PrimaryModuleSupport,
};
use fedimint_client_module::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client_module::transaction::{
    ClientInput, ClientInputBundle, ClientInputSM, ClientOutput, ClientOutputBundle, ClientOutputSM,
};
use fedimint_client_module::{DynGlobalClientContext, sm_enum_variant_translation};
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{
    Database, DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    AmountUnit, Amounts, ApiVersion, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::secp256k1::{Keypair, Secp256k1};
use fedimint_core::util::BoxStream;
use fedimint_core::{Amount, OutPoint, apply, async_trait_maybe_send, push_db_pair_items};
pub use fedimint_dummy_common as common;
use fedimint_dummy_common::{DummyCommonInit, DummyInput, DummyModuleTypes, DummyOutput};
use futures::StreamExt;
use strum::IntoEnumIterator;
use tokio::sync::watch;

pub mod db;
mod input_sm;
mod output_sm;

use input_sm::{DummyInputSMCommon, DummyInputSMState, DummyInputStateMachine};
use output_sm::{DummyOutputSMCommon, DummyOutputSMState, DummyOutputStateMachine};

/// Wrapper enum for all state machines in the dummy module
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum DummyStateMachine {
    Input(DummyInputStateMachine),
    Output(DummyOutputStateMachine),
}

impl State for DummyStateMachine {
    type ModuleContext = DummyClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self {
            DummyStateMachine::Input(sm) => {
                sm_enum_variant_translation!(
                    sm.transitions(context, global_context),
                    DummyStateMachine::Input
                )
            }
            DummyStateMachine::Output(sm) => {
                sm_enum_variant_translation!(
                    sm.transitions(context, global_context),
                    DummyStateMachine::Output
                )
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            DummyStateMachine::Input(sm) => sm.operation_id(),
            DummyStateMachine::Output(sm) => sm.operation_id(),
        }
    }
}

impl IntoDynInstance for DummyStateMachine {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

pub struct DummyClientModule {
    key: Keypair,
    db: Database,
    notifier: ModuleNotifier<DummyStateMachine>,
    client_ctx: ClientContext<Self>,
    balance_update_sender: watch::Sender<()>,
}

impl std::fmt::Debug for DummyClientModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DummyClientModule").finish_non_exhaustive()
    }
}

/// Data needed by the state machine
#[derive(Clone)]
pub struct DummyClientContext {
    pub balance_update_sender: watch::Sender<()>,
}

impl std::fmt::Debug for DummyClientContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DummyClientContext").finish_non_exhaustive()
    }
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
            balance_update_sender: self.balance_update_sender.clone(),
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
        PrimaryModuleSupport::Any {
            priority: PrimaryModulePriority::LOW,
        }
    }

    async fn create_final_inputs_and_outputs(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        unit: AmountUnit,
        input_amount: Amount,
        output_amount: Amount,
    ) -> anyhow::Result<(
        ClientInputBundle<DummyInput, DummyStateMachine>,
        ClientOutputBundle<DummyOutput, DummyStateMachine>,
    )> {
        dbtx.ensure_isolated().expect("must be isolated");

        match input_amount.cmp(&output_amount) {
            Ordering::Less => {
                // Spending: balance subtracted immediately, refund on rejection
                let missing_input_amount = output_amount.saturating_sub(input_amount);

                let our_funds = get_funds(dbtx, unit).await;

                if our_funds < missing_input_amount {
                    return Err(anyhow::format_err!("Insufficient funds"));
                }

                let updated = our_funds.saturating_sub(missing_input_amount);

                dbtx.insert_entry(&DummyClientFundsKey(unit), &updated)
                    .await;

                let sender = self.balance_update_sender.clone();

                dbtx.on_commit(move || sender.send_replace(()));

                let input = ClientInput {
                    input: DummyInput {
                        amount: missing_input_amount,
                        unit,
                        pub_key: self.key.public_key(),
                    },
                    amounts: Amounts::new_custom(unit, missing_input_amount),
                    keys: vec![self.key],
                };

                let input_sm = ClientInputSM {
                    state_machines: Arc::new(move |out_point_range: OutPointRange| {
                        out_point_range
                            .into_iter()
                            .map(|out_point| {
                                DummyStateMachine::Input(DummyInputStateMachine {
                                    common: DummyInputSMCommon {
                                        operation_id,
                                        out_point,
                                        amount: missing_input_amount,
                                        unit,
                                    },
                                    state: DummyInputSMState::Created,
                                })
                            })
                            .collect()
                    }),
                };

                Ok((
                    ClientInputBundle::new(vec![input], vec![input_sm]),
                    ClientOutputBundle::new(vec![], vec![]),
                ))
            }
            Ordering::Equal => Ok((
                ClientInputBundle::new(vec![], vec![]),
                ClientOutputBundle::new(vec![], vec![]),
            )),
            Ordering::Greater => {
                // Receiving: balance added only on acceptance
                let missing_output_amount = input_amount.saturating_sub(output_amount);

                let output = ClientOutput {
                    output: DummyOutput {
                        amount: missing_output_amount,
                        unit,
                    },
                    amounts: Amounts::new_custom(unit, missing_output_amount),
                };

                let output_sm = ClientOutputSM {
                    state_machines: Arc::new(move |out_point_range: OutPointRange| {
                        out_point_range
                            .into_iter()
                            .map(|out_point| {
                                DummyStateMachine::Output(DummyOutputStateMachine {
                                    common: DummyOutputSMCommon {
                                        operation_id,
                                        out_point,
                                        amount: missing_output_amount,
                                        unit,
                                    },
                                    state: DummyOutputSMState::Created,
                                })
                            })
                            .collect()
                    }),
                };

                Ok((
                    ClientInputBundle::new(vec![], vec![]),
                    ClientOutputBundle::new(vec![output], vec![output_sm]),
                ))
            }
        }
    }

    async fn await_primary_module_output(
        &self,
        operation_id: OperationId,
        out_point: OutPoint,
    ) -> anyhow::Result<()> {
        let mut stream = self.notifier.subscribe(operation_id).await;

        loop {
            let DummyStateMachine::Output(output_sm) = stream
                .next()
                .await
                .expect("Stream should not end before reaching final state")
            else {
                continue;
            };

            if output_sm.common.out_point != out_point {
                continue;
            }

            match output_sm.state {
                DummyOutputSMState::Created => {}
                DummyOutputSMState::Accepted => return Ok(()),
                DummyOutputSMState::Rejected => {
                    return Err(anyhow::anyhow!("Transaction was rejected"));
                }
            }
        }
    }

    async fn get_balance(&self, dbtc: &mut DatabaseTransaction<'_>, unit: AmountUnit) -> Amount {
        get_funds(dbtc, unit).await
    }

    async fn get_balances(&self, dbtx: &mut DatabaseTransaction<'_>) -> Amounts {
        get_funds_all(dbtx).await
    }

    async fn subscribe_balance_changes(&self) -> BoxStream<'static, ()> {
        Box::pin(tokio_stream::wrappers::WatchStream::new(
            self.balance_update_sender.subscribe(),
        ))
    }
}

impl DummyClientModule {
    /// The dummy server accepts any public key, so this can be used to create
    /// funds out of thin air that get converted to e-cash as change.
    pub fn create_input(&self, amount: Amount) -> ClientInputBundle {
        let keypair = Keypair::new(&Secp256k1::new(), &mut rand::rngs::OsRng);

        let client_input = ClientInput {
            input: DummyInput {
                amount,
                unit: AmountUnit::BITCOIN,
                pub_key: keypair.public_key(),
            },
            amounts: Amounts::new_bitcoin(amount),
            keys: vec![keypair],
        };

        self.client_ctx
            .make_client_inputs(ClientInputBundle::new_no_sm(vec![client_input]))
    }

    /// Add funds to the local balance (for testing)
    pub async fn mock_receive(&self, amount: Amount, unit: AmountUnit) -> anyhow::Result<()> {
        let mut dbtx = self.db.begin_transaction().await;

        let current = dbtx
            .get_value(&DummyClientFundsKey(unit))
            .await
            .unwrap_or(Amount::ZERO);

        dbtx.insert_entry(&DummyClientFundsKey(unit), &(current + amount))
            .await;

        dbtx.commit_tx().await;

        Ok(())
    }
}

async fn get_funds(dbtx: &mut DatabaseTransaction<'_>, unit: AmountUnit) -> Amount {
    dbtx.get_value(&DummyClientFundsKey(unit))
        .await
        .unwrap_or(Amount::ZERO)
}

async fn get_funds_all(dbtx: &mut DatabaseTransaction<'_>) -> Amounts {
    dbtx.find_by_prefix(&DummyClientFundsKeyPrefixAll)
        .await
        .fold(Amounts::ZERO, |acc, (key, amount)| async move {
            acc.checked_add_unit(amount, key.0).expect("can't overflow")
        })
        .await
}

#[derive(Debug, Clone)]
pub struct DummyClientInit;

impl ModuleInit for DummyClientInit {
    type Common = DummyCommonInit;

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let mut items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::ClientFunds => {
                    push_db_pair_items!(
                        dbtx,
                        DummyClientFundsKeyPrefixAll,
                        DummyClientFundsKey,
                        Amount,
                        items,
                        "Dummy Funds"
                    );
                }
                DbKeyPrefix::ExternalReservedStart
                | DbKeyPrefix::CoreInternalReservedStart
                | DbKeyPrefix::CoreInternalReservedEnd => {}
            }
        }

        Box::new(items.into_iter())
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
            db: args.db().clone(),
            notifier: args.notifier().clone(),
            client_ctx: args.context(),
            balance_update_sender: watch::channel(()).0,
        })
    }

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientModuleMigrationFn> {
        BTreeMap::new()
    }
}
