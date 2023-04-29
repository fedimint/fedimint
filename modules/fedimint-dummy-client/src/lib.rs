use std::sync::Arc;

use anyhow::format_err;
use fedimint_client::derivable_secret::DerivableSecret;
use fedimint_client::module::gen::ClientModuleGen;
use fedimint_client::module::{ClientModule, PrimaryClientModule};
use fedimint_client::sm::{
    ClientSMDatabaseTransaction, Context, DynState, ModuleNotifier, OperationId, State,
    StateTransition,
};
use fedimint_client::transaction::{ClientInput, ClientOutput};
use fedimint_client::{Client, DynGlobalClientContext};
use fedimint_core::core::{IntoDynInstance, KeyPair, ModuleInstanceId};
use fedimint_core::db::{Database, ModuleDatabaseTransaction};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{CommonModuleGen, ExtendsCommonModuleGen, ModuleCommon, TransactionItemAmount};
use fedimint_core::{Amount, apply, async_trait_maybe_send, TransactionId};
pub use fedimint_dummy_common as common;
use fedimint_dummy_common::config::DummyClientConfig;
use fedimint_dummy_common::{DummyCommonGen, DummyInput, DummyModuleTypes, DummyOutput, DummyPrintMoneyRequest};
use secp256k1::Secp256k1;
use states::{DummyClientState, DummyClientStateMachine};
use crate::api::DummyFederationApi;

use crate::db::DummyClientFundsKeyV0;

mod db;
mod states;
mod api;

/// Exposed library API for client apps
#[apply(async_trait_maybe_send!)]
pub trait DummyClientExt {
    /// Request the federation prints money for us
    async fn print_money(&self, amount: Amount) -> anyhow::Result<()>;
}

#[apply(async_trait_maybe_send!)]
impl DummyClientExt for Client {
    async fn print_money(&self, amount: Amount) -> anyhow::Result<()> {
        let account = dummy_client(&self).1.key.x_only_public_key().0;
        Ok(self.api().print_money(DummyPrintMoneyRequest{
            amount,
            account,
        }).await?)
    }
}

// TODO: Boiler-plate
fn dummy_client(client: &Client) -> (ModuleInstanceId, &DummyClientModule) {
    let id = client
        .get_first_instance(&DummyCommonGen::KIND)
        .expect("No mint module attached to client");

    let client = client
        .get_module_client::<DummyClientModule>(id)
        .expect("Instance ID exists, we just fetched it");

    (id, client)
}

#[derive(Debug)]
pub struct DummyClientModule {
    cfg: DummyClientConfig,
    notifier: ModuleNotifier<DynGlobalClientContext, DummyClientStateMachine>,
    key: KeyPair,
}

/// Data needed by the state machine
#[derive(Debug, Clone)]
pub struct DummyClientContext;

// TODO: Boiler-plate
impl Context for DummyClientContext {}

impl ClientModule for DummyClientModule {
    type Common = DummyModuleTypes;
    type ModuleStateMachineContext = DummyClientContext;
    type States = DummyClientStateMachine;

    fn context(&self) -> Self::ModuleStateMachineContext {
        DummyClientContext
    }

    fn input_amount(&self, input: &<Self::Common as ModuleCommon>::Input) -> TransactionItemAmount {
        TransactionItemAmount {
            amount: input.amount,
            fee: self.cfg.tx_fee,
        }
    }

    fn output_amount(
        &self,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> TransactionItemAmount {
        TransactionItemAmount {
            amount: output.amount,
            fee: self.cfg.tx_fee,
        }
    }
}

/// Creates exact inputs and outputs for the module
#[apply(async_trait_maybe_send)]
impl PrimaryClientModule for DummyClientModule {
    async fn create_sufficient_input(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        operation_id: OperationId,
        min_amount: Amount,
    ) -> anyhow::Result<ClientInput<<Self::Common as ModuleCommon>::Input, Self::States>> {
        // Check and subtract from our funds
        let funds = get_funds(dbtx).await;
        if funds < min_amount {
            return Err(format_err!("Insufficient funds"));
        }
        set_funds(dbtx, funds - min_amount).await;

        // Construct the state machine to track our input
        let state_machines = Arc::new(move |txid, idx| {
            vec![DummyClientStateMachine {
                operation_id,
                txid,
                idx,
                amount: min_amount,
                state: DummyClientState::Input,
            }]
        });

        Ok(ClientInput {
            input: DummyInput {
                amount: min_amount,
                account: self.key.x_only_public_key().0,
            },
            keys: vec![self.key],
            state_machines,
        })
    }

    async fn create_exact_output(
        &self,
        _dbtx: &mut ModuleDatabaseTransaction<'_>,
        operation_id: OperationId,
        amount: Amount,
    ) -> ClientOutput<<Self::Common as ModuleCommon>::Output, Self::States> {
        // Construct the state machine to track our output
        let state_machines = Arc::new(move |txid, idx| {
            vec![DummyClientStateMachine {
                operation_id,
                txid,
                idx,
                amount,
                state: DummyClientState::Output,
            }]
        });

        ClientOutput {
            output: DummyOutput {
                amount,
                account: self.key.x_only_public_key().0,
            },
            state_machines,
        }
    }
}

async fn set_funds(dbtx: &mut ModuleDatabaseTransaction<'_>, amount: Amount) {
    dbtx.insert_entry(&DummyClientFundsKeyV0, &amount).await;
}

async fn get_funds(dbtx: &mut ModuleDatabaseTransaction<'_>) -> Amount {
    let funds = dbtx.get_value(&DummyClientFundsKeyV0).await;
    funds.unwrap_or(Amount::ZERO)
}

#[derive(Debug, Clone)]
pub struct DummyClientGen;

// TODO: Boilerplate-code
impl ExtendsCommonModuleGen for DummyClientGen {
    type Common = DummyCommonGen;
}

/// Generates the client module
#[apply(async_trait_maybe_send!)]
impl ClientModuleGen for DummyClientGen {
    type Module = DummyClientModule;
    type Config = DummyClientConfig;

    async fn init(
        &self,
        cfg: Self::Config,
        _db: Database,
        module_root_secret: DerivableSecret,
        notifier: ModuleNotifier<DynGlobalClientContext, <Self::Module as ClientModule>::States>,
    ) -> anyhow::Result<Self::Module> {
        Ok(DummyClientModule {
            cfg,
            notifier,
            key: module_root_secret.to_secp_key(&Secp256k1::new()),
        })
    }
}
