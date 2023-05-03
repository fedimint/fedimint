use std::sync::Arc;
use std::time::Duration;

use anyhow::format_err;
use fedimint_client::derivable_secret::DerivableSecret;
use fedimint_client::module::gen::ClientModuleGen;
use fedimint_client::module::{
    ClientModule, DynPrimaryClientModule, IClientModule, PrimaryClientModule,
};
use fedimint_client::sm::{Context, ModuleNotifier, OperationId};
use fedimint_client::transaction::{ClientInput, ClientOutput, TransactionBuilder};
use fedimint_client::{Client, DynGlobalClientContext};
use fedimint_core::api::GlobalFederationApi;
use fedimint_core::core::{IntoDynInstance, KeyPair, ModuleInstanceId};
use fedimint_core::db::{Database, ModuleDatabaseTransaction};
use fedimint_core::module::{
    CommonModuleGen, ExtendsCommonModuleGen, ModuleCommon, TransactionItemAmount,
};
use fedimint_core::{apply, async_trait_maybe_send, Amount, OutPoint};
pub use fedimint_dummy_common as common;
use fedimint_dummy_common::config::DummyClientConfig;
use fedimint_dummy_common::{
    DummyCommonGen, DummyInput, DummyModuleTypes, DummyOutput, DummyOutputOutcome,
    DummyPrintMoneyRequest,
};
use secp256k1::{Secp256k1, XOnlyPublicKey};
use states::DummyStateMachine;

use crate::api::DummyFederationApi;
use crate::db::DummyClientFundsKeyV0;

pub mod api;
mod db;
mod states;

/// Exposed API calls for client apps
#[apply(async_trait_maybe_send!)]
pub trait DummyClientExt {
    /// Request the federation prints money for us
    async fn print_money(&self, amount: Amount) -> anyhow::Result<()>;

    /// Send money to another user
    async fn send_money(&self, account: XOnlyPublicKey, amount: Amount)
        -> anyhow::Result<OutPoint>;

    /// Wait to receive money at an outpoint
    async fn receive_money(&self, outpoint: OutPoint) -> anyhow::Result<()>;

    /// The amount of funds we have
    async fn total_funds(&self) -> Amount;

    /// Return our account
    fn account(&self) -> XOnlyPublicKey;
}

#[apply(async_trait_maybe_send!)]
impl DummyClientExt for Client {
    async fn print_money(&self, amount: Amount) -> anyhow::Result<()> {
        let (id, dummy) = dummy_client(self);
        let account = dummy.key.x_only_public_key().0;
        let request = DummyPrintMoneyRequest { amount, account };
        self.api().with_module(id).print_money(request).await?;
        let funds = self.api().with_module(id).wait_for_money(account).await?;

        // TODO: Not very nice to get to the module db
        let mod_db = self.db().new_isolated(id);
        let mut dbtx = mod_db.begin_transaction().await;
        dbtx.insert_entry(&DummyClientFundsKeyV0, &funds).await;
        dbtx.commit_tx().await;
        Ok(())
    }

    async fn send_money(
        &self,
        account: XOnlyPublicKey,
        amount: Amount,
    ) -> anyhow::Result<OutPoint> {
        let (id, dummy) = dummy_client(self);
        let mut dbtx = self.db().begin_transaction().await;
        let op_id = rand::random();

        // TODO: Building a tx could be easier
        // Create input using our own account
        let input = dummy
            .create_sufficient_input(&mut dbtx.with_module_prefix(id), op_id, amount)
            .await?;
        dbtx.commit_tx().await;

        // Create output using another account
        let output = ClientOutput {
            output: DummyOutput { amount, account },
            state_machines: Arc::new(move |_, _| Vec::<DummyStateMachine>::new()),
        };

        // Build and send tx to the fed
        let tx = TransactionBuilder::new()
            .with_input(input.into_dyn(id))
            .with_output(output.into_dyn(id));
        let outpoint = |txid| OutPoint { txid, out_idx: 0 };
        let txid = self
            .finalize_and_submit_transaction(op_id, DummyCommonGen::KIND.as_str(), outpoint, tx)
            .await?;

        let tx_subscription = self.transaction_updates(op_id).await;
        // TODO: Return actual API error if any
        tx_subscription
            .await_tx_accepted(txid)
            .await
            .expect("Tx failed");

        Ok(outpoint(txid))
    }

    async fn receive_money(&self, outpoint: OutPoint) -> anyhow::Result<()> {
        let (id, dummy) = dummy_client(self);

        let DummyOutputOutcome(amount, account) = self
            .api()
            .await_output_outcome(outpoint, Duration::from_secs(10), &dummy.decoder())
            .await?;

        if account != dummy.key.x_only_public_key().0 {
            return Err(format_err!("Wrong account id"));
        }

        let mod_db = self.db().new_isolated(id);
        let mut dbtx = mod_db.begin_transaction().await;
        let funds = self.total_funds().await + amount;
        dbtx.insert_entry(&DummyClientFundsKeyV0, &funds).await;
        dbtx.commit_tx().await;
        Ok(())
    }

    async fn total_funds(&self) -> Amount {
        // TODO: Not very nice to get to the module db
        let (id, _) = dummy_client(self);
        let mut dbtx = self.db().begin_transaction().await;
        let mut mod_dbtx = dbtx.with_module_prefix(id);
        get_funds(&mut mod_dbtx).await
    }

    fn account(&self) -> XOnlyPublicKey {
        let (_, client) = dummy_client(self);
        client.key.x_only_public_key().0
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
    type States = DummyStateMachine;

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
        id: OperationId,
        amount: Amount,
    ) -> anyhow::Result<ClientInput<<Self::Common as ModuleCommon>::Input, Self::States>> {
        // Check and subtract from our funds
        let funds = get_funds(dbtx).await;
        if funds < amount {
            return Err(format_err!("Insufficient funds"));
        }
        let updated = funds - amount;
        dbtx.insert_entry(&DummyClientFundsKeyV0, &updated).await;

        // Construct input and state machine to track the tx
        Ok(ClientInput {
            input: DummyInput {
                amount,
                account: self.key.x_only_public_key().0,
            },
            keys: vec![self.key],
            state_machines: Arc::new(move |txid, _| {
                vec![DummyStateMachine::Input(amount, txid, id)]
            }),
        })
    }

    async fn create_exact_output(
        &self,
        _dbtx: &mut ModuleDatabaseTransaction<'_>,
        id: OperationId,
        amount: Amount,
    ) -> ClientOutput<<Self::Common as ModuleCommon>::Output, Self::States> {
        // Construct output and state machine to track the tx
        ClientOutput {
            output: DummyOutput {
                amount,
                account: self.key.x_only_public_key().0,
            },
            state_machines: Arc::new(move |txid, _| {
                vec![DummyStateMachine::Output(amount, txid, id)]
            }),
        }
    }
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

    // TODO: Boilerplate-code
    async fn init_primary(
        &self,
        cfg: Self::Config,
        db: Database,
        module_root_secret: DerivableSecret,
        notifier: ModuleNotifier<DynGlobalClientContext, <Self::Module as ClientModule>::States>,
    ) -> anyhow::Result<DynPrimaryClientModule> {
        Ok(self
            .init(cfg, db, module_root_secret, notifier)
            .await?
            .into())
    }

    async fn init(
        &self,
        cfg: Self::Config,
        _db: Database,
        module_root_secret: DerivableSecret,
        _notifier: ModuleNotifier<DynGlobalClientContext, <Self::Module as ClientModule>::States>,
    ) -> anyhow::Result<Self::Module> {
        Ok(DummyClientModule {
            cfg,
            key: module_root_secret.to_secp_key(&Secp256k1::new()),
        })
    }
}
