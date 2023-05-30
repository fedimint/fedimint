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
use fedimint_core::api::{DynGlobalApi, DynModuleApi, GlobalFederationApi};
use fedimint_core::core::{Decoder, IntoDynInstance, KeyPair};
use fedimint_core::db::{Database, ModuleDatabaseTransaction};
use fedimint_core::module::{
    CommonModuleGen, ExtendsCommonModuleGen, ModuleCommon, TransactionItemAmount,
};
use fedimint_core::util::{BoxStream, NextOrPending};
use fedimint_core::{apply, async_trait_maybe_send, Amount, OutPoint};
pub use fedimint_dummy_common as common;
use fedimint_dummy_common::config::DummyClientConfig;
use fedimint_dummy_common::{
    fed_key_pair, fed_public_key, DummyCommonGen, DummyInput, DummyModuleTypes, DummyOutput,
    DummyOutputOutcome, KIND,
};
use futures::{pin_mut, StreamExt};
use secp256k1::{Secp256k1, XOnlyPublicKey};
use states::DummyStateMachine;
use threshold_crypto::{PublicKey, Signature};

use crate::api::DummyFederationApi;
use crate::db::DummyClientFundsKeyV0;

pub mod api;
mod db;
mod states;

/// Exposed API calls for client apps
#[apply(async_trait_maybe_send!)]
pub trait DummyClientExt {
    /// Request the federation prints money for us
    async fn print_money(&self, amount: Amount) -> anyhow::Result<(OperationId, OutPoint)>;

    /// Send money to another user
    async fn send_money(&self, account: XOnlyPublicKey, amount: Amount)
        -> anyhow::Result<OutPoint>;

    /// Wait to receive money at an outpoint
    async fn receive_money(&self, outpoint: OutPoint) -> anyhow::Result<()>;

    /// Request the federation signs a message for us
    async fn fed_signature(&self, message: &str) -> anyhow::Result<Signature>;

    /// Return our account
    fn account(&self) -> XOnlyPublicKey;

    /// Return the fed's public key
    fn fed_public_key(&self) -> PublicKey;
}

#[apply(async_trait_maybe_send!)]
impl DummyClientExt for Client {
    async fn print_money(&self, amount: Amount) -> anyhow::Result<(OperationId, OutPoint)> {
        let (_dummy, instance) = self.get_first_module::<DummyClientModule>(&KIND);
        let op_id = OperationId(rand::random());

        // TODO: Building a tx could be easier
        // Create input using the fed's account
        let input = ClientInput {
            input: DummyInput {
                amount,
                account: fed_public_key(),
            },
            keys: vec![fed_key_pair()],
            state_machines: Arc::new(move |_, _| Vec::<DummyStateMachine>::new()),
        };

        // Build and send tx to the fed
        // Will output to our primary client module
        let tx = TransactionBuilder::new().with_input(input.into_dyn(instance.id));
        let outpoint = |txid, _| OutPoint { txid, out_idx: 0 };
        let txid = self
            .finalize_and_submit_transaction(op_id, KIND.as_str(), outpoint, tx)
            .await?;

        Ok((op_id, OutPoint { txid, out_idx: 0 }))
    }

    async fn send_money(
        &self,
        account: XOnlyPublicKey,
        amount: Amount,
    ) -> anyhow::Result<OutPoint> {
        let (dummy, instance) = self.get_first_module::<DummyClientModule>(&KIND);
        let mut dbtx = instance.db.begin_transaction().await;
        let op_id = OperationId(rand::random());

        // TODO: Building a tx could be easier
        // Create input using our own account
        let input = dummy
            .create_sufficient_input(&mut dbtx.get_isolated(), op_id, amount)
            .await?;
        dbtx.commit_tx().await;

        // Create output using another account
        let output = ClientOutput {
            output: DummyOutput { amount, account },
            state_machines: Arc::new(move |_, _| Vec::<DummyStateMachine>::new()),
        };

        // Build and send tx to the fed
        let tx = TransactionBuilder::new()
            .with_input(input.into_dyn(instance.id))
            .with_output(output.into_dyn(instance.id));
        let outpoint = |txid, _| OutPoint { txid, out_idx: 0 };
        let txid = self
            .finalize_and_submit_transaction(op_id, DummyCommonGen::KIND.as_str(), outpoint, tx)
            .await?;

        let tx_subscription = self.transaction_updates(op_id).await;
        tx_subscription.await_tx_accepted(txid).await?;

        Ok(OutPoint { txid, out_idx: 0 })
    }

    async fn receive_money(&self, outpoint: OutPoint) -> anyhow::Result<()> {
        let (dummy, instance) = self.get_first_module::<DummyClientModule>(&KIND);
        let mut dbtx = instance.db.begin_transaction().await;
        let DummyOutputOutcome(amount, account) = self
            .api()
            .await_output_outcome(outpoint, Duration::from_secs(10), &dummy.decoder())
            .await?;

        if account != dummy.key.x_only_public_key().0 {
            return Err(format_err!("Wrong account id"));
        }

        let funds = self.get_balance().await + amount;
        dbtx.insert_entry(&DummyClientFundsKeyV0, &funds).await;
        dbtx.commit_tx().await;
        Ok(())
    }

    async fn fed_signature(&self, message: &str) -> anyhow::Result<Signature> {
        let (_dummy, instance) = self.get_first_module::<DummyClientModule>(&KIND);
        instance.api.sign_message(message.to_string()).await?;
        let sig = instance.api.wait_signed(message.to_string()).await?;
        Ok(sig.0)
    }

    fn account(&self) -> XOnlyPublicKey {
        let (dummy, _instance) = self.get_first_module::<DummyClientModule>(&KIND);
        dummy.key.x_only_public_key().0
    }

    fn fed_public_key(&self) -> PublicKey {
        let (dummy, _instance) = self.get_first_module::<DummyClientModule>(&KIND);
        dummy.cfg.fed_public_key
    }
}

#[derive(Debug)]
pub struct DummyClientModule {
    cfg: DummyClientConfig,
    key: KeyPair,
    notifier: ModuleNotifier<DynGlobalClientContext, DummyStateMachine>,
}

/// Data needed by the state machine
#[derive(Debug, Clone)]
pub struct DummyClientContext {
    pub dummy_decoder: Decoder,
}

// TODO: Boiler-plate
impl Context for DummyClientContext {}

impl ClientModule for DummyClientModule {
    type Common = DummyModuleTypes;
    type ModuleStateMachineContext = DummyClientContext;
    type States = DummyStateMachine;

    fn context(&self) -> Self::ModuleStateMachineContext {
        DummyClientContext {
            dummy_decoder: self.decoder(),
        }
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

    async fn await_primary_module_output(
        &self,
        operation_id: OperationId,
        _out_point: OutPoint,
    ) -> anyhow::Result<Amount> {
        let stream = self
            .notifier
            .subscribe(operation_id)
            .await
            .filter_map(|state| async move {
                let DummyStateMachine::Done(amount, _) = state else { return None };
                Some(Ok(amount))
            });

        pin_mut!(stream);

        stream.next_or_pending().await
    }

    async fn get_balance(&self, dbtc: &mut ModuleDatabaseTransaction<'_>) -> Amount {
        get_funds(dbtc).await
    }

    async fn subscribe_balance_changes(&self) -> BoxStream<'static, ()> {
        Box::pin(
            self.notifier
                .subscribe_all_operations()
                .await
                .filter_map(|state| async move {
                    match state {
                        // Since Done also happens for inputs we will fire too often, but that's ok
                        DummyStateMachine::Done(_, _) => Some(()),
                        DummyStateMachine::Input { .. } => Some(()),
                        _ => None,
                    }
                }),
        )
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
        api: DynGlobalApi,
        module_api: DynModuleApi,
    ) -> anyhow::Result<DynPrimaryClientModule> {
        Ok(self
            .init(cfg, db, module_root_secret, notifier, api, module_api)
            .await?
            .into())
    }

    async fn init(
        &self,
        cfg: Self::Config,
        _db: Database,
        module_root_secret: DerivableSecret,
        notifier: ModuleNotifier<DynGlobalClientContext, <Self::Module as ClientModule>::States>,
        _api: DynGlobalApi,
        _module_api: DynModuleApi,
    ) -> anyhow::Result<Self::Module> {
        Ok(DummyClientModule {
            cfg,
            key: module_root_secret.to_secp_key(&Secp256k1::new()),
            notifier,
        })
    }
}
