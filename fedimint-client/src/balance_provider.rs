use fedimint_core::{
    apply, async_trait_maybe_send,
    core::{ModuleInstanceId, OperationId},
    db::DatabaseTransaction,
    task::{MaybeSend, MaybeSync},
    util::BoxStream,
    Amount, OutPoint,
};

use crate::{
    module::DynClientModule,
    transaction::{ClientInput, ClientOutput},
    Client,
};

#[apply(async_trait_maybe_send!)]
pub trait BalanceProvider: 'static + MaybeSend + MaybeSync {
    /// Creates an input of **at least** a given `min_amount` from the holdings
    /// managed by the module.
    ///
    /// If successful it returns:
    /// * A set of private keys belonging to the input for signing the
    ///   transaction
    /// * The input of **at least** `min_amount`, the actual amount might be
    ///   larger, the caller has to handle this case and possibly generate
    ///   change using `create_change_output`.
    /// * A closure that generates states belonging to the input. This closure
    ///   takes the transaction id of the transaction in which the input was
    ///   used and the input index as input since these cannot be known at time
    ///   of calling `create_funding_input` and have to be injected later.
    ///
    /// The function returns an error if the client's funds are not sufficient
    /// to create the requested input.
    async fn create_sufficient_input(
        &self,
        client: &Client,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        min_amount: Amount,
    ) -> anyhow::Result<Vec<ClientInput>>;

    /// Creates an output of **exactly** `amount` that will pay into the
    /// holdings managed by the module.
    ///
    /// It returns:
    /// * The output of **exactly** `amount`.
    /// * A closure that generates states belonging to the output. This closure
    ///   takes the transaction id of the transaction in which the output was
    ///   used and the output index as input since these cannot be known at time
    ///   of calling `create_change_output` and have to be injected later.
    async fn create_exact_output(
        &self,
        client: &Client,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        amount: Amount,
    ) -> Vec<ClientOutput>;

    /// Waits for the funds from an output created by
    /// [`Self::create_exact_output`] to become available. This function
    /// returning typically implies a change in the output of
    /// [`Self::get_balance`].
    async fn await_primary_module_output(
        &self,
        client: &Client,
        operation_id: OperationId,
        out_point: OutPoint,
    ) -> anyhow::Result<Amount>;

    /// Returns the balance held by this module and available for funding
    /// transactions.
    async fn get_balance(&self, client: &Client, dbtx: &mut DatabaseTransaction<'_>) -> Amount;

    /// Returns a stream that will output the updated module balance each time
    /// it changes.
    async fn subscribe_balance_changes(&self, client: &Client) -> BoxStream<'static, ()>;
}

pub struct PrimaryModuleBalanceProvider {
    primary_module_instance_id: ModuleInstanceId,
}

#[apply(async_trait_maybe_send!)]
impl BalanceProvider for PrimaryModuleBalanceProvider {
    async fn create_sufficient_input(
        &self,
        client: &Client,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        min_amount: Amount,
    ) -> anyhow::Result<Vec<ClientInput>> {
        let primary_module = self.primary_module(client);
        primary_module
            .create_sufficient_input(
                self.primary_module_instance_id,
                dbtx,
                operation_id,
                min_amount,
            )
            .await
    }

    async fn create_exact_output(
        &self,
        client: &Client,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        amount: Amount,
    ) -> Vec<ClientOutput> {
        self.primary_module(client)
            .create_exact_output(self.primary_module_instance_id, dbtx, operation_id, amount)
            .await
    }

    async fn await_primary_module_output(
        &self,
        client: &Client,
        operation_id: OperationId,
        out_point: OutPoint,
    ) -> anyhow::Result<Amount> {
        self.primary_module(client)
            .await_primary_module_output(operation_id, out_point)
            .await
    }

    async fn get_balance(&self, client: &Client, dbtx: &mut DatabaseTransaction<'_>) -> Amount {
        self.primary_module(client)
            .get_balance(self.primary_module_instance_id, dbtx)
            .await
    }

    async fn subscribe_balance_changes(&self, client: &Client) -> BoxStream<'static, ()> {
        self.primary_module(client)
            .subscribe_balance_changes()
            .await
    }
}

impl PrimaryModuleBalanceProvider {
    pub fn new(primary_module_instance_id: ModuleInstanceId) -> Self {
        Self {
            primary_module_instance_id,
        }
    }

    fn primary_module<'a>(&self, client: &'a Client) -> &'a DynClientModule {
        client
            .modules
            .get(self.primary_module_instance_id)
            .expect("primary module must be present")
    }
}
