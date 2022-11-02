//! # Module Client State Machine
//! Module clients have to keep track of inputs and outputs created in the past in case further
//! action is required. Since the client can crash at any point intermediate results have to be
//! persisted atomically. This module defines an interface and execution environment for such
//! actions by modeling them as state machines.

use std::time::SystemTime;

use async_trait::async_trait;
use fedimint_api::db::DatabaseTransaction;
use fedimint_api::TransactionId;
use fedimint_core::transaction::Input;

use crate::query::QueryStrategy;

#[async_trait]
pub trait State {
    /// Returns a list of events on which the state machine should be woken up
    fn poll_events(&self) -> Vec<PollEventCondition>;

    /// Logical operation to which the action belongs.
    ///
    /// This information can be used to route anyway correlated network traffic over the same Tor
    /// circuit. It is typically set to the transaction id of the first transaction of the
    /// operation.
    fn operation_id(&self) -> TransactionId;

    /// Try to drive the state machine forward
    async fn poll(
        self: Box<Self>,
        side_effects_executor: &mut dyn DelayedSideEffectsExecutor,
        event_condition: PollEventCondition,
        event: PollEvent,
    ) -> Result<Box<Self>, anyhow::Error>;
}

pub enum PollEventCondition {
    Timer {
        fire_time: SystemTime,
    },
    AwaitSubscription {
        operation_id: TransactionId,
        api_endpoint: String,
        query_strategy: Box<dyn QueryStrategy<serde_json::Value>>,
        predicate: Box<dyn Fn(&serde_json::Value) -> bool>,
    },
}

pub enum PollEvent {
    Timer {
        fire_time: SystemTime,
        now: SystemTime,
    },
    AwaitSubscription {
        operation_id: TransactionId,
        api_endpoint: String,
        result: serde_json::Value,
    },
}

#[async_trait]
pub trait DelayedSideEffectsExecutor {
    /// Create a transaction from the supplied input that sends all the funds to the user.
    ///
    /// The transaction is queued for submission via `api_call` and its ID is returned.
    async fn claim_funds(&mut self, input: Input) -> TransactionId;

    /// Queue an API call to be performed after the state transition
    async fn api_call(&mut self, api_endpoint: String, body: serde_json::Value);

    /// Do some direct DB operation before any of the side effects are executed
    fn db_transaction(&mut self) -> &mut DatabaseTransaction;

    /// Commit database changes, then execute side effects
    async fn execute(self: Box<Self>);
}
