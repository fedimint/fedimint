mod dbtx;
pub(crate) mod executor;
/// State machine state interface
mod state;
pub mod util;

// FIXME: use DB subscriptions? Needs prefix subscriptions :(
/// Helper to notify modules about state transitions
mod notifier;

use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

pub use dbtx::ClientSMDatabaseTransaction;
pub use executor::{ActiveState, Executor, ExecutorBuilder, InactiveState};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::{MaybeSend, MaybeSync};
pub use notifier::{ModuleNotifier, Notifier, NotifierSender};
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize};
pub use state::{Context, DynContext, DynState, IState, OperationState, State, StateTransition};

/// Context given to all state machines
pub trait GlobalContext: Debug + Clone + MaybeSync + MaybeSend + 'static {}

impl GlobalContext for () {}

/// Unique identifier for one semantic, correlatable operation.
///
/// The concept of *operations* is used to avoid losing privacy while being as
/// efficient as possible with regards to network requests.
///
/// For Fedimint transactions to be private users need to communicate with the
/// federation using an anonymous communication network. If each API request was
/// done in a way that it cannot be correlated to any other API request we would
/// achieve privacy, but would reduce efficiency. E.g. on Tor we would need to
/// open a new circuit for every request and open a new web socket connection.
///
/// Fortunately we do not need to do that to maintain privacy. Many API requests
/// and transactions can be correlated by the federation anyway, in these cases
/// it does not make any difference to re-use the same network connection. All
/// requests, transactions, state machines that are connected from the
/// federation's point of view anyway are grouped together as one *operation*.
///
/// # Choice of Operation ID
///
/// In cases where an operation is created by a new transaction that's being
/// submitted the transaction's ID can be used as operation ID. If there is no
/// transaction related to it, it should be generated randomly. Since it is a
/// 256bit value collisions are impossible for all intents and purposes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Encodable, Decodable)]
pub struct OperationId(pub [u8; 32]);

impl OperationId {
    /// Generate random [`OperationId`]
    pub fn new_random() -> Self {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl Display for OperationId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        bitcoin_hashes::hex::format_hex(&self.0, f)
    }
}

impl Debug for OperationId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "OperationId({self})")
    }
}

impl FromStr for OperationId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: [u8; 32] = bitcoin_hashes::hex::FromHex::from_hex(s)?;
        Ok(OperationId(bytes))
    }
}

impl Serialize for OperationId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for OperationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let operation_id = OperationId::from_str(&s)
                .map_err(|e| serde::de::Error::custom(format!("invalid operation id: {e}")))?;
            Ok(operation_id)
        } else {
            let bytes: [u8; 32] = <[u8; 32]>::deserialize(deserializer)?;
            Ok(OperationId(bytes))
        }
    }
}
