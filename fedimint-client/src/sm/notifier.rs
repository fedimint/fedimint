use fedimint_client_module::module::FinalClientIface;
use fedimint_client_module::sm::{DynState, ModuleNotifier};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::util::FmtCompact;
use tracing::{debug, trace};

/// State transition notifier owned by the modularized client used to inform
/// modules of state transitions.
///
/// To not lose any state transitions that happen before a module subscribes to
/// the operation the notifier loads all belonging past state transitions from
/// the DB. State transitions may be reported multiple times and out of order.
#[derive(Clone)]
pub struct Notifier {
    /// Broadcast channel used to send state transitions to all subscribers
    broadcast: tokio::sync::broadcast::Sender<DynState>,
}

impl Notifier {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let (sender, _receiver) = tokio::sync::broadcast::channel(10_000);
        Self { broadcast: sender }
    }

    /// Notify all subscribers of a state transition
    pub fn notify(&self, state: DynState) {
        let queue_len = self.broadcast.len();
        trace!(?state, %queue_len, "Sending notification about state transition");
        // FIXME: use more robust notification mechanism
        if let Err(err) = self.broadcast.send(state) {
            debug!(
                err = %err.fmt_compact(),
                %queue_len,
                receivers=self.broadcast.receiver_count(),
                "Could not send state transition notification, no active receivers"
            );
        }
    }

    /// Create a new notifier for a specific module instance that can only
    /// subscribe to the instance's state transitions
    pub fn module_notifier<S>(
        &self,
        module_instance: ModuleInstanceId,
        client: FinalClientIface,
    ) -> ModuleNotifier<S>
    where
        S: fedimint_client_module::sm::State,
    {
        ModuleNotifier::new(self.broadcast.clone(), module_instance, client)
    }

    /// Create a [`NotifierSender`] handle that lets the owner trigger
    /// notifications without having to hold a full `Notifier`.
    pub fn sender(&self) -> NotifierSender {
        NotifierSender {
            sender: self.broadcast.clone(),
        }
    }
}

/// Notifier send handle that can be shared to places where we don't need an
/// entire [`Notifier`] but still need to trigger notifications. The main use
/// case is triggering notifications when a DB transaction was committed
/// successfully.
pub struct NotifierSender {
    sender: tokio::sync::broadcast::Sender<DynState>,
}

impl NotifierSender {
    /// Notify all subscribers of a state transition
    pub fn notify(&self, state: DynState) {
        let _res = self.sender.send(state);
    }
}
