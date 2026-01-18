use std::ops;
use std::sync::Arc;
use std::time::Duration;

use anyhow::format_err;
use fedimint_core::runtime;
use fedimint_core::util::FmtCompactAnyhow as _;
use fedimint_logging::LOG_CLIENT;
#[cfg(not(target_family = "wasm"))]
use tokio::runtime::{Handle as RuntimeHandle, RuntimeFlavor};
use tracing::{debug, error, trace, warn};

use super::Client;
use crate::ClientBuilder;

/// User handle to the [`Client`] instance
///
/// On the drop of [`ClientHandle`] the client will be shut-down, and resources
/// it used freed.
///
/// Notably it [`ops::Deref`]s to the [`Client`] where most
/// methods live.
///
/// Put this in an Arc to clone it (see [`ClientHandleArc`]).
#[derive(Debug)]
pub struct ClientHandle {
    inner: Option<Arc<Client>>,
}

/// An alias for a reference counted [`ClientHandle`]
pub type ClientHandleArc = Arc<ClientHandle>;

impl ClientHandle {
    /// Create
    pub(crate) fn new(inner: Arc<Client>) -> Self {
        ClientHandle {
            inner: inner.into(),
        }
    }

    pub(crate) fn as_inner(&self) -> &Arc<Client> {
        self.inner.as_ref().expect("Inner always set")
    }

    pub fn start_executor(&self) {
        self.as_inner().start_executor();
    }

    /// Shutdown the client.
    pub async fn shutdown(mut self) {
        self.shutdown_inner().await;
    }

    async fn shutdown_inner(&mut self) {
        let Some(inner) = self.inner.take() else {
            error!(
                target: LOG_CLIENT,
                "ClientHandleShared::shutdown called twice"
            );
            return;
        };
        inner.executor.stop_executor();
        let db = inner.db.clone();
        debug!(target: LOG_CLIENT, "Waiting for client task group to shut down");
        if let Err(err) = inner
            .task_group
            .clone()
            .shutdown_join_all(Some(Duration::from_secs(30)))
            .await
        {
            warn!(target: LOG_CLIENT, err = %err.fmt_compact_anyhow(), "Error waiting for client task group to shut down");
        }

        let client_strong_count = Arc::strong_count(&inner);
        debug!(target: LOG_CLIENT, "Dropping last handle to Client");
        // We are sure that no background tasks are running in the client anymore, so we
        // can drop the (usually) last inner reference.
        drop(inner);

        if client_strong_count != 1 {
            debug!(target: LOG_CLIENT, count = client_strong_count - 1, LOG_CLIENT, "External Client references remaining after last handle dropped");
        }

        let db_strong_count = db.strong_count();
        if db_strong_count != 1 {
            debug!(target: LOG_CLIENT, count = db_strong_count - 1, "External DB references remaining after last handle dropped");
        }
        trace!(target: LOG_CLIENT, "Dropped last handle to Client");
    }

    /// Restart the client
    ///
    /// Returns false if there are other clones of [`ClientHandle`], or starting
    /// the client again failed for some reason.
    ///
    /// Notably it will re-use the original [`fedimint_core::db::Database`]
    /// handle, and not attempt to open it again.
    pub async fn restart(self) -> anyhow::Result<ClientHandle> {
        let (builder, config, api_secret, root_secret, db, endpoints) = {
            let client = self
                .inner
                .as_ref()
                .ok_or_else(|| format_err!("Already stopped"))?;
            let builder = ClientBuilder::from_existing(client);
            let config = client.config().await;
            let api_secret = client.api_secret.clone();
            let root_secret = client.root_secret.clone();
            let db = client.db().clone();
            let endpoints = client.endpoints().clone();

            (builder, config, api_secret, root_secret, db, endpoints)
        };
        self.shutdown().await;

        builder
            .build(
                endpoints,
                db,
                root_secret,
                config,
                api_secret,
                false,
                None,
                None,
                None, // chain_id should already be cached
            )
            .await
    }
}

impl ops::Deref for ClientHandle {
    type Target = Client;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().expect("Must have inner client set")
    }
}

/// We need a separate drop implementation for `Client` that triggers
/// `Executor::stop_executor` even though the `Drop` implementation of
/// `ExecutorInner` should already take care of that. The reason is that as long
/// as the executor task is active there may be a cycle in the
/// `Arc<Client>`s such that at least one `Executor` never gets dropped.
impl Drop for ClientHandle {
    fn drop(&mut self) {
        if self.inner.is_none() {
            return;
        }

        // We can't use block_on in single-threaded mode or wasm
        #[cfg(target_family = "wasm")]
        let can_block = false;
        #[cfg(not(target_family = "wasm"))]
        // nosemgrep: ban-raw-block-on
        let can_block = RuntimeHandle::current().runtime_flavor() != RuntimeFlavor::CurrentThread;
        if !can_block {
            let inner = self.inner.take().expect("Must have inner client set");
            inner.executor.stop_executor();
            if cfg!(target_family = "wasm") {
                error!(target: LOG_CLIENT, "Automatic client shutdown is not possible on wasm, call ClientHandle::shutdown manually.");
            } else {
                error!(target: LOG_CLIENT, "Automatic client shutdown is not possible on current thread runtime, call ClientHandle::shutdown manually.");
            }
            return;
        }

        debug!(target: LOG_CLIENT, "Shutting down the Client on last handle drop");
        #[cfg(not(target_family = "wasm"))]
        runtime::block_in_place(|| {
            runtime::block_on(self.shutdown_inner());
        });
    }
}
