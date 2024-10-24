use std::collections::BTreeSet;
use std::result;
use std::string::ToString;

use fedimint_api_client::api::{DynModuleApi, IRawFederationApi, JsonRpcClientError};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{Database, DatabaseTransaction};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send, PeerId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::watch;

/// Event log event right before making an api call
///
/// Notably there is no guarantee that a corresponding [`ApiCallDone`]
/// is ever called, or that the api call actually reached the server.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApiCallStarted {
    method: String,
    peer_id: PeerId,
}

impl Event for ApiCallStarted {
    const MODULE: Option<fedimint_core::core::ModuleKind> = None;

    const KIND: EventKind = EventKind::from_static("api-call-started");

    /// These were deemed heavy volume enough and mostly diagnostics, so they
    /// are not persisted
    const PERSIST: bool = false;
}

/// Event log event right after an api call
///
/// Notably there is no guarantee this event is always created. If the
/// client completed the call, but was abruptly terminated before logging
/// an event, the call might have completed on the server side, but never
/// create this event.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApiCallDone {
    method: String,
    peer_id: PeerId,
    duration_ms: u64,
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_str: Option<String>,
}

impl Event for ApiCallDone {
    const MODULE: Option<fedimint_core::core::ModuleKind> = None;

    const KIND: EventKind = EventKind::from_static("api-call-done");
}

use crate::db::event_log::{DBTransactionEventLogExt as _, Event, EventKind};

/// Convenience extension trait used for wrapping [`IRawFederationApi`] in
/// a [`ClientRawFederationApi`]
pub trait ClientRawFederationApiExt
where
    Self: Sized,
{
    fn with_client_ext(
        self,
        db: Database,
        log_ordering_wakeup_tx: watch::Sender<()>,
    ) -> ClientRawFederationApi<Self>;
}

impl<T> ClientRawFederationApiExt for T
where
    T: IRawFederationApi + MaybeSend + MaybeSync + 'static,
{
    fn with_client_ext(
        self,
        db: Database,
        log_ordering_wakeup_tx: watch::Sender<()>,
    ) -> ClientRawFederationApi<T> {
        db.ensure_global().expect("Must be given global db");
        ClientRawFederationApi {
            inner: self,
            db,
            log_ordering_wakeup_tx,
        }
    }
}

/// A wrapper over [`IRawFederationApi`] adding client side event logging
///
/// Create using [`ClientRawFederationApiExt::with_client_ext`]
#[derive(Debug)]
pub struct ClientRawFederationApi<I> {
    inner: I,
    db: Database,
    log_ordering_wakeup_tx: watch::Sender<()>,
}

impl<I> ClientRawFederationApi<I> {
    pub async fn log_event<E>(&self, event: E)
    where
        E: Event + Send,
    {
        let mut dbtx = self.db.begin_transaction().await;
        self.log_event_dbtx(&mut dbtx, event).await;
        dbtx.commit_tx().await;
    }

    pub async fn log_event_dbtx<E, Cap>(&self, dbtx: &mut DatabaseTransaction<'_, Cap>, event: E)
    where
        E: Event + Send,
        Cap: Send,
    {
        dbtx.log_event(self.log_ordering_wakeup_tx.clone(), None, event)
            .await;
    }
}

#[apply(async_trait_maybe_send!)]
impl<I> IRawFederationApi for ClientRawFederationApi<I>
where
    I: IRawFederationApi,
{
    fn all_peers(&self) -> &BTreeSet<PeerId> {
        self.inner.all_peers()
    }

    fn self_peer(&self) -> Option<PeerId> {
        self.inner.self_peer()
    }

    fn with_module(&self, id: ModuleInstanceId) -> DynModuleApi {
        self.inner.with_module(id)
    }

    async fn request_raw(
        &self,
        peer_id: PeerId,
        method: &str,
        params: &[Value],
    ) -> result::Result<Value, JsonRpcClientError> {
        self.log_event(ApiCallStarted {
            method: method.to_string(),
            peer_id,
        })
        .await;

        let start = fedimint_core::time::now();
        let res = self.inner.request_raw(peer_id, method, params).await;
        let end = fedimint_core::time::now();

        self.log_event(ApiCallDone {
            method: method.to_string(),
            peer_id,
            duration_ms: end
                .duration_since(start)
                .unwrap_or_default()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            success: res.is_ok(),
            error_str: res.as_ref().err().map(ToString::to_string),
        })
        .await;

        res
    }
}
