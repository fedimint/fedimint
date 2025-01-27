use std::collections::BTreeSet;

use anyhow::format_err;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send, PeerId};
use serde_json::Value;
use tokio::sync::{watch, RwLock};

use super::super::{DynModuleApi, IRawFederationApi};
use crate::api::{PeerError, PeerResult};

/// Convenience extension trait used for wrapping [`IRawFederationApi`] in
/// a [`RawFederationApiWithOnlineToggle`]
pub trait RawFederationApiWithOnlineToggleExt
where
    Self: Sized,
{
    fn with_online_toggle(
        self,
        online: watch::Receiver<bool>,
    ) -> RawFederationApiWithOnlineToggle<Self>;
}

impl<T> RawFederationApiWithOnlineToggleExt for T
where
    T: IRawFederationApi + MaybeSend + MaybeSync + 'static,
{
    fn with_online_toggle(
        self,
        online: watch::Receiver<bool>,
    ) -> RawFederationApiWithOnlineToggle<T> {
        RawFederationApiWithOnlineToggle::new(self, online)
    }
}

/// [`IRawFederationApi`] wrapping some `T: IRawFederationApi` and adding
/// a toggle for online/offline state.
///
/// If the state is offline, all requests will block until toggle switched to
/// online, without actually making any connections.
///
/// Use [`RawFederationApiWithOnlineToggleExt::with_online_toggle`] to
/// create.
#[derive(Debug)]
pub struct RawFederationApiWithOnlineToggle<T> {
    pub(crate) inner: T,
    online: tokio::sync::RwLock<watch::Receiver<bool>>,
}

impl<T> RawFederationApiWithOnlineToggle<T> {
    pub fn new(inner: T, online: watch::Receiver<bool>) -> RawFederationApiWithOnlineToggle<T> {
        Self {
            inner,
            online: RwLock::new(online),
        }
    }
}

#[apply(async_trait_maybe_send!)]
impl<T> IRawFederationApi for RawFederationApiWithOnlineToggle<T>
where
    T: IRawFederationApi + MaybeSend + MaybeSync + 'static,
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
        params: &ApiRequestErased,
    ) -> PeerResult<Value> {
        if !*self.online.write().await.borrow() {
            return Err(PeerError::Connection(format_err!("Online toggle is off")));
        }
        // Note: We could block until online too...
        // if self.online.write().await.wait_for(|v| *v).await.is_err() {
        //     return Err(PeerError::InternalClientError(format_err!(
        //         "Client disconnected?"
        //     )));
        // }
        self.inner.request_raw(peer_id, method, params).await
    }
}
